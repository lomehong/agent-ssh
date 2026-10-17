import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { runDirectCli, runApprovalsCli, DIRECT_VERBS } from '../../src/cli-rpc.js';
import { startHost, type RunningHost } from '../../src/host/main.js';
import { createApprovalRequest } from '../../src/guard/approval-queue.js';
import { hashPassword } from '../../src/rpc/auth.js';
import { RpcClient } from '../../src/rpc/client.js';
import { createAppConfig } from '../integration/fixtures.js';

// T-17：CLI 经 RPC 的语义保持（旧 cli-direct.test 的继任）。
// run/info 与 approvals 都 dial startHost 拉起的 Host；operator 会话经
// AGENT_SSH_SESSION_TOKEN env 注入（免去 TTY 口令交互）；纯逻辑用例
// （usage/禁止名单）不拨号，红线优先于网络的语义由此钉死。

const OPERATOR_PASSWORD = 'operator-test-password';

let host: RunningHost | undefined;
let dir: string | undefined;
const savedEnv: Record<string, string | undefined> = {};

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'cli-rpc-'));
});

afterEach(async () => {
  await host?.stop();
  host = undefined;
  for (const [k, v] of Object.entries(savedEnv)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  if (dir !== undefined) rmSync(dir, { recursive: true, force: true });
  dir = undefined;
});

/** 32 字节 base64url——与 src/rpc generateAgentToken 同熵源（≥256bit）。 */
function newAgentToken(): string {
  return randomBytes(32).toString('base64url');
}

async function startWithSession(
  profileEndpoint?: { host: string; port: number },
): Promise<{ queueDir: string; sessionToken: string }> {
  const queueDir = join(dir!, 'approvals');
  const token = newAgentToken();
  host = await startHost({
    config: (() => {
      const cfg = createAppConfig();
      if (profileEndpoint) {
        cfg.profiles = cfg.profiles.map((p) => ({ ...p, host: profileEndpoint.host, port: profileEndpoint.port }));
      }
      return cfg;
    })(),
    agentToken: token,
    operatorPasswordHash: hashPassword(OPERATOR_PASSWORD),
    configFilePath: join(dir ?? tmpdir(), "config.toml"),
        auditPath: join(dir!, 'audit.log'),
    approvalQueueDir: queueDir,
    reaperIntervalMs: 60_000,
  });

  const pre = new RpcClient({
    host: '127.0.0.1',
    port: host.port,
    token: '',
    skipHello: true,
    reconnect: false,
    requestTimeoutMs: 10_000,
  });
  await pre.connect();
  const started = await pre.call<{ sessionToken: string }>('auth.session.start', {
    password: OPERATOR_PASSWORD,
  });
  await pre.close();

  savedEnv.AGENT_SSH_HOST_ADDR = process.env.AGENT_SSH_HOST_ADDR;
  savedEnv.AGENT_SSH_SESSION_TOKEN = process.env.AGENT_SSH_SESSION_TOKEN;
  process.env.AGENT_SSH_HOST_ADDR = `127.0.0.1:${host.port}`;
  process.env.AGENT_SSH_SESSION_TOKEN = started.sessionToken;
  return { queueDir, sessionToken: started.sessionToken };
}

describe('cli-rpc 直连面（旧 cli-direct 继任）', () => {
  it('动词表恰为 run 与 info', () => {
    expect(DIRECT_VERBS).toEqual(['run', 'info']);
  });

  it('run 无命令 → 用法说明 + 退出码 1（拨号前的纯逻辑）', async () => {
    const errors: string[] = [];
    const errSpy = vi.spyOn(console, 'error').mockImplementation((m) => errors.push(String(m)));
    const code = await runDirectCli('run', []);
    errSpy.mockRestore();
    expect(code).toBe(1);
    expect(errors.join('\n')).toContain('Usage: agent-ssh run');
  });

  it('forbidden 命中：拨号前本地拒绝 + exit 1（红线优先于网络）', async () => {
    const errors: string[] = [];
    const errSpy = vi.spyOn(console, 'error').mockImplementation((m) => errors.push(String(m)));
    const code = await runDirectCli('run', ['rm -rf /']);
    errSpy.mockRestore();
    expect(code).toBe(1);
    expect(errors.join('\n')).toContain('命中禁止名单');
  });

  it('run 目标不可达 → cli-run failed + exit 1（Host 语义桥的 deny 审计在 Host 侧）', async () => {
    await startWithSession({ host: '127.0.0.1', port: 1 });
    const logs: string[] = [];
    const errSpy = vi.spyOn(console, 'error').mockImplementation((m) => logs.push(String(m)));
    const code = await runDirectCli('run', ['--profile=admin', 'echo', 'hi']);
    errSpy.mockRestore();
    expect(code).toBe(1);
    expect(logs.join('\n')).toContain('cli-run failed');
  });

  it('info 经 operator 会话返回 profile 行', async () => {
    await startWithSession();
    const logs: string[] = [];
    const logSpy = vi.spyOn(console, 'log').mockImplementation((m) => logs.push(String(m)));
    const code = await runDirectCli('info', ['--profile=admin']);
    logSpy.mockRestore();
    expect(code).toBe(0);
    expect(logs.join('\n')).toContain('profile     : admin');
  });
});

describe('cli-rpc approvals（队列在 Host 机）', () => {
  it('list：空队列 → No approval requests. + exit 0', async () => {
    await startWithSession();
    const logs: string[] = [];
    const logSpy = vi.spyOn(console, 'log').mockImplementation((m) => logs.push(String(m)));
    const code = await runApprovalsCli(['list']);
    logSpy.mockRestore();
    expect(code).toBe(0);
    expect(logs.join('\n')).toContain('No approval requests.');
  });

  it('approve：完整上下文打印 + 决定生效（approver=cli:<user> 语义）', async () => {
    const { queueDir } = await startWithSession();
    const req = await createApprovalRequest(
      {
        profile: 'admin',
        command: 'rm -rf /tmp/build',
        commandClass: 'destructive',
        binary: 'rm',
        timeoutMs: 60_000,
      },
      { dir: queueDir },
    );
    const logs: string[] = [];
    const logSpy = vi.spyOn(console, 'log').mockImplementation((m) => logs.push(String(m)));
    const code = await runApprovalsCli(['approve', req.id]);
    logSpy.mockRestore();
    expect(code).toBe(0);
    expect(logs.join('\n')).toContain('rm -rf /tmp/build');
    expect(logs.join('\n')).toContain('approved');
    // 落盘终态：decidedBy 来自 CLI 传的 by=cli:<user>
    const stored = JSON.parse(readFileSync(join(queueDir, 'pending', `${req.id}.json`), 'utf8')) as {
      status: string;
      decidedBy: string;
    };
    expect(stored.status).toBe('approved');
    expect(stored.decidedBy).toMatch(/^cli:/);
  });

  it('reject：拒绝生效', async () => {
    const { queueDir } = await startWithSession();
    const req = await createApprovalRequest(
      {
        profile: 'admin',
        command: 'rm -rf /tmp/build',
        commandClass: 'destructive',
        binary: 'rm',
        timeoutMs: 60_000,
      },
      { dir: queueDir },
    );
    const code = await runApprovalsCli(['reject', req.id]);
    expect(code).toBe(0);
    const stored = JSON.parse(readFileSync(join(queueDir, 'pending', `${req.id}.json`), 'utf8')) as {
      status: string;
    };
    expect(stored.status).toBe('rejected');
  });
});
