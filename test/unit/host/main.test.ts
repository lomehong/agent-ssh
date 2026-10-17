import { describe, expect, it, afterEach } from 'vitest';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { startHost, type RunningHost } from '../../../src/host/main.js';
import { RpcClient, type RpcClientOpts } from '../../../src/rpc/client.js';
import { generateAgentToken } from '../../../src/rpc/auth.js';
import { createAppConfig } from '../../integration/fixtures.js';

// T-15 验收 1：引擎迁入——startHost 把真实管线（23 工具+resources+审计）
// 挂到 RPC 面后面，并继承 index.ts 的回收器与停机梯资产。
// 全链路断言走真实桥接：RPC → 进程内 McpServer → pipeline。

const PASSWORD = 'host-main-operator';
let host: RunningHost | undefined;
let dir: string | undefined;
const clients: RpcClient[] = [];

afterEach(async () => {
  for (const c of clients.splice(0)) await c.close();
  await host?.stop();
  host = undefined;
  if (dir !== undefined) rmSync(dir, { recursive: true, force: true });
  dir = undefined;
});

async function start(profileEndpoint?: { host: string; port: number }): Promise<{ port: number; token: string }> {
  dir ??= mkdtempSync(join(tmpdir(), 'host-main-'));
  const token = generateAgentToken();
  const config = createAppConfig();
  if (profileEndpoint) {
    config.profiles = config.profiles.map((p) => ({ ...p, host: profileEndpoint.host, port: profileEndpoint.port }));
  }
  host = await startHost({
    config,
    agentToken: token,
    configFilePath: join(dir ?? tmpdir(), "config.toml"),
        auditPath: join(dir, 'audit.log'),
    approvalQueueDir: join(dir, 'approvals'),
    reaperIntervalMs: 60_000,
  });
  return { port: host.port, token };
}

function client(port: number, token: string, extra: Partial<RpcClientOpts> = {}): RpcClient {
  const c = new RpcClient({ host: '127.0.0.1', port, token, ...extra });
  clients.push(c);
  return c;
}

describe('Host 引擎迁入（T-15 验收 1）', () => {
  it('真实管线桥接：tool.call list-connections 经 RPC 返回 profiles', async () => {
    const { port, token } = await start();
    const c = client(port, token);
    await c.connect();
    const result = await c.call<{ content: Array<{ text: string }> }>('tool.call', {
      name: 'list-connections',
      arguments: {},
    });
    expect(result.content).toHaveLength(1);
    // list-connections 返回人类可读摘要（非 JSON）：断言真实管线产物含 profile 名。
    expect(result.content[0]!.text).toContain('admin');
  });

  it('host.toolManifest 在真实装配下仍是 23 工具+3 资源', async () => {
    const { port, token } = await start();
    const c = client(port, token);
    await c.connect();
    const manifest = await c.call<{ tools: unknown[]; resources: unknown[] }>('host.toolManifest');
    expect(manifest.tools).toHaveLength(23);
    expect(manifest.resources).toHaveLength(3);
  });

  it('D15 单令牌模型：agent 调 approval.list 直连放行（旧 -32002 已废止）', async () => {
    const { port, token } = await start();
    const c = client(port, token);
    await c.connect();
    const outcome = await c.call<{ pending: unknown[] }>('approval.list');
    expect(Array.isArray(outcome.pending)).toBe(true);
  });

  it('D15：auth.session.start 已废止（Unknown method）+agent 直连 approval.decide', async () => {
    const { port, token } = await start();
    const agentClient = client(port, token);
    await agentClient.connect();
    await expect(agentClient.call('auth.session.start', { password: PASSWORD })).rejects.toThrow(
      /Unknown method/,
    );
    const outcome = await agentClient.call<{ decided: boolean; message: string }>('approval.decide', {
      id: 'no-such-id',
      decision: 'approved',
    });
    expect(outcome.decided).toBe(false);
    expect(outcome.message).toMatch(/No such approval request/);
  });

  it('host.admin.rotateToken：agent 直连触发，新令牌立即可用（M9 双活宽限）', async () => {
    const { port, token } = await start();
    const operator = client(port, token);
    await operator.connect();
    const rotated = await operator.call<{ agentToken: string }>('host.admin.rotateToken');
    expect(rotated.agentToken).toMatch(/^[A-Za-z0-9_-]{43}$/);
    // 新令牌立即可用（双活宽限）；旧令牌吊销语义登记 T-16/T-17 装配确认。
    const fresh = client(port, rotated.agentToken);
    await fresh.connect();
    expect(await fresh.call('host.ping')).toMatchObject({ pong: true });
  });

  it('resource.list 桥接返回静态资源（connections；模板资源属 listResourceTemplates，T-16 对齐）', async () => {
    const { port, token } = await start();
    const c = client(port, token);
    await c.connect();
    const listed = await c.call<{ resources: Array<{ uri: string }> }>('resource.list');
    expect(listed.resources.some((r) => r.uri === 'ssh://connections')).toBe(true);
  });

  // ── T-17：cli.run / cli.info 语义桥（D4：人即批准者，无审批门）──
  it('cli.info 经 operator 会话返回结构化 profile 信息（无 SSH 触达）', async () => {
    const started = await start();
    const operator = client(started.port, started.token);
    await operator.connect();
    const info = await operator.call<{ profile: { name: string; host: string; user: string }; connected: boolean }>('cli.info', { profile: 'admin' });
    expect(info.profile.name).toBe('admin');
    expect(info.profile.user).toBe('admin');
    expect(info.connected).toBe(false);
  });

  it('cli.run 禁止名单先于一切：FORBIDDEN_PATTERN 拒绝 + deny 审计留痕（评审 jc3）', async () => {
    const started = await start();
    const operator = client(started.port, started.token);
    await operator.connect();
    await expect(operator.call('cli.run', { command: 'rm -rf /' })).rejects.toThrow(/FORBIDDEN_PATTERN/);
    const auditText = readFileSync(join(dir!, 'audit.log'), 'utf8');
    expect(auditText).toContain('"ruleId":"cli-direct-forbidden"');
  });

  it('cli.run 目标不可达：deny 审计留痕（ruleId=cli-direct-error）+ 结构化拒绝', async () => {
    const started = await start({ host: '127.0.0.1', port: 1 }); // ECONNREFUSED 立即失败
    const operator = client(started.port, started.token);
    await operator.connect();
    await expect(operator.call('cli.run', { profile: 'admin', command: 'echo hi' })).rejects.toThrow(/cli-run failed/);
    const auditText = readFileSync(join(dir!, 'audit.log'), 'utf8');
    expect(auditText).toContain('"ruleId":"cli-direct-error"');
    expect(auditText).toContain('"approver":"cli-direct"');
  });

  it('stop() 后连接与桥全部拆除（后续调用 fail-fast）', async () => {
    const started = await start();
    const c = client(started.port, started.token);
    await c.connect();
    expect(await c.call('host.ping')).toMatchObject({ pong: true });
    await host!.stop();
    await expect(c.call('host.ping')).rejects.toThrow();
  });
});