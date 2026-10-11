import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtempSync, rmSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { connect as netConnect } from 'node:net';
import { createAppConfig } from './fixtures.js';
import { ConnectionRegistry } from '../../src/ssh/connection-registry.js';
import { listPending, decideApproval } from '../../src/guard/approval-queue.js';
import type { AppConfig, Profile } from '../../src/types.js';

/**
 * T-07 验收③（修订版）：真实 Linux 服务器全链路抽验。
 *
 * 主人自备服务器与凭证，凭证只经环境变量、绝不打印：
 *   REAL_HOST / REAL_PORT(默认22) / REAL_USER
 *   REAL_AUTH=password|key（默认 password）
 *   REAL_PASSWORD 或 REAL_KEY_PATH
 * 运行：npx vitest --run test/integration/real-linux.test.ts
 *
 * 清单：连接+exec → 大输出治理 → 真 PTY（写入/回显/提示就绪）→ SFTP →
 * 审批队列闭环 → 本地转发（读服务器自身 sshd banner）→ 审计文件核验。
 */

const HOST = process.env.REAL_HOST;
const PORT = Number(process.env.REAL_PORT || 22);
const USER = process.env.REAL_USER;
const AUTH = (process.env.REAL_AUTH || 'password') as 'password' | 'key';

const enabled = Boolean(HOST && USER && (process.env.REAL_PASSWORD || process.env.REAL_KEY_PATH));

let registry: ConnectionRegistry;
let tmp: string;
let client: import('@modelcontextprotocol/sdk/client/index.js').Client;

function mask(s: string | undefined): string {
  return s ? '***' : '(unset)';
}

beforeAll(async () => {
  if (!enabled) return;
  console.log(`real-linux: target=${HOST}:${PORT} user=${USER} auth=${AUTH} password=${mask(process.env.REAL_PASSWORD)} key=${mask(process.env.REAL_KEY_PATH)}`);
  tmp = mkdtempSync(join(tmpdir(), 'real-linux-'));
  if (process.env.REAL_PASSWORD) process.env.SSH_MCP_REAL_PASSWORD = process.env.REAL_PASSWORD;
  if (process.env.REAL_KEY_PATH) process.env.SSH_MCP_REAL_KEY = process.env.REAL_KEY_PATH;

  const base = createAppConfig();
  const profile: Profile = {
    ...base.profiles.find((x) => x.name === 'admin')!,
    approvalPolicy: 'ask-destructive',
    name: 'real',
    host: HOST!,
    port: PORT,
    user: USER!,
    auth: AUTH,
    keyRef: process.env.REAL_KEY_PATH,
  };
  const cfg: AppConfig = {
    ...base,
    defaults: { ...base.defaults, approvalChannel: 'queue', allowDynamicForwarding: true },
    profiles: [profile],
  };
  const registryReal = new ConnectionRegistry(cfg, 'insecure');
  void registryReal;

  const { McpServer } = await import('@modelcontextprotocol/sdk/server/mcp.js');
  const { Client } = await import('@modelcontextprotocol/sdk/client/index.js');
  const { InMemoryTransport } = await import('@modelcontextprotocol/sdk/inMemory.js');
  const { registerTools } = await import('../../src/tools/registry.js');
  const { PolicyEngine } = await import('../../src/policy/engine.js');
  const { AuditStore } = await import('../../src/audit/store.js');
  void registry;
  registry = new ConnectionRegistry(cfg, 'insecure');
  const audit = new AuditStore(join(tmp, 'audit.log'));
  const server = new McpServer({ name: 'real-linux', version: '0.0.0' }, { capabilities: { tools: {}, resources: {} } });
  registerTools(server, registry, new PolicyEngine(), audit, {
    approvalChannel: 'queue',
    approvalQueueDir: join(tmp, 'approvals'),
    approvalQueuePollMs: 5,
    // 本机 %TEMP% 继承 DSH 沙箱的只读授权，生产 ACL 检查会如实拒绝——
    // 验证目标是机制本身，故注入 clean 判定（ACL 语义由 approval-queue-acl 单测覆盖）。
    approvalQueueInspectAcl: async () => ({ status: 'restricted' }),
  });
  client = new Client({ name: 'verify-client', version: '0.0.0' }, { capabilities: {} });
  const [ct, st] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(st), client.connect(ct)]);
}, 30000);

afterAll(async () => {
  await client?.close();
  rmSync(tmp, { recursive: true, force: true });
});

async function call(name: string, args: Record<string, unknown> = {}) {
  return client.callTool({ name, arguments: args }) as Promise<any>;
}

function textOf(res: any): string {
  return (res.content ?? []).map((c: any) => c.text ?? '').join('');
}

async function approveLastQueued(by = 'master', timeoutMs = 15000): Promise<void> {
  // The queued request lands asynchronously (mkdir + write); poll instead of
  // racing a fixed sleep.
  const deadline = Date.now() + timeoutMs;
  let pending: Awaited<ReturnType<typeof listPending>> = [];
  while (Date.now() < deadline) {
    pending = (await listPending({ dir: join(tmp, 'approvals') })).filter((p) => p.status === 'pending');
    if (pending.length > 0) break;
    await new Promise((r) => setTimeout(r, 50));
  }
  expect(pending.length).toBeGreaterThanOrEqual(1);
  const outcome = await decideApproval(pending[pending.length - 1].id, 'approved', { dir: join(tmp, 'approvals'), by });
  expect(outcome.decided).toBe(true);
}

describe.skipIf(!enabled)('T-07 修订验收：真实 Linux 服务器全链路', () => {
  it('① 连接 + 命令执行', async () => {
    // read-command 的 allowlist 不保证含 whoami/uname；通用执行路径是
    // run-command（destructive 依分类，此处 safe→直接放行）。
    const res = await call('run-command', { command: 'whoami && uname -s' });
    expect(res.isError).toBeFalsy();
    const text = textOf(res);
    expect(text).toContain(USER!);
    expect(text).toContain('Linux');
  }, 30000);

  it('② 大输出治理（超 1MB 截断）', async () => {
    const res = await call('run-command', { command: 'seq 1 200000' });
    expect(res.isError).toBeFalsy();
    const len = textOf(res).length;
    expect(len).toBeGreaterThan(0);
    expect(len).toBeLessThanOrEqual(1_100_000);
  }, 60000);

  it('③ 真 PTY：写入/回显/就绪', async () => {
    const opened = call('pty-open', { name: 'real-pty' }) as Promise<any>;
    await new Promise((r) => setTimeout(r, 80));
    await approveLastQueued('master');
    expect((await opened).isError).toBeFalsy();

    const marker = `PTY-OK-${Date.now()}`;
    await call('pty-write', { name: 'real-pty', input: `echo ${marker}\n` });
    let cursor = 0;
    let seen = '';
    for (let i = 0; i < 60 && !seen.includes(marker); i++) {
      await new Promise((r) => setTimeout(r, 100));
      const read = await call('pty-read', { name: 'real-pty', cursor });
      const parsed = JSON.parse(textOf(read));
      seen += parsed.output;
      cursor = parsed.cursor;
    }
    expect(seen).toContain(marker);
    const closed = await call('pty-close', { name: 'real-pty' });
    expect(closed.isError).toBeFalsy();
  }, 60000);

  it('④ SFTP 上传/列出/下载一致（destructive 过审批队列）', async () => {
    const marker = `real-sftp-${Date.now()}`;
    const up = call('sftp-upload', { remotePath: `/tmp/${marker}.txt`, content: marker }) as Promise<any>;
    await new Promise((r) => setTimeout(r, 80));
    await approveLastQueued('master');
    const upRes = await up;
    expect(upRes.isError).toBeFalsy();
    // 交叉验证：shell 视角确认文件真实落盘（不只 SFTP 会话自证）。
    const probe = await call('run-command', { command: `ls -la /tmp/${marker}.txt` });
    expect(textOf(probe)).toContain(marker);
    expect(textOf(probe)).toContain(USER!);

    // /tmp 在该服务器有 2 万+ 条目：list 按 maxEntries 截断属正常行为，
    // 文件存在性已由 upload 响应 + shell ls 探针证明；此处断言 bound 生效。
    const list = await call('sftp-list', { remotePath: '/tmp', maxEntries: 500 });
    const listText = textOf(list);
    expect(listText.split('\n').length).toBeLessThanOrEqual(502); // 500 条 + truncated 注记
    expect(listText).toContain('[truncated:');
        const down = await call('sftp-download', { remotePath: `/tmp/${marker}.txt` });
    expect(textOf(down)).toContain(marker);

    // rm -f（非 -r）分类为 safe：直接执行、不入审批队列——上游分类语义。
    const cleanup = await call('run-command', { command: `rm -f /tmp/${marker}.txt` });
    expect(cleanup.isError).toBeFalsy();
  }, 60000);

  it('⑤ 本地转发：读到服务器自身 sshd banner', async () => {
    const fwd = call('forward-open', { mode: 'local', listenPort: 0, targetHost: '127.0.0.1', targetPort: PORT }) as Promise<any>;
    await new Promise((r) => setTimeout(r, 80));
    await approveLastQueued('master');
    const res = await fwd;
    expect(res.isError).toBeFalsy();
    const listen = textOf(res).match(/listening on ([^\s]+)/)?.[1] ?? '';
    const port = Number(listen.split(':')[1]);

    const seen = await new Promise<string>((resolve, reject) => {
      let out = '';
      const s = netConnect(port, '127.0.0.1');
      const timer = setTimeout(() => { s.destroy(); reject(new Error(`banner timeout; seen=${JSON.stringify(out)}`)); }, 5000);
      s.on('data', (b: Buffer) => {
        out += b.toString('utf8');
        if (out.includes('SSH-2.0')) { clearTimeout(timer); s.destroy(); resolve(out); }
      });
      s.on('error', (e) => { clearTimeout(timer); reject(e); });
    });
    expect(seen).toContain('SSH-2.0');
  }, 60000);

  it('⑥ 审计文件核验（含审批与 pty 记录）', async () => {
    const auditPath = join(tmp, 'audit.log');
    expect(existsSync(auditPath)).toBe(true);
    const body = readFileSync(auditPath, 'utf8');
    expect(body).toContain('"command":"whoami && uname -s"');
    expect(body).toContain('pty:open real-pty');
    expect(body).toMatch(/cli:master/);
  }, 30000);
});
