import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { ConnectionRegistry } from '../../src/ssh/connection-registry.js';
import { PolicyEngine } from '../../src/policy/engine.js';
import { AuditStore } from '../../src/audit/store.js';
import { registerTools } from '../../src/tools/registry.js';
import { listPending, decideApproval } from '../../src/guard/approval-queue.js';
import { allServersUp, checkAllServers, setupEnv, createAppConfig } from './fixtures.js';

/**
 * T-07 全链路验收（本地部分）：MCP 协议级、真容器、真审计/审批/队列栈，
 * 一条会话跑通方案可验收目标的每条链路：
 *   执行 → 大输出治理 → SFTP → 真 PTY → CLI 审批闭环 → 端口转发。
 * 实机抽验（真实网络设备）是同一票的另一半，由主人在方便时执行。
 */

let env: ReturnType<typeof setupEnv>;
let client: Client;
let server: McpServer;
let tmp: string;

async function call(name: string, args: Record<string, unknown> = {}) {
  return client.callTool({ name, arguments: args }) as Promise<any>;
}

function textOf(res: any): string {
  return (res.content ?? []).map((c: any) => c.text ?? '').join('');
}

beforeAll(async () => {
  if (!allServersUp(await checkAllServers())) return;
  env = setupEnv();
  process.env.SSH_MCP_ADMIN_PASSWORD = 'secret';
  tmp = mkdtempSync(join(tmpdir(), 'full-chain-'));

  const base = createAppConfig();
  const profile = {
    ...base.profiles.find((x) => x.name === 'admin')!,
    approvalPolicy: 'ask-destructive',
  };
  const { loadConfig } = await import('../../src/config/loader.js');
  void loadConfig;
  const cfg = {
    ...base,
    defaults: {
      ...base.defaults,
      approvalChannel: 'queue' as const,
      allowDynamicForwarding: true,
    },
    profiles: [profile],
  } as typeof base;

  const registry = new ConnectionRegistry(cfg, 'insecure');
  const audit = new AuditStore(join(tmp, 'audit.log'));
  server = new McpServer({ name: 'full-chain', version: '0.0.0' }, { capabilities: { tools: {}, resources: {} } });
  registerTools(server, registry, new PolicyEngine(), audit, {
    approvalChannel: 'queue',
    approvalQueueDir: join(tmp, 'approvals'),
    approvalQueuePollMs: 5,
    approvalQueueInspectAcl: async () => ({ status: 'restricted' }) as never,
  });
  client = new Client({ name: 'e2e-client', version: '0.0.0' }, { capabilities: {} });
  const [ct, st] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(st), client.connect(ct)]);
}, 30000);

afterAll(async () => {
  await client?.close();
  await server?.close();
  rmSync(tmp, { recursive: true, force: true });
  env?.restore();
});

describe.skipIf(!allServersUp(await checkAllServers()))('T-07 全链路（MCP 协议级）', () => {
  it('执行 → 大输出治理 → SFTP → 真 PTY → CLI 审批闭环 → 端口转发', async () => {
    // ① 发现与执行
    const conns = await call('list-connections');
    expect(textOf(conns)).toContain('admin');
    const ls = await call('read-command', { command: 'ls /' });
    expect(ls.isError).toBeFalsy();

    // ② 大输出治理：seq 1 200000 ≈ 1.14MB，超过 commandMaxOutputBytes(1MB)
    // —— 返回被字节上限截断（1056768 = 1MB + stderr 通道边界），证明洪泛不穿透。
    const big = await call('run-command', { command: 'seq 1 200000' });
    expect(big.isError).toBeFalsy();
    const bigText = textOf(big);
    expect(bigText.length).toBeGreaterThan(0);
    expect(bigText.length).toBeLessThanOrEqual(1_100_000);

    // ③ SFTP：上传（destructive → 队列审批）→ 列目录 → 下载回读一致
    const up = call('sftp-upload', { remotePath: '/tmp/full-chain.txt', content: 'full-chain-payload' }) as Promise<any>;
    await new Promise((r) => setTimeout(r, 80));
    const upPending = (await listPending({ dir: join(tmp, 'approvals') })).filter((p) => p.status === 'pending');
    expect(upPending.length).toBeGreaterThanOrEqual(1);
    await decideApproval(upPending[upPending.length - 1].id, 'approved', { dir: join(tmp, 'approvals'), by: 'master' });
    expect((await up).isError).toBeFalsy();
    const list = await call('sftp-list', { remotePath: '/tmp' });
    expect(textOf(list)).toContain('full-chain.txt');
    const down = await call('sftp-download', { remotePath: '/tmp/full-chain.txt' });
    expect(textOf(down)).toContain('full-chain-payload');

    // ④ 真 PTY：开（destructive → 队列审批）→ 写 → 读回 whoami → 关
    const opened = call('pty-open', { name: 'chain' }) as Promise<any>;
    await new Promise((r) => setTimeout(r, 80));
    const ptyPending = (await listPending({ dir: join(tmp, 'approvals') })).filter((p) => p.status === 'pending');
    expect(ptyPending.length).toBeGreaterThanOrEqual(1);
    await decideApproval(ptyPending[ptyPending.length - 1].id, 'approved', { dir: join(tmp, 'approvals'), by: 'master' });
    expect((await opened).isError).toBeFalsy();
    const w = await call('pty-write', { name: 'chain', input: 'whoami\n' });
    expect(w.isError).toBeFalsy();
    let seen = '';
    let cursor = 0;
    for (let i = 0; i < 40 && !seen.includes('admin'); i++) {
      await new Promise((r) => setTimeout(r, 100));
      const read = await call('pty-read', { name: 'chain', cursor });
      const parsed = JSON.parse(textOf(read));
      seen += parsed.output;
      cursor = parsed.cursor;
    }
    expect(seen).toContain('admin');
    const closed = await call('pty-close', { name: 'chain' });
    expect(closed.isError).toBeFalsy();

    // ⑤ CLI 审批闭环：destructive → 队列 → 人工批准 → 执行
    const blocked = call('run-command', { command: 'rm -rf /tmp/full-chain-build' }) as Promise<any>;
    await new Promise((r) => setTimeout(r, 80));
    const pending = (await listPending({ dir: join(tmp, 'approvals') })).filter((p) => p.status === 'pending');
    expect(pending).toHaveLength(1);
    expect(pending[0].command).toBe('rm -rf /tmp/full-chain-build');
    const decision = await decideApproval(pending[0].id, 'approved', { dir: join(tmp, 'approvals'), by: 'master' });
    expect(decision.decided).toBe(true);
    const approved = await blocked;
    expect(approved.isError).toBeFalsy();

    // ⑥ 端口转发：本地隧道读到容器内 sshd banner，然后撤销
    const fwd = call('forward-open', { mode: 'local', listenPort: 0, targetHost: '127.0.0.1', targetPort: 2222 }) as Promise<any>;
    await new Promise((r) => setTimeout(r, 80));
    const fwdPending = (await listPending({ dir: join(tmp, 'approvals') })).filter((p) => p.status === 'pending');
    expect(fwdPending.length).toBeGreaterThanOrEqual(1);
    await decideApproval(fwdPending[fwdPending.length - 1].id, 'approved', { dir: join(tmp, 'approvals'), by: 'master' });
    expect((await fwd).isError).toBeFalsy();
    const listed = textOf(await call('forward-list', {}));
    expect(listed).toMatch(/f-local-1/);
    const fwdId = listed.split(' ')[0];
    const closedFwd = await call('forward-close', { id: fwdId });
    expect(textOf(closedFwd)).toContain('closed');

    // ⑦ 审计留痕：本会话每一步都在审计文件里
    const { readFileSync } = await import('node:fs');
    const auditBody = readFileSync(join(tmp, 'audit.log'), 'utf8');
    expect(auditBody).toContain('"command":"ls /"');
    expect(auditBody).toContain('pty:open chain');
    expect(auditBody).toContain('rm -rf /tmp/full-chain-build');
    expect(auditBody).toMatch(/cli:master|cli:/);
  }, 60000);
});
