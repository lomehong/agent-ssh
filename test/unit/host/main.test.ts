import { describe, expect, it, afterEach } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { startHost, type RunningHost } from '../../../src/host/main.js';
import { RpcClient, type RpcClientOpts } from '../../../src/rpc/client.js';
import { generateAgentToken, hashPassword } from '../../../src/rpc/auth.js';
import { RPC_ERROR } from '../../../src/rpc/protocol.js';
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

async function start(): Promise<{ port: number; token: string }> {
  dir ??= mkdtempSync(join(tmpdir(), 'host-main-'));
  const token = generateAgentToken();
  host = await startHost({
    config: createAppConfig(),
    agentToken: token,
    operatorPasswordHash: hashPassword(PASSWORD),
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

  it('矩阵在真实装配下仍然生效：agent 调 approval.list → -32002', async () => {
    const { port, token } = await start();
    const c = client(port, token);
    await c.connect();
    await expect(c.call('approval.list')).rejects.toMatchObject({ code: RPC_ERROR.FORBIDDEN });
  });

  it('operator 会话全流程：无凭据 start（agent 凭据会被矩阵拒）→会话→approval.decide', async () => {
    const { port, token } = await start();
    // 矩阵红线实例：agent 凭据调 auth.session.start 必须 FORBIDDEN（不可自铸 operator 会话）。
    const agentClient = client(port, token);
    await agentClient.connect();
    await expect(agentClient.call('auth.session.start', { password: PASSWORD })).rejects.toMatchObject({
      code: RPC_ERROR.FORBIDDEN,
    });
    // start 是 pre-auth 方法：凭无凭据信封 + 口令换会话。
    const pre = client(port, '', { skipHello: true });
    await pre.connect();
    const started = await pre.call<{ sessionToken: string }>('auth.session.start', { password: PASSWORD });
    const operator = client(port, started.sessionToken);
    await operator.connect();
    const outcome = await operator.call<{ decided: boolean; message: string }>('approval.decide', {
      id: 'no-such-id',
      decision: 'approved',
    });
    expect(outcome.decided).toBe(false);
    expect(outcome.message).toMatch(/No such approval request/);
  });

  it('host.admin.rotateToken：operator 触发，新令牌立即可用（M9 双活宽限）', async () => {
    const { port } = await start();
    const pre = client(port, '', { skipHello: true });
    await pre.connect();
    const started = await pre.call<{ sessionToken: string }>('auth.session.start', { password: PASSWORD });
    const operator = client(port, started.sessionToken);
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

  it('stop() 后连接与桥全部拆除（后续调用 fail-fast）', async () => {
    const started = await start();
    const c = client(started.port, started.token);
    await c.connect();
    expect(await c.call('host.ping')).toMatchObject({ pong: true });
    await host!.stop();
    await expect(c.call('host.ping')).rejects.toThrow();
  });
});