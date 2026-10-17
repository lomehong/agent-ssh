import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  OperatorSessionStore,
  generateAgentToken,
  hashPassword,
  tokenDigest,
} from '../../../src/rpc/auth.js';
import { RPC_ERROR } from '../../../src/rpc/protocol.js';
import { RpcClient, type RpcClientOpts } from '../../../src/rpc/client.js';
import { RpcHostServer } from '../../../src/rpc/server.js';

interface Stack {
  server: RpcHostServer;
  port: number;
  token: string;
  imToken: string;
  password: string;
  sessions: OperatorSessionStore;
  clientOpts: (overrides?: Partial<RpcClientOpts>) => RpcClientOpts;
}

async function startStack(): Promise<Stack> {
  const token = generateAgentToken();
  const imToken = generateAgentToken();
  const password = 'slice-pass-9';
  const sessions = new OperatorSessionStore({ storedHash: hashPassword(password) });
  const server = new RpcHostServer({
    tables: {
      agentTokens: new Set([tokenDigest(token)]),
      sessions,
      imDecisionTokens: new Set([tokenDigest(imToken)]),
    },
    handlers: {
      'tool.call': (params) => ({ echoed: params }),
    },
  });
  const port = await server.listen({ host: '127.0.0.1' });
  return {
    server,
    port,
    token,
    imToken,
    password,
    sessions,
    clientOpts: (overrides) => ({ host: '127.0.0.1', port, token, ...overrides }),
  };
}

describe('垂直切片：stub 客户端 ↔ Host 服务端 真链路（T-14.5）', () => {
  // 真实时钟用例（重连退避观察窗 6.5s）超出 vitest 默认 5s——文件级预算（K9-⑤ 同源）
  vi.setConfig({ testTimeout: 12_000 });

  const cleanup: (() => Promise<void>)[] = [];
  afterEach(async () => {
    while (cleanup.length > 0) {
      const fn = cleanup.pop();
      if (fn !== undefined) await fn();
    }
    vi.restoreAllMocks();
  });

  it('tool.call echo 经 认证→矩阵→handler 全链路返回', async () => {
    const stack = await startStack();
    const client = new RpcClient(stack.clientOpts());
    cleanup.push(() => client.close());
    await client.connect();
    const result = await client.call<{ echoed: { n: number } }>('tool.call', { n: 42 });
    expect(result.echoed.n).toBe(42);
  });

  it('connect 即 hello：协商本协议版本', async () => {
    const stack = await startStack();
    const client = new RpcClient(stack.clientOpts());
    cleanup.push(() => client.close());
    await expect(client.connect()).resolves.toBeUndefined();
  });

  it('D15 单令牌：agent 令牌过矩阵——approval.list 到 handler 层（-32601 未实现，非 -32002 禁行）', async () => {
    const stack = await startStack();
    const client = new RpcClient(stack.clientOpts());
    cleanup.push(() => client.close());
    await client.connect();
    // 本裸 server 只注册 tool.call；approval.list 过矩阵后按「未实现」-32601 应答。
    // 若此断言变为 -32002，说明矩阵半途改回——D15 红线漂移。
    await expect(client.call('approval.list')).rejects.toMatchObject({
      code: RPC_ERROR.METHOD_NOT_FOUND,
    });
  });

  it('FORBIDDEN：im 令牌调非 decide 方法 → -32002 且审计留痕（D15 后唯一禁行组合）', async () => {
    const stack = await startStack();
    // im 令牌连 hello 都禁行（矩阵 im:false）——skipHello 直连后首调即撞矩阵。
    const client = new RpcClient(stack.clientOpts({ token: stack.imToken, skipHello: true }));
    cleanup.push(() => client.close());
    await client.connect();
    await expect(client.call('tool.call', { n: 1 })).rejects.toMatchObject({
      code: RPC_ERROR.FORBIDDEN,
    });
    expect(
      stack.server.auditLog.some((e) => e.kind === 'forbidden' && e.method === 'tool.call'),
    ).toBe(true);
  });

  it('无令牌客户端连 hello 都被拒（矩阵：hello 需有效凭据）→ -32001', async () => {
    const stack = await startStack();
    const client = new RpcClient(stack.clientOpts({ token: '' }));
    cleanup.push(() => client.close());
    await expect(client.connect()).rejects.toMatchObject({ code: RPC_ERROR.UNAUTHORIZED });
  });

  it('hello 版本不匹配：连接被显式拒绝并附双方版本', async () => {
    const stack = await startStack();
    const client = new RpcClient(stack.clientOpts({ protocolVersion: '9.0.0' }));
    cleanup.push(() => client.close());
    await expect(client.connect()).rejects.toThrow(/9\.0\.0/);
  });

  it('推送：operator 凭据订阅后，服务端 hub.publish 到达客户端', async () => {
    const stack = await startStack();
    // approval.subscribe 是 operator 通道（矩阵：agent FORBIDDEN）——会话建在 server 的会话表里
    const sessionToken = stack.sessions.start(stack.password, 'slice-k');
    if (!sessionToken.ok) throw new Error('session start failed');
    const client = new RpcClient(stack.clientOpts({ token: sessionToken.token }));
    cleanup.push(() => client.close());
    await client.connect();
    const got: unknown[] = [];
    await client.subscribeApproval((payload) => got.push(payload));
    stack.server.hub.publish('approval.pending', { id: 'ap-9' });
    await vi.waitFor(() => expect(got).toEqual([{ id: 'ap-9' }]));
  });

  it('服务端断连后客户端按退避自动重连，链路恢复可用', async () => {
    const stack = await startStack();
    const client = new RpcClient(stack.clientOpts());
    cleanup.push(() => client.close());
    await client.connect();
    stack.server.destroyAllConnections(); // 模拟 Host 侧掐断
    // 断连异步传播：先观察到 ready→false（客户端已感知），再等退避重连回到 true
    await vi.waitFor(() => expect(client.isConnected()).toBe(false), { timeout: 5_000 });
    await vi.waitFor(() => expect(client.isConnected()).toBe(true), { timeout: 10_000 });
    const result = await client.call<{ echoed: { ok: boolean } }>('tool.call', { ok: true });
    expect(result.echoed).toEqual({ ok: true });
  });

  it('Host 持续不可达：重连退避不产生 unhandled rejection，close 可停止重连链', async () => {
    const stack = await startStack();
    const client = new RpcClient(stack.clientOpts());
    cleanup.push(() => client.close());
    await client.connect();
    // 彻底关停监听（非仅掐连接）：重连拨号将持续 ECONNREFUSED，触达退避续期分支
    await stack.server.close();
    // 观察窗覆盖前两档重试（1s 失败→4s 档触发于 5s）：旧实现在第二档 `void this.connect()`
    // 处产生 unhandled rejection（vitest 记失败）——本用例即其回归测试
    await new Promise((r) => setTimeout(r, 6_500));
    await client.close();
    expect(client.isConnected()).toBe(false);
  });

  it('close 后不再重连，服务端连接归零；close 后调用 fail-fast', async () => {
    const stack = await startStack();
    const client = new RpcClient(stack.clientOpts());
    await client.connect();
    await client.close();
    await vi.waitFor(() => expect(stack.server.connectionCount).toBe(0));
    await expect(client.call('tool.call')).rejects.toThrow();
  });

    // T-17.6 E2E 首次踩中的产品缺陷回归：审批门内的 tool.call 合法阻塞至
    // 人工决定（最长 10min），客户端级 10s 默认会掐断任何真实人工延迟——
    // 此前所有测试都有裁决泵秒批（2-4s 完成），从未暴露。
    it('per-call timeoutMs 覆盖：慢 handler 在客户端级超时下经覆盖成功返回', async () => {
      const token = generateAgentToken();
      const password = 'slow-pass-9';
      const sessions = new OperatorSessionStore({ storedHash: hashPassword(password) });
      let slowServer: RpcHostServer | undefined;
      const server = new RpcHostServer({
        tables: { agentTokens: new Set([tokenDigest(token)]), sessions, imDecisionTokens: new Set() },
        handlers: {
          'tool.call': async () => {
            // 300ms「人工延迟」：客户端级 150s? 不——用 150ms 客户端超时档
            await new Promise((r) => setTimeout(r, 300));
            return { decided: true };
          },
        },
      });
      slowServer = server;
      const port = await server.listen({ host: '127.0.0.1' });
      const client = new RpcClient({ host: '127.0.0.1', port, token, requestTimeoutMs: 150 });
      cleanup.push(() => client.close());
      cleanup.push(() => slowServer!.close());
      await client.connect();
      // 默认（150ms 客户端级）：300ms handler 必超时
      await expect(client.call('tool.call', { x: 1 })).rejects.toThrow(/timeout after 150ms/);
      // 覆盖（5s）：同一慢 handler 成功返回
      const result = await client.call<{ decided: boolean }>('tool.call', { x: 1 }, { timeoutMs: 5_000 });
      expect(result.decided).toBe(true);
    });
});
