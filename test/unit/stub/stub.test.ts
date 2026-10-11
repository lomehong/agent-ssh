import { describe, expect, it, afterEach, vi } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { createServer as netCreateServer } from 'node:net';
import { readFileSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateAgentToken, hashPassword, tokenDigest, OperatorSessionStore } from '../../../src/rpc/auth.js';
import { RpcHostServer } from '../../../src/rpc/server.js';
import { startStub, type StubHandle } from '../../../src/stub/stub.js';

// T-16a：stub 纯单向 MCP 前端。§3.4 启动机语义——窗口期空工具集诚实态、
// Host 上线后注册并发 list_changed、断连 fail-closed 绝不本地降级、
// 重连后 manifest 重拉（单连接内不可变=跨连接重拉）。

const STUB_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', 'src', 'stub');

interface Stack {
  port: number;
  token: string;
  stubHandle: StubHandle;
  stubServer: McpServer;
  client: Client;
  startHost(): Promise<RpcHostServer>;
  host?: RpcHostServer;
}

async function startStack(hostUp: boolean): Promise<Stack> {
  const token = generateAgentToken();
  // 端口预留：先占一个环回端口再放开，stub 对它退避重连。
  const port = await new Promise<number>((resolve, reject) => {
    const holder = netCreateServer();
    holder.once('error', reject);
    holder.listen(0, '127.0.0.1', () => {
      const p = (holder.address() as { port: number }).port;
      holder.close(() => resolve(p));
    });
  });

  const stubServer = new McpServer(
    { name: 'agent-ssh stub', version: '0.0.0' },
    { capabilities: { tools: {}, resources: {} } },
  );
  const stubHandle = await startStub({
    server: stubServer,
    hostAddr: `127.0.0.1:${port}`,
    token,
    reconnectPollMs: 10,
  });

  const client = new Client({ name: 'mcp-host', version: '0.0.0' });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await Promise.all([stubServer.connect(serverTransport), client.connect(clientTransport)]);

  const stack: Stack = {
    port,
    token,
    stubHandle,
    stubServer,
    client,
    startHost: async () => {
      const host = new RpcHostServer({
        tables: {
          agentTokens: new Set([tokenDigest(token)]),
          sessions: new OperatorSessionStore({ storedHash: hashPassword('stub-test') }),
          imDecisionTokens: new Set(),
        },
        handlers: {
          'tool.call': (params) => {
            const p = params as { name?: unknown };
            if (p.name === 'boom') throw new Error('handler exploded');
            return { content: [{ type: 'text', text: `echo:${String(p.name)}` }], isError: false };
          },
        },
      });
      await host.listen({ host: '127.0.0.1', port });
      stack.host = host;
      return host;
    },
  };
  if (hostUp) {
    await stack.startHost();
    // 等 stub 首次连接+manifest 拉取完成（isReady 翻牌）再交给用例。
    const deadline = Date.now() + 10_000;
    while (!stack.stubHandle.isReady() && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 10));
    }
  }
  return stack;
}

let stack: Stack | undefined;
afterEach(async () => {
  await stack?.stubHandle.close();
  await stack?.host?.close();
  stack = undefined;
  vi.restoreAllMocks();
});

describe('stub 启动机（§3.4 诚实态）', () => {
  it('Host 未上线窗口期：tools/list 返回空集（诚实），不挂死', async () => {
    stack = await startStack(false);
    const listed = await stack.client.listTools();
    expect(listed.tools).toEqual([]);
  });

  it('Host 上线后：重拉 manifest 注册 23 工具，tools/list 可见', async () => {
    stack = await startStack(false);
    const before = await stack.client.listTools();
    expect(before.tools).toEqual([]);

    await stack.startHost();
    await vi.waitFor(async () => {
      const listed = await stack!.client.listTools();
      expect(listed.tools.length).toBe(23);
    }, { timeout: 10_000 });
  });

  it('透传：tools/call 经 RPC 到 Host handler，结果结构保真', async () => {
    stack = await startStack(true);
    const res = await stack.client.callTool({ name: 'run-command', arguments: { command: 'x' } });
    expect(res.isError).toBeFalsy();
    expect(JSON.stringify(res.content)).toContain('echo:run-command');
  });

  it('断连 fail-closed：Host 下线后 tools/call 收结构化错误，不本地降级', async () => {
    stack = await startStack(true);
    // host.close = 监听+连接全撤（持续不可达，非 destroy 瞬窗）：ready 必然翻 false。
    await stack.host!.close();
    await vi.waitFor(() => expect(stack!.stubHandle.isReady()).toBe(false));
    await expect(stack.client.callTool({ name: 'run-command', arguments: {} })).rejects.toThrow(
      /Host unreachable|fail-closed/i,
    );
  });

  it('重连后 manifest 重拉：Host 复活后 tools/call 恢复可用（跨连接重拉，D3 不违背）', async () => {
    stack = await startStack(true);
    await stack.host!.close();
    await vi.waitFor(() => expect(stack!.stubHandle.isReady()).toBe(false));
    stack.host = await stack.startHost(); // 同端口复活
    await vi.waitFor(() => expect(stack!.stubHandle.isReady()).toBe(true), { timeout: 10_000 });
    const res = await stack.client.callTool({ name: 'run-command', arguments: {} });
    expect(res.isError).toBeFalsy();
  });

  it('Host handler 抛错：结构化错误透传（拒绝路径，不挂死）', async () => {
    stack = await startStack(true);
    await expect(stack.client.callTool({ name: 'boom', arguments: {} })).rejects.toThrow(
      /handler exploded/,
    );
  });
});

// ─── 红线③：stub 无 ssh2/无 fs/无子进程（import 白名单，K9-⑨ 口径落地）───
describe('红线③：stub import 白名单（不引 dependency-cruiser）', () => {
  it('src/stub/*.ts 的 import 全部落在白名单内', () => {
    const allowed = [
      /^@modelcontextprotocol\//, // MCP SDK（协议面）
      /^node:/, // node 内置（net/crypto/url——白名单形状由 forbidden 反向收紧）
      /^\.{1,2}\//, // 仓内相对模块（./ 与 ../——rpc 层已受各自纪律约束）
    ];
    const forbidden = [/ssh2/, /node:fs/, /node:child_process/];
    const files = readdirSync(STUB_DIR).filter((f) => f.endsWith('.ts'));
    expect(files.length).toBeGreaterThan(0);
    for (const file of files) {
      const source = readFileSync(join(STUB_DIR, file), 'utf8');
      const imports = [...source.matchAll(/from\s+['"]([^'"]+)['"]/g)].map((m) => m[1]!);
      for (const spec of imports) {
        const ok = allowed.some((re) => re.test(spec)) && !forbidden.some((re) => re.test(spec));
        expect(ok, `${file} imports '${spec}' — outside stub whitelist`).toBe(true);
      }
    }
  });
});
