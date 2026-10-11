import { describe, expect, it, afterEach, vi } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { createServer as netCreateServer } from 'node:net';
import { readFileSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { existsSync } from 'node:fs';
import { generateAgentToken, hashPassword, tokenDigest, OperatorSessionStore } from '../../../src/rpc/auth.js';
import { TOOL_DESCRIPTIONS } from '../../../src/tools/descriptions.js';
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
    reconnectMaxDelayMs: 10,
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
          'resource.read': (params) => {
            const p = params as { uri?: unknown };
            return {
              contents: [{ uri: String(p.uri), mimeType: 'application/json', text: '{"via":"host"}' }],
            };
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
      // 与 host 注册面同源对齐（不硬编码计数，脆断防：数变即本测试随之变）。
      expect(listed.tools.map((t) => t.name).sort()).toEqual(
        Object.keys(TOOL_DESCRIPTIONS).sort(),
      );
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

  it('resources 透传：list 回 manifest 三资源，read 经 RPC 到 Host（T-16 b 腿）', async () => {
    stack = await startStack(true);
    const listed = await stack.client.listResources();
    expect(listed.resources.map((r) => r.uri).sort()).toEqual([
      'ssh://connections',
      'ssh://connections/{profile}',
      'ssh://sessions/{profile}/{session}',
    ]);
    const read = await stack.client.readResource({ uri: 'ssh://connections' });
    const first = read.contents[0] as { text: string };
    expect(JSON.parse(first.text)).toEqual({ via: 'host' });
  });
});

// ─── 红线③：stub 无 ssh2/无 fs/无子进程（K9-⑨ 口径成文）───
/**
 * import 白名单口径（K9-⑨ 落地，票面第 6 项）：
 * 1. 运行时 import（含动态 import()）必须匹配允许面：
 *    a) @modelcontextprotocol/sdk/*（MCP 协议面）；
 *    b) node:net / node:crypto / node:url（枚举式内置白名单——node:fs、
 *       node:child_process 及其余内置一律禁止）；
 *    c) 仓内相对导入 ./ 与 ../（其所指模块自身受「所属层无 ssh2 链」测试
 *       约束——传递依赖以「每层各自无 ssh2 + stub 直系禁 ssh2」双保险闭合，
 *       不做全图分析，不引 dependency-cruiser）。
 * 2. `import type`（类型擦除、零运行时边）豁免上述 b) 的枚举限制，但仍禁
 *    ssh2 类型面（类型依赖亦是供应链信号）。
 * 3. 动态 import() / createRequire / eval / new Function 在 stub 内一律禁止
 *    （按字节扫描，绕过静态正则的通道同被堵死）。
 * 4. 扫描递归 src/stub/ 子目录。
 */
describe('红线③：stub import 白名单（不引 dependency-cruiser）', () => {
  const forbiddenSpec = [/^ssh2/, /^node:fs/, /^node:child_process/];

  function scanFile(path: string, source: string, depth: number): string[] {
    const issues: string[] = [];
    const dynamic = [...source.matchAll(/import\s*\(\s*['"]([^'"]+)['"]\s*\)/g)].map((m) => m[1]!);
    const statics = [...source.matchAll(/(?:^|\n)\s*(?:import(?:\s+type)?\s+(?:[^'"]*?\s+from\s+)?)['"]([^'"]+)['"]/g)].map((m) => m[1]!);
    for (const spec of [...statics, ...dynamic]) {
      const isTypeOnly = new RegExp(`import\\s+type\\s[^\\n]*['"]${spec}['"]`).test(source);
      const allowed =
        /^@modelcontextprotocol\//.test(spec) ||
        /^node:(net|crypto|url)$/.test(spec) ||
        /^\.{1,2}\//.test(spec);
      if (forbiddenSpec.some((re) => re.test(spec))) issues.push(`${path}: forbidden '${spec}'`);
      if (!allowed && !isTypeOnly) issues.push(`${path}: outside whitelist '${spec}'`);
      // 传递依赖：仓内相对导入递归下钻（type 豁免不递归；深度由 visited 封顶）。
      if (spec.startsWith('.') && !isTypeOnly && depth < 6) {
        const base = join(dirname(path), spec);
        for (const candidate of [base + '.ts', join(base, 'index.ts')]) {
          if (existsSync(candidate) && !visited.has(candidate)) {
            visited.add(candidate);
            issues.push(...scanFile(candidate, readFileSync(candidate, 'utf8'), depth + 1));
          }
        }
      }
    }
    return issues;
  }
  const visited = new Set<string>();

  it('src/stub/** 运行时 import 全落白名单，递归覆盖仓内相对依赖', () => {
    visited.clear();
    const files = readdirSync(STUB_DIR, { recursive: true } as never)
      .map(String)
      .filter((f) => f.endsWith('.ts'));
    expect(files.length).toBeGreaterThan(0);
    const issues: string[] = [];
    for (const file of files) {
      const full = join(STUB_DIR, file);
      if (visited.has(full)) continue;
      visited.add(full);
      issues.push(...scanFile(full, readFileSync(full, 'utf8'), 0));
    }
    expect(issues, issues.join('\n')).toEqual([]);
  });

  it('动态 import 与 require 通道按字节禁止（口径第 3 条）', () => {
    for (const file of readdirSync(STUB_DIR).filter((f) => f.endsWith('.ts'))) {
      const source = readFileSync(join(STUB_DIR, file), 'utf8');
      expect(/import\s*\(/.test(source), `${file} uses dynamic import()`).toBe(false);
      expect(/createRequire|new Function|eval\(/.test(source), `${file} uses eval/createRequire`).toBe(false);
    }
  });
});
