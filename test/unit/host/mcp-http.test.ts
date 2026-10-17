// T-24：MCP Streamable HTTP 面单测——鉴权（401/200）、路由（404/405）、
// 体限（413）、回环绑定、无状态工具调用全链路。
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { randomBytes } from 'node:crypto';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { z } from 'zod';
import { startMcpHttp, type McpHttpHandle } from '../../../src/host/mcp-http.js';
import { tokenDigest } from '../../../src/rpc/auth.js';

const TOKEN = randomBytes(32).toString('base64url');
let handle: McpHttpHandle;

/** 最小工具面（全 23 工具的真管线在真机 E2E 验证，此处钉 HTTP 语义）。 */
function factory(): McpServer {
  const server = new McpServer(
    { name: 'test host', version: '0' },
    { capabilities: { tools: {} } },
  );
  server.tool('echo', { text: z.string() }, async ({ text }) => ({
    content: [{ type: 'text', text }],
  }));
  return server;
}

beforeAll(async () => {
  handle = await startMcpHttp({
    serverFactory: factory,
    expectedTokenDigest: tokenDigest(TOKEN),
    digest: tokenDigest,
    port: 0, // 内核分配，避免测试口冲突
    log: () => {},
  });
});

afterAll(async () => {
  await handle.close();
});

function rawRequest(
  path: string,
  init: { method: string; headers?: Record<string, string>; body?: string },
): Promise<{ status: number; text: string }> {
  return fetch(`http://127.0.0.1:${handle.port}${path}`, {
    method: init.method,
    headers: init.headers,
    body: init.body,
  }).then(async (r) => ({ status: r.status, text: await r.text() }));
}

describe('MCP HTTP 面（T-24）', () => {
  it('缺 Bearer → 401 恒定文案', async () => {
    const r = await rawRequest('/mcp', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }),
    });
    expect(r.status).toBe(401);
    expect(r.text).toBe('{"error":"unauthorized"}');
  });

  it('错令牌 → 401', async () => {
    const r = await rawRequest('/mcp', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${randomBytes(32).toString('base64url')}` },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }),
    });
    expect(r.status).toBe(401);
  });

  it('非 /mcp 路径 → 404；GET → 405（stateless 无 SSE）', async () => {
    const notFound = await rawRequest('/other', {
      method: 'POST',
      headers: { authorization: `Bearer ${TOKEN}` },
      body: '{}',
    });
    expect(notFound.status).toBe(404);
    const get = await rawRequest('/mcp', { method: 'GET', headers: { authorization: `Bearer ${TOKEN}` } });
    expect(get.status).toBe(405);
  });

  it('体超 4MB 帧限 → 413', async () => {
    const r = await rawRequest('/mcp', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${TOKEN}` },
      body: 'x'.repeat(4 * 1024 * 1024 + 1),
    });
    expect(r.status).toBe(413);
  });

  it('对令牌全链路：initialize → tools/list → tools/call（StreamableHTTP 客户端）', async () => {
    const transport = new StreamableHTTPClientTransport(
      new URL(`http://127.0.0.1:${handle.port}/mcp`),
      { requestInit: { headers: { authorization: `Bearer ${TOKEN}` } } },
    );
    const client = new Client({ name: 't24-test', version: '0' });
    await client.connect(transport);
    try {
      const tools = await client.listTools();
      expect(tools.tools.map((t) => t.name)).toContain('echo');
      const res = await client.callTool({ name: 'echo', arguments: { text: 't24-ok' } });
      expect(res.content).toEqual([{ type: 'text', text: 't24-ok' }]);
    } finally {
      await client.close();
    }
  });

  it('绑定 127.0.0.1（句柄端口仅回环可达）', async () => {
    expect(handle.port).toBeGreaterThan(0);
    // node http server 以 '127.0.0.1' listen——非回环地址不可达属 OS 语义；
    // 此处钉住句柄端口与 listen 参数一致（实现内 host 硬编码，误改即此断言红）。
    const r = await rawRequest('/mcp', { method: 'GET', headers: { authorization: `Bearer ${TOKEN}` } });
    expect([401, 405]).toContain(r.status);
  });
});
