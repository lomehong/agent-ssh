/**
 * Host 的 MCP Streamable HTTP 面（T-24）：支持远程 MCP 的宿主以一条 URL
 * 直连（http://127.0.0.1:<port>/mcp，Authorization: Bearer <agent 令牌>），
 * 免 node stub 进程链。接入形态与 opencode/cursor 的 remote MCP（url+headers）
 * 同构——宿主侧证据：opencode.json 的 web-search-prime 即 url+headers 形态。
 *
 * 设计要点：
 * - 无状态（sessionIdGenerator: undefined + enableJsonResponse）：无会话表、
 *   无清理负担。per-request transport+server 实例——SDK 的 Server/Protocol
 *   是单 transport 槽，共享 server 实例并发请求会互踩；官方 stateless 示例
 *   即每请求新建。server 由工厂提供（main.ts 注入 registerTools 全套，
 *   状态对象 registry/policy/audit/quota 跨请求共享，工厂只造壳）。
 * - 鉴权：仅 Authorization: Bearer；digest timingSafeEqual（不比对原文，
 *   与 rpc/auth 表纪律一致）。401 恒定文案（不泄露原因细节）。
 * - 127.0.0.1 强制绑定（D15 单令牌明文只走回环；listen host 硬编码）。
 * - 请求体上限 4MB（D12 同值）；超限 413 断连。审批长轮询（≤660s）依赖
 *   HTTP 长请求，node http server 默认无请求级超时，满足。
 * - GET/DELETE 由 SDK transport 自行 405/404（stateless 无 SSE 流）。
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { timingSafeEqual } from 'node:crypto';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { RPC_FRAME_LIMIT_BYTES } from '../rpc/frame.js';

/** 恒定 401 文案（鉴权失败细节只进日志，不回客户端）。 */
const UNAUTHORIZED_BODY = '{"error":"unauthorized"}';

export interface McpHttpOpts {
  /** per-request server 工厂：返回未 connect 的 McpServer（工具已注册）。 */
  serverFactory: () => Promise<McpServer> | McpServer;
  /** 期望 agent 令牌的 digest（tokenDigest 产物，定长）。 */
  expectedTokenDigest: string;
  /** digest 函数（调用方注入 tokenDigest，保持单一来源）。 */
  digest: (token: string) => string;
  port: number;
  log: (line: string) => void;
}

export interface McpHttpHandle {
  port: number;
  close(): Promise<void>;
}

function authorized(req: IncomingMessage, expectedDigest: string, digest: (t: string) => string): boolean {
  const header = req.headers.authorization ?? '';
  const m = /^Bearer (.+)$/.exec(header);
  if (m === null) return false;
  const presented = digest(m[1]!);
  const expected = Buffer.from(expectedDigest);
  const got = Buffer.from(presented);
  if (got.length !== expected.length) return false;
  return timingSafeEqual(got, expected);
}

function readBody(req: IncomingMessage, limitBytes: number): Promise<Buffer | undefined> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    let over = false;
    req.on('data', (chunk: Buffer) => {
      if (over) return;
      size += chunk.length;
      if (size > limitBytes) {
        // 超限：停收（不 destroy——先让 413 能写出去），清场交给调用方。
        over = true;
        req.pause();
        resolve(undefined);
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (!over) resolve(Buffer.concat(chunks));
    });
    req.on('error', (err) => {
      if (!over) reject(err);
    });
  });
}

export async function startMcpHttp(opts: McpHttpOpts): Promise<McpHttpHandle> {
  const server: Server = createServer((req, res) => {
    void handle(req, res).catch((err) => {
      opts.log(`mcp-http handler error: ${err instanceof Error ? err.message : String(err)}`);
      if (!res.headersSent) {
        res.writeHead(500, { 'content-type': 'application/json' });
        res.end('{"error":"internal"}');
      } else {
        res.end();
      }
    });
  });

  const handle = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const url = req.url ?? '/';
    if (url.split('?')[0] !== '/mcp') {
      res.writeHead(404, { 'content-type': 'application/json' });
      res.end('{"error":"not found"}');
      return;
    }
    if (!authorized(req, opts.expectedTokenDigest, opts.digest)) {
      opts.log(`mcp-http auth rejected: ${req.socket.remoteAddress ?? '?'}`);
      res.writeHead(401, { 'content-type': 'application/json' });
      res.end(UNAUTHORIZED_BODY);
      return;
    }
    if (req.method !== 'POST') {
      // stateless 面：GET(SSE 流)/DELETE(会话销毁) 无意义，SDK transport
      // 也会拒——此处显式 405，语义前置。
      res.writeHead(405, { 'content-type': 'application/json', allow: 'POST' });
      res.end('{"error":"method not allowed"}');
      return;
    }
    const body = await readBody(req, RPC_FRAME_LIMIT_BYTES);
    if (body === undefined) {
      res.writeHead(413, { 'content-type': 'application/json' });
      res.end('{"error":"request body exceeds frame limit"}', () => {
        req.destroy(); // 413 已交付，掐掉未消费的残余体
      });
      return;
    }
    // per-request transport+server（无状态）：请求毕即弃。
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      enableJsonResponse: true,
    });
    const mcpServer = await opts.serverFactory();
    await mcpServer.connect(transport);
    res.on('close', () => {
      void transport.close().catch(() => {});
    });
    let parsedBody: unknown;
    try {
      parsedBody = body.length > 0 ? JSON.parse(body.toString('utf8')) : undefined;
    } catch {
      res.writeHead(400, { 'content-type': 'application/json' });
      res.end('{"error":"invalid json"}');
      return;
    }
    await transport.handleRequest(req, res, parsedBody);
  };

  // 127.0.0.1 硬绑定（D15：令牌明文只走回环）。
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(opts.port, '127.0.0.1', () => resolve());
  });
  const address = server.address();
  const port = typeof address === 'object' && address !== null ? address.port : opts.port;
  opts.log(`mcp-http listening on http://127.0.0.1:${port}/mcp (bearer auth, stateless)`);

  return {
    port,
    close: () =>
      new Promise<void>((resolve) => {
        server.close(() => resolve());
      }),
  };
}
