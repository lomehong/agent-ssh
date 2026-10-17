/**
 * stub 纯单向 MCP 前端（T-16a，方案 §2.2/§3.4）。
 *
 * 架构：请求级转发而非工具重注册——tools/list 回缓存 manifest（inputSchema
 * 字节级保真）、tools/call 与 resource.read 经 RPC 透传 Host。这样 stub 不
 * 需要 import 任何工具实现（红线③：无 ssh2/无 fs/无子进程）。
 *
 * §3.4 启动机语义：连接前 MCP initialize 已可用（零工具空集诚实态）；
 * Host 上线 → 拉 manifest → ready → 发 tools/list_changed；断连 → ready 翻
 * false、调用一律结构化失败（绝不本地降级）；重连成功 → 重拉 manifest（D3
 * 单连接内不可变=跨连接重拉）→ 再发 list_changed。
 */
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ListResourcesRequestSchema,
  ReadResourceRequestSchema,
  ErrorCode,
  McpError,
} from '@modelcontextprotocol/sdk/types.js';
import { RpcClient } from '../rpc/client.js';
import type { HostToolManifest } from '../rpc/manifest.js';
import { nextRetryDelayMs } from '../rpc/reconnect.js';

export interface StubOpts {
  /** 裸 McpServer：不得预注册任何工具/资源（stub 全量转发）。 */
  server: McpServer;
  /** Host 地址 `host:port`（IPv6 用 `[::1]:port` 文法）。 */
  hostAddr: string;
  token: string;
  pin?: string;
  protocolVersion?: string;
  /** 重连退避上限覆盖（测试压短）；缺省 30s 退避封顶。 */
  reconnectMaxDelayMs?: number;
}

export interface StubHandle {
  close(): Promise<void>;
  /** manifest 已拉取且连接可用（§3.4 的「已注册」态）。 */
  isReady(): boolean;
}

/** `host:port` 拆分（IPv6 `[::1]:port` 文法支持）。 */
export function splitHostAddr(addr: string): { host: string; port: number } {
  const i = addr.lastIndexOf(':');
  if (i === -1) throw new Error(`Invalid host address '${addr}' — expected host:port`);
  let host = addr.slice(0, i);
  const port = Number(addr.slice(i + 1));
  if (host.startsWith('[') && host.endsWith(']')) host = host.slice(1, -1);
  if (!Number.isInteger(port) || port <= 0 || port > 65_535) {
    throw new Error(`Invalid port in host address '${addr}'`);
  }
  return { host, port };
}

function unreachable(): McpError {
  return new McpError(
    ErrorCode.InternalError,
    'Host unreachable: the stub never degrades locally (fail-closed). ' +
      'The command was not executed; retry when the host daemon is back.',
  );
}

/**
 * tool.call 的转发超时：审批门内的调用合法阻塞至审批窗口走完（U3：
 * APPROVAL_TIMEOUT_MS = 10min；Host 侧队列轮询 2s）。660s = 窗口 + 余量；
 * T-17.6 真实人工 E2E 首次踩中默认 10s 掐断（此前裁决泵秒批从未暴露）。
 * 其余方法（hello/manifest/resource）维持客户端级 10s——快失败快重连。
 */
const TOOL_CALL_TIMEOUT_MS = 660_000;

export async function startStub(opts: StubOpts): Promise<StubHandle> {
  const { server } = opts;
  let manifest: HostToolManifest | undefined;
  let ready = false;
  let stopping = false;
  let signalStop: (() => void) | undefined;
  const stopSignal = new Promise<void>((resolve) => {
    signalStop = resolve;
  });

  const hostPort = splitHostAddr(opts.hostAddr);
  const cap = opts.reconnectMaxDelayMs ?? 30_000;
  let attempt = 0;
  let currentClient: RpcClient | undefined;

  // ── 请求级转发（handler 读取当前 ready/manifest 状态）──
  server.server.setRequestHandler(ListToolsRequestSchema, () => {
    if (!ready || manifest === undefined) return { tools: [] }; // 窗口期空集诚实态
    return {
      tools: manifest.tools.map((t) => ({
        name: t.name,
        description: t.description,
        inputSchema: t.inputSchema ?? { type: 'object', properties: {} },
      })),
    };
  });
  server.server.setRequestHandler(CallToolRequestSchema, async (req) => {
    if (!ready || currentClient === undefined || manifest === undefined) throw unreachable();
    return (await currentClient.call('tool.call', {
      name: req.params.name,
      arguments: req.params.arguments ?? {},
    }, { timeoutMs: TOOL_CALL_TIMEOUT_MS })) as never;
  });
  server.server.setRequestHandler(ListResourcesRequestSchema, () => {
    if (!ready || manifest === undefined) return { resources: [] };
    return {
      resources: manifest.resources.map((r) => ({
        uri: r.uri,
        name: r.name,
        description: r.description,
        mimeType: 'application/json',
      })),
    };
  });
  server.server.setRequestHandler(ReadResourceRequestSchema, async (req) => {
    if (!ready || currentClient === undefined) throw unreachable();
    return (await currentClient.call('resource.read', { uri: req.params.uri })) as never;
  });

  // ── 连接循环：连接→hello→manifest→ready→等断线→重连（指数退避）──
  const loop = async (): Promise<void> => {
    while (!stopping) {
      const client = new RpcClient({
        host: hostPort.host,
        port: hostPort.port,
        token: opts.token,
        ...(opts.pin !== undefined ? { tls: { pin: opts.pin } } : {}),
        reconnect: false,
        requestTimeoutMs: 10_000,
      });
      currentClient = client;
      // 竞态安全（评审 jc）：ready 翻牌后同一宏任务内同步注册断线监听——
      // close 事件（宏任务）插不进队，race 等待期不漏断线信号。
      const offDisconnect = client.onDisconnected(() => {
        ready = false;
      });
      try {
        await client.connect();
        manifest = await client.call('host.toolManifest') as HostToolManifest;
        // 通知先行于 ready 翻牌：通知自身的失败（宿主瞬时不可写）不影响就绪态。
        try {
          server.sendToolListChanged();
        } catch {
          // tools/list_changed 投递失败不回滚 ready——宿主下次 tools/list 仍见全量。
        }
        ready = true;
        attempt = 0;
        await Promise.race([
          new Promise<void>((resolve) => {
            const off = client.onDisconnected(() => {
              off();
              resolve();
            });
            void stopSignal.then(() => off());
          }),
          stopSignal,
        ]);
      } catch (err) {
        ready = false;
        console.error(`[stub-loop] connect failed (retrying): ${err instanceof Error ? err.message : String(err)}`);
      } finally {
        offDisconnect();
        await client.close().catch(() => {});
        if (currentClient === client) currentClient = undefined;
      }
      if (stopping) break;
      await new Promise<void>((resolve) => {
        const t = setTimeout(resolve, Math.max(10, nextRetryDelayMs(attempt, cap)));
        void stopSignal.then(() => clearTimeout(t)).then(() => resolve());
      });
      attempt++;
    }
  };
  const loopDone = loop().catch(() => {});

  return {
    isReady: () => ready,
    async close(): Promise<void> {
      stopping = true;
      signalStop?.();
      await loopDone;
    },
  };
}
