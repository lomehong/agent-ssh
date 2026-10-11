/**
 * Host 守护装配（T-15 验收 1：引擎迁入，方案 §2.1/§6/index.ts 资产继承）。
 *
 * startHost = 真实引擎 + RPC 面：
 * - 真实管线经进程内 McpServer（registerTools 全 23 工具）+ InMemory 客户端桥接：
 *   tool.call → mcpClient.callTool，resource.* → mcpClient 读——MCP 语义零重实现；
 * - 审批队列处理器：approval.list/decide（operator 面，K7 串行化在队列模块内）；
 * - operator 会话（D1'）：口令哈希来自 Host 配置；缺省时生成不可知口令哈希
 *   = 等价禁用 operator 会话面；
 * - host.admin.rotateToken（M9）：operator 触发，Host 生成新令牌并加入表
 *   （旧令牌保留=双活宽限；立即吊销语义为设计未尽处，登记 T-16/T-17 装配确认）；
 * - 资产继承（M6）：60s 回收器（回收顺序承重注释随迁）+ 停机梯
 *   （审计先行冲刷 → closeAll 5s 预算）。库形态 stop()，process.exit 归进程包装。
 *
 * cli.run/cli.info（T-17）、desktop/im 推送（T-17.5b/T-17.6）接线前按已知方法
 * 未实现应答（-32601）。
 */
import { randomBytes } from 'node:crypto';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { TlsOptions } from 'node:tls';
import { listPending, decideApproval, type ApprovalSurface } from '../guard/approval-queue.js';
import { generateAgentToken, hashPassword, tokenDigest, OperatorSessionStore } from '../rpc/auth.js';
import { RpcHostServer, type RpcHandler, type RpcHandlerContext } from '../rpc/server.js';
import type { RpcTables } from '../rpc/authorize.js';
import { SERVER_VERSION } from '../version.js';
import { registerResources, registerTools } from '../tools/registry.js';
import { AuditStore } from '../audit/store.js';
import { PolicyEngine } from '../policy/engine.js';
import { ConnectionRegistry } from '../ssh/connection-registry.js';
import type { HostKeyMode } from '../ssh/host-key.js';
import type { AppConfig } from '../types.js';
import type { RotatingLogger } from './log.js';

export interface StartHostOpts {
  config: AppConfig;
  /** agent 静态令牌（host init 生成）。 */
  agentToken: string;
  /** operator 口令哈希（host init 落配置）；缺省 = operator 会话面禁用。 */
  operatorPasswordHash?: string;
  auditPath: string;
  host?: string;
  port?: number;
  hostKeyMode?: HostKeyMode;
  tls?: TlsOptions;
  certFingerprint?: string;
  /** 审批队列目录（缺省平台目录）。 */
  approvalQueueDir?: string;
  approvalQueuePollMs?: number;
  approvalGrantTtlMs?: number;
  /** 守护日志（验收 7）；缺省仅 stderr。 */
  log?: RotatingLogger;
  /** 回收器间隔（测试可缩短），默认 60_000（M6 承重顺序随迁）。 */
  reaperIntervalMs?: number;
}

export interface RunningHost {
  port: number;
  server: RpcHostServer;
  audit: AuditStore;
  stop(): Promise<void>;
}

export async function startHost(opts: StartHostOpts): Promise<RunningHost> {
  const log = (line: string): void => {
    opts.log?.append(line);
    console.error(line);
  };

  const registry = new ConnectionRegistry(opts.config, opts.hostKeyMode ?? 'tofu');
  const policy = new PolicyEngine();
  const audit = new AuditStore(opts.auditPath);

  const mcpServer = new McpServer(
    { name: 'agent-ssh host', version: SERVER_VERSION },
    { capabilities: { tools: {}, resources: {} } },
  );
  registerTools(mcpServer, registry, policy, audit, {
    approvalGrantTtlMs: opts.approvalGrantTtlMs ?? opts.config.defaults.approvalGrantTtlMs,
    approvalSurfaces: opts.config.defaults.approvalSurfaces as ApprovalSurface[],
    approvalQueueDir: opts.approvalQueueDir,
    approvalQueuePollMs: opts.approvalQueuePollMs,
  });
  registerResources(mcpServer, registry);

  const mcpClient = new Client({ name: 'agent-ssh host bridge', version: SERVER_VERSION });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await Promise.all([mcpServer.connect(serverTransport), mcpClient.connect(clientTransport)]);

  // operator 会话表：口令哈希缺省 = 不可知随机口令（等价禁用 operator 面）。
  const sessions = new OperatorSessionStore({
    storedHash: opts.operatorPasswordHash ?? hashPassword(randomBytes(32).toString('base64url')),
  });
  const agentDigests = new Set<string>([tokenDigest(opts.agentToken)]);
  const tables: RpcTables & { agentTokens: Set<string> } = {
    agentTokens: agentDigests,
    sessions,
    imDecisionTokens: new Set<string>(),
  };

  const queueDir = opts.approvalQueueDir;

  const handlers: Record<string, RpcHandler> = {
    // 真实管线桥接：MCP 语义原样（isError/content 结构透传）。
    'tool.call': async (params) => {
      const p = params as { name?: unknown; arguments?: unknown };
      if (typeof p?.name !== 'string') throw new Error('tool.call requires params.name');
      const result = await mcpClient.callTool({ name: p.name, arguments: (p.arguments ?? {}) as never });
      return result;
    },
    'resource.list': async () => {
      const listed = await mcpClient.listResources();
      return { resources: listed.resources };
    },
    'resource.read': async (params) => {
      const p = params as { uri?: unknown };
      if (typeof p?.uri !== 'string') throw new Error('resource.read requires params.uri');
      const read = await mcpClient.readResource({ uri: p.uri });
      return { contents: read.contents };
    },
    'approval.list': async () => {
      const pending = await listPending(queueDir ? { dir: queueDir } : {});
      return { pending };
    },
    'approval.decide': async (params, ctx: RpcHandlerContext) => {
      const p = params as { id?: unknown; decision?: unknown; by?: unknown };
      if (typeof p?.id !== 'string' || (p.decision !== 'approved' && p.decision !== 'rejected')) {
        throw new Error('approval.decide requires params {id, decision: approved|rejected}');
      }
      // approver 语义（§4.4）：面来源 + 操作者。operator 会话的面身份在
      // T-17.5b/T-17.6 登记绑定表；过渡期以 callerClass 标注。
      const by = typeof p.by === 'string' && p.by !== '' ? p.by : ctx.callerClass;
      const outcome = await decideApproval(p.id, p.decision, {
        ...(queueDir ? { dir: queueDir } : {}),
        by,
      });
      return outcome;
    },
    'auth.session.start': async (params) => {
      const p = params as { password?: unknown };
      if (typeof p?.password !== 'string') throw new Error('auth.session.start requires params.password');
      // 失败限速/常时比较在会话表内；异常转结构化错误的策略由 server 通用 catch 承担。
      const started = sessions.start(p.password, 'rpc');
      return { sessionToken: started.ok ? started.token : '' };
    },
    'auth.session.renew': async (_params, ctx: RpcHandlerContext) => {
      // renew 的凭据即信封 auth 成员（会话令牌）——server 在 ctx 携带原文。
      const token = ctx.presentedToken;
      if (token === undefined) throw new Error('auth.session.renew requires the session credential');
      return { renewed: sessions.renew(token) };
    },
    'host.admin.rotateToken': async () => {
      // M9：operator 触发在线轮换。新令牌 Host 生成并加入表（双活宽限——
      // 旧令牌立即吊销的运维语义为设计未尽处，登记 T-16/T-17 装配确认）。
      const fresh = generateAgentToken();
      tables.agentTokens.add(tokenDigest(fresh));
      log('agent token rotated: a new token was issued (old token remains valid until revocation)');
      return { agentToken: fresh };
    },
  };

  const server = new RpcHostServer({
    tables,
    // 内建 hello/ping/toolManifest/approval.subscribe 之外的方法走 handlers；
    // handlers 逐条传给 server 的 handlers 映射（内建优先，见 server.ts 分发序）。
    handlers,
    certFingerprint: opts.certFingerprint,
    audit: (event) => log(`rpc-audit kind=${event.kind} method=${event.method ?? ''}`),
  });
  const port = await server.listen({ host: opts.host ?? '127.0.0.1', port: opts.port ?? 0, tls: opts.tls });
  log(`agent-ssh host ready port=${port} tools=23 resources=3`);

  // ── 资产继承（M6）：60s 回收器（index.ts 原注释随迁，回收顺序承重）──
  const reaperInterval = setInterval(() => {
    void (async () => {
      const conns = registry
        .listConnections()
        .map((info) => registry.get(info.profile))
        .filter((c): c is NonNullable<typeof c> => Boolean(c));
      await Promise.all(conns.map((conn) => conn.reapExpiredSessions().catch(() => {})));
      registry.reapIdleConnections();
    })();
  }, opts.reaperIntervalMs ?? 60_000);

  let stopping = false;
  return {
    port,
    server,
    audit,
    async stop(): Promise<void> {
      if (stopping) return;
      stopping = true;
      clearInterval(reaperInterval);
      // 停机梯（index.ts 继承）：审计先行冲刷 → closeAll 有界（kill 阶梯+余量）。
      try {
        await audit.close();
      } catch (e) {
        log(`audit.close failed: ${e instanceof Error ? e.message : String(e)}`);
      }
      try {
        await Promise.race([
          registry.closeAll(),
          new Promise((resolve) => setTimeout(resolve, 5_000).unref()),
        ]);
      } catch (e) {
        log(`closeAll failed: ${e instanceof Error ? e.message : String(e)}`);
      }
      await mcpClient.close();
      await mcpServer.close();
      await server.close();
    },
  };
}
