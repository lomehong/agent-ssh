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
import { listPending, listDecided, decideApproval, type ApprovalSurface } from '../guard/approval-queue.js';
import { acquirePidfile } from '../rpc/pidfile.js';
import { generateAgentToken, hashPassword, tokenDigest, OperatorSessionStore } from '../rpc/auth.js';
import { RpcHostServer, type RpcHandler, type RpcHandlerContext } from '../rpc/server.js';
import { ChallengeStore } from '../rpc/challenge.js';
import type { RpcTables } from '../rpc/authorize.js';
import { SERVER_VERSION } from '../version.js';
import { registerResources, registerTools } from '../tools/registry.js';
import { AuditStore } from '../audit/store.js';
import { queryAudit, auditStats } from '../audit/query.js';
import { listProfiles } from '../config/profiles-edit.js';
import { PolicyEngine } from '../policy/engine.js';
import { CommandQuota } from '../policy/quota.js';
import { classifyCommand, findForbiddenMatch } from '../policy/classifier.js';
import { redactText } from '../guard/redactor.js';
import { ConnectionRegistry } from '../ssh/connection-registry.js';
import { initKeychain } from '../config/credential-resolver.js';
import { scanHosts, configureHost, removeHost, loadDeployment } from '../agents/index.js';
import type { HostKeyMode } from '../ssh/host-key.js';
import type { AppConfig } from '../types.js';
import { ImBot } from '../im/bot.js';
import { SdkLarkPort } from '../im/port.js';
import { RotatingLogger } from './log.js';

export interface StartHostOpts {
  config: AppConfig;
  /** agent 静态令牌（host init 生成）。 */
  agentToken: string;
  auditPath: string;
  /** Host 配置文件路径（T-21e 口令轮换写回目标）。 */
  configFilePath: string;
  host?: string;
  port?: number;
  hostKeyMode?: HostKeyMode;
  tls?: TlsOptions;
  certFingerprint?: string;
  /** 审批队列目录（缺省平台目录）。 */
  approvalQueueDir?: string;
  approvalQueuePollMs?: number;
  approvalGrantTtlMs?: number;
  /** 守护日志（验收 7）：提供 logFile 即 RotatingLogger 落盘+stderr 双写；缺省仅 stderr。 */
  logFile?: string;
  /** pidfile 路径（验收 6）：提供即单实例强制（活实例存在 → fail-fast）。 */
  pidfilePath?: string;
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
  // 验收 6/7 接线：pidfile 单实例强制（活实例即 fail-fast）与守护日志落盘
  // （RotatingLogger+stderr 双写）。缺省不启用——生产缺省路径随 T-16 进程包装定。
  const pidHandle = opts.pidfilePath !== undefined ? acquirePidfile(opts.pidfilePath) : undefined;
  const rotating = opts.logFile !== undefined
    ? new RotatingLogger({ file: opts.logFile })
    : undefined;
  const log = (line: string): void => {
    rotating?.append(line);
    console.error(line);
  };

  // OS 密钥链初始化（T-20 部署实测修复）：v2 重写入口时上游 WD-1 的
  // initKeychain 接线被静默丢失——keychain 型 profile 从此全部
  // 「returned nothing」。测试全用 password/env 故从未暴露。
  await initKeychain();
  const registry = new ConnectionRegistry(opts.config, opts.hostKeyMode ?? 'tofu');
  const policy = new PolicyEngine();
  const configFilePath = opts.configFilePath;
  const audit = new AuditStore(opts.auditPath);

  const mcpServer = new McpServer(
    { name: 'agent-ssh host', version: SERVER_VERSION },
    { capabilities: { tools: {}, resources: {} } },
  );

  const queueDir = opts.approvalQueueDir;
  // 校验码库（T-17.5b，D10/K8-②）：破坏性类入队即生成，decide 携码单次校验。
  const challenges = new ChallengeStore();

  // server 句柄提升：推送回调运行时 hub 已就绪（listen 后才会触发）。
  let serverRef: RpcHostServer | undefined;

  // 审批 decide 核心（RPC handler 与飞书 bot 共用，T-17.6 抽取）：
  // 校验码面分流（desktop/im 携码；cli 兜底免码）→ decideApproval（K7
  // 队列内串行化）→ 码吊销 + settled 推送 + bot 卡片收尾。face 由调用点
  // 固定：RPC 客户端声明（不可全信但 callerClass 留痕）、bot 进程内恒 'im'。
  const decideApprovalRequest = async (input: {
    id: string;
    decision: 'approved' | 'rejected';
    by?: string;
    face?: string;
    challenge?: string;
  }): Promise<{ decided: boolean; message: string }> => {
    const { id, decision } = input;
    // 校验码只属于 IM 面（码在手机上，agent 够不着——那是它唯一的价值）。
    // 桌面/CLI 免码（主人 2026-10-17 裁决：弹窗就在操作者自己屏幕上，
    // 码=「验证我是我」伪需求；且 D15 下码对本地 agent 本就不保密——
    // approval.pending 推送载荷明文带码）。拒绝永远免验（安全方向操作）。
    if (decision === 'approved' && input.face === 'im' && challenges.hasPendingChallenge(id)) {
      const code = input.challenge ?? '';
      {
        const verified = challenges.verify(id, code);
        if (!verified.ok) {
          // reason 细类进审计不入客户端消息（可探测码状态，评审 jc7）。
          await audit
            .record({
              mcpRequestId: 0,
              profile: '(approval-decide)',
              user: '(operator)',
              command: redactText(`approval.decide ${id}`),
              commandClass: 'safe',
              binary: 'approval.decide',
              decision: 'deny',
              ruleId: 'challenge-rejected',
              error: `challenge ${verified.reason ?? 'invalid'}`,
              approver: 'cli-direct',
            })
            .catch(() => {});
          throw new Error('CHALLENGE_REJECTED: challenge invalid');
        }
      }
    }
    // 评审 T-21 实现 A4：by 前缀白名单（desktop:/cli:/im:/agent:）——
    // 无前缀/未知前缀的自报一律落 'agent:unknown'。D15 单令牌模型下连接内
    // 人/agent 不可区分（主人知情接受），白名单至少保证决定文件与审计的
    // decidedBy 形态统一可解析，杜绝任意串污染追责链。
    const rawBy = input.by && input.by !== '' ? input.by : '';
    const by = /^(desktop|cli|im|agent):.+/.test(rawBy) ? rawBy : 'agent:unknown';
    const outcome = await decideApproval(id, decision, {
      ...(queueDir ? { dir: queueDir } : {}),
      by,
    });
    // settled 推送 + 未消费码吊销（他面已决定时码即作废）+ bot 卡片收尾。
    challenges.revoke(id);
    serverRef?.hub.publish('approval.settled', { id, decision, approved: outcome.decided });
    void imBot?.settled(id, decision, by);
    return outcome;
  };

  // 飞书 bot 面（T-17.6）：surfaces 含 'im' 且 [im] 配置在场即装配；
  // 缺席由 loader 启动期拒绝，此处防御性兜底。独立 error domain 在 bot
  // 内部（K5）：WS/发送异常审计 im.unreachable，绝不拖垮 Host。
  let imBot: ImBot | undefined;
  if ((opts.config.defaults.approvalSurfaces as ApprovalSurface[]).includes('im')) {
    const imCfg = opts.config.im;
    if (imCfg === undefined) {
      throw new Error('approvalSurfaces includes "im" but config has no [im] section (appId/appSecret/allowedUsers)');
    }
    imBot = new ImBot(imCfg, {
      port: new SdkLarkPort(imCfg.appId, imCfg.appSecret),
      decide: decideApprovalRequest,
      listPending: () => listPending(queueDir ? { dir: queueDir } : {}),
      auditUnreachable: (context, err) => {
        const message = err instanceof Error ? err.message : String(err);
        log(`im.unreachable ${context}: ${message}`);
        void audit
          .record({
            mcpRequestId: 0,
            profile: '(im)',
            user: '(operator)',
            command: redactText(`im ${context}`),
            commandClass: 'safe',
            binary: 'im:bot',
            decision: 'deny',
            ruleId: 'im-unreachable',
            error: message,
            approver: 'im-surface',
          })
          .catch(() => {});
      },
      log: (line) => log(`im ${line}`),
    });
  }

  // 审批推送桥（T-17.5b）：pipeline 入队 → hub.publish（approval.pending）。
  // 破坏性/特权类生成 4 位校验码随推送下发（仅窗口可见，D10/K8-②）；
  // T-17.6：同一 payload 直发飞书 bot（IM 面的码即卡片，§4.2）。
  const onApprovalQueued = (payload: {
    id: string;
    profile: string;
    command: string;
    commandClass: string;
    expiresAt: string;
  }): void => {
    const challenge =
      payload.commandClass === 'destructive' || payload.commandClass === 'privileged'
        ? challenges.generate(payload.id)
        : undefined;
    serverRef?.hub.publish('approval.pending', { ...payload, ...(challenge ? { challenge } : {}) });
    void imBot?.notifyPending(payload, challenge);
    log(`approval.push id=${payload.id} class=${payload.commandClass}${challenge ? ' challenge=****' : ''}${imBot ? ' surfaces=hub+im' : ''}`);
  };

  // 配额实例 Host 级持有（T-21d）：同实例入管线（计数）+ 快照面（读取）。
  const quota = new CommandQuota();
  registerTools(mcpServer, registry, policy, audit, {
    approvalGrantTtlMs: opts.approvalGrantTtlMs ?? opts.config.defaults.approvalGrantTtlMs,
    approvalSurfaces: opts.config.defaults.approvalSurfaces as ApprovalSurface[],
    approvalQueueDir: opts.approvalQueueDir,
    approvalQueuePollMs: opts.approvalQueuePollMs,
    onApprovalQueued,
    quota,
  });
  registerResources(mcpServer, registry);

  const mcpClient = new Client({ name: 'agent-ssh host bridge', version: SERVER_VERSION });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await Promise.all([mcpServer.connect(serverTransport), mcpClient.connect(clientTransport)]);

  // operator 会话表：口令哈希缺省 = 不可知随机口令（等价禁用 operator 面）。
  const sessions = new OperatorSessionStore({
    storedHash: hashPassword(randomBytes(32).toString('base64url')),
  });
  const agentDigests = new Set<string>([tokenDigest(opts.agentToken)]);
  const tables: RpcTables & { agentTokens: Set<string> } = {
    agentTokens: agentDigests,
    sessions,
    imDecisionTokens: new Set<string>(),
  };

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
    'audit.query': async (params) => {
      // T-21c：审计过滤查询（operator 面；审计写入侧已脱敏，按存储原样出）。
      const p = (params ?? {}) as { offsetTail?: unknown; limit?: unknown; filter?: Record<string, unknown> };
      const f = p.filter ?? {};
      return queryAudit({
        auditPath: opts.auditPath,
        filter: {
          ...(typeof f.profile === 'string' && f.profile !== '' ? { profile: f.profile } : {}),
          ...(typeof f.commandClass === 'string' && f.commandClass !== '' ? { commandClass: f.commandClass } : {}),
          ...(typeof f.decision === 'string' && f.decision !== '' ? { decision: f.decision } : {}),
          ...(typeof f.ruleId === 'string' && f.ruleId !== '' ? { ruleId: f.ruleId } : {}),
          ...(typeof f.keyword === 'string' && f.keyword !== '' ? { keyword: f.keyword } : {}),
          ...(typeof f.timeFrom === 'string' && f.timeFrom !== '' ? { timeFrom: f.timeFrom } : {}),
          ...(typeof f.timeTo === 'string' && f.timeTo !== '' ? { timeTo: f.timeTo } : {}),
        },
        ...(typeof p.offsetTail === 'number' ? { offsetTail: p.offsetTail } : {}),
        ...(typeof p.limit === 'number' ? { limit: p.limit } : {}),
      });
    },
    'audit.stats': async () => auditStats(opts.auditPath),
    'host.connections': async () => {
      // T-21d：连接/会话状态投影（registry 只读）。
      return {
        connections: registry.listConnections().map((info) => {
          const conn = registry.get(info.profile);
          return {
            ...info,
            sessions: conn?.listSessions?.().length ?? 0,
            ptySessions: conn?.listPtySessions?.().length ?? 0,
          };
        }),
      };
    },
    'quota.snapshot': async () => {
      // T-21d：每 profile 当日（滚动 24h）配额用量快照。
      return {
        quotas: opts.config.profiles.map((p) => ({
          profile: p.name,
          used: quota.used(p.name),
          limit: p.commandQuotaPerDay,
        })),
      };
    },
    'approval.history': async (params) => {
      // T-21b：已决/过期审批流水（operator 面便利视图；法律级留痕仍在审计）。
      const p = (params ?? {}) as { limit?: unknown; offset?: unknown };
      const page = listDecided({
        ...(queueDir ? { dir: queueDir } : {}),
        ...(typeof p.limit === 'number' ? { limit: p.limit } : {}),
        ...(typeof p.offset === 'number' ? { offset: p.offset } : {}),
      });
      return page;
    },
    'list_pending': async () => {
      // T-23 弹窗补拉：未决请求清单（破坏性/特权类附存活校验码——弹窗错过
      // 推送时仍可完成校验码批准；码单次有效性不受影响）。
      const pending = await listPending(queueDir ? { dir: queueDir } : {});
      return {
        pending: pending
          .filter((p) => p.status === 'pending')
          .map((p) => {
            const needsChallenge = p.commandClass === 'destructive' || p.commandClass === 'privileged';
            const code = needsChallenge ? challenges.get(p.id) : undefined;
            return code !== undefined ? { ...p, challenge: code } : p;
          }),
      };
    },
    'approval.decide': async (params, ctx: RpcHandlerContext) => {
      const p = params as {
        id?: unknown;
        decision?: unknown;
        by?: unknown;
        challenge?: unknown;
        /** 决定面声明：desktop/im 携码校验；cli 兜底免码（人已在 shell）。 */
        face?: unknown;
      };
      if (typeof p?.id !== 'string' || (p.decision !== 'approved' && p.decision !== 'rejected')) {
        throw new Error('approval.decide requires params {id, decision: approved|rejected}');
      }
      // approver 语义（§4.4）：面来源 + 操作者。operator 会话的面身份在
      // T-17.5b/T-17.6 登记绑定表；过渡期以 callerClass 标注。
      const by = typeof p.by === 'string' && p.by !== '' ? p.by : ctx.callerClass;
      return decideApprovalRequest({
        id: p.id,
        decision: p.decision,
        by,
        face: typeof p.face === 'string' ? p.face : '',
        ...(typeof p.challenge === 'string' ? { challenge: p.challenge } : {}),
      });
    },
    'host.status': async () => {
      // T-21e：审批面在线态 + 版本聚合（只读）。
      return {
        version: SERVER_VERSION,
        surfaces: (opts.config.defaults.approvalSurfaces as ApprovalSurface[]).map((s) => ({
          surface: s,
          online: s === 'im' ? (imBot?.connected ?? false) : s === 'desktop' ? server.connectionCount > 0 : true,
        })),
        queueDir: queueDir ?? '(platform default)',
        port,
      };
    },
    'host.profiles.list': async () => {
      // T-22 主机管理：config 内 profile 只读投影（不含凭证）。
      return { profiles: listProfiles(configFilePath) };
    },
    'host.profiles.upsert': async (params) => {
      // T-22：新增/编辑主机（密码→凭据管理器；结构化 TOML 改写+备份+校验+回滚）。
      const p = (params ?? {}) as Record<string, unknown>;
      const input = {
        name: String(p.name ?? ''),
        host: String(p.host ?? ''),
        port: typeof p.port === 'number' ? p.port : Number.parseInt(String(p.port ?? '22'), 10),
        user: String(p.user ?? ''),
        auth: (p.auth === 'key' ? 'key' : 'password') as 'key' | 'password',
        ...(typeof p.password === 'string' && p.password !== '' ? { password: p.password } : {}),
        ...(typeof p.keyRef === 'string' && p.keyRef !== '' ? { keyRef: p.keyRef } : {}),
        ...(typeof p.group === 'string' && p.group !== '' ? { group: p.group } : {}),
      };
      const { upsertProfile } = await import('../config/profiles-edit.js');
      const { Entry } = await import('@napi-rs/keyring');
      const result = upsertProfile(configFilePath, input);
      if (input.auth === 'password') {
        const target = (await import('../config/profiles-edit.js')).keychainTarget(input.name);
        new Entry(target.service, target.account).setPassword(input.password ?? '');
      }
      return { ...result, note: '配置已写入。Host 需重启后生效（设置页可一键重启）。' };
    },
    'host.profiles.remove': async (params) => {
      const p = (params ?? {}) as { name?: unknown };
      if (typeof p.name !== 'string') throw new Error('host.profiles.remove requires params.name');
      const { removeProfile } = await import('../config/profiles-edit.js');
      return removeProfile(configFilePath, p.name);
    },
    'agents.scan': async () => {
      // T-21g：本机宿主识别（安装指纹扫描，只读）。
      return { hosts: scanHosts() };
    },
    'agents.configure': async (params) => {
      // T-21g：一键接入（结构化改写+备份+回读校验+回滚，纪律 §2.6）。
      const p = (params ?? {}) as { id?: unknown };
      if (typeof p.id !== 'string') throw new Error('agents.configure requires params.id');
      const dep = loadDeployment();
      return configureHost(p.id as Parameters<typeof configureHost>[0], dep);
    },
    'agents.remove': async (params) => {
      const p = (params ?? {}) as { id?: unknown };
      if (typeof p.id !== 'string') throw new Error('agents.remove requires params.id');
      return removeHost(p.id as Parameters<typeof removeHost>[0]);
    },
    'host.admin.rotateToken': async () => {
      // M9：operator 触发在线轮换。新令牌 Host 生成并加入表（双活宽限——
      // 旧令牌立即吊销的运维语义为设计未尽处，登记 T-16/T-17 装配确认）。
      const fresh = generateAgentToken();
      tables.agentTokens.add(tokenDigest(fresh));
      log('agent token rotated: a new token was issued (old token remains valid until revocation)');
      return { agentToken: fresh };
    },
    'cli.info': async (params) => {
      // T-17（D4）：operator 面的连接/profile 信息——无 SSH 触达，纯注册表读。
      const p = params as { profile?: unknown };
      const profileName = typeof p?.profile === 'string' ? p.profile : undefined;
      const profile = registry.getProfile(profileName);
      const conn = registry.get(profile.name);
      return {
        profile: {
          name: profile.name,
          user: profile.user,
          host: profile.host,
          port: profile.port,
          auth: profile.auth,
          keyRef: profile.keyRef,
          role: profile.role,
          group: profile.group,
          deviceType: profile.deviceType,
          algorithms: profile.algorithms ? Object.keys(profile.algorithms) : null,
          approvalPolicy: profile.approvalPolicy,
        },
        connected: conn?.isConnected?.() ?? false,
        sessions: conn?.listSessions?.().length ?? 0,
        ptySessions: conn?.listPtySessions?.().length ?? 0,
      };
    },
    'cli.run': async (params, ctx: RpcHandlerContext) => {
      // D4 语义桥（cli-direct 移植）：人即批准者——无审批门；分类、禁止名单、
      // redact 与审计（approver=cli-direct）全部保持，审计增 rpcCallerClass。
      const p = params as { command?: unknown; profile?: unknown };
      if (typeof p?.command !== 'string' || p.command.trim() === '') {
        throw new Error('cli.run requires params.command');
      }
      const command = p.command;
      // 禁止名单先于一切（T-13 High-1 整改语义随迁）：红线优先于配置与执行。
      // 可审计点保留（评审 T-17 jc3）：Host 持有 AuditStore，拒绝亦留痕。
      const forbidden = findForbiddenMatch(command);
      if (forbidden !== null) {
        await audit
          .record({
            mcpRequestId: 0,
            profile: '(forbidden-before-profile)',
            user: '(operator)',
            command: redactText(command),
            commandClass: 'safe',
            binary: 'cli:run',
            decision: 'deny',
            ruleId: 'cli-direct-forbidden',
            error: `forbidden pattern: ${forbidden}`,
            approver: 'cli-direct',
          })
          .catch(() => {});
        throw new Error(`FORBIDDEN_PATTERN: ${forbidden} — 禁止名单对人工与模型一视同仁；确需此类操作请在服务器 shell 上自行评估执行。`);
      }
      const profileName = typeof p.profile === 'string' ? p.profile : undefined;
      const profile = registry.getProfile(profileName);
      try {
        const conn = await registry.getOrCreate(profile.name);
        const parsed = classifyCommand(command);
        const result = await conn.exec(command);
        await audit.record({
          mcpRequestId: 0,
          profile: profile.name,
          user: profile.user,
          command: redactText(command),
          commandClass: parsed.class,
          binary: parsed.binary,
          decision: 'allow',
          ruleId: 'cli-direct',
          exitCode: result.exitCode,
          durationMs: result.durationMs,
          approver: 'cli-direct',
          rpcCallerClass: ctx.callerClass === 'operator' ? 'operator' : undefined,
        });
        return {
          stdout: result.stdout,
          stderr: result.stderr,
          exitCode: result.exitCode,
          durationMs: result.durationMs,
          profile: profile.name,
          commandClass: parsed.class,
        };
      } catch (err) {
        // cli-direct catch 语义随迁：失败也留 deny 审计（redact 后），错误
        // 转结构化拒绝直传 CLI（redact 防 profile 错误消息夹带秘密）。
        const message = err instanceof Error ? err.message : String(err);
        await audit
          .record({
            mcpRequestId: 0,
            profile: profile.name,
            user: profile.user,
            command: redactText('cli-run'),
            commandClass: 'safe',
            binary: 'cli:run',
            decision: 'deny',
            ruleId: 'cli-direct-error',
            error: redactText(message),
            approver: 'cli-direct',
          })
          .catch(() => {});
        throw new Error(`cli-run failed on "${profile.name}": ${redactText(message)}`);
      }
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
  serverRef = server;
  log(`agent-ssh host ready port=${port} tools=23 resources=3`);
  // IM 面异步非阻塞启动（K5）：WS 连接与补偿推送不挡 ready 行；
  // 失败仅审计降级，Host 其余面照常。
  if (imBot !== undefined) void imBot.start();

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
      pidHandle?.release();
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
