// ─── Config Types ───────────────────────────────────────────────────────────

import type { AlgorithmOverride } from './ssh/algorithms.js';
import type { ApprovalSurface } from './guard/approval-queue.js';

export type AuthMethod = 'agent' | 'key' | 'password' | 'keychain';
export type ApprovalMode = 'auto' | 'ask-destructive' | 'ask-all' | 'deny';

/** 目标主机的厂商特性（驱动关分页/提示符处理）。 */
export type DeviceType = 'generic' | 'huawei' | 'h3c' | 'cisco' | 'ruijie';

export interface Profile {
  name: string;
  host: string;
  port: number;
  user: string;
  auth: AuthMethod;
  keyRef?: string;
  keychainEntry?: string;
  via?: string;
  /** 显式策略层级（prod | staging | dev | 自定义）。 */
  group?: string;
  workdir?: string;
  trustedHostKey?: string;
  tty: boolean;
  /** 为主机放宽 FROZEN_ALGORITHMS；对照冻结基线解析。 */
  algorithms?: AlgorithmOverride;
  /** 厂商特性（网络设备兼容）；缺省即 generic。 */
  deviceType?: DeviceType;
  /** 裸 PTY 输出解码；缺省即 utf8。 */
  ptyEncoding?: 'utf8' | 'gbk';
  /** 用解析出的密码回答 keyboard-interactive 提示。 */
  keyboardInteractive: boolean;
  timeout: number;
  maxChars: number;
  maxOutputBytes: number;
  role: string;
  readOnly: boolean;
  approvalPolicy: ApprovalMode;
  cert: boolean;
  /**
    * 在为命令打开的每条通道上向该主机发送 `AI_AGENT=ssh-mcp`。
   *
    * 默认 true。对不受你控制的主机请清除：无论主机是否设置 `AcceptEnv`，
    * 请求都会出现在线上，等于告诉它驱动会话的是 agent 而非真人。
   * agent rather than a person is driving.
   */
  announceAgent: boolean;
  sessionMaxPerConnection: number;
  sessionIdleTimeoutMs: number;
  sessionBackgroundMaxMs: number;
  /** 滚动 24h 窗口内最大命令数；0 = 不限制。 */
  commandQuotaPerDay: number;
  /** 本 profile 单次流式 SFTP 传输的字节上限。 */
  transferMaxBytes: number;
  /** 本 profile 单步流式 SFTP 传输的空闲预算。 */
  transferTimeoutMs: number;
}

export interface Defaults {
  defaultProfile?: string;
  sessionMaxPerConnection: number;
  sessionIdleTimeoutMs: number;
  sessionBackgroundMaxMs: number;
  commandTimeoutMs: number;
  commandMaxChars: number;
  commandMaxOutputBytes: number;
  connectionIdleReapMs: number;
  commandQuotaPerDay: number;
  /** JIT 审批授权的寿命；0 = 每次都提示。 */
  approvalGrantTtlMs: number;
  approvalMode: ApprovalMode;
  /** 人工审批的征求面集合（desktop / im / queue）。 */
  approvalSurfaces: ApprovalSurface[];
  /** dynamic 转发的通用 SOCKS 出网；默认关闭。 */
  allowDynamicForwarding: boolean;
  /**
    * 流式 SFTP 文件工具被限制在内的本地目录。缺省即拒绝——
    * 没有「任意位置」这个设置。
   */
  transferRoot?: string;
  transferMaxBytes: number;
  transferTimeoutMs: number;
  /** 裸 PTY 会话空闲上限（计划第 ③ 层；U3 默认 10 分钟）。 */
  ptySessionIdleTimeoutMs: number;
  /** 裸 PTY 会话生存期上限（计划第 ③ 层；U3 默认 2 小时）。 */
  ptySessionMaxLifetimeMs: number;
  /** 裸 PTY 会话输出保留上限（字节；默认 1MB）。 */
  ptySessionBufferBytes: number;
}

/**
  * 配置文件中可选的 `[policy]` 节，启动时由 mergePolicyRules()
  * 合并到编译期内置的 DEFAULT_RULES 之上。
 *
  * 每个字段都可省，因为合并是增量的：只写 `admin.prod` 的配置
  * 只改矩阵中那一格。
 */
export interface PolicyConfig {
  /** 角色 → 主机组 → 该角色在该层级可运行的命令类别。 */
  roleBindings?: Record<string, Record<string, CommandClass[]>>;
  /**
    * 额外拒绝模式，正则源字符串。追加在内置「永不放行」清单
    * （classifier.ts 的 FORBIDDEN_PATTERNS）之上，后者始终生效——
    * 设置它关不掉那些正统保护。它确实会替换基础 PolicyRules 上的
    * `denylist`（编译期内置默认不设置它）。
   * defaults do not set.
   */
  denylist?: string[];
}

export interface AppConfig {
  defaults: Defaults;
  profiles: Profile[];
  policy?: PolicyConfig;
}

// ─── SSH Connection Types ───────────────────────────────────────────────────

export type ConnectionStatus = 'pending' | 'connected' | 'reconnecting' | 'error' | 'closed';

export interface ConnectionInfo {
  profile: string;
  host: string;
  port: number;
  user: string;
  status: ConnectionStatus;
  sessionCount: number;
  activeChannels: number;
  connectedAt?: Date;
  lastActivity?: Date;
}

// ─── Session Types ──────────────────────────────────────────────────────────

export type SessionType = 'interactive' | 'background';
export type SessionStatus = 'active' | 'disconnected' | 'expired' | 'closed';

export interface SessionOpts {
  name: string;
  type: SessionType;
  command?: string;
  tty?: boolean;
  ttlMs?: number;
}

export interface SessionInfo {
  id: string;
  name: string;
  profile: string;
  type: SessionType;
  status: SessionStatus;
  cwd?: string;
  createdAt: Date;
  lastActivity: Date;
  ttlMs: number;
}

// ─── Command Types ──────────────────────────────────────────────────────────

export type CommandClass = 'read-only' | 'safe' | 'destructive' | 'privileged';

export interface ExecOpts {
  tty?: boolean;
  stdin?: string;
  timeoutMs?: number;
  onProgress?: (bytesReceived: number, recentOutput: string) => void;
  abortSignal?: AbortSignal;
}

export interface CommandResult {
  stdout: string;
  stderr: string;
  exitCode: number;
  durationMs: number;
  cwd?: string;
  sessionId?: string;
  profile: string;
  signal?: string;
}

export interface ParsedCommand {
  binary: string;
  fullCommand: string;
  class: CommandClass;
  /**
    * 仅当 `class` 是 reader 文法拒绝某个 argv 词而产生的最外层 `safe` 时
    * 才设置——嵌套或合成类别把结果抬过 `safe` 时绝不设置，
    * 命令根本不是 reader 时也绝不设置。`binary` 是命中的 `READERS` 键
    * （双词条目即双词前缀）；`word` 是文法不肯接受的 argv 词
    * （操作数计数/`each` 违规时为出问题的操作数；值标志无值可吃时
    * 为标志本身）。
    * 见 `policy/classifier.ts` 的 `classifyCommand`。
   * accept. See `classifyCommand` in `policy/classifier.ts`.
   */
  readOnlyRejection?: { binary: string; word: string };
}

// ─── Policy Types ───────────────────────────────────────────────────────────

export type PolicyDecision = 'allow' | 'deny' | 'require-approval';

export interface PolicyEvaluation {
  decision: PolicyDecision;
  commandClass: CommandClass;
  binary: string;
  ruleId?: string;
  reason?: string;
  /** 拷贝自所解析命令的 `readOnlyRejection`；见 `ParsedCommand`。 */
  readOnlyRejection?: { binary: string; word: string };
}

// ─── Credential Types ───────────────────────────────────────────────────────

export interface ResolvedCredentials {
  password?: string;
  privateKey?: string;
  certificate?: string;
  passphrase?: string;
  sudoPassword?: string;
  agentSocket?: string;
}

// ─── Audit Types ────────────────────────────────────────────────────────────

export interface AuditRecord {
  timestamp: string;
  eventId: string;
  mcpRequestId: string | number;
  profile: string;
  user: string;
  command: string;
  commandClass: CommandClass;
  binary: string;
  decision: PolicyDecision;
  /** 是哪条规则给出的决定（denylist、角色绑定、审批策略……）。 */
  ruleId?: string;
  /** 命令运行在放宽 FROZEN_ALGORITHMS 的 profile 上时为真。 */
  algorithmsOverride?: boolean;
  /** 裸 PTY 输入命中危险模式；列出击中的类别。 */
  ptyAlert?: string;
  exitCode?: number;
  durationMs?: number;
  approver?: string;
  error?: string;
}

// ─── Tool Types ─────────────────────────────────────────────────────────────

export interface ToolContext {
  requestId: string | number;
  profile?: string;
  session?: string;
}

// ─── SFTP Types ─────────────────────────────────────────────────────────────

export interface SftpUploadOpts {
  profile?: string;
  remotePath: string;
  content: string | Buffer;
  mode?: number;
}

export interface SftpDownloadOpts {
  profile?: string;
  remotePath: string;
  /** 下载字节上限。默认取 profile 的 maxOutputBytes。 */
  maxBytes?: number;
}

export interface SftpStat {
  path: string;
  size: number;
  mode: number;
  isDirectory: boolean;
  isFile: boolean;
  mtime: Date;
  atime: Date;
}
