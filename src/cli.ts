/**
 * 命令行：argv 到 AppConfig。
 *
 * 从 index.ts 拆出，后者在导入时运行 main()，除非
 * SSH_MCP_DISABLE_MAIN=1 已设*且* SSH_MCP_TEST 不是 1——
 * 该门是或逻辑，测试变量覆盖禁用变量。这使得每个纯 argv
 * 助手的测试都可能在一台有真实配置的机器上连上真实主机；
 * 其中一个为此带了六行注释和 vi.stubEnv，拆分后两者都删了。
 * 本文件没有任何导入时副作用，导入是安全的。
 * time, so importing it is safe.
 *
 * 并非一切 argv 形状的代码都在这里：index.ts 仍在接线处读取
 * transport、OTEL 与 OPA 标志。搬走的是必须脱离启动门才能测试的部分。
 * escape the boot gate to be testable.
 */

import { loadConfig, getConfigPath } from './config/loader.js';
import { OperatorError, ConfigNotFoundError, UnconfiguredError } from './errors.js';
import type { AclFinding } from './config/windows-acl.js';
import { HOST_GROUPS } from './policy/engine.js';
import type { HostKeyMode } from './ssh/host-key.js';
import type { AppConfig, Profile, Defaults } from './types.js';
import { listPending, decideApproval, type PendingApproval } from './guard/approval-queue.js';

/**
 * 运维是否要求了快速启动。
 *
 * 看「存在」而非真值——正是 flagEnabled 为 #91 写的同一个坑。
 * parseArgv 对不带 = 的标志存 null、丢掉裸词，因此空格分隔、
 * 单独的 --host、以及 --host= --user= 都产出假值但标志明明给了。
 * 测真值让他们全都走了软路径：服务器启动、看似健康，解释只在
 * MCP 客户端通常吞掉的 stderr 上。「什么都没要求」才软处理；
 * 半给或空值的快速启动是笔误，仍然拒绝。
 * on a stderr stream an MCP client typically swallows. Only "asked for nothing" softens;
 * a half-given or empty-valued quick start is a typo and still refuses.
 */
function nothingRequested(argv: Record<string, string | null>): boolean {
  return !('host' in argv) && !('user' in argv);
}

export function parseArgv(args: string[] = process.argv.slice(2)): Record<string, string | null> {
  const config: Record<string, string | null> = {};
  for (const arg of args) {
    if (arg.startsWith('--')) {
      const eq = arg.indexOf('=');
      if (eq === -1) {
        config[arg.slice(2)] = null;
      } else {
        config[arg.slice(2, eq)] = arg.slice(eq + 1);
      }
    }
  }
  return config;
}

/**
 * 布尔标志是否被传入过。
 *
 * parseArgv 对不带 = 的标志存 null，这正是一切文档化布尔标志
 * 的写法。对值测真值让标志变成空操作：--disableApproval、
 * --auditEntropyScan 和 --auditTamperEvident 全都无效，
 * 除非写成 --flag=1，而没有任何文档这样做（#91）。
 * 已有的两处正确调用用的是 !== undefined；这里给检查命名，
 * 下一个就不会漏。
 *
 * --flag=false 和 --flag=0 表示关闭，因为写进包装脚本后
 * 无法关闭的标志本身就是麻烦。
 */
/**
 * --authFailureLimit，拒绝而非猜。
 *
 * parseArgv 对不带值的标志存 null，而 null !== undefined，
 * 裸 --authFailureLimit 到达 parseInt 产生 NaN。NaN 过不了
 * 传输层决定是否构建限流器的 > 0 测试，于是拼写错误——或
 * --authFailureLimit=off（0 = off 使其看似合理）——静默关闭了
 * 一个默认开启的控制，启动横幅上无一行提及。--rateLimit 上
 * 同样的形状无害因为那个默认就是关的；这个不是，
 * 这就是 fail-open 成为新问题的原因。
 */
export function parseFailureLimit(raw: string | null | undefined): number | undefined {
  if (raw === undefined) return undefined;
  if (raw === null || !/^\d+$/.test(raw.trim())) {
    throw new OperatorError(
      `--authFailureLimit needs a non-negative whole number, got ${JSON.stringify(raw)}. ` +
      'Use --authFailureLimit=0 to turn the check off deliberately.',
    );
  }
  const value = Number(raw.trim());
  // 有界，因为无界就是本守卫要阻止的 fail-open：
  // --authFailureLimit=99999999999999999999 解析为 1e20，一个永不清空的桶
  // 加 Retry-After 为 1——配置为开，功能上缺席。
  if (!Number.isSafeInteger(value) || value > MAX_AUTH_FAILURE_LIMIT) {
    throw new OperatorError(
      `--authFailureLimit must be between 0 and ${MAX_AUTH_FAILURE_LIMIT}, got ${JSON.stringify(raw)}.`,
    );
  }
  return value;
}

/** `--httpSessionTtl`, refusing values that would silently disable idle eviction. */
export function parseHttpSessionTtl(raw: string | null | undefined): number | undefined {
  if (raw === undefined) return undefined;
  if (raw === null || !/^\d+$/.test(raw.trim())) {
    throw new OperatorError(
      `--httpSessionTtl needs a positive whole number of milliseconds, got ${JSON.stringify(raw)}.`,
    );
  }
  const value = Number(raw.trim());
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new OperatorError(
      `--httpSessionTtl must be a positive safe integer, got ${JSON.stringify(raw)}.`,
    );
  }
  return value;
}

/** Far above any real budget; the point is that there is one. */
const MAX_AUTH_FAILURE_LIMIT = 10_000;

export function flagEnabled(argv: Record<string, string | null>, name: string): boolean {
  if (!(name in argv)) return false;
  const value = argv[name];
  if (value === null || value === '') return true;
  return !['false', '0', 'no', 'off'].includes(value.toLowerCase());
}

/**
 * v2 已移除的 v1 标志。静默忽略意味着用户到第一条命令时才发现，
 * 表现为无缘由的认证失败。
 */
const REMOVED_V1_FLAGS: Record<string, string> = {
  password: 'Use the SSH_MCP_PASSWORD env var (or a per-profile SSH_MCP_<PROFILE>_PASSWORD).',
  suPassword: 'Use the SSH_MCP_SUDO_PASSWORD env var.',
  sudoPassword: 'Use the SSH_MCP_SUDO_PASSWORD env var.',
  disableSudo: 'Sudo is now a separate tool; restrict it with a role/policy that disallows the "privileged" class.',
};

export function checkRemovedFlags(argv: Record<string, string | null>): void {
  const found = Object.keys(REMOVED_V1_FLAGS).filter((f) => f in argv);
  if (found.length === 0) return;
  throw new OperatorError(
    'These flags were removed in v2:\n' +
    found.map((f) => `  --${f}: ${REMOVED_V1_FLAGS[f]}`).join('\n') +
    '\nSee the "Migrating from v1" section of the README.',
  );
}

/**
 * v1 将 --maxChars=none（及 0/负数）文档化为「不限制」。
 * 用 parseInt(...) || 5000 解析会静默将其变成 5000 字符上限。
 */
export function parseMaxChars(raw: string | null | undefined): number {
  if (typeof raw !== 'string' || raw === '') return 5_000;
  if (raw.toLowerCase() === 'none') return Number.MAX_SAFE_INTEGER;
  const parsed = parseInt(raw);
  if (isNaN(parsed)) return 5_000;
  return parsed <= 0 ? Number.MAX_SAFE_INTEGER : parsed;
}

/**
 * --opaTimeoutMs，两侧皆有界。
 *
 * 太低：sidecar 稍慢时，显式 OPA 拒绝变成放行——正是此预算所在
 * 的 fail-open；太高则恢复了它替代的挂起。下限一秒，上限两分钟。
 * second is the floor and two minutes the ceiling.
 */
export function parseOpaTimeout(raw: string | null | undefined): number | undefined {
  if (raw === undefined) return undefined;
  const value = raw === null ? NaN : Number(raw.trim());
  if (!Number.isSafeInteger(value) || value < 1_000 || value > 120_000) {
    throw new OperatorError(
      `--opaTimeoutMs must be a whole number of milliseconds between 1000 and 120000, got ${JSON.stringify(raw)}.`,
    );
  }
  return value;
}

/**
 * --opaUrl，在启动时而非每次请求时拒绝。
 *
 * 只查了空，fetch 无法使用的任何值都到达引擎、每次调用失败——
 * 启动打印 OPA sidecar enabled，每分钟一行 stderr 是唯一信号。
 * --opaUrl=localhost:8181 是现实的失误：OPA 自己的 --addr 写作 :8181，
 * 默认模式下留下一扇看似配置、从不被询问的门。URL 中的凭据也拒绝：
 * fetch 直接拒收这种 URL，那会是一扇根本无法工作的门。
 * rejects such a URL outright, so it would be a gate that cannot work at all.
 */
export function parseOpaUrl(raw: string | null | undefined): string {
  if (!raw) {
    throw new OperatorError('--opaUrl needs a URL, as --opaUrl=http://localhost:8181.');
  }
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new OperatorError(
      `--opaUrl=${raw} is not a URL. Include the scheme, as --opaUrl=http://localhost:8181.`,
    );
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new OperatorError(`--opaUrl must be http or https, got ${parsed.protocol}`);
  }
  if (parsed.username || parsed.password) {
    throw new OperatorError(
      '--opaUrl must not embed credentials — fetch() refuses such a URL, so the gate would ' +
      'never be consulted. Put the sidecar behind a network boundary instead.',
    );
  }
  // 尾随斜杠会让请求路径变成 //v1/data/...。
  return (parsed.origin + parsed.pathname).replace(/\/$/, '');
}

/**
 * strict 之前不可达：除测试代码无人能选中它，而 host-key.ts 让用户
 * 找一个从不存在的 --acceptNewHostKey 标志。--insecureHostKey
 * 保留为文档化标志的别名。
 */
export function resolveHostKeyMode(argv: Record<string, string | null>): HostKeyMode {
  if (flagEnabled(argv, 'insecureHostKey')) return 'insecure';
  const mode = argv.hostKeyMode;
  if (mode === null || mode === undefined) return 'tofu';
  if (mode === 'tofu' || mode === 'strict' || mode === 'insecure') return mode;
  throw new OperatorError(`Invalid --hostKeyMode=${mode}. Expected one of: tofu, strict, insecure.`);
}

/**
 * CLI 配置的主机属于哪个策略层级。
 *
 * 没有它就无法从命令行表达。内联 profile 不带 group，
 * 落到最严格层级，admin 角色在那里没有 privileged——
 * 没写配置文件的任何人 sudo 都跑不了（#91）。
 * who had not written a config file (#91).
 *
 * 默认保持 prod。对未知主机猜生产是安全方向；缺的是纠正猜错的方式。
 * direction; what was missing was a way to correct the guess.
 */
export function resolveHostGroup(argv: Record<string, string | null>): string {
  const group = argv.group;
  if (group === null || group === undefined) return 'prod';
  if ((HOST_GROUPS as readonly string[]).includes(group)) return group;
  // 落空会把 prod 绑定静默套在一个拼写错误上，
  // 运维会把拒绝读成策略，而不是自己的失误。
  throw new OperatorError(
    `Invalid --group=${group}. Expected one of: ${HOST_GROUPS.join(', ')}.`,
  );
}

/**
 * 快速启动 profile 仅从标志继承的默认值。
 *
 * 之所以命名，是因为未配置的启动也需要它们——approvalGrantTtlMs
 * 在接线工具时读取，远早于任何 profile 存在，两条路径必须一致。
 */
export function defaultsFromArgv(argv: Record<string, string | null>): Defaults {
  return {
    sessionMaxPerConnection: parseInt(argv.sessionMax as string) || 5,
    sessionIdleTimeoutMs: parseInt(argv.sessionTtl as string) || 600_000,
    sessionBackgroundMaxMs: 3_600_000,
    commandTimeoutMs: parseInt(argv.timeout as string) || 60_000,
    commandMaxChars: parseMaxChars(argv.maxChars),
    commandMaxOutputBytes: 1_048_576,
    connectionIdleReapMs: 900_000,
    commandQuotaPerDay: parseInt(argv.commandQuota as string) || 200,
    approvalGrantTtlMs: parseInt(argv.approvalGrantTtl as string) || 0,
    approvalMode: 'ask-destructive',
    approvalChannel: 'both',
    allowDynamicForwarding: false,
    ptySessionBufferBytes: 1_048_576,
    // 刻意不为 transferRoot 提供标志。它是对触碰本地磁盘的同意，
    // 而快速启动路径是为在命令行传了主机和用户的人准备的——
    // 不是顺路获取同意的地方。流式文件工具因此在 --host/--user 下
    // 持续拒绝，直到配置文件指名一个根目录。
    // config file names a root.
    transferMaxBytes: 268_435_456,
    transferTimeoutMs: 300_000,
    ptySessionIdleTimeoutMs: 600_000,
    ptySessionMaxLifetimeMs: 7_200_000,
  };
}

export async function buildAppConfig(argv: Record<string, string | null>): Promise<AppConfig> {
  // 绕过无法读取的 ACL 的方式，而非运维无路可走。
  // 接收器在此提供而非留给模块默认——这正是有默认的意义：
  // 「这条安全检查没跑」是关于必须告诉运维什么的决定，
  // loader 不是拥有该决定的层。
  // operator must be told, and the loader is not the layer that owns that. Routing it to
  // the audit store as well needs an AuditRecord variant for a startup event — that type
  // is hash-chained and tamper-evident, so it is its own change, and it is queued.
  //
  // 更早版本还把每条发现推入模块级数组「让 main() 能处理」。
  // 无人读过它，拆分让这种说法不可能——main() 在另一个模块，
  // 数组未导出。有消费者可写时重新加收集点只要一行。
  // one line when there is a consumer to write it against.
  const aclOpts = {
    enforce: flagEnabled(argv, 'strictConfigAcl'),
    allowUnchecked: flagEnabled(argv, 'allowUncheckedConfigAcl'),
    onFinding: (f: AclFinding) => {
      console.error(`Warning: ${f.message}`);
    },
  };

  if (argv.config !== undefined) {
    // parseArgv 对不带 = 的标志存 null，裸 --config 在此曾为假值
    // 落入默认路径分支——现在该分支拒绝而非静默忽略不可用文件，
    // 运维得到一个指名从未要求的路径的拒绝。
    // never asked for.
    if (argv.config === null || argv.config === '') {
      throw new OperatorError('--config needs a path: --config=<path>');
    }
    return loadConfig(argv.config, aclOpts);
  }

  try {
    const fromFile = await loadConfig(undefined, aclOpts);
    // #138 之前每个 Windows 配置都被模式位检查拒绝且拒绝被吞，
    // 同时传了 --host/--user 的运维在静默跑标志。现在文件加载成功
    // 就优先——值得一行代码的转变，而不是「命令到了哪台主机」的惊喜。
    // precedence — a flip worth one line rather than a surprise about which host
    // a command reached.
    if (argv.host || argv.user) {
      console.error(
        `Note: ${getConfigPath()} was loaded, so --host/--user are ignored. ` +
        'Pass --config <path> to choose a different file.',
      );
    }
    return fromFile;
  } catch (err) {
    // 只有「无文件」才落空。存在但不可用的文件——TOML 畸形、schema
    // 违规、权限失败——过去也在这里被吞、报成配置缺失，
    // #138 因此无迹可寻：运维的文件在正确位置，
    // 真正的错误在任何人读到之前就被丢弃了。
    // and the real error was discarded before anyone could read it.
    // --host/--user 恰好同时存在时落空也不对：服务器启动，
    // 静默无视运维写的每一个 profile、策略和角色绑定。
    // --host/--user happen to be present: the server would start, silently
    // ignoring every profile, policy and role binding the operator wrote.
    if (!(err instanceof ConfigNotFoundError)) throw err;
  }

  // 什么都没配置、命令行也没指名。照样启动，无 profile：MCP 客户端
  // 或目录能完成握手并读 tools/list，每次工具调用都被
  // ConnectionRegistry 以下方消息拒绝——包括 list-connections，
  // 它不解析任何 profile，所以必须单独告知。
  //
  // 此前实测：对着自己的镜像 initialize 和 tools/list 没有得到
  // 任何 JSON-RPC 响应——进程先在这个检查上退出——每个目录
  // 和每个「添加此服务器」流程看到的都是崩溃。工具定义是静态元数据，
  // 配置决定的是它们能*到达*什么，把两者耦合买不到安全。
  //
  // 半给的快速启动不是这种情况：--host 无 --user 是笔误，
  // 指向空处的显式 --config 已在上面抛出。只有「什么都没配」才软——
  // 见 nothingRequested，测的是标志缺席而非假值，
  // 使无值或空格分隔的仍是笔误。
  if (nothingRequested(argv)) {
    console.error(`Warning: starting unconfigured — every tool call will be refused.\n${new UnconfiguredError(getConfigPath()).message}`);
    return { defaults: defaultsFromArgv(argv), profiles: [] };
  }

  if (!argv.host || !argv.user) {
    throw new UnconfiguredError(getConfigPath());
  }

  const defaults = defaultsFromArgv(argv);

  const profile: Profile = {
    name: 'default',
    host: argv.host,
    port: parseInt(argv.port as string) || 22,
    user: argv.user,
    auth: argv.key ? 'key' : 'password',
    keyRef: argv.key || undefined,
    workdir: argv.workdir || undefined,
    tty: false,
    keyboardInteractive: false,
    timeout: defaults.commandTimeoutMs,
    maxChars: defaults.commandMaxChars,
    maxOutputBytes: defaults.commandMaxOutputBytes,
    role: 'admin',
    group: resolveHostGroup(argv),
    readOnly: false,
    // 与配置 schema 相同的默认。CLI profile 是一次性情形——
    // --host/--user 无配置文件——它的宣告与其他任何主机一致。
    announceAgent: true,
    approvalPolicy: flagEnabled(argv, 'disableApproval') ? 'auto' : defaults.approvalMode,
    cert: false,
    sessionMaxPerConnection: defaults.sessionMaxPerConnection,
    sessionIdleTimeoutMs: defaults.sessionIdleTimeoutMs,
    sessionBackgroundMaxMs: defaults.sessionBackgroundMaxMs,
    commandQuotaPerDay: defaults.commandQuotaPerDay,
    transferMaxBytes: defaults.transferMaxBytes,
    transferTimeoutMs: defaults.transferTimeoutMs,
  };

  return { defaults, profiles: [profile] };
}

// ─── approvals CLI (agent-ssh) ──────────────────────────────────────────────

/**
 * 位置参数（非 --），供子命令面。此前本文件解析的一切都是标志，
 * 位置参数是噪音；approvals CLI 是第一个需要它们的文法。
 * 空格分隔标志的值也会落到这里——本文件从未接受该写法，
 * approvals 文法的标志也只接受 --x=v 形式，理由相同。
 * grammar takes its flags only in the `--x=v` form for the same reason.
 */
export function positionalsOf(args: string[]): string[] {
  return args.filter((a) => !a.startsWith('--'));
}

function formatPending(p: PendingApproval, now: Date): string {
  const ageS = Math.max(0, Math.round((now.getTime() - Date.parse(p.createdAt)) / 1000));
  const leftS = Math.max(0, Math.round((Date.parse(p.expiresAt) - now.getTime()) / 1000));
  const status = p.status === 'pending' ? `expires in ${leftS}s` : p.status;
  // 「完整上下文」承诺（审计 M8）：审批人看到的就是将被执行的完整命令，
  // 不做截断——指纹核对也以全文为对象。
  const command = p.command;
  return `${p.id}  [${status}]  ${p.commandClass} on "${p.profile}" (age ${ageS}s)\n    ${command}\n    fingerprint ${p.fingerprint.slice(0, 16)}…`;
}

/**
 * agent-ssh approvals list|approve <id>|reject <id> [--dir=path]。
 *
 * 队列通道的决定面（计划 §2 R6）。子命令即同意：
 * 一个人运行了它，看到了判定上方打印的完整载荷，
 * 文件记录了谁运行的。没有 approve-all 也没有批处理——
 * 每个请求都被独立阅读和决定。
 */
export async function runApprovalsCli(args: string[]): Promise<number> {
  const [verb, id] = positionalsOf(args);
  const flags = parseArgv(args);
  const dir = flags.dir || undefined;
  const now = new Date();

  if (verb === 'list') {
    const pending = await listPending({ dir });
    if (pending.length === 0) {
      console.log('No approval requests.');
      return 0;
    }
    for (const p of pending) console.log(formatPending(p, now));
    return 0;
  }

  if (verb === 'approve' || verb === 'reject') {
    if (!id) {
      console.error(`Usage: agent-ssh approvals ${verb} <id> [--dir=path]`);
      return 1;
    }
    // 完整上下文在判定写入之前打印——只看 id 不看它指名什么
    // 就做决定，正是批准被批量刷掉的方式。
    const pending = await listPending({ dir });
    const target = pending.find((p) => p.id === id);
    if (target) console.log(formatPending(target, now));
    const outcome = await decideApproval(id, verb === 'approve' ? 'approved' : 'rejected', { dir });
    console.log(outcome.message);
    return outcome.decided ? 0 : 1;
  }

  console.error('Usage: agent-ssh approvals list | approvals approve <id> | approvals reject <id> [--dir=path]');
  return 1;
}
