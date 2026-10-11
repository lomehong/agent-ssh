import { z } from 'zod';

const authMethodSchema = z.enum(['agent', 'key', 'password', 'keychain']);
const approvalModeSchema = z.enum(['auto', 'ask-destructive', 'ask-all', 'deny']);
const commandClassSchema = z.enum(['read-only', 'safe', 'destructive', 'privileged']);

// 网络设备兼容轴（agent-ssh T-02）。值侧类别恰为 FROZEN_ALGORITHMS 所有的键：
// 未知类别会干净解析然后什么都不做——正是本文件要防止的
// 「schema 接受但从不生效」形态。
//
const algorithmNameSchema = z.string().trim().min(1);
const algorithmListAdjustmentSchema = z
  .object({
    append: z.array(algorithmNameSchema).optional(),
    prepend: z.array(algorithmNameSchema).optional(),
    remove: z.array(algorithmNameSchema).optional(),
  })
  .strict();
const algorithmCategoryValueSchema = z.union([
  z.array(algorithmNameSchema).min(1),
  algorithmListAdjustmentSchema,
]);
// 显式对象而非 z.record(algorithmCategorySchema, ...)：zod 4 里
// 以枚举为键的 record 要求*每个*枚举键都存在，
// 那会让仅 kex 的覆盖变成校验错误。strict 仍拒绝未知类别——
// `compression` 的拼写错误必须在加载时报错，
// 而不是干净解析后什么都不做。
const algorithmsOverrideSchema = z
  .object({
    kex: algorithmCategoryValueSchema.optional(),
    cipher: algorithmCategoryValueSchema.optional(),
    serverHostKey: algorithmCategoryValueSchema.optional(),
    hmac: algorithmCategoryValueSchema.optional(),
  })
  .strict();

// 目标主机的设备特性。T-02 中的骨架（在 profile 上校验并携带）；
// 各厂商的关分页/提示符行为随设备档案落地。`generic` 是默认行为，
// 无需写出。
const deviceTypeSchema = z.enum(['generic', 'huawei', 'h3c', 'cisco', 'ruijie']);

/**
 * 角色与层级名，自由字符串，运维可自定义。
 *
 * 排除 `__proto__` 是因为合并会向普通对象赋值，而该赋值落在
 * 原型上而非创建键：这个名字的角色会被接受然后不存在。
 * `constructor` 与 `prototype` 一并排除，
 * 而不是逐案推理。
 */
const RESERVED_BINDING_KEYS = ['__proto__', 'constructor', 'prototype'];
const RESERVED_KEY_MESSAGE =
  `Reserved name (${RESERVED_BINDING_KEYS.join(', ')}). Rename the role or tier.`;

/** 只有长度规则。保留名规则在下方 `checkReservedKeys`。 */
const bindingKeySchema = z.string().min(1);

/**
 * 遍历深度：role → tier → classes。
 *
 * 无论输入长什么样，schema 恰好下钻两层，但本函数跟随*数据*，
 * 无边界时它会随 TOML 嵌套递归任意深。`smol-toml` 愉快地解析
 * 一万层，随之而来的 `RangeError` 会逃出 `loadConfig`——
 * `safeParse` 是抛异常而不是返回 `{ success: false }`，而该调用
 * 位于 loader 的 try/catch 之外——于是运维拿到的是堆栈，
 * 而 zod 3 打印的是校验错误。
 */
const MAX_BINDING_DEPTH = 2;

/**
 * 保留键检查，在 `z.record` 看到 raw 对象之前运行。
 *
 * 光靠 `bindingKeySchema` 在 zod 4 就不够了。它的 record 实现
 * 从不把 `__proto__` 交给键 schema——直接丢键返回无键对象，
 * 于是命名该角色的配置*干净*解析、结果为空。实测：
 * 对解析后的 TOML 做 `Object.keys` 可见 `__proto__`，
 * `z.record` 接受，结果零键。
 *
 * zod 4 以两种独立方式破坏了它，均经实测。`z.record` 从不把
 * `__proto__` 交给键 schema——丢键返回无键对象。
 * 而对它确实检查的键，zod 4 会用自带的 `Invalid key in record`
 * 替换键 schema 的消息，保留名文案与 `min(1)` 的都到不了运维眼前。
 *
 *
 * 被丢的键不是原型污染——zod 4 干脆不写它，这是安全的一半。
 * 丢掉的是拒绝，而下游只在某 profile 使用该角色时才兜住：
 * `resolvePolicyRules` 对无绑定的角色抛异常，但没有任何
 * profile 引用的绑定块被无声丢弃。
 *
 * 所以两条规则都由这里全权负责，而不是叠在键 schema 之上。
 * 保留名 `refine` 同时从 `bindingKeySchema` 上摘除——管道会短路，
 * 它永远跑不到，称之为第二层是在描述不存在的东西。
 *
 * 用 `getOwnPropertyNames` 加属性描述符，而非 `Object.keys`
 * 加属性读取。实测，对本函数能收到的一切，两者结果相同：
 * `smol-toml` 产出可枚举字符串键，自有 `__proto__` 数据属性
 * 会遮蔽原型访问器，直接读也返回该键。保留它们是因为
 * 描述符不会执行 getter，且键是否可枚举是 TOML 解析器的
 * 决定而非我们的。
 *
 */
function checkReservedKeys(
  value: unknown,
  ctx: z.RefinementCtx,
  prefix: (string | number)[] = [],
): void {
  if (typeof value !== 'object' || value === null) return;
  if (prefix.length >= MAX_BINDING_DEPTH) return;

  for (const key of Object.getOwnPropertyNames(value)) {
    // path 携带祖先链，保留的 tier 会点名它所在的 role。
    // 只报叶子会把运维指向一个不在其文件里的顶层角色，
    // 与「可行动的拒绝」正好相反。
    const path = [...prefix, key];

    if (RESERVED_BINDING_KEYS.includes(key)) {
      ctx.addIssue({ code: 'custom', message: RESERVED_KEY_MESSAGE, path });
      // 用 `continue` 而非 `return`：有多处坏名字的配置应该
      // 全部听到，就像策略引擎的一致性检查那样。
      continue;
    }
    if (key.length === 0) {
      ctx.addIssue({ code: 'custom', message: 'Role and tier names cannot be empty.', path });
      continue;
    }

    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor && typeof descriptor.value === 'object' && descriptor.value !== null) {
      checkReservedKeys(descriptor.value, ctx, path);
    }
  }
}

export const defaultsSchema = z.object({
  defaultProfile: z.string().optional(),
  sessionMaxPerConnection: z.number().int().positive().default(5),
  sessionIdleTimeoutMs: z.number().int().positive().default(600_000),
  sessionBackgroundMaxMs: z.number().int().positive().default(3_600_000),
  commandTimeoutMs: z.number().int().positive().default(60_000),
  // 0 = 不限制，对应 CLI 的 `--maxChars=none`。normalizeConfig()
  // 把它映射为 Number.MAX_SAFE_INTEGER，两个表面交给后续代码
  // 的就是同一个 Profile。
  commandMaxChars: z.number().int().nonnegative().default(5000),
  commandMaxOutputBytes: z.number().int().positive().default(1_048_576),
  connectionIdleReapMs: z.number().int().positive().default(900_000),
  // 0 = 不限制。针对失控 agent 的熔断器，不是限速。
  commandQuotaPerDay: z.number().int().nonnegative().default(200),
  // 0 = 每条破坏性命令都提示。自动审批削弱大门，
  // 因此是 opt-in 而非默认便利。
  approvalGrantTtlMs: z.number().int().nonnegative().default(0),
  approvalMode: approvalModeSchema.default('ask-destructive'),
  // 人工审批的征求位置（agent-ssh）：'elicitation' = 仅 MCP
  // 客户端对话框；'queue' = 仅文件队列 + approvals CLI；
  // 'both'（默认）= 先试客户端，无法询问时落到队列。
  // 人的拒绝永远是终局——只有不可用才会降级。
  approvalChannel: z.enum(['elicitation', 'queue', 'both']).default('both'),
  // dynamic（SOCKS）端口转发。默认关：开放的 SOCKS 监听
  // 是通用出网通道——其他隧道都指名目标、可被拒绝清单拦下，
  // 这个不能。opt-in，按部署开启。
  allowDynamicForwarding: z.boolean().default(false),
  /**
    * 流式 SFTP 文件工具在本机上可以读写的位置。 machine.
   *
   * No default, and deliberately not a per-profile key. It names a directory on
    * 本机运行本服务器的何处，与远程主机无关，
    * 且 tools/local-path.ts 的大门坚持该目录 0700 且归本账户所有——
    * 没选过的运维就是没同意这些工具触碰本地磁盘。
    * 缺省即拒绝；不存在表示「任意位置」的写法。
    *
   */
  transferRoot: z.string().optional(),
  // 256 MiB。同时也是 `transferRoot` 的磁盘占用上限：下载先以
  // `.part` 暂存在那里再发布，所以这个上限就是单次调用能往
  // 一个运维未必盯着的目录里放多少。
  //
  // 上界 MAX_SAFE_INTEGER，因为 ssh/sftp.ts 的 `assertBounds`
  // 拒绝更大的值。这里不设界的话，配置了更大数字的配置能干净启动，
  // 然后每次调用都失败——本文件其他注释要防的「schema 接受
  // 但从不生效」形态，向下挪了一层。
  //
  transferMaxBytes: z.number().int().positive().max(Number.MAX_SAFE_INTEGER).default(268_435_456),
  // *空闲*预算，不是墙钟预算：它限制一次元数据往返、或拷贝中
  // 一段无字节移动的时间，有进展就重置（见 ssh/sftp.ts 的
  // TransferBounds）。这正是慢但在动的大文件传输能在宽松
  // 字节上限下存活的原因，两者无须相除来验证相称（#206）。
  // 它也不会让停滞更快被发现：停止交付的通道仍要付满一个窗口，
  // 按默认即五分钟。
  //
  //
  // 上限 2^31-1，即 `setTimeout` 接受的最大延迟——Node 会把更大的
  // 钳到 1ms，那样每一步都会立即失败、嘴里还报着运维要的值。
  //
  transferTimeoutMs: z.number().int().positive().max(2_147_483_647).default(300_000),
  // 裸 PTY 会话边界（安全计划第 ③ 层，默认值经主人 2026-10-11
  // 批准）：被 agent 弃之不顾的裸 shell 自行死亡——因空闲与因年龄。
  // 与 transferTimeoutMs 同样设上限，因为 setTimeout 把更大的值
  // 钳到 1ms，那会让每个会话立即死。
  ptySessionBufferBytes: z.number().int().positive().max(2_147_483_647).default(1_048_576),
  ptySessionIdleTimeoutMs: z.number().int().positive().max(2_147_483_647).default(600_000),
  ptySessionMaxLifetimeMs: z.number().int().positive().max(2_147_483_647).default(7_200_000),
}).strict();

export const profileSchema = z.object({
  name: z.string().min(1),
  host: z.string().min(1),
  port: z.number().int().min(1).max(65535).default(22),
  user: z.string().min(1),
  auth: authMethodSchema.default('agent'),
  keyRef: z.string().optional(),
  keychainEntry: z.string().optional(),
  via: z.string().optional(),
  // 驱动角色绑定层级。缺省时按 profile 名猜层级，
  // 无法识别的名字解析为最严格层级。
  group: z.string().optional(),
  workdir: z.string().optional(),
  // `.trim().min(1)` 而非裸字符串。`trustedHostKey = ""` 曾通过
  // 校验然后什么都不做：connection.ts 的旧门测的是真值，空固定
  // 于是静默无效，写下这行的运维却以为自己已被固定。空固定
  // 永远是错误，启动时大声报错胜过一个悄悄什么都不验证的 profile。
  // trim 是为同一理由的反向操作——对照指纹的比较是精确的，
  // heredoc 或编辑器带来的尾随换行会毫无提示地拒绝每一把钥匙。
  //
  //
  trustedHostKey: z.string().trim().min(1, 'trustedHostKey cannot be empty').optional(),
  tty: z.boolean().default(false),
  // 仅为该主机放宽 FROZEN_ALGORITHMS（精确清单替换冻结类别；
  // {append,prepend,remove} 调整它）。解析在 ssh/algorithms.ts
  // 对照冻结基线进行——绝不透传给 ssh2，其调整形态会放回
  // 冻结清单拒绝的一切。每项覆盖都以加载时告警宣布，
  // 并记在命令审计记录上：放宽白名单就是降低传输下限。
  //
  algorithms: algorithmsOverrideSchema.optional(),
  // 厂商特性（网络设备兼容）。在此校验，拼写错误在启动时报错，
  // 而不是静默按 `generic` 行事。
  deviceType: deviceTypeSchema.optional(),
  // 裸 PTY 输出解码（agent-ssh）。默认 UTF-8；遗留华为/华三固件
  // 输出 GB2312/GBK 时用 gbk——经 Node 内建 TextDecoder（full-ICU）
  // 解码，无额外依赖。
  ptyEncoding: z.enum(['utf8', 'gbk']).optional(),
  // 用解析出的密码回答 keyboard-interactive 提示。有些主机
  //（以及许多网络设备）只经 keyboard-interactive 方法提供密码认证；
  // 没有它，密码凭据在那里不可用。提示盲答——从不请求回显。
  //
  keyboardInteractive: z.boolean().default(false),
  role: z.string().default('operator'),
  readOnly: z.boolean().default(false),
  cert: z.boolean().default(false),
  // schema 级默认而非 [defaults] 条目，同上方的 tty/readOnly/cert：
  // 哪些主机值得信任以接收该声明，是单台主机的属性，
  // 不值得全局设置再按 profile 覆盖。默认 true——宣告即特性；
  // 开关是给你不受控的主机留的。
  //
  announceAgent: z.boolean().default(true),
  // 刻意保持可选：normalizeConfig() 从 [defaults] 填充它们，
  // schema 级 .default() 会让「用户省略」与「用户填了默认值」
  // 无法区分，静默遮蔽 [defaults]。
  timeout: z.number().int().positive().optional(),
  // 0 = 不限制，同上方 [defaults].commandMaxChars。
  maxChars: z.number().int().nonnegative().optional(),
  maxOutputBytes: z.number().int().positive().optional(),
  approvalPolicy: approvalModeSchema.optional(),
  sessionMaxPerConnection: z.number().int().positive().optional(),
  sessionIdleTimeoutMs: z.number().int().positive().optional(),
  sessionBackgroundMaxMs: z.number().int().positive().optional(),
  commandQuotaPerDay: z.number().int().nonnegative().optional(),
  // 按 profile，区别于 transferRoot：一次传输可以多大、多长的
  // 静默线路可容忍，是到该主机那条链路的属性。上界同 [defaults]，
  // 理由相同。
  transferMaxBytes: z.number().int().positive().max(Number.MAX_SAFE_INTEGER).optional(),
  transferTimeoutMs: z.number().int().positive().max(2_147_483_647).optional(),
}).strict();

/**
 * 启动时合并到编译期内置 DEFAULT_RULES 之上的覆盖。
 *
 * `roleBindings` 按角色 → 主机组 → 命令类索引，组键刻意为自由字符串：
 * 定义了自己层级的配置，能让 profile 上的 `group = "tier-1"`
 * 解析到该层级，而不是回落到最严格的一档。
 *
 *
 * 命令类别对照枚举校验而非作为自由字符串接受，`priviledged`
 * 因此在加载时失败，而不是解析成一个空授权——那在运行时读起来
 * 恰像一项策略决定。
 *
 * `allowlist` 刻意缺席：PolicyRules 声明了该字段但无代码读它，
 * 在这里接受它等于文档化一个什么都不做的键。
 */
export const policySchema = z.object({
  roleBindings: z.unknown()
    .superRefine(checkReservedKeys)
    .pipe(z.record(
      bindingKeySchema,
      z.record(bindingKeySchema, z.array(commandClassSchema)),
    ))
    .optional(),
  denylist: z.array(z.string()).optional(),
}).strict();

// 根上也 .strict()：否则未知节（拼写错误，或更新版本的键）
// 会干净解析后被无声丢弃，运维得到干净启动，
// 却没有他们配置的任何行为。
export const configSchema = z.object({
  defaults: defaultsSchema.prefault({}),
  profiles: z.array(profileSchema).min(1),
  policy: policySchema.optional(),
}).strict();

export type RawDefaults = z.infer<typeof defaultsSchema>;
export type RawProfile = z.infer<typeof profileSchema>;
export type RawPolicy = z.infer<typeof policySchema>;
export type RawConfig = z.infer<typeof configSchema>;
