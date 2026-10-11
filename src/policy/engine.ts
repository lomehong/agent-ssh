import type {
  CommandClass,
  ParsedCommand,
  PolicyConfig,
  PolicyEvaluation,
  Profile,
  ApprovalMode,
} from '../types.js';
import { classifyCommand, findForbiddenMatch, formatReadOnlyRejection } from './classifier.js';
import { normalizeRemotePath, normalizeRemotePathForWindows } from './remote-path.js';
import { OperatorError } from '../errors.js';

export interface PolicyRules {
  roleBindings: Record<string, Record<string, CommandClass[]>>;
  /**
    * 运维提供的额外拒绝模式，正则源字符串。
    * 正统「永不放行」清单（FORBIDDEN_PATTERNS）在 classifier.ts 中，
    * 且始终叠加在这些之上——此处不重复。
   */
  denylist?: string[];
}

/**
 * 等待 OPA sidecar 多久后才视为不可用。
 *
 * 有界是因为无界等待曾让每次工具调用等 undici 的五分钟头超时。
 * 十秒而非两秒：默认模式下超时回落到本地决定，所以此预算
 * 也是把显式 OPA *拒绝*变成放行的代价——两秒时负载中的 sidecar
 * 意外就越界，能加延迟的人则故意越界。十秒高于负载 sidecar 的 p99，
 * 仍比它替代的挂起便宜三十倍。--opaTimeoutMs 可调：
 * 调低让 fail-open 更早触发，调高让故障更迟被发现。
 * fail-open cheaper to reach, higher makes an outage slower to notice.
 */
const DEFAULT_OPA_TIMEOUT_MS = 10_000;

/** Tiers, most restrictive first. Unknown/unset tiers resolve to the first. */
export const HOST_GROUPS = ['prod', 'staging', 'dev'] as const;

export const DEFAULT_RULES: PolicyRules = {
  // Null 原型，理由见 mergePolicyRules 处：角色名是自由字符串，
  // 本对象以它为键。mergePolicyRules 在无覆盖时原样返回此对象，
  // 所以只修合并后的副本会让最常见路径——完全无 [policy] 节——
  // 仍留在普通对象上。
  roleBindings: Object.assign(Object.create(null), {
    viewer: {
      prod: ['read-only'],
      staging: ['read-only'],
      dev: ['read-only', 'safe'],
    },
    operator: {
      prod: ['read-only', 'safe'],
      staging: ['read-only', 'safe', 'destructive'],
      dev: ['read-only', 'safe', 'destructive'],
    },
    admin: {
      prod: ['read-only', 'safe', 'destructive'],
      staging: ['read-only', 'safe', 'destructive', 'privileged'],
      dev: ['read-only', 'safe', 'destructive', 'privileged'],
    },
  }),
};

/**
 * 将运维的 [policy] 节叠加到编译期内置默认之上。
 *
 * 合并深度是 role 内的 group，不是 role 级。用部分表替换整个角色的
 * 绑定是这里的陷阱：只写 admin.prod 的配置会把 admin.staging 和
 * admin.dev 清空回无绑定，无声放宽或收紧运维从未提及的两个层级。
 *
 *
 * 覆盖中缺席的角色和层级保留默认值；默认值没听过的角色或层级
 * 会被新增而非拒绝。这正是自定义 group = tier-1 能解析到
 * 真实绑定的机制。
 *
 * denylist 是替换而非追加，因为默认值不带任何拒绝清单，
 * FORBIDDEN_PATTERNS 由引擎始终叠加在其上。
 *
 * 无可叠加时原样返回 base 而非拷贝。结果两种方式都是只读的——
 * PolicyEngine 只读 rules；下方拷贝的存在是为了后续合并不能
 * 通过共享的 tier 对象触及 DEFAULT_RULES，
 * 而不是因为调用方被期望修改拿到的结果。
 */
export function mergePolicyRules(
  base: PolicyRules,
  override?: PolicyConfig,
): PolicyRules {
  if (!override?.roleBindings && !override?.denylist) return base;

  // 拷贝每个 tier 映射：直接透传 base 的对象会让后续合并
  // 修改模块级单例 DEFAULT_RULES。
  //
  // 用 Object.create(null) 而非 {}：下方循环赋值运维选的键，
  // roleBindings[role] = ... 且 role === __proto__ 时
  // 普通对象走的是原型 setter 而非创建键。实测影响不是全局的——
  // Object.prototype 未被动——但本对象自身的原型被运维的 tier 映射
  // 替换，此后 roleBindings.prod 沿原型链解析如同 prod 是一个角色。
  // 报告为 github.com/tufantunc/ssh-mcp/issues/172。
  //
  //
  // 触发它需要先绕过 config/schema.ts 的 schema 守卫，
  // 而该守卫正是 zod 4 已经静默禁用过一次的（2.5.0 重建了它）。
  // 授权引擎里的保险值得一次函数调用。
  //
  // 它还消除了无配置介入的第二种情况：普通对象上
  // roleBindings[toString] 返回一个函数，角色名为 Object.prototype
  // 成员的 profile 会找到一个真值「绑定」。那会 fail-closed——
  // findPolicyProblems 仍拒绝且评估下限为 read-only——但走了
  // 与未知角色不同的分支，读者看不出为什么。
  const roleBindings: Record<string, Record<string, CommandClass[]>> =
    Object.create(null);
  for (const [role, groups] of Object.entries(base.roleBindings)) {
    roleBindings[role] = { ...groups };
  }
  for (const [role, groups] of Object.entries(override.roleBindings ?? {})) {
    roleBindings[role] = { ...(roleBindings[role] ?? {}), ...groups };
  }

  return {
    roleBindings,
    denylist: override.denylist ?? base.denylist,
  };
}

/**
 * 本 profile 适用哪个层级的角色绑定。
 *
 * profile.group 是权威。缺省时为方便仍从名称推断，
 * 但无法识别的名称解析为最严格层级：以前的默认把每个
 * 未识别的 profile 送到 dev，一个仅仅叫 web-01 的生产主机
 * 就静默拿到矩阵中最宽松的权限。
 *
 *
 * 导出而非私有，因为启动校验必须到达引擎将到达的同一答案，
 * 推断包含在内。只查显式 group 会放过每个没设它的 profile，
 * 而下方正是放宽发生的地方。
 *
 */
export function resolveProfileGroup(profile: Profile): string {
  if (profile.group) return profile.group;

  const name = profile.name.toLowerCase();
  if (name.includes('prod')) return 'prod';
  if (name.includes('staging')) return 'staging';
  if (/\b(dev|local|test|sandbox)\b/.test(name) || /(^|[-_])(dev|local|test|sandbox)([-_]|$)/.test(name)) {
    return 'dev';
  }
  return HOST_GROUPS[0];
}

/**
 * 配置的策略可以偏离其字面意思的每一种方式。
 *
 * 双向检查，因为静默空操作从两侧都可达：
 * profile 可以命名一个无人定义的角色或层级，[policy]
 * 块也可以定义一个没有 profile 能达到的角色或层级。
 * #95 是第二种（写了、解析了、丢了），第一种落到
 * read-only，运行时与刻意的策略决定无法区分。
 *
 * [policy] 侧对照 override 检查，绝不对照合并后的表：
 * 合并携带三个编译期内置角色，真实配置不会引用全部。
 *
 *
 * 返回所有问题而非第一个，与 loader.ts 的配置校验错误一致。
 * 修配置文件的运维想要完整清单。
 */
export function findPolicyProblems(
  merged: PolicyRules,
  profiles: Profile[],
  override?: PolicyConfig,
): string[] {
  const problems: string[] = [];

  for (const profile of profiles) {
    const roleBinding = merged.roleBindings[profile.role];
    if (!roleBinding) {
      problems.push(
        `profile "${profile.name}": role "${profile.role}" has no role bindings, so it can only ever ` +
        `run read-only commands. Define [policy.roleBindings.${profile.role}], or set role to one of: ` +
        `${Object.keys(merged.roleBindings).join(', ')}.`,
      );
      continue;
    }

    const group = resolveProfileGroup(profile);
    if (roleBinding[group]) continue;

    const tiers = Object.keys(roleBinding).join(', ');
    problems.push(
      profile.group
        ? `profile "${profile.name}": role "${profile.role}" has no bindings for group "${group}". ` +
          `Add a "${group}" key under [policy.roleBindings.${profile.role}], or set group to one of: ${tiers}.`
        : `profile "${profile.name}": no group is set, so the tier is inferred from the name as "${group}", ` +
          `and role "${profile.role}" has no bindings for it. Set group explicitly to one of: ${tiers}, ` +
          `or add a "${group}" key under [policy.roleBindings.${profile.role}].`,
    );
  }

  const rolesInUse = [...new Set(profiles.map((p) => p.role))];
  for (const [role, tiers] of Object.entries(override?.roleBindings ?? {})) {
    if (!rolesInUse.includes(role)) {
      problems.push(
        `[policy.roleBindings.${role}]: no profile uses role "${role}", so this block changes nothing. ` +
        `Roles in use: ${rolesInUse.join(', ')}.`,
      );
    }
    for (const tier of Object.keys(tiers)) {
      if ((HOST_GROUPS as readonly string[]).includes(tier)) continue;
      if (profiles.some((p) => p.group === tier)) continue;
      problems.push(
        `[policy.roleBindings.${role}]: key "${tier}" matches no profile's group and is not a built-in ` +
        `tier (${HOST_GROUPS.join(', ')}), so it changes nothing. Set group = "${tier}" on a profile, ` +
        `or remove the key.`,
      );
    }
  }

  return problems;
}

/**
 * main() 运行的规则：编译期内置默认、运维覆盖叠加其上，
 * 以及两者描述的不是同一个世界时拒绝启动。
 * world.
 *
 * 拒绝而非告警。告警走 stderr，对 stdio MCP 服务器那是
 * 运维不读的日志文件，「写了、忽略了、什么都没说」
 * 正是 #95 的全部。
 */
export function resolvePolicyRules(
  profiles: Profile[],
  override?: PolicyConfig,
): PolicyRules {
  const merged = mergePolicyRules(DEFAULT_RULES, override);
  const problems = findPolicyProblems(merged, profiles, override);
  if (problems.length > 0) {
    throw new OperatorError(
      'Policy configuration error:\n' +
      problems.map((p) => `  ${p}`).join('\n') +
      '\nSee the "Configuring the matrix" section of the README.',
    );
  }
  return merged;
}

/**
 * 调用作用的对象，超出命令字符串。只有 SFTP 工具传任何东西：
 * 其命令字符串是本服务器编排的，为路径写的 [policy].denylist
 * 规则也对照路径本身测试（#230）。同一个值进入 OPA 输入的
 * resource——名称沿用该词汇表：resource 是被作用的对象，
 * subject 是执行动作的 profile。
 */
export interface PolicyResource {
  remotePath?: string;
}

export class PolicyEngine {
  private opaUrl: string | null = null;
  private opaFailClosed = false;
  private opaTimeoutMs = DEFAULT_OPA_TIMEOUT_MS;
  /** Rate-limits the fail-open warning so one outage can't flood stderr. */
  private lastOpaWarning = 0;
  /**
    * 运维的模式，只编译一次——每个两次：按原样，以及
    * 不区分大小写（远程路径的 Windows 读法，大小写变体
    * 到达同一文件（#230））。内建清单在 classifier.ts 中。
   */
  private readonly userPatterns: ReadonlyArray<{ exact: RegExp; caseInsensitive: RegExp }>;

  constructor(private rules: PolicyRules = DEFAULT_RULES) {
    // 急切编译：静默降级的拒绝规则（旧代码把命令对照正则*源文本*
    // 做子串匹配）比启动失败更糟，因为没有任何东西暴露降级。
    // worse than a startup failure, because nothing surfaces the degradation.
    this.userPatterns = (rules.denylist ?? []).map((pattern) => {
      try {
        return { exact: new RegExp(pattern), caseInsensitive: new RegExp(pattern, 'i') };
      } catch (err) {
        throw new OperatorError(
          `Invalid denylist pattern ${JSON.stringify(pattern)}: ${err instanceof Error ? err.message : String(err)}`,
        );
      }
    });
  }

  setOpaUrl(url: string | null, failClosed = false, timeoutMs = DEFAULT_OPA_TIMEOUT_MS): void {
    this.opaTimeoutMs = timeoutMs;
    // 模式变化时重置告警节流，否则每分钟一条的告警可能是
    // *上一个*模式的句子——引擎在拒一切时打印
    // 「OPA 会拒绝的命令现在可能被放行」。
    if (failClosed !== this.opaFailClosed || url !== this.opaUrl) this.lastOpaWarning = 0;
    this.opaUrl = url;
    this.opaFailClosed = failClosed;
  }

  evaluate(
    command: string,
    profile: Profile,
    resource: PolicyResource = {},
  ): PolicyEvaluation {
    const parsed = classifyCommand(command);
    const allowedClasses = this.getAllowedClasses(profile);
    const classAllowed = allowedClasses.includes(parsed.class);
    // 复制到下方每个分支而非仅角色绑定分支：
    // read-command 的 enforceClass 检查从 allow 决定上读取它，
    // 因为文法拒绝的 reader 对多数角色允许为 safe，
    // 仅在工具层上一级被拒。
    const readOnlyRejection = parsed.readOnlyRejection;

    const denied = this.findDenyMatch(command, resource);
    if (denied) {
      return {
        decision: 'deny',
        commandClass: parsed.class,
        binary: parsed.binary,
        ruleId: 'denylist',
        reason: denied,
        readOnlyRejection,
      };
    }

    const needsApproval =
      parsed.class === 'destructive' || parsed.class === 'privileged';

    const approvalRequired = this.requiresApproval(profile, needsApproval);

    if (!classAllowed) {
      return {
        decision: 'deny',
        commandClass: parsed.class,
        binary: parsed.binary,
        ruleId: 'role-binding',
        reason: this.explainRoleDenial(profile, parsed),
        readOnlyRejection,
      };
    }

    if (approvalRequired) {
      // approvalPolicy deny 直接拒绝而非提示——否则行为与
      // ask-destructive 完全相同，永远不拒绝任何东西。
      if (profile.approvalPolicy === 'deny') {
        return {
          decision: 'deny',
          commandClass: parsed.class,
          binary: parsed.binary,
          ruleId: 'approval-policy',
          reason: `Profile "${profile.name}" denies ${parsed.class} commands (approvalPolicy = "deny")`,
          readOnlyRejection,
        };
      }
      return {
        decision: 'require-approval',
        commandClass: parsed.class,
        binary: parsed.binary,
        ruleId: 'approval-policy',
        reason: `Profile "${profile.name}" requires approval for ${parsed.class} commands`,
        readOnlyRejection,
      };
    }

    return {
      decision: 'allow',
      commandClass: parsed.class,
      binary: parsed.binary,
      ruleId: 'default',
      readOnlyRejection,
    };
  }

  async evaluateWithOpa(
    command: string,
    profile: Profile,
    toolName: string,
    resource: PolicyResource = {},
  ): Promise<PolicyEvaluation> {
    const local = this.evaluate(command, profile, resource);

    if (local.decision === 'deny') {
      return local;
    }

    if (!this.opaUrl) {
      return local;
    }

    try {
      const parsed = classifyCommand(command);
      // 按原样的路径，加上本地 denylist 用的两种读法，让 Rego 规则
      // 能匹配规范拼写而无需在此重新实现任一读法。非 SFTP 工具
      // 及空路径为 undefined，JSON 会省略键。
      // JSON drops the keys then.
      const remotePath = resource.remotePath || undefined;
      const input = {
        subject: { role: profile.role, profile: profile.name },
        action: { tool: toolName, commandClass: parsed.class },
        resource: {
          command: parsed.fullCommand,
          binary: parsed.binary,
          host: profile.host,
          remotePath,
          remotePathNormalized: remotePath === undefined ? undefined : normalizeRemotePath(remotePath),
          remotePathWindows: remotePath === undefined ? undefined : normalizeRemotePathForWindows(remotePath),
        },
        context: { readOnly: profile.readOnly },
      };

      const resp = await fetch(`${this.opaUrl}/v1/data/ssh/mcp/allow`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ input }),
        // 接受连接但永不回答的 sidecar 是 OPA「不可达」的典型方式，
        // 没有这行的话调用会跑到 undici 的五分钟头超时，
        // 每次工具调用都在等它。中止落入下方 catch，
        // 两种模式都在预算内到达各自的答案。
        signal: AbortSignal.timeout(this.opaTimeoutMs),
      });

      if (!resp.ok) {
        return this.onOpaUnavailable(`HTTP ${resp.status}`, local);
      }

      const payload: unknown = await resp.json();
      // 加守卫而非强转。as { result?: unknown } 对 null body 是谎言——
      // 读 .result 会抛，stderr 上的原因被读成本服务器的缺陷，
      // 而不是下方标名的「无决定」条件。
      const result = typeof payload === 'object' && payload !== null
        ? (payload as { result?: unknown }).result
        : undefined;
      if (typeof result !== 'boolean') {
        // 200 但无决定是 OPA 对未定义文档的回答——错误包路径、
        // 未激活的 bundle、或没写 default allow := false 的 allow 规则
        // 都会产生。读成同意意味着 --opaFailClosed 无法覆盖
        // OPA 门真正倒下的方式：七种应答形态六种放行，无任何告警。
        //
        return this.onOpaUnavailable('no boolean `result` in the response', local);
      }
      if (result === false) {
        return {
          decision: 'deny',
          commandClass: parsed.class,
          binary: parsed.binary,
          ruleId: 'opa',
          reason: 'Denied by OPA policy',
        };
      }
    } catch (err) {
      return this.onOpaUnavailable(err instanceof Error ? err.message : String(err), local);
    }

    return local;
  }

  /**
    * OPA 故障意味着什么，是运维的选择而非我们的。
   *
    * 回落到本地决定是默认且保持默认：OPA 是额外拒绝层，
    * 停掉全部工作的故障比缩小策略更糟。但把 OPA *当作*
    * 授权门部署的运维，拥有的控制会在故障期间消失，
    * 唯一信号是 MCP 客户端通常丢弃的 stderr 行。
    * --opaFailClosed 让他们说：门倒了就是不行。
    *
   */
  private onOpaUnavailable(cause: string, local: PolicyEvaluation): PolicyEvaluation {
    this.warnOpaUnavailable(cause);
    if (!this.opaFailClosed) return local;
    return {
      decision: 'deny',
      commandClass: local.commandClass,
      binary: local.binary,
      ruleId: 'opa-unavailable',
      // 固定字符串。cause 走 stderr 给运维；此 reason 重抛为
      // 工具错误文本并写入审计记录，它携带了 this.opaUrl——
      // 内部主机名和其中嵌入的任何凭据——到每次拒绝时的
      // MCP 客户端。
      reason: 'OPA evaluation unavailable and --opaFailClosed is set',
    };
  }

  /**
    * 这是刻意的取舍，但必须响亮：把 OPA 当硬授权门部署的运维
    * 否则无从得知门倒了、而它本会拒绝的命令仍在跑。
    *
    *
   * would have denied keep running.
   */
  private warnOpaUnavailable(cause: string): void {
    const now = Date.now();
    if (now - this.lastOpaWarning < 60_000) return;
    this.lastOpaWarning = now;
    console.error(
      `POLICY WARNING: OPA evaluation unavailable (${cause}). ` +
      (this.opaFailClosed
        ? 'Refusing every command while it is down, because --opaFailClosed is set.'
        : 'Falling back to local policy — commands OPA would deny may now be allowed.'),
    );
  }

  /**
    * 说清楚产生拒绝的三件事，而不是只说一件。
   *
    * 消息过去是 Role admin cannot run privileged commands，
    * 点名了角色和类别但没提主机组——而通常是组在起决定作用：
    * admin 在 staging 和 dev 有 privileged 但 prod 没有。读者得出
    * 「我的角色就是不能 sudo」的结论去找不存在的大角色（#91）。
    *
   *
    * 推断的情形最要紧：没设 group 的 profile 从名称猜层级，
    * 原因因此是运维从未在任何地方写下、也无法看到的东西。
    *
   */
  private explainRoleDenial(profile: Profile, parsed: ParsedCommand): string {
    const commandClass = parsed.class;
    let reason: string;

    if (profile.readOnly) {
      reason = `Profile "${profile.name}" is read-only, so "${commandClass}" commands are refused. ` +
        `Clear readOnly on the profile to allow them.`;
    } else {
      const group = resolveProfileGroup(profile);
      const inferred = !profile.group;
      const allowed = this.getAllowedClasses(profile).join(', ');

      reason =
        `Role "${profile.role}" on host group "${group}" cannot run "${commandClass}" commands ` +
        `(allowed: ${allowed}).`;

      if (inferred) {
        // 不是「回落到最严格层级」：名称先匹配 prod/staging/dev，
        // 叫 staging-web 的 profile 落在 staging，旧措辞描述了一个
        // 并未发生的回落。运维需要知道的是没有任何他们写的东西
        // 选择了这个层级。
        //
        reason +=
          ` No group is set for profile "${profile.name}", so the tier was inferred from its name as "${group}".` +
          ` Set group explicitly on the profile, or pass --group, if that is not where this host belongs.`;
      } else {
        reason += ` Change the profile's group, or grant the class to this role in the policy's roleBindings.`;
      }
    }

    // 在此被拒的 safe 命令往往不是硬「不」——离 read-only 只差
    // 一个 argv 词，没有这句读者会断定该二进制整体被禁，
    // 永远不知道哪种写法能通过。
    //
    if (parsed.readOnlyRejection) {
      reason += ` ${formatReadOnlyRejection(parsed.readOnlyRejection)}`;
    }

    return reason;
  }

  private getAllowedClasses(profile: Profile): CommandClass[] {
    if (profile.readOnly) {
      return ['read-only'];
    }
    const roleBinding = this.rules.roleBindings[profile.role];
    if (!roleBinding) {
      return ['read-only'];
    }
    // 此层级无绑定时绝不跳到其他层级。roleBindings 还是编译期
    // 内置时，回落到 HOST_GROUPS[0] 意味着回落到该角色*最严格*的
    // 格子，旧注释因此为真。一旦 [policy] 块能写 prod 格子，同样的
    // 跳转就把未解析的层级交给 prod 被授予的任何东西。
    // 那是放宽，且是无声的。
    //
    // 未解析层级现在是启动错误（resolvePolicyRules），
    // 走到这行说明引擎被直接构造而非来自配置文件。fail-closed。
    //
    // 用 ?? 而非 ||：空类别列表是刻意的锁定，
    // 它是否存活不应取决于 [] 是否为真值。
    //
    return roleBinding[resolveProfileGroup(profile)] ?? ['read-only'];
  }

  /**
    * 由 evaluate() 根据 approvalPolicy 决定。
    *
   */
  private requiresApproval(profile: Profile, needsApproval: boolean): boolean {
    const mode: ApprovalMode = profile.approvalPolicy;
    if (mode === 'auto') return false;
    if (mode === 'ask-all') return true;
    // ask-destructive 和 deny 都以 destructive/privileged 设门。
    return needsApproval;
  }

  /**
   * Which deny rule refused this command, worded so the reader can act on it.
    * 旧消息是 Command matches denylist pattern，什么都不点名——
    * 不说规则、不说来源、不说运维能否改。遇到它的用户无法区分
    * 内置拒绝与自己写的拒绝（#91）。explainRoleDenial 已点名角色、
    * 组、类别和允许集；这条路径一直没得到同样待遇。
    *
   * group, the class and the allowed set; this path never got the same
   * treatment.
   */
  private findDenyMatch(command: string, resource: PolicyResource): string | null {
    const builtIn = findForbiddenMatch(command);
    if (builtIn) {
      return `Command matches a built-in never-allowed rule: ${builtIn}. ` +
        `This list cannot be switched off — the [policy].denylist key adds patterns, it does not remove these.`;
    }

    // 下方不可能匹配：跳过路径读取——这是最常见的配置，
    // 默认不带 denylist。
    if (this.userPatterns.length === 0) return null;

    // 路径本身也单独测试，不仅仅在命令字符串内：SFTP 工具的
    // 字符串由我们编排，为路径写的规则不应取决于我们放在哪（#230）。
    // 空路径意味着没传路径。
    const remotePath = resource.remotePath || undefined;
    const normalized = remotePath === undefined ? undefined : normalizeRemotePath(remotePath);
    const windows = remotePath === undefined ? undefined : normalizeRemotePathForWindows(remotePath);
    const fromConfig = 'a pattern from [policy].denylist in your config file. ' +
      'Remove or narrow it there to allow this command.';
    for (const { exact, caseInsensitive } of this.userPatterns) {
      if (exact.test(command)) {
        return `Command matches /${exact.source}/, ${fromConfig}`;
      }
      if (remotePath === undefined) continue;
      if (exact.test(remotePath)) {
        return `Remote path ${quotePath(remotePath)} matches /${exact.source}/, ${fromConfig}`;
      }
      if (normalized !== remotePath && exact.test(normalized!)) {
        return `Remote path ${quotePath(remotePath)} (read as ${quotePath(normalized!)}) ` +
          `matches /${exact.source}/, ${fromConfig}`;
      }
      // Windows 读法即使与普通读法字符串相等也运行，
      // 因为此处和不区分大小写地测试模式：Windows 上
      // 大小写变体是同一个文件（实测，见 remote-path.ts）。
      if (caseInsensitive.test(windows!)) {
        return `Remote path ${quotePath(remotePath)} (read as ${quotePath(windows!)}, the Windows reading) ` +
          `matches /${caseInsensitive.source}/i, ${fromConfig}`;
      }
    }

    return null;
  }
}

/**
 * 可长达 MAX_REMOTE_PATH_CHARS（4096）；拒绝会重抛给 MCP 客户端
 * 并写入审计记录，那里命令字符串已带完整拼写——所以尾部
 * 不放弃运维需要的任何东西，拒绝也不再是引擎最冗长的句子。
 * spelling — so the tail gives up nothing an operator needs, and a refusal stops being
 * the engine's most verbose sentence by an order of magnitude.
 */
function quotePath(path: string): string {
  const capped = path.length > 256 ? `${path.slice(0, 253)}…` : path;
  return JSON.stringify(capped);
}
