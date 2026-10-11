/**
 * Windows ACL 检查的 SDDL 半边：描述符文本进，判定出。
 *
 * 从 windows-acl.ts 拆出使解析器的平台独立性在模块图中清晰可见——
 * 本文件什么都不导入，sddl-import-boundary.test.ts 强制执行这一点。
 * 它拥有的是文法*以及*文法被评判的白名单
 *（ALWAYS_ALLOWED_SIDS、aclIdentity 中的 RID-500 规则）：后者是
 * 授权策略而非语法，但它是不需要机器即可求值的策略，
 * 这正是本次切分实际画下的线。
 *
 * 本头文件的更早版本声称拆分防止*静默*失败——在 parseDacl 中
 * 伸手拿 icacls 的编辑会让 CI 保持绿色。那是错的，评审轮通过
 * 实际做它推翻了：这样的编辑在 Linux 上大声失败约 69 个解析器测试，
 * 因为那些测试没有一个带平台守卫。真正的危险在下一步。
 * 面对「显然只影响 Windows」的变更上的 69 个红测试，
 * 最便宜的修复是 describe.runIf(win32)——然后 2000 次运行的
 * property 测试套件在 Windows 之外停止检查该决定，绿色变成真的。
 * 在这里断言边界意味着第一步在一个唯一合理修复就是撤销导入的
 * 地方失败。
 *
 * 类型拆分沿同一条线：判定词汇是描述符说的内容，所以
 * Grant、UnknownReason、AclVerdict 和 AclIdentity 在这里。
 * AclFinding 和 AclOptions 是我们告诉运维的、以及运维要求的，
 * 所以它们留在平台半边。
 *
 * PRINCIPAL_NAMES/nameFor 在这里是违背排队此拆分的计划的，
 * 计划把它们放在消息侧。parseDacl 填充 Grant.name 时它们去不了那里：
 * 遵守它意味着给解析器传一个名称解析器，同一计划以不改变行为
 * 为由排除了这种签名变更。表以 SDDL 别名和 SID 为键，
 */

/**
 * 私有配置可以点名的主体，按 SID。
 *
 * 白名单，因为 POSIX 分支就是——拒绝 0700 之外的任何位——
 * 拒绝消息承诺「仅属主」。本文件首版是六个知名组的拒绝清单，
 * 放过了 Domain Users（SID 是域相对的，静态列表无法点名）、
 * Power Users、以及任何第二个本地账户或自定义组。在域加入主机上
 * 那是每个员工，却报为仅属主。
 *
 *
 * SYSTEM 和 Administrators 保持允许：它们正是 %APPDATA% 下文件
 * 实际携带的（实测），且管理员无论 DACL 说什么都能取得所有权，
 * 拒绝它们买不到任何东西。
 */
const ALWAYS_ALLOWED_SIDS: ReadonlySet<string> = new Set([
  'S-1-5-18',       // NT AUTHORITY\SYSTEM
  'S-1-5-32-544',   // BUILTIN\Administrators
]);

/**
 * SDDL 别名到 SID。
 *
 * 三个条目承载正确性——SY、BA、以及经 DOMAIN_RELATIVE_RIDS 的 LA——
 * 因为那些是白名单中能出现的仅有主体，所以也是仅有需要
 * 一个主体的两种拼写得出相等结果的比较处。这很重要：
 * GitHub windows-latest runner 上的用户是内建 Administrator，
 * 其自有 ACE 写作 LA，比较原始 SID 使运维对自己的配置成了陌生人——
 * 60 个测试以「访问授予了 LA」失败。
 *
 *
 * 其余十四个判定中性：未解析别名原样透传、两种方式都被拒。
 * 它们存在使拒绝按主体报一条、打印修复可以点名的 SID——
 * 因此这份清单的长度不是安全属性。
 *
 */
const ALIAS_SIDS: ReadonlyMap<string, string> = new Map([
  ['SY', 'S-1-5-18'],
  ['BA', 'S-1-5-32-544'],
  ['WD', 'S-1-1-0'],
  ['BU', 'S-1-5-32-545'],
  ['AU', 'S-1-5-11'],
  ['IU', 'S-1-5-4'],
  ['BG', 'S-1-5-32-546'],
  ['AN', 'S-1-5-7'],
  ['PU', 'S-1-5-32-547'],
  ['NU', 'S-1-5-2'],
  ['SU', 'S-1-5-6'],
  ['RU', 'S-1-5-32-554'],
  ['WR', 'S-1-5-33'],
  ['CO', 'S-1-3-0'],
  ['LS', 'S-1-5-19'],
  ['NS', 'S-1-5-20'],
  ['RC', 'S-1-5-12'],
]);

/**
 * LA 是这个东西存在的理由；组条目在这里是为了让描述符
 * 两种拼写指同一主体时只报一次而非两次——
 * 显示名仍来自原始受托者，DU 读作 Domain Users
 * 而 SID 拼写读作 SID。
 *
 */
const DOMAIN_RELATIVE_RIDS: ReadonlyMap<string, number> = new Map([
  ['LA', 500],  // built-in Administrator
  ['LG', 501],  // built-in Guest
  ['DA', 512],  // Domain Admins
  ['DU', 513],  // Domain Users
  ['DG', 514],  // Domain Guests
  ['DC', 515],  // Domain Computers
  ['DD', 516],  // Domain Controllers
  ['CA', 517],  // Cert Publishers
  // 这两个只存在于林根域，对照*我们的*账户域展开得到的是
  // 子域中不存在的 SID。对判定无害——解析为空的 SID
  // 不在白名单中，ACE 两种方式都被拒——但修复
  // 会打印 icacls 无法映射的 /remove:g，
  // 正是 Grant.sid 存在要防止的缺陷。保留使拒绝点名主体；
  // SID 视为尽力而为。
  ['SA', 518],  // Schema Admins (forest root)
  ['EA', 519],  // Enterprise Admins (forest root)
  ['PA', 520],  // Group Policy Creator Owners
]);

/**
 * 我们预期在拒绝中必须点名的主体的显示名。仅为美观——
 * 未识别受托者以其 SID 或别名报告、两种方式都被拒，
 * 安全都与此表是否完整无关。
 *
 */
const PRINCIPAL_NAMES: ReadonlyMap<string, string> = new Map([
  ['WD', 'Everyone'], ['S-1-1-0', 'Everyone'],
  ['BU', 'BUILTIN\\Users'], ['S-1-5-32-545', 'BUILTIN\\Users'],
  ['AU', 'Authenticated Users'], ['S-1-5-11', 'Authenticated Users'],
  ['IU', 'Interactive'], ['S-1-5-4', 'Interactive'],
  ['BG', 'BUILTIN\\Guests'], ['S-1-5-32-546', 'BUILTIN\\Guests'],
  ['AN', 'Anonymous'], ['S-1-5-7', 'Anonymous'],
  ['PU', 'BUILTIN\\Power Users'], ['S-1-5-32-547', 'BUILTIN\\Power Users'],
  ['DU', 'Domain Users'],
  ['NU', 'NETWORK'], ['S-1-5-2', 'NETWORK'],
  ['SU', 'SERVICE'], ['S-1-5-6', 'SERVICE'],
  ['RU', 'Pre-Windows 2000 Compatible Access'], ['S-1-5-32-554', 'Pre-Windows 2000 Compatible Access'],
  ['WR', 'WRITE RESTRICTED'], ['S-1-5-33', 'WRITE RESTRICTED'],
  ['CO', 'CREATOR OWNER'], ['S-1-3-0', 'CREATOR OWNER'],
]);

/**
 * 不给受托者任何东西的 ACE 类型：拒绝、审计、告警
 * 与非 ACL 条目类型。
 *
 * 这里用拒绝清单、主体用白名单——各按 fail-safe 的方向。
 * 首版测试了 type === 'A' || type === 'OA'，
 * 静默跳过了 XA 和 ZA：条件允许 ACE，恰是 Dynamic Access
 * Control 放在受管文件上的东西。本类不识别的 ACE 类型
 * 是文法错误而非策略决定，必须 fail-closed。
 *
 */
const NON_GRANTING_ACE_TYPES: ReadonlySet<string> = new Set([
  'D', 'OD', 'XD',                    // 拒绝访问
  'AU', 'AL', 'OU', 'OL', 'XU',       // 审计和告警
  'ML', 'RA', 'SP', 'TL', 'FL',       // 标签、属性、策略、信任、过滤
]);

/**
 * 两种不同的旗标词汇，容易混淆——初稿混淆了，将每个真实
 * 描述符都拒绝为不可解析，因为 D:AI(...) 携带的是*控制*旗标
 * 而非 ACE 旗标。
 *
 * DACL 控制旗标限定整个 ACL：P 受保护（阻止继承）、
 * AI 自动继承、AR 需要自动继承。P 是单字符，
 * 所以这些不能用固定宽度分块读取。
 */
const DACL_CONTROL_FLAGS = /^(?:P|AI|AR)*$/;

/** ACE 旗标，全部两个字符。 */
const ACE_FLAG_CODES: ReadonlySet<string> = new Set([
  'CI', 'OI', 'IO', 'NP', 'ID', 'SA', 'FA', 'TP', 'CR',
]);

/**
 * 让受托者可以修改对象的权限，SDDL 字母码。这里的 WD 是
 * WRITE_DAC 而非 Everyone——权限字段和受托者字段使用
 * 恰好共享拼写的独立词汇表。
 */
const WRITE_RIGHT_CODES: ReadonlySet<string> = new Set([
  'FA', 'FW', 'KA', 'KW', 'GA', 'GW', 'SD', 'WD', 'WO', 'CC', 'DC', 'SW', 'WP', 'DT',
]);

/** Rights that only let a trustee look. Anything unrecognised counts as write. */
const READ_RIGHT_CODES: ReadonlySet<string> = new Set([
  'FR', 'FX', 'GR', 'GX', 'KR', 'RC', 'RP', 'LC', 'LO',
]);

/**
 * DELETE、WRITE_DAC、WRITE_OWNER、GENERIC_WRITE、GENERIC_ALL。
 *
 */
const WRITE_MASK = 0x2 | 0x4 | 0x10 | 0x100 | 0x10000 | 0x40000 | 0x80000 | 0x40000000 | 0x10000000;

/**
 *
 * 这一区别是默认姿态的基础，该字段过去被解析后丢弃。
 * Windows 上的读暴露确实比 POSIX 含糊——共享卷授予
 * BUILTIN\Users 读，拒绝它曾让 #138 的报告者搁浅——
 * 但写暴露毫无含糊：一个 ACE 给非属主
 * FILE_WRITE_DATA 或 WRITE_DAC 与 0o022 一样毫不含糊，
 * 另一账户可以改写的配置决定本服务器认可哪些主机、角色
 * 和审批策略。那是授权绕过而非信息泄露，过去却被报为后者。
 *
 * 从真实继承实测：0x1200a9 是读和执行，0x1301bf 是修改。
 * 此处无法分类的一律算写，拒绝是安全的方向。
 *
 */
function grantsWrite(rights: string): boolean {
  const field = rights.trim().toUpperCase();
  if (field === '') return true;
  if (/^0X[0-9A-F]+$/.test(field)) return (Number.parseInt(field.slice(2), 16) & WRITE_MASK) !== 0;
  if (/^[0-9]+$/.test(field)) return (Number.parseInt(field, 10) & WRITE_MASK) !== 0;
  if (field.length % 2 !== 0) return true;
  for (let i = 0; i < field.length; i += 2) {
    const code = field.slice(i, i + 2);
    if (WRITE_RIGHT_CODES.has(code)) return true;
    if (!READ_RIGHT_CODES.has(code)) return true;
  }
  return false;
}

export interface Grant {
  /** 运维在 icacls 输出中如何看到它；回落到受托者。 */
  name: string;
  /** 受托者恰如描述符拼写的样子——SID 或 SDDL 别名。 */
  trustee: string;
  /**
   * The resolved SID, which is what a remediation must name.
   *
   * `*` introduces a SID for `icacls /remove:g`. That SDDL *aliases* work there at all
   * is undocumented — the SID Strings page says the conversion APIs do not support SDDL
   * constants — and it is not uniform. Measured on a workgroup host (a `windows-latest`
   * runner): `*WD` is accepted, `*DU` exits 1337, ERROR_NONE_MAPPED, having processed 0
   * files. The split is not about obscurity: `WD` is a fixed SID while `DU` is
   * domain-relative and needs an account domain to expand against, which that host does
   * not have. So printing the alias makes the command's success depend on the operator's
   * domain membership.
   *
   * The SID is already computed to make the decision, so using it means the message and
   * the verdict cannot disagree, on any host.
   */
  sid: string | null;
  /** 此授权是否让受托者修改文件而非仅读取。 */
  writes: boolean;
}

/** ACL 为何无法确定。决定我们是拒绝还是继续。 */
export type UnknownReason =
  /** 此机器上无 icacls。文件本身无可疑之处。 */
  | 'tool-missing'
  /**
   * The check ran out of time. Also a statement about the machine rather than the
   * file — a cold host or an on-access scanner can outlast any budget — so it is
   * treated like a missing tool rather than as grounds to refuse.
   */
  | 'timed-out'
  /** The identity to compare against could not be established. */
  | 'identity-unknown'
  /** icacls ran and would not or could not describe this path. */
  | 'read-refused'
  /** A descriptor came back that this parser cannot account for. */
  | 'unparsable';

export type AclVerdict =
  /** Nobody but the owner, SYSTEM and Administrators. */
  | { status: 'restricted' }
  /** Named trustees beyond the owner hold access. */
  | { status: 'broad'; grants: Grant[] }
  /** A NULL DACL: full control for every principal, expressed by having no ACL. */
  | { status: 'no-dacl' }
  /** No answer. The caller decides what an absent answer means. */
  | { status: 'unknown'; reason: UnknownReason; detail: string };

/**
 * Whether a group's parentheses balance when quoting is ignored.
 *
 * The quote handling closed one merge and opened another: two ACEs whose conditional
 * literals each carry a single unmatched `"` put the scanner into `inQuotes` across the
 * intervening `)(`, collapsing every ACE between them into one group whose type, flags
 * and trustee the attacker chooses. Five shapes were executed against the previous
 * version and all five came back `restricted` while hiding real Everyone, Users and
 * Authenticated Users grants.
 *
 * Where the quote-aware and quote-blind scans disagree, the quotes were load-bearing
 * across an ACE boundary and the descriptor is not something to draw a conclusion from.
 */
function quoteBlindBalanced(group: string): boolean {
  let depth = 0;
  for (const ch of group) {
    if (ch === '(') depth++;
    else if (ch === ')') {
      depth--;
      if (depth < 0) return false;
    }
  }
  return depth === 0;
}

/**
 * ACE groups from a DACL body, respecting nesting *and quoting*.
 *
 * The quote handling is not decoration. A conditional ACE (`XA`/`ZA`) carries an
 * expression whose string literals may contain parentheses, and SDDL gives them
 * no escape. A quote-blind scan can therefore be fed two conditional ACEs whose
 * literals hold `"("` and `")"`, which merges every ACE between them into a
 * single group — and field 5 of the merged blob is the *first* ACE's trustee,
 * which the attacker sets to the owner. Verified before the fix: a descriptor
 * bracketing the real `BUILTIN\Users` and `Authenticated Users` grants that way
 * came back `restricted`.
 *
 * That is the previous version's truncating regex returning as a merging scan,
 * and it fails in the same unsafe direction, so the counting has to know about
 * quotes. SDDL string literals have no `"` escape, which makes a plain toggle
 * exact rather than approximate.
 */
function aceGroups(body: string): string[] | null {
  const groups: string[] = [];
  let depth = 0;
  let start = -1;
  let inQuotes = false;
  for (let i = 0; i < body.length; i++) {
    const ch = body[i];
    if (ch === '"') {
      inQuotes = !inQuotes;
      continue;
    }
    if (inQuotes) continue;
    if (ch === '(') {
      if (depth === 0) start = i + 1;
      depth++;
    } else if (ch === ')') {
      depth--;
      // A stray ')' means this is not a descriptor we understand.
      if (depth < 0) return null;
      if (depth === 0) {
        const group = body.slice(start, i);
        if (!quoteBlindBalanced(group)) return null;
        groups.push(group);
      }
    }
  }
  // An unterminated quote means the same thing as unbalanced parentheses: we do
  // not know where this ACE ends, so we do not know what it grants.
  return depth === 0 && !inQuotes ? groups : null;
}

/** Whether a DACL's own flag string is one we recognise. */
function daclFlagsAreValid(flags: string): boolean {
  return flags === 'NO_ACCESS_CONTROL' || DACL_CONTROL_FLAGS.test(flags);
}

/**
 * An ACE flag string as the set of two-character codes it is made of, or null if
 * it is not made of them.
 *
 * Returning the set rather than a boolean is what makes the inherit-only test
 * safe. `flags.includes('IO')` matched across a code boundary: `CIOI` — accepted
 * by this order-agnostic validator — contains the substring `IO` spanning CI and
 * OI, so a grant that does apply to the object was discarded as inherit-only.
 * Measured before the fix: `D:(A;CIOI;FA;;;WD)` came back restricted while
 * `D:(A;OICI;FA;;;WD)` correctly came back broad.
 */
function aceFlagCodes(flags: string): Set<string> | null {
  if (flags.length % 2 !== 0) return null;
  const codes = new Set<string>();
  for (let i = 0; i < flags.length; i += 2) {
    const code = flags.slice(i, i + 2);
    if (!ACE_FLAG_CODES.has(code)) return null;
    codes.add(code);
  }
  return codes;
}

/**
 * Trustees this parser is willing to act on: a SID, or an SDDL alias.
 *
 * Anything else is `unparsable` rather than "a principal named oddly". Two
 * reasons. It stops a trustee field from being trusted purely for being
 * non-empty, which is what the merged-group attack above relied on; and the
 * value is interpolated into an `icacls` command the operator is told to paste,
 * where `FOO"BAR` produced an unbalanced-quote command line.
 */
const TRUSTEE = /^(?:S-1-[0-9]+(?:-[0-9]+)*|[A-Z]{2})$/;

function nameFor(trustee: string): string {
  return PRINCIPAL_NAMES.get(trustee) ?? trustee;
}

/** The account a descriptor is judged for. */
export interface AclIdentity {
  /** SIDs that may hold access. */
  allowed: ReadonlySet<string>;
  /**
   * The account-domain portion of our own SID — everything before the final RID.
   * Lets `LA`, `DU` and friends resolve to real SIDs rather than staying opaque.
   */
  accountDomain?: string;
}

/** The SID a trustee names, resolving both kinds of alias. */
function resolveTrustee(trustee: string, accountDomain?: string): string | null {
  const fixed = ALIAS_SIDS.get(trustee);
  if (fixed) return fixed;
  const rid = DOMAIN_RELATIVE_RIDS.get(trustee);
  if (rid !== undefined && accountDomain) return `${accountDomain}-${rid}`;
  // A trustee that already *is* a SID resolves to itself; only an alias this cannot
  // expand comes back null.
  if (trustee.startsWith('S-1-')) return trustee;
  // Null, not the trustee. Returning the raw alias let it travel on as `Grant.sid` and
  // be printed as `/remove:g *OW` — and `*` declares a numeric SID to icacls, so that
  // command removes nothing. Reproduced for `AC` (on `C:\Program Files`), `OW` (on
  // redirected profiles), `RD`, `ED`, `PS`, `LW`, and for every domain-relative alias on
  // a host with no derivable account domain: a service identity or an Entra-joined
  // account. The operator restarted into the identical refusal, and
  // --allowUncheckedConfigAcl deliberately does not cover a `broad` verdict, so the
  // message was a dead end. Fifth instance of this defect in this change.
  return null;
}

/**
 * What a security descriptor's DACL grants, judged against the SIDs allowed to
 * hold access.
 *
 * Returns `unknown` for anything it cannot fully account for. That is the whole
 * point of the rewrite: the first version had one output — an empty list — for
 * "restricted to the owner" and for "I found nothing I recognise", which are
 * opposite security conclusions. It reported `D:NO_ACCESS_CONTROL` (full
 * control for everyone), a descriptor with no `D:` at all, a conditional ACE,
 * and the string `D:\` as safe.
 *
 * Exported so the parsing runs on every CI platform rather than only on the
 * Windows job. The fixtures are real `icacls /save` output.
 */
export function parseDacl(descriptor: string, identity: AclIdentity): AclVerdict {
  const { allowed: allowedSids, accountDomain } = identity;
  const unknown = (detail: string): AclVerdict => ({ status: 'unknown', reason: 'unparsable', detail });

  const marker = descriptor.indexOf('D:');
  if (marker === -1) return unknown('no DACL component');

  let body = descriptor.slice(marker + 2);
  // A SACL may follow. Cut at the boundary, which is the ')' closing the last
  // DACL ACE — or immediately, for a DACL with no ACEs at all.
  const saclAfterAce = body.search(/\)S:/);
  if (saclAfterAce !== -1) body = body.slice(0, saclAfterAce + 1);
  else if (body.startsWith('S:')) body = '';
  else {
    const bareSacl = body.indexOf('S:');
    if (bareSacl !== -1 && !body.slice(0, bareSacl).includes('(')) body = body.slice(0, bareSacl);
  }

  const firstAce = body.indexOf('(');
  const flags = (firstAce === -1 ? body : body.slice(0, firstAce)).trim();
  if (!daclFlagsAreValid(flags)) return unknown(`unrecognised DACL flags ${JSON.stringify(flags)}`);

  // A NULL DACL grants full control to every principal. It carries no ACEs, so
  // an ACE scan finds nothing and would call it restricted.
  if (flags === 'NO_ACCESS_CONTROL') return { status: 'no-dacl' };

  const groups = aceGroups(firstAce === -1 ? '' : body.slice(firstAce));
  if (groups === null) return unknown('unbalanced parentheses in the DACL');

  // An empty DACL is not a missing one: it denies everyone, which is private.
  if (groups.length === 0) return { status: 'restricted' };

  const grants = new Map<string, Grant>();
  for (const ace of groups) {
    const fields = ace.split(';');
    if (fields.length < 6) return unknown(`ACE with ${fields.length} fields: ${JSON.stringify(ace)}`);

    const type = fields[0].trim().toUpperCase();
    if (NON_GRANTING_ACE_TYPES.has(type)) continue;

    const aceFlags = fields[1].trim().toUpperCase();
    const flagCodes = aceFlagCodes(aceFlags);
    if (flagCodes === null) {
      return unknown(`unrecognised ACE flags ${JSON.stringify(aceFlags)}`);
    }
    // Inherit-only grants nothing on this object; it applies to children, whose
    // own descriptors are read separately.
    if (flagCodes.has('IO')) continue;

    const trustee = fields[5].trim().toUpperCase();
    if (!TRUSTEE.test(trustee)) {
      return unknown(`ACE with an unrecognised trustee ${JSON.stringify(fields[5])}`);
    }
    const sid = resolveTrustee(trustee, accountDomain);
    if (sid !== null && allowedSids.has(sid)) continue;

    grants.set(sid ?? trustee, {
      name: nameFor(trustee), trustee, sid, writes: grantsWrite(fields[2]),
    });
  }

  return grants.size === 0 ? { status: 'restricted' } : { status: 'broad', grants: [...grants.values()] };
}

/**
 * Which SIDs a descriptor may name, given the account we run as.
 *
 * Separate from `inspectAcl` so the rule is asserted rather than mirrored. While
 * it was inline, both test suites built a replica of this set by hand — so adding
 * `BUILTIN\Users` to the allowlist, or dropping the RID-500 entry, left every
 * off-Windows test green and failed only on the advisory Windows job. Two
 * mutations survived the required check that way.
 */
export function aclIdentity(sid: string): AclIdentity {
  // Classic account domains only: `S-1-5-21-A-B-C-1001` -> `S-1-5-21-A-B-C`. An
  // Entra-joined account is `S-1-12-1-…` and has no account domain, so the
  // domain-relative aliases stay unresolved there and fail closed.
  const accountDomain = /^(S-1-5-21-[0-9-]+)-\d+$/.exec(sid)?.[1];
  const allowed = new Set([...ALWAYS_ALLOWED_SIDS, sid]);
  // RID 500 is the built-in Administrator. In a default configuration it belongs
  // to the Administrators group, which is already allowed, so naming the account
  // directly grants nobody new access — while refusing it is a false positive,
  // and here that means refusing, or at best warning, about a config that is fine. (On a
  // domain-joined host the account domain is the domain, so this authorises
  // DOMAIN\Administrator, whose local-admin status comes from Domain Admins
  // nesting — a GPO default rather than a law.)
  if (accountDomain) allowed.add(`${accountDomain}-500`);
  return { allowed, accountDomain };
}
