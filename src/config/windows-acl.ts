import { execFile } from 'child_process';
import { promisify } from 'util';
import { existsSync, realpathSync } from 'fs';
import { mkdtemp, readFile, rm } from 'fs/promises';
import { tmpdir, userInfo } from 'os';
import { join, resolve, parse as parsePath } from 'path';
import { OperatorError } from '../errors.js';
import { isWithinRoot } from './path-containment.js';
import {
  parseDacl,
  aclIdentity,
  type Grant,
  type UnknownReason,
  type AclVerdict,
} from './sddl.js';

const run = promisify(execFile);

const WINDOWS_ROOT = /^[A-Za-z]:\\Windows$/;
const CANONICAL_SYSTEM32 = 'C:\\Windows\\System32';

/**
 * 绝对路径，非裸名——且非调用方可选的路径。
 *
 * 这些子进程决定配置文件是否私有，所以谁应答不能由环境决定。
 * Windows 经应用目录、工作目录、然后 PATH 解析裸名，
 * 工作目录属于生成我们的 MCP 客户端；种植的 icacls.exe
 * 会以运维身份运行*并*决定判定，因为它只需输出一行
 * 读作 D:(A;ID;FA;;;SY) 的内容。
 *
 *
 * 本注释首版声称环境无法影响判定、随后却读 %SystemRoot%，
 * 而同一父进程设置它——洞移了一个变量而非关闭。
 * 所以该值仅在真实 Windows 根的形状下被接受，且 readDescriptor
 * 不会在未检查规范位置的情况下把「icacls 不在此处」当
 * 「本机无 icacls」——因为该判定是无论如何都会加载的那个。
 *
 *
 * 一件它*没有*关闭的事：os.tmpdir() 从同一环境读 TEMP/TMP，
 * 那正是描述符写入和读回的地方。把 TEMP 指向自己监视处的父进程
 * 拥有 icacls 写 acl.sddl 与我们 readFile 之间的窗口，
 * 可替换为一行读作 D:(A;ID;FA;;;SY) 的内容。
 * 从另一环境变量取临时根会把问题移动而非解决，
 * 且拥有那么多控制的父进程本就选择我们的 argv——它可以直接传
 * --allowUncheckedConfigAcl。威胁模型的已知限制，而非已处理。
 */
function systemDir(): string {
  // 规范位置优先。形状不是完整性：前一版本接受任何匹配
  // /^[A-Za-z]:..Windows$/ 的 %SystemRoot%，而可移动介质上的
  // Z:.Windows、映射驱动器、subst 别名或挂载 VHD 都满足——
  // 于是两个子进程都成了攻击者的，且一个全世界可读的配置被报为
  // restricted 无任何告警。本变更前已复现。任何正常主机上
  // C:.Windows.System32.icacls.exe 都存在，环境根本无法重定向。
  if (existsSync(join(CANONICAL_SYSTEM32, 'icacls.exe'))) return CANONICAL_SYSTEM32;
  const fromEnv = process.env.SystemRoot;
  return fromEnv && WINDOWS_ROOT.test(fromEnv) ? join(fromEnv, 'System32') : CANONICAL_SYSTEM32;
}

const SYSTEM32 = systemDir();
const ICACLS = join(SYSTEM32, 'icacls.exe');
const WHOAMI = join(SYSTEM32, 'whoami.exe');

/**
 * 这些子进程继承什么：什么都不继承。不读我们的任何配置，
 * Path 仅 System32，因此它们可能启动的任何东西也无处重定向。
 */
const CHILD_ENV: NodeJS.ProcessEnv = { SystemRoot: join(SYSTEM32, '..'), Path: SYSTEM32 };

/**
 *
 *
 * 按子进程是首版形状，使上限变成检查恰好生成的子进程数之和——
 * 今天三个，服务器报告就绪前 4.5 秒死寂，对照实测 happy path
 * 的 60-150ms。
 *
 * 首版只把信号传给 execFile，留下 mkdtemp、readFile 和 rm——
 * 跨两个主体的六次操作——在注释声称的界之外。被重定向到
 * 停滞共享的 %TEMP% 使启动延迟无界而非五秒。截止时间现在
 * 与整个单主体检查竞速，数字说它意味着什么就是什么。
 *
 *
 * 宽裕，因为耗尽不构成关于文件的证据：三次进程创建加两次
 * 临时目录往返共五秒，使按需扫描器有余地。
 *
 * 超时有自己的判定，同一理由——见 timed-out。
 */
const ACL_TIMEOUT_MS = 5_000;


/**
 * 调用方会被告知的发现，无论是否也拒绝。
 *
 * 判别联合，因为两种不是同一陈述，日志读者必须区分：
 * 「此 ACL 让 Authenticated Users 修改你的配置」和「我无法读此 ACL」
 * 是不同事实，前者更可行动。更早的形状只能表达后者，
 * 更强的发现直接进了 console.error，调用方无法触及——
 * 正是 onFinding 自己的文档说不许发生的。
 *
 */
export type AclFinding =
  | {
      path: string; kind: 'file' | 'directory';
      status: 'unchecked'; reason: UnknownReason; detail: string; message: string;
    }
  | {
      path: string; kind: 'file' | 'directory';
      status: 'broad' | 'no-dacl'; grants: Grant[]; message: string;
    };

export interface AclOptions {
  /**
    * ACL 可被属主以外读取时拒绝而非告警。
    * --strictConfigAcl。默认关，而默认正是要点。
    *
    * 2.3.0 曾默认拒绝，第一天就在文档化的 %APPDATA% 位置
    * 挡住了一位报告者的配置——他们的 ACL 带了第四个主体，
    * 白名单建时不知道它，因为白名单是在一台机器上实测的。
    * --allowUncheckedConfigAcl 刻意不覆盖已知坏的判定，
    * 于是完全无路可走：一个安全检查，最坏结果是把运维
    * 锁在自己的配置之外，而 Windows 对该保证的表述不如 POSIX 清晰。
    *
   *
    * 所以发现被报告、配置加载。检查知道的仍值得说——
    * C:\ 下的配置确实给 BUILTIN Users 读和 Authenticated Users 修改——
    * 但说出来和拒绝是两件事，只有其中一件能把人困住。
    *
   */
  enforce?: boolean;
  /**
    * 即使 ACL 无法确定也加载配置。
    * --allowUncheckedConfigAcl。
   */
  allowUnchecked?: boolean;
  /**
    * 「这条检查没跑」去哪。
    *
    * 它曾从配置加载器内部直达 console.error，对 stdio MCP
    * 服务器那是客户端的日志文件——而本代码库已两次裁定
    * stderr 不能是唯一副本（policy/engine.ts、
    *），因为它与 stdout 竞速、被吞、且在客户端断开时丢弃。
    *
   * 到 stderr 使模块自立。
   */
  onFinding?: (finding: AclFinding) => void;
}

/**
 * 本进程以其运行的账户的 SID。
 *
 * 需要它是因为 icacls /save 只输出 DACL——没有 O: 属主组件——
 * 所以「属主」必须来自别处，而 Node 不暴露 SID
 *（os.userInfo().uid 在 Windows 上是 -1）。实测 12-20ms，
 * 成功后每进程只付一次——只有成功被缓存，失败会重试。
 */
let cachedUserSid: string | null | undefined;

async function currentUserSid(signal?: AbortSignal): Promise<string | null> {
  if (cachedUserSid !== undefined) return cachedUserSid;
  try {
    const { stdout } = await run(WHOAMI, ['/user', '/fo', 'csv', '/nh'], {
      signal,
      windowsHide: true,
      env: CHILD_ENV,
    });
    // 形如 host user 加逗号加 SID
    const sid = stdout.match(/"(S-1-[0-9-]+)"/)?.[1];
    // 只记住成功。缓存失败使一次中止或瞬态的 whoami
    // 在进程生命周期内钉死 identity-unknown，此后每次检查都拒绝——
    // 还迫使导出一个 resetIdentityCache，其唯一调用方
    // 是撤销该污染的测试。
    if (sid) cachedUserSid = sid;
    return sid ?? null;
  } catch {
    return null;
  }
}

/**
 * icacls /save 写的安全描述符文件的每一行。
 *
 * 保存的文件是 UTF-16LE，一行是条目名、下一行是其描述符。
 * 哪行是什么不在此猜——调用方把每行交给解析器、保留第一个
 * 能解析的，使读取器和解析器不可能对描述符的样子不一致。
 * 首版它们确实不一致：读取器要求以 D: 开头的行，
 * 解析器却接受 O:/G: 前缀，分歧解析为 unchecked。
 *
 * "unchecked".
 *
 * 用 /save 的 SDDL 而非 PowerShell 的 Get-Acl，后者的描述符
 * 带 O: 属主组件、省下第二个子进程：实测 8-22ms 对 740-830ms，
 * 而检查每次启动都跑。也不用普通 icacls 输出——它打印
 * 依赖安装语言的账户名。那段推理只活在变更集中，发布即删。
 *
 *
 * Microsoft 对目录文档化了 /save；单文件形式无文档但真实，
 * windows-acl.live.test.ts 用断言一个只有描述符可解析才可达的
 * 拒绝来覆盖它。
 */
/**
 * 描述符读取失败意味着什么。
 *
 * 除注入的存在性检查外为纯函数，因为最重要的分支在
 * 任何平台的测试中均不可达：非 Windows 上身份查找先失败，
 * Windows 作业上只有 read-refused 臂被走到。固定 System32 的
 * 安全论证正是规范位置检查，而它之前什么都没执行过。
 *
 *
 * 两种失败不构成关于文件的证据——机器上缺 icacls、
 * 检查超时——而即使在 --strictConfigAcl 下调用方
 * 也照样加载的正是这两个。
 *
 *
 * 这使「缺席」值得确认：此处缺席不够，因为重定向的 %SystemRoot%
 * 否则会到达 fail-open 分支，固定路径的存在正是为了阻止它。
 *
 */
export function classifyReadFailure(
  err: any,
  exists: (path: string) => boolean = existsSync,
): { failure: UnknownReason; detail: string } {
  const notHere = err?.code === 'ENOENT' && typeof err?.path === 'string' && err.path === ICACLS;
  const missing = notHere && !exists(join(CANONICAL_SYSTEM32, 'icacls.exe'));
  if (err?.name === 'AbortError') {
    return { failure: 'timed-out', detail: `the check exceeded its ${ACL_TIMEOUT_MS}ms budget` };
  }
  if (missing) return { failure: 'tool-missing', detail: String(err?.message ?? err).split('\n')[0] };
  if (notHere) {
    return {
      failure: 'read-refused',
      detail: `${ICACLS} is missing but ${CANONICAL_SYSTEM32}\\icacls.exe is not — %SystemRoot% looks wrong`,
    };
  }
  return { failure: 'read-refused', detail: String(err?.message ?? err).split('\n')[0] };
}

async function readDescriptor(
  path: string,
  signal?: AbortSignal,
): Promise<{ lines: string[] } | { failure: UnknownReason; detail: string }> {
  let dir: string | undefined;
  try {
    dir = await mkdtemp(join(tmpdir(), 'ssh-mcp-acl-'));
    const saved = join(dir, 'acl.sddl');
    await run(ICACLS, [path, '/save', saved], { signal, windowsHide: true, env: CHILD_ENV });
    const text = await readFile(saved, { encoding: 'utf16le', signal });
    return { lines: text.split(/\r?\n/) };
  } catch (err: any) {
    return classifyReadFailure(err);
  } finally {
    // 不等待：rm 不收信号，await 它会把无界文件系统操作
    // 放到服务器启动等待的路径上。该目录装的是安全描述符
    // 而非机密，且 %TEMP% 按用户隔离——输给停滞磁盘的竞速
    // 代价是一个游离目录，而非正确性。
    if (dir) void rm(dir, { recursive: true, force: true }).catch(() => {});
  }
}

/**
 * 先到者：判定，或截止时间。
 *
 * 信号到达子进程，但 mkdtemp 和 rm 不收，所以没有这个
 * 预算只约束检查九次操作中的三次。超时解析为与子进程超时
 * 相同的判定——告警并加载：慢机器不构成关于文件的证据。
 *
 */
function raceDeadline(verdict: Promise<AclVerdict>, signal?: AbortSignal): Promise<AclVerdict> {
  if (!signal) return verdict;
  const expired = new Promise<AclVerdict>((resolve) => {
    if (signal.aborted) resolve(TIMED_OUT);
    else signal.addEventListener('abort', () => resolve(TIMED_OUT), { once: true });
  });
  return Promise.race([verdict, expired]);
}

const TIMED_OUT: AclVerdict = {
  status: 'unknown',
  reason: 'timed-out',
  detail: `the check exceeded its ${ACL_TIMEOUT_MS}ms budget`,
};

/** Read one path's DACL and judge it. */

export async function inspectAcl(path: string, signal?: AbortSignal): Promise<AclVerdict> {
  const sid = await currentUserSid(signal);
  // 预算耗尽必须处处意味着同一件事。whoami 先跑且失败
  // 在 catch 内不可分辨，没有这个的话身份查找期间的超时
  // 变成 identity-unknown 且*拒绝*，而晚一个子进程的同一超时
  // 变成 timed-out 并加载。只缓存成功，于是目录也被拒第二次。
  //
  if (sid === null && signal?.aborted) return TIMED_OUT;
  if (sid === null) {
    return { status: 'unknown', reason: 'identity-unknown', detail: 'could not read this account\'s SID' };
  }
  const identity = aclIdentity(sid);

  const read = await readDescriptor(path, signal);
  if ('failure' in read) return { status: 'unknown', reason: read.failure, detail: read.detail };

  // 读取器不决定哪行是描述符；解析器决定。
  let lastDetail = 'no line parsed as a security descriptor';
  for (const line of read.lines) {
    const trimmed = line.trim();
    // 描述符以其组件之一开头。没有这个，「第一行能解析」让
    // 条目名行顶替描述符：parseDacl 的 D: 是合法的空 DACL 因而是
    // restricted，而对驱动器相对的 --config D:config.toml 跑
    // icacls D: /save 恰好写出一行名为 D: 的名字行。
    if (!/^[OGDS]:/.test(trimmed)) continue;
    const verdict = parseDacl(trimmed, identity);
    if (verdict.status !== 'unknown') return verdict;
    lastDetail = verdict.detail;
  }
  return { status: 'unknown', reason: 'unparsable', detail: lastDetail };
}

/**
 * 路径是否处于其 ACL 可以被合理收紧的地方。
 *
 * 驱动器根或工作目录不是：C: 下配置的修复过去被打印为
 * icacls C: 加 /inheritance:d 后接对 BUILTIN Users 的 /remove:g——
 * 照原样运行会破坏整个卷的继承、把驱动器从每个非管理员手里拿走。
 * 那种位置的配置的修复是把它放到别处。
 *
 */
function isTightenable(path: string, kind: 'file' | 'directory'): boolean {
  // 文件总是可收紧。从单个配置文件移除 BUILTIN Users
  // 不从任何人手里拿走任何东西——破坏性情形从来只是目录，
  // 把两者都框进来会让现实情形的建议（配置在 C: 下）
  // 比它替代的东西更糟。
  if (kind === 'file') return true;

  const { root } = parsePath(path);
  if (path === root || path === '.' || path === '..') return false;
  // 对目录，不只是「是否为根」。C: 下一切继承 BUILTIN Users
  // 的读和执行，profile 之外的任何目录都可能回来 broad——
  // 而 C:Users 下配置会得到「从 C:Users 移除 BUILTIN Users」，
  // 这会移除其他所有账户到自己 profile 的遍历路径。首版按路径
  // 拼写键控，只抓到被报告的两种形状。
  //
  //
  // profile 之外以描述而非打印给出修复。运维确实拥有的目录
  //——比如 D:configs——完全可以收紧，让他们移文件是差建议；
  // 但那无法与其他账户依赖的目录区分，而两种错误中只有一种是
  // 破坏性的。
  //
  const home = process.env.USERPROFILE;
  // 没有 profile 可对照时诚实的回答是「无法判断」，
  // 于是告警而非收紧。
  //
  // 在共享目录上破坏继承并从中移除 BUILTIN Users。
  if (!home) return false;
  // 两侧都经 realpath：Windows 发放 8.3 短名，此比较的两端
  // 未必用同一种形式：GitHub runner 上 %TEMP% 是 C:.Users.RUNNER~1
  // 而 %USERPROFILE% 是 C:.Users.runneradmin，比较文本对一个
  // 完全在 profile 之内的目录说「在 profile 之外」，运维得到
  // 「移走配置」而修复只是两条命令。Windows 作业抓到了它；VM 没有。
  //
  //
  // 用 path.relative 而非前缀匹配：硬编码分隔符在测试运行的平台
  // 上就是错的，裸 startsWith 还会接受一个名字恰好以 profile 开头的
  // 兄弟目录（C:.Users.meloud）。
  //
  // 经 isWithinRoot 而非本地 !rel.startsWith：后者把合法命名的
  // 子项如 ..cache 当成逃逸。一处包含实现，与传输根门共享。
  //
  return isWithinRoot(canonical(home), canonical(path));
}

/**
 * 文件系统自身使用的形式的路径，小写。
 *
 * realpathSync.native 是展开 8.3 短名的那个。它要求路径存在，
 * 缺失时回落到词法解析。
 */
function canonical(path: string): string {
  try {
    return realpathSync.native(resolve(path)).toLowerCase();
  } catch {
    return resolve(path).toLowerCase();
  }
}

/**
 * 让路径重新变私有的两条命令。
 *
 * NULL DACL 时 grants 为空：没有可移除的，重点是给对象一个 ACL。
 * 共享而非写两遍：这段文本在本次变更中错误记录最差——
 * 至今三个修正版本——第二份就是第二件要继续修的东西。
 *
 */
function remediation(path: string, kind: 'file' | 'directory', grants: Grant[] = []): string {
  const resolved = grants.filter((g) => g.sid !== null);
  const unresolved = grants.filter((g) => g.sid === null);
  const removals = resolved.length
    ? ` ${resolved.map((g) => `/remove:g *${g.sid}`).join(' ')}`
    : '';
  // Named rather than guessed at: `/remove:g *<alias>` is accepted and removes nothing,
  // which is worse than admitting we cannot name the SID.
  const byHand = unresolved.length
    ? `\nOne entry cannot be named as a SID from here: ${unresolved.map((g) => g.name).join(', ')}. ` +
      `Run \`icacls "${path}"\` to see it and remove it by the SID icacls prints.`
    : '';
  const rights = kind === 'file' ? 'F' : '(OI)(CI)F';
  // The account name is interpolated rather than left as %USERNAME%. That spelling
  // is cmd.exe's; pasted into PowerShell — the default shell on Windows 11 — it
  // reaches icacls literally, which reports "Failed processing 1 files" and
  // changes nothing. Measured. An instruction that only works in one shell is
  // the same defect as the `chmod 600` this whole change replaced.
  //
  // Guarded because this is now on the *reporting* path, not only the throwing one. A
  // Windows service under a virtual account, or a container with no loaded profile, makes
  // `userInfo()` throw ENOENT — which escaped as a raw stack and cost the operator their
  // config, which is #138 one environment over. A message that cannot name the account is
  // still worth printing.
  //
  // A visible placeholder rather than `process.env.USERNAME`, which was the first spelling
  // of this fallback. In the environments where `userInfo()` actually throws the env var is
  // either unset or holds something icacls will not accept — a virtual service account, or
  // `MACHINE$` — so it would print a command that fails, which is the defect class this
  // whole change exists to remove. A placeholder the operator has to fill in cannot be
  // followed by mistake.
  let account: string;
  try {
    account = userInfo().username;
  } catch {
    account = '<your account>';
  }
  return (
    'Restrict it with these two commands, in this order:\n' +
    `  icacls "${path}" /inheritance:d\n` +
    `  icacls "${path}" /grant:r "${account}:${rights}"${removals}\n` +
    'The first converts inherited entries into entries this object owns — an inherited ' +
    'entry cannot be removed while it is still inherited, which is why it takes two ' +
    'commands. The second grants you full access and drops the broad ones. SYSTEM and ' +
    'Administrators keep theirs, which is what a file under %APPDATA% looks like.' +
    byHand
  );
}

function relocation(path: string, kind: 'file' | 'directory', grants: Grant[]): string {
  // The commands come from `remediation`, not from a copy, and they are printed rather
  // than referred to.
  //
  // Two reasons. Reaching this arm for a directory requires the *file* to have been
  // private — the loop reports the first offending subject — so the earlier wording,
  // "the same two commands shown for the file apply to it", pointed at text that was
  // absent every single time. And a hand-written pair here would have omitted the
  // `/remove:g` arguments, which is a command that reports success and leaves the
  // directory exactly as open as it was: the defect this whole change is about,
  // reproduced one arm over.
  return (
    'Move the config under %APPDATA%\\ssh-mcp instead, which inherits an ACL restricted ' +
    'to you, SYSTEM and Administrators.\n' +
    `${path} is a filesystem root, or sits outside your user profile, so removing the ` +
    'broad entries from it could take access away from every other account on the ' +
    'machine. If it is in fact yours alone, the commands below do it — but whether it ' +
    'is, only you can judge.\n' +
    remediation(path, kind, grants)
  );
}

/**
 * What a verdict means for one subject, as text and as data — and nothing else.
 *
 * Pure, so every message is assertable without a subprocess or a `console.error` spy, and
 * so the refusal and the report cannot drift apart: they sat fifteen lines apart and had
 * already diverged, one calling the same condition "was not checked" and the other "could
 * not be checked".
 */
function describe(path: string, kind: 'file' | 'directory', verdict: AclVerdict): AclFinding | null {
  if (verdict.status === 'restricted') return null;

  if (verdict.status === 'unknown') {
    return {
      path,
      kind,
      status: 'unchecked',
      reason: verdict.reason,
      detail: verdict.detail,
      message:
        `Config ${kind} ${path} could not be checked for access by other accounts ` +
        `(${verdict.reason}: ${verdict.detail}).\n` +
        'Either fix the cause, move the config under %APPDATA%\\ssh-mcp, or pass ' +
        '--allowUncheckedConfigAcl to accept it unverified.',
    };
  }

  // An empty grants list for a NULL DACL is deliberate: there is nothing to `/remove:g`,
  // and the fix is to give the object an ACL at all. `remediation` reads that emptiness.
  const grants = verdict.status === 'broad' ? verdict.grants : [];
  const writers = grants.filter((g) => g.writes);
  const readers = grants.filter((g) => !g.writes);
  const what = verdict.status === 'no-dacl'
    ? 'has no access control list at all, which on Windows means full control for every ' +
      'account on the machine.'
    : writers.length > 0
      // Named as modifiable, not "readable". Calling a modify grant readable understated an
      // integrity failure as a disclosure — and the two now decide different postures, so
      // the wording has to tell them apart.
      ? `can be modified by accounts other than its owner: ${writers.map((g) => g.name).join(', ')}` +
        `${readers.length ? `, and read by ${readers.map((g) => g.name).join(', ')}` : ''}. ` +
        'Required: this account, SYSTEM and Administrators only.'
      : `is readable beyond its owner: access is granted to ${grants.map((g) => g.name).join(', ')}. ` +
        'Required: this account, SYSTEM and Administrators only.';

  return {
    path,
    kind,
    status: verdict.status,
    grants,
    message:
      `Config ${kind} ${path} ${what}\n` +
      (isTightenable(path, kind) ? remediation(path, kind, grants) : relocation(path, kind, grants)),
  };
}

/**
 * Whether a finding is reported rather than refused.
 *
 * Three postures, two flags, and deliberately no combination that leaves an operator with
 * no exit — the lesson of #138, and why this is a function rather than one boolean.
 *
 * By default: a grant that only lets another account *read* is reported, because that is
 * where Windows is muddier than POSIX and refusing over it stranded a real operator. A
 * grant that lets another account *change* the config is refused, because that is an
 * authorization bypass and Windows is not muddy about it. An ACL that could not be
 * determined is refused too — #138 was a known-bad verdict, never an undeterminable one,
 * and flipping those open would let an attacker swap a loud finding for a vague one for
 * free. The two exceptions stay: `icacls` absent, and the check running out of time, both
 * statements about the machine rather than about the file.
 *
 * `--allowUncheckedConfigAcl` reports everything and refuses nothing — the single exit.
 * `--strictConfigAcl` refuses everything the check objects to, read-only grants included.
 */
function waived(finding: AclFinding, opts: AclOptions): boolean {
  if (opts.allowUnchecked) return true;
  if (opts.enforce) return false;
  if (finding.status === 'unchecked') {
    return finding.reason === 'tool-missing' || finding.reason === 'timed-out';
  }
  // A NULL DACL is full control for everyone, so it is never read-only.
  return finding.status === 'broad' && !finding.grants.some((g) => g.writes);
}

/**
 * Report what a config's ACL grants beyond its owner, and refuse when it is not merely
 * readable — the Windows half of `checkPermissions`.
 *
 * Both the file and its directory are examined. What happens to a finding is
 * `waived`'s decision; see it for the three postures and why the default is not to refuse
 * a read-only over-grant.
 */
export async function assertPrivateOnWindows(
  filePath: string,
  opts: AclOptions = {},
  inspect?: (path: string) => Promise<AclVerdict>,
): Promise<void> {
  // One deadline for the whole check, shared by every subprocess it starts.
  // A budget per subject, not one shared across both. Sharing it meant an expiry during
  // the file check aborted the directory check on entry, so one slow call did not degrade
  // the check — it disabled the rest of it.
  const look = inspect ?? ((p: string) => {
    const signal = AbortSignal.timeout(ACL_TIMEOUT_MS);
    return raceDeadline(inspectAcl(p, signal), signal);
  });
  const report = opts.onFinding ?? ((f: AclFinding) => console.error(`Warning: ${f.message}`));
  const subjects = [
    { path: filePath, kind: 'file' as const },
    { path: parsePath(filePath).dir || '.', kind: 'directory' as const },
  ];

  for (const { path, kind } of subjects) {
    const finding = describe(path, kind, await look(path));
    if (finding === null) continue;

    // One decision, read once. Refusing and reporting used to be decided in three places —
    // twice on the same flag for the same question — with two `continue`s and two throw
    // sites, and the advisory path wrote to stderr directly rather than through the sink.
    if (!waived(finding, opts)) throw new OperatorError(finding.message);
    report(finding);
  }
}
