import { McpError, ErrorCode } from '@modelcontextprotocol/sdk/types.js';
// 用分类器自己的解析器，不再造第二个。见下方 SYNTHETIC_NAMESPACE。
import { extractBinary } from '../policy/classifier.js';

/** Shell 会读作「一条命令结束、另一条开始」的所有字符。 */
const LINE_BREAKS = /[\r\n\u2028\u2029]/;
const NUL = /\u0000/;

/**
 * 本服务器自造的动词，调用方因此不得手输。
 *
 * `classifyOuter` 分不出合成字符串与调用方手打的字符串——两者
 * 到达时都是文本。于是 `sftp:list` 一被赋予类别，`read-command`
 * 也把它当命令词接受：实测，`readOnly` 的 viewer 可以发送
 * `read-command "sftp:list /tmp sudo id"`，分类器答 `read-only`，
 * 门放行，`exec` 执行。在 main 上同一字符串是 `safe`、会被拒绝。
 * was `safe` and refused.
 *
 * 审计日志从另一侧遇到同一问题：一条伪造记录与工具自产记录
 * 在每个字段上都相同。
 *
 * `sanitizeCommand` 是正确的位置，因为它按构造只对*不是*
 * 来自我们的命令运行——`runAudited` 在 `synthetic: true` 时跳过它。
 * `synthetic: true`.
 *
 * 对照 `extractBinary`（分类器自己的解析器）测试，而不是对照
 * 本文件自造的取首词助手。私助手先写、先漂移：`extractBinary`
 * 会剥掉前导 `-c ` 与前导提权前缀，助手不会，于是
 * `read-command "-c sftp:download /etc/shadow"` 解析出二进制
 * `sftp:download`、归类 `read-only`，在 main 上拒绝它的 profile
 * 放了行、也执行了。两个解析器回答同一个问题就是 bug；
 * 去问那个做决定的就是修法。
 * asking the one that decides is the fix.
 *
 * 保证的范围，刻意说窄：`sftp:*` 与 `session:*` 的审计记录
 * 可证明出自工具。`signal-process` 合成的
 * `kill -TERM <pid>` 不在此命名空间、也无法保留——
 * `kill` 是调用方可能正当需要的二进制——所以该形态的记录
 * 不在覆盖之内。
 */
const SYNTHETIC_NAMESPACE = /^(?:sftp|session):/;

export function sanitizeCommand(command: unknown, maxChars: number): string {
  if (typeof command !== 'string') {
    throw new McpError(ErrorCode.InvalidParams, 'Command must be a string');
  }
  const cleaned = command.trim();
  if (!cleaned) {
    throw new McpError(ErrorCode.InvalidParams, 'Command cannot be empty');
  }
  if (LINE_BREAKS.test(cleaned)) {
    throw new McpError(
      ErrorCode.InvalidParams,
      'Command cannot contain a line break: a second line would run past the classifier ' +
      'that only saw the first. It is refused rather than silently joined into one line, ' +
      'which is what happened before and changed what ran without saying so. ' +
      'To run a multi-line script, upload it with sftp-upload and execute it by path.',
    );
  }
  if (NUL.test(cleaned)) {
    throw new McpError(ErrorCode.InvalidParams, 'Command cannot contain a null byte');
  }
  if (SYNTHETIC_NAMESPACE.test(extractBinary(cleaned))) {
    throw new McpError(
      ErrorCode.InvalidParams,
      'Command cannot begin with "sftp:" or "session:": that namespace is reserved for the ' +
      'strings this server builds for its own tools, and the classifier cannot tell a typed ' +
      'one from a generated one. Use the sftp-* and *-session tools instead.',
    );
  }
  if (Number.isFinite(maxChars) && cleaned.length > maxChars) {
    throw new McpError(ErrorCode.InvalidParams, `Command is too long (max ${maxChars} characters)`);
  }
  return cleaned;
}

/**
 * 所有可能让「被审计的字符串、审批提示、实际用到的路径」
 * 三者互不一致的字符。
 *
 * C0 与 C1 控制符、Unicode 行分隔符、Bidi_Control 集合
 * （U+061C、U+200E、U+200F、U+202A-U+202E、U+2066-U+2069），以及
 * 自身不携带意义的零宽字符。远程路径会在审批提示里引给人看、
 * 写进哈希链审计记录，因此带右到左覆盖符的名字渲染成一条路径、
 * 传输的却是另一条；带零宽空格的名字渲染起来与另一条路径
 * 别无二致。
 * different path.
 *
 * 更早的版本止步于 overrides 与 isolates，漏掉了会重排*中性*字符的
 * 标记——而路径几乎全是中性字符：斜杠、点、连字符与数字。
 * slashes, dots, hyphens and digits.
 *
 * **U+200C 与 U+200D 刻意不在此列**，尽管它们落在本类更早版本
 * 的扫荡范围里。ZWNJ 与 ZWJ 不可见但并非无意义：它们在波斯语与
 * 印度语系文字中是正字法要求，在 emoji 序列中是结构成分。
 * 拒绝它们会拒绝真实文件名——实测，`/srv/mi<ZWNJ>ravad.txt`
 * 是文件系统接受、用户会敲出的名字。欺骗论证也够不到它们：
 * 那个论证依赖两条*不同*路径渲染一致，而本代码库早已接受
 * 同形字（西里尔 а 对拉丁 a）做到这一点，
 * 没有任何字符类能拦住。拒绝连接符却放过同形字，
 * 既不一致，也让合法输入付代价。
 *
 *
 * 导出是因为 `tools/local-path.ts` 对本地一半问的是同一个问题。
 * 两个*函数*分开有真实理由——那个必须 stat、这个必须不 stat——
 * 但字符类是同一个威胁模型，两份拷贝会在添加第一个码点时漂移。
 * copies of it drift the first time a codepoint is added.
 */
export const PATH_CONTROL_CHARS =
  /[\u0000-\u001f\u007f-\u009f\u061c\u200b\u200e\u200f\u2028-\u202e\u2060-\u2064\u2066-\u2069\ufeff]/;

/** 比任何真实文件系统接受的最长路径还长，因此不会误伤任何合法路径。 */
const MAX_REMOTE_PATH_CHARS = 4096;

/** 审计记录对未通过校验的路径的称呼。 */
export const REJECTED_REMOTE_PATH = '(rejected: invalid remote path)';

/**
 * 为流式 SFTP 文件工具校验调用方提供的*远程*路径。
 *
 * 纯函数：不碰文件系统、不达主机，正因如此它才能跑在
 * 策略决定之前（#207）。同一问题的本地一半在
 * `tools/local-path.ts`，那边无法保持纯——它必须 stat——
 * 所以改在批准之后运行。
 *
 * 前导与结尾空白**拒绝**而非修剪。`sanitizeCommand` 修剪，
 * 因为 shell 忽略命令两端的空白，修剪不改变将运行的东西。
 * 路径不是命令：POSIX 文件名只排除 NUL 与 `/`，
 * `"report.txt "` 与 `"report.txt"` 是两个不同的文件。
 * 在这里修剪等于悄悄改写传输目标，
 * 审计的却是没用上的那个名字。
 *
 * shell 元字符刻意*不*拒绝。路径会被内插进合成命令
 * （`sftp:upload-file <path>`）再由分类器读取，而
 * `classifyCommand` 对一切会被 shell 读作载体的东西取*较高*类别——
 * 于是 `/tmp/x; sudo id` 归类 `privileged`、被策略拒绝，
 * 而不是以 `destructive` 溜过。真含 `$` 的文件名出于同样理由
 * 被拒——这正是应当失败的方向。
 * is the direction to fail in.
 */
export function sanitizeRemotePath(path: unknown): string {
  if (typeof path !== 'string') {
    throw new McpError(ErrorCode.InvalidParams, 'Remote path must be a string');
  }
  if (!path) {
    throw new McpError(ErrorCode.InvalidParams, 'Remote path cannot be empty');
  }
  if (path !== path.trim()) {
    throw new McpError(
      ErrorCode.InvalidParams,
      'Remote path cannot begin or end with whitespace: a filename may legitimately ' +
      'contain it, so trimming would transfer a different file than the one named ' +
      'and audit the name it did not use.',
    );
  }
  if (path.length > MAX_REMOTE_PATH_CHARS) {
    throw new McpError(
      ErrorCode.InvalidParams,
      `Remote path is too long (max ${MAX_REMOTE_PATH_CHARS} characters)`,
    );
  }
  if (PATH_CONTROL_CHARS.test(path)) {
    throw new McpError(
      ErrorCode.InvalidParams,
      'Remote path cannot contain control, bidirectional or zero-width formatting ' +
      'characters: the approval prompt and the audit record quote this path back, ' +
      'and such a character makes what is shown differ from what is transferred.',
    );
  }
  return path;
}

/**
 * 同一路径，无效时用固定占位符——绝不抛异常。
 *
 * 为的是被拒的调用仍有东西可登记审计。被审计字符串必须
 * 在 `runAudited` 评估任何东西之前构造，用未校验的路径构造会把
 * 控制字符写进哈希链日志；用空构造则让探测校验边界的客户端
 * 对运维隐形——`pipeline.ts` 把脱敏挪进自身 try 就是为了除掉
 * 那个失败。抛异常的检查照常运行，在 `preCheck`，拒绝在那里入账。
 *
 *
 */
export function remotePathForAudit(path: unknown): string {
  try {
    return sanitizeRemotePath(path);
  } catch {
    return REJECTED_REMOTE_PATH;
  }
}

export function sanitizeSessionName(name: string): string {
  if (!/^[a-zA-Z0-9_-]{1,64}$/.test(name)) {
    throw new McpError(
      ErrorCode.InvalidParams,
      'Session name must be 1-64 chars, alphanumeric/dash/underscore only',
    );
  }
  return name;
}

export function shellSingleQuote(s: string): string {
  return `'${s.replace(/'/g, "'\\''")}'`;
}
