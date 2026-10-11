import { randomUUID } from 'node:crypto';
import { constants, realpath as realpathCb } from 'node:fs';
import { open, lstat, rename, link, unlink, stat } from 'node:fs/promises';
import type { FileHandle } from 'node:fs/promises';
import type { Writable } from 'node:stream';
import { platform } from 'node:os';
import { basename, dirname, isAbsolute, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { ErrorCode, McpError } from '@modelcontextprotocol/sdk/types.js';
import { isWithinRoot, pathsOverlap } from '../config/path-containment.js';
// 一个类，一个威胁模型。它曾在这里以私有拷贝存在，又在
// guard/sanitizer.ts 有一份逐字节相同的副本，于是每次放宽——
// 一个 bidi 标记、一个零宽格式符——只到作者当时打开的那个文件。
import { PATH_CONTROL_CHARS } from '../guard/sanitizer.js';

const INSTALL_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const NO_FOLLOW = constants.O_NOFOLLOW ?? 0;

/**
 * `fs.promises.realpath` 不展开 Windows 8.3 短名，同一路径的两种拼写
 * 可能比较不等。原生绑定会展开。POSIX 上两者行为一致，
 * 因此处处用它做安全默认，而不是一个只在单一 OS 上
 * 被真正练过的平台分支。
 */
const realpath = promisify(realpathCb.native);

/** 传输根不得与之重叠的目录，附要报告的原因。 */
export interface ForbiddenDir {
  path: string;
  reason: string;
}

/** 本地路径大门所需的、非来自调用方的一切。 */
export interface LocalPathContext {
  transferRoot: string | undefined;
  configPath?: string;
  forbidden?: readonly ForbiddenDir[];
}

export interface LocalReadFile {
  handle: FileHandle;
  size: number;
  displayPath: string;
}

export interface LocalWriteTarget {
  destination: string;
  displayPath: string;
  parent: string;
}

export interface LocalDownload {
  handle: FileHandle;
  temporary: string;
  target: LocalWriteTarget;
  /**
    * 建在暂存文件之上、**不**关闭句柄的写流。
   *
    * 传输引擎会 end 它拿到的目标——字节就是靠这个冲刷的——而
    * 基于 FileHandle 的流默认在 end 时关闭句柄。发布随即失败：
    * `publish()` 调 `handle.sync()` 得到 EBADF，`cleanup()`
    * 删掉一个其实已完整传完的文件。由这里发放流、
    * 而不是让每个调用方自建，正是为了不让人忘记
    * `autoClose: false`。
   */
  createStream(): Writable;
  publish(): Promise<void>;
  cleanup(): Promise<void>;
}

/**
 * 两种拼写下的根。包含判断用 `canonical`；调用方的绝对路径
 * 额外允许按 `configured` 拼写，因为运维的 shell 就是那样显示的。
 * because that is how an operator's shell shows it.
 */
interface ResolvedRoot {
  configured: string;
  canonical: string;
}

function invalid(message: string): never {
  throw new McpError(ErrorCode.InvalidParams, message);
}

function validateInput(input: string): void {
  if (!input.trim()) invalid('Local path cannot be empty');
  if (PATH_CONTROL_CHARS.test(input)) {
    invalid('Local path cannot contain control or bidi formatting characters');
  }
}

/** 审计记录与审批提示对未通过校验的路径的称呼。 */
export const REJECTED_LOCAL_PATH = '(rejected: invalid local path)';

/**
 * 调用方对本地路径自己的拼写，或占位符——绝不抛异常，
 * 不碰文件系统。
 *
 * 本文件其余一切都要 stat，所以全都跑在策略决定之后。
 * 这个不用，因此*审批提示*才能同时点名一次传输的两端。
 * 没有它，批准下载的人只看得到远程路径，对字节将落在
 * 自己磁盘的何处一无所知——而本地写正是让下载成为
 * `destructive` 的那一半。
 *
 * 用的是调用方的拼写，不是解析后的：解析需要 `realpath`。
 * 门跑完之后 `onResolved` 会换成规范形式，审计记录
 * 最终记下的是实际用到的路径。
 */
export function localPathForAudit(input: unknown): string {
  if (typeof input !== 'string') return REJECTED_LOCAL_PATH;
  try {
    validateInput(input);
    return input;
  } catch {
    return REJECTED_LOCAL_PATH;
  }
}

function display(root: string, candidate: string): string {
  const value = relative(root, candidate);
  return value || '.';
}

function confined(root: string, candidate: string): void {
  if (!isWithinRoot(root, candidate)) invalid('Local path must stay within defaults.transferRoot');
}

async function assertPrivateTransferRoot(root: string): Promise<void> {
  const info = await stat(root);
  const uid = process.getuid?.();
  if (uid !== undefined && info.uid !== uid) {
    invalid('defaults.transferRoot must be owned by the SSH MCP account');
  }
  if ((info.mode & 0o077) !== 0) {
    invalid('defaults.transferRoot permissions must be 0700');
  }

  // 可写祖先可能在 realpath() 与 open() 之间换掉根。/tmp 这类
  // 粘滞目录对属主自控的子路径是安全的，允许。
  let child = root;
  for (let parent = dirname(root); parent !== child; child = parent, parent = dirname(parent)) {
    const parentInfo = await stat(parent);
    if (uid !== undefined && parentInfo.uid !== uid && parentInfo.uid !== 0) {
      invalid('defaults.transferRoot has a parent owned by an untrusted account');
    }
    const writableByOthers = (parentInfo.mode & 0o022) !== 0;
    const sticky = (parentInfo.mode & 0o1000) !== 0;
    if (writableByOthers && !sticky) {
      invalid('defaults.transferRoot has an unsafe writable parent directory');
    }
  }
}

async function configuredRoot(ctx: LocalPathContext): Promise<ResolvedRoot> {
  // Windows 上直接拒绝，而不是套用配置文件的 ACL 宽免姿态——
  // 那套姿态会宽免读暴露的目录、从不读 `O:` 属主、
  // 还把缺失或缓慢的 `icacls.exe` 当通过。无法验证的传输根
  // 应当禁用工具，而不是启用。
  if (platform() === 'win32') {
    invalid(
      'Streaming SFTP file tools are not available on Windows: the transfer root cannot yet ' +
      'be verified private there, and an unverifiable root would leave every downloaded file ' +
      'readable by other accounts on the machine.',
    );
  }

  const input = ctx.transferRoot;
  if (!input) invalid('Streaming SFTP file tools require defaults.transferRoot in config.toml');
  if (!isAbsolute(input)) invalid('defaults.transferRoot must be an absolute path');

  let canonical: string;
  try {
    canonical = await realpath(input);
  } catch {
    invalid('defaults.transferRoot is not an accessible directory');
  }
  const info = await stat(canonical);
  if (!info.isDirectory()) invalid('defaults.transferRoot must name a directory');

  const install = await realpath(INSTALL_DIR);
  if (pathsOverlap(canonical, install)) {
    invalid('defaults.transferRoot must be separate from the SSH MCP installation');
  }
  if (ctx.configPath) {
    let configDir: string;
    try {
      configDir = dirname(await realpath(resolve(ctx.configPath)));
    } catch {
      invalid('The SSH MCP config directory cannot be resolved safely');
    }
    if (pathsOverlap(canonical, configDir)) {
      invalid('defaults.transferRoot must be separate from the SSH MCP config directory');
    }
  }

  // 敏感目录不止安装与配置目录。含审计日志的根让一次下载就能
  // 替换「记录这次传输本身」的防篡改记录；形如 ~/.ssh 的根把同样的
  // 工具变成「读私钥」与「追加 authorized_keys」。两者按惯例
  // 都是 0700 且属主自有，上面的隐私检查因此会放行；
  // 必须按名字排除。
  //
  for (const entry of ctx.forbidden ?? []) {
    let forbidden: string;
    try {
      forbidden = await realpath(entry.path);
    } catch {
      // 尚不存在的目录装不下根，但一旦创建，
      // 其词法形态仍可能装下。
      forbidden = resolve(entry.path);
    }
    if (pathsOverlap(canonical, forbidden)) {
      invalid(`defaults.transferRoot must be separate from ${entry.reason}`);
    }
  }

  await assertPrivateTransferRoot(canonical);
  return { configured: resolve(input), canonical };
}

/**
 * 让调用方的路径能与规范根比较，而不触及根外文件系统。
 *
  * `input` 为绝对路径时 `resolve(root, input)` 完全无视 `root`，
  * 因此一个合法的、按 shell 显示方式拼写的绝对路径——根被规范化为
  * `/private/var/...` 时的 macOS `/var/...`——尚不可比较。旧形态
  * 立刻封闭这种词法形式，于是在每个传输根躲在符号链接后面的主机上
  * 一律拒绝。
 * those outright, on every host whose transfer root sits behind a symlink.
  * 接受两种拼写修好了它。检查保持词法，
  * 让根外路径在被任何 stat 之前就遭拒绝，工具因此不会
  * 为任意路径回答「这文件存在吗」。
 * these tools from answering "does this file exist?" for arbitrary paths.
 */
function lexicalCandidate(root: ResolvedRoot, input: string): string {
  const candidate = resolve(root.canonical, input);
  if (isWithinRoot(root.canonical, candidate)) return candidate;
  if (isWithinRoot(root.configured, candidate)) return candidate;
  invalid('Local path must stay within defaults.transferRoot');
}

/** 只打开既有普通文件一次，让传输永不重新解析其路径。 */
export async function localFileForRead(
  ctx: LocalPathContext,
  input: string,
  onResolved?: (displayPath: string) => void,
): Promise<LocalReadFile> {
  try {
    validateInput(input);
    const root = await configuredRoot(ctx);
    const lexical = lexicalCandidate(root, input);

    // 先规范化父目录再管叶子：叶子可能是必须拒绝而非跟随的符号链接，
    // 它自己的 realpath 会掩盖这一点。先封闭父目录也意味着
    // 只有在确认叶子位于根内之后才对它 lstat。
    // once it is known to be inside the root.
    const parent = await realpath(dirname(lexical));
    confined(root.canonical, parent);
    const candidate = resolve(parent, basename(lexical));
    confined(root.canonical, candidate);
    onResolved?.(display(root.canonical, candidate));

    if ((await lstat(candidate)).isSymbolicLink()) {
      invalid(`Local upload source cannot be a symlink: ${input}`);
    }
    const real = await realpath(candidate);
    confined(root.canonical, real);

    const handle = await open(real, constants.O_RDONLY | NO_FOLLOW);
    try {
      const info = await handle.stat();
      if (!info.isFile()) invalid(`Local path is not a regular file: ${input}`);
      return { handle, size: info.size, displayPath: display(root.canonical, real) };
    } catch (err) {
      await handle.close().catch(() => {});
      throw err;
    }
  } catch (err) {
    if (err instanceof McpError) throw err;
    invalid(`Local upload source is not an accessible regular file: ${input}`);
  }
}

/** 经真实父目录解析目标，并执行覆盖策略。 */
export async function localFileForWrite(
  ctx: LocalPathContext,
  input: string,
  overwrite: boolean,
  onResolved?: (target: LocalWriteTarget) => void,
): Promise<LocalWriteTarget> {
  try {
    validateInput(input);
    const root = await configuredRoot(ctx);
    const lexical = lexicalCandidate(root, input);

    const parent = await realpath(dirname(lexical));
    confined(root.canonical, parent);
    const destination = resolve(parent, basename(lexical));
    confined(root.canonical, destination);
    const target = { destination, displayPath: display(root.canonical, destination), parent };
    onResolved?.(target);

    try {
      const info = await lstat(destination);
      if (!overwrite) invalid(`Refusing to overwrite existing local file: ${input}`);
      if (info.isSymbolicLink()) invalid(`Refusing to overwrite a local symlink: ${input}`);
      if (!info.isFile()) invalid(`Local destination is not a regular file: ${input}`);
    } catch (err: any) {
      if (err?.code !== 'ENOENT') throw err;
    }

    return target;
  } catch (err) {
    if (err instanceof McpError) throw err;
    invalid(`Local download destination is not accessible: ${input}`);
  }
}

async function assertParentUnchanged(target: LocalWriteTarget): Promise<void> {
  let currentParent: string;
  try {
    currentParent = await realpath(dirname(target.destination));
  } catch {
    invalid('Local destination parent changed during transfer');
  }
  if (currentParent !== target.parent) invalid('Local destination parent changed during transfer');
}

/** 创建同目录临时文件并原子发布。 */
export async function createLocalDownload(
  ctx: LocalPathContext,
  input: string,
  overwrite: boolean,
  onResolved?: (target: LocalWriteTarget) => void,
): Promise<LocalDownload> {
  const target = await localFileForWrite(ctx, input, overwrite, onResolved);
  await assertParentUnchanged(target);
  const temporary = resolve(target.parent, `.ssh-mcp-download-${randomUUID()}.part`);
  let handle: FileHandle;
  try {
    handle = await open(
      temporary,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | NO_FOLLOW,
      0o600,
    );
  } catch {
    invalid('Local download temporary file could not be created safely');
  }
  let published = false;

  // 由 createStream() 发放、在这里拆除，因为两者本就该在一起：
  // 一条 `autoClose: false` 的流已完成却未被销毁时，`handle.close()`
  // 会无限期挂起——实测，不是推演。把流给调用方却不管其拆除，
  // 只是把危险外移了一层。
  // moved the hazard one level out.
  let stream: Writable | undefined;
  const releaseStream = () => {
    if (stream && !stream.destroyed) stream.destroy();
    stream = undefined;
  };

  return {
    handle,
    temporary,
    target,
    createStream() {
      stream ??= handle.createWriteStream({ autoClose: false });
      return stream;
    },
    async publish() {
      // 这里没有 releaseStream()：销毁流即使设了 autoClose: false
      // 也会关掉句柄，而下面的 sync() 需要它开着。拆除属于
      // cleanup()，调用方总是会跑它。
      await assertParentUnchanged(target);
      try {
        await handle.sync();
        if (overwrite) {
          await rename(temporary, target.destination);
          published = true;
        } else {
          // link() 遇已存在报 EEXIST 而不是覆盖，这正是
          // 不覆盖保证；临时文件随后被解除链接。
          await link(temporary, target.destination);
          published = true;
          await unlink(temporary).catch(() => {
            console.error('Warning: an SFTP download was published but its stale .part hard link could not be removed');
          });
        }
      } catch (err: any) {
        if (err?.code === 'EEXIST') invalid('Refusing to overwrite a local file created during transfer');
        throw new McpError(ErrorCode.InternalError, 'Local download could not be published safely');
      }
      try {
        const parentHandle = await open(target.parent, constants.O_RDONLY);
        try { await parentHandle.sync(); } finally { await parentHandle.close(); }
      } catch {
        console.error('Warning: SFTP download was published, but its directory metadata could not be synced');
      }
    },
    async cleanup() {
      releaseStream();
      await handle.close().catch(() => {});
      if (!published) {
        await unlink(temporary).catch((err: any) => {
          console.error(
            err?.code === 'ENOENT'
              ? 'Warning: an unpublished SFTP temporary file is no longer reachable; check transferRoot for stale .part files'
              : 'Warning: an unpublished SFTP temporary file could not be removed; check transferRoot for stale .part files',
          );
        });
      }
    },
  };
}
