import ssh2 from 'ssh2';
import type { FileEntryWithStats, SFTPWrapper, Attributes } from 'ssh2';
import { Readable, type Writable } from 'node:stream';
import { once } from 'node:events';
import { randomUUID } from 'node:crypto';
import { dirname, join } from 'node:path/posix';
import type { SftpUploadOpts, SftpDownloadOpts, SftpStat } from '../types.js';
import type { SSHConnection } from './connection.js';
import { openWithRetry } from './channel-retry.js';

/*
 * 经默认导入，而非 import { utils } from 'ssh2'。
 *
 * ssh2 是 CommonJS。Node 的 ESM 加载器静态探测到它的一些具名导出
 *（connection.ts 以那种方式导入的 Client）但探测不到 utils，
 * 所以具名形式能通过类型检查、通过每次 vitest——vitest 自己
 * 转换模块——然后在*构建产物*首次加载时抛 Named export not found。
 * 只有生成 build/index.js 的 e2e 套件才能抓到它。
 *
 */
const { STATUS_CODE } = ssh2.utils.sftp;

/**
 * 失败请求携带的数字 SFTP 状态码，如果有的话。
 *
 * ssh2 只从 SSH_FXP_STATUS 字（数字）设置 code，从不用
 * libuv 风格的字符串——本文件更早版本也测过两个永远匹配不到的
 * 字符串。那些死比较正是迫使 (err as any).code 的原因，
 * 而强转反过来又掩盖了它们是死的。ssh2 自身抛的错误
 * 不带任何 code，这正是返回 undefined 而非哨兵的原因。
 *
 * why this returns `undefined` rather than a sentinel.
 */
function statusCode(err: unknown): number | undefined {
  const code = (err as { code?: unknown } | null | undefined)?.code;
  return typeof code === 'number' ? code : undefined;
}

/**
 * readdir 的三参形式，运行时支持而类型定义省略了。
 *
 * ssh2 只声明 readdir(location, callback)（types index.d.ts:1897）
 * 但实现了 readdir(where, opts, cb)（SFTP.js:866）——而 opts.full
 * 是唯一能让它不在回调看到之前把 . 和 .. 从每批中切掉的方式，
 * 下方 list() 需要它来区分短批次与目录结束。
 *
 */
type ReaddirWithOptions = (
  handle: Buffer,
  opts: { full: true },
  callback: (err: Error | undefined, list: FileEntryWithStats[]) => void,
) => void;

/** Bounds every transfer needs. Required, because a missing bound is not a default. */
export interface TransferBounds {
  maxBytes: number;
  /**
 * 或复制中一段没有字节移动的时间。
 *
   *
 * 整个操作的单一墙钟预算无法同时服务字节上限和线路：
 * 60 秒内 1 GiB 要求 17.9 MB/s 持续，宽裕的上限在普通超时下
 * 变得不可达。随进度重置把两个问题分开——「连接还在动吗」
 * 得到紧凑答案，大文件合法地能花多久不再取决于它。
 *
 *
   */
  idleTimeoutMs: number;
  abortSignal?: AbortSignal;
}

/** Upload-only knobs. Separate, because a download can honour neither. */
export interface UploadFileOptions extends TransferBounds {
  overwrite?: boolean;
  mode?: number;
}

export interface SftpListOptions {
  maxEntries: number;
  /**
    * 此调用将*返回*的清单的预算，非线上字节的——
    * 本文件别处的 maxBytes 意为后者，所以这个刻意分开命名。
    *
   */
  maxResponseBytes: number;
  idleTimeoutMs: number;
  abortSignal?: AbortSignal;
}

export interface SftpListResult {
  entries: SftpStat[];
  truncated: boolean;
}

interface DeadlineOptions {
  idleTimeoutMs: number;
  abortSignal?: AbortSignal;
}

/**
 * 当一步自己的界过期时抛出，区别于服务器拒绝。
 *
 * 区别在一个地方要紧：*等待*过期的发布可能已落地，
 * 因为界覆盖的是等待而非请求本身。被服务器主动拒绝的
 * 发布则确定未落地。把两者都当含糊曾告诉调用方其文件
 * 「可能已包含此上传」，而真实答案是一个权限错误。
 *
 */
export class DeadlineExceededError extends Error {}

const MAX_TIMER_MS = 2 ** 31 - 1;

/**
 * 拒绝干不了活的界，而非让它古怪地失败。
 *
 * 高于 2^31-1 的 idleTimeoutMs（或 Infinity、NaN）被 Node 钳位到
 * 1ms，每步随即失败且消息引用调用方要求的值——来自合理输入的
 * 自我反驳输出。0 在这里比无用更糟：本代码库别处 0 意为
 * 「不限制」（commandQuotaPerDay、approvalGrantTtlMs），遵循惯例
 * 的调用方会得到与要求完全相反的东西。
 *
 */
function assertBounds(idleTimeoutMs: number, byteBudget: number, label: string): void {
  if (!Number.isInteger(idleTimeoutMs) || idleTimeoutMs < 1 || idleTimeoutMs > MAX_TIMER_MS) {
    throw new Error(
      `${label}: idleTimeoutMs must be an integer between 1 and ${MAX_TIMER_MS}; ` +
      `0 does not mean "unlimited" here`,
    );
  }
  if (!Number.isSafeInteger(byteBudget) || byteBudget < 1) {
    throw new Error(`${label}: the byte budget must be a positive safe integer`);
  }
}

/** One place the wire shape becomes this module's own, so the masks exist once. */
function toSftpStat(path: string, attrs: Attributes): SftpStat {
  return {
    path,
    size: attrs.size,
    mode: attrs.mode,
    isDirectory: (attrs.mode & 0o170000) === 0o040000,
    isFile: (attrs.mode & 0o170000) === 0o100000,
    mtime: new Date(attrs.mtime * 1000),
    atime: new Date(attrs.atime * 1000),
  };
}

/**
 * 把 source 复制到 destination，任一停滞或字节上限超出即失败。
 * 返回远端确认的字节数。
 *
 * 上限在流流动时强制，不仅靠事先 stat：远端大小可能过期、
 * 不可用或说谎，本地文件也可能在读取中增长。
 *
 *
 * **所有权：** 本函数结束 destination——这是字节被冲刷、计数
 * 变得可信的方式——但从不关闭 destination 包裹的东西。其 Writable
 * 坐在必须活得比流久的资源上的调用方（仍需 sync() 再发布的
 * FileHandle）必须以 autoClose: false 构造；否则 end() 在此关掉
 * 句柄、调用方后来的 sync() 以 EBADF 失败。
 *
 */
async function transfer(
  source: Readable,
  destination: Writable,
  opts: TransferBounds,
  direction: 'upload' | 'download',
): Promise<number> {
  const controller = new AbortController();
  let rejectFailure!: (reason: unknown) => void;
  const failure = new Promise<never>((_resolve, reject) => { rejectFailure = reject; });
  const abortStreams = () => {
    const reason = controller.signal.reason instanceof Error
      ? controller.signal.reason
      : new Error(`SFTP file ${direction} aborted`);
    rejectFailure(reason);
    source.destroy();
    destination.destroy();
  };
  const onSourceError = (err: Error) => rejectFailure(err);
  const onDestinationError = (err: Error) => rejectFailure(err);

  // 只推导一次。三个事实是同一个问题——哪端是 SFTP 支撑的流、
  // 因此哪个完成事件是权威——在每个使用点重新推导使函数体读作
  // 五个决定。
  const remoteStream = direction === 'upload' ? destination : source;
  const settledEvent = direction === 'upload' ? 'close' : 'finish';
  const destinationSettled = () => (
    direction === 'upload' ? destination.closed : destination.writableFinished
  );

  // 每块之后重置，收尾再一次。慢而活的传输活下来；
  // 停止投递的通道在一个窗口内失败。
  let idle: ReturnType<typeof setTimeout> | undefined;
  const arm = () => {
    if (idle) clearTimeout(idle);
    idle = setTimeout(
      () => controller.abort(
        new Error(`SFTP file ${direction} stalled: no progress for ${opts.idleTimeoutMs}ms`),
      ),
      opts.idleTimeoutMs,
    );
  };
  const disarm = () => { if (idle) clearTimeout(idle); idle = undefined; };

  const onAbort = () => controller.abort(
    opts.abortSignal?.reason ?? new Error(`SFTP file ${direction} aborted`),
  );
  controller.signal.addEventListener('abort', abortStreams, { once: true });
  source.on('error', onSourceError);
  destination.on('error', onDestinationError);
  opts.abortSignal?.addEventListener('abort', onAbort, { once: true });
  if (opts.abortSignal?.aborted) onAbort();

  let bytes = 0;
  let resolveRemoteClosed!: () => void;
  const remoteClosed = new Promise<void>((resolve) => { resolveRemoteClosed = resolve; });
  const onRemoteClose = () => resolveRemoteClosed();
  remoteStream.once('close', onRemoteClose);
  // ssh2 以 emitClose: false 构造流，已发生的 close 永不重放。
  // 有界：这是工作完成后的礼节性等待，不是可挂起调用方的一步。
  //
  const waitForRemoteClose = async () => {
    if (remoteStream.closed) return;
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      await Promise.race([
        remoteClosed,
        new Promise<void>((resolve) => {
          timer = setTimeout(resolve, Math.min(opts.idleTimeoutMs, 1_000));
        }),
      ]);
    } finally {
      if (timer) clearTimeout(timer);
    }
  };

  arm();
  try {
    const copy = async () => {
      for await (const value of source) {
        if (controller.signal.aborted) throw controller.signal.reason;
        const chunk = Buffer.isBuffer(value) ? value : Buffer.from(value);
        bytes += chunk.length;
        if (bytes > opts.maxBytes) {
          throw new Error(`SFTP file ${direction} exceeds the ${opts.maxBytes} byte transfer limit`);
        }
        arm();
        // 有信号：once 只在 drain 或 error 上结算，ssh2 的 destroy 路径
        // 发 close 而无 error。背压期间干净消失的目的地
        // 因此让这里等满整个空闲窗口，表现为「无进度」
        // 而非它本来的 close。
        //
        if (!destination.write(chunk)) {
          await once(destination, 'drain', { signal: controller.signal });
        }
      }

      // 收尾付出一次 SSH_FXP_CLOSE 往返，其延迟与块节奏无关。
      // 不重置的话它跑在最后一块设的窗口剩余上——有时几乎没有——
      // 每个字节都被确认的传输反而以「停滞」失败。
      //
      arm();
      const completed = new Promise<void>((resolve, reject) => {
        const cleanup = () => {
          destination.removeListener(settledEvent, done);
          destination.removeListener('error', failed);
        };
        const done = () => { cleanup(); resolve(); };
        const failed = (err: Error) => { cleanup(); reject(err); };
        destination.once(settledEvent, done);
        destination.once('error', failed);
      });
      destination.end();
      if (!destinationSettled()) await completed;
      // Not dead code on the download side, though it looks it: `source` there
      // is ssh2's SFTP read stream, built with emitClose: false, so `.closed`
      // 完成 for await 也不会把 SSH_FXP_CLOSE 送上线路。没有这个，
      // withSftp 结束子系统通道时句柄仍然打开。评审轮曾对普通
      // Readable 检查后称它死代码——那里确实是死的。
      //
      if (direction === 'download' && !source.destroyed) source.destroy();
      await waitForRemoteClose();
      return bytes;
    };
    return await Promise.race([copy(), failure]);
  } catch (err) {
    source.destroy();
    destination.destroy();
    await waitForRemoteClose();
    if (controller.signal.aborted && controller.signal.reason instanceof Error) {
      throw controller.signal.reason;
    }
    throw err;
  } finally {
    disarm();
    controller.signal.removeEventListener('abort', abortStreams);
    source.removeListener('error', onSourceError);
    destination.removeListener('error', onDestinationError);
    remoteStream.removeListener('close', onRemoteClose);
    opts.abortSignal?.removeEventListener('abort', onAbort);
  }
}

/**
 * 在自己的界下运行一次回调风格的 SFTP 操作。
 *
 * 每次元数据往返的 idleTimeoutMs 从自己的起点起算，
 * 任何单步都不能挂起、也不消耗下一步需要的预算。
 *
 * 它界的是*等待*而非请求：界之后到达的回复发现 settled 已为 true
 * 而被丢弃。迟到的成功要紧的调用方必须重建状态而非假设失败。
 *
 *
 * 导出供自己的测试。经真实 SFTP 调用驱动超时无法钉住它：
 * 对回环容器，元数据往返在 1ms 界内完成，复制的停滞赢得竞速，
 * 本助手为其存在的分支保持未走。
 *
 */
export function callbackBeforeDeadline<T>(
  opts: DeadlineOptions,
  label: string,
  start: (callback: (err?: Error, value?: T) => void) => void,
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    let settled = false;
    const finish = (err?: Error, value?: T) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      opts.abortSignal?.removeEventListener('abort', abort);
      if (err) reject(err);
      else resolve(value as T);
    };
    const abort = () => finish(
      opts.abortSignal?.reason instanceof Error
        ? opts.abortSignal.reason
        : new Error(`${label} aborted`),
    );
    const timer = setTimeout(
      () => finish(new DeadlineExceededError(`${label} timed out after ${opts.idleTimeoutMs}ms`)),
      opts.idleTimeoutMs,
    );
    opts.abortSignal?.addEventListener('abort', abort, { once: true });
    if (opts.abortSignal?.aborted) abort();
    else {
      try { start(finish); } catch (err) { finish(err as Error); }
    }
  });
}

function remoteTemporaryPath(remotePath: string): string {
  return join(dirname(remotePath), `.ssh-mcp-upload-${randomUUID()}.part`);
}

/**
 * 发布暂存的上传，服务器允许时原子完成。
 *
 * ssh2 不经回调报告未通告的扩展——它在发送任何东西前 throw，
 * Error 上没有 code。两个扩展调用因此都包裹：更早版本测回调的
 * code === 8，为这些服务器写的纯 rename 回退不可达，
 * overwrite: true 对一切不通告该扩展的服务器直接失败。
 *
 * does not advertise posix-rename@openssh.com.
 *
 * 导出供自己的测试。本仓库没有服务器能走到该 throw：
 * docker-compose 钉住 OpenSSH 的 sftp-server，连 Dropbear 镜像
 * 都装 openssh-sftp-server，因为 Dropbear 不带 SFTP 子系统——
 * 所以两个扩展总是被通告，没有 stub 的话回退无法验证。
 *
 */
export function publishRemote(
  sftp: SFTPWrapper,
  temporary: string,
  remotePath: string,
  opts: UploadFileOptions,
): Promise<void> {
  return callbackBeforeDeadline<void>(opts, 'SFTP upload publish', (callback) => {
    const standardRename = () => sftp.rename(
      temporary,
      remotePath,
      (err) => callback(err ?? undefined),
    );

    const unsupported = () => callback(new Error(
      'The SFTP server cannot atomically publish a file without overwrite; retry with overwrite=true',
    ));

    if (!opts.overwrite) {
      // SFTP v3 rename has no portable no-clobber semantics. The OpenSSH
      // hardlink 扩展映射到 link(2)，目标在上面的 stat 之后出现
      // 则原子失败。
      try {
        sftp.ext_openssh_hardlink(temporary, remotePath, (err) => {
          if (!err) return callback();
          const code = statusCode(err);
          if (code === STATUS_CODE.OP_UNSUPPORTED) return unsupported();
          // v3 没有专门的「已存在」状态，OpenSSH 把 EEXIST 报为 FAILURE。
          // 其余一切——权限、不能硬链接的文件系统、配额——过去也被报为
          // 输了竞速，让读者去找从未存在的并发写者。
          //
          if (code === STATUS_CODE.FAILURE) {
            return callback(new Error('Refusing to overwrite a remote file created during transfer'));
          }
          return callback(new Error(`SFTP upload publish failed: ${err.message}`));
        });
      } catch {
        unsupported();
      }
      return;
    }

    try {
      sftp.ext_openssh_rename(temporary, remotePath, (err) => {
        if (statusCode(err) === STATUS_CODE.OP_UNSUPPORTED) standardRename();
        else callback(err ?? undefined);
      });
    } catch {
      standardRename();
    }
  });
}

export class SftpClient {
  constructor(private conn: SSHConnection) {}

  private async withSftp<T>(fn: (sftp: SFTPWrapper) => Promise<T>): Promise<T> {
    // ensureConnected 活在重试内：Dropbear 在 SFTP 通道震荡下丢整条
    // 连接，一次尝试可能因链路死亡而非通道被拒而失败。每次尝试前
    // 重新建立覆盖两者。
    //
    const sftp = await openWithRetry(async () => {
      await this.conn.ensureConnected();
      const client = this.conn.getClient();
      return new Promise<SFTPWrapper>((resolve, reject) => {
        client.sftp((err, handle) => {
          if (err) {
            reject(new Error(`SFTP error: ${err.message}`));
            return;
          }
          resolve(handle);
        });
      });
    });
    try {
      return await fn(sftp);
    } finally {
      // 每次 client.sftp() 开一条新子系统通道。没有 end() 它们在连接
      // 生命周期内积累直到服务器 MaxSessions 上限（OpenSSH 默认 10），
      // 此后该连接上再也无法开任何通道——SFTP、exec 或 shell。
      //
      try { sftp.end(); } catch { /* already torn down */ }
    }
  }

  /**
    * 把 string 或 Buffer 内容写到远程路径。
    *
    * 刻意以 0o644 直接写，而非经 rename 发布暂存的 .part，
    * 且用 || 而非 ??，使 mode: 0 回落而非产生无人可读的文件。
    * 这是既有工具：暂存需要对目录的写权限，而直接写只需
    * 文件上的；重新发布丢弃目标的 mode、属主和 ACL。
    * #185 要求文本工具保持不变，集成测试钉住全部三个属性。
    *
   * test/integration/ssh-sftp.test.ts pins all three properties.
   *
    * 权衡相反的流式路径是 uploadFile()。
   */
  async upload(opts: SftpUploadOpts): Promise<void> {
    return this.withSftp(async (sftp) => {
      return new Promise<void>((resolve, reject) => {
        const stream = sftp.createWriteStream(opts.remotePath, { mode: opts.mode || 0o644 });
        stream.on('error', reject);
        stream.on('close', resolve);
        stream.end(Buffer.isBuffer(opts.content) ? opts.content : Buffer.from(opts.content));
      });
    });
  }

  /**
   * 从已打开的源上传，不在 MCP 进程内缓冲。
   *
   * 经同级 .part 发布，失败的传输从不在目的地留下半写文件——
   * 对目的地预期为新文件的新工具这是正确的取舍，
   * 对上方 upload() 则是错的。
   *
   * 注意 overwrite: true 的代价，因为那正是目的地不新的情形：
   * 经 rename 发布替换 inode，目标的属主和 ACL 不保留。权限位保留，
   * 除非调用方传了 mode——且只有低九位：setuid、setgid 和
   * 粘滞位被丢弃而非保留。见下方 chmod。
   *
   */
  async uploadFile(source: Readable, remotePath: string, opts: UploadFileOptions): Promise<number> {
    assertBounds(opts.idleTimeoutMs, opts.maxBytes, 'SFTP upload');
    return this.withSftp(async (sftp) => {
      const exists = async () => callbackBeforeDeadline<boolean>(opts, 'SFTP upload stat', (callback) => {
        sftp.stat(remotePath, (err) => {
          if (!err) callback(undefined, true);
          else if (statusCode(err) === STATUS_CODE.NO_SUCH_FILE) callback(undefined, false);
          else callback(new Error(`SFTP upload stat failed: ${err.message}`));
        });
      });
      if (!opts.overwrite && await exists()) {
        throw new Error('Refusing to overwrite an existing remote file');
      }

      // Read before the transfer, because after it the destination is about to
      // 能带过去的部分。
      const inheritedMode = opts.overwrite && opts.mode === undefined
        ? await callbackBeforeDeadline<number | undefined>(opts, 'SFTP upload mode stat', (callback) => {
            sftp.stat(remotePath, (err, stats) => callback(undefined, err ? undefined : stats?.mode));
          })
        : undefined;

      const temporary = remoteTemporaryPath(remotePath);
      let published = false;
      try {
        const destination = sftp.createWriteStream(temporary, {
          flags: 'wx',
          mode: opts.mode || 0o600,
        });
        const bytes = await transfer(source, destination, opts, 'upload');

        if (inheritedMode !== undefined) {
          // 没有这个，用 0600 替换 0644 的服务配置是一次看似成功的上传，
          // 静默打断所有其他读者。
          //
          // 仅低九位。& 0o7777 还会带过 setuid、setgid 和粘滞位，把
          // 「可以替换此文件」变成「可以以其属主身份运行代码」——
          // 对 SSH 用户所有的 04755 目的地实测：内容变成调用方的而
          // mode 保持 4755。上传路径中再无别处能抓到它：调用方从未
          // 指名 mode；它经继承、经调用方可省略的那个参数到达。
          //
          // one argument the caller can omit.
          await callbackBeforeDeadline<void>(opts, 'SFTP upload chmod', (callback) => {
            sftp.chmod(temporary, inheritedMode & 0o777, (err) => callback(err ?? undefined));
          });
        }
        if (!opts.overwrite && await exists()) {
          throw new Error('Refusing to overwrite a remote file created during transfer');
        }

        try {
          await publishRemote(sftp, temporary, remotePath, opts);
          published = true;
        } catch (err) {
          // 只有已过期的界才是含糊的：请求可能仍在途，目的地随后
          // 存在可能就是本次上传。把它报成普通失败把重试的调用方送进
          // 「拒绝覆盖已存在的远程文件」——与占位者无法区分，
          // 还是建立在错误前提上的 overwrite: true 论据。服务器主动
          // 拒绝的发布不含糊，必须保留自己的错误。
          //
          // actively refused is not ambiguous and must keep its own error.
          if (err instanceof DeadlineExceededError && await exists().catch(() => false)) {
            published = true;
            throw new Error(
              'SFTP upload publish did not confirm within its bound, but the destination now exists. ' +
              'Verify the remote file before retrying; it may already hold this upload.',
            );
          }
          throw err;
        }

        if (!opts.overwrite) {
          // 上面的硬链接留下一个 inode 两个名字；删掉我们的。
          await this.removeTemporary(sftp, temporary, opts.idleTimeoutMs).catch(() => {
            console.error('Warning: an SFTP upload was published but its stale .part hard link could not be removed');
          });
        }
        return bytes;
      } finally {
        if (!published) {
          await this.removeTemporary(sftp, temporary, opts.idleTimeoutMs).catch(() => {
            // 记录而非吞掉：这是留下无人知道的远程状态的情形。
            // local-path.ts 对本地半边说同样的话；此处沉默是不对称。
            //
            console.error(
              `Warning: an unpublished SFTP upload left a staging file in ${dirname(remotePath)}; ` +
              'look for .ssh-mcp-upload-*.part and remove it',
            );
          });
        }
      }
    });
  }

  /**
    * 移除一个暂存文件。
    *
    * 以数字而非调用方选项收超时，因为它刻意无视 abortSignal：
    * 清理在被中止的路径上运行，从这里穿过的信号恰在需要时
    * 使其无法运行。自己的短界防止它延长已经失败的传输。
    *
   */
  private async removeTemporary(
    sftp: SFTPWrapper,
    temporary: string,
    idleTimeoutMs: number,
  ): Promise<void> {
    return callbackBeforeDeadline<void>(
      { idleTimeoutMs: Math.min(idleTimeoutMs, 1_000) },
      'SFTP upload cleanup',
      (callback) => sftp.unlink(temporary, (err) => callback(err ?? undefined)),
    );
  }

  /**
   * Download into an already-open destination without buffering it in memory.
   *
   * Ends the destination when the transfer completes — see transfer()'s
   * ownership note. A caller holding a `FileHandle` it still needs (to `sync()`
   * and publish) must create the stream with `autoClose: false`.
   */
  async downloadFile(remotePath: string, destination: Writable, opts: TransferBounds): Promise<number> {
    assertBounds(opts.idleTimeoutMs, opts.maxBytes, 'SFTP download');
    return this.withSftp(async (sftp) => {
      const size = await callbackBeforeDeadline<number | undefined>(opts, 'SFTP download stat', (callback) => {
        sftp.stat(remotePath, (err, stats) => callback(undefined, err ? undefined : stats?.size));
      });
      if (size !== undefined && size > opts.maxBytes) {
        throw new Error(`SFTP file download exceeds the ${opts.maxBytes} byte transfer limit (${size} bytes)`);
      }
      const source = sftp.createReadStream(remotePath);
      return transfer(source, destination, opts, 'download');
    });
  }

  async download(opts: SftpDownloadOpts): Promise<Buffer> {
    const maxBytes = opts.maxBytes ?? this.conn.profile.maxOutputBytes;

    return this.withSftp(async (sftp) => {
      // Refuse before transferring anything when the size is known up front.
      //
      // Bounded, because this promise had no reject path and no timeout: a
      // server that accepted SSH_FXP_STAT and never answered left this tool
      // call suspended for the life of the connection, with no error and
      // nothing for a caller to act on. That is the same shape as #197 on the
      // exec side. The bound is the profile's command timeout, which is what
      // every other step of a tool call already answers to; an unanswerable
      // stat now falls through to the streaming cap below, exactly as an
      // unavailable one always did.
      const size = await callbackBeforeDeadline<number | undefined>(
        { idleTimeoutMs: this.conn.profile.timeout },
        'SFTP download stat',
        (callback) => {
          sftp.stat(opts.remotePath, (err, stats) => callback(undefined, err ? undefined : stats?.size));
        },
      ).catch(() => undefined);
      if (size !== undefined && size > maxBytes) {
        throw new Error(
          `Refusing to download ${opts.remotePath}: ${size} bytes exceeds the ${maxBytes} byte limit ` +
          `(commandMaxOutputBytes). Narrow the file or raise the limit for this profile.`,
        );
      }

      return new Promise<Buffer>((resolve, reject) => {
        const chunks: Buffer[] = [];
        let received = 0;
        const stream = sftp.createReadStream(opts.remotePath);
        stream.on('data', (chunk: Buffer) => {
          received += chunk.length;
          // stat can be stale or unavailable (growing file, no permission), so
          // enforce the cap on the stream too and stop reading immediately.
          if (received > maxBytes) {
            stream.destroy();
            reject(new Error(
              `Refusing to download ${opts.remotePath}: exceeded the ${maxBytes} byte limit while transferring.`,
            ));
            return;
          }
          chunks.push(chunk);
        });
        stream.on('error', reject);
        stream.on('close', () => resolve(Buffer.concat(chunks)));
      });
    });
  }

  /**
   * List a remote directory, retaining at most `maxEntries + 1` entries.
   *
   * Reads happen in server-sized batches; the bound is on what is *retained*,
   * and the one entry past the limit is what makes `truncated` honest without a
   * second round-trip. Unbounded readdir was the previous shape, and a directory
   * with a million entries turned one call into a million-object array.
   */
  async list(remotePath: string, opts: SftpListOptions): Promise<SftpListResult> {
    assertBounds(opts.idleTimeoutMs, opts.maxResponseBytes, 'SFTP list');
    if (!Number.isInteger(opts.maxEntries) || opts.maxEntries < 1) {
      throw new Error('SFTP list: maxEntries must be a positive integer');
    }
    return this.withSftp(async (sftp) => {
      const handle = await callbackBeforeDeadline<Buffer>(opts, 'SFTP list open', (callback) => {
        sftp.opendir(remotePath, (err, opened) => {
          callback(err ? new Error(`SFTP list error: ${err.message}`) : undefined, opened);
        });
      });
      const entries: SftpStat[] = [];
      let retained = 0;
      let responseBytes = 0;
      let budgetTruncated = false;
      // The loop advances on retained entries or on EOF, and neither is
      // guaranteed: a batch holding only `.`/`..` is legitimately empty after
      // filtering and must not be read as EOF, so a server answering every
      // READDIR that way kept this issuing requests forever. Each step has its
      // own idle bound; nothing bounded the number of steps, and a synthetic
      // tool call carries no overall deadline — so the call never settled.
      // Sixteen is far past any real directory layout and still terminates.
      const MAX_BARREN_BATCHES = 16;
      let barren = 0;

      try {
        while (retained <= opts.maxEntries && !budgetTruncated) {
          const batch = await callbackBeforeDeadline<FileEntryWithStats[] | null>(
            opts,
            'SFTP list read',
            (callback) => {
              // `{ full: true }` so `.` and `..` reach us. Without it ssh2 splices
              // them out before the callback, and a server whose READDIR batch
              // holds only those two names arrives here as a zero-length batch —
              // which the loop would read as EOF and report a listing it never
              // read as complete. Genuine EOF is the EOF status, nothing else.
              (sftp.readdir as unknown as ReaddirWithOptions)(
                handle,
                { full: true },
                (err, list) => {
                  if (statusCode(err) === STATUS_CODE.EOF) callback(undefined, null);
                  else if (err) callback(new Error(`SFTP list error: ${err.message}`));
                  else callback(undefined, list);
                },
              );
            },
          );
          if (batch === null) break;

          const before = retained;
          for (const entry of batch) {
            if (entry.filename === '.' || entry.filename === '..') continue;
            // Bill what is actually retained. `longname` is the server's `ls -l`
            // line — attacker-controlled, unbounded up to the packet limit, and
            // repeating the filename — so charging only the filename let a
            // hostile server retain three orders of magnitude more than the
            // budget said. Projecting to SftpStat here rather than pushing
            // ssh2's object drops `longname` instead of holding it.
            responseBytes += Buffer.byteLength(entry.filename, 'utf8')
              + Buffer.byteLength(entry.longname ?? '', 'utf8')
              + 256;
            if (responseBytes > opts.maxResponseBytes) {
              budgetTruncated = true;
              break;
            }
            retained++;
            if (retained > opts.maxEntries) break;
            entries.push(toSftpStat(join(remotePath, entry.filename), entry.attrs));
          }

          if (retained === before && !budgetTruncated) {
            if (++barren >= MAX_BARREN_BATCHES) {
              throw new Error(
                `SFTP list error: server returned ${MAX_BARREN_BATCHES} consecutive batches with no entries and no EOF`,
              );
            }
          } else {
            barren = 0;
          }
        }
      } finally {
        await callbackBeforeDeadline<void>(opts, 'SFTP list close', (callback) => {
          sftp.close(handle, () => callback());
        }).catch(() => {});
      }

      return { truncated: budgetTruncated || retained > opts.maxEntries, entries };
    });
  }

  async stat(remotePath: string): Promise<SftpStat> {
    return this.withSftp(async (sftp) => {
      return new Promise<SftpStat>((resolve, reject) => {
        sftp.stat(remotePath, (err: Error | undefined, stats) => {
          if (err) {
            reject(new Error(`SFTP stat error: ${err.message}`));
            return;
          }
          resolve(toSftpStat(remotePath, stats));
        });
      });
    });
  }
}
