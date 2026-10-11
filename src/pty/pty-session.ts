import type { ClientChannel } from 'ssh2';
import { terminateChannel } from '../ssh/channel-signal.js';
import { outputEndsWithPrompt } from '../devices/archives.js';
import { PtyOutputBuffer } from './output-buffer.js';
import type { PtyTranscript } from './transcript.js';

/**
 * 一个裸 PTY 会话：一条真正的伪终端通道，其字节流由
 * 调用方直接读写。
 *
 * 这刻意不是上游的交互式会话——后者用 printf 标记包裹每条命令，
 * 以在 POSIX shell 上取回退出码与 CWD——该协议面对网络设备 CLI
 * （或任何没有 `$(...)` 与 `$?` 的主机）会立即失效。
 * 裸会话完全没有协议：主机回显什么就返回什么，包括分页提示。
 * 这既是它能用于设备的原因，也正是它在打开处设门的原因
 * （分类器看不见字节流内部——计划第 ① 层）、
 * 在每次写入处审计（第 ② 层）、全程转录（第 ② 层），
 * 并受两个定时器约束
 * （第 ③ 层）。
 */

export type PtyCloseReason = 'operator' | 'idle' | 'lifetime' | 'disconnect' | 'remote';

export interface PtySessionInfo {
  name: string;
  profile: string;
  createdAt: Date;
  lastActivity: Date;
  closed: boolean;
  closeReason?: PtyCloseReason;
  /** 下一次增量读取的游标（缓冲输出的当前末端）。 */
  cursor: number;
  totalBytes: number;
  droppedBytes: number;
  transcriptBytes: number;
  transcriptFrozen: boolean;
}

export interface PtyWriteOutcome {
  delivered: boolean;
  /** 写入与关闭中的通道竞态时的备注；正常时为空。 */
  note: string;
}

export class PtySession {
  closed = false;
  closeReason?: PtyCloseReason;
  readonly createdAt = new Date();
  private lastActivity = Date.now();
  private readonly buffer: PtyOutputBuffer;
  private transcript: PtyTranscript | null;
  private promptPatterns: RegExp[] = [];
  private readonly decoder: TextDecoder;

  constructor(
    readonly name: string,
    readonly profileName: string,
    readonly channel: ClientChannel,
    opts: { maxBufferBytes: number; transcript?: PtyTranscript | null; encoding?: 'utf8' | 'gbk' },
  ) {
    this.buffer = new PtyOutputBuffer(opts.maxBufferBytes);
    // 在这里绑定，避免日后的 setTranscript() 追加挂上第二个汇。
    this.transcript = opts.transcript ?? null;
    // 遗留设备固件（华为/华三）输出 GB2312/GBK；Node 的 full-ICU
    // TextDecoder 无需额外依赖即可识别该标签。`{ stream: true }`
    // 保证跨 chunk 边界的多字节序列不被截断。
    // utf-8 同样走流式解码：toString 的整段语义在 chunk 边界会产生 U+FFFD（审计 M5）。
    this.decoder = new TextDecoder(opts.encoding ?? 'utf-8');
    channel.on('data', (data: Buffer) => {
      const text = this.decode(data);
      this.buffer.append(text);
      this.lastActivity = Date.now();
      this.transcript?.append('out', text);
    });
    channel.stderr.on('data', (data: Buffer) => {
      const text = this.decode(data);
      this.buffer.append(text);
      this.transcript?.append('out', text);
    });
    channel.on('close', () => {
      if (!this.closed) {
        this.closed = true;
        this.closeReason = 'remote';
      }
    });
  }

  private decode(data: Buffer): string {
    return this.decoder.decode(data, { stream: true });
  }

  /**
    * 转录文件就绪后再挂载（open 是异步的，泵不是）。挂载前的输出
    * 存于缓冲区供读者使用；转录只覆盖自身挂载之后的部分——
    * 经 `transcriptBytes` 如实记录。
   */
  setTranscript(transcript: PtyTranscript | null): void {
    this.transcript = transcript;
  }

  /** 来自 profile 的 deviceType 档案的提示符形态；generic 为空。 */
  setPromptPatterns(patterns: RegExp[]): void {
    this.promptPatterns = patterns;
  }

  /**
    * 缓冲尾部是否止于设备提示符——网络设备版的「命令执行完毕」。
    * 只看最后一行非空行，因此几屏之前的分页横幅
    * 冒充不了就绪。
   */
  seesPrompt(): boolean {
    return outputEndsWithPrompt(this.buffer.stats().cursor === 0 ? '' : this.buffer.readSince(0, this.buffer.totalBytes).output, this.promptPatterns);
  }

  touch(): void {
    this.lastActivity = Date.now();
  }

  get idleMs(): number {
    return Date.now() - this.lastActivity;
  }

  get lifetimeMs(): number {
    return Date.now() - this.createdAt.getTime();
  }

  write(input: string): PtyWriteOutcome {
    if (this.closed) {
      return {
        delivered: false,
        note: `PTY session "${this.name}" is closed (${this.closeReason ?? 'unknown'}).`,
      };
    }
    this.touch();
    this.transcript?.append('in', input);
    try {
      this.channel.write(input);
      return { delivered: true, note: '' };
    } catch {
      return { delivered: false, note: 'write failed — the channel may have dropped; read to see the tail.' };
    }
  }

  readSince(cursor: number, maxChunk: number) {
    return this.buffer.readSince(cursor, maxChunk);
  }

  resize(rows: number, cols: number): void {
    if (this.closed) throw new Error(`PTY session "${this.name}" is closed (${this.closeReason ?? 'unknown'}).`);
    // setWindow(rows, cols, heightPx, widthPx)——本工具面向的所有消费方
    // 都忽略像素尺寸；0 是文档写明的「未设置」。
    this.channel.setWindow(rows, cols, 0, 0);
    this.touch();
  }

  /** 与上游会话释放共用的信号加关闭阶梯。幂等。 */
  close(): boolean {
    const alreadyClosed = this.closed;
    if (!alreadyClosed) {
      this.closed = true;
      this.closeReason = 'operator';
    }
    // 即使会话已关闭也要派发：定时器的 markClosed 可能已标记它
    // 却未触及通道，而 terminateChannel 对死通道是安全的
    // （其 ssh2WillSend 门会干净地拒绝）。
    const dispatched = terminateChannel(this.channel);
    try { this.channel.close(); } catch { /* already gone */ }
    return alreadyClosed ? true : dispatched;
  }

  markClosed(reason: PtyCloseReason): void {
    if (!this.closed) {
      this.closed = true;
      this.closeReason = reason;
    }
  }

  toInfo(): PtySessionInfo {
    const stats = this.buffer.stats();
    return {
      name: this.name,
      profile: this.profileName,
      createdAt: this.createdAt,
      lastActivity: new Date(this.lastActivity),
      closed: this.closed,
      closeReason: this.closeReason,
      cursor: stats.cursor,
      totalBytes: stats.totalBytes,
      droppedBytes: stats.droppedBytes,
      transcriptBytes: this.transcript?.bytesWritten ?? 0,
      transcriptFrozen: this.transcript?.frozen ?? false,
    };
  }
}
