/**
 * 裸 PTY 会话的有界输出缓冲区。
 *
 * agent 以游标增量读取；缓冲区只保留最近 `maxBytes` 个字符。两种不同的丢失
 * 被分开报告，因为它们对调用方的含义不同：
 *
 *
 * - `droppedBytes` —— 被上限逐出。对所有读者永久消失。
 * - `skippedBytes` —— 读者自己的游标落在逐出点之后
 *   （读得太少）。上限导致的跳过是缓冲区的责任；
 *   游标导致的跳过是读者自己的节奏问题。
 */

export interface PtyBufferRead {
  /** 从调用方游标起可见的输出，上限 `maxChunk`。 */
  output: string;
  /** 传给下一次读取的游标。 */
  cursor: number;
  /** 累计追加的字节总数（逻辑流长度）。 */
  totalBytes: number;
  /** 被保留上限逐出的字节数。 */
  droppedBytes: number;
  /** 调用方游标与保留点之间的字节数（已丢失）。 */
  skippedBytes: number;
}

export class PtyOutputBuffer {
  private text = '';
  /** `text[0]` 的逻辑流偏移；头部被逐出时前移。 */
  private base = 0;
  private dropped = 0;

  constructor(private readonly maxBytes: number) {
    if (maxBytes <= 0) throw new Error('PtyOutputBuffer maxBytes must be positive');
  }

  get totalBytes(): number {
    return this.base + this.text.length;
  }

  get droppedBytes(): number {
    return this.dropped;
  }

  append(chunk: string): void {
    if (chunk.length === 0) return;
    this.text += chunk;
    // 保留计量按 UTF-8 字节（与 ptySessionBufferBytes 配置口径一致）：
    // 中文设备输出一字符 3 字节，按字符计会把 1MB 上限实际放大三倍。
    let overflowBytes = Buffer.byteLength(this.text, 'utf8') - this.maxBytes;
    if (overflowBytes <= 0) return;
    // 从头部逐出至字节数达标；按字符步进并在边界处不切断多字节序列。
    let cut = 0;
    while (overflowBytes > 0 && cut < this.text.length) {
      overflowBytes -= Buffer.byteLength(this.text[cut], 'utf8');
      cut++;
    }
    this.text = this.text.slice(cut);
    this.base += cut;
    this.dropped += cut;
  }

  /** 流末端游标、总量与丢失计数——一次无副作用的读取。 */
  stats(): { cursor: number; totalBytes: number; droppedBytes: number } {
    return { cursor: this.totalBytes, totalBytes: this.totalBytes, droppedBytes: this.dropped };
  }

  readSince(cursor: number, maxChunk: number): PtyBufferRead {
    if (maxChunk <= 0) throw new Error('PtyOutputBuffer maxChunk must be positive');
    const clamped = Math.max(cursor, 0);
    const start = Math.max(clamped, this.base);
    const skipped = start - clamped;
    const output = this.text.slice(start - this.base, start - this.base + maxChunk);
    return {
      output,
      cursor: start + output.length,
      totalBytes: this.totalBytes,
      droppedBytes: this.dropped,
      skippedBytes: skipped,
    };
  }
}
