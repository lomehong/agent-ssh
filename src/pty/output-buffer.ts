/**
 * Bounded output buffer for a raw PTY session.
 *
 * The agent reads incrementally with a cursor; the buffer retains only the most
 * recent `maxBytes` characters. Two distinct losses are reported separately
 * because they mean different things to a caller:
 *
 * - `droppedBytes` — evicted by the cap. Gone for every reader, forever.
 * - `skippedBytes` — the reader's own cursor sat behind the eviction point
 *   (it read too rarely). A cap-skip is the buffer's fault; a cursor-skip is
 *   the reader's pacing.
 */

export interface PtyBufferRead {
  /** Output visible from the caller's cursor, capped at `maxChunk`. */
  output: string;
  /** Cursor to pass to the next read. */
  cursor: number;
  /** Total bytes ever appended (logical stream length). */
  totalBytes: number;
  /** Bytes evicted by the retention cap. */
  droppedBytes: number;
  /** Bytes between the caller's cursor and the retention point (already gone). */
  skippedBytes: number;
}

export class PtyOutputBuffer {
  private text = '';
  /** Logical stream offset of `text[0]`; advances as the head is evicted. */
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
    const overflow = this.text.length - this.maxBytes;
    if (overflow > 0) {
      this.text = this.text.slice(overflow);
      this.base += overflow;
      this.dropped += overflow;
    }
  }

  /** Stream-end cursor, total, and loss counters — a read with no side effects. */
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
