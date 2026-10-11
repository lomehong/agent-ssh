import type { ClientChannel } from 'ssh2';
import { terminateChannel } from '../ssh/channel-signal.js';
import { PtyOutputBuffer } from './output-buffer.js';
import type { PtyTranscript } from './transcript.js';

/**
 * One raw PTY session: a real pseudo-terminal channel whose byte stream the
 * caller reads and writes directly.
 *
 * This is deliberately NOT the upstream interactive session, which frames every
 * command in printf markers to recover exit codes and CWD on a POSIX shell —
 * a protocol that fails immediately against a network-device CLI (or any host
 * without `$(...)` and `$?`). A raw session has no protocol at all: whatever
 * the host echoes comes back, paging prompts included. That is exactly what
 * makes it usable on devices, and exactly why it is gated at open (the
 * classifier cannot see inside a byte stream — plan layer ①), audited on every
 * write (layer ②), transcripted end to end (layer ②), and bounded by two
 * timers (layer ③).
 */

export type PtyCloseReason = 'operator' | 'idle' | 'lifetime' | 'disconnect' | 'remote';

export interface PtySessionInfo {
  name: string;
  profile: string;
  createdAt: Date;
  lastActivity: Date;
  closed: boolean;
  closeReason?: PtyCloseReason;
  /** Cursor for the next incremental read (current end of buffered output). */
  cursor: number;
  totalBytes: number;
  droppedBytes: number;
  transcriptBytes: number;
  transcriptFrozen: boolean;
}

export interface PtyWriteOutcome {
  delivered: boolean;
  /** Note when the write raced a closing channel; empty when clean. */
  note: string;
}

export class PtySession {
  closed = false;
  closeReason?: PtyCloseReason;
  readonly createdAt = new Date();
  private lastActivity = Date.now();
  private readonly buffer: PtyOutputBuffer;
  private transcript: PtyTranscript | null;

  constructor(
    readonly name: string,
    readonly profileName: string,
    readonly channel: ClientChannel,
    opts: { maxBufferBytes: number; transcript?: PtyTranscript | null },
  ) {
    this.buffer = new PtyOutputBuffer(opts.maxBufferBytes);
    // Bound here so a later setTranscript() cannot retro-attach two sinks.
    this.transcript = opts.transcript ?? null;
    channel.on('data', (data: Buffer) => {
      const text = data.toString('utf8');
      this.buffer.append(text);
      this.lastActivity = Date.now();
      this.transcript?.append('out', text);
    });
    channel.stderr.on('data', (data: Buffer) => {
      const text = data.toString('utf8');
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

  /**
   * Attach the transcript once its file is ready (open is async; the pump is
   * not). Pre-attach output lives in the buffer for readers; the transcript
   * covers its own attach onward — recorded honestly via `transcriptBytes`.
   */
  setTranscript(transcript: PtyTranscript | null): void {
    this.transcript = transcript;
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
    // setWindow(rows, cols, heightPx, widthPx) — pixel dims are ignored by
    // every consumer this tool targets; zero is the documented "unset".
    this.channel.setWindow(rows, cols, 0, 0);
    this.touch();
  }

  /** Signal-and-close ladder shared with upstream session release. Idempotent. */
  close(): boolean {
    const alreadyClosed = this.closed;
    if (!alreadyClosed) {
      this.closed = true;
      this.closeReason = 'operator';
    }
    // Dispatch even on an already-closed session: markClosed from a timer may
    // have flagged it without touching the channel, and terminateChannel is
    // safe on a dead channel (its ssh2WillSend gate refuses cleanly).
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
