import { appendFile, mkdir, stat } from 'fs/promises';
import { dirname, join } from 'path';
import { redactText } from '../guard/redactor.js';
import { getAuditLogPath } from '../audit/store.js';

/**
 * Redacted per-session transcript for raw PTY sessions.
 *
 * Layer ② of the PTY safety plan (technical scheme §6 U2, ratified by master
 * on 2026-10-11): a raw PTY is a byte stream, so nothing on it can pass the
 * command classifier — the compensating control is that everything on it is
 * auditable. The transcript records each input write and each output chunk,
 * redacted with the same engine as the audit log, into one file per session
 * next to the audit log.
 *
 * The transcript is best-effort by design: an I/O failure must never break the
 * session it observes, so append errors are swallowed after being reported to
 * `onError`. A `maxBytes` cap stops runaway output from filling the disk; past
 * the cap the file is frozen and the drop is counted (and surfaced on the
 * session's info) rather than silently truncating mid-line forever.
 */

export interface PtyTranscript {
  append(direction: 'in' | 'out', text: string): void;
  readonly bytesWritten: number;
  readonly frozen: boolean;
}

const DEFAULT_MAX_BYTES = 10 * 1024 * 1024;

export function getTranscriptDir(): string {
  return join(dirname(getAuditLogPath()), 'pty-transcripts');
}

export class FilePtyTranscript implements PtyTranscript {
  private size = 0;
  private freezeState = false;
  private dirEnsured = false;
  /** Serialise appends so interleaved in/out chunks stay ordered in the file. */
  private queue: Promise<void> = Promise.resolve();

  private constructor(
    private readonly filePath: string,
    private readonly maxBytes: number,
    private readonly onError: (err: unknown) => void,
  ) {}

  static async open(
    sessionName: string,
    opts: { dir?: string; maxBytes?: number; onError?: (err: unknown) => void } = {},
  ): Promise<FilePtyTranscript | null> {
    const dir = opts.dir ?? getTranscriptDir();
    const filePath = join(
      dir,
      `${sessionName.replace(/[^A-Za-z0-9_-]/g, '_')}-${Date.now()}.log`,
    );
    const transcript = new FilePtyTranscript(
      filePath,
      opts.maxBytes ?? DEFAULT_MAX_BYTES,
      opts.onError ?? (() => {}),
    );
    try {
      await mkdir(dirname(filePath), { recursive: true });
      transcript.dirEnsured = true;
      return transcript;
    } catch (err) {
      transcript.onError(err);
      return null;
    }
  }

  get bytesWritten(): number {
    return this.size;
  }

  get frozen(): boolean {
    return this.freezeState;
  }

  append(direction: 'in' | 'out', text: string): void {
    if (this.freezeState || text.length === 0) return;
    // Redact with the audit engine — a device banner or a pasted secret must
    // not land in a log file just because this stream is "not a command".
    const line = JSON.stringify({
      t: new Date().toISOString(),
      dir: direction,
      text: redactText(text),
    }) + '\n';
    const bytes = Buffer.byteLength(line);
    if (this.size + bytes > this.maxBytes) {
      this.freezeState = true;
      return;
    }
    this.size += bytes;
    this.queue = this.queue
      .then(async () => {
        if (!this.dirEnsured) {
          await mkdir(dirname(this.filePath), { recursive: true });
          this.dirEnsured = true;
        }
        await appendFile(this.filePath, line, 'utf8');
      })
      .catch((err) => this.onError(err));
  }
}

/** Probe used by tests and startup logging; null when the directory is absent. */
export async function transcriptDirExists(): Promise<boolean> {
  try {
    await stat(getTranscriptDir());
    return true;
  } catch {
    return false;
  }
}
