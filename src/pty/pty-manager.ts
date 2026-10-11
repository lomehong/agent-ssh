import type { Client, ClientChannel } from 'ssh2';
import { sanitizeSessionName } from '../guard/sanitizer.js';
import { getDeviceArchive } from '../devices/archives.js';
import type { Profile } from '../types.js';
import { FilePtyTranscript, type PtyTranscript } from './transcript.js';
import { PtySession, type PtyCloseReason, type PtySessionInfo } from './pty-session.js';

/**
 * Per-connection manager of raw PTY sessions.
 *
 * Mirrors the upstream SessionManager's lifecycle duties (unique names, idle
 * reaping, close-all on connection teardown) and adds the PTY plan's lifetime
 * bound: a raw shell that an agent walked away from must die on its own, both
 * from idleness and from age (plan layer ③). Reaping is pull-based — every
 * tool call and the connection's periodic sweep call `reapExpired()` — because
 * timers per session would keep the process alive for shells nobody watches.
 */

export interface PtyManagerOptions {
  /** Live profile getter — the profile object can be replaced at runtime. */
  profile: () => Profile;
  /** Live client getter; throws when the connection is down. */
  getClient: () => Client;
  /** Idle bound (U3 default 10min); lifetime bound (U3 default 2h). */
  idleTimeoutMs: number;
  maxLifetimeMs: number;
  maxBufferBytes?: number;
  /** Null disables transcripts (tests); default opens one per session. */
  openTranscript?: (sessionName: string) => Promise<PtyTranscript | null>;
}

export interface PtyOpenRequest {
  name: string;
  cols?: number;
  rows?: number;
  term?: string;
}

export class PtySessionManager {
  private readonly sessions = new Map<string, PtySession>();

  constructor(private readonly opts: PtyManagerOptions) {}

  list(): PtySessionInfo[] {
    return [...this.sessions.values()].map((s) => s.toInfo());
  }

  get(name: string): PtySession | undefined {
    return this.sessions.get(name);
  }

  get size(): number {
    return this.sessions.size;
  }

  async open(request: PtyOpenRequest): Promise<PtySessionInfo> {
    const name = sanitizeSessionName(request.name);
    // Reap first: a session that hit its idle/lifetime bound must not answer a
    // name collision with "already open" when it is in fact dead walking.
    this.reapExpired();
    if (this.sessions.has(name)) {
      const existing = this.sessions.get(name)!;
      throw new Error(
        `PTY session "${name}" is already open${existing.closed ? ` but marked closed (${existing.closeReason})` : ''}; close it or pick another name.`,
      );
    }
    const max = this.opts.profile().sessionMaxPerConnection;
    if (this.sessions.size >= max) {
      throw new Error(`PTY session cap reached (${max} per connection); close one first.`);
    }

    const channel = await new Promise<ClientChannel>((resolve, reject) => {
      // The window object is what allocates the PTY (`shell(window, options, cb)`);
      // upstream's interactive sessions pass the same shape — the difference is
      // that this session hands the raw stream to the caller instead of framing
      // commands in printf markers.
      this.opts.getClient().shell(
        { term: request.term ?? 'xterm-256color', cols: request.cols ?? 200, rows: request.rows ?? 50 },
        {},
        (err, stream) => (err ? reject(err) : resolve(stream)),
      );
    });

    const transcript = (this.opts.openTranscript ?? ((n: string) => FilePtyTranscript.open(n)))(name);
    const session = new PtySession(name, this.opts.profile().name, channel, {
      maxBufferBytes: this.opts.maxBufferBytes ?? 1_048_576,
      encoding: this.opts.profile().ptyEncoding,
    });
    // Vendor personality: prompt shapes for readiness detection, and the
    // paging-off command sent through the SAME path a user write takes — so
    // the transcript records it like any other input.
    const archive = getDeviceArchive(this.opts.profile().deviceType);
    session.setPromptPatterns(archive?.promptPatterns ?? []);
    this.sessions.set(name, session);
    const attached = await transcript;
    session.setTranscript(attached);
    if (archive?.disablePaging) session.write(archive.disablePaging + '\n');
    return session.toInfo();
  }

  read(name: string, cursor: number, maxChunk: number) {
    this.reapExpired();
    const session = this.mustGet(name);
    return { ...session.readSince(cursor, maxChunk), promptDetected: session.seesPrompt() };
  }

  write(name: string, input: string) {
    this.reapExpired();
    const session = this.mustGet(name);
    return session.write(input);
  }

  resize(name: string, rows: number, cols: number): void {
    this.mustGet(name).resize(rows, cols);
  }

  close(name: string): { outcome: 'closed' | 'unsignalled'; reason?: PtyCloseReason } {
    const session = this.sessions.get(name);
    if (!session) throw new Error(`PTY session "${name}" not found.`);
    const alreadyClosed = session.closed;
    const dispatched = session.close();
    this.sessions.delete(name);
    return {
      outcome: alreadyClosed || dispatched ? 'closed' : 'unsignalled',
      reason: session.closeReason,
    };
  }

  /** Close idle/lifetime-expired sessions; returns what it closed and why. */
  reapExpired(): Array<{ name: string; reason: PtyCloseReason }> {
    const reaped: Array<{ name: string; reason: PtyCloseReason }> = [];
    for (const [name, session] of this.sessions) {
      if (session.closed) {
        // Remote-closed shells linger until observed; dropping them here keeps
        // `list` truthful without a close round-trip.
        if (session.closeReason === 'remote' || session.closeReason === 'disconnect') {
          this.sessions.delete(name);
          reaped.push({ name, reason: session.closeReason });
        }
        continue;
      }
      if (session.lifetimeMs >= this.opts.maxLifetimeMs) {
        session.markClosed('lifetime');
        session.close();
        this.sessions.delete(name);
        reaped.push({ name, reason: 'lifetime' });
        continue;
      }
      if (session.idleMs >= this.opts.idleTimeoutMs) {
        session.markClosed('idle');
        session.close();
        this.sessions.delete(name);
        reaped.push({ name, reason: 'idle' });
      }
    }
    return reaped;
  }

  async closeAll(): Promise<void> {
    for (const [, session] of this.sessions) {
      session.markClosed('disconnect');
      session.close();
    }
    this.sessions.clear();
  }

  private mustGet(name: string): PtySession {
    const session = this.sessions.get(name);
    if (!session) throw new Error(`PTY session "${name}" not found.`);
    return session;
  }
}
