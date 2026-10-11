import type { Client, ClientChannel } from 'ssh2';
import { sanitizeSessionName } from '../guard/sanitizer.js';
import { getDeviceArchive } from '../devices/archives.js';
import type { Profile } from '../types.js';
import { FilePtyTranscript, type PtyTranscript } from './transcript.js';
import { PtySession, type PtyCloseReason, type PtySessionInfo } from './pty-session.js';

/**
 * Per-connection manager of raw PTY sessions.
 * 每连接一个的裸 PTY 会话管理器。
 * 沿用上游 SessionManager 的生命周期职责（名字唯一、空闲回收、
 * 连接拆除时全部关闭），并加上 PTY 计划的生存期上限：
 * 一个被 agent 弃之不顾的裸 shell 必须自行死亡——既因空闲，
 * 也因年龄（计划第 ③ 层）。回收是拉取式的——每次工具调用
 * 与连接的周期清扫都会调 `reapExpired()`——因为每会话一个定时器
 * 会为了没人看的 shell 把进程吊着不死。
 */

export interface PtyManagerOptions {
  /** 活动 profile getter——profile 对象可在运行时被替换。 */
  profile: () => Profile;
  /** 活动 client getter；连接断开时抛错。 */
  getClient: () => Client;
  /** 空闲上限（U3 默认 10 分钟）；生存期上限（U3 默认 2 小时）。 */
  idleTimeoutMs: number;
  maxLifetimeMs: number;
  maxBufferBytes?: number;
  /** null 表示禁用转录（测试用）；默认每会话开启一份。 */
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
    // 先回收：一个已越过空闲/生存期上限的会话，不能在名字冲突时
    // 回答「已打开」——它其实是具行尸。
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
      // window 对象正是分配 PTY 的入参（`shell(window, options, cb)`）；
      // 上游的交互式会话传的也是这个形态——区别在于本会话把原始流
      // 交给调用方，
      // 而不是用 printf 标记包裹命令。
      this.opts.getClient().shell(
        { term: request.term ?? 'xterm-256color', cols: request.cols ?? 200, rows: request.rows ?? 50 },
        {},
        (err, stream) => (err ? reject(err) : resolve(stream)),
      );
    });

    const transcript = (this.opts.openTranscript ?? ((n: string) => FilePtyTranscript.open(n)))(name);
    const session = new PtySession(name, this.opts.profile().name, channel, {
      maxBufferBytes: this.opts.maxBufferBytes ?? 1_048_576,
      encoding: this.opts.profile().ptyEncoding ?? getDeviceArchive(this.opts.profile().deviceType)?.encoding,
    });
    // 厂商特性：用于就绪检测的提示符形态，以及经与用户写入
    // 完全相同的路径发送的关分页命令——
    // 因此转录会像记录任何其他输入一样记录它。
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

  /** 关闭空闲/生存期到期的会话；返回关了什么、为何关。 */
  reapExpired(): Array<{ name: string; reason: PtyCloseReason }> {
    const reaped: Array<{ name: string; reason: PtyCloseReason }> = [];
    for (const [name, session] of this.sessions) {
      if (session.closed) {
        // 远端已关闭的 shell 在被观察到之前会一直挂着；在这里丢弃它们，
        // 让 `list` 保持真实，又不必多一次关闭往返。
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
