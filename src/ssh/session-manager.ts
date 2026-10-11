import type { ClientChannel } from 'ssh2';
import type { Profile, SessionOpts } from '../types.js';
import { InteractiveSession, BackgroundSession, stripAnsi, type Session , type CloseOutcome } from './session.js';
import { shellSingleQuote } from '../guard/sanitizer.js';
import { openWithRetry } from './channel-retry.js';
import { randomUUID } from 'crypto';

/**
 * 管理器如何够到 SSH 连接。
 *
 * 刻意收窄：管理器只开通道、报告通道的打开与关闭，
 * 对连接、重连或 exec 一无所知。这让会话簿记——它随每个
 * 会话特性不断增长——不再与那个它总被缠在一起的连接
 * 生命周期混作一团。
 */
export interface SessionManagerDeps {
  /**
    * 每次调用都读，而不是构造时快照：限制、超时与 workdir
    * 都来自 profile，而 profile 对象可能被替换
    * （配置热重载，或测试在调限制）。
   */
  profile(): Profile;
  openShell(): Promise<ClientChannel>;
  openExec(command: string): Promise<ClientChannel>;
  onChannelOpened(): void;
  onChannelClosed(): void;
}

/** 拥有一条 SSH 连接的全部命名会话。 */
export class SessionManager {
  private sessions = new Map<string, Session>();

  constructor(private deps: SessionManagerDeps) {}

  get size(): number {
    return this.sessions.size;
  }

  async open(opts: SessionOpts): Promise<Session> {
    const profile = this.deps.profile();

    if (this.sessions.size >= profile.sessionMaxPerConnection) {
      throw new Error(
        `Session limit reached for ${profile.name} (max: ${profile.sessionMaxPerConnection})`,
      );
    }
    if (this.sessions.has(opts.name)) {
      throw new Error(`Session "${opts.name}" already exists on ${profile.name}`);
    }

    const ttlMs = opts.ttlMs ?? profile.sessionIdleTimeoutMs;
    const id = randomUUID();

    if (opts.type === 'interactive') {
      return this.openInteractive(id, opts.name, ttlMs);
    }
    if (!opts.command) throw new Error('Background sessions require a command');
    return this.openBackground(id, opts.name, opts.command, ttlMs);
  }

  /**
    * 注册会话并把其生命周期绑到通道上。
   *
    * 逐出有守卫：close() 只结束流，所以通道的 'close' 可能在
    * 同名被复用很久之后才到，无守卫的 delete 会逐出*新*
    * 会话——通道开着，却从 get/list/close/reap
    * 都够不到。
   */
  private register(name: string, session: Session, stream: ClientChannel): void {
    this.sessions.set(name, session);
    this.deps.onChannelOpened();

    stream.on('close', () => {
      this.deps.onChannelClosed();
      if (this.sessions.get(name) === session) this.sessions.delete(name);
    });
  }

  private async openInteractive(id: string, name: string, ttlMs: number): Promise<Session> {
    let stream: ClientChannel;
    try {
      stream = await openWithRetry(() => this.deps.openShell());
    } catch (err) {
      throw new Error(`Failed to open interactive session: ${err instanceof Error ? err.message : String(err)}`);
    }

    const session = new InteractiveSession(id, name, this.deps.profile().name, stream, ttlMs);
    this.register(name, session, stream);
    try {
      await this.primeShell(stream, session);
    } catch (err) {
      await session.close().catch(() => { /* channel already going away */ });
      this.sessions.delete(name);
      throw err;
    }
    return session;
  }


  /**
    * 让 shell 安静下来，并确认它能跑会话协议——一次往返完成。
    *
   *
    * Priming 压掉提示符、历史与括号粘贴，否则它们都会混进
    * 命令输出。末尾的就绪标记兼任握手：只有能跑 `printf`
    * 的 shell 才会回它，而那正是后续每条命令都依赖的
    * 同一能力。
    *
    * 它替代了两个更弱的机制。用 /[#$>]\s*$/ 等提示符是猜，
    * 在 busybox ash 上失败（其提示符后跟光标位置查询），
    * 又会在 cmd.exe 上静默「成功」——它显示 `>` 提示符，
    * 却跑不了任何一条命令，之后每次调用都坐等到 60 秒
    * 命令超时，一无所获。
   */
  private primeShell(stream: ClientChannel, session: InteractiveSession): Promise<void> {
    const { workdir, name: profileName } = this.deps.profile();
    // 拆成字面量：回显的输入永远不含拼装出的标记，
    // 因此只有 shell 自己的输出能满足匹配。
    const parts = ['SSHMCP_RDY', `_${randomUUID()}`];
    const marker = parts.join('');

    return new Promise((resolve, reject) => {
      let buffer = '';
      let settled = false;

      const settle = (err?: Error) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        stream.removeListener('data', onData);
        err ? reject(err) : resolve();
      };

      const onData = (data: Buffer) => {
        buffer += data.toString();
        if (stripAnsi(buffer).includes(marker)) settle();
      };

      const timer = setTimeout(() => settle(new Error(
        `Interactive sessions are not supported on ${profileName}: its shell did not complete the ` +
        'session handshake. The protocol requires a POSIX shell (sh/bash/ash/zsh); cmd.exe and ' +
        'PowerShell do not provide it. Use read-command / run-command instead, which work on any shell.',
      )), 5000);

      stream.on('data', onData);
      stream.write('PS1=""\n');
      stream.write('set +o history 2>/dev/null\n');
      stream.write('bind "set enable-bracketed-paste off" 2>/dev/null\n');
      if (workdir) {
        stream.write(`cd ${shellSingleQuote(workdir)}\n`);
        session.setCwd(workdir);
      }
      stream.write(`printf '%s%s\\n' '${parts[0]}' '${parts[1]}'\n`);
    });
  }

  private async openBackground(id: string, name: string, command: string, ttlMs: number): Promise<Session> {
    let stream: ClientChannel;
    try {
      stream = await openWithRetry(() => this.deps.openExec(command));
    } catch (err) {
      throw new Error(`Failed to open background session: ${err instanceof Error ? err.message : String(err)}`);
    }

    const profile = this.deps.profile();
    const session = new BackgroundSession(
      id, name, profile.name, stream, ttlMs, profile.sessionBackgroundMaxMs,
    );
    this.register(name, session, stream);
    return session;
  }

  get(name: string): Session | undefined {
    return this.sessions.get(name);
  }

  list(): Session[] {
    return Array.from(this.sessions.values());
  }

  async close(name: string): Promise<CloseOutcome> {
    const session = this.sessions.get(name);
    if (!session) throw new Error(`Session "${name}" not found on ${this.deps.profile().name}`);
    try {
      return await session.close();
    } finally {
      // 加守卫并放进 `finally`：因为现在的关闭要等一条 kill 阶梯，
      // 而不是下个微任务就返回。无守卫时，回收器关闭本会话的同一时刻
      // 调用方重开同名，会逐出*新*会话——`register` 已记录的隐患。
      // 没有 `finally`，一次 rejection 会把条目永远留在那里，
      // 占着一个 `sessionMaxPerConnection` 槽位并堵死该名字。
      //
      if (this.sessions.get(name) === session) this.sessions.delete(name);
    }
  }

  async closeAll(): Promise<void> {
    // 并行。各阶梯是独立通道上的独立计时器，串行时实测：五条
    // 无视 INT 与 TERM 的命令耗了 10.0 秒——超过 Docker 默认 10 秒
    // 停止宽限，容器在拆除中途被 SIGKILL，后面的会话根本没得到
    // 升级信号。阶梯被 await 之前每个会话至少立即收到自己的 INT，
    // 串行化让尾部比它修掉的 bug 更糟。
    //
    await Promise.all([...this.sessions.keys()].map((name) => this.close(name).catch(() => {})));
  }

  /**
    * 关闭每条过期会话，并等升级走完。
    *
    * 之所以 await、之所以是 async。发射后不管在 `waitForChannelClose`
    * 所守护的保证上留了个洞：`close()` 派发 INT 即返回，条目被删，
    * `sessionCount` 同一 tick 归零，回收器的下一次调用——以
    * `sessionCount` 为门的 `reapIdleConnections`——随即关闭连接，
    * 客户端微秒级结束。TERM 与 KILL 随之被丢，
    * 对 INT 无视的后台命令就这样活过了自己的回收。
   */
  async reapExpired(): Promise<void> {
    const expired = [...this.sessions.entries()].filter(([, s]) => s.isExpired());
    await Promise.all(expired.map(([name]) => this.close(name).catch(() => {})));
  }

  markAllDisconnected(): void {
    for (const session of this.sessions.values()) {
      session.markDisconnected();
    }
  }
}
