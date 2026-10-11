import { Client, type ClientChannel, type ConnectConfig, type ExecOptions } from 'ssh2';
import type { ConnectionInfo, Profile, ResolvedCredentials, ExecOpts, CommandResult, SessionOpts } from '../types.js';
import { resolveAlgorithms } from './algorithms.js';
import { verifyHostKey, fingerprintPublicKey, type HostKeyMode } from './host-key.js';
import type { Session, CloseOutcome } from './session.js';
import { SessionManager } from './session-manager.js';
import { PtySessionManager } from '../pty/pty-manager.js';
import { ForwardManager } from '../forward/forward-manager.js';
import type { Span } from '@opentelemetry/api';
import { tracer } from '../observability/tracer.js';
import { redactText } from '../guard/redactor.js';
import { shellSingleQuote } from '../guard/sanitizer.js';
import { openWithRetry } from './channel-retry.js';
import { terminateChannel, COULD_NOT_SIGNAL } from './channel-signal.js';

/**
 * 本服务器在为命令打开的每条通道上向主机表明的身份。
 *
 * ssh2 的 exec() 调 reqEnv(chan, opts.env) 无回调，
 * 请求以 want_reply=0 发出，服务器无以应答：
 * 未被接受的名字不会让 exec 失败。对照 ssh2 1.17.0
 *（lib/client.js:1230 与 :1863 的 wantReply 行）、Dropbear、
 * 及默认配置的 Windows OpenSSH 实测——命令跑通，
 * 变量只是不在，退出码不变。
 *
 * **无论主机是否设置 AcceptEnv，请求都发给每台主机。** AcceptEnv
 * 是服务器关于是否*存储*该对的策略；
 * 不是客户端侧的门，这里没有任何东西查询它。对照无 AcceptEnv
 * 机制的 Dropbear 在线上实测：
 *
 *     Outbound: Sending CHANNEL_REQUEST (r:0, env: AI_AGENT=ssh-mcp)
 *     Outbound: Sending CHANNEL_REQUEST (r:0, exec: echo hi)
 *
 * 从未选择加入的主机依然知道驱动会话的是 agent 而非人。
 * 这是一种披露，SECURITY.md 的威胁模型包含主机定制输出
 * 以注入模型——这正是 profile 上存在 announceAgent = false 的原因。
 * 本注释更早的草稿称该声明在未选择加入的主机上「无效」——
 * 对会话环境为真，对线路为假，
 * 这一区别正是 profile 有开关的全部理由。
 *
 *
 * 刻意只有名字——不带 ssh-mcp 构建号。传输本来就会在 identification
 * string 中暴露*库*版本（ssh2 发 SSH-2.0-ssh2js<ver>，此处不覆盖 ident），
 * 但那是该库所有用户共有的一个版本；本工具的按构建版本号
 * 会把敌意主机收窄到一个部署。
 *
 *
 * AI_AGENT 刻意在本项目 SSH_MCP_* 命名空间之外。本仓库拥有的
 * 其余环境变量名都有前缀；这个没有，因为它是被服务端探测器读取
 * 的跨工具约定，那些探测器不知道也不关心哪个客户端发送了它，
 * 加前缀的名字会挫败它唯一的目的。
 * 改名为 SSH_MCP_AGENT 看似一致性修复，却会静默破坏
 * 每一个消费者——因此有了这一段。
 *
 * 冻结，因为它是进程内每条连接每条通道共享的一个对象。
 * 今天无人修改它；第一个按命令向通道 env 添加的操作会，
 * 并在进程生命周期内跨 profile 泄漏。
 *
 */
const AGENT_ENV = Object.freeze({ AI_AGENT: 'ssh-mcp' });

/**
 * 停掉 channel 背后的命令，在 span 上记录原因，返回拒绝应携带的句子。
 * rejection should carry.
 *
 * 模块作用域而非 exec 内的闭包：它只捕获 span，
 * 模块作用域下可直接用 stub span 和假通道测试。
 * 它存在的理由：三个结算路径过去内联了这段逻辑，其中两个
 * 算了消息的 unstopped 值却在 span 之前丢掉——
 * ssh.unstopped 因此在结构上不可能对被取消的命令为真，
 * 而那是 MCP 客户端停止命令最常见的方式。
 */
export function stopAndDescribe(
  span: Span,
  reason: 'ssh.timedOut' | 'ssh.aborted',
  channel: ClientChannel | null,
): string {
  span.setAttribute(reason, true);
  // null 通道意味着 exec 回调尚未到达。并不代表没在运行——
  // ssh2 在 CHANNEL_SUCCESS 时调用该回调，OpenSSH 在 fork 命令后发送——
  // 但也没有什么可告警的：onExecChannel 会在迟到通道到达时
  // 立即停掉它。此处告警会把「可能仍在运行」贴到每次与慢通道
  // 开启竞速的超时上，而什么都没错时的告警不再被读。
  //
  //
  // 以独立属性记录而非 ssh.unstopped: false——后者断言了
  // 此路径尚不可知的干净停止。迟到处理器在自己的 span 上
  // 发出真正的答案。
  if (channel === null) {
    span.setAttribute('ssh.stopDeferred', true);
    return '';
  }
  const dispatched = terminateChannel(channel);
  // 每个结算路径都设置，无一例外，让「干净停止」和「跑的是旧构建」
  // 不是同一个缺席属性查询。
  span.setAttribute('ssh.unstopped', !dispatched);
  return dispatched ? '' : COULD_NOT_SIGNAL;
}

type KeyboardInteractiveHandler = (
  name: string,
  instructions: string,
  instructionsLang: string,
  prompts: { prompt: string; echo: boolean }[],
  finish: (answers: string[]) => void,
) => void;

/**
 * 用 profile 的密码回答每一条 keyboard-interactive 提示。
 *
 * 导出以便直接单测：ssh2 事件在 connect() 握手中触发，
 * 测试否则需要一台提供该方法的真实服务器。网络设备通常
 * 只通过 keyboard-interactive 暴露密码认证，提示被盲答以
 * auth = password 本会使用的同一凭据。无密码凭据时
 * 应答为空字符串——服务器以自己的消息拒绝认证，
 * 而非本侧发明一个不同的错误。
 *
 */
export function answerKeyboardInteractive(
  password: string | undefined,
): (
  name: string,
  instructions: string,
  instructionsLang: string,
  prompts: { prompt: string; echo: boolean }[],
  finish: (answers: string[]) => void,
) => void {
  return (_name, _instructions, _instructionsLang, prompts, finish) => {
    finish(prompts.map(() => password ?? ''));
  };
}

export class SSHConnection {
  readonly profile: Profile;
  private client: Client | null = null;
  private credentials: ResolvedCredentials;
  private readonly sessions: SessionManager;
  private readonly ptySessions: PtySessionManager;
  private readonly forwards: ForwardManager;
  private readonly allowDynamicForwarding: boolean;
  private activeChannels = 0;
  private connecting: Promise<void> | null = null;
  /** Which connect() call currently owns `connecting`; see connect(). */
  private connectAttempt: symbol | null = null;
  private connected = false;
  private connectedAt: Date | null = null;
  private lastActivity = new Date();
  private knownHostsStore: Map<string, string>;
  private hostKeyMode: HostKeyMode;
  private bastionSock: ClientChannel | null;

  constructor(
    profile: Profile,
    credentials: ResolvedCredentials,
    knownHostsStore: Map<string, string>,
    hostKeyMode: HostKeyMode = 'tofu',
    bastionSock?: ClientChannel,
    /** Raw-PTY session bounds from [defaults]; U3 values when omitted (tests). */
    ptyBounds: { idleTimeoutMs: number; maxLifetimeMs: number; bufferBytes: number } = { idleTimeoutMs: 600_000, maxLifetimeMs: 7_200_000, bufferBytes: 1_048_576 },
    /** Dynamic (SOCKS) forwarding switch from [defaults]; off when omitted. */
    allowDynamicForwarding = false,
  ) {
    this.profile = profile;
    this.credentials = credentials;
    this.knownHostsStore = knownHostsStore;
    this.hostKeyMode = hostKeyMode;
    this.bastionSock = bastionSock ?? null;
    this.allowDynamicForwarding = allowDynamicForwarding;

    this.sessions = new SessionManager({
      // 活读：profile 对象可在构造后被替换。
      profile: () => this.profile,
      // 回调内也要 ensureConnected，不只是重试前：这些
      // 跑在 openWithRetry 下，Dropbear 在通道震荡时丢整条连接
      // 而非仅拒通道。openSession 确实先查链路，
      // 但链路可能在查完与通道开启之间死掉——然后每次重试都在死
      // 客户端上调 getClient() 抛同一个 SSH connection not established，
      // 重试跑了三遍尸体。SftpClient 已是这种做法。
      //
      openShell: async () => {
        await this.ensureConnected();
        return new Promise<ClientChannel>((resolve, reject) => {
          this.getClient().shell(
            { term: 'xterm-256color', cols: 200, rows: 50 },
            // 三参形式，刻意。ssh2 在首参携带 env 或 x11 时
            // 将其重分类为选项对象（lib/client.js:1260），
            // 折进上方 window 对象会在每次交互会话
            // 上静默丢掉 term/cols/rows。
            //
            this.channelEnv(),
            (err, stream) => (err ? reject(err) : resolve(stream)),
          );
        });
      },
      openExec: async (command) => {
        await this.ensureConnected();
        return new Promise<ClientChannel>((resolve, reject) => {
          this.getClient().exec(
            this.applyWorkdir(command),
            this.channelEnv(),
            (err, stream) => (err ? reject(err) : resolve(stream)),
          );
        });
      },
      onChannelOpened: () => { this.activeChannels++; },
      onChannelClosed: () => { this.activeChannels--; },
    });

    // 裸 PTY 会话（agent-ssh）：与 SessionManager 相同的活 profile 读取，
    // 加上计划第 ③ 层批准的 [defaults] 空闲/生存期上限。
    this.ptySessions = new PtySessionManager({
      profile: () => this.profile,
      getClient: () => this.getClient(),
      idleTimeoutMs: ptyBounds.idleTimeoutMs,
      maxLifetimeMs: ptyBounds.maxLifetimeMs,
    });

    this.forwards = new ForwardManager({
      profile: () => this.profile,
      getClient: () => this.getClient(),
      allowDynamic: () => this.allowDynamicForwarding,
    });
  }

  /**
   * The announcement for a channel about to be opened, or nothing.
    * 即将打开的通道的宣告，或无。
    *
    * 一个访问器而非每个站点一个对象字面量。此特性首版在三个
    * 开通道站点中的两个写了 { env: AGENT_ENV }，漏了 openShell，
    * 交互会话内的每条命令都未宣告而 README 声称相反。
    * 三个字面量给站点一个看起来完整实则空手的机会；
    * 漏调本函数则不会。
    *
    * 活读，同此处一切 profile 字段：profile 对象可在构造后替换，
    * 运维清除 announceAgent 在下一条通道即生效，而非下次重启。
    *
   *
    * 返回类型是两个调用方都接受的交集——ExecOptions 和
    * ShellOptions 以相同方式声明 env——一个访问器服务 exec()、
    * openExec 和 openShell，无须点名任一 API。
   */
  private channelEnv(): { env?: NodeJS.ProcessEnv } {
    return this.profile.announceAgent === false ? {} : { env: AGENT_ENV };
  }

  async ensureConnected(): Promise<void> {
    if (this.isConnected()) return;
    if (this.connecting) return this.connecting;

    this.connecting = this.connect();
    return this.connecting;
  }

  private async connect(): Promise<void> {
    // 本次尝试的身份，让「本次尝试是否仍拥有 connecting」
    // 无须经过 this.client 即可提问。
    //
    // 这是两个不同的问题，混淆它们就是 #197：settle() 过去只在
    // if (isCurrent()) 时清 connecting，而断连处理器在 settle 前
    // 就将 this.client 置空。isCurrent() 已为 false，connecting 保留
    // 被拒的 promise，ensureConnected() 在进程生命周期内重放它——
    // 该 profile 的每次后续调用立即以过期消息失败，
    // 服务器恢复后也无路可回。重启服务器是唯一出口，
    // 正是它的报告方式。
    //
    //
    // 重排两条语句也能工作且为下次编辑留下同样的陷阱；
    // 耦合才是必须消除的。
    const attempt = Symbol('connect');
    this.connectAttempt = attempt;

    return new Promise((resolve, reject) => {
      // 下方每个处理器作用于 client 而非 this.client，且仅在
      // 它仍是当前客户端时修改共享状态。被替代尝试的迟到事件
      // 不得拆掉替换了它的那条连接。
      //
      const client = new Client();
      this.client = client;
      const isCurrent = () => this.client === client;

      let settled = false;
      const settle = (fn: () => void) => {
        if (settled) return;
        settled = true;
        clearTimeout(timeoutId);
        // 对*本次*尝试无条件：被替代的不动更新尝试的 promise，
        // 没有别的能把它搁浅。
        if (this.connectAttempt === attempt) this.connecting = null;
        fn();
      };

      const timeoutId = setTimeout(() => {
        settle(() => {
          try { client.end(); } catch { /* already gone */ }
          if (isCurrent()) this.client = null;
          reject(new Error('SSH connection timeout'));
        });
      }, 20000);

      client.on('ready', () => {
        settle(() => {
          this.connected = true;
          this.connectedAt = new Date();
          this.lastActivity = new Date();
          resolve();
        });
      });

      client.on('error', (err: Error) => {
        settle(() => {
          if (isCurrent()) this.client = null;
          reject(new Error(`SSH connection error: ${err.message}`));
        });
      });

      // end/close 也在成功握手很久后连接掉线时触发——那条路径
      // 必须清连接状态但不动已解决的 promise。
      //
      const onDisconnect = (reason: string) => () => {
        if (!isCurrent()) return;
        this.connected = false;
        this.sessions.markAllDisconnected();
        this.client = null;
        this.connectedAt = null;
        // 不在此清计时器的话，经干净 TCP 关闭失败的握手留下一颗
        // 20 秒炸弹：它会稍后结束*更新的*客户端的握手中途
        // 并将其 connecting 置空，让那次尝试挂起。
        settle(() => reject(new Error(`SSH connection ${reason} during handshake`)));
      };

      client.on('end', onDisconnect('ended'));
      client.on('close', onDisconnect('closed'));

      const connectConfig: ConnectConfig = {
        host: this.profile.host,
        port: this.profile.port,
        username: this.profile.user,
        // 在此对照 FROZEN_ALGORITHMS 解析——绝不透传 profile 的
        // 调整形态，ssh2 会对照它自己（宽得多）的默认应用，
        // 静默绕过冻结下限。
        algorithms: resolveAlgorithms(this.profile.algorithms) as ConnectConfig['algorithms'],
        hostVerifier: (key: Buffer) => {
          // 固定过去在此检查，作为 verifyHostKey 前面的 return false。
          // 那使它只拒不禁：*匹配的*固定落下去仍被拒——在 strict 下，
          // 其存储永远无法被填充。传入它让一个函数统管整个决定，
          // return false 给 ssh2 的是泛型握手失败，
          // 而 verifyHostKey 抛出的消息点名了决策者。
          //
          return verifyHostKey(
            this.profile.host,
            this.profile.port,
            fingerprintPublicKey(key),
            this.knownHostsStore,
            this.hostKeyMode,
            this.profile.trustedHostKey,
          );
        },
        readyTimeout: 20000,
        keepaliveInterval: 15000,
        keepaliveCountMax: 3,
      };

      if (this.credentials.agentSocket) {
        connectConfig.agent = this.credentials.agentSocket;
      }
      if (this.credentials.privateKey) {
        connectConfig.privateKey = this.credentials.certificate
          ? this.credentials.privateKey + '\n' + this.credentials.certificate
          : this.credentials.privateKey;
        if (this.credentials.passphrase) {
          connectConfig.passphrase = this.credentials.passphrase;
        }
      }
      if (this.credentials.password) {
        connectConfig.password = this.credentials.password;
      }
      if (this.bastionSock) {
        connectConfig.sock = this.bastionSock;
      }

      // 某些主机——许多网络设备在内——只经 keyboard-interactive
      // 方法提供密码认证。ssh2 用 tryKeyboard 请求该方法
      // 并期望在此事件上收到答案；在 connect() 前挂载，
      // 使其在握手能发出之前就注册好。
      if (this.profile.keyboardInteractive) {
        connectConfig.tryKeyboard = true;
        // ssh2 的 d.ts 省略了客户端侧 keyboard-interactive 事件
        //（运行时存在、上游 README 有、仅服务端 Connection 有类型），
        // 所以经最小结构视图而非 any。
        //
        const events = client as unknown as {
          on(event: 'keyboard-interactive', listener: KeyboardInteractiveHandler): void;
        };
        events.on('keyboard-interactive', answerKeyboardInteractive(this.credentials.password));
      }

      client.connect(connectConfig);
    });
  }

  isConnected(): boolean {
    return this.connected && this.client !== null;
  }

  getClient(): Client {
    if (!this.client) throw new Error('SSH connection not established');
    return this.client;
  }

  getSudoPassword(): string | undefined {
    return this.credentials.sudoPassword;
  }

  /**
    * 在此而非工具层应用，策略引擎分类的字符串
    * 永远不是携带 && 的那个。
    *
   */
  private applyWorkdir(command: string): string {
    if (!this.profile.workdir) return command;
    return `cd ${shellSingleQuote(this.profile.workdir)} && ${command}`;
  }

  async exec(rawCommand: string, opts: ExecOpts = {}): Promise<CommandResult> {
    await this.ensureConnected();
    const command = this.applyWorkdir(rawCommand);
    const timeoutMs = opts.timeoutMs ?? this.profile.timeout;
    const startTime = Date.now();

    const span = tracer.startSpan('ssh.exec');
    span.setAttribute('ssh.host', this.profile.host);
    span.setAttribute('ssh.port', this.profile.port);
    span.setAttribute('ssh.command', redactText(command));
    // 在 span 上可见，理由同审计记录携带它：
    // 放宽白名单就是降低传输下限，
    // 必须在其下运行的每条命令上可见。
    span.setAttribute('ssh.algorithmsOverride', this.profile.algorithms !== undefined);

    return new Promise((resolve, reject) => {
      let activeStream: ClientChannel | null = null;
      let resolved = false;

      const timeoutId = setTimeout(() => {
        if (!resolved) {
          resolved = true;
          const note = stopAndDescribe(span, 'ssh.timedOut', activeStream);
          span.end();
          reject(new Error(`Command timed out after ${timeoutMs}ms${note}`));
        }
      }, timeoutMs);

      const execOpts: ExecOptions = { ...this.channelEnv() };
      if (opts.tty || this.profile.tty) {
        execOpts.pty = { term: 'xterm-256color', cols: 200, rows: 50 };
      }

      // 已重试：某些服务器（尤其 Dropbear）在前一条释放后立即
      // 间歇性拒绝通道。只重试 open——流一旦存在，
      // 这里不会重跑命令。
      const openExecChannel = async () => {
        // 每次尝试重新建立：拒绝可能是掉线而非拒通道。
        //
        await this.ensureConnected();
        const activeClient = this.getClient();
        return new Promise<ClientChannel>((res, rej) => {
          activeClient.exec(command, execOpts, (err, stream) => (err ? rej(err) : res(stream)));
        });
      };

      const onExecChannel = (err: Error | undefined, stream: ClientChannel) => {
        if (err) {
          if (!resolved) {
            resolved = true;
            clearTimeout(timeoutId);
            span.end();
            reject(new Error(`SSH exec error: ${err.message}`));
          }
          return;
        }
        // promise 可能已结算——超时可在 openWithRetry 仍在途时触发，
        // 且 ssh2 只在服务器应答 CHANNEL_SUCCESS 后调此回调，
        // OpenSSH 在 fork 命令*之后*发送。没有这段，
        // 命令在调用方被告知超时后在主机上跑到完成，
        // 占着通道、丢着输出：正是 #146，首次修复未覆盖的路径。
        //
        if (resolved) {
          // 在自己的 span 上：exec span 已在 promise 结算时结束，
          // 已结束 span 上的属性被静默丢弃。没有这段，
          // stopAndDescribe 推迟的唯一结局就不可观测——
          // 正是这次变更要移除的形态。
          const late = tracer.startSpan('ssh.exec.lateStop');
          late.setAttribute('ssh.host', this.profile.host);
          late.setAttribute('ssh.unstopped', !terminateChannel(stream));
          late.end();
          return;
        }

        activeStream = stream;
        this.activeChannels++;

        let stdout = '';
        let stderr = '';
        const maxOutput = this.profile.maxOutputBytes;
        let lastProgressSent = 0;
        const PROGRESS_INTERVAL = 500;

        if (opts.stdin) {
          try { stream.write(opts.stdin); } catch { /* */ }
        }
        try { stream.end(); } catch { /* */ }

        if (opts.abortSignal) {
          if (opts.abortSignal.aborted) {
            resolved = true;
            clearTimeout(timeoutId);
            // 在此递减而非 close：下方 close 监听器在此路径
            // 从未挂载。通道现在比计数多活一条 kill 阶梯的时间。
            //
            this.activeChannels--;
            // client.exec() 已派发命令，不信号就拒绝
            // 会让它在主机上跑到完成并占通道直到结束。
            // 关通道也停不了——只有送达的信号才行（#146）。
            //
            const note = stopAndDescribe(span, 'ssh.aborted', stream);
            span.end();
            reject(new Error(`Command aborted before execution${note}`));
            return;
          }
          const onAbort = () => {
            if (!resolved) {
              resolved = true;
              clearTimeout(timeoutId);
              const note = stopAndDescribe(span, 'ssh.aborted', stream);
              span.end();
              reject(new Error(`Command aborted${note}`));
            }
          };
          opts.abortSignal.addEventListener('abort', onAbort, { once: true });
          stream.on('close', () => { opts.abortSignal!.removeEventListener('abort', onAbort); });
        }

        stream.on('data', (data: Buffer) => {
          if (stdout.length < maxOutput) stdout += data.toString();
          if (opts.onProgress && Date.now() - lastProgressSent >= PROGRESS_INTERVAL) {
            lastProgressSent = Date.now();
            let tail = stdout;
            for (let i = 0; i < 3; i++) {
              const idx = tail.lastIndexOf('\n', tail.length - 2);
              if (idx < 0) break;
              tail = tail.substring(idx + 1);
            }
            opts.onProgress(stdout.length, redactText(tail.trim(), { entropyScan: true }));
          }
        });
        stream.stderr.on('data', (data: Buffer) => {
          if (stderr.length < maxOutput) stderr += data.toString();
        });

        stream.on('close', (code: number, signal: string) => {
          this.activeChannels--;
          if (!resolved) {
            resolved = true;
            clearTimeout(timeoutId);
            this.lastActivity = new Date();
            resolve({
              stdout,
              stderr,
              exitCode: code,
              durationMs: Date.now() - startTime,
              profile: this.profile.name,
              signal: signal || undefined,
            });
            span.setAttribute('ssh.exitCode', code);
            if (signal) span.setAttribute('ssh.signal', signal);
            span.end();
          }
        });
      };

      openWithRetry(openExecChannel).then(
        (stream) => onExecChannel(undefined, stream),
        (err: Error) => onExecChannel(err, undefined as unknown as ClientChannel),
      );
    });
  }

  // ─── Sessions (delegated to SessionManager) ──────────────────────────

  async openSession(opts: SessionOpts): Promise<Session> {
    await this.ensureConnected();
    return this.sessions.open(opts);
  }

  getSession(name: string): Session | undefined {
    return this.sessions.get(name);
  }

  listSessions(): Session[] {
    return this.sessions.list();
  }

  async closeSession(name: string): Promise<CloseOutcome> {
    return this.sessions.close(name);
  }

  async reapExpiredSessions(): Promise<void> {
    this.ptySessions.reapExpired();
    return this.sessions.reapExpired();
  }

  // ─── Raw PTY sessions (agent-ssh) ─────────────────────────────────────

  async openPtySession(req: { name: string; cols?: number; rows?: number; term?: string }) {
    await this.ensureConnected();
    const span = tracer.startSpan('pty.session.open');
    span.setAttribute('pty.session', req.name);
    span.setAttribute('ssh.profile', this.profile.name);
    try {
      return await this.ptySessions.open(req);
    } finally {
      span.end();
    }
  }

  readPtySession(name: string, cursor: number, maxChunk: number) {
    return this.ptySessions.read(name, cursor, maxChunk);
  }

  writePtySession(name: string, input: string) {
    return this.ptySessions.write(name, input);
  }

  resizePtySession(name: string, rows: number, cols: number): void {
    return this.ptySessions.resize(name, rows, cols);
  }

  closePtySession(name: string) {
    const span = tracer.startSpan('pty.session.close');
    span.setAttribute('pty.session', name);
    span.setAttribute('ssh.profile', this.profile.name);
    try {
      return this.ptySessions.close(name);
    } finally {
      span.end();
    }
  }

  listPtySessions() {
    return this.ptySessions.list();
  }

  // ─── Port forwarding (agent-ssh) ──────────────────────────────────────

  openForward(req: { mode: 'local' | 'remote' | 'dynamic'; listenHost?: string; listenPort: number; targetHost?: string; targetPort?: number }) {
    const span = tracer.startSpan('forward.open');
    span.setAttribute('forward.mode', req.mode);
    span.setAttribute('forward.listen', `${req.listenHost ?? '127.0.0.1'}:${req.listenPort}`);
    span.setAttribute('ssh.profile', this.profile.name);
    try {
      if (req.mode === 'local') {
        return this.forwards.openLocal({
          listenHost: req.listenHost, listenPort: req.listenPort,
          targetHost: req.targetHost!, targetPort: req.targetPort!,
        });
      }
      if (req.mode === 'remote') {
        return this.forwards.openRemote({
          listenHost: req.listenHost, listenPort: req.listenPort,
          targetHost: req.targetHost!, targetPort: req.targetPort!,
        });
      }
      return this.forwards.openDynamic({ listenHost: req.listenHost, listenPort: req.listenPort });
    } finally {
      span.end();
    }
  }

  listForwards() {
    return this.forwards.list();
  }

  closeForward(id: string) {
    const span = tracer.startSpan('forward.close');
    span.setAttribute('forward.id', id);
    span.setAttribute('ssh.profile', this.profile.name);
    try {
      return this.forwards.close(id);
    } finally {
      span.end();
    }
  }

  async close(): Promise<void> {
    await this.sessions.closeAll();
    await this.ptySessions.closeAll();
    await this.forwards.closeAll();
    if (this.client) {
      this.client.end();
      this.client = null;
    }
    this.connecting = null;
    this.connected = false;
    this.connectedAt = null;
  }

  toInfo(): ConnectionInfo {
    return {
      profile: this.profile.name,
      host: this.profile.host,
      port: this.profile.port,
      user: this.profile.user,
      status: this.isConnected() ? 'connected' : 'closed',
      sessionCount: this.sessions.size,
      activeChannels: this.activeChannels,
      connectedAt: this.connectedAt || undefined,
      lastActivity: this.lastActivity,
    };
  }
}
