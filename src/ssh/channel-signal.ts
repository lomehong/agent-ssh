import type { ClientChannel } from 'ssh2';

/**
 * 停掉一条跑在 exec 通道后的命令——要可靠，而 ssh2 自带的 signal()
 * 在 stdin 关闭后就不可靠了。
 *
 * SSHConnection.exec() 在命令派发后立即关闭 stdin，
 * 否则读 stdin 的命令会等待永远不会到来的输入。ssh2 1.17 的
 * Channel.signal()（lib/Channel.js:237）只在以下条件成立时写入请求：
 *
 *     this.type === 'session' && this.writable && this.outgoing.state === 'open'
 *
 * 而 end() 清掉了后两个：触发 prefinish/finish，ssh2 的 onFinish
 * 监听器（lib/Channel.js:268）调用 eof()——outgoing 状态变为 eof——
 * 并设 writable = false。它不抛异常也不报告——只是返回。
 * 于是每一条要停掉超时命令的信号都在 ssh2 内部被丢弃，
 * 命令在主机上继续跑到完成，调用方却被「已超时」。
 *
 *
 * 对照 OpenSSH 10.3p1 实测，每行一条通道，以 30 秒 sleep 为目标：
 *
 *   end() 后 INT/TERM/close()          +4 秒仍活，+9 秒仍活
 *   不 end()，INT/TERM                 +4 秒前消失
 *   end() 后仅 close()                 +9 秒仍活
 *   eof() 后 INT/TERM                  +9 秒仍活
 *   end() 后走下方的协议调用            +4 秒前消失
 *
 * 由此得出两件事。送达的信号是停掉非 tty 命令的*唯一*手段——
 * 关通道不行，与本机 ssh host sleep 30 杀掉后 sleep 仍跑同理。
 * 而报告者提议的 end() 到 eof() 改动自身无效，eof 过不了
 * ssh2 的门，跟 writable === false 一样；只有配合
 * mscdex/ssh2#1510（放宽该门以接受 eof）才有效。
 * mscdex/ssh2#1510, which relaxes the gate to accept `'eof'`.
 *
 * 与其等它（ssh2 约一年一版——1.16.0 到 1.17.0 用了十一个月），
 * 本模块经 ssh2 自己的方法本会使用的协议对象发送请求。SSH 协议
 * 允许 EOF 后的通道请求：EOF 结束的是数据流，不是通道。
 * 反对的只有 ssh2 的簿记。
 *
 * 退役这条回退路径是一次代码变更，不会自动发生。公共路径由下方
 * ssh2WillSend 把守——它刻意照抄 ssh2 1.17 的条件——所以即使
 * mscdex/ssh2#1510 发布了，我们自己的副本仍然拒绝，回退路径
 * 继续在热路径上，直到有人放宽它。ssh2WillSend 是唯一要改的
 * 地方，channel-signal.test.ts 中的行为绊线会在 ssh2 开始在 EOF 后
 * 送信号的那一刻失败——那就是该改的信号。本注释的更早版本声称
 * 回退路径会自行不再被走到；它不会，一个永远打不响的计划
 * 比没有计划更糟。
 *
 * 送达的请求能达到什么效果是*服务器*的选择，不是我们的。OpenSSH
 * 以对命令进程组执行 killpg() 来响应 signal 通道请求
 *（session.c 的 session_signal_req），因此普通进程树确实会死——
 * 对照 10.3p1 实测：sh -c trap INT TERM sleep N true 与其子进程
 * 共享一个 pgid，一次 KILL 请求后两者都消失。
 *
 * 本注释的更早版本声称相反——信号只到达会话首进程、子进程被遗留。
 * 那是错的，所谓的「孤儿」是更早实验泄漏的残渣而非结果。
 * 记录这个错误，因为它曾以*低估*爆炸半径的方向
 * 写进 SECURITY.md——对 SIGKILL 而言，那是更糟的错法。
 *
 *
 * 但这些都不是我们能承诺的。RFC 4254 §6.9 未规定送达语义，
 * sshd 对 forced-command 与 subsystem 会话拒绝信号请求，
 * 本项目刻意支持第二种服务器实现（Dropbear）。也没有任何东西
 * 确认请求——所以下方返回值只关于派发，这里不声称进程已死。
 * dispatch and nothing here claims the process is gone.
 */

/** ssh2 未放进公共类型定义的通道部件。 */
type ChannelInternals = {
  type?: string;
  writable?: boolean;
  outgoing?: { id?: number; state?: string };
  _client?: {
    _protocol?: { signal?: (id: number, name: string) => void };
    /** ssh2 drops any write to this silently once it is unwritable; see `onTheWire`. */
    _sock?: { writable?: boolean; _readableState?: { ended?: boolean } };
  };
};

/** 本模块发送的信号。强类型化，ssh2 拒收的名字即编译错误。 */
export type SignalName = 'INT' | 'TERM' | 'KILL';

/** 远端仍有通道可接收请求的 outgoing 状态。 */
const OPEN_STATES = new Set(['open', 'eof']);

/**
 * ssh2 自己的 Channel.signal() 会不会把该请求送上线路？
 *
 * 对 ssh2 1.17 lib/Channel.js:241-243 的刻意照抄，也是该处变化时
 * 唯一要更新的地方。照抄它让我们能区分「ssh2 会处理」与
 * 「ssh2 会静默丢弃」——正是本模块存在的意义。
 */
function ssh2WillSend(ch: ClientChannel & ChannelInternals): boolean {
  return ch.type === 'session' && ch.writable === true && ch.outgoing?.state === 'open';
}

/**
 * Whether the transport can still carry a packet.
 *
 * ssh2 把每个包交给 onWrite，即 if (isWritable(sock)) sock.write(data)
 *（lib/client.js:303）——不可写的套接字意味着包被丢弃，无错误
 * 无返回值。对照 1.17.0 实测：client.end() 之后立刻，
 * sock.writable 为 false 而 outgoing.state 仍是 eof，
 * 下方状态守卫通过、信号调用不抛异常即返回。把它报告为已送达
 * 就是 #146 往下一层，且只要连接在命令运行中被关闭就可触发——
 * SSHConnection.close()，或不查 activeChannels 的空闲回收器。
 * `activeChannels`.
 *
 * isWritable 的三个条件全用，不只第一个。第一版只查
 * sock.writable，ssh2 加上另两个是有原因的
 *（nodejs/node#36029：流结束后 writable 仍为 true）。实测：
 *
 *   allowHalfOpen=false, peer FIN -> writable=false, isWritable()=false   （一致）
 *   allowHalfOpen=true,  peer FIN -> writable=true,  isWritable()=false   （不一致）
 *
 * ProxyJump 连接的传输恰好是第二种——connectConfig.sock
 * 是一条 forwardOut 通道，ssh2 的通道默认 allowHalfOpen: true
 *（lib/Channel.js:90）。所以单条件版本在自己的集成测试所走的
 * 路径上是瞎的。照抄整个判断也是 ssh2WillSend 的做法，
 * 两者的不对称才是真正的缺陷。
 */
function onTheWire(ch: ClientChannel & ChannelInternals): boolean {
  const sock = ch._client?._sock;
  // 对读不懂的形状 fail-closed：本模块中一切其他未知都报
  // 「未派发」，职责是「不确定就拒」的守卫不能是
  // 唯一往好处想的地方。
  if (sock === undefined || typeof sock.writable !== 'boolean') return false;
  return sock.writable && sock._readableState?.ended === false;
}

/**
 * Send `name` to the process behind `channel`.
 *
 * 返回请求是否**已派发到线路**——不是命令是否停止。SSH 中
 * 没有任何东西确认信号请求，送达语义是服务器而非协议的选择，
 * 目标也可以直接拒绝，所以「进程已死」不是本函数能产出的事实。
 * 它能诚实产出的是「我连问都没问成」——调用方正是就此告警，
 * 因为报成功却哪儿也没到的信号，就是本模块要消灭的缺陷。
 * signal that goes nowhere while reporting success is the defect this module exists to
 * remove.
 */
export function signalChannel(channel: ClientChannel, name: SignalName): boolean {
  const ch = channel as ClientChannel & ChannelInternals;
  const state = ch.outgoing?.state;

  // 只有 session 通道承载进程。ssh2 也以此设门，
  // forwarded-tcpip 通道没有可发信号的东西。
  if (ch.type !== undefined && ch.type !== 'session') return false;
  // 已在关闭或已关闭：请求没有可到达的通道，
  // 且 ssh2 可能已把 id 分给新通道。
  if (state !== undefined && !OPEN_STATES.has(state)) return false;
  // ssh2 不会写入的套接字上什么也派发不了，而且它不会告诉我们——
  // 所以必须在任一路径声称成功之前先问这一步。
  if (!onTheWire(ch)) return false;

  // 支持的路径：ssh2 确实会写入请求时走这条。
  if (ssh2WillSend(ch)) {
    try {
      channel.signal(name);
      return true;
    } catch {
      return false;
    }
  }

  const id = ch.outgoing?.id;
  const protocol = ch._client?._protocol;
  if (typeof id === 'number' && typeof protocol?.signal === 'function') {
    try {
      protocol.signal(id, name);
      return true;
    } catch {
      return false;
    }
  }

  // 不认识的形状。照样问 ssh2、照样报失败：我们无法分辨
  // 它是否发了什么，声称无法验证的送达正是这个 bug
  // 长期隐形的原因。多一句「可能仍在运行」的告警
  // 是更好的错法。
  try { channel.signal(name); } catch { /* nothing left to try */ }
  return false;
}

/**
 * 停止请求连派发都没做到时追加——主机什么都没被问到。
 * host at all.
 *
 * 刻意比「命令仍在运行」窄，后者从这里不可知：
 * 没有任何东西确认信号请求。它的*缺席*因此意味着「我们问了」，
 * 而不是「它死了」。
 *
 * 它放在决定它的函数旁边，因为现在有两个调用方需要同一句话——
 * 超时或取消的 exec，以及对后台会话的 close-session。
 * 一份契约，一个地方。
 */
export const COULD_NOT_SIGNAL =
  ' The remote command could not be signalled, so it may still be running on the host.';

/** 每个信号在被下一个尝试前的等待时间。 */
const ESCALATION_MS = 1000;

/**
 * 升级直到命令消失：INT，然后 TERM，然后 KILL，然后丢通道。
 * channel.
 * KILL 放最后因为它剥夺命令清理的机会；它存在是因为
 * 下一级原来是 close()，而实测关通道停不了任何东西。
 * 无视 INT 和 TERM 的命令过去会永远跑下去。
 *
 *
 * 返回*第一条*信号是否已派发——同步可知，调用方因此能在报告
 * 超时的同时说「我连问都没问成」。它不是「命令已停」的断言，
 * 调用方不得如此解读：后续级别还没跑，也没有任何级别被确认。
 *
 */
export function terminateChannel(channel: ClientChannel): boolean {
  const dispatched = signalChannel(channel, 'INT');

  const pending: NodeJS.Timeout[] = [];
  const later = (fn: () => void, ms: number) => {
    // 不引用：本阶梯比它已结算的 promise 多活至多三秒，
    // 引用型计时器会把这段时间加到任何以超时命令为
    // 最后一件事的进程的退出上。
    pending.push(setTimeout(fn, ms).unref());
  };

  const stop = () => { for (const t of pending) clearTimeout(t); pending.length = 0; };
  // 通道没了就没什么可发的了，且 id 可能已被复用。
  channel.once('close', stop);

  later(() => { signalChannel(channel, 'TERM'); }, ESCALATION_MS);
  later(() => { signalChannel(channel, 'KILL'); }, ESCALATION_MS * 2);
  later(() => { try { channel.close(); } catch { /* already gone */ } }, ESCALATION_MS * 3);

  return dispatched;
}

/**
 * Wait for a channel to actually close, bounded.
 * 阶梯的各级是计时器，terminateChannel 远在升级完成之前就返回了。
 * 之后再拆传输——SSHConnection.close() 调 client.end()，或进程退出——
 * 会取消剩余部分，无视 INT 的命令就这样活着、再无升级可能。
 * 即将这么做的调用方必须先在这里等。
 *
 * 通道关闭则 resolve true，超时为 false。默认预算是阶梯
 * 加一点余量，只死于 KILL 的命令也赶得上。
 *
 *
 */
export function waitForChannelClose(
  channel: ClientChannel,
  ms: number = ESCALATION_MS * 3 + 500,
): Promise<boolean> {
  // ssh2 恰好发一次 close，且 onCHANNEL_CLOSE 对 incoming 已是
  // closed 的通道提前返回——事后挂的监听器永不触发，
  // 调用方会烧完整个预算等一个已发生的事件。今天经 SessionManager
  // 不可达，因为同一次 emit 就把会话从 map 移除了；
  // 这是给下一个调用方的陷阱。
  const incoming = (channel as ClientChannel & { incoming?: { state?: string } }).incoming;
  if (incoming?.state === 'closed' || channel.destroyed) return Promise.resolve(true);

  return new Promise((resolve) => {
    let settled = false;
    const onClose = () => done(true);
    const done = (closed: boolean) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      // 超时路径上也摘除：否则超时的等待会把它的闭包
      // 留在一条可能比它活得更久的通道上。
      channel.removeListener('close', onClose);
      resolve(closed);
    };
    const timer = setTimeout(() => done(false), ms);
    // 不引用，挂死的通道无法扣住进程；调用方在 await 本 promise，
    // 循环只要调用方自己活着就活着。
    timer.unref();
    channel.once('close', onClose);
  });
}
