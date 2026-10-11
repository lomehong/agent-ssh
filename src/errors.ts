import { writeSync } from 'fs';
import { inspect } from 'util';

/**
 * 因调用或配置方式而起的服务器错误，有别于服务器自身的缺陷。
 * defect in it.
 *
 * 这条区分存在，是因为两者需要*以不同方式呈现*。过去 `main()` 把一切失败
 * 交给 `console.error('Fatal error:', error)`，打印出完整 Error 对象——
 * 名称、消息与堆栈。于是缺一个 `--host` 到达运维眼前的，
 * 是穿过 `buildAppConfig` 与 `main` 的堆栈，读起来像崩溃。我们为他们写的
 * 三行解释被埋在只有调试本代码库的人才需要的帧里。#138 的报告者
 * 贴出来的第一段就是这个，
 * 而其中没有一字指向他真正的问题。
 * pasted, and none of it pointed at their actual problem.
 *
 * 下面的 `reportFatal` 是这条规则的另一半，放在这里而不是 CLI 入口，
 * 为的是推理只写一遍，单测无需导入一个一导入就起服务器的模块
 * 也能够到它。
 *
 * 名字用 operator 而非 user，因为在本代码库里 "user" 指的是
 * 命令在其下运行的 SSH 账户；这里说的是启动服务器的人。
 *
 * 范围：传输连接建立之前 `main()` 可达的任何 throw 都应是
 * OperatorError，而 `reportFatal` 是该 promise 唯一的读取者。
 * `getProfile` 对不存在的 profile 名也会抛一个，工具调用可能在请求时
 * 触发——那时消息经 MCP error 到达客户端而非 `reportFatal`，
 * 但措辞面向的是同一类读者。
 * written for the same audience either way.
 */
export class OperatorError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'OperatorError';
  }
}

/**
 * 我们查找的路径上没有配置文件。
 *
 * 与其他一切配置失败分开，因为它是唯一未必是问题的情形：
 * 没有配置文件时，`--host`/`--user` 接管。
 * `buildAppConfig` 曾用裸 `catch {}` 表达这一点，而它同时吞掉了
 * 「文件在但不可用」——TOML 畸形、schema 违规、权限失败——
 * 把它们统统报成 "No config file found"。
 *
 * 这正是 #138 无从发现的原因。一位 Windows 运维把合法配置放在
 * 正确位置，却被告知文件不存在，而真正的错误（一个在 Windows 上
 * 永远通不过的权限检查）被未读即弃。
 *
 * 信号是类型而非消息文本，因此对措辞的无关改动
 * 无法扩大这条落空路径。
 */
export class ConfigNotFoundError extends OperatorError {
  /**
    * 保留原因：`loadConfig(customPath)` 过去对缺失文件以 Node 自带的
    * SystemError 拒绝，其 `.code` 可被观察。本仓库无人读它，
    * 但包装脚本可能会读；保留它只花一行。
   * it costs one line.
   */
  readonly code = 'ENOENT';

  constructor(public readonly configPath: string) {
    super(
      `No config file found at ${configPath}. Create one or use --config <path>. ` +
      'See documentation for the TOML schema.',
    );
    this.name = 'ConfigNotFoundError';
  }
}

/**
 * 什么都没配置：无配置文件，命令行也没有 `--host`/`--user`。
 *
 * 之所以是独立类型而非裸 `OperatorError`，理由同 `ConfigNotFoundError`——
 * 两层必须就这一状态达成一致，却不必共享同一字符串。`cli.ts` 把它
 * 作为启动告警打印、服务器继续运行；`ConnectionRegistry` 则在
 * 每次工具调用时抛它。读者不同、通道不同，一处措辞的改动
 * 不得悄悄破坏另一处的匹配。
 *
 * 路径是构造参数而非消息内嵌 `getConfigPath()` 调用，
 * 本文件因此不依赖配置层，文本也无需 stub `os.platform()`
 * 即可测试。
 */
export class UnconfiguredError extends OperatorError {
  constructor(public readonly configPath: string) {
    super(
      'No config file found and missing required --host/--user.\n' +
      `Either create a config file at ${configPath} or pass --config <path>.\n` +
      'For quick start: --host=<host> --user=<user> (credentials via env vars).',
    );
    this.name = 'UnconfiguredError';
  }
}

/** 运维错误的退出码，监督程序可据此与崩溃区分。 */
export const EXIT_OPERATOR_ERROR = 2;
/** 其余一切的退出码。 */
export const EXIT_DEFECT = 1;

/**
 * 一次失败如何到达运维。
 *
 * OperatorError 关于的是服务器如何被调用或配置，因此其消息
 * 就是全部答案。其余一切保留堆栈，因为对真正的缺陷而言，
 * 堆栈才是值得要的部分——这同时让堆栈成为信号：
 * 有堆栈即「这是我们的问题，请上报」。
 *
 * 返回退出码而不直接调 `process.exit`，让规则的两侧
 * 无需拉起进程即可测试。
 */
export function reportFatal(
  error: unknown,
  log: (...args: unknown[]) => void = writeStderr,
): number {
  if (error instanceof OperatorError) {
    log(error.message);
    return EXIT_OPERATOR_ERROR;
  }
  log('Fatal error:', error);
  return EXIT_DEFECT;
}

/**
 * 默认汇：对文件描述符 2 的同步写入。
 *
 * 不用 `console.error`，因为调用方下一行就调 `process.exit`。
 * Node 对 stderr 的写入对文件是同步的，对 Linux 与 Windows 的管道也是——
 * 但**对 macOS 的管道是异步的**，而 stdio 传输下 stderr *正是*
 * 一条归 MCP 客户端所有的管道。于是在 macOS 上，这次改动本要送达的
 * 消息可能被排队、再被退出截断，运维只落得一个断连和一个退出码。
 * CI 跑在 Linux（管道同步）上，所以任何测试都抓不到它。
 * Linux, where the pipe is synchronous, so no test would have caught it.
 */
function writeStderr(...args: unknown[]): void {
  let line = '';
  try {
    // 放在 try 内：`util.inspect` 抓不住会抛异常的
    // `[util.inspect.custom]`，于是格式化可能在「报告异常」时自己抛异常，
    // 以未处理 rejection 的形式逃出 main() 的 catch，什么都没打印。
    line = args.map((a) => (typeof a === 'string' ? a : inspect(a))).join(' ');
    writeSync(2, `${line}\n`);
  } catch {
    // 非阻塞管道的 EAGAIN，或已关闭的 fd。丢一行总好过
    // 在报告异常时再抛一个异常。
    console.error(line || `Fatal error: <unprintable ${typeof args[args.length - 1]}>`);
  }
}
