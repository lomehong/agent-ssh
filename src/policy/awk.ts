/**
 * 读透一段 awk 程序，足以分类它做什么（#184）。
 *
 * awk 是本代码库无法塞进 INTERPRETERS 表的唯一解释器，
 * 两轮评审产生了五个尝试，每个都被下一个击穿。
 * 两个原因是结构性的，加表加旗标都修不了：
 *
 *
 * 1. **程序是位置操作数，不是旗标的值。** 对 sh -c 或
 *    python3 -c，旗标本身就是解释器被*调用*的证据；
 *    awk 没有，参数列表里没有任何东西区分「跑 awk」和「提 awk」。
 *    以任何含 awk 的词为键，readlink -f /usr/bin/awk 和 man awk
 *    就变成了破坏性。答案是键于片段的*命令词*——
 *    调用方在到达本模块前已经做了这件事。
 * 2. **四种实现对哪些旗标消费一个值意见不一。**
 *    gawk 对 -i 和 -W 消费；mawk 对 -W 消费并拒绝 -i；
 *    busybox 对 -W 消费；BWK awk——macOS/BSD/Debian
 *    original-awk 的 awk——无视未知选项*不消费*，
 *    把下一个操作数当程序跑。跳过 awk 没跳过的词的表
 *    会把数据文件而非程序交给本模块。所以只有四个实现
 *    都同意消费值的三个旗标被跳过——加上两个根本不跑程序的——
 *    其余任何旗标使程序位置不可知，报为 unreadable。
 *
 *
 * 其余是一个小词法分析器。存在的原因是转义序列无法用正则找到：
 * `awk 'NR>1'` 与 `awk '{print $1 > $2}'` 的区别仅在于
 * `>` 是否跟随输出语句——这正是 awk 自己的规则，
 * 也是 print (a>b) 需要括号的原因。五个更早的洞有三个
 * 在试图逼近它的正则里，第四个是逼近所需的二次回溯。
 *
 *
 * 单遍、无回溯：211KB 的重复 print 令牌程序是
 * 抓到二次回溯的种子，已在测试中。
 */

/** What an awk program was found to do. */
export interface AwkFindings {
  /**
    * 程序交给 shell 的 shell 命令——system()、print | "cmd"、
    * "cmd" | getline。返回而非在此分类，让调用方能
    * 重入自己的分类器：awk 'BEGIN{system("sudo id")}' 于是是
    * privileged——它本来的样子——而非笼统的 destructive。
   */
  commands: string[];
  /**
    * 程序把*输出*管道进去的命令——print … | "cmd"。
    *
    * 与 commands 分开是因为方向才是载荷：shell 类比
    * echo "sudo id" | sh 已被 readsProgramFromStdin 设门，
    * 它把命令词是无程序解释器的管道级读作运行前一级打印的东西。
    * 只把 sh 推入 commands 曾把 awk 'BEGIN{print "sudo id" | "sh"}'
    * 归为 safe，因为 sh 本身不危险——危险的是 awk 打进它的内容，
    * 而那不是本模块能知道的。
    *
   */
  pipedInto: string[];
  /** The program writes a file through output redirection. */
  writesFile: boolean;
  /**
    * 程序或程序所在之处无法读取。
    *
    * 「无法判断」而非「这是 root」——与 hasUnreadableProgram
    * 对 python3 -c 的回答相同，且它设审批门而非拒绝。
   */
  unreadable: boolean;
}

/** Command words that run an awk program. `busybox awk` arrives here as `awk`. */
export const AWK_NAMES: ReadonlySet<string> = new Set(['awk', 'gawk', 'mawk', 'nawk']);

/**
 * The only flags all four implementations agree consume a following word.
 *
 * -f 在此是为了*被识别*而非被跟随：它的值是本进程读不到的
 * 程序文件，见到它即以 unreadable 结束读取。
 */
const VALUE_FLAGS = new Set(['-F', '-v', '-f']);

/**
 * The size past which a program is refused rather than read.
 * 选在本模块替代的二次回溯的 211KB 回归种子之上——
 * 该形状仍需被词法分析，代价测试才有意义——
 * 远低于线性遍历仍然成为停滞的大小：1MB 的 system() 调用程序
 * 在服务全部工具调用的单线程上实测 2.1 秒。没有 awk 一行命令
 * 接近这两个数字。
 *
 */
const MAX_PROGRAM_CHARS = 256 * 1024;

/** Flags that take no value and run no program, so `awk --version` stays quiet. */
const INFO_FLAGS = new Set(['--version', '--help']);

/**
 * Redirection targets that are not a file write.
 *
 * print > "/dev/stderr" 是把诊断与输出分离的常见惯用法，
 * 设门会把提示贴到什么都不写的脚本上。
 */
const NON_FILE_TARGETS = new Set(['/dev/stdout', '/dev/stderr', '/dev/null', '/dev/fd/1', '/dev/fd/2']);

/** Fresh object rather than a shared constant: the arrays are ones a caller could push to. */
const unreadable = (): AwkFindings => ({ commands: [], pipedInto: [], writesFile: false, unreadable: true });

type Token =
  | { k: 'word'; v: string }
  | { k: 'num' }
  | { k: 'str'; v: string }
  | { k: 'regex' }
  | { k: 'punct'; v: string }
  | { k: 'nl' };

/** Operators that are two or three characters, longest first so `>>` beats `>`. */
const OPERATORS = [
  // 没有 >>=：awk 根本没有位移运算符——gawk 把位移暴露为
  // lshift()/rshift() 函数，所以没有可赋值的位移。
  // 在 BWK awk 20200816 上验证：x>>=1 是语法错误。**= 是真的。
  '**=',
  '|&', '&&', '||', '==', '!=', '<=', '>=', '>>', '++', '--',
  '+=', '-=', '*=', '/=', '%=', '^=', '!~', '**',
];

/**
 * Operators grouped by first character, so a punctuation token costs one lookup.
 *
 * 扫描过去为每个标点字符切两个新串并对全表跑两个 Array.find。
 * 实测使标点成为词法分析器最贵的输入：比标识符贵 8 倍、
 * 比空白贵 81 倍——而 ?:,~$ 既是最便宜可写的程序又什么都不匹配，
 * 于是在每个字符上都走最慢的路径。
 *
 */
const OPERATORS_BY_FIRST = new Map<string, string[]>();
for (const op of OPERATORS) {
  const bucket = OPERATORS_BY_FIRST.get(op[0]);
  if (bucket) bucket.push(op);
  else OPERATORS_BY_FIRST.set(op[0], [op]);
}

/**
 *
 * 仅保留字。更早版本列了 and、or、not、case、
 * func、getline 和内建函数名，每一个都是洞：POSIX awk、
 * BWK awk、mawk、busybox awk 都不保留它们，于是
 * BEGIN{not=2; x = not / system("sudo id") / 3} 是真实 awk
 * 求值的*除法*——在 BWK awk 20200816 上实测 not 是普通变量，
 * 程序在跑完命令后打印 0.666667。把 / 当正则开符号
 * 会把 system() 调用吞成模式文本，程序归类为 safe。
 *
 * classified `safe`.
 *
 * getline 被排除的镜像理由：它产出值，所以操作数*已经*结束，
 * getline / 2 是除法。
 *
 * 失败方向不对称，所以这份清单很短。
 * 把正则当除法读——区域被读作代码，只会多报；
 * 把代码当正则读——隐藏里面的东西。拿不准时，别列这个词。
 *
 */
const AWK_KEYWORDS = new Set([
  'print', 'printf', 'if', 'while', 'do', 'for', 'return', 'delete',
  'else', 'in', 'BEGIN', 'END', 'function', 'exit', 'next',
]);

/**
 *
 *
 * awk 自己的规则，也是每个 JavaScript 词法分析器需要的同一条：
 * 能结束操作数的东西之后的 / 是除法；其他地方是正则。
 * 弄错两个方向都有影响——awk '/a>b/{print}' 在正则里
 * 藏着 >，awk '{print a/b}' 不能把剩余程序当成一个吞掉。
 *
 */
function regexCanStart(previous: Token | undefined): boolean {
  if (previous === undefined) return true;
  if (previous.k === 'num' || previous.k === 'str' || previous.k === 'regex') return false;
  if (previous.k === 'word') return AWK_KEYWORDS.has(previous.v);
  if (previous.k === 'punct') return ![')', ']', '++', '--', '$'].includes(previous.v);
  return true;
}

const IDENT_START = /[A-Za-z_]/;
const IDENT_PART = /[A-Za-z_0-9]/;
const DIGIT = /[0-9]/;

const SIMPLE_ESCAPES: Record<string, string> = {
  n: '\n'.slice(0), t: '\t', r: '\r',
  '\\': '\\', '"': '"', '/': '/',
  a: '\x07', b: '\b', f: '\f', v: '\v',
};

const OCTAL = /[0-7]/;
const HEX = /[0-9a-fA-F]/;

/**
 * Decode one escape sequence, returning its value and how many source
 *
 *
 * \ddd 和 \xhh 是这里不能用单字符 switch 的原因。每个 awk
 * 都解码它们，它们改变到达 shell 的字节：在 BWK awk 20200816 上实测，
 * awk 'BEGIN{system("\145cho OCTAL_RAN")}' 跑的是 echo，
 * print "\163udo" 打印 sudo。字面读意味着推入 commands 的字符串
 * 不是实际运行的命令，system("\163udo id") 归为 safe——
 * 同样的拼写还溜过了测试原始文本的永不放行清单。
 *
 *
 * \xhh 是 gawk 的，BWK awk 也解码；mawk 不。在不解码的实现上
 * 解码是多报方向——那是该选的失败方向。
 *
 *
 * 其余是字符本身，每个实现都这样处理未知转义。这让
 * FS="\."——极常见的惯用法——不被读成本模块无法建模的东西。
 *
 */
function readEscape(source: string, at: number): { value: string; consumed: number } {
  const c = source[at];
  if (OCTAL.test(c)) {
    let digits = c;
    while (digits.length < 3 && OCTAL.test(source[at + digits.length] ?? '')) {
      digits += source[at + digits.length];
    }
    return { value: String.fromCharCode(parseInt(digits, 8)), consumed: digits.length };
  }
  if (c === 'x' && HEX.test(source[at + 1] ?? '')) {
    let digits = '';
    while (digits.length < 2 && HEX.test(source[at + 1 + digits.length] ?? '')) {
      digits += source[at + 1 + digits.length];
    }
    return { value: String.fromCharCode(parseInt(digits, 16)), consumed: digits.length + 1 };
  }
  return { value: SIMPLE_ESCAPES[c] ?? c, consumed: 1 };
}

/**
 *
 *
 * 未终止的字符串或正则返回 null 而非猜测：剩余程序会在错误的
 * 模式下被词法分析，错误的模式正是 system() 调用藏身的方式。
 * 在那里 fail-closed 是全部意义所在。
 */
function lex(source: string): Token[] | null {
  const tokens: Token[] = [];
  let i = 0;
  const n = source.length;

  while (i < n) {
    const c = source[i];

    if (c === '\n') { tokens.push({ k: 'nl' }); i++; continue; }
    if (c === ' ' || c === '\t' || c === '\r') { i++; continue; }
    // 反斜杠换行是续行：连接各行而非终止语句，
    // 所以不发 nl 令牌。
    if (c === '\\' && source[i + 1] === '\n') { i += 2; continue; }
    if (c === '#') { while (i < n && source[i] !== '\n') i++; continue; }

    if (c === '"') {
      let value = '';
      i++;
      while (i < n && source[i] !== '"') {
        if (source[i] === '\\') {
          if (i + 1 >= n) return null;
          const escape = readEscape(source, i + 1);
          value += escape.value;
          i += 1 + escape.consumed;
          continue;
        }
        // 字符串内的裸换行不是合法 awk，当作合法会让
        // 剩余程序被读作字符串内容。
        if (source[i] === '\n') return null;
        value += source[i];
        i++;
      }
      if (i >= n) return null;
      i++;
      tokens.push({ k: 'str', v: value });
      continue;
    }

    if (c === '/' && regexCanStart(tokens[tokens.length - 1])) {
      i++;
      let inBracket = false;
      while (i < n) {
        const r = source[i];
        if (r === '\\') { i += 2; continue; }
        if (r === '\n') return null;
        // 方括号表达式内的 / 是字面量——/[/]/ 是匹配斜杠的合法
        // 正则，在那里结束令牌会让剩余程序被读作
        // 实际是模式文本的代码。
        if (r === '[') inBracket = true;
        else if (r === ']') inBracket = false;
        else if (r === '/' && !inBracket) break;
        i++;
      }
      if (i >= n) return null;
      i++;
      tokens.push({ k: 'regex' });
      continue;
    }

    if (DIGIT.test(c) || (c === '.' && DIGIT.test(source[i + 1] ?? ''))) {
      while (i < n && /[0-9.eExXa-fA-F+-]/.test(source[i])) {
        // 1e+5 继续，1+5 是两个令牌加一个运算符。
        if ((source[i] === '+' || source[i] === '-') && !/[eE]/.test(source[i - 1] ?? '')) break;
        i++;
      }
      tokens.push({ k: 'num' });
      continue;
    }

    if (IDENT_START.test(c)) {
      const start = i;
      while (i < n && IDENT_PART.test(source[i])) i++;
      tokens.push({ k: 'word', v: source.slice(start, i) });
      continue;
    }

    const candidates = OPERATORS_BY_FIRST.get(c);
    const op = candidates?.find((o) => source.startsWith(o, i));
    if (op !== undefined) { tokens.push({ k: 'punct', v: op }); i += op.length; continue; }

    tokens.push({ k: 'punct', v: c });
    i++;
  }

  return tokens;
}

/**
 * Walk the tokens and record what the program does.
 *
 * 输出语句状态是这需要解析器而非扫描器的全部原因：
 * > 只在未加括号的 print/printf 参数列表打开时才是重定向，
 * 这就是 awk 'NR>1' 做比较而
 * awk '{print $1 > $2}' 做写入的原因。
 */
function walk(tokens: Token[]): AwkFindings {
  const commands: string[] = [];
  const pipedInto: string[] = [];
  let writesFile = false;
  let unreadable = false;

  let depth = 0;
  /** Paren depth at which an output statement is open; -1 when none is. */
  let printDepth = -1;

  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];

    if (t.k === 'punct') {
      if (t.v === '(' || t.v === '[') { depth++; continue; }
      if (t.v === ')' || t.v === ']') {
        depth--;
        if (printDepth >= 0 && depth < printDepth) printDepth = -1;
        continue;
      }
      // 语句边界关闭任何打开的输出语句。
      if (t.v === '{' || t.v === '}' || t.v === ';') { printDepth = -1; continue; }

      // gawk 的间接调用（f="system"; @f("sudo id")）和 @load /
      // @include 指令。@ 到达的东西在运行时选择或在别的文件里，
      // 从这里都读不到。
      if (t.v === '@') { unreadable = true; continue; }

      if (printDepth >= 0 && depth === printDepth) {
        if (t.v === '>' || t.v === '>>') {
          const target = tokens[i + 1];
          // 字面目标可识别为终端；计算的则是文件写，名字未知，
          // 但仍是文件写。
          //
          if (!(target?.k === 'str' && NON_FILE_TARGETS.has(target.v))) writesFile = true;
          printDepth = -1;
          continue;
        }
        if (t.v === '|' || t.v === '|&') {
          // 单一字面量，无拼接。awk 将相邻字符串连接为
          // 运行的命令，只读第一个分类了比实际执行的
          // *更短的*命令——本模块中唯一可能降低而非提升类别的形状。
          // 实测：print "x" | "id" "; sudo sh" 落为 safe。
          //
          const target = tokens[i + 1];
          const after = tokens[i + 2];
          if (target?.k === 'str' && after?.k !== 'str' && after?.k !== 'word') {
            pipedInto.push(target.v);
          } else {
            unreadable = true;
          }
          printDepth = -1;
          continue;
        }
      }

      // "cmd" | getline 在任何输出语句之外运行命令，
      // 所以在这里读而非在上方块中。
      if (t.v === '|' || t.v === '|&') {
        const after = tokens[i + 1];
        if (after?.k === 'word' && after.v === 'getline') {
          const before = tokens[i - 1];
          const earlier = tokens[i - 2];
          // 与上方 print 管道相同的单字面量规则："sudo" " id" |
          // getline 跑的是 sudo id，只读最后一个字面量归类为
          //  id。
          if (before?.k === 'str' && earlier?.k !== 'str' && earlier?.k !== 'word') {
            commands.push(before.v);
          } else {
            unreadable = true;
          }
        }
      }
      continue;
    }

    if (t.k === 'nl') { printDepth = -1; continue; }

    if (t.k === 'word') {
      if (t.v === 'print' || t.v === 'printf') { printDepth = depth; continue; }
      if (t.v === 'system') {
        const open = tokens[i + 1];
        if (open?.k !== 'punct' || open.v !== '(') continue;
        const arg = tokens[i + 2];
        const close = tokens[i + 3];
        // 只有单一字符串字面量可读。system("rm " f) 是运行时
        // 拼装文本的真实 shell 命令，猜测比说无法读取更糟。
        //
        if (arg?.k === 'str' && close?.k === 'punct' && close.v === ')') commands.push(arg.v);
        else unreadable = true;
        continue;
      }
    }
  }

  return { commands, pipedInto, writesFile, unreadable };
}

/**
 *
 *
 * args 是命令词之后的词，已被调用方的分词器去引号。
 * 调用完全不跑程序时返回 null——裸 awk 或 awk --version——
 * 这不等同于在其中没发现危险。
 *
 */
export function readAwkInvocation(args: readonly string[]): AwkFindings | null {
  let i = 0;
  while (i < args.length) {
    const word = args[i];

    if (word === '--') { i++; break; }
    // 裸 - 是作为数据文件的 stdin，不是旗标。
    if (word === '-' || !word.startsWith('-')) break;
    if (INFO_FLAGS.has(word)) { i++; continue; }

    const flag = word.slice(0, 2);
    if (VALUE_FLAGS.has(flag)) {
      // -f prog.awk 把程序放进本进程读不到的文件，
      // -f- 从 stdin 读，同样不可读。
      if (flag === '-f') return unreadable();
      // 分离值（-F ':'）消费下一个词；附着的（-F:）不消费。
      i += word.length === 2 ? 2 : 1;
      continue;
    }

    // 其余旗标：见模块注释。实现对是否消费下一个词意见不一，
    // 哪个操作数是程序从此不可知，猜测正是五洞中两洞的来路。
    //
    return unreadable();
  }

  const program = args[i];
  if (program === undefined) return null;

  // 词法分析前有界。单次调用成本是线性的，但对无界输入的线性
  // 在服务全部工具调用的单线程上仍是停滞：commandMaxChars = 0——
  // 配置中不限的写法——时，1MB 的 system() 调用程序实测 2.1 秒。
  // 默认 5000 字符上限使其不可达；提高它的运维得到提示而非暂停，
  // 正是本模块对「无法读取」已给出的回答。
  //
  if (program.length > MAX_PROGRAM_CHARS) return unreadable();

  const tokens = lex(program);
  if (tokens === null) return unreadable();
  return walk(tokens);
}
