/**
 * 判定一个 reader 的参数是否可证明为数据，而非更多命令。
 *
 * 分类器中的 `READERS` 给任何首词在白名单上的命令授予 `read-only`，
 * 而不看其后的词。这之所以安全，只是因为后一阶段会拒绝 shell
 * 元字符，但 `cat -- "$x"` 与 `cat $(id)` 今天都能过那道闸；
 * 在「白名单 reader」与「并非数据的参数」之间，只剩外层 shell 控制
 * 扫描（或调用方自己的审计）把守。本模块就是为那些旗标简单到
 * 可用文法描述的 reader 补上这一缺口的部件：给它命令名之后的
 * argv 词与一份该二进制接受什么的描述，它回答每个词是否为本
 * 文法认可的选项、某选项消费的值，或满足 `operands` 形状的操作数。
 * 这里没有任何东西决定*类别*——那仍是调用方的职责，
 * 连同设计文档中的正确性条件（可选参数旗标绝不进 `valueFlags`；
 * 某选项仅在命令名可解析到的每个实现都以同样方式读它时才列出）。
 *
 * 纯函数、无副作用：不碰文件系统、不 import `classifier.ts`。
 * 把它接进命令类别的表是后续任务。
 * way).
 *
 * Pure and side-effect free: no filesystem, no `classifier.ts` import. The
 * table that wires this into a command's class is a later task.
 */

/**
 * 一个 reader 参数文法长什么样。
 *
 * `'any'` 让 reader 完全跳过本匹配器——其参数经其他手段
 * 信任为数据，且必须有 `audit`，让这种信任无法在不说明
 * 查过哪些实现、发现了什么的情况下被断言。
 *
 *
 * `flags` 不取值；`valueFlags` 必取一个；`optionalValueFlags` 模拟
 * getopt 的可选参数（`::`），绝不消费下一个词。短条目自带
 * 短横（`'-n'`），长条目两者都带（`'--since'`）——匹配器不增删
 * 短横，写错的文法就什么都匹配不上。同一个名字出现在 `flags`、
 * `valueFlags` 与 `optionalValueFlags` 中多个清单的，所有路径都拒绝。
 *
 */
export type ArgGrammar =
  | { args: 'any'; audit: string }
  | {
      args: 'getopt' | 'exact';
      flags?: readonly string[];
      valueFlags?: readonly string[];
      optionalValueFlags?: readonly string[]; // 值可选：绝不消费下一个词
      numericShort?: boolean;           // 仅 getopt：接受 -<数字>（git -<n>）
      optionsBeforeOperands?: boolean;  // 首个操作数之后拒绝看似选项的词
      operands?: {
        max?: number;
        first?: readonly string[];
        each?: RegExp;
      };
    };

/** {@link ArgGrammar} 非 `'any'` 臂所携带的操作数形状。 */
type OperandRules = NonNullable<Extract<ArgGrammar, { args: 'getopt' | 'exact' }>['operands']>;

/**
 * `ok: true`，或 `ok: false` 附带匹配器不肯接受的第一个词——
 * 被选项消费的值也算被接受，因此绝不会出现在这里。
 * 值旗标后无值可吃时，`word` 是那个旗标，而非它前面的词。
 * 操作数计数、`first` 或 `each` 违规时，`word` 是出问题的操作数。
 * 后续任务会把它变成拒绝文案，所以返回的是词本身——
 * 不只是一个布尔。
 * is what this returns.
 */
type MatchResult = { ok: true } | { ok: false; word: string };

/**
 * `words` 里的每个词是否都出自 `grammar` 的描述？
 *
 * 扫描逐词、自左向右，与 getopt（或 `exact` 时该二进制自己的
 * 手写解析器）实际读 argv 的方式一致：孤立的 `-` 永远是操作数
 * （stdin），选项剥离后剩下的每个词都对照 `operands` 检查。
 * `--` 仅在 `getopt` 下终止其后所有词的选项解析——`exact` 解析器
 * 在 `--` 之后仍继续评估它的选项词（实测：GNU `find -- d -fprint /tmp/x`
 * 写出了文件），因此在 exact 下 `--` 作为未识别词被拒，
 * 而不是当作检查终点。
 * than treated as end-of-checks.
 */
export function matchesGrammar(words: readonly string[], grammar: ArgGrammar): MatchResult {
  if (grammar.args === 'any') {
    return { ok: true };
  }

  const flags = new Set(grammar.flags ?? []);
  const valueFlags = new Set(grammar.valueFlags ?? []);
  const optionalValueFlags = new Set(grammar.optionalValueFlags ?? []);
  const operands: string[] = [];
  let optionsEnded = false;

  for (let i = 0; i < words.length; i++) {
    const word = words[i];

    // 孤立的 ’-’ 是 stdin，不是选项——且一旦见过 ’--’，
    // 再没有任何词看起来像选项。
    const looksLikeOption = !optionsEnded && word.length > 1 && word.startsWith('-');

    // POSIX 选项顺序，按条目选择加入——并刻意排在下方 getopt `--`
    // 分支之前：`--` 本身就是个看似选项的词，而不重排的实现
    // （macOS uniq 的 `+` 前缀 optstring、BSD ifconfig）在第一个
    // 操作数处就已停止选项扫描，于是把 `--` 读作操作数——
    // uniq 的操作数是它要覆盖的 OUTFILE（一个字面名为 `--` 的文件），
    // ifconfig 的则是一个接口配置词。会重排的实现（GNU）会把同一个
    // 词当作它拼写的终止符，所以这个词无法对两者一概而论：
    // `optionsBeforeOperands` 拒绝它，仅「存在不重排实现」的条目
    // 才设置该标志。
    //
    if (grammar.optionsBeforeOperands && operands.length > 0 && looksLikeOption) {
      return { ok: false, word };
    }

    // 仅 getopt。`exact` 解析器从不赋予 `--` 这个含义：find 在它之后
    // 仍继续读 primaries，若在那里接受 `--`，检查恰好终止在
    // 攻击者最能藏身的那个词上。
    if (grammar.args === 'getopt' && !optionsEnded && word === '--') {
      optionsEnded = true; // 其后每个词都是操作数，-- 本身不是
      continue;
    }

    if (!looksLikeOption) {
      operands.push(word);
      continue;
    }

    // git 的 `-<n>` 版本数上限（`-20`）：整词数字，在任何簇或长选项
    // 解析看到它之前，作为无值选项接受。
    // `-2x` 非全数字，落进下方的簇路径，
    // 除非字符被列出，否则被拒。仅 getopt 风格。
    //
    // 显式条目永远压过这条捷径，但只有前导 `-<数字>` *字符*
    // 生效：下方的簇解析器按 getopt 的方式逐字符读，
    // 从不整词读。因此只列 `-20` 的条目并不能让 `-20` 通过——
    // 捷径退位（该词「已被显式列出」），簇解析器接着拒绝它，
    // 除非 `-2` 也被列出。fail-closed，
    // 这对一个二进制根本不会那样读的条目是正确的失败方式。
    // 这里同样拒绝歧义，与其他路径一致——
    // 否则调用方列进多个清单的名字会经这条捷径被静默接受，
    // 而不是被抓住。
    //
    if (grammar.args === 'getopt' && grammar.numericShort && /^-\d+$/.test(word)) {
      const shortChar = word.slice(0, 2); // 首字符为 - 加首个数字
      if (
        isAmbiguousName(word, flags, valueFlags, optionalValueFlags) ||
        isAmbiguousName(shortChar, flags, valueFlags, optionalValueFlags)
      ) {
        return { ok: false, word };
      }
      const explicitlyListed =
        flags.has(word) ||
        valueFlags.has(word) ||
        optionalValueFlags.has(word) ||
        flags.has(shortChar) ||
        valueFlags.has(shortChar) ||
        optionalValueFlags.has(shortChar);
      if (!explicitlyListed) {
        continue; // 无显式条目认领该数字——走数字捷径
      }
      // 显式条目认领了本词或其前导数字字符：
      // 落到下方普通的短簇解析，由它正确应用
      //（包括为 `valueFlags` 条目消费独立的值词，
      // 这是本捷径绝不可做的事）。
    }

    if (grammar.args === 'getopt' && !word.startsWith('--')) {
      // 短簇：按 getopt 的方式逐字符读。
      const cluster = matchShortCluster(word, words, i, flags, valueFlags, optionalValueFlags);
      if (!cluster.ok) return cluster;
      i = cluster.nextIndex; // for 循环自身的 i++ 随即落在下一个未读词上
      continue;
    }

    // 长选项（getopt）或任何 ’-’ 前缀词（exact——没有独立的短簇
    // 路径，所以 ’-n’ 也在这里检查）。
    // 仅 getopt 把 ’=值’ 从名字上拆下；exact 按原始词匹配，
    // 因此 ’--name=值’ 只有整串被列出才匹配。
    const eqIndex = grammar.args === 'getopt' ? word.indexOf('=') : -1;
    const name = eqIndex === -1 ? word : word.slice(0, eqIndex);

    // 同时出现在三个清单中的名字是文法 bug，
    // 不是匹配器能替二进制做的判断——接受它就得选边
    // （它取值、取可选值，还是不取？），选错正是正确性条件
    // 警告的那个洞。宁拒不猜。
    //
    if (isAmbiguousName(name, flags, valueFlags, optionalValueFlags)) {
      return { ok: false, word };
    }

    if (valueFlags.has(name)) {
      if (eqIndex !== -1) {
        continue; // --name=值：值已附带，无需再消费
      }
      if (i + 1 >= words.length) {
        return { ok: false, word: name }; // 值旗标后无值
      }
      i++; // 消费下一个词作为值
      continue;
    }

    if (optionalValueFlags.has(name)) {
      // 裸旗标，或（getopt）值已通过上方 `name`/`eqIndex` 附在同一词上的
      // ’--name=值’。两者都无需再消费，
      // 且绝不触碰下一个词。
      continue;
    }

    if (flags.has(name) && eqIndex === -1) {
      continue; // 无值旗标绝不接受附带的 =值
    }

    return { ok: false, word };
  }

  return checkOperands(operands, grammar.operands);
}

/**
 * `name` 同时出现在三个选项清单中的两个以上时为真——
 * 正确性条件要求所有路径都拒绝的歧义。
 */
function isAmbiguousName(
  name: string,
  flags: ReadonlySet<string>,
  valueFlags: ReadonlySet<string>,
  optionalValueFlags: ReadonlySet<string>,
): boolean {
  const inFlags = flags.has(name);
  const inValueFlags = valueFlags.has(name);
  const inOptionalValueFlags = optionalValueFlags.has(name);
  return (
    (inFlags && inValueFlags) || (inFlags && inOptionalValueFlags) || (inValueFlags && inOptionalValueFlags)
  );
}

/**
 * 逐字符读取一个 getopt 风格的短选项簇（`-rn5`）。
 * `flags` 字符继续扫描；`valueFlags` 字符取该词其余部分为值、
 * 其余为空则取下一个词；`optionalValueFlags` 字符在该词有余部时
 * 取其余部分为值、绝不取下一个词，无论哪种都结束本词扫描；
 * 其余任何字符拒绝整个簇。
 *
 * 返回外层循环自身 `i++` 应落过的下标——值已附带、可选或无值可取时
 * 不变，仅当必值旗标消费了下一个词时为 `index + 1`。
 *
 *
 */
function matchShortCluster(
  word: string,
  words: readonly string[],
  index: number,
  flags: ReadonlySet<string>,
  valueFlags: ReadonlySet<string>,
  optionalValueFlags: ReadonlySet<string>,
): { ok: true; nextIndex: number } | { ok: false; word: string } {
  for (let c = 1; c < word.length; c++) {
    const ch = '-' + word[c];
    // 与长/exact 路径相同的歧义拒绝，且先查：出现在多个清单的
    // 字符在这里也被拒，而不是被静默当作属于其中某一个
    //（长/exact 路径同样不会这样处理）。
    //
    if (isAmbiguousName(ch, flags, valueFlags, optionalValueFlags)) return { ok: false, word };
    if (flags.has(ch)) continue;
    if (valueFlags.has(ch)) {
      const rest = word.slice(c + 1);
      if (rest.length > 0) return { ok: true, nextIndex: index };
      if (index + 1 >= words.length) return { ok: false, word: ch };
      return { ok: true, nextIndex: index + 1 };
    }
    if (optionalValueFlags.has(ch)) {
      // 该词的余部（若有）即本选项的值；无论如何本词扫描到此结束，
      // 且绝不消费下一个词。
      return { ok: true, nextIndex: index };
    }
    return { ok: false, word };
  }
  return { ok: true, nextIndex: index };
}

/**
 * 把对 `words` 一轮扫描收集到的操作数对照 `rules` 检查。
 * `first` 只对照 `operands[0]`——完全没有操作数的 reader
 * 无从违反它——`each` 对照每个操作数，`max` 最后查，
 * 因为超预算是整份清单的性质，不是任何一个词的。
 *
 */
function checkOperands(operands: readonly string[], rules: OperandRules | undefined): MatchResult {
  if (!rules) return { ok: true };

  for (let i = 0; i < operands.length; i++) {
    const operand = operands[i];
    if (i === 0 && rules.first && !rules.first.includes(operand)) {
      return { ok: false, word: operand };
    }
    if (rules.each) {
      // 调用方的 /g 或 /y 正则让 RegExp#test 带状态：lastIndex
      // 会从上一次调用延续，不在每次测试前重置的话，
      // 前一个操作数的匹配位置会泄入下一个——把应拒的操作数
      // 放进来，或相反。每次测试前重置，让每个操作数都被新鲜检查，
      // 正如普通（非粘性、非全局）模式天然的行为。
      //
      rules.each.lastIndex = 0;
      if (!rules.each.test(operand)) {
        return { ok: false, word: operand };
      }
    }
  }

  if (rules.max !== undefined) {
    // 不是非负整数的 `max`（NaN、1.5、-1……）无法与计数安全比较：
    // `length > NaN` 恒为假，等于接受任意数量的操作数，
    // 而小数 max 会从操作数数组不存在的下标读出 undefined。
    // 把任何此类值当作最严苛的界——在一个无法被检查的限制下，
    // 没有任何操作数是安全放行的——而不是让畸形的文法条目
    // 接受（或静默少报）无界操作数。
    //
    //
    const validMax = Number.isInteger(rules.max) && rules.max >= 0;
    const limit = validMax ? rules.max : 0;
    if (operands.length > limit) {
      return { ok: false, word: operands[limit] };
    }
  }

  return { ok: true };
}
