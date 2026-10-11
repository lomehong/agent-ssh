import type { CommandClass, ParsedCommand } from '../types.js';
import { AWK_NAMES, readAwkInvocation, type AwkFindings } from './awk.js';
import { matchesGrammar, type ArgGrammar } from './reader-grammar.js';

/**
 * shell 经其启动第二条命令的任何东西。
 *
 * 此门决定白名单中的二进制是否算只读，
 * 白名单只为二进制背书——从不为 shell 可能顺带跑的东西。
 * 过去测 /[>;|]/，使 ls $(touch /tmp/x) 以只读通过：
 * ls 在白名单、无列出的元字符出现，而远端 shell 仍展开替换、
 * 跑内部命令（GHSA-r8hm-vpm8-cfh6）。
 *
 *
 * 列举每个危险构造是输定的游戏——$()、反引号、<(...)、
 * ${x:=...}、&&、裸换行——所以这里改为拒绝一切对 shell
 * 有语法意义的字符，且 $ 整体拒绝而非仅 $(。
 * 代价是 echo $HOME 不再被归类只读。
 * 对整个承诺是「不能写」的工具这是正确的取舍：
 * run-command 在策略下仍接受它。
 */
const SHELL_CONTROL_CHARS = /[;&|<>`$(){}\n\r]/;

/**
 * 主机 shell 如何读反斜杠。
 *
 * posix：反斜杠转义下一字符——双引号内仅 $、反引号、双引号、
 * 反斜杠本身或换行。windows：反斜杠处处是普通字符，
 * 即 cmd.exe 的规则；shell 层完全无反斜杠转义。
 *
 *
 * 分类器无法知道连接远端是什么 shell，含反斜杠的命令
 * 因此按两种方言读取并取更严格的读法（GHSA-972x-g47g-3922）。
 *
 */
type ShellDialect = 'posix' | 'windows';

/**
 * command 中第一个携带未引号、未转义 shell 通配字符——
 * 星号、问号或左方括号——的词，无则 null。
 *
 * 通配字符不是 shell 控制字符（它不开启命令），
 * SHELL_CONTROL_CHARS 正确地忽略它——但主机 shell 在二进制
 * 看到 argv 之前展开它，文法匹配器读去引号的词，
 * find -name 加引号与不加引号的同一字符串已无分别。
 * 它们不是同一命令：带引号的词是一个数据操作数，
 * 不带引号的展开为每个匹配文件名，把一个计数操作数
 * 变成多个真实的（uniq 加通配路径只计一个操作数；
 * debian:12 实测：展开使 .pub 成为 uniq 的 OUTFILE，
 * 被私钥覆写）。此扫描保留分词器自己的引号与转义状态，
 * 判断因此发生在仍能区分两者的唯一一层。
 *
 *
 * 刻意词域且全命令：$() 或反引号内的通配永远到不了
 * 本助手的调用方（那些携带 SHELL_CONTROL_CHARS 并提前返回），
 * 命令词本身的通配使白名单查找 miss，所以调用方——
 * 只在命令词精确匹配 READERS 键时才运行的白名单分支——
 * 也看不到。
 *
 */
function firstUnquotedGlobWord(command: string, honorQuotes = true, dialect: ShellDialect = 'posix'): string | null {
  let quote: string | null = null;
  let escaped = false;
  let word = '';
  let globInWord = false;

  for (const ch of command) {
    if (escaped) {
      // 反斜杠引出的通配字符是 shell 原样传递的数据。
      word += ch;
      escaped = false;
      continue;
    }
    if (quote) {
      // 反斜杠在单引号内是字面量；双引号内转义——
      // 与分词器的区分相同。
      if (dialect === 'posix' && ch === '\\' && quote === '"') { escaped = true; continue; }
      if (ch === quote) quote = null;
      else word += ch;
      continue;
    }
    if (dialect === 'posix' && ch === '\\') { escaped = true; continue; }
    if (honorQuotes && (ch === '"' || ch === "'")) { quote = ch; continue; }
    if (/\s/.test(ch)) {
      if (globInWord) return word;
      word = '';
      globInWord = false;
      continue;
    }
    if (ch === '*' || ch === '?' || ch === '[') globInWord = true;
    word += ch;
  }

  // 末尾留开的引号不是 shell 会跑的命令，分词器把这样的串
  // 以引号降级为文本重读（见 tokenizeSegmentsDetailed）。
  // 此处同样判断：那个读法里通配字符是未引号的。
  //
  if (honorQuotes && quote !== null) return firstUnquotedGlobWord(command, false, dialect);
  return globInWord ? word : null;
}

/**
 *
 *
 * 三个问题，分开是因为一个回答全部的 Set 正是 #217 如何
 * 通过把两个动词加进关于类别的列表、把解释器载体扫描
 * 对两个动词关掉的方式：
 *
 *   readOnly         此二进制只读吗？  -> 决定类别
 *   operandsAreData  其操作数能藏命令吗？  -> 决定载体扫描是否运行
 *   grammar          matchesGrammar 接受哪些 argv 词？  ->
 *                    决定 read-only 还是 safe
 *
 *
 * 今天每个条目 readOnly 和 operandsAreData 都是 true。
 * 价值不在内容而在类型不允许下一个人不加回答全部三个
 * 就添加名字。
 *
 * grammar 只决定那一个边界，不直接决定类别：文法拒绝的命令
 * 落得不比 safe 低，且 DISQUALIFYING_ARGS 仍在白名单分支之前运行，
 * 所以它仍能把一个被拒的——或被接受的——读者抬过 safe
 *（sort -o /tmp/x /etc/passwd 无论 sort 的文法说什么都是 destructive）。
 * any 文法接受每个词，携带 audit 字符串说明为何相信该信任可靠；
 * 其余每个条目列出其文法接受的旗标和操作数形状，且从零开始
 *——见 reader-grammar.ts。
 *
 *
 * 两个机制在此表之外回答第二个问题且不受其影响——
 * DISQUALIFYING_ARGS 和 FIND_EXEC_FLAGS——这正是 find 能携带
 * operandsAreData: true 而 find 后接 exec sudo id 仍是 privileged
 * 的原因。
 *
 * 双词条目只为类别查找：operandsAreData 读单词，
 * 所以那些行永远到不了第二个问题。其 grammar 读双词前缀之后的词
 *（classifyOuter 应用偏移）。
 */
const READERS: Record<string, { readOnly: boolean; operandsAreData: boolean; grammar: ArgGrammar }> = {
  // arp：-a、-e、-n、-v 仅显示；-H、-t（硬件类型）和 -i
  // (interface) filter the display, not set anything. Excludes `-d` (deletes an
  // entry), `-s`/`-S` (adds one — BSD man synopsis) and `-f` (loads entries from
  // a file — net-tools arp(8)). Measured: busybox --help + `arp -a`; macOS man
  // arp read; net-tools arp(8) documented only (die.net). Windows 11 build
  // 26200 measurement: `arp.exe` accepts the slash form (`/a` measured),
  // /d、/s 被推断（不运行——改变状态的形态绝不执行以确认）为
  // 删除/添加。/X 开关在此 POSIX 文法下是操作数，
  // 与 /etc 这样的路径无法区分；each 拒绝任何单词 /word 操作数，
  // 尾斜杠有无皆然（见设计的 Windows 节）——
  // arp /d/ 风格形态的尾斜杠容忍度无法在不运行改变状态的
  // 形态的情况下测量，所以 fail-closed 拒绝。代价是合法的
  // 斜杠形式显示 arp /a 也落到 safe。
  //
  "arp":              { readOnly: true, operandsAreData: true, grammar: { args: 'getopt',
    flags: ['-a', '-e', '-n', '-v'],
    valueFlags: ['-H', '-t', '-i'],
    operands: { max: 1, each: /^(?!\/[^/]*\/?$)/ } } },
  "basename":         { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured GNU/BSD: pure string manipulation of its argument; no filesystem access at all' } },
  "cat":              { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: "measured GNU/busybox/BSD: writes file contents to stdout; BSD's -l is a transient advisory lock on cat's own stdout fd, not a lasting write, and clears at exit" } },
  "comm":             { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured GNU/BSD: compares two sorted files and prints the differences; no output-file operand or flag' } },
  "cut":              { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: "measured GNU/BSD: extracts byte/field ranges to stdout; --output-delimiter only changes what's printed, not where" } },
  // date：-u/--utc/--universal 与 -R/--rfc-2822/--rfc-email 仅改
  // 显示格式；-r/--reference 读文件的 mtime（GNU）或 epoch 值（BSD）；
  // --rfc-3339 选显示格式；-v（BSD）只显示调整后的时间（man 称
  // 并未真的设置）。-I/--iso-8601 是可选值（getopt 的双冒号）：
  // 它在 optionalValueFlags 里列出，所以裸 -I/--iso-8601 或附着形态
  //（-Iseconds、--iso-8601=date）保持只读——匹配器只是从不把后续
  // 分离词当它的值消费。裸 +FMT 操作数被接受（max 1，each 匹配加号）；
  // 排除 -s/--set（设置时钟）、-d/--date（GNU/busybox 同样只读
  // 但在 BSD 历史上设置内核 DST 标志——实现分歧故排除）
  // 与 BSD 专有 -D、-f、-j、-n。实测：GNU d12+trixie --help、
  // busybox（date -d 2020-01-01 显示）、macOS man；FreeBSD date(1) 仅文档。
  //
  // `-D`/`-f`/`-j`/`-n`. Measured: GNU d12+trixie --help, busybox (`date -d
  // 2020-01-01` displayed), macOS man; FreeBSD date(1) documented only.
  "date":             { readOnly: true, operandsAreData: true, grammar: { args: 'getopt',
    flags: ['-u', '--utc', '--universal', '-R', '--rfc-2822', '--rfc-email'],
    valueFlags: ['-r', '--reference', '--rfc-3339', '-v'],
    optionalValueFlags: ['-I', '--iso-8601'],
    operands: { max: 1, each: /^\+/ } } },
  "df":               { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured GNU/busybox/BSD: reports space usage read from mounted filesystems; --output= selects columns to print, not a file' } },
  // diff：仅比较/输出格式旗标，加读取或匹配的值旗标
  //（-D/--ifdef 合并到 stdout 而非文件）。-C/-U 是必值
  //（valueFlags）——GNU、BSD、busybox 都收带计数的短形态，
  // 附着或分离词；仅长拼写 --context/--unified/--color 是可选值
  //（optionalValueFlags：裸或等号值，绝非分离词）。从设计轮的
  // any 猜测移来：-l/--paginate 把输出经 /usr/bin/pr 管道——
  // debian:12 实测：移除 /usr/bin/pr 后变成「找不到辅程序」，
  // 且无论 PATH 如何都跑绝对路径，所以是排除而非列出。实测：
  // GNU --help（d12+trixie 3.10）与 -l 行为；BSD man（也有 -l）；
  // busybox --help（无 -l）。
  //
  // --help (d12 + trixie 3.10) and the -l behaviour; BSD man (also has -l);
  // busybox --help (no -l).
  "diff":             { readOnly: true, operandsAreData: true, grammar: { args: 'getopt',
    flags: ['-q', '--brief', '-s', '--report-identical-files', '-c', '-u', '-e', '--ed', '-n', '--rcs',
      '-y', '--side-by-side', '--left-column', '--suppress-common-lines', '-p', '--show-c-function',
      '-t', '--expand-tabs', '-T', '--initial-tab', '--suppress-blank-empty', '-r', '--recursive',
      '--no-dereference', '-N', '--new-file', '--unidirectional-new-file', '--ignore-file-name-case',
      '--no-ignore-file-name-case', '-i', '--ignore-case', '-E', '--ignore-tab-expansion', '-b',
      '--ignore-space-change', '-w', '--ignore-all-space', '-B', '--ignore-blank-lines', '-a', '--text',
      '--strip-trailing-cr', '-d', '--minimal'],
    valueFlags: ['-C', '-U', '-W', '--width', '--tabsize', '-F', '--show-function-line', '-I',
      '--ignore-matching-lines', '-D', '--ifdef', '--label', '-x', '--exclude', '-X', '--exclude-from',
      '-S', '--starting-file', '--from-file', '--to-file', '--line-format'],
    optionalValueFlags: ['--context', '--unified', '--color'],
    operands: { max: 2 } } },
  "dig":              { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured BIND 9.10.6 (BSD): sends a DNS query and prints the answer; writes nothing locally (DNS egress tracked separately)' } },
  "dirname":          { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured GNU/BSD: pure string manipulation of its argument; no filesystem access at all' } },
  "docker images":    { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured docker CLI 29.7.2 --help: lists local images from the daemon; every option only changes what is listed, no state change' } },  // two-word: class only
  "docker inspect":   { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: "measured docker CLI 29.7.2 --help: prints low-level JSON about an object; no state change" } },  // two-word: class only
  "docker logs":      { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: "measured docker CLI 29.7.2 --help: prints a container's captured output; no state change" } },  // two-word: class only
  "docker ps":        { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured docker CLI 29.7.2 --help: lists containers; no state change' } },  // two-word: class only
  "docker stats":     { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured docker CLI 29.7.2 --help: streams live resource-usage numbers; no state change' } },  // two-word: class only
  "du":               { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured GNU/busybox/BSD: walks a directory tree and reports disk usage; no write mode' } },
  "echo":             { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured GNU/BSD: writes its arguments to stdout only; a file write needs shell redirection, which the outer gate already refuses' } },
  "false":            { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured GNU: exits 1 immediately; no I/O of any kind' } },
  // file：显示/格式旗标，加指名读什么的值旗标（文件列表、magic 库、
  // 排除项）。排除 -C/--compile，**实测会写**：本机 macOS file 5.41 上
  // file -C -m /usr/share/file/magic/magic 在临时目录创建了 magic.mgc
  //（2256 字节）。GNU 仅文档（file(1) die.net 5.04：-C 是唯一创建文件的选项）——
  // 每个实测镜像中都无 GNU file（见 spec 问题 3）。也排除 -z/-Z
  //（解压/解压不报告——audit.md 列为无值）：libmagic 在未针对匹配
  // 解压库构建时可能运行外部解压器（文档化未实测；契约禁止执行
  // 另一程序），所以即使 audit.md 自己的逐条表有它们也保持排除。
  // 本集合无可选值选项；-p/--preserve-date 作为不必要而非不安全排除。
  //
  // 契约禁止执行另一程序），所以即使 audit.md 自己的逐条表有它们也保持排除。
  // 本集合无可选值选项；-p/--preserve-date 作为不必要而非不安全排除。
  //
  // unnecessary rather than unsafe.
  "file":             { readOnly: true, operandsAreData: true, grammar: { args: 'getopt',
    flags: ['-b', '--brief', '-c', '--checking-printout', '-i', '--mime', '--mime-type', '--mime-encoding',
      '-k', '--keep-going', '-L', '--dereference', '-h', '--no-dereference', '-n', '--no-buffer',
      '-r', '--raw', '-s', '--special-files', '-0', '--print0'],
    valueFlags: ['-f', '--files-from', '-m', '--magic-file', '-M', '-e', '--exclude', '-F', '--separator'] } },
  // find：exact，因为 find 自己解析谓词而非经 getopt，且不识别
  // 聚簇或缩写——实测 find . -exe 报「未知谓词 -exe」。无值谓词/运算符
  // 加读取元数据用于测试的值谓词；-printf 写 stdout 而非文件
  //（写文件的兄弟 -fprintf 被排除，见下）。排除写/执行家族——
  // -delete、-exec 等见下。
  //
  // -execdir、-ok、-okdir（也先被 DISQUALIFYING_ARGS 抓住）、
  // -fprint、-fprint0、-fprintf、-fls（写文件）——以及少量
  // 只读但不必要的谓词，留出而非穷尽列出（-files0-from、
  // -quit、-prune、-fstype、-newerXY、-regextype、-D）。无操作数规则：
  // 起始路径和括号作为操作数透传，设计轮对 Windows find.exe 的
  // 测量发现它只读，所以此处无需 each 规则。实测：GNU d12 --help；
  // busybox（find /tmp/t -name 加通配 -type f 跑了；busybox find
  // 无 -ls/-printf，自身拒绝它们，fail-closed）；BSD man。
  //
  // itself, fail-closed); BSD man.
  "find":             { readOnly: true, operandsAreData: true, grammar: { args: 'exact',
    flags: ['-H', '-L', '-P', '-print', '-print0', '-ls', '-not', '-a', '-and', '-o', '-or', '-true', '-false',
      '-empty', '-xdev', '-mount', '-depth', '-daystart', '-executable', '-readable', '-writable'],
    valueFlags: ['-name', '-iname', '-path', '-ipath', '-wholename', '-iwholename', '-regex', '-iregex',
      '-type', '-perm', '-user', '-group', '-uid', '-gid', '-size', '-mtime', '-mmin', '-atime', '-amin',
      '-ctime', '-cmin', '-newer', '-anewer', '-cnewer', '-links', '-inum', '-maxdepth', '-mindepth',
      '-printf'] } },
  "free":             { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured busybox; documented (procps free(1)): reports memory usage parsed from /proc; every option only changes units or format' } },
  // git branch：列表/显示旗标加排除在 valueFlags 之外的可选值旗标
  //（规则 1；--contains HEAD 的操作数无论如何被 max 0 拒绝——接受的代价）。
  // --sort=键 是唯一必值旗标。max 0 排除操作数形式：裸 git branch NAME
  // 会*创建*分支（实测 refs/heads/side 被创建），所以这里无操作数预算
  // 是安全的。排除 -d/-D（删除；git branch -D main 在本轮别处实测）、
  // -m/-M（移动/改名——两者都需要操作数，已被 max 0 挡住）
  // 和 --edit-description（打开编辑器）。实测：macOS git 2.55.0。
  //
  // `--edit-description` (opens an editor). Measured: git 2.55.0 on macOS
  // (`git branch side` + `git for-each-ref`; `--help`).
  "git branch":       { readOnly: true, operandsAreData: true, grammar: { args: 'getopt',
    flags: ['-a', '--all', '-r', '--remotes', '-v', '--verbose', '-q', '--quiet', '--list', '--show-current'],
    valueFlags: ['--sort'],
    optionalValueFlags: ['--color', '--contains', '--merged', '--no-merged'],
    operands: { max: 0 } } },
  // git diff：显示/格式旗标，加 -M/--find-renames、-C/--find-copies、
  // -U/--unified、--color、--word-diff 和 --stat 为可选值
  //（optionalValueFlags）：-U5 和 --unified=5 都保持只读（附着值没问题）；
  // 只有后续分离词从不被当值消费，这正是无值的 -u 仍然存在的原因。
  // --diff-filter、-S、-G、-O 都是读或搜索，从不写。无操作数规则（修订/路径）。
  // 排除 --output——**实测会写**：草稿 checkout 上 git diff --output=diffout.txt
  // 创建了 93 字节文件（设计轮只有文档）。实测：git 2.55.0。
  //
  // scratch checkout, `git diff --output=diffout.txt` created a 93-byte file
  // (the design round had this only as documented). Measured: git 2.55.0.
  "git diff":         { readOnly: true, operandsAreData: true, grammar: { args: 'getopt',
    flags: ['-p', '-u', '--patch', '--name-only', '--name-status', '--cached', '--staged', '--raw', '-w',
      '--ignore-all-space', '-b', '--ignore-space-change', '--summary', '--shortstat', '--exit-code',
      '--quiet', '-R', '--no-color', '--first-parent'],
    valueFlags: ['--diff-filter', '-S', '-G', '-O'],
    optionalValueFlags: ['-M', '--find-renames', '-C', '--find-copies', '-U', '--unified', '--color',
      '--word-diff', '--stat'] } },
  // git log：显示/格式旗标，加排除在 valueFlags 之外的可选值旗标（规则 1）。
  // 无操作数规则（修订/路径，含 -- 之后的任何东西）。排除 --output——
  // **实测会写**：草稿 checkout 上 git log --output=out.txt HEAD 创建了
  // 113 字节文件（.git/index 不变）。需要 numericShort: true，因为语料库
  // 需要 git log --oneline -20：git 自己的 -<n> 修订上限快捷方式被真 getopt
  // 逐字符扫描，没有任何 flags/valueFlags 条目能点名 -20 这个词本身——
  // 这正是设计轮审计要求的匹配器能力，对 git show 同样无害。
  // 实测：git 2.55.0（调用了 git log --oneline；index 不变）。
  //
  // show` too. Measured: git 2.55.0 (`git log --oneline` called; index
  // unchanged).
  "git log":          { readOnly: true, operandsAreData: true, grammar: { args: 'getopt',
    flags: ['--oneline', '--graph', '--all', '-p', '-u', '--patch', '--name-only', '--name-status',
      '--abbrev-commit', '--relative-date', '--reverse', '--topo-order', '--date-order', '--parents',
      '--merges', '--no-merges'],
    valueFlags: ['-n', '--max-count', '--since', '--until', '--author', '--grep', '--date', '-S', '-G',
      '--skip'],
    optionalValueFlags: ['--pretty', '--format', '--decorate', '--branches', '--tags', '--remotes',
      '--stat', '-L'],
    numericShort: true } },
  // git remote：-v/--verbose 和两个 verbose 相邻的无值旗标仅显示。
  // first get-url、max 2——裸 git remote 和 git remote -v 都合法（0 操作数）。
  // show 被终审从 first 移除：git remote show 加 URL 接受 URL
  // 的原因（实测 git 2.55.0）：它对调用方选择的目标跑 ssh 或
  // git-remote-助手，所以该子命令被排除，查看者失去 git remote show origin
  //（已定价的代价）。排除 add（写 config——实测 git remote add 把
  // remote origin 段写进 .git/config）、rename、remove/rm、set-url、
  // set-head（全写）、prune（删远程跟踪引用）和 update（fetch——改引用）。
  // 实测：git 2.55.0。
  //
  // refs). Measured: git 2.55.0.
  "git remote":       { readOnly: true, operandsAreData: true, grammar: { args: 'getopt',
    flags: ['-v', '--verbose', '-n', '--push'],
    operands: { max: 2, first: ['get-url'] } } },
  // git show：显示/格式旗标，加 --pretty、--format、--decorate、--stat
  // 为可选值（optionalValueFlags：裸或等号值，后续分离词从不消费），
  // --date 为唯一必值旗标。无操作数规则（HEAD、commit、tag 等）。
  // 排除 --output——与 git log/git diff 相同的写已被实测，同一选项家族。
  // numericShort: true 为 git log 需要的同一个 -<n> 快捷方式（git show -3）。
  // 实测：git 2.55.0（兄弟 --output 写本轮重新实测）。
  //
  // re-measured this round).
  "git show":         { readOnly: true, operandsAreData: true, grammar: { args: 'getopt',
    flags: ['-s', '--no-patch', '--name-only', '--name-status', '--oneline', '--abbrev-commit', '--raw'],
    valueFlags: ['--date'],
    optionalValueFlags: ['--pretty', '--format', '--decorate', '--stat'],
    numericShort: true } },
  "git status":       { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured git 2.55.0: opportunistically refreshes cached stat data in .git/index when stale; writes no content, ref or config; host can disable via GIT_OPTIONAL_LOCKS=0' } },  // two-word: class only
  "grep":             { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured GNU/busybox/BSD: searches input for a pattern and prints matches; no option writes a file or runs a program' } },
  "head":             { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured GNU/busybox/BSD: prints the first lines of a file; no write mode' } },
  "host":             { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured BIND 9.10.6 (BSD): sends a DNS query and prints the answer; writes nothing locally (DNS egress tracked separately)' } },
  // hostname：仅显示旗标，无值旗标。operands max 0——裸 hostname NAME
  // 在每个实现上都*设置*主机名（GNU --help 用法行、busybox 用法、BSD man），
  // 所以零以上的操作数预算都不安全。排除 -F/--file（从文件设置）、
  // -b/--boot（无配置时设默认主机名——GNU --help）和 -y/--yp/--nis
  //（经操作数设 NIS 域，max 0 已拒绝——作为不必要而非不安全留出）。
  // 实测：GNU hostname 3.21/3.25 --help；busybox（hostname -s）；macOS man。
  //
  // GNU hostname 3.21/3.25 --help; busybox (`hostname -s`); macOS man (`[-f]
  // [-s | -d]`).
  "hostname":         { readOnly: true, operandsAreData: true, grammar: { args: 'getopt',
    flags: ['-a', '--alias', '-A', '--all-fqdns', '-d', '--domain', '-f', '--fqdn', '--long', '-i',
      '--ip-address', '-I', '--all-ip-addresses', '-s', '--short'],
    operands: { max: 0 } } },
  "htop":             { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: "documented (htop(1) + FILES section, 2.x/3.x): no CLI option writes or executes; kill/renice are interactive keys (F7/F8/F9), unreachable by a read-only caller; ~/.config/htop/htoprc is written only after an interactive Setup change on clean exit; not measured — htop is absent from every image and from macOS" } },
  "id":               { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: "measured GNU/BSD: prints the caller's uid/gid/groups; no write mode" } },
  // ifconfig：仅显示旗标/过滤器（BSD 的 -l -m -d -u -v -L -r -C 格式化列表），
  // 加一个 BSD 输出格式值旗标。operands max 1——裸 ifconfig eth0 只*显示*
  // 该接口状态；第二个操作数（地址、up/down、netmask、hw、mtu、add/del、
  // destroy 等）会配置它并被拒。optionsBeforeOperands: true（终审修复）：
  // BSD ifconfig 只在接口操作数之前读选项，macOS 接受之后的同样字母
  // 作为接口设置——ifconfig en0 -av/-dad 会从本文法列出的字母改设置——
  // 所以操作数之后看似选项的词被拒而非当作列出的旗标读取。实测：
  // busybox --help 加 ifconfig -a（用法行 [-a] [IFACE] [ADDRESS]——
  // ADDRESS 之后的一切都是写）；BSD man 概要；net-tools ifconfig(8) 仅文档。
  //
  // `ifconfig -a` (usage line is `[-a] [IFACE] [ADDRESS]` — everything from
  // ADDRESS on is a write); BSD man synopsis; net-tools ifconfig(8) documented
  // only ("Otherwise, it configures the interface").
  "ifconfig":         { readOnly: true, operandsAreData: true, grammar: { args: 'getopt',
    flags: ['-a', '-s', '-l', '-m', '-d', '-u', '-v', '-L', '-r', '-C'],
    valueFlags: ['-f'],
    optionsBeforeOperands: true,
    operands: { max: 1 } } },
  "iostat":           { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured busybox; documented (sysstat iostat(1)): reports kernel I/O statistics; no write mode' } },
  // ip addr：完全无选项——像 -4/-6/-o 这样的全局旗标在双词前缀之前，
  // 所以 ip -4 addr show 根本到不了双词匹配、被可见地拒绝（接受的代价）。
  // first show/list：add/del/flush 不能是第一个操作数；show/list 之后，
  // dev eth0、to 前缀、label、scope 等操作数自由，裸 ip addr 合法（空 first）。
  // 缩写（ip a、ip ad sh）GNU 有文档但此处拒绝，因为文法要求完整双词——
  // 接受的代价。实测：busybox（ip addr show、ip addr list、裸 ip addr 都跑了）；
  // GNU ip(8) 仅文档（man7：show 或 list）。
  //
  // addr list`, bare `ip addr` all ran); GNU ip(8) documented only (man7: "show
  // (or list)").
  "ip addr":          { readOnly: true, operandsAreData: true, grammar: { args: 'exact', operands: { first: ['show', 'list'] } } },  // two-word: class only
  // ip route：first 含 show/list/get——get 地址是只读
  // 查询（ip-route(8)：实际不发包）。排除 add、del、change、append、
  // replace、flush、restore（全写）和 save（转储到 stdout，
  // 但其兄弟 restore 写，所以动词对整体留出而非拆分）。实测：
  // busybox（ip route list、ip route show 跑了；ip route get 10.0.0.1
  // 查询未写）；GNU ip(8)+ip-route(8) 仅文档。
  //
  "ip route":         { readOnly: true, operandsAreData: true, grammar: { args: 'exact', operands: { first: ['show', 'list', 'get'] } } },  // two-word: class only
  // journalctl：显示/过滤旗标，加 -n/--lines、-b/--boot 和 --facility
  // 为可选值（optionalValueFlags；journalctl(1)：参数可省略）——
  // 裸词或附着形态（-b1、--boot=2）保持只读，但匹配器从不把后续
  // 分离词当值消费，所以 -b 加 -1 仍在未识别的 -1 上拒绝（接受的代价，
  // 不声称每个附着拼写都被拒）。无操作数规则（单元名/匹配模式——读）。
  // 排除归档变更家族——--vacuum-time/--vacuum-size（删归档日志；
  // --vacuum-time=1s 在本轮别处实测破坏性）、--rotate（也实测过）、
  // --flush/--sync/--relinquish-var（重定向守护进程磁盘写）、
  // --setup-keys（生成 FSS 密钥）和 --verify/--verify-key/--root
  //（作为不必要留出）。完全仅文档——journalctl(1)（man7，systemd 262 开发版）——
  // journalctl 在每个实测镜像和 macOS 中都缺席。
  //
  // and `--verify`/`--verify-key`/`--root` (left out as unnecessary). Entirely
  // documented only — journalctl(1) (man7, systemd 262~devel) — journalctl is
  // absent from every measured image and from macOS.
  "journalctl":       { readOnly: true, operandsAreData: true, grammar: { args: 'getopt',
    flags: ['-f', '--follow', '-e', '--pager-end', '-r', '--reverse', '-k', '--dmesg', '-q', '--quiet',
      '-x', '--catalog', '-a', '--all', '-l', '--full', '-m', '--merge', '--no-pager', '--no-hostname',
      '--no-tail', '--disk-usage', '--header', '--list-boots', '--system', '--user'],
    valueFlags: ['-u', '--unit', '--since', '--until', '-S', '-U', '-o', '--output', '-p', '--priority',
      '-g', '--grep', '-t', '--identifier', '-D', '--directory'],
    optionalValueFlags: ['-n', '--lines', '-b', '--boot', '--facility'] } },
  "ls":               { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured GNU/busybox/BSD: lists directory entries; no write mode' } },
  // netstat：台账修正——从设计轮的 any 猜测移为文法；audit.md 主表
  // 仍记录此条目为 any（每个选项都是显示）。修正理由（progress.md 台账）：
  // FreeBSD netstat(1) 文档化 -z 重置计数器（文档化未实测——排除，
  // 非下列列出），-p 放在 flags 而非 valueFlags，因为它在 BSD/Windows
  // 取值而在 net-tools（Linux）不取——列为必值旗标会在不取值的
  // 实现上强制消费下一个词。-f/-I 是可选值（optionalValueFlags）。
  // 无需操作数规则。实测：busybox 加 BSD（netstat -rn 等）；net-tools
  // netstat(8) 对超出实测集合的部分仅文档。
  //
  // needed. Measured: busybox + BSD (`netstat -rn`, etc.); net-tools
  // netstat(8) documented only for anything beyond the measured set.
  "netstat":          { readOnly: true, operandsAreData: true, grammar: { args: 'getopt',
    flags: ['-a', '-n', '-t', '-u', '-l', '-p', '-r', '-i', '-s', '-e', '-W', '-x', '-w', '-4', '-6',
      '-v', '-b', '-d', '-m'],
    optionalValueFlags: ['-f', '-I'] } },
  "nslookup":         { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured busybox/BSD: sends a DNS query; interactive mode does nothing beyond querying, and interactive input is unreachable by design (out of scope)' } },
  "ping":             { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured busybox; documented (BSD man): sends ICMP echo requests and prints replies; writes nothing locally (ICMP egress tracked separately)' } },
  "printenv":         { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured GNU/BSD: prints environment variables; no write mode' } },
  "printf":           { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured GNU/BSD: writes formatted text to stdout only; a file write needs shell redirection, which the outer gate already refuses' } },
  "ps":               { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: "measured busybox; documented (procps ps(1): 'works by reading /proc'): lists processes; no write mode" } },
  "pwd":              { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured GNU/BSD: prints the working directory; no write mode' } },
  "readlink":         { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured GNU/BSD: resolves a symlink; no write mode' } },
  "realpath":         { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured GNU/BSD: resolves a canonical path; no write mode' } },
  "seq":              { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured GNU/BSD: prints a numeric sequence to stdout; no write mode' } },
  // sort：仅显示/比较旗标，加 --check 为可选值（optionalValueFlags）：
  // 裸 --check 或附着 --check=diagnose-first/--check=silent 都保持只读——
  // 后续分离词从不被当值消费，这正是无值的 -c 仍然存在的原因。
  // 值旗标读键规格、字段分隔符、缓冲区大小或并行计数。无操作数计数限制
  //（多个输入文件合法）。Windows 11 build 26200 实测：sort.exe /O 文件 输入
  // 写文件、不区分大小写、接受缩写（/OU、/OUTPUT）——-O 不是开关，
  // 所以这里已有的没有排除它。/X 开关在此 POSIX 文法下是操作数，
  // 与 /etc 这样的路径无法区分；each 拒绝任何单词 /word 操作数，尾斜杠
  // 有无皆然——尾斜杠形态在 VM 2026-09-26（build 10.0.26200.9550，
  // 限于 %TEMP%）重新实测：/O/、/o/、/OU/、/OUTPUT/、/T/、/A/ 全是
  // Invalid switch 且什么都不写（对照 /O 写），但该规则与 arp 共享，
  // arp 的 /d//s 斜杠容忍度无法在不运行改变状态的形态下测量，
  // 尾斜杠有无皆然——尾斜杠形态在 VM 2026-09-26（build 10.0.26200.9550，
  // 限于 %TEMP%）重新实测：/O/、/o/、/OU/、/OUTPUT/、/T/、/A/ 全是
  // Invalid switch 且什么都不写（对照 /O 写），但该规则与 arp 共享，
  // arp 的 /d//s 斜杠容忍度无法在不运行改变状态的形态下测量，
  // 所以保持 fail-closed。代价是命名 / 下文件的（sort /data）
  // 或带尾斜杠的目录（sort /etc/）也被拒。排除 -o/--output
  //（写——本评审自己的发现）、--compress-program（执行程序——
  // 同一发现实测 14224 次）、-T/--temporary-directory（选写位置；
  // 查看者无用处，摩擦表决定）和 --random-source/--files0-from
  //（读文件但不必要）。DISQUALIFYING_ARGS 自己的 sort 规则仍在此文法之前
  // 运行并仍能抬升类别；文法只画只读/safe 的线。实测：
  // GNU d12+trixie --help；busybox --help（自己拒绝 sort 长选项：
  // sort: unrecognized option: key=2）；BSD man（同选项家族；BSD 自己的
  // -o 不在列表，到不了此文法）。
  //
  // (rejects sort's long options itself: `sort: unrecognized option:
  // key=2`); BSD man (same option family; BSD's own `-o` never reaches this
  // grammar since it is not listed).
  "sort":             { readOnly: true, operandsAreData: true, grammar: { args: 'getopt',
    flags: ['-b', '-c', '-d', '-f', '-g', '-h', '-i', '-M', '-m', '-n', '-R', '-r', '-s', '-u', '-V', '-z',
      '--ignore-leading-blanks', '--dictionary-order', '--ignore-case', '--general-numeric-sort',
      '--human-numeric-sort', '--ignore-nonprinting', '--month-sort', '--merge', '--numeric-sort',
      '--random-sort', '--reverse', '--stable', '--unique', '--version-sort', '--debug',
      '--zero-terminated'],
    valueFlags: ['-k', '--key', '-t', '--field-separator', '-S', '--buffer-size', '--sort', '--parallel'],
    optionalValueFlags: ['--check'],
    operands: { each: /^(?!\/[^/]*\/?$)/ } } },
  // ss：完全仅文档——ss(8)（man7，iproute2）；ss 在每个实测镜像
  // 和 macOS 中缺席。仅显示旗标，加指名套接字族/查询/过滤的值旗标。
  // 排除 -K/--kill（强制关闭套接字）、-D/--diag（转储原始 TCP 信息到文件）、
  // -N/--net（经 setns 切换网络命名空间）和 -b/--bpf（管理）；少量
  // 只显示但不必要的旗标留出而非穷尽列出（-E、-T、-Q、-S、-M、-Z、-z、
  // --tos、--cgroup 等）。
  //
  "ss":               { readOnly: true, operandsAreData: true, grammar: { args: 'getopt',
    flags: ['-H', '--no-header', '-O', '--oneline', '-n', '--numeric', '-r', '--resolve', '-a', '--all',
      '-l', '--listening', '-o', '--options', '-e', '--extended', '-m', '--memory', '-p', '--processes',
      '-i', '--info', '-s', '--summary', '-t', '--tcp', '-u', '--udp', '-d', '--dccp', '-w', '--raw',
      '-x', '--unix', '-4', '-6', '-0', '--packet'],
    valueFlags: ['-f', '--family', '-A', '--query', '--socket', '-F', '--filter'] } },
  "stat":             { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured GNU/busybox/BSD: prints file or filesystem status; no write mode' } },
  // systemctl status：台账修正——从设计轮的 any 猜测移为文法；
  // audit.md 主表仍记录此条目为 any。修正理由（progress.md 台账）：
  // systemctl(1) 文档化 -H/--host 经 SSH 运行操作（在另一主机执行
  // 另一程序）、-M/--machine 面向容器/VM——两者排除而非下列列出。
  // -n/--lines 和 -o/--output 是可选值（optionalValueFlags）。
  // 完全仅文档——systemctl(1)（man7，systemd 262 开发版）——
  // 在每个实测镜像和 macOS 中缺席。
  //
  // Entirely documented only — systemctl(1) (man7, systemd 262~devel) —
  // absent from every measured image and from macOS.
  "systemctl status": { readOnly: true, operandsAreData: true, grammar: { args: 'getopt',
    flags: ['-l', '--full', '--no-pager', '-a', '--all', '-q', '--quiet', '--user', '--system', '-r',
      '--recursive', '--no-legend'],
    optionalValueFlags: ['-n', '--lines', '-o', '--output'] } },  // two-word: class only
  "tail":             { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured GNU/busybox/BSD: prints the last lines of a file; -f/-F only follow, they do not write' } },
  "test":             { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured GNU/BSD: evaluates a conditional expression and sets exit status; no I/O of any kind' } },
  "top":              { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: "measured busybox/BSD; documented (procps top(1)): no non-interactive write mode in any implementation — kill/renice/config-write keys are interactive-only, and batch mode ('top will not accept input') takes none of them" } },
  "tr":               { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured GNU/BSD: translates or deletes characters from stdin to stdout; no write mode' } },
  "traceroute":       { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured busybox; documented (BSD man): sends probe packets and prints the path; writes nothing locally (ICMP/UDP egress tracked separately)' } },
  "true":             { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured GNU: exits 0 immediately; no I/O of any kind' } },
  "uname":            { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured GNU/BSD: prints system identification; no write mode' } },
  // uniq：仅显示旗标，加 --all-repeated 保持可选值而在 valueFlags 之外
  //（规则 1）。operands max 1——仅 INPUT；第二个操作数是 OUTFILE 且被*覆写*
  //（本评审别处实测：uniq /etc/passwd 到 authorized_keys；GNU 自己的
  // 用法行是 [INPUT [OUTPUT]]，busybox 是 [FILE [OUTFILE]]）。
  // optionsBeforeOperands: true（终审修复）：macOS 的 optstring 以加号
  // 开头（POSIX 顺序），所以 uniq IN -c 在那里不把 -c 当计数旗标读——
  // 它是 OUTFILE，uniq 覆写它；GNU 会重排，所以那个拼写只在 GNU 无害，
  // 而文法必须对每个实现成立。排除 --group（可选值、读，
  // 但作为不必要留出——非最小文法增补）。实测：GNU d12 --help；
  // busybox --help；BSD man（同选项家族加 -D --all-repeated）。
  //
  // busybox --help; BSD man (same option family plus `-D --all-repeated
  // [septype]`).
  "uniq":             { readOnly: true, operandsAreData: true, grammar: { args: 'getopt',
    flags: ['-c', '--count', '-d', '--repeated', '-u', '--unique', '-i', '--ignore-case', '-z',
      '--zero-terminated', '-D'],
    valueFlags: ['-f', '--skip-fields', '-s', '--skip-chars', '-w', '--check-chars'],
    optionalValueFlags: ['--all-repeated'],
    optionsBeforeOperands: true,
    operands: { max: 1 } } },
  "uptime":           { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured busybox/BSD: prints load average and boot time; no write mode' } },
  "vmstat":           { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: "documented (procps vmstat(8): 'requires read access to /proc'): reports virtual-memory statistics; no write mode" } },
  "wc":               { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured GNU/BSD: counts lines, words and bytes of input; no write mode' } },
  "whereis":          { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured GNU/BSD: searches PATH directories for binaries, sources and manuals; no write mode' } },
  "which":            { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured GNU/BSD: locates a binary on PATH; no write mode' } },
  "who":              { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured GNU/BSD: lists logged-in sessions from utmp; no write mode' } },
  "whoami":           { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured GNU/BSD: prints the effective username; no write mode' } },
};

/** The class half of READERS, as the shape its consumers already expect. */
const READ_ONLY_ALLOWLIST = new Set(
  Object.entries(READERS).filter(([, e]) => e.readOnly).map(([name]) => name),
);
// 刻意非只读：env，因为它是 exec 包装器。env 加命令会跑那个命令，
// 所以把名字 env 加入白名单等于为分类器从未看过的命令背书——
// env sudo rm -f /etc/passwd 被归类 read-only 并跑在整个契约是
// 「不能写」的 profile 上。它不带任何 shell 元字符，所以下方的
// SHELL_CONTROL_CHARS 门也没抓住它。落到 safe，run-command 在策略下
// 仍可达；只打印环境的裸 env 随之失去只读状态，
// 这是基于名字的白名单的代价。

//
// 刻意非只读：curl 和 wget 抓取任意 URL（对内网发起 SSRF，
// cloud metadata / internal services), post local files to a remote host
//（curl -d 加文件路径），也写远程文件（curl -o、wget -O）——
// 两者都不需要 shell 元字符就能逃过分类器。它们落到 safe 类，
// run-command 在策略下仍可使用。

// 刻意保留的残余风险：dig/nslookup/host/ping/traceroute 可经
// DNS/ICMP 查询泄露少量数据。它们不能修改主机，保持只读；
// 出口要紧时经 profile 策略收紧。

/**
 * SFTP 读动词，由工具层合成而非调用方键入。
 *
 * 用第二集合而非往 READ_ONLY_ALLOWLIST 加两条，原因是那个 Set
 * 双重用途：operandsAreData 也读它，以决定片段的操作数是数据还是命令。
 * 把这些动词放进去会为它们关掉载体扫描——实测，sftp:list 加
 * sh -c sudo id 从 privileged 降到 read-only，
 * 因为 nestedCommands 停止提取 sh -c 载荷。那是唯一不携带
 * SHELL_CONTROL_CHARS 任何字符的载体形态，即扫描承重的那个形态。
 *
 * the form the scan is load-bearing for.
 *
 * 这里的抑制反正买不到任何东西。它存在是为了 grep python3 -c file
 * 不被读作调用 python；这些动词取的是无人解析的路径，
 * 没有要抑制的误报。
 *
 * 为什么要降级：两者都带 readOnlyHint: true，README 标注两者只读，
 * sftp-list 的描述以「只读。」结尾——而 safe 被 readOnly profile
 * 直接拒绝，所以注释针对的那个 profile 类恰是不能跑它们的（#217）。
 *（sftp-download 的描述没有只读声明；本段更早版本说两者都有，
 * 正是本文件不断抓到的过度声明。）降级没给该 profile 任何新东西：
 * cat /etc/shadow 和 ls /root 本来就是 read-only，
 * 读 SSH 用户可读的任何文件的权限本来就已持有。
 *
 * so the authority to read any file the SSH user can read is already held.
 *
 * sftp:upload、sftp:upload-file 和 sftp:download-file 保持在外——
 * 前两个在远程主机上写，第三个在传输根内写。
 */
const READ_ONLY_SYNTHETIC = new Set(['sftp:list', 'sftp:download', 'pty:read', 'pty:list', 'forward:list']);

/**
 * 无论角色或审批策略如何都不允许的命令。
 *
 * 这是策略引擎的拒绝清单——唯一定义。引擎过去以正则*字符串*
 * 保存平行副本，且已漂移（缺 fork 炸弹和递归 chown，rm 模式更窄）。
 * 这里的一切在分类意义上也是破坏性的；见下方 DESTRUCTIVE_DENYLIST。
 *
 * purposes; see DESTRUCTIVE_DENYLIST below.
 */
/*
 * 这些是保持正则的模式，每一个都是线性的。
 *
 * 原本不是的四个——dd 模式、两个 curl/wget 管道形态、chown -R 形态——
 * 现在是下方的片段检查。此处更早的注释推断匹配*内部*的歧义是
 * 唯一代价，那是错的：引擎还会在每个廉价字面头部匹配的偏移处重启，
 * 所以由 dd curl wget chown -R x 重复构成的命令每次翻倍跑 4 倍。
 * 在真实链上实测：64 KB 花 255ms，1 MB 花 65 秒阻塞事件循环，停顿落在
 * repeated ran at 4x per doubling. Measured on the real chain: 64 KB took
 * 255 ms, 1 MB took 65 seconds of blocked event loop, and the stall lands in
 * classifyCommand — before the approval gate and before the allow/deny
 * decision, so no role, approval mode or readOnly flag protects against it.
 *
 * The old note said sanitizeCommand's maxChars cap kept this cheap, "but a
 * policy check should not depend on a limit set three layers away and
 * configurable to any value". Once a config file could say `commandMaxChars = 0`
 *（#123）该限制消失了，预言成真。下方的重写正是那句话要的：
 * 策略检查现在以自己的条件就安全，无论 maxChars 说什么。
 *
 *
 * 已有的代价测试没抓到它，因为其种子是空格串，
 * 永远不匹配字面头部、因此从不触发重启。
 */
const FORBIDDEN_PATTERNS: RegExp[] = [
  /rm\s+-rf?\s+\/(\s|$)/,          // rm -rf / — the filesystem root itself
  /mkfs\./,
  />\s*\/dev\/sd/,
  // Fork 炸弹，五个位置允许 bash 允许的空白而旧模式不允许：
  // 括号前、括号内、管道两侧、和号前。冒号炸弹跑了且归类 safe。
  //
  //
  // 这仍然抓不到的，以免有人读作「fork 炸弹已处理」：
  // 换名的同一炸弹（f 加自管道）、用与号或分号而非管道分隔
  // 两次调用的主体、令牌之间的注释。匹配第一种需要对无界主体
  // 的反向引用且本文件已经发过一次 ReDoS；其余会放宽一个
  // 任何角色、层级或审批模式都无法覆盖的清单。影响是对目标主机
  // 而非本服务器的拒绝服务，不值得任一取舍——但那是洞不是关死的门。
  //
  // trade — but it is a hole, not a closed door.
  /:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/,
  />\s*\/etc\/cron/,
  />\s*\/etc\/systemd/,
  />\s*~\/.ssh\/authorized_keys/,
  /\biptables\s+-F\b/,
  /\bchmod\s+-R\s+777\s+\//,
];

/**
 * Words that are forbidden when *invoked*, which the patterns above cannot
 * express.
 *
 * 这些过去是 reboot 等的正则，匹配串中任何位置的该词。
 * last reboot 读日志却因含该词被拒；grep -r reboot /etc/、
 * cat /var/run/reboot-required、journalctl 加 grep shutdown 同样。
 * 在 NAS 上检查启动历史的 agent 第一条命令就踩中，
 * 这就是它的报告方式（#91）。
 *
 * 匹配调用而非提及需要知道命令词能从哪开始，
 * 那是分词器的活不是正则的——接近的正则形式都会重新引入
 * 上方区块要避免的反斜杠回溯。
 *
 */
const FORBIDDEN_INVOCATIONS = new Set(['shutdown', 'reboot', 'halt', 'poweroff', 'eval']);

/** Binaries that take the dangerous action as an argument: `systemctl reboot`. */
const ACTION_MULTIPLEXERS = new Set(['systemctl', 'init', 'telinit']);

/**
 * Binaries that run the rest of the command as another user.
 *
 * 列表显式而非模式，因为模式分不清编辑文件且非提权的
 * sudoedit 和就是 sudo 的 sudo-rs。新实现出现时必须手工维护；
 * 漏掉一个的代价是它的命令归类 safe。
 *
 *
 * 最后五个在 2.2.5 加入（#132）。直到 2.2.4 检查是 su 开头的正则，
 * 边界匹配了 su 与连字符之间，所以 su-exec 和 sudo-rs 被抓到——
 * 是正则的偶然而非意图。改为精确成员后它们掉出，
 * 在安全发布内收窄了一个安全控制。gosu 和 run0 两种形式都没抓到过。
 *
 * either form.
 */
/**
 * Class ordering, so a command that contains another can take the higher of the two.
 *
 * 仅由下方嵌套扫描使用。本文件其余一切直接决定单一类别。
 *
 */
const CLASS_RANK: Record<CommandClass, number> = {
  'read-only': 0,
  safe: 1,
  destructive: 2,
  privileged: 3,
};

/**
 *
 *
 * 一张表而非三个交叠的名字清单：在这里加解释器即全部变更，
 * 而 shell 清单与可读性清单失步正是新 shell 被当作
 * 不可读解释器对待的方式。
 *
 * readable 意味着程序是 shell，对它分类就是同一份工作再做一次、
 * 它挣到的类别是真实的。Python、Perl、Ruby、Node、PHP 不是：其程序
 * 是另一种语言，os.system 加提权是 shell 分类器看不见的。
 * 假装解析它们比承认不能更糟，所以不可读程序使命令成为 destructive——
 * 「无法判断」而非「这是 root」，与 hasUnnameableCommand 同一答案。
 *
 *
 * busybox 不在这里：它取 applet 名而非 -c，所以 busybox sh -c 加程序
 * 是包装器背后的 sh 调用。它在 EXEC_WRAPPERS 里，那正是它的类别。
 */
// Null 原型，理由见 mergePolicyRules（#172）：此对象以命令词为键，
// 命令词是自由字符串，普通对象上 INTERPRETERS 的 toString 解析为函数，
// 从其上读 programBearingWords 会在策略门内抛出。
//
/** One entry of the interpreter table — named so the lookup helper below can share it. */
interface InterpreterSpec {
  programBearingWords: string[];
  readable: boolean;
}

const INTERPRETERS: Record<string, InterpreterSpec> = Object.assign(
  Object.create(null) as Record<string, InterpreterSpec>,
  {
  sh: { programBearingWords: ['-c'], readable: true },
  bash: { programBearingWords: ['-c'], readable: true },
  dash: { programBearingWords: ['-c'], readable: true },
  zsh: { programBearingWords: ['-c'], readable: true },
  ksh: { programBearingWords: ['-c'], readable: true },
  ash: { programBearingWords: ['-c'], readable: true },
  python: { programBearingWords: ['-c'], readable: false },
  python2: { programBearingWords: ['-c'], readable: false },
  python3: { programBearingWords: ['-c'], readable: false },
  perl: { programBearingWords: ['-e', '-E'], readable: false },
  ruby: { programBearingWords: ['-e'], readable: false },
  // -p/--print 与 -e 完全同法求值后打印结果。
  node: { programBearingWords: ['-e', '--eval', '-p', '--print'], readable: false },
  php: { programBearingWords: ['-r'], readable: false },
  // 2.11.0 实测：这些各自归类 safe 而经 python3 -c 的同一攻击
  // 归类 destructive（GHSA-qmx6-47vm-3vf7）。通篇 readable: false，
  // 与 python/perl/node 一致：程序不是 shell 文本，
  // 所以算数的是其存在而非其内容。
  osascript: { programBearingWords: ['-e'], readable: false },
  lua: { programBearingWords: ['-e'], readable: false },
  Rscript: { programBearingWords: ['-e'], readable: false },
  bun: { programBearingWords: ['-e'], readable: false },
  // 无程序承载旗标：真 tclsh 以脚本文件为位置参数或从 stdin 读，
  // 与 sh/bash/python/pwsh 都不同，后三者各有自己的 -c。空列表
  // 仍把 tclsh 标记为不可读解释器供 readsProgramFromStdin 用
  //（echo 管道 tclsh），那才是真正的载体；只是它自己的命令行
  // 从不内联接收程序，所以没有可点名的旗标。
  //
  tclsh: { programBearingWords: [], readable: false },
  // eval 是子命令而非旗标——字段以其所载内容命名。
  deno: { programBearingWords: ['eval'], readable: false },
  pwsh: { programBearingWords: ['-c', '-Command', '-e', '-EncodedCommand'], readable: false },
  powershell: { programBearingWords: ['-c', '-Command', '-e', '-EncodedCommand'], readable: false },
  },
);

/**
 *
 *
 * 用第二索引而非直接对 INTERPRETERS 小写查找键，因为那张表
 * 自己的键并非一律小写——Rscript 不是 rscript——只折叠*输入*
 * 仍然会 miss。模块加载时构建一次：表是固定的，没有要同步的东西。
 *
 *
 */
const INTERPRETERS_BY_LOWERCASE_NAME: Record<string, InterpreterSpec> = Object.assign(
  Object.create(null) as Record<string, InterpreterSpec>,
  Object.fromEntries(Object.entries(INTERPRETERS).map(([name, spec]) => [name.toLowerCase(), spec])),
);

/** A Windows executable suffix this table's keys never carry. */
const WINDOWS_EXE_SUFFIX = /\.(exe|cmd|bat)$/i;

/**
 *（stripPath 加去引号，正如每个调用点已为下方精确匹配算的那样）。
 *
 * it for the exact-match case below).
 *
 * 表键是精确、区分大小写、无扩展名的拼写，所以先试直接查找——
 * 对常见情形（sh、python3、裸小写 pwsh）这就是全部成本。回退
 * 剥掉尾 .exe/.cmd/.bat 并折叠大小写，那是 Windows 目标自己的 shell
 * 对*同一*二进制交回的：powershell.exe、PWSH.EXE 和 PowerShell
 * 都点名本表已列在 powershell/pwsh 下的解释器。
 *
 * 应用于每个条目而非仅 pwsh/powershell。实测的 bug 是
 *
 * Applied to every entry, not only pwsh/powershell. The measured bug is
 * about those two, but the gap is not specific to them: a target running
 * `python.exe` or `Node.EXE` carries the identical mismatch, and scoping the
 * fix to two names would leave the rest of the table exactly as blind as it
 * was. This is the binary-*name* question, answered once — it does not touch
 * flag matching, which stays case-sensitive per interpreter (`perl -E` and
 * perl -e 仍是两个不同的旗标）经穿过 programAfterFlag 及其朋友的
 * 既有独立 caseInsensitive 参数。
 *
 */
function resolveInterpreter(word: string): InterpreterSpec | undefined {
  const exact = INTERPRETERS[word];
  if (exact !== undefined) return exact;
  return INTERPRETERS_BY_LOWERCASE_NAME[word.replace(WINDOWS_EXE_SUFFIX, '').toLowerCase()];
}

/** `find … -exec <cmd> +` runs cmd. */
const FIND_EXEC_FLAGS = new Set(['-exec', '-execdir', '-ok', '-okdir']);

/**
 *（coreutils 9.11，docker exec 加 sort --help）。仅用于计算 getopt_long
 * 视为无歧义的 --output 和 --compress-program 的哪些前缀。
 *
 * getopt_long 把一个双连字符词解析到它是其无歧义前缀的选项：
 * 与另一选项名共享的前缀被直接拒绝（选项含糊），而非运行，
 * 所以不得当作写。对二进制实测：sort --c 加等号退出 2 无文件创建；
 * sort --co 加等号——第二个字母是 --check 与 --compress-program 分歧处——运行。
 *
 *
 * write. Measured against the binary: `sort --c=x k` exits 2 with no file
 * created; `sort --co=x k` — the second letter is where `--check` and
 * `--compress-program` diverge — runs.
 */
const SORT_LONG_OPTIONS = [
  'ignore-leading-blanks', 'dictionary-order', 'ignore-case',
  'general-numeric-sort', 'ignore-nonprinting', 'month-sort',
  'human-numeric-sort', 'numeric-sort', 'random-sort', 'random-source',
  'reverse', 'sort', 'version-sort', 'batch-size', 'check',
  'compress-program', 'debug', 'files0-from', 'key', 'merge', 'output',
  'stable', 'buffer-size', 'field-separator', 'temporary-directory',
  'parallel', 'unique', 'zero-terminated', 'help', 'version',
];

/**
 * 正则交替源——getopt_long 会为它接受的每个前缀，从最短无歧义的
 * 到 full 本身——各自可选地后接等号值。
 *
 * itself — each optionally followed by `=value`.
 */
function unambiguousLongOptionSource(full: string): string {
  const prefixes: string[] = [];
  for (let len = 1; len <= full.length; len++) {
    const prefix = full.slice(0, len);
    if (SORT_LONG_OPTIONS.filter((opt) => opt.startsWith(prefix)).length === 1) {
      prefixes.push(prefix);
    }
  }
  return `--(?:${prefixes.join('|')})(?:=|$)`;
}

/**
 *
 * 只有运维不会写的输入才到达——测试用两百层。回退是 privileged
 * 而非更低类别，因为此扫描的全部意义就是无法读取的命令
 * 不得当作可以读取的。
 *
 */
const MAX_NESTING_DEPTH = 8;

/**
 *
 *
 * 分类的正则是对发送时的命令写的，但传输在命令运行前移除引号，
 * 所以带引号的 rm -rf 匹配不到破坏性模式、夹引号的 sudo 点不出
 * 提权前缀。过去在分号/管道/换行和空白上拆分的每个消费者改读这里，
 * 引号移除因此一次、一处发生，而非每条规则重新推导。
 *
 *
 * 不是 shell 解析器。变量展开、算术和 here-doc 在范围外——
 * 无法解析的命令词由 hasUnnameableCommand 拒绝。
 */
function tokenizeSegments(command: string, dialect: ShellDialect = 'posix'): string[][] {
  return tokenizeSegmentsDetailed(command, true, dialect).map((segment) => segment.words);
}

/** Inside double quotes, the characters POSIX lets a backslash escape. */
const DOUBLE_QUOTE_ESCAPABLE = new Set(['$', '`', '"', '\\', '\n']);

/**
 * 只有管道规则需要它：管道把一条命令的输出喂给下一条，
 * 分号和与号只是排序，关于管道的规则不得在排序上开火。
 * 两种视图出自一个分词器正是两者不失步的原因。
 *
 * Deriving both views from one tokeniser is what stops the two from drifting apart.
 */
function tokenizeSegmentsDetailed(
  command: string,
  honorQuotes = true,
  dialect: ShellDialect = 'posix',
): Array<{ words: string[]; sep: string }> {
  const segments: Array<{ words: string[]; sep: string }> = [];
  let pending = '';
  let words: string[] = [];
  let current = '';
  let quote: string | null = null;
  let escaped = false;

  /**
 *
 * 只查 current 会丢掉它，而对按位置读参数的一切丢词不是小事：
 * awk -F 加空串引号加 BEGIN system 命令以三词而非四词到达，
 * awk 读取器把程序当 -F 的值消费、报告调用没有跑程序——
 * 对真实 awk 会跑的命令却是 safe。BWK awk 20200816 实测：
   * the program as `-F`'s value and reported that the invocation ran no program
   * — `safe`, for a command real awk runs. Measured on BWK awk 20200816: it
   * warns "field separator FS is empty" on stderr and then executes both the
   * `system()` call and a file redirection.
   *
   * Only a *quoted* empty survives. Pushing every empty `current` would emit a
   * word per run of whitespace, which is not what a shell does.
   */
  let quotedWord = false;

  const endWord = () => {
    if (current || quotedWord) words.push(current);
    current = '';
    quotedWord = false;
  };
  const endSegment = (sep: string) => {
    endWord();
    if (words.length > 0) segments.push({ words, sep: pending });
    words = [];
    pending = sep;
  };

  for (let i = 0; i < command.length; i++) {
    const ch = command[i];
    if (escaped) {
      // A backslash quotes the next character, so `\reboot` runs reboot. Keeping the
      // character and dropping the backslash is what the shell does.
      current += ch;
      escaped = false;
      continue;
    }
    if (quote) {
      // Backslash is literal inside single quotes; inside double quotes it escapes.
      if (dialect === 'posix' && ch === '\\' && quote === '"') {
        const next = command[i + 1];
        // POSIX keeps `\x` before an ordinary character: only $ ` " \ and a
        // newline are escapable, so the backslash survives into the word
        // (GHSA-972x-g47g-3922's second finding — dropping it misread both
        // dialects at once). At end of string there is no next character to
        // protect, and the open quote sends the whole scan to the fallback.
        if (next === undefined || DOUBLE_QUOTE_ESCAPABLE.has(next)) { escaped = true; continue; }
        current += ch;
        continue;
      }
      if (ch === quote) quote = null;
      else current += ch;
      continue;
    }
    if (dialect === 'posix' && ch === '\\') { escaped = true; continue; }
    if (honorQuotes && (ch === '"' || ch === "'")) { quote = ch; quotedWord = true; continue; }
    if (ch === ';' || ch === '&' || ch === '|' || ch === '\n') { endSegment(ch); continue; }
    if (/\s/.test(ch)) { endWord(); continue; }
    current += ch;
  }
  endSegment('');

  // A quote left open at the end is not a command a shell would run — it is a syntax
  // 把它读作一个长引号参数是危险的读法：那样就不再按分号拆分、
  // 提权消失——分词前实测为 privileged、分词后变 safe。
  // 所以回落到把引号字符当普通文本的扫描：既拆分又能看到提权。
  //
  if (quote !== null) return tokenizeSegmentsDetailed(command, false, dialect);
  return segments;
}

/**
 * The command rebuilt from its tokens, for the regex rules to match against.
 *
 * 片段以分号加空格重接，模式不能跨 shell 会分别运行的两条命令匹配。
 *
 */
const normalizedCache = new Map<string, string>();

function normalizeCommand(command: string, dialect: ShellDialect): string {
  // 一次 evaluate 约问十九次，每个正则规则一次，每次问都重跑
  // 整条命令的分词器。问在同一条命令上连续到达，小缓存、
  // 逐出最早插入的条目，几乎全部消除。键带方言，因为同一命令
  // 的两种读法在同一行里都会被问。
  //
  const key = `${dialect}\u0000${command}`;
  const hit = normalizedCache.get(key);
  if (hit !== undefined) return hit;
  const value = normalizeUncached(command, dialect);
  normalizedCache.set(key, value);
  if (normalizedCache.size > 8) {
    normalizedCache.delete(normalizedCache.keys().next().value as string);
  }
  return value;
}

function normalizeUncached(command: string, dialect: ShellDialect): string {
  return tokenizeSegments(command, dialect)
    .map((words) => words.map((w) => (QUOTED_CONTENT.test(w) ? PLACEHOLDER : w)).join(' '))
    .join('; ');
}

/**
 * A character the tokeniser splits on or at, which a token can only hold if it was quoted.
 * 分词器在未引号分隔符上、未引号空白处拆分，持有任一者的令牌
 * 必来自引号内——shell 不在那里拆分，其内容是数据。把它拼回模式文本
 * 正是让参数读作命令的原因：echo 加引号串打印字符串，归一化后却
 * 变成含真实分号的命令并命中永不放行清单。丢弃这些令牌保持引号移除
 * 做它被加入时的本职——令牌不含分隔符的带引号路径——而不让带引号
 * 的参数冒充命令。真正交出带引号命令的载体（sh -c 加串）由
 * nestedCommands 读取，不由此处。
 *
 * (`sh -c "ls; rm -rf /etc"`) is read by `nestedCommands`, not by this.
 */
const QUOTED_CONTENT = /[\s;&|\n]/;

/**
 *
 *
 * 直接删除会把相邻词拼在一起、制造命令中从未出现的相邻关系：
 * echo 加引号管道词归一化后落在永不放行清单。一个无模式包含、
 * 空白也不匹配的字符代替其位，两侧不能再被读成一个短语。
 *
 */
const PLACEHOLDER = '\u0000';

/**
 *
 * 只归一化不够：它从令牌重建命令，其间 shell 元字符消失，
 * 跨分隔符匹配的模式不再开火——fork 炸弹的字面管道加与号就是证明。
 * 归一化仍是打败带引号路径的手段。两种形态互不为超集，所以都试：
 * 对以发现某物为全部职责的模式，并集是唯一不丢匹配的方向。
 *
 * 刻意只限正则。FORBIDDEN_RULES 的词规则本已分词，把归一化串交给它们
 * 会把安全地待在带引号参数里的分隔符变成真的——grep 加引号竖线词
 * 变成无条件拒绝，正是 #91 提及与调用 bug 的重演。
 *
 * tokenise, and handing them the normalised string turns a separator that was safely
 * inside a quoted argument into a real one — `grep -E "warn|reboot" syslog` became an
 * unconditional refusal, which is the mention-vs-invocation bug of #91 all over again.
 */
function matchesEitherForm(command: string, test: (form: string) => boolean, dialect: ShellDialect): boolean {
  return test(command) || test(normalizeCommand(command, dialect));
}

/**
 *
 *
 * 提权扫描读按分号管道与空白拆出的令牌，只见外层命令：
 * echo 加替换分词成三词、echo 被当真命令、找不到提权
 *（GHSA-v8jh-gv7v-3gvq）。破坏性扫描从未有此问题因为它读原始文本——
 * 所以带替换的 rm 命令一直归类正确。这通过拉出内部命令、
 * 让它们以自己的身份被分类来关闭该不对称。
 *
 * inner commands out so they can be classified in their own right.
 *
 * Four carriers, all of which a remote shell expands and runs:
 *   `$(...)`, backticks, process substitution `<(...)` / `>(...)`, and a shell
 *   given `-c`.
 *
 * @param speculativeOperands Whether the catch-all below — any multi-word,
 *   non-flag operand of a segment no more specific reader claimed — should be
 *   pushed. That catch-all is a guess about a binary this file does not
 *   recognise; the four carriers above are not guesses, the shell really does
 *   run what they hold, and are pushed regardless of this flag. Defaults to
 *   `true` for `classifyCommand`'s own recursion, where a guess may raise a
 *   command's *class* and leave role, tier and approval to weigh in.
 *   `findForbiddenMatch` passes `false`: its recursion feeds
 *   `FORBIDDEN_RULES`, the one unconditional denylist, and a guess must not
 *   be able to produce a refusal nobody can override (the maintainer's
 *   ruling — see the block comment above `findForbiddenMatch`). `$()`,
 *   backticks and `sh -c` are certain carriers and keep reaching the
 *   denylist either way.
 */
export function nestedCommands(command: string, speculativeOperands = true, dialect: ShellDialect = 'posix'): string[] {
  const found: string[] = [];

  // `$(...)`, `<(...)`, `>(...)` — scanned rather than matched, because a regex
  // cannot balance parentheses and `echo $(echo $(sudo id))` is the case that
  // matters most.
  for (let i = 0; i < command.length; i++) {
    const opensSubstitution = command[i] === '$' && command[i + 1] === '(';
    const opensProcess = (command[i] === '<' || command[i] === '>') && command[i + 1] === '(';
    if (!opensSubstitution && !opensProcess) continue;

    // `$((1 + 1))` is arithmetic, not a command. Skipping it keeps the approval
    // prompt off `echo $((1 + 1))`.
    if (opensSubstitution && command[i + 2] === '(') continue;

    let depth = 0;
    for (let j = i + 1; j < command.length; j++) {
      if (command[j] === '(') depth++;
      else if (command[j] === ')') {
        depth--;
        if (depth === 0) {
          found.push(command.slice(i + 2, j));
          i = j;
          break;
        }
      }
    }
  }

  // Backticks. No nesting to balance — the shell requires escaping to nest them.
  const backticks = command.match(/`([^`]*)`/g);
  if (backticks) {
    for (const raw of backticks) found.push(raw.slice(1, -1));
  }

  // A carrier hands a program to something that runs it. Carries no substitution, so the
  // scan above does not see it. Read each segment's command word rather than scanning
  // every word: matching a mention rather than an invocation is #91, and
  // `cat /usr/bin/python3` names an interpreter without running one.
  const segments = tokenizeSegmentsDetailed(command, true, dialect);
  for (const { words } of segments) {
    // Every word, not just the command word. Stopping at the head lost the carrier behind
    // any wrapper this file does not list: `xargs -I {} sh -c 'sudo id'` stops on `{}`, and
    // `flock`, `chroot`, `nsenter` and `systemd-run` are not wrappers it knows — all six
    // went from `privileged` to `safe`. What keeps this from matching a *mention* is not
    // where it looks but what it requires: `programAfterFlag` returns null unless a
    // program-bearing flag actually follows, so `cat /usr/bin/python3` carries nothing.
    //
    // awk is handled below rather than in this loop, and the difference is the
    // point: this loop reads *every* word so a carrier behind an unlisted
    // wrapper is not lost, and doing that to awk is what made `man awk`
    // destructive. awk's program is a positional operand, so the only evidence
    // it was invoked is that it is the segment's command word (#184).
    const awk = awkFindings(words);
    for (const inner of awk?.commands ?? []) found.push(inner);
    // A pipe target is classified too, so `print … | "sudo tee /etc/passwd"`
    // still names `tee`. Whether the *direction* makes it worse is decided in
    // hasDangerousAwk, which is where this file already keeps that rule.
    for (const inner of awk?.pipedInto ?? []) found.push(inner);

    if (!operandsAreData(words)) {
      // Which operand *indices* an interpreter actually consumed as a program —
      // not whether the segment's head happens to be a name in the table, and not
      // a single segment-wide flag either. A set of indices rather than a boolean:
      // `unknownbin sh -c true 'sudo id'` has `sh -c` consume `true` (harmless,
      // pushed below) and leave `'sudo id'` untouched, and a boolean here defused
      // the catch-all for that second operand too — measured, it classified
      // `safe`. Only the specific word an interpreter actually read should be
      // excluded from the catch-all; every other operand in the segment is still
      // this binary's own, unclaimed by anything more specific.
      //
      // A binary being recognised is also not the same as this segment's
      // invocation of it being one the loop could parse:
      // `pwsh -ExecutionPolicy Bypass -Command 'sudo id'` has a recognised head
      // and a program on the line, but `-ExecutionPolicy` takes a value
      // (`Bypass`) that isn't itself a flag, and `programAfterFlag` gives up
      // rather than guess past it. Gating the catch-all below on "head is in the
      // table" excluded exactly the binaries this file just learned, and for
      // precisely the invocations its own flag-walk cannot follow — a net
      // regression, not a wash.
      const consumedOperands = new Set<number>();
      for (let i = 0; i < words.length; i++) {
        const spec = resolveInterpreter(stripPath(unquote(words[i])));
        // pwsh/powershell's own parameter binder resolves `-ENC`/`-Enc`/`-enc` to the
        // same parameter; every other interpreter's flags are exact letters (`-E` and
        // `-e` are different flags to perl). `-EncodedCommand` only ever appears on
        // the two entries whose own parameter binder works this way, so its presence
        // is the signal for which interpreter this is, not a hardcoded name check.
        const caseInsensitive = spec?.programBearingWords.includes('-EncodedCommand') ?? false;
        if (spec === undefined || isFlagValue(words, i, spec.programBearingWords, caseInsensitive)) continue;
        // Same signal, second job: pwsh/powershell's argument parser also does not stop
        // at an unrecognised option's bare value (`-ExecutionPolicy Bypass`) the way a
        // POSIX interpreter stops at its first positional argument. See
        // `programAfterFlag`'s `tolerateUnknownWordsAtHead` for why this is scoped to
        // `i === 0` there rather than here.
        const result = programAfterFlag(words, i, spec.programBearingWords, caseInsensitive, caseInsensitive);
        if (result !== null) {
          consumedOperands.add(result.index);
          found.push(result.program);
          // An encoded program is opaque to every text scan until it is decoded. Gated on
          // the word `programAfterFlag` actually matched — the table's own canonical
          // spelling, so every case-folded or clustered form of `-EncodedCommand`/`-e`
          // reaches this the same way a literal `-EncodedCommand` does — not a scan of
          // the whole segment for one long spelling.
          if (caseInsensitive && (result.flag === '-EncodedCommand' || result.flag === '-e')) {
            const decoded = decodedPowerShellCommand(result.program);
            if (decoded !== null) found.push(decoded);
          }
        }
      }

      // An operand of a binary nothing more specific has read is classified as a
      // command in its own right, rather than scanned as text.
      //
      // The gate is the awk reader's own result, and now which specific operands
      // an interpreter actually consumed, rather than a list of names: a name
      // list here would be the defect this change exists to fix
      // (GHSA-qmx6-47vm-3vf7), and "the head is a name in the table" turned out
      // to be one too — it answers a different question than "did this
      // invocation's program-bearing word actually resolve". `awk` is already
      // null for every non-awk segment.
      //
      // Whitespace is what separates an operand worth classifying from one that is
      // not: a single token is a path, a flag value or a subcommand, while a
      // multi-word operand has the shape of a command. Flags are skipped.
      //
      // Deliberately NOT a text scan for `sudo`. That version asserted elevations
      // the awk reader and the variable-command-word logic refuse to assert — both
      // cap at `destructive` on purpose — and it out-ranked the nested
      // classification that names the elevated binary, reporting `awk` where `id`
      // was correct.
      if (speculativeOperands && awk === null) {
        for (let i = 1; i < words.length; i++) {
          if (consumedOperands.has(i)) continue;
          if (words[i].startsWith('-')) continue;
          if (/\s/.test(words[i])) found.push(words[i]);
        }
      }
    }

    // `-exec` is a flag rather than a command word, so this one is still a scan.
    for (let i = 0; i < words.length; i++) {
      if (!FIND_EXEC_FLAGS.has(words[i]) || words[i + 1] === undefined) continue;
      const rest = words.slice(i + 1);
      const stop = rest.findIndex((w) => w === '+' || w === ';');
      found.push((stop === -1 ? rest : rest.slice(0, stop)).join(' '));
      // Step past what was consumed. Leaving `i` where it was emitted one child per
      // `-exec` token, each an overlapping suffix of the last and each still holding the
      // rest of them, so the recursion re-expanded the same tail once per token: twenty
      // `-ok` tokens in 81 bytes cost 17 seconds of a single-threaded event loop.
      i = stop === -1 ? words.length : i + 1 + stop;
    }
  }

  // A pipe stage whose command word is an interpreter with no program of its own runs
  // whatever the previous stage printed. Starts at 1: a leading `|` records its separator
  // on the first segment, and reading `segments[-1]` threw.
  for (let i = 1; i < segments.length; i++) {
    if (segments[i].sep !== '|') continue;
    if (!readsProgramFromStdin(segments[i].words)) continue;
    found.push(segments[i - 1].words.join(' '));
  }

  return found.filter((c) => c.trim().length > 0);
}

const PRIVILEGE_PREFIXES = new Set([
  'sudo', 'su', 'doas', 'pkexec',
  // BusyBox/Alpine, Docker entrypoints, the Rust sudo now default on some
  // distributions, systemd's replacement, and the Solaris/illumos spelling.
  'su-exec', 'gosu', 'sudo-rs', 'run0', 'pfexec',
  // Both reach root with the command otherwise classified `safe`.
  'runuser', 'setpriv',
]);

/**
 * Binaries whose job is to run another command.
 *
 * The allowlist and the privilege check both name a binary, so a wrapper hides
 * whatever it wraps: `env sudo id` was classified by the name `env`. These are
 * stepped over when deciding whether a segment elevates, so the check sees the
 * command that will actually run.
 *
 * `env` is the one that was also allowlisted, and it has been removed from
 * READ_ONLY_ALLOWLIST above. The rest were never read-only, so before this they
 * hid elevation rather than granting it — `nohup sudo systemctl stop nginx`
 * classified `safe`, which the default bindings grant to admin and operator on
 * every tier.
 */
const EXEC_WRAPPERS = new Set([
  'env', 'nohup', 'nice', 'ionice', 'command', 'exec', 'setsid', 'stdbuf',
  'timeout', 'chrt', 'taskset', 'xargs', 'watch',
  // `busybox <applet>` runs the applet, so it wraps rather than interprets.
  'busybox',
]);

/**
 * Arguments that turn an allowlisted binary into one that writes or executes.
 *
 * The allowlist vouches for a name; these are the flags that make the name a
 * lie. `find /var/www -delete` removes a directory tree and `find / -exec sudo
 * id +` runs a command as root, and both classified `read-only` — the `-exec …
 * \;` form only escaped because `;` happens to be a shell metacharacter, while
 * the `+` terminator carries none.
 */
// Null-prototype for the same reason as INTERPRETERS: indexed by the command word.
const DISQUALIFYING_ARGS: Record<string, RegExp> = Object.assign(
  Object.create(null) as Record<string, RegExp>,
  {
    find: /^-(exec|execdir|ok|okdir|delete|fprintf?|fls)$/,
    // GNU sort execs this for every temporary file it spills, so a reader
    // becomes a launcher. Measured against coreutils 9.11: an attacker-named
    // script ran 14,224 times for one 200k-line input, and the whole command
    // classified `read-only` — which a `readOnly` viewer is allowed to run,
    // while running that same program directly is denied.
    //
    // `-o FILE` / `--output=FILE` is the same shape of bug with a plainer
    // payoff: it creates and truncates FILE, which is a write a `readOnly`
    // profile must never reach through a command classified `read-only`.
    // Measured on HEAD before this rule: `sort -o /root/.ssh/authorized_keys
    // /tmp/key.pub` classified `read-only`.
    //
    // Targeted round (2026-09-24, R2+R3): the version above closed the exact
    // spellings `-o`, `--output` and `--compress-program` and left the CLASS
    // open — GNU sort's own option grammar has two escapes past a fixed
    // spelling, both measured against the real binary:
    //
    //  - A short-option cluster is scanned left to right, and any of sort's
    //    own *argument-less* short flags may sit ahead of `-o` without
    //    consuming it: `sort -mo out in` writes `out` exactly as `sort -o out
    //    in` does. `-m` (merge) is itself argument-less, and its absence from
    //    the char class below is exactly what let `sort -mo …` through as
    //    `read-only`.
    //  - `getopt_long` resolves a `--` word by unambiguous-prefix matching:
    //    `--o`, `--ou`, `--out`, `--outp`, `--outpu` all mean `--output`
    //    (nothing else starts with `o`), and `--co` through
    //    `--compress-progra` all mean `--compress-program` (`--c` alone is
    //    ambiguous with `--check` and sort refuses to run at all —
    //    `unambiguousLongOptionSource` excludes it for exactly that reason,
    //    computed from sort's own option table rather than hand-picked).
    //
    // The cluster branch is still deliberately narrower than "any `o` in a
    // dash word": `-[bcCdfghiMmnRrsuVz]*o` only allows GNU sort's own
    // argument-less short flags ahead of the `o`, so it stops at the first
    // flag that takes a value of its own. Without that, `-tofile` — `-t`
    // (field separator) with its value attached, not `-o` — would be
    // misread as a write. `-t`, `-k`, `-S` and `-T` are exactly the short
    // flags this excludes, because each consumes the rest of a clustered
    // word as its own argument, so a following `o` is that argument's text,
    // not `-o` invoked.
    //
    // `find`'s entry above does not get the same prefix-abbreviation
    // treatment: `find` parses its predicates itself rather than through
    // `getopt_long`, and accepts no abbreviated spelling of `-exec` — `find .
    // -exe` is "unknown predicate `-exe`", measured. There is no class to
    // close there.
    sort: new RegExp(
      `^(?:${unambiguousLongOptionSource('compress-program')}`
      + `|${unambiguousLongOptionSource('output')}`
      + '|-[bcCdfghiMmnRrsuVz]*o)',
    ),
  },
);

/** A leading `NAME=value`, which a shell treats as an assignment, not a command. */
const ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/;

/** `timeout 5s`, `nice 10` — a bare argument some wrappers take before the command. */
const BARE_NUMERIC = /^\d+(\.\d+)?[smhd]?$/;

/**
 * Remove the quoting a shell would remove before looking up a command.
 *
 * `\sudo`, `'sudo'` and `"sudo"` all execute sudo — the backslash only
 * suppresses alias expansion — but a verbatim string comparison sees three
 * different words. Without this, a one-character edit walks around the check.
 *
 * One surrounding quote pair, and nothing else: the scanner has already
 * resolved escapes by the time a word reaches this, in both the
 * quote-honouring scan and the `honorQuotes = false` fallback, so a second
 * pass here could only remove backslashes the dialect meant to keep — the
 * literal ones inside single quotes, and the POSIX-retained ones inside
 * double quotes (GHSA-972x-g47g-3922).
 */
function unquote(word: string): string {
  return word.replace(/^(['"])(.*)\1$/, '$2');
}

/**
 * Privilege-prefix flags that consume the next argument, so `sudo -u root
 * reboot` is not read as invoking `root`. Enumerable because it is one tool's
 * option set, unlike "every flag of every binary".
 */
const PREFIX_VALUE_FLAGS = new Set([
  '-u', '-g', '-p', '-C', '-h', '-r', '-t', '-U', '-c',
  '--user', '--group', '--prompt', '--close-from', '--host', '--role', '--type',
  '--other-user', '--command',
]);

/** `/sbin/reboot`, `C:\Windows\reboot.exe` and `reboot` are the same invocation. */
function stripPath(word: string): string {
  const cut = Math.max(word.lastIndexOf('/'), word.lastIndexOf('\\'));
  return cut === -1 ? word : word.slice(cut + 1);
}

/**
 * The command words a shell would actually execute — the head of every
 * `;`/`&&`/`||`/`|`/newline-separated segment, past any privilege prefix, plus
 * the arguments of a multiplexer like `systemctl`.
 *
 * Pure string work: split, trim, set lookups. No quantifiers, so nothing here
 * can backtrack.
 */
interface Segment {
  /** The binary being run, with any directory part and privilege prefix removed. */
  head: string;
  /** Everything after it, verbatim — `of=/dev/sda` must not be path-stripped. */
  args: string[];
}

function parseSegments(command: string, dialect: ShellDialect = 'posix'): Segment[] {
  const segments: Segment[] = [];
  for (const words of tokenizeSegments(command, dialect)) {
    const segment = parseWords(words);
    if (segment !== null) segments.push(segment);
  }
  return segments;
}

/** The same, for callers that already hold the tokenised words. */
function parseWords(words: string[]): Segment | null {
  {
    let i = 0;
    while (i < words.length && PRIVILEGE_PREFIXES.has(stripPath(words[i]))) {
      i++;
      while (i < words.length && words[i].startsWith('-')) {
        const consumesValue = PREFIX_VALUE_FLAGS.has(words[i]);
        i++;
        if (consumesValue) i++;
      }
    }

    if (i < words.length) {
      return { head: stripPath(words[i]), args: words.slice(i + 1) };
    }
  }
  return null;
}

/**
 * Whether a segment asks for elevation, reading past anything that is not yet
 * the command.
 *
 * A shell resolves the command word after assignments, and a wrapper runs what
 * follows it, so all of these execute sudo while naming something else first:
 *
 *   env sudo id            nohup sudo id         timeout 5 sudo id
 *   FOO=1 sudo id          nice -n 10 sudo id    command sudo id
 *
 * The scan walks left to right and stops at the first word that is a real
 * command. Reaching a privilege prefix before that is elevation; reaching
 * anything else is not, which is what keeps `grep sudo /var/log/auth.log` a
 * mention rather than an invocation.
 */
function elevatedBinary(words: string[]): string | null {
  let i = 0;
  let prefix: string | null = null;

  while (i < words.length) {
    const raw = words[i];
    const word = stripPath(unquote(raw));

    if (PRIVILEGE_PREFIXES.has(word)) {
      prefix ??= word;
      i++;
      // The prefix's own options, some of which swallow the next word.
      while (i < words.length && words[i].startsWith('-')) {
        const consumesValue = PREFIX_VALUE_FLAGS.has(words[i]);
        i++;
        if (consumesValue) i++;
      }
      continue;
    }

    // Words that are not yet the command: an assignment, a wrapper, an option,
    // or the bare number `timeout`/`nice` take before theirs.
    if (ASSIGNMENT.test(raw) || EXEC_WRAPPERS.has(word)
      || raw.startsWith('-') || BARE_NUMERIC.test(raw)) {
      i++;
      continue;
    }

    // A real command. Before any prefix it means the segment does not elevate —
    // which is what keeps `grep sudo /var/log/auth.log` a mention. After one, it
    // is what actually runs as root.
    return prefix === null ? null : word;
  }

  // `sudo`, or `sudo -u root`, with nothing after it: the prefix is all there is
  // to name.
  return prefix;
}

/**
 * The binary this command runs under elevation, or null if it runs none.
 *
 * Returning the name rather than a boolean is what lets `ParsedCommand.binary`
 * describe the same command the class does. Until 2.2.4 a `privileged` class
 * implied a leading prefix, so the anchored `extractBinary` always named the
 * elevated binary; once elevation could be found in any segment that stopped
 * holding, and `echo hi; sudo id` recorded `binary: "echo"` against a
 * privileged decision — in the audit log, the OTel span and OPA's input (#134).
 */
function elevatedBinaryOf(command: string, dialect: ShellDialect = 'posix'): string | null {
  for (const words of tokenizeSegments(command, dialect)) {
    const found = elevatedBinary(words);
    if (found !== null) return found;
  }
  return null;
}


/**
 * Does this command elevate anywhere a shell would act on it?
 *
 * Replaces four `^`-anchored regexes that only saw a *leading* prefix. Elevation
 * behind a wrapper, behind an assignment, or after a separator all reached root
 * with the command classified `safe` or `read-only`.
 */


/**
 * An allowlisted binary carrying a flag that makes it write or execute.
 *
 * Keyed on `effectiveCommandIndex`, not `parseSegments`. `parseSegments`
 * (`parseWords`) only steps over a privilege prefix (`sudo`, `su`, …), not an
 * exec wrapper (`env`, `nohup`, `timeout`, …), so `env sort
 * --compress-program=X` read `head` as `"env"` — not in `DISQUALIFYING_ARGS`
 * — and the flag went unnoticed. `effectiveCommandIndex` already reads past
 * both, which is what `operandsAreData` and `readsProgramFromStdin` use it
 * for. Deliberately not fixed by changing `parseWords` itself:
 * `invokedWords` also reads it, and widening what counts as "the command"
 * there is a different, larger change this fix does not take on.
 */
function hasDisqualifyingArgs(command: string, dialect: ShellDialect = 'posix'): boolean {
  return tokenizeSegments(command, dialect).some((words) => {
    const idx = effectiveCommandIndex(words);
    if (idx === -1) return false;
    const rule = DISQUALIFYING_ARGS[stripPath(words[idx])];
    return rule !== undefined && words.slice(idx + 1).some((arg) => rule.test(arg));
  });
}

function invokedWords(command: string, dialect: ShellDialect = 'posix'): string[] {
  const invoked: string[] = [];

  for (const { head, args } of parseSegments(command, dialect)) {
    invoked.push(head);

    // `systemctl reboot` restarts the host. Reading a unit that happens to be
    // named after a power action is rare enough that erring towards refusal
    // here costs little.
    if (ACTION_MULTIPLEXERS.has(head)) {
      invoked.push(...args.filter((w) => !w.startsWith('-')).map(stripPath));
    }
  }

  return invoked;
}

const SHELLS = new Set(['sh', 'bash', 'zsh']);
const DOWNLOADERS = new Set(['curl', 'wget']);

/**
 * A download piped into a shell.
 *
 * Split on `|` rather than reading the whole string, so cost is linear in the
 * command's length no matter how the two halves are spaced. `||` produces an
 * empty part between them, and this deliberately still matches: `curl x || sh`
 * runs a shell when the download fails, which is not meaningfully safer than
 * running one when it succeeds.
 */
function pipesDownloadIntoShell(command: string, dialect: ShellDialect = 'posix'): boolean {
  // One head per pipe stage. Splitting on every separator would make `curl -O x;
  // bash build.sh` — download, then run a local script — match a rule whose label says
  // "piping a download into a shell", on a list that cannot be switched off.
  const segments = tokenizeSegmentsDetailed(command, true, dialect);
  const heads = segments
    .filter((segment, i) => i === 0 || segment.sep === '|')
    .map((segment) => parseWords(segment.words)?.head);
  const firstDownload = heads.findIndex((h) => h !== undefined && DOWNLOADERS.has(h));
  if (firstDownload === -1) return false;
  return heads.slice(firstDownload + 1).some((h) => h !== undefined && SHELLS.has(h));
}

/** `dd … of=/dev/sda` — writing an image straight onto a block device. */
function writesToDevice(command: string, dialect: ShellDialect = 'posix'): boolean {
  return parseSegments(command, dialect).some(
    ({ head, args }) => head === 'dd' && args.some((a) => a.startsWith('of=/dev/')),
  );
}

/**
 * `chown -R … /` — a recursive chown whose target is the filesystem root.
 *
 * The last non-flag argument is the target; `chown -R app:app /srv/app` is
 * ordinary and stays allowed.
 */
function chownsRoot(command: string, dialect: ShellDialect = 'posix'): boolean {
  return parseSegments(command, dialect).some(({ head, args }) => {
    if (head !== 'chown' || !args.includes('-R')) return false;
    const positional = args.filter((a) => !a.startsWith('-'));
    return positional[positional.length - 1] === '/';
  });
}

/** A forbidden rule, paired with wording a refusal can quote back. */
interface ForbiddenRule {
  label: string;
  test: (command: string, dialect: ShellDialect) => boolean;
}

const FORBIDDEN_RULES: ForbiddenRule[] = [
  ...FORBIDDEN_PATTERNS.map((re) => ({
    label: String(re),
    test: (c: string, dialect: ShellDialect) => matchesEitherForm(c, (form) => re.test(form), dialect),
  })),
  {
    label: 'invoking a power-state command (shutdown, reboot, halt, poweroff) or eval',
    test: (command, dialect) => invokedWords(command, dialect).some((w) => FORBIDDEN_INVOCATIONS.has(w)),
  },
  {
    label: 'piping a download into a shell (curl or wget into sh, bash or zsh)',
    test: (c, dialect) => pipesDownloadIntoShell(c, dialect),
  },
  { label: 'dd writing to a block device (of=/dev/…)', test: (c, dialect) => writesToDevice(c, dialect) },
  { label: 'a recursive chown of the filesystem root', test: (c, dialect) => chownsRoot(c, dialect) },
];

/**
 * Which never-allowed rule this command trips, or null. The single entry point:
 * FORBIDDEN_PATTERNS is deliberately not exported, because half of the list
 * lives in FORBIDDEN_RULES and a caller checking only the regexes would quietly
 * permit `sudo reboot`.
 */
export function findForbiddenMatch(command: string, depth = 0): string | null {
  // The engine calls this directly, so it is a decision point of its own and
  // reads both dialects like `classifyCommand` does: a refusal under either
  // reading is a refusal. The destructive-class consultation *inside* a
  // dialect pass (`isDestructive`) stays in-dialect — that pass is already one
  // reading of the whole string.
  if (command.includes('\\')) {
    const windows = findForbiddenMatchInDialect(command, depth, 'windows');
    if (windows !== null) return windows;
  }
  return findForbiddenMatchInDialect(command, depth, 'posix');
}

function findForbiddenMatchInDialect(command: string, depth: number, dialect: ShellDialect): string | null {
  for (const rule of FORBIDDEN_RULES) {
    if (rule.test(command, dialect)) return rule.label;
  }

  // The same carriers the class scan reads, for the same reason. This list is the
  // one unconditional rule in the policy — forbidden regardless of role, tier or
  // approval — and it was decided from the outer command alone, so
  // `sh -c "shutdown -h now"` and `echo $(shutdown -h now)` were not forbidden.
  // They still classified `destructive`, which on the `prod` tier degrades an
  // absolute `deny` into `require-approval`: a rule that answers "never" became
  // one a human can click through.
  //
  // `speculativeOperands: false` — the maintainer's ruling. `nestedCommands`'
  // catch-all is a guess about an unrecognised binary's operands, and this loop
  // feeds the one unconditional rule in the policy: a guess may raise a
  // command's class, which role, tier and approval still get to weigh in on,
  // but it must not manufacture a refusal nobody can override. Measured before
  // this parameter existed: `git commit -m 'reboot the worker pool'` was a hard
  // deny on an admin profile with `approvalPolicy: 'auto'`, because the catch-all
  // read the quoted commit message as an operand starting with a forbidden word.
  // `$()`, backticks and `sh -c` are certain carriers, not guesses — the shell
  // really does run what they hold — and are unaffected: they are pushed by
  // `nestedCommands` regardless of this flag.
  if (depth >= MAX_NESTING_DEPTH) return null;
  for (const inner of nestedCommands(command, false, dialect)) {
    const match = findForbiddenMatchInDialect(inner, depth + 1, dialect);
    if (match !== null) return match;
  }
  return null;
}

export function isForbidden(command: string, dialect: ShellDialect = 'posix'): boolean {
  return findForbiddenMatchInDialect(command, 0, dialect) !== null;
}

/**
 * Commands that are destructive but legitimate under approval — e.g.
 * `rm -rf /tmp/build`, which must NOT be confused with `rm -rf /`.
 */
const DESTRUCTIVE_PATTERNS: RegExp[] = [
  /rm\s+-rf?\s+\//,
];

/**
 * Everything that classifies as destructive: forbidden commands included.
 *
 * Goes through isForbidden() rather than the regex list, so a command caught by
 * an invocation rule is classified destructive too — and, just as importantly,
 * reading a log that mentions `reboot` is no longer classified destructive
 * either.
 */
function isDestructive(command: string, dialect: ShellDialect = 'posix'): boolean {
  return (
    isForbidden(command, dialect) ||
    matchesEitherForm(command, (form) => DESTRUCTIVE_PATTERNS.some((re) => re.test(form)), dialect)
  );
}

const LEADING_PRIVILEGE_PREFIXES = [
  /^\s*sudo\b/,
  /^\s*su\b/,
  /^\s*doas\b/,
  /^\s*pkexec\b/,
];

export function extractBinary(command: string, dialect: ShellDialect = 'posix'): string {
  // The first segment's words, so quoting is resolved — `s"u"do id` used to report
  // `s"u"do` in the audit record and the refusal message. Reading the normalised whole
  // command instead would be wrong in the other direction: it rejoins segments with
  // `; `, so `ls | grep x` would report `ls;`, and this name reaches the audit record,
  // the OTel span and OPA's input (#134). A separator is not a binary.
  let cmd = (tokenizeSegments(command, dialect)[0] ?? []).join(' ').trim();
  for (const prefix of LEADING_PRIVILEGE_PREFIXES) {
    cmd = cmd.replace(prefix, '').trim();
  }
  if (cmd.startsWith('-c ')) {
    cmd = cmd.slice(3).trim();
  }
  const parts = cmd.split(/\s+/);
  return parts[0] || '';
}

/**
 * The word a segment will actually execute, read past anything that is not it.
 *
 * Distinct from `elevatedBinary`, which answers "does this ask for elevation".
 * This answers "what is the name of the thing that runs", so it can be asked
 * whether that name is knowable at all.
 */
function effectiveCommandWord(words: string[]): string | null {
  const i = effectiveCommandIndex(words);
  return i === -1 ? null : words[i];
}

/**
 * The position of that word, for callers that need to read its arguments.
 *
 * Deriving the word from the index rather than searching for it afterwards is what keeps
 * `sh x sh -c 'sudo id'` from finding the wrong `sh`.
 */
function effectiveCommandIndex(words: string[]): number {
  let i = 0;
  while (i < words.length) {
    const raw = words[i];
    const word = stripPath(unquote(raw));

    if (PRIVILEGE_PREFIXES.has(word) || EXEC_WRAPPERS.has(word)) {
      i++;
      while (i < words.length && words[i].startsWith('-')) {
        const consumesValue = PREFIX_VALUE_FLAGS.has(words[i]);
        i++;
        if (consumesValue) i++;
      }
      continue;
    }
    if (ASSIGNMENT.test(raw) || raw.startsWith('-') || BARE_NUMERIC.test(raw)) {
      i++;
      continue;
    }
    return i;
  }
  return -1;
}

/**
 * Whether this segment's command word is one whose operands are data.
 *
 * The carrier scan reads every word, because a wrapper this file does not list would
 * otherwise hide `sh -c`. The cost is that an outer tool's own flag can be mistaken for an
 * interpreter's: `grep python3 -c /var/log/x` counts lines, and `-c` is also python's
 * program flag. An allowlisted command is one this file already vouches for as reading
 * rather than running, so its arguments are subjects, not commands — the positive form of
 * the mention-vs-invocation rule at #91. `find` keeps its `-exec` scan, which is separate.
 */
function operandsAreData(words: string[]): boolean {
  const idx = effectiveCommandIndex(words);
  if (idx === -1) return false;
  return READERS[stripPath(unquote(words[idx]))]?.operandsAreData === true;
}

/**
 * Whether an interpreter name is the value of the flag before it rather than a command.
 *
 * The scan looks at every word so that a carrier behind an unlisted wrapper is not lost,
 * and requires a program-bearing flag to follow before it believes one. That is not quite
 * enough: `grep -e perl -e python` puts `perl` after a flag and a second `-e` after it,
 * which reads as perl being handed a program. A search term is not a command.
 *
 * The test is deliberately narrow — the preceding flag must be one of *this interpreter's*
 * program flags. Any flag at all was too much: `nsenter -t 1 -m sh -c 'sudo id'` puts the
 * shell after `-m`, which takes no value, and dropping it lost a real elevation. Nothing
 * here can know an arbitrary tool's grammar, so `sed -n perl -e p` — a shape no one
 * writes — is still read as a carrier.
 */
/**
 * Words that may sit between an interpreter and its program flag.
 *
 * A quoted empty word survives tokenization now, because a positional reader
 * cannot work with an argument list that silently drops operands. That made an
 * empty word break this chain: `sh '' -c 'sudo id'` stopped finding the program
 * and fell from `privileged` to `safe`. Real `sh` does not run it either — it
 * reports "No such file or directory" and exits, measured — but over-reporting a
 * command that fails costs nothing and under-reporting one is the whole hazard,
 * so the chain keeps the answer it had.
 */
function skippableBetweenFlags(word: string): boolean {
  return word === '' || word.startsWith('-');
}

/**
 * Whether `word` is a spelling of `flag`, honouring case-insensitivity when asked.
 *
 * Scoped per call, never globally: pwsh/powershell's own parameter binder resolves
 * `-ENC`, `-Enc` and `-enc` to the same parameter, but `-E` and `-e` are two different
 * flags to perl. Every caller here is told explicitly, per invocation, whether the
 * interpreter it is matching against is one of the case-insensitive ones — folding case
 * is never the default.
 */
function sameFlag(word: string, flag: string, caseInsensitive: boolean): boolean {
  return caseInsensitive ? word.toLowerCase() === flag.toLowerCase() : word === flag;
}

function isFlagValue(words: string[], i: number, flags: string[], caseInsensitive = false): boolean {
  if (i === 0) return false;
  const previous = words[i - 1];
  if (!(previous.length > 1 && previous.startsWith('-'))) return false;
  return flags.some((f) => sameFlag(previous, f, caseInsensitive));
}

/**
 * A program an interpreter was handed on its command line, and the word that carried it.
 */
interface FlaggedProgram {
  program: string;
  /**
   * The canonical entry of `flags` that matched — the spelling in the table, not
   * necessarily the literal word on the command line. `-EC` case-insensitively matches
   * `-e`, and this reports `-e`, so a caller comparing against the table's own spellings
   * (deciding whether to decode, say) never has to re-derive which flag a case-folded or
   * clustered word stood for.
   */
  flag: string;
  /**
   * The index into `words` of the word that carried `program` — the whole word, whether
   * the program is that word verbatim or embedded in it (`-csudo id` attaches the program
   * to the flag's own word, so `index` names that word, not a later one). A caller tracking
   * which operands an interpreter actually consumed, rather than merely "some interpreter
   * consumed something in this segment", needs the position, not just the text.
   */
  index: number;
}

/**
 * The program an interpreter was handed on its command line, or null.
 *
 * Only flags may sit between the interpreter and its flag; anything else means this was
 * not that kind of invocation, which is what keeps `python3 script.py` — a program this
 * cannot read either, but one every deployment runs — out of the gate. That rule holds
 * for every interpreter here except pwsh/powershell (see `tolerateUnknownWordsAtHead`):
 * real POSIX interpreters stop parsing their own options at the first positional
 * argument — `python3 script.py -c 'evil'` hands `-c evil` to the script as `argv`, not
 * to python — so treating a bare word as "not this kind of invocation" is correct for
 * them, not merely convenient.
 *
 * Returns which of `flags` matched alongside the program, not just the program text, so
 * a caller can tell `-EncodedCommand` from its `-e` abbreviation apart from every other
 * program-bearing word — decoding is specific to that one flag, and both spellings reach
 * here as an ordinary match.
 *
 * @param tolerateUnknownWordsAtHead pwsh/powershell's own argument parser walks the
 *   whole command line looking for named parameters it recognises and does not stop at
 *   an unrecognised one's value (`-ExecutionPolicy Bypass`) the way a POSIX interpreter
 *   stops at its first positional argument. Only takes effect when `from` is the
 *   segment's *effective* command word — `effectiveCommandIndex(words)`, which reads
 *   past a privilege prefix or an exec wrapper (`env`, `nohup`, `timeout`, …), not merely
 *   position 0. `from === 0` missed exactly the shape those wrappers exist to describe:
 *   `env pwsh -ExecutionPolicy Bypass -EncodedCommand …` put `pwsh` at index 1, the
 *   tolerance never engaged, and the interpreter loop's own flag-walk gave up at
 *   `Bypass` before ever reaching `-EncodedCommand` — classified `safe`. Still unambiguous
 *   about *which* word is being invoked, not a value or a search term this file has no
 *   business reinterpreting (`grep -e perl -e python` never reaches here with this set,
 *   because `perl` is not the segment's effective command word and isn't pwsh-family
 *   regardless; nor is `customtool --search pwsh …`, where `customtool` is). Structural,
 *   not a list of pwsh's value-taking flags: this file does not need to know
 *   `-ExecutionPolicy` exists to stop being confused by it.
 */
function programAfterFlag(
  words: string[], from: number, flags: string[], caseInsensitive = false,
  tolerateUnknownWordsAtHead = false,
): FlaggedProgram | null {
  const tolerateUnknownWords = tolerateUnknownWordsAtHead && from === effectiveCommandIndex(words);
  for (let j = from + 1; j < words.length; j++) {
    const word = words[j];
    const exact = flags.find((f) => sameFlag(word, f, caseInsensitive));
    if (exact !== undefined) {
      // A subcommand — a program-bearing word that is not itself a `-` flag, such as
      // `deno`'s `eval` — may still have its own options before the code: `deno eval
      // --unstable <code>` is one invocation, not two. A real flag like `-c` or
      // `-Command` never has anything of its own between it and the program, so this
      // only widens the subcommand case.
      let k = j + 1;
      if (!exact.startsWith('-')) {
        while (k < words.length && skippableBetweenFlags(words[k])) k++;
      }
      const program = words[k];
      return program === undefined ? null : { program, flag: exact, index: k };
    }
    // Deliberately case-SENSITIVE even for pwsh/powershell: this branch exists for a
    // value glued directly onto a short flag with no separating space (`-csudo id`).
    // Folding case here as well made `-ExecutionPolicy` — a real pwsh option this file
    // does not otherwise track — case-insensitively start with `-e` and get read as
    // `-e` plus an attached `xecutionPolicy`, which swallowed `-ExecutionPolicy Bypass
    // -Command 'sudo id'` into `destructive` and, worse, made `foundProgram` true so
    // the catch-all below never ran. Every case-insensitive spelling the table needs
    // to accept (`-enc`, `-ec`, `-EC`, `-ENC`, `-E`, `-EncodedCOMMAND`, `-COMMAND`,
    // `-C`, …) is already reached through the exact match above or the cluster match
    // below, so this branch does not need to fold case to cover them.
    const attached = flags.find((f) => word.startsWith(f) && word.length > f.length);
    if (attached !== undefined) {
      const rest = word.slice(attached.length);
      // `sh -c'sudo id'` tokenises to `-csudo id`, so the program is attached. `bash -cx`
      // is a flag cluster and the program is the next word. A space, or the `=` of
      // `--eval=…`, is what tells them apart: a cluster is letters only.
      if (/\s/.test(rest) || rest.startsWith('=')) {
        return { program: rest.replace(/^=/, ''), flag: attached, index: j };
      }
      const program = words[j + 1];
      return program === undefined ? null : { program, flag: attached, index: j + 1 };
    }
    // The program flag need not lead the cluster: `bash -xc 'sudo id'` runs exactly what
    // `bash -cx 'sudo id'` runs, and a prefix test saw the second and missed the first.
    const clusterFlag = clusterCarriesFlag(word, flags, caseInsensitive);
    if (clusterFlag !== null) {
      const program = words[j + 1];
      return program === undefined ? null : { program, flag: clusterFlag, index: j + 1 };
    }
    if (!skippableBetweenFlags(word) && !tolerateUnknownWords) return null;
  }
  return null;
}

/** How much base64 is worth decoding before the answer stops changing. */
const MAX_ENCODED_CHARS = 64 * 1024;

/**
 * The command inside `-EncodedCommand`, or null.
 *
 * PowerShell encodes UTF-16LE, so decoding as utf8 yields text with a NUL between
 * every character and no pattern matches it. `Buffer.from(x, 'base64')` never
 * throws — it drops characters outside the alphabet — so malformed input produces
 * a wrong answer rather than an exception, and the caller must treat null and
 * nonsense alike: the flag alone has already made the command `destructive`.
 *
 * Reads a bounded, 4-aligned PREFIX rather than refusing outright past the limit. A
 * refusal is a downgrade path: it turns "pad the payload past 64 KiB" into a way to
 * trade `privileged` for `destructive`, which is strictly better for whoever is padding
 * it. 4-aligned because base64 decodes in groups of four characters to three bytes;
 * truncating mid-group corrupts the last partial character instead of just dropping
 * trailing content the decode was never going to reach anyway.
 */
function decodedPowerShellCommand(operand: string): string | null {
  const prefix = operand.length > MAX_ENCODED_CHARS
    ? operand.slice(0, MAX_ENCODED_CHARS - (MAX_ENCODED_CHARS % 4))
    : operand;
  const decoded = Buffer.from(prefix, 'base64').toString('utf16le');
  return decoded.includes('�') || decoded.trim() === '' ? null : decoded;
}

/**
 * What follows a short flag inside a single-dash cluster, or the `flags` entry it
 * carries, or null if it carries none.
 *
 * Clusters only — a run of single letters after one dash. Long flags and attached values
 * are handled before this is reached. Returns the canonical flag rather than a boolean
 * for the same reason `programAfterFlag` does: a caller deciding whether to decode
 * compares against the table's own spellings, not against whatever letters happened to
 * be clustered together.
 */
function clusterCarriesFlag(word: string, flags: string[], caseInsensitive = false): string | null {
  // Three letters at most. `/^-[A-Za-z]+$/` alone also matches every single-dash long
  // option, and `find`'s predicates are full of them: `-type` contains perl's `-e`, so
  // `find . -name perl -type f` read as a carrier and asked for approval.
  if (!/^-[A-Za-z]{2,3}$/.test(word)) return null;
  const body = caseInsensitive ? word.slice(1).toLowerCase() : word.slice(1);
  const shortFlags = flags.filter((flag) => flag.length === 2);
  // A cluster is letters only, so whatever follows the program flag is more flags — the
  // program itself is always the next word.
  //
  // Scanned by the BODY's own character order, not the table's order: `-ec` must
  // resolve to `-e` (so a caller deciding whether to decode sees `-e`), not to `-c`
  // just because `-c` happens to sit first in pwsh's `programBearingWords`. The first
  // letter in the cluster is the one the invocation leads with.
  for (const letter of body) {
    const match = shortFlags.find((flag) => (caseInsensitive ? flag[1].toLowerCase() : flag[1]) === letter);
    if (match !== undefined) return match;
  }
  return null;
}

/** Spellings of "the program is on standard input" that look like a file operand. */
const STDIN_PATHS = new Set(['-', '/dev/stdin', '/dev/fd/0', '/proc/self/fd/0']);

/**
 * Whether a segment's command word is an interpreter with no program of its own.
 *
 * `echo "sudo id" | bash` hands the program over on stdin, where there is nothing to
 * read. This holds for the shells too — `readable` is about a `-c` argument, and there is
 * no `-c` here. Requiring that no operand follow is what keeps `cat data | python3
 * app.py` out of it: there the pipe carries data, not a program.
 */
function readsProgramFromStdin(words: string[]): boolean {
  const idx = effectiveCommandIndex(words);
  if (idx === -1) return false;
  const bin = stripPath(words[idx]);
  // Interpreters only. awk's one program-from-stdin form is `awk -f -`, already gated as a
  // file flag; every other piped awk reads data, not a program.
  const spec = resolveInterpreter(bin);
  if (spec === undefined) return false;
  const flags = spec.programBearingWords;
  let sawStdinFlag = false;
  for (let j = idx + 1; j < words.length; j++) {
    const word = words[j];
    if (flags.some((f) => word === f || word.startsWith(f))) return false;
    // `--` ends the interpreter's own arguments; what follows is `$1..$n`, so a program
    // still has to come from somewhere and `bash -s -- arg` reads stdin.
    // `-s` says outright that the script comes from stdin, so everything after it is
    // `$1..$n` whatever it looks like.
    if (word === '-s') { sawStdinFlag = true; continue; }
    // `--` ends the interpreter's own arguments. Without `-s` the next word is the script
    // itself, so `bash -- process.sh` reads a file while `bash -s -- arg` reads stdin.
    if (word === '--') {
      const next = words[j + 1];
      return sawStdinFlag || next === undefined || STDIN_PATHS.has(next);
    }
    if (STDIN_PATHS.has(word)) return true;
    if (!word.startsWith('-')) return false;
  }
  return true;
}

/**
 * Whether any segment hands a program to something this file cannot read.
 *
 * Keyed on the segment's command word, never on any word that happens to name an
 * interpreter: matching a mention rather than an invocation is the defect this file
 * records fixing as #91, and `cat /usr/bin/python3` names an interpreter without running
 * one. A program-bearing flag must actually be present, so naming one is not enough.
 */
/**
 * What this segment's awk program does, or null when it runs no awk program.
 *
 * Keyed on `effectiveCommandIndex` — the word that actually runs — never on any
 * word that happens to say "awk". `readlink -f /usr/bin/awk` and `man awk` name
 * an interpreter without invoking one, and an earlier attempt that scanned every
 * word classified both destructive.
 */
function awkFindings(words: string[]): AwkFindings | null {
  const idx = effectiveCommandIndex(words);
  if (idx === -1) return null;
  if (!AWK_NAMES.has(stripPath(unquote(words[idx])))) return null;
  // No second `unquote`. `tokenizeSegmentsDetailed` has already resolved shell
  // quoting, and inside single quotes a backslash is literal — so the program
  // word arrives exactly as awk will see it. Unquoting again ran
  // `.replace(/\\(.)/g, '$1')` over the *awk program*, which deleted the
  // backslash of every escape it contains. Measured, all three ways that broke:
  // `system("\163udo id")` became `system("163udo id")` and classified `safe`;
  // `s="\""` collapsed and re-paired the string delimiters so the code between
  // them was read as string content; and `print "\\"` became an unterminated
  // string, gating ordinary awk as unreadable.
  return readAwkInvocation(words.slice(idx + 1));
}

/**
 * Whether any segment's awk program writes a file, or could not be read.
 *
 * The commands an awk program hands to a shell are not here: `nestedCommands`
 * emits those so they are classified as themselves, which is how
 * `awk 'BEGIN{system("sudo id")}'` comes out `privileged` rather than flattened
 * to the `destructive` this function reports.
 */
function hasDangerousAwk(command: string, dialect: ShellDialect = 'posix'): boolean {
  for (const { words } of tokenizeSegmentsDetailed(command, true, dialect)) {
    const findings = awkFindings(words);
    if (findings === null) continue;
    if (findings.writesFile || findings.unreadable) return true;
    // `print … | "sh"` is the awk spelling of `echo "sudo id" | sh`, which this
    // file already gates through `readsProgramFromStdin`. Classifying the target
    // alone says `sh`, which is not dangerous; what is dangerous is what awk
    // prints into it, and that is assembled at run time. So it is the same
    // "we cannot tell" this module reports for `-f progfile`.
    for (const target of findings.pipedInto) {
      const stage = tokenizeSegmentsDetailed(target, true, dialect)[0];
      if (stage !== undefined && readsProgramFromStdin(stage.words)) return true;
    }
  }
  return false;
}

function hasUnreadableProgram(command: string, dialect: ShellDialect = 'posix'): boolean {
  const segments = tokenizeSegmentsDetailed(command, true, dialect);
  for (let i = 0; i < segments.length; i++) {
    const { words, sep } = segments[i];
    if (sep === '|' && readsProgramFromStdin(words)) return true;

    if (!operandsAreData(words)) {
      for (let j = 0; j < words.length; j++) {
        const spec = resolveInterpreter(stripPath(unquote(words[j])));
        if (spec === undefined || spec.readable) continue;
        // Same case-insensitivity as `nestedCommands`'s interpreter loop, and for the
        // same reason: pwsh/powershell's own parameter binder does not distinguish
        // `-EC` from `-ec`, so neither should this.
        const caseInsensitive = spec.programBearingWords.includes('-EncodedCommand');
        if (isFlagValue(words, j, spec.programBearingWords, caseInsensitive)) continue;
        if (programAfterFlag(words, j, spec.programBearingWords, caseInsensitive, caseInsensitive) !== null) return true;
      }
    }

  }
  return false;
}

/**
 * Whether any segment runs a command this process cannot name.
 *
 * The class — and with it the approval gate — is decided from the literal text of
 * the command word. A word carrying `$` or a backtick is a name the shell resolves
 * at run time, so `$S id` was classified as though `$S` were a binary, and came
 * out `safe` (GHSA-fj9r-f47j-c73x).
 *
 * Resolving the variable is not the answer and cannot be: a session run keeps the
 * caller's shell state, so `S=sudo` and `$S id` can arrive as two separate calls,
 * and a variable exported in the target's own profile is never visible here at
 * all. What is answerable is whether we know the name — and when we do not, saying
 * so is the only honest class.
 *
 * Only the command word, never the arguments. `echo $HOME` names a command we know;
 * promoting that would put a prompt on most ordinary shell usage.
 */
function hasUnnameableCommand(command: string, dialect: ShellDialect = 'posix'): boolean {
  for (const words of tokenizeSegments(command, dialect)) {
    const head = effectiveCommandWord(words);
    if (head !== null && /[$`]/.test(head)) return true;
  }
  return false;
}

/**
 * Commands this server synthesises rather than a user typing them.
 *
 * These reach the classifier as text like `sftp:upload /etc/passwd`, and no rule named
 * them, so every one fell through to the default `safe` — a class the default rules grant
 * to `operator` on `prod`. Writing an arbitrary file to the target is not `safe`: it is
 * the same authority as `rm`, spelled through a different tool, and it reaches
 * `~/.ssh/authorized_keys` without touching a shell. Opening a session is the same
 * argument, since it hands over an interactive shell.
 *
 * `session:close` is deliberately absent: it is a release rather than an acquisition, and
 * no tool advertises it as a read.
 *
 * `sftp:download` and `sftp:list` are absent for a different reason now. They *are*
 * lowered to `read-only` — by `READ_ONLY_SYNTHETIC` near the top of this file — because
 * both tools advertise `readOnlyHint: true` and `safe` is refused outright by a `readOnly`
 * profile, so the one profile class the annotation targeted was the one that could not run
 * them (#217). They cannot be lowered *here*, because this table is a floor and a floor
 * can only raise; an entry would be inert. That inertness is the trap worth keeping
 * written down — it produced two wrong attempts during #212.
 *
 * What this paragraph used to say, and what was wrong with it: that the effect anyone
 * wants from lowering `sftp:list` — letting a `viewer` list a remote directory — is "a
 * binding change, not a classification one". It is a classification one, because the tool
 * ships an annotation and a description that both claim read-only, and a policy that
 * disagreed with them was the defect rather than the binding.
 *
 * `sftp:upload-file` and `sftp:download-file` are `destructive` because each writes a
 * file: the first on the remote host, the second inside the operator's transfer root.
 * Without a floor both classify `safe` from the verb alone, which would let an `operator`
 * write to disk through a tool nobody had approved for it.
 */
const SYNTHETIC_CLASSES: Record<string, CommandClass> = Object.assign(
  Object.create(null) as Record<string, CommandClass>,
  {
    'sftp:upload': 'destructive',
    'sftp:upload-file': 'destructive',
    'sftp:download-file': 'destructive',
    'session:open': 'destructive',
    // A raw PTY hands over an interactive byte stream the classifier cannot
    // see into — the same authority argument as `session:open`, and the load-
    // bearing half of the PTY safety plan's layer ① (owner-ratified U2): the
    // human gate lives HERE, at open, because nothing after open is classifiable.
    'pty:open': 'destructive',
    // A tunnel is an authority grant: whatever the operator can reach, the
    // agent can now reach through the listener. The synthesized command embeds
    // the full listen→target pair, so `[policy].denylist` rules written against
    // a target (`internal-db:5432`) refuse the tunnel before it opens.
    'forward:open': 'destructive',
  },
);

/** The first word, tokenised — the synthetic verb when there is one. */
function syntheticVerb(command: string, dialect: ShellDialect = 'posix'): string {
  return tokenizeSegments(command, dialect)[0]?.[0] ?? '';
}

/**
 * The class of a command, and of everything it carries.
 *
 * A command that carries another decides nothing on its own: the remote shell expands
 * `$(...)`, backticks, `<(...)` and `sh -c` and runs what is inside, so the class is the
 * higher of the two. The scan for carriers already existed, but it *replaced* the outer
 * class instead of raising it, and only when the inner class was above `safe` — so
 * `sudo sh -c 'rm -rf /etc'` reported the inner `destructive` and lost the outer
 * `privileged`, which on `prod` is the difference between a prompt and a refusal.
 * Taking the maximum is what makes the scan unable to lower anything.
 */
export function classifyCommand(command: string, depth = 0): ParsedCommand {
  // One string, two dialects, and the class is the worse of the two readings:
  // the classifier cannot know whether the host shell reads a backslash as an
  // escape or as a path separator, so policy must hold on whichever host
  // receives the command (GHSA-972x-g47g-3922). A command without a backslash
  // is byte-identical under both dialects, so it keeps the single pass.
  if (!command.includes('\\')) return classifyCommandInDialect(command, depth, 'posix');
  const posix = classifyCommandInDialect(command, depth, 'posix');
  const windows = classifyCommandInDialect(command, depth, 'windows');
  return CLASS_RANK[windows.class] > CLASS_RANK[posix.class] ? windows : posix;
}

function classifyCommandInDialect(command: string, depth: number, dialect: ShellDialect): ParsedCommand {
  const trimmed = command.trim();
  const outer = classifyOuter(trimmed, dialect);

  if (depth >= MAX_NESTING_DEPTH) {
    // Nesting this deep is not something an operator writes, and we have stopped
    // reading. Refusing to guess is the only answer consistent with the rest of this
    // file.
    return { binary: outer.binary, fullCommand: trimmed, class: 'privileged' as CommandClass };
  }

  let highest = outer;

  // A floor, not a verdict. Returning the synthetic class outright would put it above
  // the elevation and never-allowed checks, so `sftp:upload /tmp/x; sudo id` would
  // record `destructive` where the command is `privileged`.
  const verb = syntheticVerb(trimmed, dialect);
  const floor = SYNTHETIC_CLASSES[verb];
  if (floor !== undefined && CLASS_RANK[floor] > CLASS_RANK[highest.class]) {
    highest = { binary: verb, fullCommand: trimmed, class: floor };
  }

  for (const inner of nestedCommands(trimmed, true, dialect)) {
    const parsed = classifyCommandInDialect(inner, depth + 1, dialect);
    // `binary` follows the winning side deliberately: it is what the audit record and
    // the refusal message name, and naming the outer `echo` would describe the wrong
    // process as the one that ran as root.
    if (CLASS_RANK[parsed.class] > CLASS_RANK[highest.class]) highest = parsed;
  }

  // `readOnlyRejection` only ever describes the outer command's own grammar
  // rejection, and only means anything when that is also what decided the
  // final class. `highest === outer` (reference equality) is exactly that
  // condition: the synthetic floor and the nested-command loop above only
  // ever replace `highest` with something of strictly higher rank than
  // `outer`'s, so if either one fired, `highest` is no longer `outer` and the
  // rejection — which was never a fact about the synthetic verb or the nested
  // command anyway — is correctly left off.
  const result: ParsedCommand = { binary: highest.binary, fullCommand: trimmed, class: highest.class };
  if (highest === outer && outer.readOnlyRejection) {
    result.readOnlyRejection = outer.readOnlyRejection;
  }
  return result;
}

/**
 * `classifyOuter`'s own return shape, carrying the word a reader's grammar
 * rejected so a later stage can name it in a refusal message. `classifyCommand`
 * copies this onto its own `ParsedCommand` result — but only when `outer` is
 * also the winning side, see the comment above.
 */
type ClassifiedOuter = ParsedCommand & { readOnlyRejection?: { binary: string; word: string } };

/** The class of the command itself, reading none of what it carries. */
function classifyOuter(trimmed: string, dialect: ShellDialect): ClassifiedOuter {
  const binary = extractBinary(trimmed, dialect);
  const fullCommand = trimmed;

  // `binary` names the subject of the class. For everything below it is the
  // leading command; here it is the one that runs as root, which are the same
  // thing only when the prefix leads.
  const elevated = elevatedBinaryOf(trimmed, dialect);
  if (elevated !== null) {
    return { binary: elevated, fullCommand, class: 'privileged' as CommandClass };
  }

  if (hasUnreadableProgram(trimmed, dialect) || hasDangerousAwk(trimmed, dialect)
    || isDestructive(trimmed, dialect) || hasDisqualifyingArgs(trimmed, dialect)) {
    return { binary, fullCommand, class: 'destructive' as CommandClass };
  }

  // Below this point every branch assumes the command word names something we
  // recognised. When it is a variable expansion it names nothing we can check, so
  // the allowlist must not be consulted — `$S` is not on it, and falling through to
  // the default made an unknown command `safe`.
  //
  // `destructive` rather than `privileged`: this is "we cannot tell", not "this is
  // root". It gates on approval instead of refusing outright, which keeps
  // `$PREFIX/bin/tool` usable for a role that holds `destructive` on the tier.
  if (hasUnnameableCommand(trimmed, dialect)) {
    return { binary, fullCommand, class: 'destructive' as CommandClass };
  }

  const words = tokenizeSegments(fullCommand, dialect)[0] ?? [];
  const twoWordPrefix = words.slice(0, 2).join(' ');
  if (READ_ONLY_ALLOWLIST.has(binary) || READ_ONLY_ALLOWLIST.has(twoWordPrefix)
    || READ_ONLY_SYNTHETIC.has(binary)) {
    if (SHELL_CONTROL_CHARS.test(trimmed)) {
      return { binary, fullCommand, class: 'safe' as CommandClass };
    }

    // The SFTP verbs are synthesised by the tool layer, never typed by a caller,
    // so there is no argv for a grammar to read — READ_ONLY_SYNTHETIC stays
    // exactly as it was.
    if (READ_ONLY_SYNTHETIC.has(binary)) {
      return { binary, fullCommand, class: 'read-only' as CommandClass };
    }

    // Whichever key matched decides both which entry answers and how many
    // leading words are the command name rather than an argument: a two-word
    // entry's grammar reads words[2..], a one-word entry's reads words[1..].
    const matchedTwoWord = READ_ONLY_ALLOWLIST.has(twoWordPrefix);
    const readerName = matchedTwoWord ? twoWordPrefix : binary;
    const entry = READERS[readerName];
    const argWords = words.slice(matchedTwoWord ? 2 : 1);

    // An unquoted glob word is not a word this grammar can vouch for: the
    // shell replaces it with however many filenames it matches, and the
    // grammar's operand count — the thing it was about to prove — is false
    // before the binary runs. `'any'` entries are exempt: their claim is that
    // no option or operand of the binary writes or executes, so extra
    // operands from an expansion are still data.
    if (entry.grammar.args !== 'any') {
      const globWord = firstUnquotedGlobWord(fullCommand, true, dialect);
      if (globWord !== null) {
        return {
          binary,
          fullCommand,
          class: 'safe' as CommandClass,
          readOnlyRejection: { binary: readerName, word: globWord },
        };
      }
    }

    const match = matchesGrammar(argWords, entry.grammar);
    if (!match.ok) {
      return {
        binary,
        fullCommand,
        class: 'safe' as CommandClass,
        readOnlyRejection: { binary: readerName, word: match.word },
      };
    }

    return { binary, fullCommand, class: 'read-only' as CommandClass };
  }

  return { binary, fullCommand, class: 'safe' as CommandClass };
}

/**
 * The sentence a refusal appends when it carries a `readOnlyRejection`, worded
 * so the reason names the binary that would have qualified and the argv word
 * that cost it: "is not accepted there" rather than "is not one of them",
 * because most rejections are operand rules (`hostname NAME`, `sort /data`) or
 * a listed value flag missing its value, where "is not one of them" would be
 * false — it may be a perfectly good flag name, just not one bare or in this
 * position. One function so the engine's role-binding denial and
 * `read-command`'s `enforceClass` refusal never drift into two spellings of
 * the same sentence.
 */
function formatReadOnlyRejection(rejection: { binary: string; word: string }): string {
  // The rejected word can be the empty string — a quoted empty operand
  // (`hostname ""`) — and two bare backticks would render as a blank where
  // the word that cost the class should be. `""` is the shell's own spelling
  // of that operand.
  const word = rejection.word === '' ? '""' : rejection.word;
  return `\`${rejection.binary}\` is read-only only with the options and operands its grammar lists; ` +
    `\`${word}\` is not accepted there.`;
}

export {
  READ_ONLY_ALLOWLIST, READERS, READ_ONLY_SYNTHETIC, isDestructive, formatReadOnlyRejection,
};
