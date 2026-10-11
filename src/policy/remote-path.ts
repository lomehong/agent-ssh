/**
 * 一个远程路径，按 `[policy].denylist` 模式也应当看到的样子（#230）。
 *
 * 纯词法：不向目标机请求任何东西，因此相对路径保持相对，
 * 符号链接不跟随。它去掉的是「让规则看不见本来要针对的路径」的拼写——
 * `//`、`/./`、`..`、结尾分隔符——还把反斜杠 `\`
 * 也读作分隔符，于是 Windows 目标的 `C:\Users\a\.ssh\authorized_keys`
 * 也被看作 `C:/Users/a/.ssh/authorized_keys`。在 POSIX 目标上，
 * 含反斜杠的文件名可能因此在过去不会命中的地方命中；这只会放大拒绝面。
 *
 * 绝对路径——`/…` 或以盘符开头——不可能爬到自己的根之上。
 * 相对路径保留开头的 `..`，它没有任何可解析的对象。
 *
 * 不用 `node:path`：`posix.normalize` 让 `..` 爬过盘根（`C:/../x` →
 * `x`）并保留结尾分隔符，`win32.normalize` 返回反斜杠——
 * 而拒绝规则需要的是一种读法：正斜杠、永不向上爬。
 */
const DRIVE_LETTER = /^[A-Za-z]:$/;

export function normalizeRemotePath(path: string): string {
  const segments = path.replace(/\\/g, '/').split('/');
  let root: string | null = null;
  if (segments[0] === '') {
    root = '';
    segments.shift();
  } else if (DRIVE_LETTER.test(segments[0])) {
    root = segments.shift()!;
  }

  const kept: string[] = [];
  for (const segment of segments) {
    if (segment === '' || segment === '.') continue;
    if (segment === '..') {
      if (kept.length > 0 && kept[kept.length - 1] !== '..') kept.pop();
      else if (root === null) kept.push('..');
      continue;
    }
    kept.push(segment);
  }

  if (root === null) return kept.length > 0 ? kept.join('/') : '.';
  if (root === '') return kept.length > 0 ? `/${kept.join('/')}` : '/';
  return kept.length > 0 ? `${root}/${kept.join('/')}` : `${root}/`;
}

/**
 * 同一路径按 Win32 会解析成的样子，供不想依赖调用方拼写方式的
 * denylist 使用（#230）。
 *
 * 这里的每一步变换都在 Windows 测试虚拟机（Windows 11
 * build 26200）上经 SFTP 实测：下列拼写与规范拼写抵达同一个文件，
 * 因此「抓得住一种拼写、放走另一种」的规则是绕过，不是区别。
 *
 * - `\` 读作 `/`，同上。
 * - 每段结尾的成串点与空格被去除（`authorized_keys.` 与
 *   `authorized_keys..` 是同一个文件）。只由点组成的段
 *   （`a.../b`）因此整段消失，Win32 就是这么读的。
 * - `::` 后缀被切掉（`authorized_keys::$DATA` 是文件的默认流，
 *   不是另一个文件）。单个 `:` 原样保留：它命名的是另一个流，
 *   实测表明它到达的不是同一组字节。
 * - 盘符相对拼写（`C:x/…`，Windows 上相对该盘当前目录解析）
 *   锚定到盘符。实际解析到哪取决于本服务器看不见的进程状态；
 *   锚定是 fail-closed 的读法。
 * - `\\?\\` 与 `\\.\\` 设备前缀被去掉。SFTP 本身拒绝它们，但一条规则
 *   不应该非得知道这件事。
 * - UNC 拼写保留根（`\\server\\share\…` → `//server/share/…`），
 *   而普通读法会把它折叠掉；`..` 爬不过共享名。
 *
 * 大小写刻意不动——引擎以不区分大小写的方式测试这一读法，
 * 这也顺带覆盖了同一路径的大小写变体拼写。
 *
 * 两种 Windows 等价形式在任何词法读法之外，因为解析它们需要
 * 目标机自己的目录状态，它们是 README 里登记的残留项：
 * 8.3 短名（`AUTHOR~1`）与符号链接。
 *
 * 在 POSIX 目标上这些读法只会放大拒绝：真叫 `authorized_keys.` 的文件
 * 在那是另一个文件，但拒绝它是安全的方向，
 * 与上面的反斜杠同理。
 */
export function normalizeRemotePathForWindows(path: string): string {
  let slashed = path.replace(/\\/g, '/');
  if (slashed.startsWith('//?/') || slashed.startsWith('//./')) slashed = slashed.slice(4);

  const segments = slashed.split('/');
  let root: string | null = null;
  let rest = segments;
  if (segments[0] === '' && segments[1] === '') {
    // UNC 根：共享名就是 `..` 能爬到的最高处。
    root = `//${segments[2] ?? ''}/${segments[3] ?? ''}`;
    rest = segments.slice(4);
  } else if (segments[0] === '') {
    root = '/';
    rest = segments.slice(1);
  } else if (/^[A-Za-z]:/.test(segments[0])) {
    const drive = segments[0].slice(0, 2);
    const after = segments[0].slice(2);
    root = drive;
    rest = after === '' ? segments.slice(1) : [after, ...segments.slice(1)];
  }

  const kept: string[] = [];
  for (const segment of rest) {
    if (segment === '' || segment === '.') continue;
    if (segment === '..') {
      if (kept.length > 0 && kept[kept.length - 1] !== '..') kept.pop();
      else if (root === null) kept.push('..');
      continue;
    }
    const plain = segment.split('::')[0].replace(/[ .]+$/, '');
    if (plain === '') continue;
    kept.push(plain);
  }

  if (root === null) return kept.length > 0 ? kept.join('/') : '.';
  if (root === '/') return kept.length > 0 ? `/${kept.join('/')}` : '/';
  return kept.length > 0 ? `${root}/${kept.join('/')}` : `${root}/`;
}
