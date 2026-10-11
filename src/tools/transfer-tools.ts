import { z } from 'zod';
import { ErrorCode, McpError } from '@modelcontextprotocol/sdk/types.js';
import { redactText } from '../guard/redactor.js';
import { remotePathForAudit, sanitizeRemotePath } from '../guard/sanitizer.js';
import { SftpClient } from '../ssh/sftp.js';
import type { SftpStat } from '../types.js';
import { effectSuffix } from './audit-effects.js';
import { TOOL_DESCRIPTIONS as D } from './descriptions.js';
import {
  createLocalDownload,
  localFileForRead,
  localPathForAudit,
  type LocalPathContext,
} from './local-path.js';
import { syntheticSuccess, textResult } from './results.js';
import type { ToolDeps, Pipeline } from './pipeline.js';

/**
 * `maxEntries` 的上限，独立于调用方要多少。
 *
 * 响应还受 profile 的 `maxOutputBytes` 按字节封顶，
 * 所以挡住巨型目录进入模型上下文的不是这条——是那条。这条
 * 保住的是*数量*不被参数吹大，
 * 让调用方无法把一次工具调用变成对远程树的无限遍历。
 */
const MAX_LIST_ENTRIES = 1000;
const DEFAULT_LIST_ENTRIES = 200;

/**
 * rwx 三元组，按 `ls -l` 的渲染方式，含 setuid/setgid/sticky。
 *
 * 只读低九位会把 `-rwsr-xr-x` 渲染成 `-rwxr-xr-x`：
 * 形似 `ls -l`，却丢掉了仅有的三个特权位。运维或模型在判断
 * 远程文件能否安全覆盖时，将看不到它是 setuid——
 * 而这恰是让覆盖变得危险的先决条件。
 * makes overwriting one dangerous.
 */
function renderPermissions(mode: number): string {
  const rwx = 'rwxrwxrwx';
  const out: string[] = [];
  for (let i = 0; i < 9; i++) out.push((mode & (1 << (8 - i))) ? rwx[i] : '-');

  // 每个特殊位替换所在三元组的 x；该 x 未置位时用大写——
  // setuid 无执行位是 `S`，有则是 `s`，与 `ls` 的渲染一致。
  const special: [number, number, string][] = [
    [0o4000, 2, 's'],
    [0o2000, 5, 's'],
    [0o1000, 8, 't'],
  ];
  for (const [bit, at, char] of special) {
    if (mode & bit) out[at] = out[at] === 'x' ? char : char.toUpperCase();
  }
  return out.join('');
}

/**
 * `ls -l` 的类型字符，取自 mode 的文件类型位。
 *
 * 从 mode 读取而不是 `isDirectory`/`isFile`——两者合计只覆盖
 * 七种类型中的两种，其余一律报「都不是」。对照测试镜像的
 * `/usr/bin` 实测：那里几乎每项都是符号链接，用这两个布尔
 * 构建的列表把整个目录渲染成 `?`，
 * 比原始文件名传达的还少。
 */
function typeChar(mode: number): string {
  switch (mode & 0o170000) {
    case 0o040000: return 'd';
    case 0o100000: return '-';
    case 0o120000: return 'l';
    case 0o060000: return 'b';
    case 0o020000: return 'c';
    case 0o010000: return 'p';
    case 0o140000: return 's';
    default: return '?';
  }
}

/** ISO 时间戳的宽度，让下方占位符保持列对齐。 */
const MTIME_WIDTH = 24;

/**
 * 远程 mtime 在线上是可选的，因此可能根本没有日期。
 *
 * ssh2 仅在条目携带 SSH_FILEXFER_ACMODTIME 时填充 `attrs.mtime`，
 * 而 `toSftpStat` 把缺失者变成 `new Date(NaN)`。`toISOString()`
 * 会在构建响应的 `map` 里对它抛 `RangeError: Invalid time value`——
 * 于是省略该标志的服务器返回的单个条目，就让整个列表以一个
 * 莫名其妙的错误失败，而不是返回目录。mode 字段早已是降级而非
 * 抛出（`undefined & mask` 为 0，渲染成 `?` 与 `---------`）；
 * 本处让时间戳行为保持一致。
 */
function renderMtime(mtime: Date): string {
  return Number.isNaN(mtime.getTime()) ? '(no mtime)'.padStart(MTIME_WIDTH) : mtime.toISOString();
}

function renderEntry(entry: SftpStat): string {
  const size = String(entry.size).padStart(12, ' ');
  return `${typeChar(entry.mode)}${renderPermissions(entry.mode)} ${size}  ${renderMtime(entry.mtime)}  ${entry.path}`;
}

/**
 * 渲染列表，止于调用方 profile 设定的字节预算。
 *
 * `SftpClient.list` 对每个保留条目计价 `filename + longname + 256`，
 * 这只是行成本的代理而非行本身：`entry.path` 是目录拼接文件名，
 * 每行都重复目录，而 flat 256 从未覆盖它。远程路径一长，
 * 渲染产物就超出 profile 的 `maxOutputBytes` 好几倍，
 * 而自以为在执行预算的那一层只花了零头。
 * believed it was enforcing the budget had spent a fraction of it.
 *
 * 所以边界改为作用于实际产出的字节。原语的预算仍然要紧——
 * 它拦住敌意服务器的 `longname` 被驻留内存——但运维配置的数字
 * 现在描述的是他们为之配置的东西，即到达模型的那份。
 * they configured it for, which is what reaches the model.
 */
function renderListing(entries: SftpStat[], maxBytes: number): { body: string; truncated: boolean } {
  const lines: string[] = [];
  let bytes = 0;
  for (const entry of entries) {
    const line = renderEntry(entry);
    const cost = Buffer.byteLength(line, 'utf8') + 1;
    if (bytes + cost > maxBytes) return { body: lines.join('\n'), truncated: true };
    bytes += cost;
    lines.push(line);
  }
  return { body: lines.join('\n'), truncated: false };
}

/**
 * 拒绝授予传输本身并不具备的权限的 mode。
 *
 * 低九位以上全部是 setuid、setgid 与粘滞位。允许写文件的调用方，
 * 并不因此有权写一个以属主身份运行的文件，而 `uploadFile` 把它
 * 直接传给远程 `open`。
 *
 * `0` 是拒绝而非接受。`uploadFile` 经 `||` 把它读作「未设置」，
 * 于是要 mode 0 的调用方得到 0600——覆盖路径上还跳过了
 * 继承目标 mode 的步骤，要的没给、被替换的也没保住。
 * 参数被静默改写，比被拒绝更糟。
 * than one refused.
 *
 * 以 `preCheck` 运行（即在管线内），探测边界的调用会留下审计记录。
 * 该范围刻意*不*复制成字段上的 zod 边界：SDK 在进入 handler 前
 * 就校验 schema，那里的边界会在管线之外拒绝 setuid mode——
 * 无审计记录，这条消息也不可达。实测：两处都加时，
 * 0o4755 的探测连一条审计记录都没有。
 * probe at 0o4755 produced no audit record at all.
 */
export function checkMode(mode: number | undefined): number | undefined {
  if (mode === undefined) return undefined;
  if (!Number.isInteger(mode) || mode < 1 || mode > 0o777) {
    throw new McpError(
      ErrorCode.InvalidParams,
      'mode must be between 1 and 511 (0o777), or omitted. setuid, setgid and the sticky bit ' +
      'are refused: uploading a file does not carry the authority to make it run as its owner. ' +
      '0 is refused because it is read as "unset" downstream rather than as a mode.',
    );
  }
  return mode;
}

/**
 * 本地路径解析后，审计记录追加的内容。
 *
 * 是追加而不是替换，两者一致时为空。细化必须满足管线的
 * 只追加规则——被审计的字符串可以细化所批准的内容，绝不能替换——
 * 而把 `./sub/../x.bin` 换成 `x.bin` 是替换，`refineCommand`
 * 正确地对它抛了异常。
 *
 * 追加反而是更好的记录：审计者同时看到调用方发来的拼写
 * *和*解析到的文件，两者的分歧可见，而不是被静默归一化掉。
 * between them is visible rather than silently normalised away.
 */
function resolvedSuffix(asked: unknown, resolved: string): string {
  return asked === resolved ? '' : ` (resolved ${resolved})`;
}

/**
 * 流式 SFTP 工具：有界目录列表，以及在远程主机与本地磁盘之间
 * 不经过模型上下文的传输。
 *
 * 两种顺序在此承重，都来自 #207。
 *
 * **任何可观察动作都不得先于决定。** 被审计字符串由调用方
 * 对两条路径自己的拼写构建，经 `remotePathForAudit` 与
 * `localPathForAudit`——两者都不做任何 I/O。每个本地效果——
 * 存在性检查、暂存的 `.part`、传输根大门报出的运维配置错误——
 * 都发生在 `run()` 内，而管线只在调用获准并获批后才到达它。
 * 会抛异常的校验器以 `preCheck` 运行、位于管线自己的 try 内，
 * 被拒的调用因此仍留审计记录，而不是让客户端隐形探测边界。
 * leaves an audit record rather than letting a client probe the boundary
 * invisibly.
 *
 * **决定针对整个操作。** `overwrite` 与 `mode` 改变调用的行为——
 * 一个摧毁既有远程文件，另一个设定其权限——所以它们属于
 * 策略所分类的字符串、人读的提示、审批授权记忆的键。
 * 略去的话，批准一条路径即批准该调用的所有其他拼法。
 * one approval of a path covered every other spelling of the call.
 *
 * 解析出的本地路径再经 `onResolved` *追加*进审计记录，
 * 门在限制路径之后、stat 或打开任何东西之前触发它——
 * 因此后继检查抛出的拒绝也带着解析结果入账，不只是成功。
 * 追加而非替换：管线的规则是被审计字符串可细化、绝不可替换，
 * 且审计者同时看到被批准的拼写与解析到的文件更好。
 * elaborated and never replaced, and because an auditor is better served seeing
 * both the spelling that was approved and the file it resolved to.
 */
export function registerTransferTools(
  { server, localPath }: ToolDeps,
  pipeline: Pipeline,
) {
  const { runAudited } = pipeline;
  // 仅在什么都没配置时为缺省。大门读取 `transferRoot` 并以
  // 指名配置键的消息拒绝——有配置而无根的运维就该得到
  // 同样的回答。
  const ctx: LocalPathContext = localPath ?? { transferRoot: undefined };

  // ─── sftp-list ─────────────────────────────────────────────────────────
  server.tool(
    'sftp-list',
    D['sftp-list'],
    {
      remotePath: z.string().describe('Remote directory to list. No leading or trailing whitespace, and no control, bidirectional or zero-width characters.'),
      maxEntries: z.number().int().min(1).max(MAX_LIST_ENTRIES).optional()
        .describe(`Max entries to return (default ${DEFAULT_LIST_ENTRIES}, hard cap ${MAX_LIST_ENTRIES})`),
      profile: z.string().optional().describe('Profile name'),
    },
    { readOnlyHint: true },
    async ({ remotePath, maxEntries, profile }, extra) => {
      return runAudited(
        `sftp:list ${remotePathForAudit(remotePath)}`,
        {
          toolName: 'sftp-list',
          failureClass: 'read-only',
          profile,
          extra,
          synthetic: true,
          resource: { remotePath },
          preCheck: () => { sanitizeRemotePath(remotePath); },
        },
        async (rt) => {
          const budget = rt.conn.profile.maxOutputBytes;
          const { entries, truncated } = await new SftpClient(rt.conn).list(remotePath, {
            maxEntries: maxEntries ?? DEFAULT_LIST_ENTRIES,
            // 列表是 heading 给模型的输出，因此按与其他工具输出
            // 相同的预算计费。
            maxResponseBytes: budget,
            idleTimeoutMs: rt.conn.profile.transferTimeoutMs,
            abortSignal: rt.abortSignal,
          });

          const rendered = renderListing(entries, budget);
          const body = rendered.body || '(empty directory)';
          const note = truncated || rendered.truncated
            ? '\n\n[truncated: more entries exist than the entry or byte budget allowed]'
            : '';
          return {
            audited: syntheticSuccess(rt.profileName),
            // 文件名是远程的、受攻击者影响的内容，正要进入
            // 模型上下文，与命令输出完全一样。
            output: textResult(redactText(body, { entropyScan: true }) + note),
          };
        },
      );
    },
  );

  // ─── sftp-upload-file ──────────────────────────────────────────────────
  server.tool(
    'sftp-upload-file',
    D['sftp-upload-file'],
    {
      localPath: z.string().describe('Local file to upload, inside defaults.transferRoot'),
      remotePath: z.string().describe('Remote destination path. No leading or trailing whitespace, and no control, bidirectional or zero-width characters.'),
      overwrite: z.boolean().optional().describe('Replace an existing remote file (default false)'),
      // 该范围刻意不在此声明，只在 `checkMode`。SDK 在 handler
      // 运行前就校验本 schema，zod 边界会在管线*之外*拒绝
      // setuid mode——无审计记录，解释为何拒绝 setuid 的消息
      // 也不可达。在安全边界上不留痕迹的探测，正是
      // `preCheck` 存在要防止的东西，所以边界放在能记日志的
      // 地方。`.int()` 保留：非整数是类型错误而非探测。
      // because a non-integer is a type error rather than a probe.
      mode: z.number().int().optional()
        .describe('Remote file mode, 1 to 511 (0o777); setuid, setgid and the sticky bit are refused. e.g. 420 for 0644. Omit for 0600 on a new file, or the replaced file’s permission bits.'),
      profile: z.string().optional().describe('Profile name'),
    },
    { destructiveHint: true },
    async ({ localPath: source, remotePath, overwrite, mode, profile }, extra) => {
      const target = remotePathForAudit(remotePath);
      const approved =
        `sftp:upload-file ${target}${effectSuffix(overwrite, mode)} <- ${localPathForAudit(source)}`;
      return runAudited(
        approved,
        {
          toolName: 'sftp-upload-file',
          failureClass: 'destructive',
          profile,
          extra,
          synthetic: true,
          resource: { remotePath },
          preCheck: () => { sanitizeRemotePath(remotePath); checkMode(mode); },
        },
        async (rt) => {
          const maxBytes = rt.conn.profile.transferMaxBytes;
          // 经 `onResolved` 细化——门在限制路径之后、stat 或打开
          // 任何东西之前触发它。调用返回后才细化只覆盖成功路径——
          // 门自身抛出的每个拒绝（符号链接源、越出根、根自身
          // 配置错误）审计的都会是调用方的拼写。
          // misconfiguration) audited the caller's spelling instead.
          const local = await localFileForRead(ctx, source, (displayPath) => {
            rt.refineCommand(`${approved}${resolvedSuffix(source, displayPath)}`);
          });
          try {
            // 传输内部也查，但这里也查：大小已知，
            // 一个字节未动就拒绝，好过流中途越限之后
            // 还要清理远程 `.part`。
            // cleaned up.
            if (local.size > maxBytes) {
              throw new McpError(
                ErrorCode.InvalidParams,
                `Local file is ${local.size} bytes, over this profile's ${maxBytes} byte transfer limit`,
              );
            }
            const bytes = await new SftpClient(rt.conn).uploadFile(
              local.handle.createReadStream({ autoClose: false }),
              remotePath,
              {
                maxBytes,
                idleTimeoutMs: rt.conn.profile.transferTimeoutMs,
                abortSignal: rt.abortSignal,
                overwrite,
                mode,
              },
            );
            return {
              audited: syntheticSuccess(rt.profileName),
              output: textResult(`Uploaded ${bytes} bytes from ${local.displayPath} to ${remotePath}`),
            };
          } finally {
            await local.handle.close().catch(() => {});
          }
        },
      );
    },
  );

  // ─── sftp-download-file ────────────────────────────────────────────────
  server.tool(
    'sftp-download-file',
    D['sftp-download-file'],
    {
      remotePath: z.string().describe('Remote file to download. No leading or trailing whitespace, and no control, bidirectional or zero-width characters.'),
      localPath: z.string().describe('Local destination, inside defaults.transferRoot'),
      overwrite: z.boolean().optional().describe('Replace an existing local file (default false)'),
      profile: z.string().optional().describe('Profile name'),
    },
    { destructiveHint: true },
    async ({ remotePath, localPath: destination, overwrite, profile }, extra) => {
      const target = remotePathForAudit(remotePath);
      const approved =
        `sftp:download-file ${target}${effectSuffix(overwrite)} -> ${localPathForAudit(destination)}`;
      return runAudited(
        approved,
        {
          toolName: 'sftp-download-file',
          failureClass: 'destructive',
          profile,
          extra,
          synthetic: true,
          resource: { remotePath },
          preCheck: () => { sanitizeRemotePath(remotePath); },
        },
        async (rt) => {
          // 与上传侧相同、理由相同：在 `.part` 存在之前细化，
          // 覆盖与符号链接拒绝都会带着解析后的目标入账，
          // `refineCommand` 自身抛出也不会滞留暂存文件。
          // itself cannot strand a staged file.
          const download = await createLocalDownload(ctx, destination, overwrite ?? false, (t) => {
            rt.refineCommand(`${approved}${resolvedSuffix(destination, t.displayPath)}`);
          });
          try {
            const bytes = await new SftpClient(rt.conn).downloadFile(
              remotePath,
              download.createStream(),
              {
                maxBytes: rt.conn.profile.transferMaxBytes,
                idleTimeoutMs: rt.conn.profile.transferTimeoutMs,
                abortSignal: rt.abortSignal,
              },
            );
            await download.publish();
            return {
              audited: syntheticSuccess(rt.profileName),
              output: textResult(`Downloaded ${bytes} bytes from ${remotePath} to ${download.target.displayPath}`),
            };
          } finally {
            // 无条件、且在 publish() 之后：销毁流会关句柄，
            // 而 publish() 需要它开着才能 sync()。失败路径上
            // 正是它移除暂存的 `.part`。
            await download.cleanup();
          }
        },
      );
    },
  );
}
