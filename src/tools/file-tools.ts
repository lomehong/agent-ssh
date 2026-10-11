import { z } from 'zod';
import { redactText } from '../guard/redactor.js';
import { remotePathForAudit, sanitizeRemotePath } from '../guard/sanitizer.js';
import { SftpClient } from '../ssh/sftp.js';
import { OVERWRITE_FLAG, payloadSuffix } from './audit-effects.js';
import { TOOL_DESCRIPTIONS as D } from './descriptions.js';
import { syntheticSuccess, textResult } from './results.js';
import type { ToolDeps, Pipeline } from './pipeline.js';

/**
 * SFTP 传输工具。
 *
 * 两条路径都过 `sanitizeRemotePath`——与流式工具相同的标准，
 * 不过是对*路径*的标准。
 *
 * `sftp-upload` 无条件截断已存在的远程文件，而
 * `sftp-upload-file` 不传 `overwrite` 就拒绝。#223 改的是
 * 批准字符串如今写明了这一点：此前它只写目标、不写效果，
 * 对字节更是只字不提，于是对同一路径的两次上传是同一个字符串——
 * 一次批准、一条无法区分的审计记录。行为本身刻意不变：
 * 默认 `overwrite: false` 会破坏每个依赖替换语义的调用方。
 * 因此 `--overwrite` 在这里是常量，这确实意味着它不携带
 * 按调用的信息——按调用的信号是 `--bytes` 与
 * `--sha256`。它仍然保留，因为姊妹工具在不覆盖时会省略该标志，
 * 对比两者的审批者需要「在」与「不在」表达含义。
 *
 * `synthetic: true` 会跳过 `sanitizeCommand`，而这两个工具又内插
 * 调用方的原始字符串，于是一座双向覆盖符或零宽字符可以藏进路径，
 * 该路径会被引回审批提示、写进哈希链审计记录——
 * 那个校验器要阻止的正是这种混淆。检查以 `preCheck` 运行、
 * 位于管线的 try 内，因此被拒的调用
 * 仍会留下审计记录。
 *
 * 该问题此前已存在，且此前只有持 `safe` 的角色够得到；
 * 把 `sftp:download` 降到 `read-only`（#217）才会把它暴露给所有
 * `readOnly` profile，所以在这里关闭，而不是事后。
 */
export function registerFileTools(
  { server }: ToolDeps,
  pipeline: Pipeline,
) {
  const { runAudited } = pipeline;

  // ─── sftp-upload ───────────────────────────────────────────────────────
  server.tool(
    'sftp-upload',
    D["sftp-upload"],
    {
      remotePath: z.string().describe('Remote file path. No leading or trailing whitespace, and no control, bidirectional or zero-width characters: the approval prompt and the audit record quote this path back.'),
      content: z.string().describe('File content to upload'),
      profile: z.string().optional().describe('Profile name'),
    },
    { destructiveHint: true },
    async ({ remotePath, content, profile }, extra) => {
      return runAudited(
        // 动词，然后是操作做什么，再是它对哪个路径做。路径放在行尾，
        // 使字符串在提示与审计记录里读起来自然；
        // `[policy].denylist` 已不再依赖这一点，因为每个 SFTP 工具
        // 都会把远程路径单独交给引擎（#230）。锚定整个字符串的规则
        // （`^sftp:upload /root.*$`）仍与这个布局耦合。
        `sftp:upload${OVERWRITE_FLAG}${payloadSuffix(content)} ${remotePathForAudit(remotePath)}`,
        {
          toolName: 'sftp-upload',
          failureClass: 'destructive',
          profile,
          extra,
          synthetic: true,
          resource: { remotePath },
          preCheck: () => { sanitizeRemotePath(remotePath); },
        },
        async (rt) => {
          await new SftpClient(rt.conn).upload({ remotePath, content });
          return {
            audited: syntheticSuccess(rt.profileName),
            // utf8 字节，与批准字符串已携带的计数一致——
            // 为什么 `.length` 是错的，见 audit-effects.ts 的 `payloadSuffix`。
            output: textResult(`Uploaded ${Buffer.byteLength(content, 'utf8')} bytes to ${remotePath}`),
          };
        },
      );
    },
  );

  // ─── sftp-download ─────────────────────────────────────────────────────
  server.tool(
    'sftp-download',
    D["sftp-download"],
    {
      remotePath: z.string().describe('Remote file path. No leading or trailing whitespace, and no control, bidirectional or zero-width characters: the approval prompt and the audit record quote this path back.'),
      profile: z.string().optional().describe('Profile name'),
    },
    { readOnlyHint: true },
    async ({ remotePath, profile }, extra) => {
      return runAudited(
        `sftp:download ${remotePathForAudit(remotePath)}`,
        {
          toolName: 'sftp-download',
          failureClass: 'read-only',
          profile,
          extra,
          synthetic: true,
          resource: { remotePath },
          preCheck: () => { sanitizeRemotePath(remotePath); },
        },
        async (rt) => {
          const data = await new SftpClient(rt.conn).download({ remotePath });
          return {
            audited: syntheticSuccess(rt.profileName),
            output: textResult(redactText(data.toString('utf8'), { entropyScan: true })),
          };
        },
      );
    },
  );
}
