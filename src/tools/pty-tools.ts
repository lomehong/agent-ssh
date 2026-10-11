import { z } from 'zod';
import { sanitizeSessionName } from '../guard/sanitizer.js';
import { classifyCommand } from '../policy/classifier.js';
import { TOOL_DESCRIPTIONS as D } from './descriptions.js';
import { syntheticSuccess, textResult } from './results.js';
import type { ToolDeps, Pipeline } from './pipeline.js';
import type { PolicyEvaluation } from '../types.js';

/**
 * 裸 PTY 会话工具（agent-ssh）。
 *
 * 安全形态（计划 §6 U2，主人 2026-10-11 批准）：
 * - `pty-open` 是门。它在分类器的 SYNTHETIC_CLASSES 下限中归为
 *   `destructive`，因此策略引擎的审批机制对它的适用
 *   与对 `session:open` 完全一致。
 * - 裸 PTY 内的内容是字节流——它无法被命令分类。因此
 *   `pty-write` 只审计、从不拒绝（与 `session:close` 同一种
 *   release 形态的常量），每条输入都进审计日志
 *   与按会话的转录。
 * - `pty-read`/`pty-list` 是只读提示，在分类器的
 *   READ_ONLY_SYNTHETIC 集合中调低，让 readOnly profile 能观察自己的会话。
 * - 会话自行死亡：来自 [defaults] 的空闲与生存期上限
 *   （第 ③ 层），每次调用与连接清扫时回收。
 */

/** 写入是审计而非设门：门在 pty-open 时已经过了。 */
const PTY_INPUT: PolicyEvaluation = {
  decision: 'allow',
  commandClass: 'safe',
  binary: 'pty:write',
  ruleId: 'pty-input',
  reason: 'Raw-PTY input is a byte stream and cannot be classified; the gate is pty-open and every write is audited+transcripted.',
};

/** 关闭是释放，不是获取——审计但不可拒绝。 */
const PTY_RELEASE: PolicyEvaluation = {
  decision: 'allow',
  commandClass: 'safe',
  binary: 'pty:close',
  ruleId: 'pty-release',
  reason: 'A session release is audited but not policy-gated; see SECURITY.md.',
};

/** Resize is a benign metadata op — audited for the session timeline, not gated. */
const PTY_RESIZE: PolicyEvaluation = {
  decision: 'allow',
  commandClass: 'safe',
  binary: 'pty:resize',
  ruleId: 'pty-resize',
  reason: 'A terminal resize changes no host state; recorded so the session timeline stays complete.',
};

/**
 * 针对裸输入的内容级告警（计划 P2，主人 2026-10-11 裁定：
 * 该待定项未获接受，随版本发布）。
 *
 * 裸流不经策略门——但没有任何东西阻止审计日志去
 * 看它。每个非空行都过一遍 exec 路径所用的同一分类器；
 * 命中 destructive/privileged 的会写进审计记录的
 * `ptyAlert` 字段与 stderr，复查会话的运维能看到危险行
 * 出现的那一刻——尽管那一行本来也拦不住。
 */
export function detectPtyAlerts(input: string): string | undefined {
  const hits = new Set<string>();
  for (const line of input.split(/\r?\n/)) {
    const cmd = line.trim();
    if (cmd.length === 0) continue;
    const parsed = classifyCommand(cmd);
    if (parsed.class === 'destructive' || parsed.class === 'privileged') {
      hits.add(`${parsed.class}: ${cmd.slice(0, 120)}`);
    }
  }
  return hits.size > 0 ? [...hits].join('; ') : undefined;
}

export function registerPtyTools(
  { server, registry }: ToolDeps,
  pipeline: Pipeline,
) {
  const { runAudited, resolveConn, auditResult, auditFailure, makeCtx, defaultProfileName } = pipeline;

  // ─── pty-open ────────────────────────────────────────────────────────────
  server.tool(
    'pty-open',
    D['pty-open'],
    {
      name: z.string().describe('Session name (alphanumeric, dash, underscore, max 64 chars)'),
      cols: z.number().int().positive().max(500).optional().describe('Terminal width (default 200)'),
      rows: z.number().int().positive().max(200).optional().describe('Terminal height (default 50)'),
      profile: z.string().optional().describe('Profile name (uses default if omitted)'),
    },
    { destructiveHint: true },
    async ({ name, cols, rows, profile }, extra) => {
      const cleanName = sanitizeSessionName(name);
      // 经 `pty:open` 合成下限归类为 `destructive`——在默认的
      // ask-destructive 策略下会提示；若完全无审批通道
      // 则 fail-closed（APPROVAL_UNAVAILABLE）。
      return runAudited(
        `pty:open ${cleanName}`,
        {
          toolName: 'pty-open',
          failureClass: 'destructive',
          profile,
          session: cleanName,
          extra,
          synthetic: true,
        },
        async (rt) => {
          const info = await rt.conn.openPtySession({ name: cleanName, cols, rows });
          return {
            audited: syntheticSuccess(rt.profileName),
            output: textResult(
              `PTY session "${info.name}" opened on ${rt.conn.profile.name} ` +
              `(${info.createdAt.toISOString()}). Write with pty-write (include newlines), read with pty-read from cursor 0.`,
            ),
          };
        },
      );
    },
  );

  // ─── pty-read ─────────────────────────────────────────────────────────────
  server.tool(
    'pty-read',
    D['pty-read'],
    {
      name: z.string().describe('PTY session name'),
      cursor: z.number().int().nonnegative().optional().default(0).describe('Cursor from the previous pty-read (0 = from the buffered start)'),
      profile: z.string().optional().describe('Profile name'),
    },
    { readOnlyHint: true },
    async ({ name, cursor, profile }, extra) => {
      void extra;
      const conn = await resolveConn(profile);
      try {
        // 每次调用 32KB：大到足以推进，小到一次话痨的
        // `show running-config` 无法在单个响应里灌满模型上下文。
        // 剩下的部分，再调一次就行。
        const read = conn.readPtySession(sanitizeSessionName(name), cursor, 32_768);
        return textResult(JSON.stringify(read));
      } catch (err) {
        return textResult(`pty-read failed: ${(err as Error).message}`);
      }
    },
  );

  // ─── pty-write ─────────────────────────────────────────────────────────────
  server.tool(
    'pty-write',
    D['pty-write'],
    {
      name: z.string().describe('PTY session name'),
      input: z.string().min(1).describe('Raw input to send — include your own newlines'),
      profile: z.string().optional().describe('Profile name'),
    },
    // 不是 readOnly：字节会落到主机上。annotations 只带标题——
    // 这里放空 annotations 对象会踩中 open-session 上记录过的 SDK 重载陷阱。
    { title: 'Send raw PTY input' },
    async ({ name, input, profile }, extra) => {
      const cleanName = sanitizeSessionName(name);
      let profileName = profile ?? '(default)';
      const ctx = makeCtx(extra, profileName, cleanName);
      // 先截断、后脱敏：让失控的粘贴无法经由这条唯一不经策略门的路径
      // 撑爆审计日志。
      const command = `pty:write ${cleanName} ${input.length > 2000 ? input.slice(0, 2000) + `…(+${input.length - 2000} chars)` : input}`;
      const alert = detectPtyAlerts(input);
      if (alert) {
        console.error(`PTY-ALERT on "${cleanName}": ${alert}`);
      }
      const startedAt = Date.now();
      try {
        profileName = defaultProfileName(profile);
        ctx.profile = profileName;
        const conn = await resolveConn(profile);
        const outcome = conn.writePtySession(cleanName, input);
        await auditResult(ctx, profileName, command, PTY_INPUT, {
          stdout: '',
          stderr: '',
          exitCode: outcome.delivered ? 0 : 1,
          durationMs: Date.now() - startedAt,
          profile: profileName,
          ...(alert ? { ptyAlert: alert } : {}),
          ...(outcome.note ? { error: outcome.note } : {}),
        });
        return textResult(
          outcome.delivered
            ? `Delivered ${input.length} chars to PTY "${cleanName}".`
            : `Not delivered: ${outcome.note}`,
        );
      } catch (err) {
        await auditFailure(ctx, profileName, { command }, 'safe', err);
        throw err;
      }
    },
  );

  // ─── pty-resize ─────────────────────────────────────────────────────────────
  server.tool(
    'pty-resize',
    D['pty-resize'],
    {
      name: z.string().describe('PTY session name'),
      rows: z.number().int().positive().max(200),
      cols: z.number().int().positive().max(500),
      profile: z.string().optional().describe('Profile name'),
    },
    { title: 'Resize PTY session' },
    async ({ name, rows, cols, profile }, extra) => {
      const cleanName = sanitizeSessionName(name);
      let profileName = profile ?? '(default)';
      const ctx = makeCtx(extra, profileName, cleanName);
      const command = `pty:resize ${cleanName} ${rows}x${cols}`;
      const startedAt = Date.now();
      try {
        profileName = defaultProfileName(profile);
        ctx.profile = profileName;
        const conn = await resolveConn(profile);
        conn.resizePtySession(cleanName, rows, cols);
        await auditResult(ctx, profileName, command, PTY_RESIZE, {
          stdout: '',
          stderr: '',
          exitCode: 0,
          durationMs: Date.now() - startedAt,
          profile: profileName,
        });
        return textResult(`PTY "${cleanName}" resized to ${rows}x${cols}.`);
      } catch (err) {
        await auditFailure(ctx, profileName, { command }, 'safe', err);
        throw err;
      }
    },
  );

  // ─── pty-close ─────────────────────────────────────────────────────────────
  server.tool(
    'pty-close',
    D['pty-close'],
    {
      name: z.string().describe('PTY session name'),
      profile: z.string().optional().describe('Profile name'),
    },
    { destructiveHint: true },
    async ({ name, profile }, extra) => {
      const cleanName = sanitizeSessionName(name);
      let profileName = profile ?? '(default)';
      const ctx = makeCtx(extra, profileName, cleanName);
      const command = `pty:close ${cleanName}`;
      const startedAt = Date.now();
      try {
        profileName = defaultProfileName(profile);
        ctx.profile = profileName;
        const conn = await resolveConn(profile);
        const { outcome, reason } = conn.closePtySession(cleanName);
        await auditResult(ctx, profileName, command, PTY_RELEASE, {
          stdout: '',
          stderr: '',
          exitCode: outcome === 'closed' ? 0 : 1,
          durationMs: Date.now() - startedAt,
          profile: profileName,
        });
        return textResult(
          `PTY "${cleanName}" closed${reason ? ` (was: ${reason})` : ''}.` +
          (outcome === 'unsignalled' ? ' The signal could not be delivered; the channel is dropped regardless.' : ''),
        );
      } catch (err) {
        await auditFailure(ctx, profileName, { command }, 'safe', err);
        throw err;
      }
    },
  );

  // ─── pty-list ─────────────────────────────────────────────────────────────
  server.tool(
    'pty-list',
    D['pty-list'],
    { profile: z.string().optional().describe('Profile name') },
    { readOnlyHint: true },
    async ({ profile }) => {
      const conn = registry.get(profile);
      if (!conn || conn.listPtySessions().length === 0) {
        return textResult('No raw PTY sessions.');
      }
      const lines = conn.listPtySessions().map((s) => {
        const status = s.closed ? `closed (${s.closeReason})` : 'open';
        return (
          `${s.name} [${status}] created=${s.createdAt.toISOString()} ` +
          `cursor=${s.cursor} buffered=${s.totalBytes - s.cursor >= 0 ? s.totalBytes : 0} ` +
          `dropped=${s.droppedBytes} transcript=${s.transcriptBytes}${s.transcriptFrozen ? ' (frozen)' : ''}`
        );
      });
      return textResult(lines.join('\n'));
    },
  );
}
