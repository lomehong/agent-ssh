import { z } from 'zod';
import { sanitizeSessionName } from '../guard/sanitizer.js';
import { redactText } from '../guard/redactor.js';
import { BackgroundSession, type CloseOutcome } from '../ssh/session.js';
import { COULD_NOT_SIGNAL } from '../ssh/channel-signal.js';
import { TOOL_DESCRIPTIONS as D } from './descriptions.js';
import { syntheticSuccess, textResult } from './results.js';
import type { ToolDeps, Pipeline } from './pipeline.js';
import type { PolicyEvaluation } from '../types.js';

/** 连接与会话的发现/生命周期工具。 */
/**
 * 会话释放所记录的评估结论。
 *
 * 释放会话是审计的但从不拒绝，正因如此它是一个常量而不是
 * 一次引擎调用。初版把关闭路由经 `runAudited`，那让停止变得
 * *可拒绝*：`session:close <name>` 归类为 `safe`，于是
 * `readOnly` profile——它能开后台会话，因为 `tail -f` 归类
 * `read-only`——会被拒绝关闭它的许可，而且一小时内
 * 再无别的办法停掉那条命令。`ask-all` 对每次关闭都提示，
 * 耗尽的 `commandQuotaPerDay` 更是把整个 profile 卡死。
 *
 * 一个「拒绝的后果是你要停的东西继续跑」的控制，比它替代的
 * 未经审计的停止更糟。记录是值得留的部分；否决权不是。
 * `ruleId` 写明了这一点，日志因此能把这与引擎的 `allow` 区分开。
 */
const RELEASE: PolicyEvaluation = {
  decision: 'allow',
  commandClass: 'safe',
  binary: 'session:close',
  ruleId: 'session-release',
  reason: 'A session release is audited but not policy-gated; see SECURITY.md.',
};

/** 每种结果下追加到调用方确认信息之后的内容。 */
const CLOSE_NOTES: Record<CloseOutcome, string> = {
  closed: '',
  unsignalled: COULD_NOT_SIGNAL,
  'stop-unconfirmed':
    ' The command was signalled but the channel had not closed in time, so it may still be running on the host.',
};

export function registerSessionTools(
  { server, registry }: ToolDeps,
  pipeline: Pipeline,
) {
  const { runAudited, resolveConn, auditResult, auditFailure, makeCtx, defaultProfileName } = pipeline;

  // ─── list-connections ──────────────────────────────────────────────────
  server.tool(
    'list-connections',
    D["list-connections"],
    {},
    { readOnlyHint: true },
    async () => {
      // 唯一只读 `listAllProfiles()`、从不碰 `getProfile` 的工具。
      // 没有这个检查，它会以零长度的成功回答未配置的服务器——
      // 而这个工具自己的描述就让 agent 先来这里
      // （「运行命令前先发现可用主机」），而且它还是唯一一条
      // 看不到启动 stderr 告警的通道。agent 看到「没有主机」
      // 而不是「未配置」。在这里拒绝，才让 README、changeset
      // 与启动告警里的说法对每个工具都成立。
      registry.assertConfigured();
      const connections = registry.listConnections();
      const profiles = registry.listAllProfiles();
      const lines = profiles.map((p) => {
        const conn = connections.find((c) => c.profile === p.name);
        const status = conn?.status || 'disconnected';
        const sessions = conn?.sessionCount || 0;
        return `${p.name}: ${p.user}@${p.host}:${p.port} [${status}] sessions=${sessions} role=${p.role}`;
      });
      return textResult(lines.join('\n'));
    },
  );

  // ─── list-sessions ─────────────────────────────────────────────────────
  server.tool(
    'list-sessions',
    D["list-sessions"],
    { profile: z.string().optional().describe('Profile name (uses default if omitted)') },
    { readOnlyHint: true },
    async ({ profile }) => {
      const conn = registry.get(profile);
      if (!conn || conn.listSessions().length === 0) {
        return textResult('No active sessions.');
      }
      const sessions = conn.listSessions().map((s) => {
        const info = s.toInfo();
        return `${info.name} [${info.type}] status=${info.status} idle=${Math.round((Date.now() - info.lastActivity.getTime()) / 1000)}s`;
      });
      return textResult(sessions.join('\n'));
    },
  );

  // ─── open-session ──────────────────────────────────────────────────────
  server.tool(
    'open-session',
    D["open-session"],
    {
      name: z.string().describe('Session name (alphanumeric, dash, underscore, max 64 chars)'),
      type: z.enum(['interactive', 'background']).default('interactive').describe('Session type'),
      command: z.string().optional().describe('Command for background sessions'),
      profile: z.string().optional().describe('Profile name (uses default if omitted)'),
    },
    // 这里刻意不放 annotations 对象。SDK 的重载决议把空对象
    // 当作 Zod raw shape（isZodRawShape 对 `{}` 返回 true），
    // 在 annotations 槽位传 `{}` 会让它吞掉回调槽位——
    // 工具注册上了却没有 handler，
    // 每次调用都报 "cb is not a function"。
    async ({ name, type, command, profile }, extra) => {
      const cleanName = sanitizeSessionName(name);
      const isBackground = type === 'background' && Boolean(command);

      // 后台会话运行的是调用方提供的命令，所以那条命令才是
      // 策略要评估的对象。交互式会话暂时不运行任何命令，
      // 但打开一个有状态 shell 仍是值得审计的生命周期事件
      // ——该分支过去一条记录都不产生。
      return runAudited(
        isBackground ? command! : `session:open ${type} ${cleanName}`,
        {
          toolName: 'open-session',
          failureClass: isBackground ? 'destructive' : 'safe',
          profile,
          session: cleanName,
          extra,
          synthetic: !isBackground,
        },
        async (rt) => {
          await rt.conn.openSession({
            name: cleanName,
            type,
            command: isBackground ? rt.command : command,
          });
          return {
            audited: syntheticSuccess(rt.profileName),
            output: textResult(`Session "${cleanName}" opened on ${rt.conn.profile.name} (${type}).`),
          };
        },
      );
    },
  );

  // ─── close-session ─────────────────────────────────────────────────────
  server.tool(
    'close-session',
    D["close-session"],
    {
      name: z.string().describe('Session name to close'),
      profile: z.string().optional().describe('Profile name'),
    },
    { destructiveHint: true },
    async ({ name, profile }, extra) => {
      const cleanName = sanitizeSessionName(name);
      // profile 名与连接都在下面的 try 里解析。它们过去在
      // try 之上解析，于是一次拒绝——未配置的服务器、未知的
      // profile 名——会在 `auditFailure` 记下「曾尝试释放」之前逃逸。
      // 若解析本身就是失败原因，记录就登记在这些占位符名下。
      //
      let profileName = profile ?? '(default)';
      const ctx = makeCtx(extra, profileName, cleanName);
      let command = `session:close unknown ${cleanName}`;
      const startedAt = Date.now();

      try {
        profileName = defaultProfileName(profile);
        ctx.profile = profileName;
        const conn = await resolveConn(profile);
        // 按会话的类型记录，于是远程 SIGKILL 在日志里可 grep，
        // 与结束本地 shell 可区分——`open-session` 用同一方式
        // 编码其类型。
        // 经 `toInfo()` 而不是 `instanceof` 检查：该类型是公共 API，
        // 工具 handler 去够构造器身份，正是本仓库自己的规则
        // rules call out.
        const kind = conn.getSession(cleanName)?.toInfo().type ?? 'unknown';
        command = `session:close ${kind} ${cleanName}`;
        const outcome = await conn.closeSession(cleanName);
        await auditResult(ctx, profileName, command, RELEASE, {
          stdout: '',
          stderr: '',
          exitCode: outcome === 'closed' ? 0 : 1,
          durationMs: Date.now() - startedAt,
          profile: profileName,
        });
        return textResult(`Session "${cleanName}" closed.${CLOSE_NOTES[outcome]}`);
      } catch (err) {
        await auditFailure(ctx, profileName, { command }, 'safe', err);
        throw err;
      }
    },
  );

  // ─── read-session-output ───────────────────────────────────────────────
  server.tool(
    'read-session-output',
    D["read-session-output"],
    {
      name: z.string().describe('Background session name'),
      lines: z.number().optional().default(50).describe('Number of recent lines to read'),
      profile: z.string().optional().describe('Profile name'),
    },
    { readOnlyHint: true },
    async ({ name, lines, profile }) => {
      const conn = await resolveConn(profile);
      const session = conn.getSession(name);
      if (!session || session.type !== 'background') {
        return textResult(`Background session "${name}" not found.`);
      }
      if (session instanceof BackgroundSession) {
        return textResult(redactText(session.readOutput(lines), { entropyScan: true }));
      }
      return textResult(`Session "${name}" is not a background session.`);
    },
  );
}
