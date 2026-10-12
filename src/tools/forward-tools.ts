import { z } from 'zod';
import { TOOL_DESCRIPTIONS as D } from './descriptions.js';
import { syntheticSuccess, textResult } from './results.js';
import type { ToolDeps, Pipeline } from './pipeline.js';
import type { PolicyEvaluation } from '../types.js';

/**
 * 端口转发工具（agent-ssh T-06）。
 *
 * `forward-open` 把完整的「监听→目标」对放进其合成命令
 * （`forward:open local 127.0.0.1:8080 -> db:5432`），因此分类器下限
 * （`destructive`）使它落在角色矩阵 + 审批门之后，且
 * 针对目标写的 `[policy].denylist` 规则能在隧道建立前就拒绝它。
 * 动态模式另外还要：除非 `allowDynamicForwarding = true`，一律拒绝——
 * 一个开放的 SOCKS 监听是不区分目标的出网通道，
 * 无法按目标做拒绝清单，这正是它默认关闭、需显式开启的原因。
 */

const FORWARD_RELEASE: PolicyEvaluation = {
  decision: 'allow',
  commandClass: 'safe',
  binary: 'forward:close',
  ruleId: 'forward-release',
  reason: 'Closing a tunnel is a release: audited, never refusable — the operator must always be able to stop one.',
};

const TARGET_ARGS = {
  targetHost: z.string().min(1).describe('Destination host (resolved from the SSH host, not this machine)'),
  targetPort: z.number().int().min(1).max(65535).describe('Destination port'),
};

export function registerForwardTools(
  { server, registry }: ToolDeps,
  pipeline: Pipeline,
) {
  const { runAudited, resolveConn, auditResult, auditFailure, makeCtx, defaultProfileName } = pipeline;

  // ─── forward-open ─────────────────────────────────────────────────────────
  server.tool(
    'forward-open',
    D['forward-open'],
    {
      mode: z.enum(['local', 'remote', 'dynamic']).describe('local = listen here → reach target via the host; remote = host listens → connections land on target; dynamic = local SOCKS5 (opt-in)'),
      listenHost: z.string().optional().describe('Bind address (default 127.0.0.1; use 0.0.0.0 only when you mean it)'),
      listenPort: z.number().int().min(0).max(65535).describe('Port to listen on (0 = ephemeral)'),
      ...TARGET_ARGS,
      profile: z.string().optional().describe('Profile name (uses default if omitted)'),
    },
    { destructiveHint: true },
    async ({ mode, listenHost, listenPort, targetHost, targetPort, profile }, extra) => {
      // dynamic 模式没有目标：不得继承上一次调用的形态。
      const dynamic = mode === 'dynamic';
      const target = dynamic ? '(dynamic)' : `${targetHost}:${targetPort}`;
      const listen = `${listenHost ?? '127.0.0.1'}:${listenPort}（Host 机侧监听——分离架构后 local/dynamic 监听开在 Host 守护所在机器，方案 §5）`;
      return runAudited(
        `forward:open ${mode} ${listen} -> ${target}`,
        {
          toolName: 'forward-open',
          // dynamic 的「默认关」拒绝必须发生在审批门之前（审计 M9）：
          // 先弹一次注定失败的审批是在浪费人工。
          preCheck: () => {
            if (mode === 'dynamic' && !registry.isDynamicAllowed()) {
              throw new Error('Dynamic (SOCKS) forwarding is disabled: set allowDynamicForwarding = true to enable it.');
            }
          },
          failureClass: 'destructive',
          profile,
          extra,
          synthetic: true,
        },
        async (rt) => {
          const info = await rt.conn.openForward({
            mode, listenHost, listenPort, targetHost, targetPort,
          });
          return {
            audited: syntheticSuccess(rt.profileName),
            output: textResult(
              `Forward ${info.id} (${info.mode}) listening on ${info.listen}` +
              (info.target ? ` → ${info.target}` : '') + `.`,
            ),
          };
        },
      );
    },
  );

  // ─── forward-close ─────────────────────────────────────────────────────────
  server.tool(
    'forward-close',
    D['forward-close'],
    { id: z.string().describe('Forward id from forward-open/forward-list'), profile: z.string().optional().describe('Profile name') },
    { destructiveHint: true },
    async ({ id, profile }, extra) => {
      let profileName = profile ?? '(default)';
      const ctx = makeCtx(extra, profileName, id);
      const command = `forward:close ${id}`;
      const startedAt = Date.now();
      try {
        profileName = defaultProfileName(profile);
        ctx.profile = profileName;
        const conn = await resolveConn(profile);
        const { outcome, mode } = await conn.closeForward(id);
        await auditResult(ctx, profileName, command, FORWARD_RELEASE, {
          stdout: '',
          stderr: '',
          exitCode: outcome === 'closed' ? 0 : 1,
          durationMs: Date.now() - startedAt,
          profile: profileName,
        });
        if (outcome === 'not-found') return textResult(`Forward "${id}" not found.`);
        return textResult(`Forward "${id}" (${mode}) closed; live connections destroyed.`);
      } catch (err) {
        await auditFailure(ctx, profileName, { command }, 'safe', err);
        throw err;
      }
    },
  );

  // ─── forward-list ─────────────────────────────────────────────────────────
  server.tool(
    'forward-list',
    D['forward-list'],
    { profile: z.string().optional().describe('Profile name') },
    { readOnlyHint: true },
    async ({ profile }) => {
      const conn = registry.get(profile);
      const forwards = conn?.listForwards() ?? [];
      if (forwards.length === 0) return textResult('No active port forwards.');
      const lines = forwards.map((f) => {
        return `${f.id} [${f.mode}] ${f.listen}` + (f.target ? ` → ${f.target}` : '') + ` conns=${f.activeConnections}`;
      });
      return textResult(lines.join('\n'));
    },
  );
}
