import { z } from 'zod';
import { TOOL_DESCRIPTIONS as D } from './descriptions.js';
import { syntheticSuccess, textResult } from './results.js';
import type { ToolDeps, Pipeline } from './pipeline.js';
import type { PolicyEvaluation } from '../types.js';

/**
 * Port-forwarding tools (agent-ssh T-06).
 *
 * `forward-open` carries the full listen→target pair in its synthetic command
 * (`forward:open local 127.0.0.1:8080 -> db:5432`), so the classifier floor
 * (`destructive`) puts it behind the role matrix + approval gate, and
 * `[policy].denylist` rules written against a target refuse the tunnel before
 * it opens. Dynamic mode is additionally refused unless
 * `allowDynamicForwarding = true` — an open SOCKS listener is generic egress
 * and cannot be denylisted by target, which is why it is opt-in.
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
      // Dynamic has no target: it must not inherit the previous call's shape.
      const dynamic = mode === 'dynamic';
      const target = dynamic ? '(dynamic)' : `${targetHost}:${targetPort}`;
      const listen = `${listenHost ?? '127.0.0.1'}:${listenPort}`;
      return runAudited(
        `forward:open ${mode} ${listen} -> ${target}`,
        {
          toolName: 'forward-open',
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
