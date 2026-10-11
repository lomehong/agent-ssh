import { z } from 'zod';
import { sanitizeSessionName } from '../guard/sanitizer.js';
import { TOOL_DESCRIPTIONS as D } from './descriptions.js';
import { syntheticSuccess, textResult } from './results.js';
import type { ToolDeps, Pipeline } from './pipeline.js';
import type { PolicyEvaluation } from '../types.js';

/**
 * Raw-PTY session tools (agent-ssh).
 *
 * Safety shape (plan §6 U2, owner-ratified 2026-10-11):
 * - `pty-open` is the gate. It classifies `destructive` in the classifier's
 *   SYNTHETIC_CLASSES floor, so the policy engine's approval machinery applies
 *   to it exactly as to `session:open`.
 * - Content inside a raw PTY is a byte stream — it CANNOT be command-classified.
 *   `pty-write` is therefore audited-but-never-refused (the same release-shaped
 *   constant as `session:close`), with every input landing in the audit log and
 *   the per-session transcript.
 * - `pty-read`/`pty-list` are read-only hints, lowered in the classifier's
 *   READ_ONLY_SYNTHETIC set so readOnly profiles can observe their own sessions.
 * - Sessions die on their own: idle and lifetime bounds from [defaults]
 *   (layer ③), reaped on every call and by the connection sweep.
 */

/** Writes are audited, not gated: the gate already happened at pty-open. */
const PTY_INPUT: PolicyEvaluation = {
  decision: 'allow',
  commandClass: 'safe',
  binary: 'pty:write',
  ruleId: 'pty-input',
  reason: 'Raw-PTY input is a byte stream and cannot be classified; the gate is pty-open and every write is audited+transcripted.',
};

/** Closing is a release, not an acquisition — audited but not refusable. */
const PTY_RELEASE: PolicyEvaluation = {
  decision: 'allow',
  commandClass: 'safe',
  binary: 'pty:close',
  ruleId: 'pty-release',
  reason: 'A session release is audited but not policy-gated; see SECURITY.md.',
};

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
      // Classified `destructive` via the `pty:open` synthetic floor — under the
      // default ask-destructive policy this prompts, and with no approval
      // channel it fails closed (APPROVAL_UNAVAILABLE).
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
        // 32KB per call: big enough to make progress, small enough that one
        // chatty `show running-config` cannot flood model context in a single
        // response. The cursor makes the rest a repeated call away.
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
    // Not readOnly: bytes land on the host. Title-only annotations — an EMPTY
    // annotations object here is the SDK overload trap recorded on open-session.
    { title: 'Send raw PTY input' },
    async ({ name, input, profile }, extra) => {
      const cleanName = sanitizeSessionName(name);
      let profileName = profile ?? '(default)';
      const ctx = makeCtx(extra, profileName, cleanName);
      // Truncate BEFORE redaction so a runaway paste cannot bloat the audit log
      // through the one path that is not policy-gated.
      const command = `pty:write ${cleanName} ${input.length > 2000 ? input.slice(0, 2000) + `…(+${input.length - 2000} chars)` : input}`;
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
    async ({ name, rows, cols, profile }) => {
      const conn = await resolveConn(profile);
      conn.resizePtySession(sanitizeSessionName(name), rows, cols);
      return textResult(`PTY "${sanitizeSessionName(name)}" resized to ${rows}x${cols}.`);
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
