import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { tracer } from '../observability/tracer.js';
import type { ConnectionRegistry } from '../ssh/connection-registry.js';
import type { PolicyEngine, PolicyResource } from '../policy/engine.js';
import type { AuditStore } from '../audit/store.js';
import { sanitizeCommand } from '../guard/sanitizer.js';
import { requestApproval, APPROVAL_TIMEOUT_MS, type ApprovalResult } from '../guard/elicitation.js';
import {
  assertQueueDirPrivate,
  createApprovalRequest,
  getApprovalQueueDir,
  waitForDecision,
  type ApprovalChannel,
} from '../guard/approval-queue.js';
import { commandOutput, type ToolResult } from './results.js';
import { CommandQuota } from '../policy/quota.js';
import { formatReadOnlyRejection } from '../policy/classifier.js';
import type { LocalPathContext } from './local-path.js';
import { ApprovalGrants } from '../guard/approval-grants.js';
import type { CommandResult, ToolContext, PolicyEvaluation, CommandClass } from '../types.js';

/**
 * What we know about a request while it is being processed, so a failure can be
 * audited truthfully.
 *
 * The catch block of a tool handler is reached by two very different events: a
 * policy denial, and a failure *after* the command was allowed, approved and
 * executed. Recording both as `decision: 'deny'` told an auditor that commands
 * which actually ran on the host had been blocked.
 */
export interface AuditState {
  /** Best-known command string: raw until sanitized, wrapped once wrapped. */
  command: string;
  /** Set once the policy engine actually produced a decision. */
  evaluation?: PolicyEvaluation;
}

/** Policy never ran — the input was rejected at the boundary. */
function rejectedEvaluation(commandClass: CommandClass): PolicyEvaluation {
  return { decision: 'deny', commandClass, binary: '', ruleId: 'input-rejected' };
}

/**
 * Carries the policy decision that caused a refusal, so the audit record shows
 * the real rule and class instead of a synthetic placeholder.
 */
export class PolicyRefusedError extends Error {
  constructor(message: string, readonly evaluation: PolicyEvaluation) {
    super(message);
    this.name = 'PolicyRefusedError';
  }
}

export interface ToolDeps {
  server: McpServer;
  /** Lifetime of a just-in-time approval grant; 0 = always prompt. */
  approvalGrantTtlMs?: number;
  /**
   * Where a human approval is sought (agent-ssh): `elicitation` (upstream),
   * `queue` (file queue + `approvals` CLI), or `both` — try the client first,
   * fall to the queue when this client cannot be asked. Default `both`.
   */
  approvalChannel?: ApprovalChannel;
  /** Queue poll interval; a test hook — production uses the 2s default. */
  approvalQueuePollMs?: number;
  /** Queue directory override; a test hook — production uses the platform default. */
  approvalQueueDir?: string;
  /** Test hook: inject the Windows ACL inspection for the queue directory. */
  approvalQueueInspectAcl?: import('../guard/approval-queue.js').QueueAclInspect;
  registry: ConnectionRegistry;
  policy: PolicyEngine;
  audit: AuditStore;
  /**
   * Where the streaming SFTP file tools may touch local disk, and which
   * directories they must stay clear of.
   *
   * Optional so the tool layer can be built without it — an unconfigured server
   * still has to answer `tools/list`. Absent, those tools register and refuse,
   * which is the same answer a configured server with no `transferRoot` gives.
   */
  localPath?: LocalPathContext;
}

/**
 * Builds the audited execution pipeline every tool handler runs through.
 *
 * A factory rather than free functions because the pipeline closes over the
 * server (approval prompts), registry (connections and profiles), policy engine
 * and audit store. Tool groups receive the result and never touch those four
 * directly, so there is exactly one path from caller input to a remote command.
 */
export function createPipeline({
  server,
  registry,
  policy,
  audit,
  approvalGrantTtlMs = 0,
  approvalChannel = 'both',
  approvalQueuePollMs,
  approvalQueueDir,
  approvalQueueInspectAcl,
}: ToolDeps) {
  const quota = new CommandQuota();
  const grants = new ApprovalGrants(approvalGrantTtlMs);
  async function resolveConn(profileName?: string) {
    return registry.getOrCreate(profileName);
  }

  async function checkPolicyAndApprove(
    command: string,
    profileName: string,
    toolName: string,
    resource: PolicyResource = {},
  ) {
    const span = tracer.startSpan('policy.evaluate');
    span.setAttribute('tool.name', toolName);
    span.setAttribute('ssh.profile', profileName);
    try {
      const conn = await resolveConn(profileName);
      const evaluation = await policy.evaluateWithOpa(command, conn.profile, toolName, resource);
      span.setAttribute('policy.decision', evaluation.decision);
      span.setAttribute('command.class', evaluation.commandClass);
      span.setAttribute('command.binary', evaluation.binary);

      if (evaluation.decision === 'deny') {
        throw new PolicyRefusedError(
          `POLICY_DENIED: ${evaluation.reason || 'Command not allowed'}`,
          evaluation,
        );
      }

      if (evaluation.decision === 'require-approval') {
        // A live grant from an earlier explicit approval of this exact command.
        if (grants.has(conn.profile.name, command, evaluation.commandClass)) {
          span.setAttribute('policy.grant', 'reused');
          return { conn, evaluation, approver: 'jit-grant' };
        }

        const channel = approvalChannel ?? 'both';
        let approval: ApprovalResult | null = null;
        if (channel !== 'queue') {
          approval = await requestApproval(server, command, conn.profile.name, evaluation);
          if (approval.approved) {
            grants.record(conn.profile.name, command, evaluation.commandClass);
            return { conn, evaluation, approver: approval.approver };
          }
          // A human who was asked and said no is a final answer: queueing the
          // same command behind their back would shop for a second opinion.
          if (!approval.unavailable || channel === 'elicitation') {
            throw new PolicyRefusedError(
              approval.unavailable
                ? `APPROVAL_UNAVAILABLE: ${approval.unavailable}`
                : 'APPROVAL_DENIED: User did not approve this command',
              evaluation,
            );
          }
          // `both` + unavailable: this client cannot be asked — fall through to
          // the queue, which is the whole reason the channel exists.
        }

        // Queue-directory privacy gate (T-11): on Windows, a queue another
        // account can rewrite means forged approvals. Enforced, not reported —
        // the human's decision is only as trustworthy as the file it is
        // written into. POSIX took its 0700 chmod at queue creation.
        try {
          await assertQueueDirPrivate(approvalQueueDir ?? getApprovalQueueDir(), approvalQueueInspectAcl);
        } catch (err) {
          throw new PolicyRefusedError(
            `APPROVAL_UNAVAILABLE: approval queue directory failed the privacy check — ` +
            `${err instanceof Error ? err.message : String(err)} The command was refused rather than left in a queue that could be tampered with.`,
            evaluation,
          );
        }

        const request = await createApprovalRequest({
          profile: conn.profile.name,
          command,
          commandClass: evaluation.commandClass,
          binary: evaluation.binary,
          timeoutMs: APPROVAL_TIMEOUT_MS,
        }, { dir: approvalQueueDir });
        span.setAttribute('policy.queuedApproval', request.id);
        const decision = await waitForDecision(request.id, {
          dir: approvalQueueDir,
          fingerprint: request.fingerprint,
          expiresAt: request.expiresAt,
          pollMs: approvalQueuePollMs ?? 2_000,
          onQueued: (id) => {
            console.error(
              `APPROVAL_QUEUED id=${id} — a ${evaluation.commandClass} command on "${conn.profile.name}" is waiting ` +
              `for a human. Decide with: agent-ssh approvals approve ${id}   (or reject ${id}). ` +
              `It expires ${request.expiresAt}.`,
            );
          },
        });
        if (!decision.approved) {
          throw new PolicyRefusedError(
            decision.unavailable?.includes('expired')
              ? `APPROVAL_EXPIRED: ${decision.unavailable}`
              : decision.unavailable
                ? `APPROVAL_UNAVAILABLE: ${decision.unavailable}`
                : 'APPROVAL_DENIED: User did not approve this command (via approvals CLI)',
            evaluation,
          );
        }
        grants.record(conn.profile.name, command, evaluation.commandClass);
        return { conn, evaluation, approver: decision.approver };
      }

      return { conn, evaluation, approver: undefined };
    } finally {
      span.end();
    }
  }

  async function auditResult(
    ctx: ToolContext,
    profileName: string,
    command: string,
    evaluation: PolicyEvaluation,
    result: CommandResult | { error: string },
    approver?: string,
  ) {
    await audit.record({
      mcpRequestId: ctx.requestId,
      profile: profileName,
      // Looked up without throwing. This used to be `registry.getProfile(profileName).user`,
      // which throws for exactly the reason the tool call is being audited as a failure —
      // an unconfigured server, or a profile name that does not exist — and `auditFailure`
      // swallows that by design. The record the operator most needs was the one record that
      // could not be written.
      user: profileUser(profileName),
      command,
      commandClass: evaluation.commandClass,
      binary: evaluation.binary,
      decision: evaluation.decision,
      ruleId: evaluation.ruleId,
      // Carried so an auditor can tell, per command, whether it ran over a
      // widened algorithm allowlist. Undefined (and thus absent from the JSON
      // line) when the profile keeps the frozen list untouched.
      algorithmsOverride: profileHasAlgorithmsOverride(profileName),
      // Raw-PTY input alerting (plan P2): the classes a session's input hit.
      ptyAlert: 'ptyAlert' in result ? (result as { ptyAlert?: string }).ptyAlert : undefined,
      exitCode: 'exitCode' in result ? result.exitCode : undefined,
      durationMs: 'durationMs' in result ? result.durationMs : undefined,
      error: 'error' in result ? result.error : undefined,
      approver,
    });
  }

  function makeCtx(extra: any, profile?: string, session?: string): ToolContext {
    return { requestId: extra?.requestId ?? 0, profile, session };
  }

  /**
   * Audit a failed tool call with the real policy decision when there was one.
   *
   * Never throws: an audit write error must not replace the error the caller
   * actually needs to see (and on the success path, must not make an agent
   * think a non-idempotent command failed after it already ran).
   */
  async function auditFailure(
    ctx: ToolContext,
    profileName: string,
    state: AuditState,
    failureClass: CommandClass,
    err: any,
  ): Promise<void> {
    const evaluation = (err instanceof PolicyRefusedError ? err.evaluation : undefined)
      ?? state.evaluation
      ?? rejectedEvaluation(failureClass);
    try {
      await auditResult(ctx, profileName, state.command, evaluation, {
        error: err?.message ?? String(err),
      });
    } catch (auditErr) {
      console.error('Audit write failed while recording a tool failure:', auditErr);
    }
  }

  function defaultProfileName(profile?: string): string {
    return profile || registry.getProfile().name;
  }

  /** The profile's SSH user, or a placeholder — never throws, so an audit write cannot fail. */
  function profileUser(profileName: string): string {
    return registry.listAllProfiles().find((p) => p.name === profileName)?.user ?? '(unresolved)';
  }

  /** True only when the profile actually widens the frozen allowlist; otherwise undefined. */
  function profileHasAlgorithmsOverride(profileName: string): boolean | undefined {
    const profile = registry.listAllProfiles().find((p) => p.name === profileName);
    return profile?.algorithms ? true : undefined;
  }

  function makeProgressSender(extra: any): ((bytes: number, tail: string) => void) | undefined {
    const token = extra?._meta?.progressToken;
    if (token === undefined) return undefined;
    return (bytes, tail) => {
      extra.sendNotification({
        method: 'notifications/progress',
        params: { progressToken: token, progress: bytes, message: tail },
      }).catch(() => {});
    };
  }

  interface RunContext {
    conn: Awaited<ReturnType<typeof resolveConn>>;
    /** Sanitized (and wrapped, where applicable) command actually being run. */
    command: string;
    profileName: string;
    onProgress?: (bytes: number, tail: string) => void;
    abortSignal?: AbortSignal;
    extra: any;
    /**
     * Append detail that only exists once the operation has started, so the
     * audit record describes what actually happened.
     *
     * The streaming SFTP tools are why this exists (#207). Their local path can
     * only be resolved by touching the filesystem — creating a staged `.part`,
     * and answering "does this exist?" through the error it returns — and doing
     * that before the policy decision hands those effects to a caller who is
     * about to be denied. So the resolved local path is not available when
     * policy runs, and the audit record still has to name it.
     *
     * Append-only, and enforced rather than documented: the refined string must
     * start with the exact string policy evaluated and the approver saw. That
     * keeps this from being a way to audit a different operation than the one
     * that was authorized — the subject can be elaborated, never replaced.
     */
    refineCommand: (command: string) => void;
  }

  interface AuditedOpts {
    toolName: string;
    /** Class recorded when a failure happens before policy produced a decision. */
    failureClass: CommandClass;
    profile?: string;
    session?: string;
    extra: any;
    /** Reject anything the policy engine did not classify as this. */
    enforceClass?: CommandClass;
    /**
     * Synthetic commands (`sftp:upload …`, `kill -TERM …`, `session:open …`)
     * are built by us, not the caller, so they skip caller-input sanitization.
     */
    synthetic?: boolean;
    /** Extra check on the sanitized command before policy evaluation. */
    preCheck?: (cleanCmd: string) => void;
    /** Rewrite what policy evaluates and what runs (the sudo wrapper). */
    wrap?: (cleanCmd: string) => string;
    /**
     * What the call acts on beyond its command string — its remote path, for the SFTP
     * tools. Forwarded whole to the policy engine, so `[policy].denylist` is tested
     * against it as well as against the command string, which for these tools is one we
     * compose, and OPA's `resource` gains it (#230).
     */
    resource?: PolicyResource;
  }

  /**
   * The one place the sanitize → policy → approve → run → audit pipeline lives.
   *
   * Five of the six audited handlers used to inline their own copy of this, and
   * they had already drifted apart: one dropped abort/progress support, one
   * audited a different command string on success than on failure, one carried
   * a dead `?? command` fallback. Every audit-semantics fix had to be made six
   * times, so they were never all correct at once.
   */
  async function runAudited(
    command: string,
    opts: AuditedOpts,
    run: (rt: RunContext) => Promise<{ audited: CommandResult; output: ToolResult }>,
  ): Promise<ToolResult> {
    const ctx = makeCtx(opts.extra, opts.profile, opts.session);
    const onProgress = makeProgressSender(opts.extra);
    const abortSignal = opts.extra?.signal;

    // Named before the try because `auditFailure` needs something to file the record
    // under even when resolution itself is what failed. Reassigned to the resolved name as
    // the first statement inside, so the quota key and the audit record are unchanged on
    // every path that gets that far.
    let profileName = opts.profile ?? '(default)';

    // Profile resolution and sanitization both run inside the try, so a rejected call
    // still leaves an audit trail — a client probing with malformed payloads, or probing
    // a server that has no config at all, used to leave none. The unconfigured refusal
    // reaches this the same way a bad command does.
    const state: AuditState = { command };
    try {
      profileName = defaultProfileName(opts.profile);
      const profile = registry.getProfile(profileName);
      let effective = opts.synthetic ? command : sanitizeCommand(command, profile.maxChars);
      state.command = effective;

      opts.preCheck?.(effective);

      if (opts.wrap) {
        effective = opts.wrap(effective);
        state.command = effective;
      }

      const { conn, evaluation, approver } = await checkPolicyAndApprove(
        effective, profileName, opts.toolName, opts.resource,
      );
      state.evaluation = evaluation;

      if (opts.enforceClass && evaluation.commandClass !== opts.enforceClass) {
        // A command that fell to `safe` because a reader's grammar rejected one
        // of its argv words is one spelling away from the class this tool
        // demands — say which word, or the caller only learns that the tool
        // refused it, not why the reader that ran the exact same binary
        // would not have.
        const rejectionSuffix = evaluation.readOnlyRejection
          ? ` ${formatReadOnlyRejection(evaluation.readOnlyRejection)}`
          : '';
        throw new Error(
          `${opts.toolName} only accepts ${opts.enforceClass} commands, got: ${evaluation.commandClass}${rejectionSuffix}`,
        );
      }

      // Counted after the policy allowed it and before it runs: a denied
      // command should not burn quota, and an allowed one should be counted
      // even if it later fails on the host — the work was still spent.
      const budget = quota.consume(profileName, profile.commandQuotaPerDay);
      if (!budget.allowed) {
        throw new PolicyRefusedError(
          `QUOTA_EXCEEDED: profile "${profileName}" has used its ${profile.commandQuotaPerDay} commands ` +
          `for the last 24h. Next slot frees at ${budget.retryAt?.toISOString()}.`,
          { ...evaluation, decision: 'deny', ruleId: 'command-quota' },
        );
      }

      const approved = effective;
      const refineCommand = (refined: string) => {
        if (!refined.startsWith(approved)) {
          throw new Error('Internal: an audited command may only be elaborated, not replaced');
        }
        state.command = refined;
      };

      const { audited, output } = await run({
        conn, command: effective, profileName, onProgress, abortSignal, extra: opts.extra,
        refineCommand,
      });

      // `state.command`, not `effective`: identical unless the handler refined
      // it, and the refinement is exactly what the success record should carry.
      // The failure path below already reads `state`, so the two agree.
      await auditResult(ctx, profileName, state.command, evaluation, audited, approver);
      return output;
    } catch (err: any) {
      await auditFailure(ctx, profileName, state, opts.failureClass, err);
      throw err;
    }
  }

  /** Run a command over the connection and report it verbatim to the client. */
  function execAndReport(opts: { stdin?: string } = {}) {
    return async (rt: RunContext) => {
      const audited = await rt.conn.exec(rt.command, {
        stdin: opts.stdin,
        onProgress: rt.onProgress,
        abortSignal: rt.abortSignal,
      });
      return { audited, output: commandOutput(audited) };
    };
  }

  return { runAudited, execAndReport, defaultProfileName, makeCtx, auditResult, auditFailure, resolveConn, quota, grants };
}

export type Pipeline = ReturnType<typeof createPipeline>;
