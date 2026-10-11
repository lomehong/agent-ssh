import { mkdir, readFile, readdir, writeFile, chmod } from 'fs/promises';
import { homedir, platform, userInfo } from 'os';
import { join } from 'path';
import { createHash } from 'crypto';

/**
 * File-based approval queue — the human gate for hosts whose MCP client has no
 * elicitation support (plan §2, owner-ratified 2026-10-11 R6).
 *
 * Shape: the server writes one `pending/<id>.json` per blocked command; the
 * operator decides it from the CLI (`agent-ssh approvals approve|reject <id>`);
 * the server polls the same file and acts only on a decision whose
 * `decisionFingerprint` still matches the request it queued. No decision
 * interface is exposed to the model — the only writers of a decision are this
 * CLI and the human behind it.
 *
 * The fingerprint is a tripwire, not the control. The control is the
 * directory's permissions: `0700` on POSIX, and on Windows an
 * `assertPrivateOnWindows` check before the server waits. A fingerprint pins
 * the decision to the exact payload the human saw; it cannot stop someone who
 * can already rewrite the file.
 */

export type ApprovalChannel = 'elicitation' | 'queue' | 'both';

export interface PendingApproval {
  id: string;
  createdAt: string;
  expiresAt: string;
  profile: string;
  command: string;
  commandClass: string;
  binary: string;
  fingerprint: string;
  status: 'pending' | 'approved' | 'rejected' | 'expired';
  decidedAt?: string;
  decidedBy?: string;
  decisionFingerprint?: string;
}

export interface ApprovalQueueResult {
  approved: boolean;
  approver?: string;
  unavailable?: string;
}

export function getApprovalQueueDir(): string {
  const home = homedir();
  const p = platform();
  if (p === 'darwin') return join(home, 'Library', 'Application Support', 'agent-ssh', 'approvals');
  if (p === 'win32') {
    return join(process.env.LOCALAPPDATA || join(home, 'AppData', 'Local'), 'agent-ssh', 'approvals');
  }
  const xdgData = process.env.XDG_DATA_HOME || join(home, '.local', 'share');
  return join(xdgData, 'agent-ssh', 'approvals');
}

/** Canonical integrity hash of the payload the human is shown. */
export function fingerprintOf(req: Pick<PendingApproval, 'id' | 'profile' | 'command' | 'commandClass' | 'binary' | 'createdAt' | 'expiresAt'>): string {
  return createHash('sha256')
    .update(JSON.stringify({
      id: req.id,
      profile: req.profile,
      command: req.command,
      commandClass: req.commandClass,
      binary: req.binary,
      createdAt: req.createdAt,
      expiresAt: req.expiresAt,
    }))
    .digest('hex');
}

function pendingPath(dir: string, id: string): string {
  // The id is server-generated, but a reader-supplied id reaches this join via
  // the CLI, so refuse traversal shapes instead of trusting that.
  if (!/^[A-Za-z0-9_-]+$/.test(id)) throw new Error(`Invalid approval id: ${id}`);
  return join(dir, 'pending', `${id}.json`);
}

function newId(now: Date): string {
  return `${now.getTime()}-${Math.random().toString(36).slice(2, 8)}`;
}

function currentOSUser(): string {
  try {
    return userInfo().username || 'unknown';
  } catch {
    return 'unknown';
  }
}

async function ensureDir(dir: string): Promise<void> {
  const pending = join(dir, 'pending');
  await mkdir(pending, { recursive: true });
  // POSIX-only; Windows privacy is asserted by the ACL check the caller runs
  // (assertPrivateOnWindows shares the config loader's refuse/report split).
  if (platform() !== 'win32') {
    await chmod(dir, 0o700).catch(() => {});
    await chmod(pending, 0o700).catch(() => {});
  }
}

export interface CreateApprovalInput {
  profile: string;
  command: string;
  commandClass: string;
  binary: string;
  timeoutMs: number;
}

/** Write one pending request; returns what the operator will be shown. */
export async function createApprovalRequest(
  input: CreateApprovalInput,
  opts: { dir?: string; now?: Date } = {},
): Promise<PendingApproval> {
  const dir = opts.dir ?? getApprovalQueueDir();
  const now = opts.now ?? new Date();
  const request: PendingApproval = {
    id: newId(now),
    createdAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + input.timeoutMs).toISOString(),
    profile: input.profile,
    command: input.command,
    commandClass: input.commandClass,
    binary: input.binary,
    status: 'pending',
    fingerprint: '',
  };
  request.fingerprint = fingerprintOf(request);
  await ensureDir(dir);
  const file = pendingPath(dir, request.id);
  await writeFile(file, JSON.stringify(request, null, 2) + '\n', 'utf8');
  if (platform() !== 'win32') await chmod(file, 0o600).catch(() => {});
  return request;
}

export interface WaitOptions {
  dir?: string;
  fingerprint: string;
  expiresAt: string;
  /** Poll interval; the production default is 2s, tests use milliseconds. */
  pollMs?: number;
  now?: () => Date;
  /** Invoked once after the file is queued, for the server's stderr pointer. */
  onQueued?: (id: string) => void;
}

/**
 * Poll for a human decision until one arrives or the request expires.
 *
 * Fails closed three ways, each with its own unavailable reason: expiry
 * (nobody answered), fingerprint mismatch (the file changed after the human
 * saw it), or a rejected decision (that last one is the human's answer, and is
 * `approved: false` without an unavailable cause).
 */
export async function waitForDecision(
  id: string,
  opts: WaitOptions,
): Promise<ApprovalQueueResult> {
  const dir = opts.dir ?? getApprovalQueueDir();
  const file = pendingPath(dir, id);
  const pollMs = opts.pollMs ?? 2_000;
  const now = opts.now ?? (() => new Date());

  if (opts.onQueued) opts.onQueued(id);
  for (;;) {
    await new Promise((r) => setTimeout(r, pollMs));
    let stored: PendingApproval;
    try {
      stored = JSON.parse(await readFile(file, 'utf8')) as PendingApproval;
    } catch {
      continue; // transient: mid-write or vanished; the expiry bounds this loop
    }
    if (stored.decisionFingerprint !== undefined && stored.decisionFingerprint !== opts.fingerprint) {
      return {
        approved: false,
        unavailable: 'approval queue fingerprint mismatch — the request file changed after it was shown; refusing.',
      };
    }
    if (stored.status === 'approved' || stored.status === 'rejected') {
      return stored.status === 'approved'
        ? { approved: true, approver: `cli:${stored.decidedBy ?? currentOSUser()}` }
        : { approved: false };
    }
    if (now().getTime() >= Date.parse(stored.expiresAt)) {
      stored.status = 'expired';
      await writeFile(file, JSON.stringify(stored, null, 2) + '\n', 'utf8').catch(() => {});
      return {
        approved: false,
        unavailable: `no decision within the window; the request expired at ${stored.expiresAt} and was refused rather than left pending.`,
      };
    }
  }
}

/** Every pending request in the queue, oldest first (the CLI's list). */
export async function listPending(opts: { dir?: string } = {}): Promise<PendingApproval[]> {
  const dir = opts.dir ?? getApprovalQueueDir();
  const pending = join(dir, 'pending');
  let files: string[];
  try {
    files = (await readdir(pending)).filter((f) => f.endsWith('.json'));
  } catch {
    return [];
  }
  const out: PendingApproval[] = [];
  for (const f of files) {
    try {
      out.push(JSON.parse(await readFile(join(pending, f), 'utf8')) as PendingApproval);
    } catch {
      // A torn or corrupt file is listed as its own entry so the operator can
      // see it and delete it, rather than the queue quietly hiding it.
      out.push({
        id: f.replace(/\.json$/, ''), createdAt: '', expiresAt: '', profile: '(unreadable)',
        command: '(unreadable)', commandClass: '', binary: '', fingerprint: '', status: 'pending',
      });
    }
  }
  return out.sort((a, b) => a.createdAt.localeCompare(b.createdAt));
}

export interface DecideOutcome {
  decided: boolean;
  message: string;
}

/** CLI-side decision. Refuses anything not pending or already past expiry. */
export async function decideApproval(
  id: string,
  decision: 'approved' | 'rejected',
  opts: { dir?: string; by?: string; now?: Date } = {},
): Promise<DecideOutcome> {
  const dir = opts.dir ?? getApprovalQueueDir();
  const file = pendingPath(dir, id);
  let stored: PendingApproval;
  try {
    stored = JSON.parse(await readFile(file, 'utf8')) as PendingApproval;
  } catch {
    return { decided: false, message: `No such approval request: ${id}` };
  }
  const now = opts.now ?? new Date();
  if (stored.status !== 'pending') {
    return { decided: false, message: `Request ${id} is already ${stored.status}${stored.decidedBy ? ` by ${stored.decidedBy}` : ''}.` };
  }
  if (now.getTime() >= Date.parse(stored.expiresAt)) {
    stored.status = 'expired';
    await writeFile(file, JSON.stringify(stored, null, 2) + '\n', 'utf8');
    return { decided: false, message: `Request ${id} expired at ${stored.expiresAt}; it is marked expired and the server will refuse it.` };
  }
  stored.status = decision;
  stored.decidedAt = now.toISOString();
  stored.decidedBy = opts.by ?? currentOSUser();
  stored.decisionFingerprint = fingerprintOf(stored);
  await writeFile(file, JSON.stringify(stored, null, 2) + '\n', 'utf8');
  return { decided: true, message: `${decision}: ${stored.commandClass} command on "${stored.profile}" — ${stored.command}` };
}
