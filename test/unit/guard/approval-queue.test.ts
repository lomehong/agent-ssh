import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  assertQueueDirPrivate,
  createApprovalRequest,
  waitForDecision,
  decideApproval,
  listPending,
  fingerprintOf,
  getApprovalQueueDir,
} from '../../../src/guard/approval-queue.js';

// The queue is a human gate with the model on one side and a filesystem on the
// other: everything that can go wrong here is a fail-closed question — expiry,
// tampering, double decisions — and each test below is one of those questions.

let dir: string;

const REQUEST = {
  profile: 'prod-web-1',
  command: 'rm -rf /tmp/build',
  commandClass: 'destructive',
  binary: 'rm',
};

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'approval-queue-'));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe('approval queue lifecycle', () => {
  it('creates a pending file whose fingerprint matches its payload', async () => {
    const req = await createApprovalRequest({ ...REQUEST, timeoutMs: 60_000 }, { dir });
    const stored = JSON.parse(readFileSync(join(dir, 'pending', `${req.id}.json`), 'utf8'));
    expect(stored.status).toBe('pending');
    expect(stored.fingerprint).toBe(fingerprintOf(stored));
    expect(stored.command).toBe(REQUEST.command);
  });

  it('an approved decision reaches the waiter with a cli: approver', async () => {
    const req = await createApprovalRequest({ ...REQUEST, timeoutMs: 60_000 }, { dir });
    const waiter = waitForDecision(req.id, { dir, fingerprint: req.fingerprint, expiresAt: req.expiresAt, pollMs: 5 });
    const outcome = await decideApproval(req.id, 'approved', { dir, by: 'the-operator' });
    expect(outcome.decided).toBe(true);
    const result = await waiter;
    expect(result.approved).toBe(true);
    expect(result.approver).toBe('cli:the-operator');
  });

  it('a rejected decision denies without an unavailable cause (it was a human no)', async () => {
    const req = await createApprovalRequest({ ...REQUEST, timeoutMs: 60_000 }, { dir });
    const waiter = waitForDecision(req.id, { dir, fingerprint: req.fingerprint, expiresAt: req.expiresAt, pollMs: 5 });
    await decideApproval(req.id, 'rejected', { dir });
    const result = await waiter;
    expect(result.approved).toBe(false);
    expect(result.unavailable).toBeUndefined();
  });

  it('expires fail-closed and the file records it', async () => {
    const req = await createApprovalRequest({ ...REQUEST, timeoutMs: 30 }, { dir, now: new Date(Date.now() - 60_000) });
    const result = await waitForDecision(req.id, { dir, fingerprint: req.fingerprint, expiresAt: req.expiresAt, pollMs: 5 });
    expect(result.approved).toBe(false);
    expect(result.unavailable).toMatch(/expired/);
    const stored = JSON.parse(readFileSync(join(dir, 'pending', `${req.id}.json`), 'utf8'));
    expect(stored.status).toBe('expired');
  });

  it('the CLI refuses to decide an expired request', async () => {
    const req = await createApprovalRequest({ ...REQUEST, timeoutMs: 30 }, { dir, now: new Date(Date.now() - 60_000) });
    const outcome = await decideApproval(req.id, 'approved', { dir });
    expect(outcome.decided).toBe(false);
    expect(outcome.message).toMatch(/expired/);
  });

  it('a decision whose fingerprint does not match the shown payload is refused', async () => {
    const req = await createApprovalRequest({ ...REQUEST, timeoutMs: 60_000 }, { dir });
    const waiter = waitForDecision(req.id, { dir, fingerprint: req.fingerprint, expiresAt: req.expiresAt, pollMs: 5 });
    // An attacker (or an editor) rewrites the command after the human saw it.
    const file = join(dir, 'pending', `${req.id}.json`);
    const stored = JSON.parse(readFileSync(file, 'utf8'));
    stored.command = 'rm -rf /';
    stored.decisionFingerprint = fingerprintOf(stored); // recomputed by the tamperer
    stored.status = 'approved';
    const { writeFileSync } = await import('node:fs');
    writeFileSync(file, JSON.stringify(stored, null, 2));
    const result = await waiter;
    // The waiter pins the fingerprint it queued; a different payload hash —
    // even a self-consistent one — is a mismatch, because what was approved
    // is not what was queued.
    expect(result.approved).toBe(false);
    expect(result.unavailable).toMatch(/fingerprint mismatch/);
  });

  it('double decisions are refused (first decision wins)', async () => {
    const req = await createApprovalRequest({ ...REQUEST, timeoutMs: 60_000 }, { dir });
    await decideApproval(req.id, 'rejected', { dir });
    const second = await decideApproval(req.id, 'approved', { dir });
    expect(second.decided).toBe(false);
    expect(second.message).toMatch(/already rejected/);
  });

  it('lists pending requests oldest-first', async () => {
    await createApprovalRequest({ ...REQUEST, timeoutMs: 60_000 }, { dir, now: new Date(1000) });
    await createApprovalRequest({ ...REQUEST, timeoutMs: 60_000 }, { dir, now: new Date(2000) });
    const pending = await listPending({ dir });
    expect(pending.map((p) => p.createdAt)).toEqual([...pending.map((p) => p.createdAt)].sort());
    expect(pending).toHaveLength(2);
  });

  it('ids cannot traverse the filesystem', async () => {
    await expect(decideApproval('../evil', 'approved', { dir })).rejects.toThrow(/Invalid approval id/);
  });
});

describe('queue directory default', () => {
  it('is platform-scoped under the agent-ssh namespace, never a shared path', () => {
    const p = getApprovalQueueDir();
    expect(p).toContain('agent-ssh');
    expect(p).toMatch(/approvals$/);
  });
});

describe('assertQueueDirPrivate（T-19 验收②实证）', () => {
  it('目录未建时先建后查：Windows 首次部署不再 icacls read-refused（红灯→绿灯）', async () => {
    if (process.platform !== 'win32') return; // 检查本身 win32 专属（POSIX 空操作）
    const dir = join(mkdtempSync(join(tmpdir(), 'acl-t19-')), 'approvals');
    // 红灯基线：目录不存在时旧实现 icacls read-refused → fail-closed 拒绝。
    await expect(assertQueueDirPrivate(dir)).resolves.toBeUndefined(); // 绿：先建后查
    expect(existsSync(dir)).toBe(true);
  });
});

describe('并发决定仲裁（K7：Host 侧按 id 串行化）', () => {
  it('同 id 并发 approve+reject 恰好一生效，败者收「已决定」', async () => {
    const req = await createApprovalRequest({ ...REQUEST, timeoutMs: 60_000 }, { dir });
    const outcomes = await Promise.all([
      decideApproval(req.id, 'approved', { dir, by: 'desktop' }),
      decideApproval(req.id, 'rejected', { dir, by: 'cli' }),
    ]);
    expect(outcomes.filter((o) => o.decided)).toHaveLength(1);
    const loser = outcomes.find((o) => !o.decided)!;
    expect(loser.message).toMatch(/already (approved|rejected)/);
    // 落盘终态与唯一胜者一致
    const stored = JSON.parse(readFileSync(join(dir, 'pending', `${req.id}.json`), 'utf8'));
    const winner = outcomes.find((o) => o.decided)!;
    expect(stored.status).toBe(winner.message.startsWith('approved') ? 'approved' : 'rejected');
    expect(stored.decidedBy).toBe(winner.message.startsWith('approved') ? 'desktop' : 'cli');
  });

  it('不同 id 并发决定互不阻塞（锁按 id 分键，双双生效）', async () => {
    const r1 = await createApprovalRequest({ ...REQUEST, timeoutMs: 60_000 }, { dir });
    const r2 = await createApprovalRequest({ ...REQUEST, timeoutMs: 60_000 }, { dir });
    const [o1, o2] = await Promise.all([
      decideApproval(r1.id, 'approved', { dir }),
      decideApproval(r2.id, 'approved', { dir }),
    ]);
    expect(o1.decided).toBe(true);
    expect(o2.decided).toBe(true);
  });
});
