import { describe, it, expect, afterEach } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHarness, type Harness } from './harness.js';
import { listPending, decideApproval } from '../../../src/guard/approval-queue.js';
import { TOOL_DESCRIPTIONS } from '../../../src/tools/descriptions.js';

// The queue channel, through the real pipeline: a destructive command with no
// elicitation answer lands in the queue, and only a human decision moves it.
// The model-side red line is pinned at the bottom: no approval verb may ever
// appear on the tool surface.

let dir: string;
let h: Harness;

afterEach(async () => {
  await h?.close();
  rmSync(dir, { recursive: true, force: true });
});

function queueHarness() {
  dir = mkdtempSync(join(tmpdir(), 'approval-queue-pipeline-'));
  return createHarness(
    {},
    { approvalChannel: 'queue', approvalQueueDir: dir, approvalQueuePollMs: 5, approvalQueueInspectAcl: async () => ({ status: 'restricted' }) },
  );
}

describe('approval queue channel (pipeline)', () => {
  it('a destructive command waits in the queue until the CLI approves it', async () => {
    h = await queueHarness();
    const callPromise = h.client.callTool({ name: 'run-command', arguments: { command: 'rm -rf /tmp/build' } }) as Promise<any>;

    // The call is now blocked on the queue, not on elicitation.
    await new Promise((r) => setTimeout(r, 60));
    const pending = await listPending({ dir });
    expect(pending).toHaveLength(1);
    expect(pending[0].command).toBe('rm -rf /tmp/build');
    expect(pending[0].commandClass).toBe('destructive');

    const outcome = await decideApproval(pending[0].id, 'approved', { dir });
    expect(outcome.decided).toBe(true);

    const res = await callPromise;
    expect(res.isError).toBeFalsy();
    expect(h.execCalls.map((c) => c.command)).toContain('rm -rf /tmp/build');
    expect(h.auditRecords.at(-1)?.approver).toMatch(/^cli:/);
  });

  it('a CLI rejection denies the command without running it', async () => {
    h = await queueHarness();
    const callPromise = h.client.callTool({ name: 'run-command', arguments: { command: 'rm -rf /tmp/build' } }) as Promise<any>;
    await new Promise((r) => setTimeout(r, 60));
    const pending = await listPending({ dir });
    await decideApproval(pending[0].id, 'rejected', { dir });

    const res = await callPromise;
    expect(res.isError).toBe(true);
    expect(h.execCalls).toHaveLength(0);
  });

  it('elicitation is never attempted in queue mode (prompts stay at zero)', async () => {
    h = await queueHarness();
    const callPromise = h.client.callTool({ name: 'run-command', arguments: { command: 'rm -rf /tmp/build' } }) as Promise<any>;
    await new Promise((r) => setTimeout(r, 60));
    const pending = await listPending({ dir });
    await decideApproval(pending[0].id, 'approved', { dir });
    await callPromise;
    // The whole reason the channel exists: hosts without elicitation support
    // still get a working human gate, not an APPROVAL_UNAVAILABLE wall.
    expect(h.approvalPrompts()).toBe(0);
  });


  it.skipIf(process.platform !== 'win32')('队列目录 ACL 检查失败 → fail-closed（APPROVAL_UNAVAILABLE，T-11 强制；POSIX 上 assertQueueDirPrivate 为 no-op）', async () => {
    dir = mkdtempSync(join(tmpdir(), 'approval-queue-acl-'));
    h = await createHarness(
      {},
      {
        approvalChannel: 'queue',
        approvalQueueDir: dir,
        approvalQueuePollMs: 5,
        approvalQueueInspectAcl: async () => { throw new Error('icacls exploded'); },
      },
    );
    const res = await h.client.callTool({ name: 'run-command', arguments: { command: 'rm -rf /tmp/build' } }) as any;
    expect(res.isError).toBe(true);
    const text = (res.content ?? []).map((c: any) => c.text ?? '').join('');
    expect(text).toContain('APPROVAL_UNAVAILABLE');
    expect(text).toContain('privacy check');
    // fail-closed：命令绝不能在检查失败的队列上等待或执行。
    expect(h.execCalls).toHaveLength(0);
  });
  it('a client decline is final — the queue is never consulted behind a no', async () => {
    dir = mkdtempSync(join(tmpdir(), 'approval-both-'));
    h = await createHarness(
      {},
      { approvalChannel: 'both', approvalQueueDir: dir, approvalQueuePollMs: 5, approvalQueueInspectAcl: async () => ({ status: 'restricted' }) },
    );
    h.setApproval(false);
    const res = await h.client.callTool({ name: 'run-command', arguments: { command: 'rm -rf /tmp/build' } }) as any;
    expect((await res).isError).toBe(true);
    // Queueing behind an explicit no would shop for a second opinion.
    expect(await listPending({ dir })).toHaveLength(0);
    expect(h.execCalls).toHaveLength(0);
  });
});

describe('model-side red line: no approval verb on the tool surface', () => {
  it('no tool name or description offers approve/reject/decide to the model', () => {
    for (const [name, description] of Object.entries(TOOL_DESCRIPTIONS)) {
      expect(name).not.toMatch(/approv|decide/i);
      // The description must not advertise a decision action either — the gate
      // is human-only, and the model reads descriptions.
      expect(description).not.toMatch(/approve (this|the) (command|request)|you can approve/i);
    }
  });
});
