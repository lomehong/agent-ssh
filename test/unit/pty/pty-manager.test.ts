import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { EventEmitter } from 'node:events';

// terminateChannel reaches into ssh2 channel internals no test fake carries;
// the manager test asserts lifecycle decisions, not the signal ladder (that is
// channel-signal.test.ts's job, with its own behavioural tripwire).
vi.mock('../../../src/ssh/channel-signal.js', () => ({
  terminateChannel: () => true,
  COULD_NOT_SIGNAL: 'could not signal',
}));

import { PtySessionManager } from '../../../src/pty/pty-manager.js';
import type { Profile } from '../../../src/types.js';

class FakeChannel extends EventEmitter {
  writes: string[] = [];
  resized: Array<[number, number]> = [];
  closedCount = 0;
  stderr = new EventEmitter();
  write(input: string) { this.writes.push(input); }
  setWindow(rows: number, cols: number) { this.resized.push([rows, cols]); }
  close() { this.closedCount++; }
  emitData(text: string) { this.emit('data', Buffer.from(text)); }
}

function makeProfile(overrides: Partial<Profile> = {}): Profile {
  return {
    name: 'dev', host: 'h', port: 22, user: 'u', auth: 'password',
    tty: false, keyboardInteractive: false, timeout: 15000, maxChars: 5000,
    maxOutputBytes: 1048576, role: 'operator', readOnly: false,
    approvalPolicy: 'auto', cert: false, announceAgent: true,
    sessionMaxPerConnection: 2, sessionIdleTimeoutMs: 60000,
    sessionBackgroundMaxMs: 3600000, commandQuotaPerDay: 0,
    transferMaxBytes: 268435456, transferTimeoutMs: 300000,
    ...overrides,
  };
}

function makeManager(overrides: { idle?: number; lifetime?: number; maxSessions?: number; maxBufferBytes?: number } = {}) {
  const channels: FakeChannel[] = [];
  const client = {
    shell: (_window: unknown, _opts: unknown, cb: (err: Error | null, stream: FakeChannel) => void) => {
      const ch = new FakeChannel();
      channels.push(ch);
      cb(null, ch);
    },
  };
  const manager = new PtySessionManager({
    profile: () => makeProfile({ sessionMaxPerConnection: overrides.maxSessions ?? 2 }),
    getClient: () => client as never,
    idleTimeoutMs: overrides.idle ?? 1000,
    maxLifetimeMs: overrides.lifetime ?? 5000,
    maxBufferBytes: overrides.maxBufferBytes,
    openTranscript: async () => null,
  });
  return { manager, channels };
}

beforeEach(() => vi.useFakeTimers());
afterEach(() => vi.useRealTimers());

describe('PtySessionManager', () => {
  it('opens a session and routes channel output to the reader', async () => {
    const { manager, channels } = makeManager();
    await manager.open({ name: 's1' });
    channels[0].emitData('login:\n');
    const read = manager.read('s1', 0, 1000);
    expect(read.output).toBe('login:\n');
    expect(read.cursor).toBe(7);
  });

  it('delivers writes to the channel and refreshes activity', async () => {
    const { manager, channels } = makeManager();
    await manager.open({ name: 's1' });
    const outcome = manager.write('s1', 'show version\n');
    expect(outcome.delivered).toBe(true);
    expect(channels[0].writes).toEqual(['show version\n']);
  });

  it('refuses a duplicate name and enforces the per-connection cap', async () => {
    const { manager } = makeManager({ maxSessions: 2 });
    await manager.open({ name: 's1' });
    await manager.open({ name: 's2' });
    await expect(manager.open({ name: 's1' })).rejects.toThrow(/already open/);
    await expect(manager.open({ name: 's3' })).rejects.toThrow(/cap reached/);
  });

  it('resizes through to the channel', async () => {
    const { manager, channels } = makeManager();
    await manager.open({ name: 's1' });
    manager.resize('s1', 24, 80);
    expect(channels[0].resized).toEqual([[24, 80]]);
  });

  it('close removes the session and a second close reports not-found', async () => {
    const { manager } = makeManager();
    await manager.open({ name: 's1' });
    const r = manager.close('s1');
    expect(r.outcome).toBe('closed');
    expect(manager.get('s1')).toBeUndefined();
    expect(() => manager.close('s1')).toThrow(/not found/);
  });

  it('a remote-closed session is dropped by reap, so a later write reports not-found', async () => {
    const { manager, channels } = makeManager();
    await manager.open({ name: 's1' });
    channels[0].emit('close');
    // write reaps first: the remote-closed shell is dropped, and the write
    // says not-found rather than pretending the session still exists.
    expect(() => manager.write('s1', 'x\n')).toThrow(/not found/);
  });

  it('reaps a session past the idle bound with reason idle', async () => {
    const { manager, channels } = makeManager({ idle: 1000, lifetime: 60000 });
    await manager.open({ name: 's1' });
    channels[0].emitData('banner\n');
    vi.advanceTimersByTime(1001);
    const reaped = manager.reapExpired();
    expect(reaped).toEqual([{ name: 's1', reason: 'idle' }]);
    expect(manager.get('s1')).toBeUndefined();
  });

  it('activity defers the idle reap; lifetime still ends the session', async () => {
    const { manager } = makeManager({ idle: 1000, lifetime: 5000 });
    await manager.open({ name: 's1' });
    vi.advanceTimersByTime(800);
    manager.write('s1', 'x\n'); // refresh
    vi.advanceTimersByTime(800); // idle would have fired without the refresh
    expect(manager.reapExpired()).toEqual([]);
    vi.advanceTimersByTime(4200); // past lifetime (5s) since creation
    const reaped = manager.reapExpired();
    expect(reaped).toEqual([{ name: 's1', reason: 'lifetime' }]);
  });

  it('drops a remote-closed session on the next reap', async () => {
    const { manager, channels } = makeManager();
    await manager.open({ name: 's1' });
    channels[0].emit('close');
    const reaped = manager.reapExpired();
    expect(reaped).toEqual([{ name: 's1', reason: 'remote' }]);
  });

  it('buffers beyond the read cap and reports the retention drop', async () => {
    const { manager, channels } = makeManager({ maxBufferBytes: 700 });
    await manager.open({ name: 's1' });
    channels[0].emitData('x'.repeat(600));
    const r1 = manager.read('s1', 0, 100);
    expect(r1.output).toHaveLength(100);
    channels[0].emitData('y'.repeat(600));
    const info = manager.list()[0];
    expect(info.droppedBytes).toBeGreaterThan(0);
    expect(info.totalBytes).toBe(1200);
  });

  it('closeAll tears every session down (connection teardown path)', async () => {
    const { manager, channels } = makeManager();
    await manager.open({ name: 's1' });
    await manager.open({ name: 's2' });
    await manager.closeAll();
    expect(manager.size).toBe(0);
    expect(channels.every((c) => c.closedCount > 0)).toBe(true);
  });
});
