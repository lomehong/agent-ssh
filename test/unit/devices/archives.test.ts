import { describe, it, expect } from 'vitest';
import { mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { getDeviceArchive, outputEndsWithPrompt } from '../../../src/devices/archives.js';
import { FilePtyTranscript } from '../../../src/pty/transcript.js';

describe('device archives', () => {
  it('returns an archive per vendor, null for generic/absent', () => {
    for (const t of ['huawei', 'h3c', 'cisco', 'ruijie'] as const) {
      expect(getDeviceArchive(t)?.disablePaging).toBeTruthy();
      expect(getDeviceArchive(t)!.promptPatterns.length).toBeGreaterThan(0);
    }
    expect(getDeviceArchive('generic')).toBeNull();
    expect(getDeviceArchive(undefined)).toBeNull();
  });

  it('carries each vendor\'s real paging-off command', () => {
    expect(getDeviceArchive('huawei')!.disablePaging).toBe('screen-length 0 temporary');
    expect(getDeviceArchive('h3c')!.disablePaging).toBe('screen-length disable');
    expect(getDeviceArchive('cisco')!.disablePaging).toBe('terminal length 0');
    expect(getDeviceArchive('ruijie')!.disablePaging).toBe('terminal length 0');
  });
});

describe('outputEndsWithPrompt', () => {
  const huawei = getDeviceArchive('huawei')!.promptPatterns;

  it('detects a user-view prompt on the last non-empty line', () => {
    expect(outputEndsWithPrompt('\r\n<sim-huawei>', huawei)).toBe(true);
  });

  it('detects a system-view prompt', () => {
    expect(outputEndsWithPrompt('info\r\n[~sim-huawei]', huawei)).toBe(true);
  });

  it('ignores a prompt embedded mid-output when newer lines follow', () => {
    expect(outputEndsWithPrompt('<sim-huawei>\r\nsome output\r\n', huawei)).toBe(false);
  });

  it('is false for empty output or prompt-less archives', () => {
    expect(outputEndsWithPrompt('', huawei)).toBe(false);
    expect(outputEndsWithPrompt('<x>', [])).toBe(false);
  });
});

describe('FilePtyTranscript', () => {
  it('appends redacted in/out entries and reports size', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'pty-transcript-'));
    try {
      const t = await FilePtyTranscript.open('sess', { dir });
      expect(t).not.toBeNull();
      t!.append('in', 'show version\n');
      // The secret below is redactable by the audit engine's DEFAULT rules
      // (aws-access-key pattern) — the same guarantee level as the audit log
      // without its opt-in entropy scan.
      t!.append('out', 'IOS 15.2, key AKIAIOSFODNN7EXAMPLE\n');
      // Appends are queued; flush by awaiting the queue's settling through a
      // fresh stat loop.
      await new Promise((r) => setTimeout(r, 50));
      const files = readdirSync(dir);
      expect(files).toHaveLength(1);
      const body = readFileSync(join(dir, files[0]), 'utf8');
      expect(body).toContain('"dir":"in"');
      expect(body).toContain('show version');
      expect(body).not.toContain('AKIAIOSFODNN7EXAMPLE');
      expect(t!.frozen).toBe(false);
      expect(t!.bytesWritten).toBeGreaterThan(0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('freezes at the byte cap instead of growing forever', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'pty-transcript-cap-'));
    try {
      const t = await FilePtyTranscript.open('sess', { dir, maxBytes: 10 });
      t!.append('in', 'x');
      await new Promise((r) => setTimeout(r, 30));
      t!.append('in', 'this line must be refused because the cap is 10 bytes');
      expect(t!.frozen).toBe(true);
      const before = t!.bytesWritten;
      t!.append('out', 'more');
      expect(t!.bytesWritten).toBe(before);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
