import { describe, expect, it, afterEach } from 'vitest';
import { mkdtempSync, rmSync, readFileSync, existsSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { acquirePidfile, PidfileLockedError } from '../../../src/rpc/pidfile.js';

let dir: string | undefined;
const holders: { release(): void }[] = [];

afterEach(() => {
  for (const h of holders.splice(0)) h.release();
  if (dir !== undefined && existsSync(dir)) rmSync(dir, { recursive: true, force: true });
  dir = undefined;
});

function pidPath(name: string): string {
  dir ??= mkdtempSync(join(tmpdir(), 'rpc-pidfile-'));
  return join(dir, name);
}

describe('pidfile 单实例（T-15 验收 6，D5' + "' 二次启动 fail-fast）", () => {
  it('获取成功并写入自身 pid；release 删除文件', () => {
    const path = pidPath('host.pid');
    const handle = acquirePidfile(path);
    holders.push(handle);
    expect(readFileSync(path, 'utf8')).toBe(String(process.pid));
    handle.release();
    expect(existsSync(path)).toBe(false);
  });

  it('进程活着时二次获取 → PidfileLockedError 且携带 pid', () => {
    const path = pidPath('live.pid');
    const handle = acquirePidfile(path);
    holders.push(handle);
    expect(() => acquirePidfile(path)).toThrow(PidfileLockedError);
    try {
      acquirePidfile(path);
    } catch (err) {
      expect((err as PidfileLockedError).pid).toBe(process.pid);
    }
  });

  it('陈旧 pidfile（进程已死）→ 接管而非拒绝', () => {
    const path = pidPath('stale.pid');
    writeFileSync(path, '999999999', 'utf8'); // 不存在的 pid
    const handle = acquirePidfile(path);
    holders.push(handle);
    expect(readFileSync(path, 'utf8')).toBe(String(process.pid));
  });

  it('损坏的 pidfile 内容 → 视为陈旧接管（运维可恢复）', () => {
    const path = pidPath('corrupt.pid');
    writeFileSync(path, 'not-a-pid', 'utf8');
    const handle = acquirePidfile(path);
    holders.push(handle);
    expect(readFileSync(path, 'utf8')).toBe(String(process.pid));
  });

  it('release 幂等（重复 release 不抛）', () => {
    const handle = acquirePidfile(pidPath('idem.pid'));
    handle.release();
    expect(() => handle.release()).not.toThrow();
  });
});
