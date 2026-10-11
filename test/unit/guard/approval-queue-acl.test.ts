import { describe, it, expect, beforeEach, afterEach } from 'vitest';

// win32-only enforcement：POSIX 上该函数直接返回（0700 chmod 是那一侧的控制），
// 委托/传播行为因此在 Windows 上验证。
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { assertQueueDirPrivate } from '../../../src/guard/approval-queue.js';
import type { AclVerdict } from '../../../src/config/sddl.js';

// T-11 粘合层测试：assertQueueDirPrivate 的职责是「win32 时委托上游
// assertPrivateOnWindows 并传播其拒绝；POSIX 直接放行（0700 chmod 是那一侧
// 的控制）」。broad/unknown 判定会触发上游拒绝的语义归上游自有测试所有
// （windows-acl 家族），此处不重测——本文件钉住委托与传播。

const clean: AclVerdict = { status: 'restricted' };

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'queue-acl-'));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe.skipIf(process.platform !== 'win32')('assertQueueDirPrivate（Windows 强制委托）', () => {
  it('restricted 判定放行', async () => {
    await expect(assertQueueDirPrivate(dir, async () => clean)).resolves.toBeUndefined();
  });

  it('检查失败（icacls 不可用等）原样传播，不吞错', async () => {
    const boom = async () => { throw new Error('icacls exploded'); };
    await expect(assertQueueDirPrivate(dir, boom)).rejects.toThrow('icacls exploded');
  });

  it('上游拒绝（以 throw 表达）原样传播', async () => {
    const refuse = async () => { throw new Error('readable beyond its owner: S-1-5-21-…'); };
    await expect(assertQueueDirPrivate(dir, refuse)).rejects.toThrow('readable beyond its owner');
  });
});
