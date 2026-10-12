import { describe, expect, it, afterEach } from 'vitest';
import { rmSync } from 'node:fs';
import { ChallengeStore } from '../../../src/rpc/challenge.js';

// D10/K8-②：破坏性类输入校验码——Host 生成 4 位码、仅窗口可见（随推送
// 下发）、单次有效、Host 侧 3 次失败作废 + 60s TTL（本地计数不可信）。

let dir: string | undefined;

afterEach(() => {
  if (dir !== undefined) rmSync(dir, { recursive: true, force: true });
  dir = undefined;
});

/** 可拨动的单调钟（毫秒），校验码 TTL 判定用它（§3.5 单调钟纪律）。 */
function fakeClock(start = 1_000_000): { now(): number; advance(ms: number): void } {
  let t = start;
  return {
    now: () => t,
    advance(ms: number) {
      t += ms;
    },
  };
}

describe('校验码 ChallengeStore（D10/K8-②）', () => {
  it('generate 产出 4 位数字码，且同一 approval id 重复生成返回同码', () => {
    const clock = fakeClock();
    const store = new ChallengeStore({ clock: clock.now });
    const code1 = store.generate('ap-1');
    expect(code1).toMatch(/^[0-9]{4}$/);
    expect(store.generate('ap-1')).toBe(code1);
  });

  it('verify 对码通过且单次有效：第二次即失败', () => {
    const clock = fakeClock();
    const store = new ChallengeStore({ clock: clock.now });
    const code = store.generate('ap-1');
    expect(store.verify('ap-1', code).ok).toBe(true);
    expect(store.verify('ap-1', code).ok).toBe(false);
  });

  it('verify 错码计入失败：3 次失败后作废（对码也拒）', () => {
    const clock = fakeClock();
    const store = new ChallengeStore({ clock: clock.now });
    store.generate('ap-1');
    expect(store.verify('ap-1', '0000').ok).toBe(false);
    expect(store.verify('ap-1', '0001').ok).toBe(false);
    const third = store.verify('ap-1', '0002');
    expect(third.ok).toBe(false);
    expect(third.invalidated).toBe(true);
    // 作废后即使出示对码也拒。
    expect(store.verify('ap-1', store.codeOf('ap-1') ?? '').ok).toBe(false);
  });

  it('TTL 60s：过期即失效（含对码），过期判定走单调钟不受回拨影响', () => {
    const clock = fakeClock();
    const store = new ChallengeStore({ clock: clock.now });
    const code = store.generate('ap-1');
    clock.advance(59_999);
    expect(store.verify('ap-1', code).ok).toBe(true);
    // 单次已消费——重新生成（窗口重发语义）再验 TTL 终点。
    const code2 = store.generate('ap-2');
    clock.advance(60_001);
    expect(store.verify('ap-2', code2).ok).toBe(false);
  });

  it('revoke 吊销：决定在他面完成后作废未消费码', () => {
    const clock = fakeClock();
    const store = new ChallengeStore({ clock: clock.now });
    store.generate('ap-1');
    store.revoke('ap-1');
    expect(store.verify('ap-1', store.codeOf('ap-1') ?? '').ok).toBe(false);
  });

  it('codeOf 不存在时返回 undefined（非破坏性类无码）', () => {
    const store = new ChallengeStore({ clock: fakeClock().now });
    expect(store.codeOf('ap-none')).toBeUndefined();
  });
});
