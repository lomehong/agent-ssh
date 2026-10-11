import { describe, expect, it } from 'vitest';
import {
  AuthFailureLimitExceededError,
  BadPasswordError,
  OPERATOR_SESSION_TTL_MS,
  OperatorSessionStore,
  generateAgentToken,
  hashPassword,
  verifyPassword,
} from '../../../src/rpc/auth.js';

/** 可拨动的单调钟（毫秒）。 */
function fakeClock(start = 1_000_000): { now(): number; advance(ms: number): void } {
  let t = start;
  return {
    now: () => t,
    advance(ms: number) {
      t += ms;
    },
  };
}

describe('agent 静态令牌（≥256bit，§3.2）', () => {
  it('生成 256bit 熵的 URL 安全令牌（32 字节 → 43 字符 base64url）', () => {
    const token = generateAgentToken();
    expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it('两次生成不重复', () => {
    const seen = new Set(Array.from({ length: 100 }, () => generateAgentToken()));
    expect(seen.size).toBe(100);
  });
});

describe('operator 口令哈希（scrypt+盐，D13 零新依赖）', () => {
  it('hashPassword 产出 salt:hash 十六进制格式（16B 盐 + 64B scrypt）', () => {
    const stored = hashPassword('correct horse battery staple');
    const [salt, hash] = stored.split(':');
    expect(salt).toMatch(/^[0-9a-f]{32}$/);
    expect(hash).toMatch(/^[0-9a-f]{128}$/);
  });

  it('同口令两次哈希盐不同（防彩虹表）', () => {
    expect(hashPassword('pw')).not.toBe(hashPassword('pw'));
  });

  it('verifyPassword 正确/错误判定', () => {
    const stored = hashPassword('s3cret!');
    expect(verifyPassword('s3cret!', stored)).toBe(true);
    expect(verifyPassword('wrong', stored)).toBe(false);
  });

  it('存储串被篡改时验证失败而非抛异常', () => {
    expect(verifyPassword('x', 'no-colon')).toBe(false);
    expect(verifyPassword('x', 'zz:zz')).toBe(false);
  });
});

describe('operator 会话（30min 滑动 TTL + 失败限速复用 AuthFailureLimiter）', () => {
  it('口令正确 → 发放会话令牌（≥256bit）且 validate 通过', () => {
    const store = new OperatorSessionStore({ storedHash: hashPassword('pw') });
    const result = store.start('pw', '10.0.0.1');
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.token).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect(store.validate(result.token)).toBe(true);
    }
  });

  it('口令错误 → BadPasswordError 且计入失败预算', () => {
    const store = new OperatorSessionStore({ storedHash: hashPassword('pw') });
    expect(() => store.start('nope', '10.0.0.2')).toThrow(BadPasswordError);
    // 第 10 次（默认 DEFAULT_AUTH_FAILURE_LIMIT）后该键被限速
    for (let i = 0; i < 9; i++) {
      expect(() => store.start('nope', '10.0.0.2')).toThrow(BadPasswordError);
    }
    expect(() => store.start('nope', '10.0.0.2')).toThrow(AuthFailureLimitExceededError);
    // 正确口令也被锁（该地址预算耗尽——设计内：地址耗尽一切都要等）
    expect(() => store.start('pw', '10.0.0.2')).toThrow(AuthFailureLimitExceededError);
    // 其他地址不受影响
    const other = store.start('pw', '10.0.0.3');
    expect(other.ok).toBe(true);
  });

  it('TTL：30min 内有效，过期即失效（可注入单调钟）', () => {
    const clock = fakeClock();
    const store = new OperatorSessionStore({ storedHash: hashPassword('pw'), clock: clock.now });
    const result = store.start('pw', 'k');
    if (!result.ok) throw new Error('start failed');
    clock.advance(OPERATOR_SESSION_TTL_MS - 1);
    expect(store.validate(result.token)).toBe(true);
    clock.advance(1);
    expect(store.validate(result.token)).toBe(false);
  });

  it('renew 滑动续期：用一次就续一次', () => {
    const clock = fakeClock();
    const store = new OperatorSessionStore({ storedHash: hashPassword('pw'), clock: clock.now });
    const result = store.start('pw', 'k');
    if (!result.ok) throw new Error('start failed');
    clock.advance(20 * 60_000);
    expect(store.renew(result.token)).toBe(true);
    clock.advance(29 * 60_000); // 距始发 49min，距续期 29min
    expect(store.validate(result.token)).toBe(true);
    clock.advance(60_001); // 距续期 30min+
    expect(store.validate(result.token)).toBe(false);
  });

  it('吊销（revoke）立即使会话失效', () => {
    const store = new OperatorSessionStore({ storedHash: hashPassword('pw') });
    const result = store.start('pw', 'k');
    if (!result.ok) throw new Error('start failed');
    store.revoke(result.token);
    expect(store.validate(result.token)).toBe(false);
    expect(store.renew(result.token)).toBe(false);
  });

  it('未知令牌 validate/renew 一律 false（不区分不存在与过期之外的形态）', () => {
    const store = new OperatorSessionStore({ storedHash: hashPassword('pw') });
    expect(store.validate('bogus')).toBe(false);
    expect(store.renew('bogus')).toBe(false);
  });
});
