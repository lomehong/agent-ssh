import { describe, expect, it } from 'vitest';
import { RECONNECT_MAX_DELAY_MS, nextRetryDelayMs } from '../../../src/rpc/reconnect.js';

describe('断线重连指数退避（§3.1：stub/审批端断线指数退避重连）', () => {
  it('1s 起步逐次翻倍，封顶 30s', () => {
    expect(nextRetryDelayMs(0)).toBe(1000);
    expect(nextRetryDelayMs(1)).toBe(2000);
    expect(nextRetryDelayMs(2)).toBe(4000);
    expect(nextRetryDelayMs(3)).toBe(8000);
    expect(nextRetryDelayMs(4)).toBe(16000);
    expect(nextRetryDelayMs(5)).toBe(32000 > RECONNECT_MAX_DELAY_MS ? RECONNECT_MAX_DELAY_MS : 32000);
    expect(nextRetryDelayMs(6)).toBe(RECONNECT_MAX_DELAY_MS);
    expect(nextRetryDelayMs(50)).toBe(RECONNECT_MAX_DELAY_MS);
  });

  it('封顶值即 30s 常量', () => {
    expect(RECONNECT_MAX_DELAY_MS).toBe(30_000);
  });
});
