import { describe, expect, it } from 'vitest';
import { PushHub } from '../../../src/rpc/push.js';

describe('approval.subscribe 推送分发（§3.3：pending/settled 两通道）', () => {
  it('发布扇出到全部订阅者并回传投递数', () => {
    const hub = new PushHub();
    const got: string[] = [];
    hub.subscribe('conn-a', (e) => got.push(`a:${e.channel}`));
    hub.subscribe('conn-b', (e) => got.push(`b:${e.channel}`));
    const n = hub.publish('approval.pending', { id: 'ap-1' });
    expect(n).toBe(2);
    expect(got).toEqual(['a:approval.pending', 'b:approval.pending']);
  });

  it('payload 原样透传（不做深拷贝承诺，但引用不变）', () => {
    const hub = new PushHub();
    const payload = { id: 'ap-2', command: 'rm -rf /tmp/x' };
    let received: unknown;
    hub.subscribe('c', (e) => {
      received = e.payload;
    });
    hub.publish('approval.settled', payload);
    expect(received).toBe(payload);
  });

  it('退订后不再投递；无订阅者发布返回 0', () => {
    const hub = new PushHub();
    let count = 0;
    const unsubscribe = hub.subscribe('c', () => count++);
    unsubscribe();
    expect(hub.publish('approval.pending', {})).toBe(0);
    expect(count).toBe(0);
  });

  it('dropAll（断连清理）移除该连接全部订阅', () => {
    const hub = new PushHub();
    let count = 0;
    hub.subscribe('c', () => count++);
    hub.subscribe('c', () => count++);
    hub.dropAll('c');
    expect(hub.publish('approval.settled', {})).toBe(0);
    expect(count).toBe(0);
  });

  it('同一连接重复订阅互不干扰（多面/多窗订阅）', () => {
    const hub = new PushHub();
    let count = 0;
    const u1 = hub.subscribe('c', () => count++);
    hub.subscribe('c', () => count++);
    hub.publish('approval.pending', {});
    expect(count).toBe(2);
    u1();
    hub.publish('approval.pending', {});
    expect(count).toBe(3);
  });
});
