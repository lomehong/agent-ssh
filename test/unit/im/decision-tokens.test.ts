import { describe, it, expect } from 'vitest';
import { DecisionTokenStore } from '../../../src/im/decision-tokens.js';

// 单次决策令牌（K8-⑤/A8）：消费制、跨请求绑定、revokeFor 收尾。
// 「截图转发/复制按钮消息不能批别的请求」的执行点。

describe('im 决策令牌', () => {
  it('签发→消费成功一次，第二次必拒（单次消费）', () => {
    const store = new DecisionTokenStore();
    const t = store.issue('req-1');
    expect(store.consume(t, 'req-1')).toBe(true);
    expect(store.consume(t, 'req-1')).toBe(false);
  });

  it('跨请求重放必拒（req-1 的令牌批不了 req-2）', () => {
    const store = new DecisionTokenStore();
    const t = store.issue('req-1');
    expect(store.consume(t, 'req-2')).toBe(false);
    // 绑定校验失败不消费：req-1 仍可用一次。
    expect(store.consume(t, 'req-1')).toBe(true);
  });

  it('未签发/非字符串令牌必拒', () => {
    const store = new DecisionTokenStore();
    expect(store.consume('nope', 'req-1')).toBe(false);
    expect(store.consume(undefined, 'req-1')).toBe(false);
    expect(store.consume({ t: 'x' }, 'req-1')).toBe(false);
  });

  it('revokeFor：请求作废后未消费令牌失效', () => {
    const store = new DecisionTokenStore();
    const a = store.issue('req-1');
    const b = store.issue('req-1');
    store.consume(a, 'req-1'); // a 已消费
    store.revokeFor('req-1'); // b 应被收回
    expect(store.consume(b, 'req-1')).toBe(false);
    expect(store.size).toBe(0);
  });

  it('令牌强度：≥22 字符 base64url（≥128bit）', () => {
    const store = new DecisionTokenStore();
    expect(store.issue('req-1').length).toBeGreaterThanOrEqual(22);
  });
});
