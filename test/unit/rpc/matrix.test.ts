import { describe, expect, it } from 'vitest';
import { OperatorSessionStore, generateAgentToken, hashPassword } from '../../../src/rpc/auth.js';
import { METHOD_MATRIX, isKnownMethod, methodAllowedFor } from '../../../src/rpc/matrix.js';
import { authorize, type RpcTables } from '../../../src/rpc/authorize.js';

const METHODS = Object.keys(METHOD_MATRIX);

/** 规格表（方案 §3.3）的独立抄录——测试意图与实现分离，防同义反复。 */
const SPEC_ROWS: Record<string, { agent: boolean; operator: boolean; im: boolean }> = {
  'host.hello': { agent: true, operator: true, im: false },
  'host.ping': { agent: true, operator: true, im: false },
  'host.toolManifest': { agent: true, operator: true, im: false },
  'tool.call': { agent: true, operator: true, im: false },
  'resource.list': { agent: true, operator: true, im: false },
  'resource.read': { agent: true, operator: true, im: false },
  'auth.session.start': { agent: false, operator: false, im: false },
  'auth.session.renew': { agent: false, operator: true, im: false },
  'approval.subscribe': { agent: false, operator: true, im: false },
  'approval.list': { agent: false, operator: true, im: false },
  'approval.decide': { agent: false, operator: true, im: true },
  'cli.run': { agent: false, operator: true, im: false },
  'cli.info': { agent: false, operator: true, im: false },
  'host.admin.rotateToken': { agent: false, operator: true, im: false },
};

/** 单调可拨钟。 */
function fakeClock(start = 1_000_000): { now(): number; advance(ms: number): void } {
  let t = start;
  return { now: () => t, advance(ms: number) { t += ms; } };
}

function makeTables(): RpcTables & {
  clock: ReturnType<typeof fakeClock>;
  agentToken: string;
  oldAgentToken: string;
  imToken: string;
  sessionToken: string;
} {
  const clock = fakeClock();
  const agentToken = generateAgentToken();
  const oldAgentToken = generateAgentToken(); // 已轮换：不在表内
  const imToken = generateAgentToken();
  const sessions = new OperatorSessionStore({ storedHash: hashPassword('pw'), clock: clock.now });
  const sessionToken = sessions.start('pw', 'k');
  if (!sessionToken.ok) throw new Error('session start failed');
  return {
    clock,
    agentTokens: new Set([agentToken]),
    sessions,
    imDecisionTokens: new Set([imToken]),
    agentToken,
    oldAgentToken,
    imToken,
    sessionToken: sessionToken.token,
  };
}

describe('方法×凭据矩阵（红线执行点，方案 §3.3）', () => {
  it('注册方法与规格表一致', () => {
    expect(METHODS.sort()).toEqual(Object.keys(SPEC_ROWS).sort());
  });

  it('isKnownMethod / methodAllowedFor 直查', () => {
    expect(isKnownMethod('tool.call')).toBe(true);
    expect(isKnownMethod('nope')).toBe(false);
    expect(methodAllowedFor('approval.list', 'agent')).toBe(false);
    expect(methodAllowedFor('tool.call', 'agent')).toBe(true);
    expect(methodAllowedFor('nope', 'agent')).toBeUndefined();
  });
});

describe('7 凭据态 × 全方法枚举（K9-①：5 态扩 7 态）', () => {
  const states = [
    'agent', // 有效 agent 令牌
    'operator', // 有效 operator 会话
    'none', // 无凭据
    'expired-session', // 过期会话
    'lying-class', // 谎报 class（持 agent 令牌自称 operator）
    'im', // IM 决定令牌（绑定表命中）
    'rotated-agent-token', // 已轮换旧令牌（不在表内）
  ] as const;

  function tokenFor(state: (typeof states)[number], t: ReturnType<typeof makeTables>): string | undefined {
    switch (state) {
      case 'agent':
      case 'lying-class':
        return t.agentToken;
      case 'operator':
        return t.sessionToken;
      case 'im':
        return t.imToken;
      case 'expired-session':
      case 'rotated-agent-token':
        return t.oldAgentToken === t.agentToken ? generateAgentToken() : t.oldAgentToken;
      case 'none':
        return undefined;
    }
  }

  function expectOutcome(
    method: string,
    state: (typeof states)[number],
    auth: ReturnType<typeof authorize>,
  ): void {
    const row = SPEC_ROWS[method];
    if (state === 'agent' || state === 'lying-class') {
      // 谎报 class 按真实凭据判定（M3）：结果必须与 agent 态完全一致
      expect(auth).toEqual(
        row.agent
          ? { ok: true, callerClass: 'agent' }
          : { ok: false, code: -32002, message: expect.any(String), audit: true },
      );
      return;
    }
    if (state === 'operator') {
      expect(auth).toEqual(
        row.operator
          ? { ok: true, callerClass: 'operator' }
          : { ok: false, code: -32002, message: expect.any(String), audit: true },
      );
      return;
    }
    if (state === 'im') {
      expect(auth).toEqual(
        row.im
          ? { ok: true, callerClass: 'im' }
          : { ok: false, code: -32002, message: expect.any(String), audit: true },
      );
      return;
    }
    // none / expired-session / rotated-agent-token → 未认证：仅 start 放行，其余 -32001+审计
    if (method === 'auth.session.start') {
      expect(auth).toEqual({ ok: true, callerClass: 'unauthenticated' });
    } else {
      expect(auth).toEqual({ ok: false, code: -32001, message: expect.any(String), audit: true });
    }
  }

  it('全组合（14 方法 × 7 态 = 98 断言）', () => {
    const t = makeTables();
    for (const method of METHODS) {
      for (const state of states) {
        const auth = authorize(method, tokenFor(state, t), t);
        expectOutcome(method, state, auth);
      }
    }
  });

  it('过期会话确实过期过（会话表时钟推进）', () => {
    const t = makeTables();
    t.clock.advance(31 * 60_000);
    expect(t.sessions.validate(t.sessionToken)).toBe(false);
    const auth = authorize('tool.call', t.sessionToken, t);
    expect(auth).toEqual({ ok: false, code: -32001, message: expect.any(String), audit: true });
  });
});

describe('红线专项', () => {
  it('K8-⑥ JIT 暗门断言：反射枚举全方法 × agent 令牌，无 grant/approve 语义可达', () => {
    const t = makeTables();
    for (const method of METHODS) {
      const auth = authorize(method, t.agentToken, t);
      if (auth.ok) {
        expect(method).not.toMatch(/approv|grant|authoriz|escrow/i);
      }
    }
    // approval.* 对 agent 全部 FORBIDDEN
    for (const method of METHODS) {
      if (method.startsWith('approval.')) {
        const auth = authorize(method, t.agentToken, t);
        expect(auth.ok).toBe(false);
      }
    }
  });

  it('FORBIDDEN 携带审计标记（-32002 + audit:true）', () => {
    const t = makeTables();
    const auth = authorize('approval.list', t.agentToken, t);
    expect(auth).toEqual({ ok: false, code: -32002, message: expect.any(String), audit: true });
  });

  it('未知方法 → -32601（method not found，不审计）', () => {
    const t = makeTables();
    const auth = authorize('host.selfDestruct', t.agentToken, t);
    expect(auth).toEqual({ ok: false, code: -32601, message: expect.any(String), audit: false });
  });
});
