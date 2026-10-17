import { describe, expect, it } from 'vitest';
import {
  OperatorSessionStore,
  generateAgentToken,
  hashPassword,
  tokenDigest,
} from '../../../src/rpc/auth.js';
import { METHOD_MATRIX, isKnownMethod, methodAllowedFor } from '../../../src/rpc/matrix.js';
import { authorize, type RpcTables } from '../../../src/rpc/authorize.js';
import { OPERATOR_SESSION_TTL_MS } from '../../../src/rpc/auth.js';
import { fakeClock } from './helpers.js';

const METHODS = Object.keys(METHOD_MATRIX);

/** 规格表（方案 §3.3）的独立抄录——测试意图与实现分离，防同义反复。 */
const SPEC_ROWS: Record<string, { agent: boolean; operator: boolean; im: boolean }> = {
  'host.hello': { agent: true, operator: true, im: false },
  'host.ping': { agent: true, operator: true, im: false },
  'host.toolManifest': { agent: true, operator: true, im: false },
  'tool.call': { agent: true, operator: true, im: false },
  'resource.list': { agent: true, operator: true, im: false },
  'resource.read': { agent: true, operator: true, im: false },
  'approval.subscribe': { agent: true, operator: true, im: false },
  'approval.list': { agent: true, operator: true, im: false },
  // T-23 弹窗补拉（未决清单附存活码）：D15 单令牌下行权与 approval.list 同类
  // （码对本地 agent 本不保密——approval.pending 推送载荷明文带码）。
  'list_pending': { agent: true, operator: true, im: false },
  'approval.history': { agent: true, operator: true, im: false },
  'audit.query': { agent: true, operator: true, im: false },
  'audit.stats': { agent: true, operator: true, im: false },
  'host.connections': { agent: true, operator: true, im: false },
  'quota.snapshot': { agent: true, operator: true, im: false },
  'approval.decide': { agent: true, operator: true, im: true },
  'cli.run': { agent: true, operator: true, im: false },
  'cli.info': { agent: true, operator: true, im: false },
  'host.admin.rotateToken': { agent: true, operator: true, im: false },
  'host.status': { agent: true, operator: true, im: false },
  'agents.scan': { agent: true, operator: true, im: false },
  'agents.configure': { agent: true, operator: true, im: false },
  'agents.remove': { agent: true, operator: true, im: false },
  'host.profiles.list': { agent: true, operator: true, im: false },
  'host.profiles.upsert': { agent: true, operator: true, im: false },
  'host.profiles.remove': { agent: true, operator: true, im: false },
};

interface Harness {
  tables: RpcTables;
  agentToken: string;
  oldAgentToken: string; // 已轮换：不在表内
  imToken: string;
  sessionToken: string;
}

function makeHarness(): Harness {
  const agentToken = generateAgentToken();
  const oldAgentToken = generateAgentToken();
  const imToken = generateAgentToken();
  const sessions = new OperatorSessionStore({ storedHash: hashPassword('pw') });
  const started = sessions.start('pw', 'k');
  if (!started.ok) throw new Error('session start failed');
  return {
    tables: {
      // 表中只存摘要（tokenDigest）——防时序 hash-then-lookup，与实现纪律一致
      agentTokens: new Set([tokenDigest(agentToken)]),
      sessions,
      imDecisionTokens: new Set([tokenDigest(imToken)]),
    },
    agentToken,
    oldAgentToken,
    imToken,
    sessionToken: started.token,
  };
}

/** 每态独立凭据与表：expired-session 态构造真过期的会话表（K9-① 名实相符）。 */
function stateCredential(
  state: (typeof states)[number],
  h: Harness,
): { tables: RpcTables; token: string | undefined } {
  if (state === 'expired-session') {
    const clock = fakeClock();
    const store = new OperatorSessionStore({ storedHash: hashPassword('pw'), clock: clock.now });
    const started = store.start('pw', 'k');
    if (!started.ok) throw new Error('session start failed');
    clock.advance(OPERATOR_SESSION_TTL_MS + 1); // 真·过期（非「未知令牌」近似）
    const expiredToken = started.token;
    return { tables: { ...h.tables, sessions: store }, token: expiredToken };
  }
  const token =
    state === 'agent' || state === 'lying-class'
      ? h.agentToken
      : state === 'operator'
        ? h.sessionToken
        : state === 'im'
          ? h.imToken
          : state === 'rotated-agent-token'
            ? h.oldAgentToken
            : undefined;
  return { tables: h.tables, token };
}

const states = [
  'agent', // 有效 agent 令牌
  'operator', // 有效 operator 会话
  'none', // 无凭据
  'expired-session', // 过期会话（真过期）
  'lying-class', // 谎报 class（持 agent 令牌自称 operator）
  'im', // IM 决定令牌（绑定表命中）
  'rotated-agent-token', // 已轮换旧令牌（不在表内）
] as const;

describe('方法×凭据矩阵（红线执行点，方案 §3.3）', () => {
  it('注册方法与规格表一致', () => {
    expect(METHODS.sort()).toEqual(Object.keys(SPEC_ROWS).sort());
  });

  it('isKnownMethod / methodAllowedFor 直查', () => {
    expect(isKnownMethod('tool.call')).toBe(true);
    expect(isKnownMethod('nope')).toBe(false);
    // 单令牌信任模型（主人 2026-10-17 裁决）：本机令牌=全权，approval.list 对 agent 开放。
    expect(methodAllowedFor('approval.list', 'agent')).toBe(true);
    expect(methodAllowedFor('tool.call', 'agent')).toBe(true);
    expect(methodAllowedFor('nope', 'agent')).toBeUndefined();
  });
});

describe('7 凭据态 × 全方法枚举（K9-①：5 态扩 7 态）', () => {
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
    const h = makeHarness();
    for (const method of METHODS) {
      for (const state of states) {
        const { tables, token } = stateCredential(state, h);
        expectOutcome(method, state, authorize(method, token, tables));
      }
    }
  });

  it('过期会话确属「曾有效后过期」：同令牌在未过期时通过、过期后 -32001', () => {
    const clock = fakeClock();
    const store = new OperatorSessionStore({ storedHash: hashPassword('pw'), clock: clock.now });
    const started = store.start('pw', 'k');
    if (!started.ok) throw new Error('session start failed');
    const tables: RpcTables = {
      agentTokens: new Set([tokenDigest(generateAgentToken())]),
      sessions: store,
      imDecisionTokens: new Set(),
    };
    expect(authorize('tool.call', started.token, tables).ok).toBe(true);
    clock.advance(OPERATOR_SESSION_TTL_MS + 1);
    expect(authorize('tool.call', started.token, tables)).toEqual({
      ok: false,
      code: -32001,
      message: expect.any(String),
      audit: true,
    });
  });
});

describe('红线专项', () => {
  it('单令牌信任模型（主人 2026-10-17 裁决）：agent 令牌对本机全方法开放', () => {
    // 裁决背景：主人对 Agent 的约束=SSH 凭证隔离（凭证永不进 Agent 信任域）；
    // operator 口令约束的是主人自己的日常使用——知情接受「Agent 可自批」残余风险后
    // 取消双类凭据。本断言忠实钉住新模型，防将来半途改回造成行为漂移。
    const h = makeHarness();
    for (const method of METHODS) {
      const auth = authorize(method, h.agentToken, h.tables);
      expect(auth.ok, `${method} should be allowed for the single local token`).toBe(true);
    }
  });

  it('FORBIDDEN 携带审计标记（-32002 + audit:true）', () => {
    const h = makeHarness();
    // im 类令牌除 decide 外一律 FORBIDDEN。
    const auth = authorize('audit.query', h.imToken, h.tables);
    expect(auth).toEqual({ ok: false, code: -32002, message: expect.any(String), audit: true });
  });

  it('未知方法 → -32601（method not found，不审计）', () => {
    const h = makeHarness();
    const auth = authorize('host.selfDestruct', h.agentToken, h.tables);
    expect(auth).toEqual({ ok: false, code: -32601, message: expect.any(String), audit: false });
  });
});
