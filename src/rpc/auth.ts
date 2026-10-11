/**
 * RPC 认证（T-14，方案 §3.2/§12 D13）：
 * - agent 静态令牌：≥256bit（32 字节 base64url），Host init 生成（T-15 接线）；
 * - operator 会话制（D1'）：口令 → scrypt 验证 → 内存态会话令牌（≥256bit），
 *   30min 滑动 TTL + renew，进程退出即灭，磁盘零 operator 秘密；
 * - 失败限速复用 AuthFailureLimiter（T-13.5 已迁入 ./limiters）——peek 先于验证，
 *   耗尽的地址不评估猜测就拒绝（与 http.ts 同款纪律）。
 *
 * 时钟：默认 performance.now()（单调钟，方案 §3.5——审批/会话窗口判定不受
 * 系统时钟回拨影响），可注入供测试拨动。
 */
import { randomBytes, scryptSync, timingSafeEqual } from 'crypto';
import { AuthFailureLimiter, DEFAULT_AUTH_FAILURE_LIMIT } from './limiters.js';

/** operator 会话 TTL：30min 滑动（方案 §3.2）。 */
export const OPERATOR_SESSION_TTL_MS = 30 * 60_000;

/** 生成 256bit URL 安全令牌（agent 静态令牌与会话令牌同一生成器）。 */
export function generateAgentToken(): string {
  return randomBytes(32).toString('base64url');
}

/** 口令哈希：16B 随机盐 + scryptSync(64B)，十六进制 `salt:hash` 存储。 */
export function hashPassword(password: string): string {
  const salt = randomBytes(16);
  const hash = scryptSync(password, salt, 64);
  return `${salt.toString('hex')}:${hash.toString('hex')}`;
}

/** 口令验证：常时比较（timingSafeEqual）。存储串畸形一律 false 不抛。 */
export function verifyPassword(password: string, stored: string): boolean {
  const parts = stored.split(':');
  const saltHex = parts[0];
  const hashHex = parts[1];
  if (saltHex === undefined || hashHex === undefined) return false;
  const salt = Buffer.from(saltHex, 'hex');
  const expected = Buffer.from(hashHex, 'hex');
  if (salt.length === 0 || expected.length === 0) return false;
  try {
    const actual = scryptSync(password, salt, expected.length);
    return timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
}

/** 口令错误（计一次失败预算）。 */
export class BadPasswordError extends Error {
  constructor() {
    super('Operator password verification failed');
    this.name = 'BadPasswordError';
  }
}

/** 该地址失败预算耗尽（重试需等 Retry-After）。 */
export class AuthFailureLimitExceededError extends Error {
  constructor(readonly retryAfterMs: number) {
    super(`Too many failed authentication attempts. Retry after ${Math.ceil(retryAfterMs / 1000)}s.`);
    this.name = 'AuthFailureLimitExceededError';
  }
}

export interface OperatorSessionStoreOpts {
  /** host init 时 scrypt 落盘的口令哈希（`salt:hash` 十六进制）。 */
  storedHash: string;
  /** 单调钟，默认 performance.now()。 */
  clock?: () => number;
  /** 默认 OPERATOR_SESSION_TTL_MS。 */
  ttlMs?: number;
  /** 每地址每分钟失败预算，默认 DEFAULT_AUTH_FAILURE_LIMIT；0 禁用限速。 */
  authFailureLimit?: number;
}

/**
 * operator 会话表（内存态）：token → 过期时刻（单调钟毫秒）。
 * 会话令牌与 agent 令牌同一熵源（32B base64url，≥256bit，K8-⑦ 最小熵要求），
 * 两表分立：服务端类别判定按「查哪张表命中」（M3），不在矩阵入口做。
 */
export class OperatorSessionStore {
  private readonly sessions = new Map<string, { expiresAt: number }>();
  private readonly limiter: AuthFailureLimiter | null;
  private readonly storedHash: string;
  private readonly clock: () => number;
  private readonly ttlMs: number;

  constructor(opts: OperatorSessionStoreOpts) {
    this.storedHash = opts.storedHash;
    this.clock = opts.clock ?? (() => performance.now());
    this.ttlMs = opts.ttlMs ?? OPERATOR_SESSION_TTL_MS;
    const limit = opts.authFailureLimit ?? DEFAULT_AUTH_FAILURE_LIMIT;
    this.limiter = limit > 0 ? new AuthFailureLimiter(limit) : null;
  }

  /**
   * 口令换会话。失败顺序：先 peek 失败预算（耗尽即拒，不评估猜测），
   * 再验口令（错则 recordFailure）。成功发放新令牌。
   */
  start(password: string, clientKey: string): { ok: true; token: string } {
    if (this.limiter) {
      const peeked = this.limiter.peek(clientKey);
      if (!peeked.allowed) throw new AuthFailureLimitExceededError(peeked.retryAfterMs);
    }
    if (!verifyPassword(password, this.storedHash)) {
      this.limiter?.recordFailure(clientKey);
      throw new BadPasswordError();
    }
    const token = generateAgentToken();
    this.sessions.set(token, { expiresAt: this.clock() + this.ttlMs });
    return { ok: true, token };
  }

  /** 存在且未过期。读取不续期（滑动只由 renew/后续语义触发）。 */
  validate(token: string): boolean {
    const session = this.sessions.get(token);
    if (session === undefined) return false;
    return this.clock() < session.expiresAt;
  }

  /** 滑动续期：有效会话把过期时刻推到 now+TTL。 */
  renew(token: string): boolean {
    const session = this.sessions.get(token);
    if (session === undefined || this.clock() >= session.expiresAt) return false;
    session.expiresAt = this.clock() + this.ttlMs;
    return true;
  }

  /** 吊销（K8-⑦：会话须有吊销手段；轮换/登出由调用方语义决定）。 */
  revoke(token: string): void {
    this.sessions.delete(token);
  }
}
