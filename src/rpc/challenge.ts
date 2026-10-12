/**
 * 输入校验码（T-17.5b，D10/K8-②）：破坏性类审批的“人真的在看”凭证。
 *
 * - Host 生成 4 位数字码，仅随 approval.pending 推送下发到审批窗口；
 * - 单次有效：decide 携码校验通过即消费；
 * - Host 侧 3 次失败作废（本地计数不可信——作废判定全在 Host）；
 * - TTL 60s，过期判定走单调钟（§3.5：时钟回拨不延长窗口）。
 *
 * 非破坏性类不生成码（generate 仅由 Host 在 destructive 入队时调用）。
 */
export const CHALLENGE_TTL_MS = 60_000;
export const CHALLENGE_MAX_FAILURES = 3;

export interface VerifyOutcome {
  ok: boolean;
  /** 本次失败是否触发 3 次作废。 */
  invalidated?: boolean;
  reason?: 'no-challenge' | 'already-consumed' | 'invalidated' | 'expired' | 'mismatch';
}

interface ChallengeEntry {
  code: string;
  createdAt: number;
  expiresAt: number;
  failedAttempts: number;
  invalidated: boolean;
  consumed: boolean;
}

/**
 * 生成 4 位码。CSPRNG（crypto.randomInt）而非 Math.random：码是唯一门槛
 * 因子时不应引入可预测源（3 败+60s 限下风险受控，但惯例优先）。
 */
function randomCode4(): string {
  return randomInt(0, 10_000).toString().padStart(4, '0');
}

export class ChallengeStore {
  private readonly entries = new Map<string, ChallengeEntry>();
  private readonly clock: () => number;

  constructor(opts: { clock?: () => number } = {}) {
    this.clock = opts.clock ?? (() => performance.now());
  }

  /** 生成（或返回既有）4 位码。幂等：同 id 重发推送不给新码。 */
  generate(approvalId: string): string {
    const existing = this.entries.get(approvalId);
    if (existing && !existing.invalidated && !existing.consumed) {
      return existing.code;
    }
    const code = randomCode4();
    this.entries.set(approvalId, {
      code,
      createdAt: this.clock(),
      expiresAt: this.clock() + CHALLENGE_TTL_MS,
      failedAttempts: 0,
      invalidated: false,
      consumed: false,
    });
    return code;
  }

  /** 只读：该 id 是否存在未消费码（decide 分流依据；含过期态）。 */
  hasPendingChallenge(approvalId: string): boolean {
    const entry = this.entries.get(approvalId);
    return entry !== undefined && !entry.invalidated && !entry.consumed;
  }

  /** 只读：当前码（审计/诊断用；失效态返回 undefined）。 */
  codeOf(approvalId: string): string | undefined {
    const entry = this.entries.get(approvalId);
    if (entry === undefined || entry.invalidated || entry.consumed) return undefined;
    if (this.clock() >= entry.expiresAt) return undefined;
    return entry.code;
  }

  /**
   * 单次校验。结果三态：ok / mismatch（计失败）/ invalidated（第 3 次失败，
   * 已作废——对码也拒）。expired/无码 = ok:false 不计失败。
   */
  verify(approvalId: string, code: string): VerifyOutcome {
    const entry = this.entries.get(approvalId);
    if (entry === undefined) return { ok: false, reason: 'no-challenge' };
    if (entry.invalidated) return { ok: false, reason: 'invalidated' };
    if (entry.consumed) return { ok: false, reason: 'already-consumed' };
    if (this.clock() >= entry.expiresAt) {
      entry.consumed = true;
      return { ok: false, reason: 'expired' };
    }
    if (entry.code === code) {
      entry.consumed = true; // 单次有效
      return { ok: true };
    }
    entry.failedAttempts += 1;
    if (entry.failedAttempts >= CHALLENGE_MAX_FAILURES) {
      entry.invalidated = true;
      return { ok: false, reason: 'mismatch', invalidated: true };
    }
    return { ok: false, reason: 'mismatch' };
  }

  /** 吊销（决定在他面完成/过期落盘时，未消费码即作废）。 */
  revoke(approvalId: string): void {
    this.entries.delete(approvalId);
  }
}
