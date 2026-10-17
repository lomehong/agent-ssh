/**
 * IM 单次决策令牌（T-17.6，K8-⑤/A8）。
 *
 * 每次卡片下发签发一枚 ≥128bit 随机令牌，按钮 value 携 {id, token, decision}；
 * 回调消费时三重绑定：令牌存在（签发过）、绑定同一请求 id（跨请求重放必拒）、
 * 单次消费（第二次必拒）。审批本身的过期/状态由 decideApproval 与
 * ChallengeStore 兜底——这里是"截图转发/复制按钮消息不能批别的请求"的执行点。
 *
 * 不入 RPC imDecisionTokens 表：卡片回调走 Host 进程内路径（face 固定 'im'，
 * 不可谎报）；若把令牌登记为 RPC 凭据，持有人可经 RPC 谎报 face='cli'
 * 绕过破坏性类校验码——授权表保持预留（T-14 注释语义），本模块不触碰。
 */
import { randomBytes } from 'node:crypto';

export class DecisionTokenStore {
  private readonly issued = new Map<string, string>();

  /** 签发：返回随卡片下发的令牌（128bit base64url）。 */
  issue(approvalId: string): string {
    const token = randomBytes(16).toString('base64url');
    this.issued.set(token, approvalId);
    return token;
  }

  /** 校验并消费：令牌未签发/绑定其他请求/已消费 → null。 */
  consume(token: unknown, approvalId: string): boolean {
    if (typeof token !== 'string' || token.length === 0) return false;
    const bound = this.issued.get(token);
    if (bound === undefined || bound !== approvalId) return false;
    this.issued.delete(token);
    return true;
  }

  /** 请求作废（settled/expired）时收回未消费令牌。 */
  revokeFor(approvalId: string): void {
    for (const [token, id] of this.issued) {
      if (id === approvalId) this.issued.delete(token);
    }
  }

  /** 在场令牌数（测试/观测）。 */
  get size(): number {
    return this.issued.size;
  }
}
