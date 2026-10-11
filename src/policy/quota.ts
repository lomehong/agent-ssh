/**
 * 按 profile 的命令配额——针对失控 agent 的熔断器。
 *
 * 审批门拦的是*破坏性*命令，HTTP 限流器限制请求速率，
 * 但两者都不限制总工作量：被提示注入的 agent 循环执行
 * 允许的命令，两条限制都拦不住。配额限制的是总量。
 *
 * 作用域是 profile 而不是「agent」：MCP 没有给我们稳定的客户端身份
 * （stdio 服务器本来也只服务一个客户端），宣称按 agent 计数
 * 会夸大实际强制执行的东西。
 */

const DAY_MS = 24 * 60 * 60 * 1000;

export interface QuotaDecision {
  allowed: boolean;
  /** 窗口内剩余可用命令数。 */
  remaining: number;
  /** 最老的已计数命令何时滑出窗口。 */
  retryAt?: Date;
}

export class CommandQuota {
  /** 已计数命令的时间戳，每 profile 一份，最老的在前。 */
  private hits = new Map<string, number[]>();

  /**
    * 滚动 24 小时窗口而非自然日：固定每日重置会让 agent
    * 烧完整份配额、等午夜、再立刻烧一份——几分钟内干出
    * 两倍的活。
   */
  constructor(private windowMs: number = DAY_MS) {}

  /**
    * 把一条命令计入该 profile 的配额。
    * `limit <= 0`（或未定义）表示不限制，不记录任何东西。
   */
  consume(profile: string, limit: number | undefined, now = Date.now()): QuotaDecision {
    if (!limit || limit <= 0) return { allowed: true, remaining: Infinity };

    const cutoff = now - this.windowMs;
    const recent = (this.hits.get(profile) ?? []).filter((t) => t > cutoff);

    if (recent.length >= limit) {
      // 被拒不得消耗预算，否则一个被挡住的 agent 可以
      // 不断把窗口往前推，永不恢复。
      this.hits.set(profile, recent);
      return {
        allowed: false,
        remaining: 0,
        retryAt: new Date(recent[0] + this.windowMs),
      };
    }

    recent.push(now);
    this.hits.set(profile, recent);
    return { allowed: true, remaining: limit - recent.length };
  }

  /** 当前窗口已用命令数，用于状态上报。 */
  used(profile: string, now = Date.now()): number {
    const cutoff = now - this.windowMs;
    return (this.hits.get(profile) ?? []).filter((t) => t > cutoff).length;
  }

  reset(profile?: string): void {
    if (profile) this.hits.delete(profile);
    else this.hits.clear();
  }
}
