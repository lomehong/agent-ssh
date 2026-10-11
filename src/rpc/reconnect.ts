/**
 * 断线重连退避（T-14，方案 §3.1：stub/审批端断线指数退避重连，上限后向宿主/托盘报错态）。
 * 确定性序列（无抖动）：可测试性优先；重连风暴在本产品拓扑（单 stub/单审批端对单 Host）不成立。
 */

export const RECONNECT_BASE_DELAY_MS = 1_000;
export const RECONNECT_MAX_DELAY_MS = 30_000;

/** 第 attempt 次重连前的等待：1s 起步逐次翻倍，封顶 maxDelay（缺省 30s）。 */
export function nextRetryDelayMs(attempt: number, maxDelayMs = RECONNECT_MAX_DELAY_MS): number {
  const exponent = Math.max(0, attempt);
  return Math.min(RECONNECT_BASE_DELAY_MS * 2 ** exponent, maxDelayMs);
}
