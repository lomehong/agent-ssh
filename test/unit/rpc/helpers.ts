/** rpc 测试共享助手（可拨动单调钟——auth/matrix 等会话与时序用例通用）。 */
export function fakeClock(start = 1_000_000): { now(): number; advance(ms: number): void } {
  let t = start;
  return {
    now: () => t,
    advance(ms: number) {
      t += ms;
    },
  };
}
