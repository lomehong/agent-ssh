/**
 * 方法×凭据矩阵（T-14，方案 §3.3 红线执行点）。
 *
 * 行语义：`none` = 无凭据可调用（仅 auth.session.start——认证入口本身）；
 * `im` = IM 单次决策令牌（绑定表命中，仅 approval.decide，T-17.6 落地）。
 * 纯数据表：类别判定的服务端执行在 ./authorize（M3——请求里的 class 字段
 * 仅作展示，真实类别由凭据在哪张表命中决定）。
 */

export type CallerClass = 'agent' | 'operator' | 'im' | 'unauthenticated';

export interface MethodRow {
  agent: boolean;
  operator: boolean;
  im: boolean;
  /** 无凭据可调用（仅认证入口方法）。 */
  none: boolean;
}

export const METHOD_MATRIX: Record<string, MethodRow> = {
  'host.hello': { agent: true, operator: true, im: false, none: false },
  'host.ping': { agent: true, operator: true, im: false, none: false },
  'host.toolManifest': { agent: true, operator: true, im: false, none: false },
  'tool.call': { agent: true, operator: true, im: false, none: false },
  'resource.list': { agent: true, operator: true, im: false, none: false },
  'resource.read': { agent: true, operator: true, im: false, none: false },
  'approval.subscribe': { agent: true, operator: true, im: false, none: false },
  'approval.list': { agent: true, operator: true, im: false, none: false },
  // T-23 弹窗补拉（未决清单，破坏性/特权附存活校验码）。D15 单令牌下码对
  // 本地 agent 本就不保密（approval.pending 推送载荷明文带码，订阅即得）——
  // 码的定位是「人面摩擦」（必须手输），唯一 agent 不可及的通道是 IM 卡片；
  // 行权与 approval.list 同类。主控台 list_pending 命令即调此方法。
  'list_pending': { agent: true, operator: true, im: false, none: false },
  'approval.history': { agent: true, operator: true, im: false, none: false },
  'audit.query': { agent: true, operator: true, im: false, none: false },
  'audit.stats': { agent: true, operator: true, im: false, none: false },
  'host.connections': { agent: true, operator: true, im: false, none: false },
  'quota.snapshot': { agent: true, operator: true, im: false, none: false },
  'approval.decide': { agent: true, operator: true, im: true, none: false },
  'cli.run': { agent: true, operator: true, im: false, none: false },
  'cli.info': { agent: true, operator: true, im: false, none: false },
  'host.admin.rotateToken': { agent: true, operator: true, im: false, none: false },
  'host.status': { agent: true, operator: true, im: false, none: false },
  'agents.scan': { agent: true, operator: true, im: false, none: false },
  'agents.configure': { agent: true, operator: true, im: false, none: false },
  'agents.remove': { agent: true, operator: true, im: false, none: false },
  'host.profiles.list': { agent: true, operator: true, im: false, none: false },
  'host.profiles.upsert': { agent: true, operator: true, im: false, none: false },
  'host.profiles.remove': { agent: true, operator: true, im: false, none: false },
};

export function isKnownMethod(method: string): boolean {
  return Object.prototype.hasOwnProperty.call(METHOD_MATRIX, method);
}

/** 已知方法对某类别的放行位；未知方法返回 undefined（与 isKnownMethod 同一判定路径）。 */
export function methodAllowedFor(
  method: string,
  cls: Exclude<CallerClass, 'unauthenticated'>,
): boolean | undefined {
  if (!isKnownMethod(method)) return undefined;
  const row = METHOD_MATRIX[method]!;
  return row[cls];
}
