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
  'auth.session.start': { agent: false, operator: false, im: false, none: true },
  'auth.session.renew': { agent: false, operator: true, im: false, none: false },
  'approval.subscribe': { agent: false, operator: true, im: false, none: false },
  'approval.list': { agent: false, operator: true, im: false, none: false },
  'approval.history': { agent: false, operator: true, im: false, none: false },
  'audit.query': { agent: false, operator: true, im: false, none: false },
  'audit.stats': { agent: false, operator: true, im: false, none: false },
  'host.connections': { agent: false, operator: true, im: false, none: false },
  'quota.snapshot': { agent: false, operator: true, im: false, none: false },
  'approval.decide': { agent: false, operator: true, im: true, none: false },
  'cli.run': { agent: false, operator: true, im: false, none: false },
  'cli.info': { agent: false, operator: true, im: false, none: false },
  'host.admin.rotateToken': { agent: false, operator: true, im: false, none: false },
  'host.admin.changePassword': { agent: false, operator: true, im: false, none: false },
  'host.status': { agent: false, operator: true, im: false, none: false },
  'agents.scan': { agent: false, operator: true, im: false, none: false },
  'agents.configure': { agent: false, operator: true, im: false, none: false },
  'agents.remove': { agent: false, operator: true, im: false, none: false },
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
