/**
 * 凭据解析与矩阵执行（T-14，方案 §3.2/§3.3 + M3）。
 *
 * 服务端类别判定：单一凭据字符串按表命中顺序判定真实类别——
 * agent 静态表 → operator 会话表 → IM 绑定表；都不命中 = unauthenticated。
 * 客户端自报的 class 字段不参与判定（M3：谎报按真实凭据）。
 *
 * 审计语义：FORBIDDEN（-32002）与未认证拒绝（-32001）都置 audit:true，
 * 由服务层落审计（T-15 装配真实 sink）；method not found 不审计。
 */
import type { OperatorSessionStore } from './auth.js';
import { METHOD_MATRIX, isKnownMethod, type CallerClass } from './matrix.js';
import { RPC_ERROR } from './protocol.js';

export interface RpcTables {
  /** agent 静态令牌表（轮换后旧令牌移出，T-15 host.admin.rotateToken 接线）。 */
  agentTokens: ReadonlySet<string>;
  /** operator 会话表（含过期判定，validate 为准）。 */
  sessions: OperatorSessionStore;
  /** IM 决策令牌绑定表（T-17.6 落地；T-14 阶段为空集。 */
  imDecisionTokens: ReadonlySet<string>;
}

export type Authorization =
  | { ok: true; callerClass: CallerClass }
  | { ok: false; code: number; message: string; audit: boolean };

export function authorize(
  method: string,
  presentedToken: string | undefined,
  tables: RpcTables,
): Authorization {
  if (!isKnownMethod(method)) {
    return { ok: false, code: RPC_ERROR.METHOD_NOT_FOUND, message: `Unknown method: ${method}`, audit: false };
  }
  const row = METHOD_MATRIX[method]!;

  let callerClass: CallerClass = 'unauthenticated';
  if (presentedToken !== undefined && presentedToken !== '') {
    if (tables.agentTokens.has(presentedToken)) callerClass = 'agent';
    else if (tables.sessions.validate(presentedToken)) callerClass = 'operator';
    else if (tables.imDecisionTokens.has(presentedToken)) callerClass = 'im';
  }

  if (callerClass === 'unauthenticated') {
    if (row.none) return { ok: true, callerClass };
    return {
      ok: false,
      code: RPC_ERROR.UNAUTHORIZED,
      message: 'Unauthorized: no valid credential presented',
      audit: true,
    };
  }

  if (!row[callerClass]) {
    return {
      ok: false,
      code: RPC_ERROR.FORBIDDEN,
      message: `Method ${method} is forbidden for ${callerClass} credentials`,
      audit: true,
    };
  }
  return { ok: true, callerClass };
}
