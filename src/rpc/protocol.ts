/**
 * RPC 协议共享常量（T-14）。错误码分段：
 * -32700/-32600/-32601/-32603 = JSON-RPC 2.0 标准段；
 * -32001 = 未认证（无有效凭据）；-32002 = 已认证但该方法对该类别 FORBIDDEN
 * （方案 §3.3 红线；FORBIDDEN 必须随审计事件，见 authorize 的 audit 标记）。
 */
export const RPC_ERROR = {
  METHOD_NOT_FOUND: -32601,
  UNAUTHORIZED: -32001,
  FORBIDDEN: -32002,
} as const;
