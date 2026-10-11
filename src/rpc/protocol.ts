/**
 * RPC 协议共享件（T-14）：错误码分段、协议版本、JSON-RPC 信封类型、hello 版本协商。
 *
 * 错误码：-32601/-32603 = JSON-RPC 2.0 标准段；-32001 = 未认证（无有效凭据）；
 * -32002 = 已认证但该方法对该类别 FORBIDDEN（方案 §3.3 红线，须随审计事件）。
 * protocolVersion 语义化且独立于 npm 版本（§3.6）：0.x 期 minor 即破坏性，
 * major>0 后仅 major 破坏；patch 恒兼容。升级顺序 runbook：先 Host 后 stub/审批端（D5'）。
 */

export const RPC_ERROR = {
  METHOD_NOT_FOUND: -32601,
  INTERNAL: -32603,
  UNAUTHORIZED: -32001,
  FORBIDDEN: -32002,
} as const;

export const RPC_PROTOCOL_VERSION = '0.2.0';

export interface JsonRpcRequest {
  jsonrpc: '2.0';
  id: string | number;
  method: string;
  params?: unknown;
}

export interface JsonRpcResponse {
  jsonrpc: '2.0';
  id: string | number | null;
  result?: unknown;
  error?: { code: number; message: string; data?: unknown };
}

export type HelloNegotiation = { ok: true } | { ok: false; clientVersion: string; serverVersion: string };

/** hello 版本协商：0.x 期 minor 差异即拒绝（附双方版本供诊断与审计）。 */
export function negotiateHello(clientVersion: string, serverVersion: string): HelloNegotiation {
  const parse = (v: string): number[] => v.split('.').map((p) => Number.parseInt(p, 10) || 0);
  const client = parse(clientVersion);
  const server = parse(serverVersion);
  const clientMajor = client[0] ?? 0;
  const clientMinor = client[1] ?? 0;
  const serverMajor = server[0] ?? 0;
  const serverMinor = server[1] ?? 0;
  const compatible =
    clientMajor === serverMajor && (clientMajor > 0 || clientMinor === serverMinor);
  return compatible ? { ok: true } : { ok: false, clientVersion, serverVersion };
}
