/**
 * 契约夹具构建器（T-14，K6：golden.json 由 TS 协议类型单测生成、Rust 只消费）。
 *
 * 本模块只产出确定性的样本数据（纯函数，零 fs/零随机）；写盘由生成测试完成
 * （test/unit/rpc/golden.test.ts → test/fixtures/rpc/protocol-golden.json）。
 * Rust 侧（T-17.5a）消费该文件做对拍，绝不自行生成——TS/Rust 双实现的单一事实源。
 * 样本集合新增/修改即协议变更：随 PR 评审，Rust CI 对拍兜住漂移。
 */
import { encodeFrame } from './frame.js';
import { RPC_PROTOCOL_VERSION, type JsonRpcRequest, type JsonRpcResponse } from './protocol.js';

export interface GoldenSample {
  name: string;
  /** 完整线格式（含结尾 \n），Rust 侧按字节比对/解析。 */
  wire: string;
}

export interface GoldenFixture {
  protocolVersion: string;
  samples: GoldenSample[];
}

const CERT_FINGERPRINT_FIXTURE = 'aa'.repeat(32); // sha256 hex 形态的确定样本（64 字符）

export function buildGoldenFixture(): GoldenFixture {
  const helloRequest: JsonRpcRequest = {
    jsonrpc: '2.0',
    id: 1,
    method: 'host.hello',
    params: { protocolVersion: RPC_PROTOCOL_VERSION },
  };
  const helloResult: JsonRpcResponse = {
    jsonrpc: '2.0',
    id: 1,
    result: { protocolVersion: RPC_PROTOCOL_VERSION, certFingerprint: CERT_FINGERPRINT_FIXTURE },
  };
  const toolCallRequest: JsonRpcRequest = {
    jsonrpc: '2.0',
    id: 2,
    method: 'tool.call',
    params: { name: 'exec', arguments: { command: 'ls' } },
  };
  const toolCallResult: JsonRpcResponse = {
    jsonrpc: '2.0',
    id: 2,
    result: { content: [{ type: 'text', text: 'file.txt' }] },
  };
  const errorForbidden: JsonRpcResponse = {
    jsonrpc: '2.0',
    id: 3,
    error: { code: -32002, message: 'Method approval.list is forbidden for agent credentials' },
  };
  const approvalPendingPush = {
    jsonrpc: '2.0' as const,
    method: 'approval.pending',
    params: {
      id: 'ap-1',
      profile: 'web-1',
      class: 'destructive',
      command: 'rm -rf /tmp/x',
      expiresAt: 1710000000000,
    },
  };

  return {
    protocolVersion: RPC_PROTOCOL_VERSION,
    samples: [
      { name: 'hello.request', wire: encodeFrame(helloRequest) },
      { name: 'hello.result', wire: encodeFrame(helloResult) },
      { name: 'tool.call.request', wire: encodeFrame(toolCallRequest) },
      { name: 'tool.call.result', wire: encodeFrame(toolCallResult) },
      { name: 'error.forbidden', wire: encodeFrame(errorForbidden) },
      { name: 'approval.pending.push', wire: encodeFrame(approvalPendingPush) },
    ],
  };
}
