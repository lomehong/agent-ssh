import { describe, expect, it } from 'vitest';
import {
  FrameLimitExceededError,
  FrameReader,
  RPC_FRAME_LIMIT_BYTES,
  encodeFrame,
  type FrameEvent,
} from '../../../src/rpc/frame.js';

/** 构造序列化后恰为 n 个 ASCII 字符的 JSON 值（bytes === UTF-16 code units）。 */
function jsonOfExactLength(n: number): { jsonrpc: string; id: number; result: { padding: string } } {
  const head = '{"jsonrpc":"2.0","id":1,"result":{"padding":"';
  const tail = '"}}';
  const text = head + 'x'.repeat(n - head.length - tail.length) + tail;
  expect(text.length).toBe(n);
  return JSON.parse(text);
}

function kinds(events: FrameEvent[]): string[] {
  return events.map((e) => e.kind);
}

describe('RPC 帧层（\\n 分帧，4MB 上限进出同值，D12）', () => {
  it('解码单个完整帧', () => {
    const reader = new FrameReader();
    const events = reader.push('{"jsonrpc":"2.0","id":1,"method":"host.ping"}\n');
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({ kind: 'frame' });
    if (events[0].kind === 'frame') {
      expect(events[0].value).toEqual({ jsonrpc: '2.0', id: 1, method: 'host.ping' });
    }
    expect(reader.isDead()).toBe(false);
  });

  it('一个 chunk 内多帧依次解出', () => {
    const reader = new FrameReader();
    const events = reader.push('{"id":1}\n{"id":2}\n{"id":3}\n');
    expect(events).toHaveLength(3);
    expect(kinds(events)).toEqual(['frame', 'frame', 'frame']);
  });

  it('跨 chunk 分割的帧正确重组（含多字节字符）', () => {
    const reader = new FrameReader();
    const line = '{"jsonrpc":"2.0","id":7,"method":"tool.call","params":{"cmd":"echo 世界"}}';
    const cut = 20;
    const first = reader.push(line.slice(0, cut));
    expect(first).toEqual([]);
    const second = reader.push(line.slice(cut) + '\n');
    expect(second).toHaveLength(1);
    if (second[0].kind === 'frame') {
      expect((second[0].value as { params: { cmd: string } }).params.cmd).toBe('echo 世界');
    }
  });

  it('最大合法截断响应 1,056,768B 过单帧（full-chain 实测值，验收钉死）', () => {
    const value = jsonOfExactLength(1_056_768);
    const reader = new FrameReader();
    const events = reader.push(JSON.stringify(value) + '\n');
    expect(kinds(events)).toEqual(['frame']);
    expect(reader.isDead()).toBe(false);
    // 进出同值：编码侧同载荷不抛
    expect(() => encodeFrame(value)).not.toThrow();
  });

  it('恰好 4MB 的帧允许，超一字节即溢出（进出同值）', () => {
    const atLimit = jsonOfExactLength(RPC_FRAME_LIMIT_BYTES);
    const okReader = new FrameReader();
    expect(kinds(okReader.push(JSON.stringify(atLimit) + '\n'))).toEqual(['frame']);

    const encodeReaderValue = jsonOfExactLength(RPC_FRAME_LIMIT_BYTES + 1);
    expect(() => encodeFrame(encodeReaderValue)).toThrow(FrameLimitExceededError);
  });

  it('超限行产生 fatal 事件且读取器死亡（超限断连，审计由调用方接）', () => {
    const reader = new FrameReader();
    const events = reader.push('x'.repeat(RPC_FRAME_LIMIT_BYTES + 1) + '\n');
    expect(kinds(events)).toEqual(['oversize']);
    expect(reader.isDead()).toBe(true);
    // 死亡后不再产出任何事件（连接已被服务层拆除）
    expect(reader.push('{"id":1}\n')).toEqual([]);
  });

  it('无换行的渐进超限同样触发 fatal（分块累积）', () => {
    const reader = new FrameReader();
    expect(reader.push('y'.repeat(RPC_FRAME_LIMIT_BYTES))).toEqual([]);
    const events = reader.push('y'.repeat(1));
    expect(kinds(events)).toEqual(['oversize']);
    expect(reader.isDead()).toBe(true);
  });

  it('非法 JSON 产生 parseError 且读取器存活（-32700 语义，由服务层应答）', () => {
    const reader = new FrameReader();
    const events = reader.push('{not-json}\n');
    expect(kinds(events)).toEqual(['parseError']);
    expect(reader.isDead()).toBe(false);
    // 后续帧照常解析
    expect(kinds(reader.push('{"id":2}\n'))).toEqual(['frame']);
  });

  it('空行按 parseError 处理（严格，不静默吞）', () => {
    const reader = new FrameReader();
    expect(kinds(reader.push('\n'))).toEqual(['parseError']);
  });

  it('encodeFrame 产出 \\n 结尾帧并与 FrameReader 往返', () => {
    const value = { jsonrpc: '2.0', id: 9, result: { ok: true } };
    const wire = encodeFrame(value);
    expect(wire.endsWith('\n')).toBe(true);
    const reader = new FrameReader();
    const events = reader.push(wire);
    expect(events).toHaveLength(1);
    if (events[0].kind === 'frame') expect(events[0].value).toEqual(value);
  });
});
