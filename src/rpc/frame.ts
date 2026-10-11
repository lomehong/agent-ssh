/**
 * RPC 帧层（T-14）：JSON-RPC 2.0 over TCP，`\n` 分帧。
 *
 * 单帧上限 4MB，进出同值（方案 §3.1/§12 D12）。取值依据：最大合法截断
 * 工具响应实测 1,056,768B（full-chain.test.ts 注释原值）+ JSON 包装膨胀 +
 * sftp-upload 内联大参数，留一倍余量。上限按 **UTF-8 字节**计（buffer.byteLength），
 * 与方案「1,056,768 字节」的口径一致；SizeCappedText 的 UTF-16 计数是 http.ts
 * 请求体上限的历史语义，本层不沿用。
 *
 * 超限 → fatal（调用方必须断连并审计，方案 §3.1「超限断连并审计」）；
 * 非法 JSON → parseError 事件（-32700 语义，读取器存活，由服务层决定应答）；
 * 空行严格按 parseError，不静默吞。
 */

/** 单帧上限：4MB，进出同值（D12）。恰好等于上限的帧允许，超过即溢出。 */
export const RPC_FRAME_LIMIT_BYTES = 4 * 1024 * 1024;

/** 编码侧超限：调用方应把载荷视为不可投递，而非截断（截断会破坏 JSON-RPC 语义）。 */
export class FrameLimitExceededError extends Error {
  constructor(bytes: number) {
    super(`Frame is ${bytes} bytes, exceeding the ${RPC_FRAME_LIMIT_BYTES}-byte frame limit`);
    this.name = 'FrameLimitExceededError';
  }
}

export type FrameEvent =
  | { kind: 'frame'; value: unknown; bytes: number }
  | { kind: 'parseError' }
  | { kind: 'oversize'; bytes: number };

/** JSON 值编码为一帧（`\n` 结尾）。序列化后超限抛 FrameLimitExceededError。 */
export function encodeFrame(value: unknown): string {
  const text = JSON.stringify(value);
  const bytes = Buffer.byteLength(text, 'utf8');
  if (bytes > RPC_FRAME_LIMIT_BYTES) throw new FrameLimitExceededError(bytes);
  return text + '\n';
}

/**
 * 增量帧读取器：`push` 喂入任意切割的文本块（TCP data 事件），
 * 返回本块解出的全部事件。多字节字符不会被 chunk 边界切开
 * （输入约定为已解码字符串，与 socket.setEncoding 一致）。
 *
 * oversize 是终态：读取器进入死亡，此后 push 静默返回空——
 * 断连与审计是服务层职责，读取器只负责不再产出。
 */
export class FrameReader {
  private pending = '';
  private pendingBytes = 0;
  private dead = false;

  isDead(): boolean {
    return this.dead;
  }

  push(chunk: string): FrameEvent[] {
    if (this.dead) return [];
    this.pending += chunk;
    this.pendingBytes += Buffer.byteLength(chunk, 'utf8');

    const events: FrameEvent[] = [];
    for (;;) {
      const idx = this.pending.indexOf('\n');
      if (idx === -1) break;
      const line = this.pending.slice(0, idx);
      const lineBytes = Buffer.byteLength(line, 'utf8');
      this.pending = this.pending.slice(idx + 1);
      this.pendingBytes -= lineBytes + 1;
      this.decodeLine(line, lineBytes, events);
    }

    if (!this.dead && this.pendingBytes > RPC_FRAME_LIMIT_BYTES) {
      this.dead = true;
      events.push({ kind: 'oversize', bytes: this.pendingBytes });
    }
    return events;
  }

  private decodeLine(line: string, lineBytes: number, events: FrameEvent[]): void {
    if (lineBytes > RPC_FRAME_LIMIT_BYTES) {
      this.dead = true;
      events.push({ kind: 'oversize', bytes: lineBytes });
      return;
    }
    try {
      const value: unknown = JSON.parse(line);
      events.push({ kind: 'frame', value, bytes: lineBytes });
    } catch {
      events.push({ kind: 'parseError' });
    }
  }
}
