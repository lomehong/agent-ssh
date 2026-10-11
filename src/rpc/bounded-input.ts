/**
 * 有界输入原语（T-13.5 预重构：自 src/transport/http.ts 的请求体上限模式抽出，零行为变化）。
 *
 * 模式 =「字符串累加 + 硬上限 + 一次性溢出处置」。http.ts 的 413 舞步
 * （Connection: close、冲刷后 destroy）保留在原处不动；本模块只承载
 * 累加与单次触发机制。RPC 层（T-14/D12）的 \n 分帧读取器在本原语之上
 * 构建，RPC 帧上限（4MB）不沿用此值，由 T-14 另行定义。
 */

/** http.ts 请求体上限原值（1MB），随模式一并迁入，现值现语义不动。 */
export const HTTP_BODY_LIMIT_BYTES = 1_048_576;

/**
 * 有界字符串累加器：append 使累计长度超限时恰好触发一次 onOverflow，
 * 与 http.ts 原内联逻辑（bodyTooLarge 单次置位）逐语义等价。
 *
 * 上限按 UTF-16 code unit 计（string.length），与原实现一致——
 * 这是有意保留的现状语义，不是字节上限；改成字节计属行为变化，
 * 不在本票范围内。
 */
export class SizeCappedText {
  private text = '';
  private overflowed = false;

  constructor(
    private readonly maxUnits: number,
    private readonly onOverflow: () => void,
  ) {}

  append(chunk: string): void {
    this.text += chunk;
    if (this.text.length > this.maxUnits && !this.overflowed) {
      this.overflowed = true;
      this.onOverflow();
    }
  }

  /** Accumulated text so far（溢出后请求已被 413 拒绝，不再消费）。 */
  get value(): string {
    return this.text;
  }

  /** 是否已溢出（一次性置位，此后恒真）。 */
  get overflow(): boolean {
    return this.overflowed;
  }
}
