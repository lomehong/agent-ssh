/**
 * 守护进程日志：落盘去向 + 按尺寸轮转（T-15 验收 7）。
 *
 * 背景（评审小残留）：Windows 计划任务自启时 stdout 零可见性——守护日志
 * 必须落文件且有界。轮转语义：单文件超 maxBytes 即整体改名 .1（序号后移，
 * 超 keepFiles 丢弃最老），新写回流主文件。行级追加（调用方自带时间戳前缀）。
 * 同步 IO：守护日志量级低（分钟级事件），同步换确定性。
 */
import { appendFileSync, existsSync, statSync, renameSync, unlinkSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

export interface RotatingLoggerOpts {
  file: string;
  /** 单文件上限（字节），默认 5MB。 */
  maxBytes?: number;
  /** 轮转保留的旧文件数（.1 ~ .keepFiles），默认 3。 */
  keepFiles?: number;
}

export class RotatingLogger {
  private readonly maxBytes: number;
  private readonly keepFiles: number;

  constructor(private readonly opts: RotatingLoggerOpts) {
    this.maxBytes = opts.maxBytes ?? 5 * 1024 * 1024;
    this.keepFiles = opts.keepFiles ?? 3;
    mkdirSync(dirname(opts.file), { recursive: true });
  }

  append(line: string): void {
    if (existsSync(this.opts.file) && statSync(this.opts.file).size >= this.maxBytes) {
      this.rotate();
    }
    appendFileSync(this.opts.file, line.endsWith('\n') ? line : line + '\n', 'utf8');
  }

  private rotate(): void {
    // .(keepFiles-1) → .keepFiles …（最老的丢弃），file → .1
    const oldest = `${this.opts.file}.${this.keepFiles}`;
    if (existsSync(oldest)) unlinkSync(oldest);
    for (let i = this.keepFiles - 1; i >= 1; i--) {
      const from = `${this.opts.file}.${i}`;
      if (existsSync(from)) renameSync(from, `${this.opts.file}.${i + 1}`);
    }
    renameSync(this.opts.file, `${this.opts.file}.1`);
  }
}
