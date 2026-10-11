import { appendFile, mkdir, stat } from 'fs/promises';
import { dirname, join } from 'path';
import { redactText } from '../guard/redactor.js';
import { getAuditLogPath } from '../audit/store.js';

/**
 * 裸 PTY 会话的按会话脱敏转录。
 *
 * PTY 安全计划第 ② 层（技术方案 §6 U2，主人 2026-10-11 批准）：
 * 裸 PTY 是字节流，其上的任何内容都无法通过命令分类器——
 * 补偿性控制是其上的一切皆可审计。转录记录每条输入写入与每个输出块，
 * 用与审计日志相同的引擎脱敏，
 * 每会话一个文件，
 * 存放在审计日志旁边。
 *
 * 转录设计上尽力而为：I/O 故障绝不能破坏它所观察的会话，
 * 因此追加错误在上报 `onError` 后被吞掉。`maxBytes` 上限防止失控输出
 * 塞满磁盘；越过上限后文件冻结，丢失被计数（并体现在
 * 会话信息中），
 * 而不是永远在行中间静默截断。
 */

export interface PtyTranscript {
  append(direction: 'in' | 'out', text: string): void;
  readonly bytesWritten: number;
  readonly frozen: boolean;
}

const DEFAULT_MAX_BYTES = 10 * 1024 * 1024;

export function getTranscriptDir(): string {
  return join(dirname(getAuditLogPath()), 'pty-transcripts');
}

export class FilePtyTranscript implements PtyTranscript {
  private size = 0;
  private freezeState = false;
  private dirEnsured = false;
   /** 串行化追加操作，使交错的输入/输出块在文件中保持有序。 */
  private queue: Promise<void> = Promise.resolve();

  private constructor(
    private readonly filePath: string,
    private readonly maxBytes: number,
    private readonly onError: (err: unknown) => void,
  ) {}

  static async open(
    sessionName: string,
    opts: { dir?: string; maxBytes?: number; onError?: (err: unknown) => void } = {},
  ): Promise<FilePtyTranscript | null> {
    const dir = opts.dir ?? getTranscriptDir();
    const filePath = join(
      dir,
      `${sessionName.replace(/[^A-Za-z0-9_-]/g, '_')}-${Date.now()}.log`,
    );
    const transcript = new FilePtyTranscript(
      filePath,
      opts.maxBytes ?? DEFAULT_MAX_BYTES,
      opts.onError ?? (() => {}),
    );
    try {
      await mkdir(dirname(filePath), { recursive: true });
      transcript.dirEnsured = true;
      return transcript;
    } catch (err) {
      transcript.onError(err);
      return null;
    }
  }

  get bytesWritten(): number {
    return this.size;
  }

  get frozen(): boolean {
    return this.freezeState;
  }

  append(direction: 'in' | 'out', text: string): void {
    if (this.freezeState || text.length === 0) return;
    // 用审计引擎脱敏——设备横幅或粘贴进来的机密不能仅因
    // 「这条流不是命令」就落进日志文件。
    const line = JSON.stringify({
      t: new Date().toISOString(),
      dir: direction,
      text: redactText(text),
    }) + '\n';
    const bytes = Buffer.byteLength(line);
    if (this.size + bytes > this.maxBytes) {
      this.freezeState = true;
      return;
    }
    this.size += bytes;
    this.queue = this.queue
      .then(async () => {
        if (!this.dirEnsured) {
          await mkdir(dirname(this.filePath), { recursive: true });
          this.dirEnsured = true;
        }
        await appendFile(this.filePath, line, 'utf8');
      })
      .catch((err) => this.onError(err));
  }
}

/** 供测试与启动日志使用的探针；目录不存在时为 null。 */
export async function transcriptDirExists(): Promise<boolean> {
  try {
    await stat(getTranscriptDir());
    return true;
  } catch {
    return false;
  }
}
