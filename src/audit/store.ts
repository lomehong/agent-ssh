import { mkdir, stat, rename, chmod, open, type FileHandle } from 'fs/promises';
import { createWriteStream, type WriteStream } from 'fs';
import { homedir, platform } from 'os';
import { join, dirname } from 'path';
import { randomUUID, createHash } from 'crypto';
import type { AuditRecord } from '../types.js';
import { redactText } from '../guard/redactor.js';
import { tracer } from '../observability/tracer.js';

const MAX_FILE_SIZE = 100 * 1024 * 1024; // 100MB
const MAX_FILES = 10;

export function getAuditLogPath(): string {
  const home = homedir();
  const p = platform();

  if (p === 'darwin') {
    return join(home, 'Library', 'Logs', 'ssh-mcp', 'audit.log');
  }
  if (p === 'win32') {
    return join(process.env.LOCALAPPDATA || join(home, 'AppData', 'Local'), 'ssh-mcp', 'audit.log');
  }
  const xdgData = process.env.XDG_DATA_HOME || join(home, '.local', 'share');
  return join(xdgData, 'ssh-mcp', 'audit.log');
}

export class AuditStore {
  private logPath: string;
  private entropyScan: boolean;
  private tamperEvident: boolean;
  private lastHash: string = '';
  private writeStream: WriteStream | null = null;
  private dirEnsured = false;
  private recordCount = 0;
  /** 已打开日志文件中的字节数；-1 表示「从磁盘读取基线」。 */
  private bytesWritten = -1;
  private writeQueue: Promise<void> = Promise.resolve();
  /** 轮转阈值；可注入，测试无须真造 100MB 文件即可触发。 */
  private maxFileSize: number;

  constructor(logPath?: string, entropyScan = false, tamperEvident = false, maxFileSize = MAX_FILE_SIZE) {
    this.logPath = logPath || getAuditLogPath();
    this.entropyScan = entropyScan;
    this.tamperEvident = tamperEvident;
    this.maxFileSize = maxFileSize;
  }

  async record(entry: Omit<AuditRecord, 'timestamp' | 'eventId'>): Promise<void> {
    this.writeQueue = this.writeQueue
      .catch(() => {})
      .then(() => this._record(entry));
    return this.writeQueue;
  }

  async close(): Promise<void> {
    try { await this.writeQueue; } catch { /* queue may be rejected */ }
    if (this.writeStream && !this.writeStream.destroyed) {
      await new Promise<void>((resolve) => this.writeStream!.end(() => resolve()));
      this.writeStream = null;
    }
  }

  private async _record(entry: Omit<AuditRecord, 'timestamp' | 'eventId'>): Promise<void> {
    const span = tracer.startSpan('audit.record');
    span.setAttribute('audit.tamperEvident', this.tamperEvident);
    try {
      const record: AuditRecord = {
        ...entry,
        timestamp: new Date().toISOString(),
        eventId: randomUUID(),
      };

      const redactedCommand = redactText(record.command, { entropyScan: this.entropyScan });
      const redactedError = record.error ? redactText(record.error, { entropyScan: this.entropyScan }) : undefined;

      let lineObj: Record<string, unknown> = { ...record, command: redactedCommand, error: redactedError };

      if (this.tamperEvident) {
        if (!this.lastHash) {
          await this.loadLastHash();
        }
        const prevHash = this.lastHash;
        const contentForHash = JSON.stringify(lineObj) + prevHash;
        const selfHash = createHash('sha256').update(contentForHash).digest('hex');
        lineObj = { ...lineObj, prevHash, selfHash };
        this.lastHash = selfHash;
      }

      const line = JSON.stringify(lineObj) + '\n';

      await this.rotateIfNeeded(Buffer.byteLength(line));
      const stream = await this.ensureStream();
      await new Promise<void>((resolve, reject) => {
        stream.write(line, (err) => err ? reject(err) : resolve());
      });
      this.bytesWritten += Buffer.byteLength(line);

      span.setAttribute('audit.bytes', line.length);
      this.recordCount++;
    } finally {
      span.end();
    }
  }

  private async ensureStream(): Promise<WriteStream> {
    if (this.writeStream && !this.writeStream.destroyed) return this.writeStream;

    if (!this.dirEnsured) {
      await mkdir(dirname(this.logPath), { recursive: true });
      this.dirEnsured = true;
    }

    this.writeStream = createWriteStream(this.logPath, { flags: 'a' });
    // 为新打开的文件强制重读一次基线。
    this.bytesWritten = -1;
    try { await chmod(this.logPath, 0o600); } catch { /* may not exist yet */ }
    return this.writeStream;
  }

  private async loadLastHash(): Promise<void> {
    let fd: FileHandle | undefined;
    try {
      // Open first, then stat the handle. Stat-then-open is a TOCTOU race
      // (js/file-system-race): the size is used as a read offset, so a file
      // that shrank in between would be read from the wrong position. Statting
      // the open handle describes exactly the file being read.
      fd = await open(this.logPath, 'r');
      const fileStat = await fd.stat();
      const readSize = Math.min(fileStat.size, 8192);
      if (readSize === 0) return;

      const buf = Buffer.alloc(readSize);
      await fd.read(buf, 0, readSize, fileStat.size - readSize);

      const lines = buf.toString('utf8').split('\n').filter(Boolean);
      if (lines.length === 0) return;
      const lastLine = JSON.parse(lines[lines.length - 1]);
      this.lastHash = lastLine.selfHash || '';
    } catch {
      // 文件不存在或不可读——从头开始
    } finally {
      // The old code closed the handle only on the success path, leaking one
      // per failed read.
      await fd?.close().catch(() => { /* already closed */ });
    }
  }

  /**
   * Rotate before the incoming record would push the file over the limit.
   *
   * The size is tracked from the open stream instead of stat()ing the file on
   * every record: every tool call awaits this on the shared write queue, so
   * that was a syscall per request to answer a question we already know.
   */
  private async rotateIfNeeded(incomingBytes: number): Promise<void> {
    try {
      if (this.bytesWritten < 0) {
        // 该流上的首次写入——只建立一次基线。
        this.bytesWritten = await stat(this.logPath).then((s) => s.size).catch(() => 0);
      }
      if (this.bytesWritten + incomingBytes < this.maxFileSize) return;

      if (this.writeStream && !this.writeStream.destroyed) {
        await new Promise<void>((resolve) => {
          this.writeStream!.end(() => resolve());
        });
        this.writeStream = null;
      }

      for (let i = MAX_FILES - 1; i > 0; i--) {
        const oldPath = `${this.logPath}.${i}`;
        const newPath = `${this.logPath}.${i + 1}`;
        try {
          await rename(oldPath, newPath);
        } catch (err: any) {
          if (err.code !== 'ENOENT') throw err;
        }
      }
      await rename(this.logPath, `${this.logPath}.1`);
    } catch (err: any) {
      if (err.code === 'ENOENT') return;
      throw err;
    }
  }
}
