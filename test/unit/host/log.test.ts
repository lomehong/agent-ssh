import { describe, expect, it, afterEach } from 'vitest';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { RotatingLogger } from '../../../src/host/log.js';

let dir: string | undefined;
const loggers: RotatingLogger[] = [];

afterEach(() => {
  for (const l of loggers.splice(0)) void l;
  if (dir !== undefined && existsSync(dir)) rmSync(dir, { recursive: true, force: true });
  dir = undefined;
});

function newLogger(maxBytes: number, keepFiles = 3): { logger: RotatingLogger; file: string } {
  dir ??= mkdtempSync(join(tmpdir(), 'rpc-log-'));
  const file = join(dir, 'host.log');
  const logger = new RotatingLogger({ file, maxBytes, keepFiles });
  loggers.push(logger);
  return { logger, file };
}

describe('守护日志轮转（T-15 验收 7）', () => {
  it('落盘去向：行以换行结尾写入主文件', () => {
    const { logger, file } = newLogger(10_000);
    logger.append('line-1');
    expect(readFileSync(file, 'utf8')).toBe('line-1\n');
  });

  it('超限触发轮转：主文件清空，旧内容到 .1', () => {
    const { logger, file } = newLogger(100);
    for (let i = 0; i < 10; i++) logger.append(`x`.repeat(30) + `-${i}`);
    expect(existsSync(`${file}.1`)).toBe(true);
    // 主文件在轮转后重新开始累积（最近内容在主或 .1 中，总数不丢）
    const total = existsSync(file) ? readFileSync(file, 'utf8') : '';
    expect(total.length).toBeLessThanOrEqual(100 + 62); // 单行上限内
  });

  it('keepFiles 上界：最老轮转文件被丢弃，序号连续', () => {
    const { logger, file } = newLogger(50, 2);
    for (let i = 0; i < 40; i++) logger.append('y'.repeat(40) + `-${i}`);
    expect(existsSync(`${file}.1`)).toBe(true);
    expect(existsSync(`${file}.2`)).toBe(true);
    expect(existsSync(`${file}.3`)).toBe(false); // keep=2 → .3 不存在
  });
});
