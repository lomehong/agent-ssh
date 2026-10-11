/**
 * pidfile 单实例强制（T-15 验收 6，方案 §3.5/D5'：二次启动 fail-fast）。
 *
 * 语义：acquire 原子创建（O_EXCL）；已存在时读 pid——进程仍活着 → 拒绝
 * （fail-fast，绝不静默并存）；进程已死 → 陈旧文件，覆盖接管。
 * release 删除自身。Windows 上 O_EXCL 同样原子，无跨进程锁需求
 * （单实例判定即存在性判定）。
 */
import { openSync, readFileSync, writeFileSync, closeSync, unlinkSync, existsSync } from 'node:fs';

export class PidfileLockedError extends Error {
  constructor(readonly pid: number, readonly path: string) {
    super(`Another instance is running (pid ${pid}, pidfile ${path}). Refusing to start (single-instance).`);
    this.name = 'PidfileLockedError';
  }
}

function processAlive(pid: number): boolean {
  try {
    process.kill(pid, 0); // 信号 0 = 存在性探测
    return true;
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    return code === 'EPERM'; // 存在但无权发信号——仍算活着
  }
}

export function acquirePidfile(path: string): { release(): void } {
  if (existsSync(path)) {
    let pid = 0;
    try {
      pid = Number.parseInt(readFileSync(path, 'utf8').trim(), 10);
    } catch {
      pid = Number.NaN;
    }
    if (Number.isInteger(pid) && pid > 0 && processAlive(pid)) {
      throw new PidfileLockedError(pid, path);
    }
    // 陈旧文件（进程已死或内容不可读）：删旧后接管。先 unlink 再 O_EXCL
    // 创建——并发接管者的竞态窗口：胜者写入前后者可能读到空/缺文件而误判，
    // 此时 O_EXCL 的 EEXIST/胜者活体探测会把它挡回 LockedError（fail-fast）。
    unlinkSync(path);
  }
  let fd: number;
  try {
    fd = openSync(path, 'wx'); // O_EXCL：与并发第二次启动的竞态也原子
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'EEXIST') {
      // 接管竞态败者：胜者（另一接管者/原实例）活着——按锁拒绝并报告其 pid。
      let winner = 0;
      try {
        winner = Number.parseInt(readFileSync(path, 'utf8').trim(), 10);
      } catch {
        winner = 0;
      }
      throw new PidfileLockedError(winner, path);
    }
    throw err;
  }
  try {
    writeFileSync(fd, String(process.pid), 'utf8');
  } finally {
    closeSync(fd);
  }
  let released = false;
  return {
    release(): void {
      if (released) return;
      released = true;
      try {
        unlinkSync(path);
      } catch {
        // 已被运维删除：release 语义已达成。
      }
    },
  };
}
