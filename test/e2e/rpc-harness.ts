/**
 * T-18b 双进程 e2e harness（per-file 复用 Host + per-test mkdtemp，K9-④）：
 * spawn `host serve` 守护子进程 + StdioClientTransport 连 stub 分发器——
 * MCP 宿主→stub→RPC→Host 全链路。
 *
 * 五件套：端口（serve --port=0+host-rpc-ready 就绪行）/进程树清理（taskkill
 * 兜底）/就绪探测（stderr 行解析，超时即杀）/per-test 隔离（独立 config+queue
 * 目录）/TLS（骨架直连明文环回；pin 路径随 T-17.5b pin 路径）。
 */
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { listPending, decideApproval } from '../../src/guard/approval-queue.js';

export const RPC_E2E_TIMEOUT_MS = 30_000;

const REPO_ROOT = resolve(import.meta.dirname ?? '.', '..', '..');
const SERVER_ENTRY = join(REPO_ROOT, 'build', 'index.js');
const READY_LINE = /host-rpc-ready port=(\d+)/;

export interface RpcE2EHost {
  proc: ChildProcess;
  port: number;
  hostToken: string;
  queueDir: string;
  workDir: string;
  stop(): Promise<void>;
}

/** 构建前置断言：build/index.js 必须已存在（调用方先 `npm run build`，
 *  与主仓 test:e2e 惯例一致；vitest 内 spawn tsc 会被 NODE_OPTIONS loader
 *  干扰，故不在测试内自动构建）。 */
export function assertBuilt(): void {
  if (!existsSync(join(REPO_ROOT, 'build', 'index.js'))) {
    throw new Error('build/index.js missing — run `npm run build` before e2e.');
  }
}



function waitReady(proc: ChildProcess, timeoutMs: number): Promise<number> {
  return new Promise((resolveP, rejectP) => {
    let settled = false;
    const finish = (fn: () => void): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      fn();
    };
    const timer = setTimeout(() => {
      finish(() => {
        void stopTree(proc);
        rejectP(new Error(`host not ready within ${timeoutMs}ms`));
      });
    }, timeoutMs);
    const stderr = proc.stderr;
    if (stderr === null) {
      finish(() => rejectP(new Error('host stderr unavailable')));
      return;
    }
    stderr.setEncoding('utf8');
    let buffer = '';
    stderr.on('data', (chunk: string) => {
      buffer += chunk;
      const m = READY_LINE.exec(buffer);
      if (m && !settled) {
        finish(() => resolveP(Number(m[1])));
      }
    });
    proc.once('exit', (code) => {
      finish(() => rejectP(new Error(`host exited before ready (code=${code}): ${buffer.slice(0, 300)}`)));
    });
  });
}

/** Windows 兜底进程树清理。 */
export async function stopTree(proc: ChildProcess): Promise<void> {
  if (proc.exitCode !== null || proc.signalCode !== null) return;
  const exited = new Promise<void>((r) => proc.once('exit', () => r()));
  if (process.platform === 'win32') {
    spawnSync('taskkill', ['/PID', String(proc.pid), '/T', '/F'], { stdio: 'ignore' });
  } else {
    proc.kill('SIGTERM');
  }
  const grace = new Promise<void>((r) => setTimeout(r, 3_000));
  await Promise.race([exited, grace]);
  if (proc.exitCode === null && proc.signalCode === null) proc.kill('SIGKILL');
  await exited;
}

/**
 * 拉起 Host 守护子进程并等就绪行（端口 0=OS 分配）。
 * hostToken 由调用方生成传入（本模块不生成凭据）。
 */
export async function spawnRpcHost(opts: {
  configToml: string;
  hostToken: string;
  queueDir: string;
}): Promise<RpcE2EHost> {

  const workDir = mkdtempSync(join(tmpdir(), 'rpc-e2e-'));
  const configPath = join(workDir, 'config.toml');
  writeFileSync(configPath, opts.configToml, 'utf8');

  const proc = spawn(
    process.execPath,
    [SERVER_ENTRY, 'host', 'serve', '--port=0', `--config=${configPath}`],
    {
      cwd: REPO_ROOT,
      stdio: ['ignore', 'ignore', 'pipe'],
      windowsHide: true,
      env: { ...process.env, AGENT_SSH_TOKEN: opts.hostToken, AGENT_SSH_QUEUE_DIR: opts.queueDir },
    },
  );
  const port = await waitReady(proc, 15_000);
  return {
    proc,
    port,
    hostToken: opts.hostToken,
    queueDir: opts.queueDir,
    workDir,
    stop: async () => {
      await stopTree(proc);
      rmSync(workDir, { recursive: true, force: true });
    },
  };
}

/** 跨进程队列裁决泵：poll queueDir 批准全部待审（destructive e2e 链路）。 */
export function startQueuePump(queueDir: string, intervalMs = 50): () => void {
  const timer = setInterval(() => {
    void (async () => {
      try {
        for (const p of await listPending({ dir: queueDir })) {
          await decideApproval(p.id, 'approved', { dir: queueDir, by: 'e2e-pump' });
        }
      } catch {
        // 瞬态下个 tick 重试。
      }
    })();
  }, intervalMs);
  return () => clearInterval(timer);
}
