/**
 * RPC 双进程测试 harness（T-14.5 五件套；后续双进程票的地基）。
 *
 * ① 端口分配：dev-host 以 --port 0 监听，OS 分配，从就绪行取实际端口；
 * ② 进程树清理：SIGTERM 优雅关停 → 兜底 taskkill /T /F（Windows）或 SIGKILL；
 * ③ 就绪探测：stderr `rpc-host-ready port=N` 行，超时即杀进程并报错；
 * ④ per-test 状态隔离：每用例独立子进程 + 独立令牌 + 独立 mkdtemp 工作目录；
 * ⑤ TLS 夹具：openssl 生成自签证书（本机无 openssl 时抛 SkipError，用例条件跳过）。
 *
 * K9-⑤：双进程用例默认 vitest 5s 不够——RPC_TEST_TIMEOUT_MS=30s，测试文件显式套用。
 */
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { generateAgentToken } from '../../src/rpc/auth.js';

/** 双进程用例超时预算（K9-⑤）。 */
export const RPC_TEST_TIMEOUT_MS = 30_000;

const REPO_ROOT = resolve(import.meta.dirname ?? '.', '..', '..');
const DEV_HOST_BUILD = join(REPO_ROOT, 'build', 'rpc', 'dev-host.js');
const READY_LINE = /rpc-host-ready port=(\d+)/;

export class SkipError extends Error {}

export interface HostProcess {
  proc: ChildProcess;
  port: number;
  token: string;
  workDir: string;
  stop(): Promise<void>;
}

/** 构建陈旧检查：build/rpc/dev-host.js 缺失或老于 src/rpc 时重跑 tsc。 */
export function ensureBuilt(): void {
  const needsBuild =
    !existsSync(DEV_HOST_BUILD) ||
    statSync(DEV_HOST_BUILD).mtimeMs < newestSrcMtime(join(REPO_ROOT, 'src', 'rpc'));
  if (needsBuild) {
    const r = spawnSync(process.execPath, [join(REPO_ROOT, 'node_modules', 'typescript', 'bin', 'tsc')], {
      cwd: REPO_ROOT,
      stdio: 'pipe',
    });
    if (r.status !== 0) throw new Error(`tsc failed for rpc harness: ${r.stderr?.toString()}`);
  }
}

function newestSrcMtime(dir: string): number {
  let newest = 0;
  const walk = (d: string): void => {
    for (const entry of readdirSync(d)) {
      const full = join(d, entry);
      const st = statSync(full);
      if (st.isDirectory()) walk(full);
      else newest = Math.max(newest, st.mtimeMs);
    }
  };
  walk(dir);
  return newest;
}

/** 拉起 dev-host 子进程并等就绪。 */
export async function spawnDevHost(opts: { tlsCertPath?: string; tlsKeyPath?: string } = {}): Promise<HostProcess> {
  ensureBuilt();
  const workDir = mkdtempSync(join(tmpdir(), 'rpc-host-'));
  const agentToken: string = generateAgentToken();
  const args = ['build/rpc/dev-host.js', '--port', '0', '--token', agentToken];
  if (opts.tlsCertPath !== undefined && opts.tlsKeyPath !== undefined) {
    args.push('--tls-cert', opts.tlsCertPath, '--tls-key', opts.tlsKeyPath);
  }
  const proc = spawn(process.execPath, args, {
    cwd: REPO_ROOT,
    stdio: ['ignore', 'ignore', 'pipe'],
    windowsHide: true,
  });
  const port = await waitReady(proc, 15_000);
  return {
    proc,
    port,
    token: agentToken,
    workDir,
    stop: async () => {
      await stopTree(proc);
      rmSync(workDir, { recursive: true, force: true });
    },
  };
}

function waitReady(proc: ChildProcess, timeoutMs: number): Promise<number> {
  return new Promise((resolvePromise, rejectPromise) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      void stopTree(proc);
      rejectPromise(new Error(`dev-host not ready within ${timeoutMs}ms`));
    }, timeoutMs);
    const stderr = proc.stderr;
    if (stderr === null) {
      clearTimeout(timer);
      rejectPromise(new Error('dev-host stderr unavailable'));
      return;
    }
    let buffer = '';
    stderr.setEncoding('utf8');
    stderr.on('data', (chunk: string) => {
      buffer += chunk;
      const m = READY_LINE.exec(buffer);
      if (m !== null && !settled) {
        settled = true;
        clearTimeout(timer);
        resolvePromise(Number(m[1]));
      }
    });
    proc.once('exit', (code) => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        rejectPromise(new Error(`dev-host exited before ready (code=${code}): ${buffer.slice(0, 400)}`));
      }
    });
  });
}

/** 进程树清理：先 SIGTERM（dev-host 有优雅关停），Windows 兜底 taskkill /T /F。 */
export async function stopTree(proc: ChildProcess): Promise<void> {
  if (proc.exitCode !== null || proc.signalCode !== null) return;
  const exited = new Promise<void>((resolvePromise) => proc.once('exit', () => resolvePromise()));
  if (process.platform === 'win32') {
    // Windows 无进程组信号，taskkill /T 连树杀
    spawnSync('taskkill', ['/PID', String(proc.pid), '/T', '/F'], { stdio: 'ignore' });
  } else {
    proc.kill('SIGTERM');
  }
  const grace = new Promise<void>((resolvePromise) => setTimeout(resolvePromise, 3_000));
  await Promise.race([exited, grace]);
  if (proc.exitCode === null && proc.signalCode === null) proc.kill('SIGKILL');
  await exited;
}

/** TLS 夹具：openssl 自签证书；不可用即 Skip（用例条件跳过，不算失败）。 */
export function tlsFixture(): { certPath: string; keyPath: string; pin: string; workDir: string } {
  const probe = spawnSync('openssl', ['version'], { stdio: 'ignore' });
  if (probe.error !== undefined || probe.status !== 0) {
    throw new SkipError('openssl not available on this machine');
  }
  const workDir = mkdtempSync(join(tmpdir(), 'rpc-tls-'));
  const certPath = join(workDir, 'cert.pem');
  const keyPath = join(workDir, 'key.pem');
  const gen = spawnSync(
    'openssl',
    ['req', '-x509', '-newkey', 'rsa:2048', '-keyout', keyPath, '-out', certPath, '-days', '2', '-nodes', '-subj', '/CN=localhost'],
    { stdio: 'ignore' },
  );
  if (gen.status !== 0) throw new SkipError('openssl cert generation failed');
  const fp = spawnSync('openssl', ['x509', '-in', certPath, '-noout', '-fingerprint', '-sha256'], {
    encoding: 'utf8',
  });
  const match = /Fingerprint=([0-9A-Fa-f:]+)/.exec(fp.stdout ?? '');
  if (match === null) throw new SkipError('openssl fingerprint parse failed');
  const pin = match[1].replace(/:/g, '').toLowerCase();
  // 自校验：pin 即证书 DER/PEM 的 sha256 十六进制（64 位），防手滑
  const pem = readFileSync(certPath, 'utf8');
  const der = Buffer.from(
    pem.replace(/-----(BEGIN|END) CERTIFICATE-----/g, '').replace(/\s+/g, ''),
    'base64',
  );
  const expected = createHash('sha256').update(der).digest('hex');
  if (expected !== pin) throw new SkipError(`fingerprint mismatch: ${pin} vs ${expected}`);
  return { certPath, keyPath, pin, workDir };
}

export function rmrf(dir: string): void {
  rmSync(dir, { recursive: true, force: true });
}
