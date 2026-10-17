import { mkdir, readFile, readdir, writeFile, chmod } from 'fs/promises';
import { homedir, platform, userInfo } from 'os';
import { join } from 'path';
import { createHash } from 'crypto';
import type { AclVerdict } from '../config/sddl.js';
import { assertPrivateOnWindows } from '../config/windows-acl.js';

/**
 * 基于文件的审批队列——MCP 客户端无 elicitation 支持的主机的人为门
 *（计划 §2，主人批准 2026-10-11 R6）。
 *
 * 形状：服务器为每个被挡命令写一个 pending/<id>.json；运维从 CLI
 * 决定（agent-ssh approvals approve 或 reject 加 id）；服务器轮询同一文件，
 * 只在 decisionFingerprint 仍匹配其排队的请求时行动。
 * 没有任何决定接口暴露给模型——决定的唯一写入者是本 CLI
 * 及其背后的人。
 *
 *
 * 指纹是绊线，不是控制。控制是目录权限：POSIX 上 0700，
 * Windows 上服务器等待前的 assertPrivateOnWindows 检查。
 * 指纹把决定钉在人看到的精确载荷上；它拦不住已经能改写文件的人。
 *
 * can already rewrite the file.
 */

export type ApprovalSurface = 'desktop' | 'im' | 'queue';

/**
 * 审批窗口（U3 裁决维持 10min）：入队即计，过期 fail-closed——Agent 收到
 * 结构化拒绝可重发。原定义在 guard/elicitation.ts（T-15 随通道移除迁入本文件，
 * 队列语义的本职归属）。语义不变：墙钟仅用于展示，判定路径用单调钟（M4）。
 */
export const APPROVAL_TIMEOUT_MS = 600_000;

export interface PendingApproval {
  id: string;
  createdAt: string;
  expiresAt: string;
  profile: string;
  command: string;
  commandClass: string;
  binary: string;
  fingerprint: string;
  status: 'pending' | 'approved' | 'rejected' | 'expired';
  decidedAt?: string;
  decidedBy?: string;
  decisionFingerprint?: string;
}

export interface ApprovalQueueResult {
  approved: boolean;
  approver?: string;
  unavailable?: string;
}

export function getApprovalQueueDir(): string {
  const home = homedir();
  const p = platform();
  if (p === 'darwin') return join(home, 'Library', 'Application Support', 'agent-ssh', 'approvals');
  if (p === 'win32') {
    return join(process.env.LOCALAPPDATA || join(home, 'AppData', 'Local'), 'agent-ssh', 'approvals');
  }
  const xdgData = process.env.XDG_DATA_HOME || join(home, '.local', 'share');
  return join(xdgData, 'agent-ssh', 'approvals');
}

/** 人所看到的载荷的规范完整性哈希。 */
export function fingerprintOf(req: Pick<PendingApproval, 'id' | 'profile' | 'command' | 'commandClass' | 'binary' | 'createdAt' | 'expiresAt'>): string {
  return createHash('sha256')
    .update(JSON.stringify({
      id: req.id,
      profile: req.profile,
      command: req.command,
      commandClass: req.commandClass,
      binary: req.binary,
      createdAt: req.createdAt,
      expiresAt: req.expiresAt,
    }))
    .digest('hex');
}

function pendingPath(dir: string, id: string): string {
  // id 由服务器生成，但读取方提供的 id 经 CLI 到达此拼接，
  // 所以拒绝目录穿越形状而非信任它。
  if (!/^[A-Za-z0-9_-]+$/.test(id)) throw new Error(`Invalid approval id: ${id}`);
  return join(dir, 'pending', `${id}.json`);
}

function newId(now: Date): string {
  return `${now.getTime()}-${Math.random().toString(36).slice(2, 8)}`;
}

export type QueueAclInspect = (path: string) => Promise<AclVerdict>;

/**
 * 队列目录的 Windows 专属强制（T-11，主人裁定 2026-10-11：
 * 仅报告的残留不被接受）。
 *
 * 人批准的是*文件*说的内容，所以另一账户可改写的目录是授权绕过——
 * 伪造批准，而非隐私泄露。这是上游 ACL 语义的写暴露半边：
 * 拒绝，绝不报告后继续。POSIX 以队列创建时取的 0700 chmod
 * 强制同一性质，所以此检查在那里是空操作。
 *
 */
export async function assertQueueDirPrivate(
  dir: string,
  inspect?: QueueAclInspect,
): Promise<void> {
  if (platform() !== 'win32') return;
  // T-19 验收②实证（评审前红灯）：目录未建时 icacls 对不存在路径 read-refused
  // → Windows 首次部署审批队列必挂。先建（与 POSIX「创建时取 0700」对齐）再查。
  await ensureDir(dir);
  await assertPrivateOnWindows(dir, {}, inspect);
}

function currentOSUser(): string {
  try {
    return userInfo().username || 'unknown';
  } catch {
    return 'unknown';
  }
}

async function ensureDir(dir: string): Promise<void> {
  const pending = join(dir, 'pending');
  await mkdir(pending, { recursive: true });
  // 仅 POSIX；Windows 隐私由调用方运行的 ACL 检查断言
  //（assertPrivateOnWindows 与配置加载器共享拒绝/报告拆分）。
  if (platform() !== 'win32') {
    await chmod(dir, 0o700).catch(() => {});
    await chmod(pending, 0o700).catch(() => {});
  }
}

export interface CreateApprovalInput {
  profile: string;
  command: string;
  commandClass: string;
  binary: string;
  timeoutMs: number;
}

/** 写一条待审请求；返回将展示给运维的内容。 */
export async function createApprovalRequest(
  input: CreateApprovalInput,
  opts: { dir?: string; now?: Date } = {},
): Promise<PendingApproval> {
  const dir = opts.dir ?? getApprovalQueueDir();
  const now = opts.now ?? new Date();
  const request: PendingApproval = {
    id: newId(now),
    createdAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + input.timeoutMs).toISOString(),
    profile: input.profile,
    command: input.command,
    commandClass: input.commandClass,
    binary: input.binary,
    status: 'pending',
    fingerprint: '',
  };
  request.fingerprint = fingerprintOf(request);
  await ensureDir(dir);
  const file = pendingPath(dir, request.id);
  await writeFile(file, JSON.stringify(request, null, 2) + '\n', 'utf8');
  if (platform() !== 'win32') await chmod(file, 0o600).catch(() => {});
  return request;
}

export interface WaitOptions {
  dir?: string;
  fingerprint: string;
  expiresAt: string;
  /** 轮询间隔；生产默认 2 秒，测试用毫秒。 */
  pollMs?: number;
  now?: () => Date;
  /** 文件入队后调用一次，用于服务器的 stderr 指引。 */
  onQueued?: (id: string) => void;
}

/**
 * 轮询人的决定，直到到达或请求过期。
 *
 * 三种方式 fail-closed，各有其不可用原因：过期（无人回答）、
 * 指纹不匹配（人看到后文件变了）、或被拒的决定
 *（最后一个是人的答案，approved: false 而无不可用原因）。
 *
 */
export async function waitForDecision(
  id: string,
  opts: WaitOptions,
): Promise<ApprovalQueueResult> {
  const dir = opts.dir ?? getApprovalQueueDir();
  const file = pendingPath(dir, id);
  const pollMs = opts.pollMs ?? 2_000;
  const now = opts.now ?? (() => new Date());

  if (opts.onQueued) opts.onQueued(id);
  for (;;) {
    await new Promise((r) => setTimeout(r, pollMs));
    let stored: PendingApproval;
    try {
      stored = JSON.parse(await readFile(file, 'utf8')) as PendingApproval;
    } catch {
      continue; // transient: mid-write or vanished; the expiry bounds this loop
    }
    if (stored.decisionFingerprint !== undefined && stored.decisionFingerprint !== opts.fingerprint) {
      return {
        approved: false,
        unavailable: 'approval queue fingerprint mismatch — the request file changed after it was shown; refusing.',
      };
    }
    if (stored.status === 'approved' || stored.status === 'rejected') {
      // decidedBy 原样透传（T-17.6 修正：此前此处硬包 `cli:` 前缀，而决定
      // 写入方已自带面身份——cli:<user>（CLI）/ desktop:<user>（桌面端
      // main.rs）/ im:<open_id>（飞书 bot）——硬前缀造成 cli:desktop:…
      // 双前缀，IM/桌面决定在审计里被冒充成 CLI 面）。前缀职责归写入方。
      return stored.status === 'approved'
        ? { approved: true, approver: stored.decidedBy ?? currentOSUser() }
        : { approved: false };
    }
    if (now().getTime() >= Date.parse(stored.expiresAt)) {
      stored.status = 'expired';
      await writeFile(file, JSON.stringify(stored, null, 2) + '\n', 'utf8').catch(() => {});
      return {
        approved: false,
        unavailable: `no decision within the window; the request expired at ${stored.expiresAt} and was refused rather than left pending.`,
      };
    }
  }
}

/** 队列中每条待审请求，最老的在前（CLI 的 list）。 */
export async function listPending(opts: { dir?: string } = {}): Promise<PendingApproval[]> {
  const dir = opts.dir ?? getApprovalQueueDir();
  const pending = join(dir, 'pending');
  let files: string[];
  try {
    files = (await readdir(pending)).filter((f) => f.endsWith('.json'));
  } catch {
    return [];
  }
  const out: PendingApproval[] = [];
  for (const f of files) {
    try {
      out.push(JSON.parse(await readFile(join(pending, f), 'utf8')) as PendingApproval);
    } catch {
      // 撕裂或损坏的文件作为自己的条目列出，使运维能看见并删除它，
      // 而非队列悄悄藏起它。
      out.push({
        id: f.replace(/\.json$/, ''), createdAt: '', expiresAt: '', profile: '(unreadable)',
        command: '(unreadable)', commandClass: '', binary: '', fingerprint: '', status: 'pending',
      });
    }
  }
  return out.sort((a, b) => a.createdAt.localeCompare(b.createdAt));
}

export interface DecideOutcome {
  decided: boolean;
  message: string;
}

/**
 * K7：决定按 id 串行化（Host 单进程内互斥）。
 *
 * decideApproval 的读-判-写在无锁下是并发双写窗口（三审批面同时收到推送时
 * 双决定真实化，评审 T-14 标准轴 K7）。按 `${dir}::${id}` 分键的 promise 链
 * 使同 id 决定严格串行：后到者读到前者的落盘终态，收「已决定」而非双写。
 * 不同 id 各自独立，互不阻塞。锁条目在落定后自清理，不随 id 数量增长。
 */
const decideLocks = new Map<string, Promise<void>>();

async function withDecisionLock<T>(key: string, fn: () => Promise<T>): Promise<T> {
  const prev = decideLocks.get(key) ?? Promise.resolve();
  const run = prev.then(fn, fn);
  const settled = run.then(
    () => undefined,
    () => undefined,
  );
  decideLocks.set(key, settled);
  try {
    return await run;
  } finally {
    if (decideLocks.get(key) === settled) decideLocks.delete(key);
  }
}

/** CLI 侧决定。拒绝任何非待审或已过期的东西。 */
export async function decideApproval(
  id: string,
  decision: 'approved' | 'rejected',
  opts: { dir?: string; by?: string; now?: Date } = {},
): Promise<DecideOutcome> {
  const dir = opts.dir ?? getApprovalQueueDir();
  return withDecisionLock(`${dir}::${id}`, async () => {
    const file = pendingPath(dir, id);
    let stored: PendingApproval;
    try {
      stored = JSON.parse(await readFile(file, 'utf8')) as PendingApproval;
    } catch {
      return { decided: false, message: `No such approval request: ${id}` };
    }
    const now = opts.now ?? new Date();
    if (stored.status !== 'pending') {
      return { decided: false, message: `Request ${id} is already ${stored.status}${stored.decidedBy ? ` by ${stored.decidedBy}` : ''}.` };
    }
    if (now.getTime() >= Date.parse(stored.expiresAt)) {
      stored.status = 'expired';
      await writeFile(file, JSON.stringify(stored, null, 2) + '\n', 'utf8');
      return { decided: false, message: `Request ${id} expired at ${stored.expiresAt}; it is marked expired and the server will refuse it.` };
    }
    stored.status = decision;
    stored.decidedAt = now.toISOString();
    stored.decidedBy = opts.by ?? currentOSUser();
    stored.decisionFingerprint = fingerprintOf(stored);
    await writeFile(file, JSON.stringify(stored, null, 2) + '\n', 'utf8');
    return { decided: true, message: `${decision}: ${stored.commandClass} command on "${stored.profile}" — ${stored.command}` };
  });
}
