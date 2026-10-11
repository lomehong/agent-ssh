/**
 * CLI 的 RPC 面（T-17，D1'/D4）：approvals 与 run/info 从「进程内直连」
 * 改为「连 Host 守护」。队列与执行都在 Host 机；CLI 只带 operator 会话。
 *
 * 会话引导（D1'）：无凭据启动（skipHello）→ 口令/令牌换会话 → 以会话令牌
 * 重连（走正常 hello）。口令输入：TTY 隐藏回显；管道场景读一行明文。
 * --session-token-stdin：脚本场景直接喂会话令牌——明示风险（同机进程可窥）。
 * 旧直连（cli-direct.ts 进程内 SSH、runApprovalsCli 文件队列直读）已删除，
 * 本模块是其唯一继任。
 */
import { userInfo } from 'node:os';
import { OperatorError } from './errors.js';
import { parseArgv, positionalsOf } from './cli.js';
import { findForbiddenMatch } from './policy/classifier.js';
import { RpcClient } from './rpc/client.js';

/** CLI 直连面的动词表（旧 cli-direct 的继承面）。 */
export const DIRECT_VERBS = ['run', 'info'] as const;

/** 审批人身份（§4.4）：cli:<本机用户>。 */
function cliUser(): string {
  try {
    return `cli:${userInfo().username}`;
  } catch {
    return 'cli:(unknown)';
  }
}

function resolveHostAddr(args: string[]): { host: string; port: number } {
  const flagIdx = args.indexOf('--host-addr');
  const fromArgs = flagIdx >= 0 ? args[flagIdx + 1] : undefined;
  const raw = fromArgs ?? process.env.AGENT_SSH_HOST_ADDR;
  if (!raw) {
    throw new OperatorError(
      'AGENT_SSH_HOST_ADDR is required (env or --host-addr host:port). The CLI dials the host daemon.',
    );
  }
  const i = raw.lastIndexOf(':');
  if (i === -1) throw new OperatorError(`Invalid host address '${raw}' — expected host:port`);
  let host = raw.slice(0, i);
  const port = Number(raw.slice(i + 1));
  if (host.startsWith('[') && host.endsWith(']')) host = host.slice(1, -1);
  if (!Number.isInteger(port) || port <= 0 || port > 65_535) {
    throw new OperatorError(`Invalid port in host address '${raw}'`);
  }
  return { host, port };
}

/** TTY 隐藏回显读口令；非 TTY（管道）读一行明文。Ctrl+C 恢复终端态。 */
async function askPassword(prompt: string): Promise<string> {
  if (process.stdin.isTTY !== true) {
    const chunks: string[] = [];
    for await (const chunk of process.stdin) chunks.push(String(chunk));
    return chunks.join('').trim();
  }
  process.stdout.write(prompt);
  process.stdin.setRawMode(true);
  process.stdin.resume();
  let out = '';
  try {
    for await (const chunk of process.stdin) {
      const s = String(chunk);
      if (s === '\r' || s === '\n') {
        process.stdout.write('\n');
        break;
      }
      if (s === '\u007f' || s === '\b') {
        out = out.slice(0, -1);
        continue;
      }
      if (s === '\u0003') {
        process.stdout.write('\n');
        throw new OperatorError('Cancelled.');
      }
      out += s;
      process.stdout.write('*');
    }
  } finally {
    // Ctrl+C 抛错路径也必须恢复终端态（评审 T-17 jc4）。
    process.stdin.setRawMode(false);
    process.stdin.pause();
  }
  return out;
}

async function readStdinToken(): Promise<string> {
  const chunks: string[] = [];
  for await (const chunk of process.stdin) chunks.push(String(chunk));
  return chunks.join('').trim();
}

/**
 * operator 客户端引导：会话令牌（env/stdin）直接用；否则交互口令→
 * auth.session.start（skipHello，start 是 pre-auth 方法）→ 以会话令牌
 * 建正式客户端（走 hello，operator 面矩阵生效）。
 */
async function operatorClient(args: string[]): Promise<RpcClient> {
  const { host, port } = resolveHostAddr(args);
  const pin = process.env.AGENT_SSH_HOST_PIN;
  let token = process.env.AGENT_SSH_SESSION_TOKEN;

  if (args.includes('--session-token-stdin')) {
    console.error(
      '[warn] --session-token-stdin：会话令牌经 stdin 传入，同机进程可窥——脚本场景专用，风险自担。',
    );
    token = await readStdinToken();
  }
  if (!token) {
    const password = await askPassword('operator password: ');
    const pre = new RpcClient({
      host,
      port,
      token: '',
      skipHello: true,
      reconnect: false,
      requestTimeoutMs: 10_000,
      ...(pin !== undefined && pin !== '' ? { tls: { pin } } : {}),
    });
    try {
      await pre.connect();
      const started = (await pre.call('auth.session.start', { password })) as { sessionToken: string };
      token = started.sessionToken;
    } finally {
      await pre.close().catch(() => {});
    }
  }

  const client = new RpcClient({
    host,
    port,
    token,
    reconnect: false,
    requestTimeoutMs: 30_000,
    ...(pin !== undefined && pin !== '' ? { tls: { pin } } : {}),
  });
  await client.connect();
  return client;
}

/** agent-ssh run / info（D4：语义经 Host 的 cli.run/cli.info，旧直连已删除）。 */
export async function runDirectCli(verb: 'run' | 'info', args: string[]): Promise<number> {
  if (verb === 'run') {
    const command = positionalsOf(args).join(' ').trim();
    if (command.length === 0) {
      console.error('Usage: agent-ssh run [--profile=<name>] <command> [words...]');
      return 1;
    }
    // 禁止名单在拨号之前本地拒绝（T-13 High-1 语义随迁）：红线优先于网络。
    const forbidden = findForbiddenMatch(command);
    if (forbidden !== null) {
      console.error(`[cli-rpc] 拒绝：命令命中禁止名单（${forbidden}）。禁止名单对人工与模型一视同仁；确需此类操作请在服务器 shell 上自行评估执行。`);
      return 1;
    }
  }

  let client: RpcClient | undefined;
  try {
    client = await operatorClient(args);
    const profileFlag = parseArgv(args).profile || undefined;

    if (verb === 'info') {
      const info = (await client.call('cli.info', { profile: profileFlag })) as {
        profile: Record<string, unknown>;
        connected: boolean;
        sessions: number;
        ptySessions: number;
      };
      const p = info.profile;
      console.log(`profile     : ${p.name}`);
      console.log(`host        : ${p.user}@${p.host}:${p.port}`);
      console.log(`auth        : ${p.auth}${p.keyRef ? ` (${p.keyRef})` : ''}`);
      console.log(`role/group  : ${p.role} / ${p.group ?? '(inferred)'}`);
      console.log(`deviceType  : ${p.deviceType ?? 'generic'}`);
      console.log(`algorithms  : ${Array.isArray(p.algorithms) ? `OVERRIDDEN (${(p.algorithms as string[]).join(', ')})` : 'frozen allowlist'}`);
      console.log(`approval    : ${p.approvalPolicy}`);
      console.log(`connect     : ${info.connected ? 'OK' : 'not connected'} | sessions: ${info.sessions} active, ${info.ptySessions} raw-pty`);
      return 0;
    }

    const command = positionalsOf(args).join(' ').trim();
    const res = (await client.call('cli.run', { command, profile: profileFlag })) as {
      stdout: string;
      stderr: string;
      exitCode: number;
      durationMs: number;
      profile: string;
      commandClass: string;
    };
    if (res.stdout) process.stdout.write(res.stdout + (res.stdout.endsWith('\n') ? '' : '\n'));
    if (res.stderr) process.stderr.write(res.stderr + (res.stderr.endsWith('\n') ? '' : '\n'));
    console.error(`[cli-rpc] ${res.profile} exit=${res.exitCode} class=${res.commandClass} ${res.durationMs}ms`);
    return res.exitCode;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    console.error(`[cli-rpc] ${verb} failed: ${message}`);
    return 1;
  } finally {
    await client?.close().catch(() => {});
  }
}

interface PendingView {
  id: string;
  createdAt: string;
  expiresAt: string;
  profile: string;
  command: string;
  commandClass: string;
  fingerprint: string;
  status: string;
}

function formatPending(p: PendingView, now: Date): string {
  const ageS = Math.max(0, Math.round((now.getTime() - Date.parse(p.createdAt)) / 1000));
  const leftS = Math.max(0, Math.round((Date.parse(p.expiresAt) - now.getTime()) / 1000));
  const status = p.status === 'pending' ? `expires in ${leftS}s` : p.status;
  // 「完整上下文」承诺（审计 M8）：审批人看到的就是将被执行的完整命令。
  return `${p.id}  [${status}]  ${p.commandClass} on "${p.profile}" (age ${ageS}s)\n    ${p.command}\n    fingerprint ${p.fingerprint.slice(0, 16)}…`;
}

/** agent-ssh approvals list|approve <id>|reject <id>（队列在 Host 机；--dir 不再适用）。 */
export async function runApprovalsCli(args: string[]): Promise<number> {
  const [verb, id] = positionalsOf(args);
  if (args.some((a) => a.startsWith('--dir='))) {
    console.error('[warn] --dir 已废弃：审批队列在 Host 机，由 Host 配置决定位置。');
  }

  let client: RpcClient | undefined;
  try {
    client = await operatorClient(args);
    const now = new Date();

    if (verb === 'list') {
      const listed = (await client.call('approval.list', {})) as { pending: PendingView[] };
      if (listed.pending.length === 0) {
        console.log('No approval requests.');
        return 0;
      }
      for (const p of listed.pending) console.log(formatPending(p, now));
      return 0;
    }

    if (verb === 'approve' || verb === 'reject') {
      if (!id) {
        console.error(`Usage: agent-ssh approvals ${verb} <id>`);
        return 1;
      }
      // 完整上下文在判定写入之前打印（M8）。
      const listed = (await client.call('approval.list', {})) as { pending: PendingView[] };
      const target = listed.pending.find((p) => p.id === id);
      if (target) console.log(formatPending(target, now));
      const outcome = (await client.call('approval.decide', {
        id,
        decision: verb === 'approve' ? 'approved' : 'rejected',
        by: cliUser(),
      })) as { decided: boolean; message: string };
      console.log(outcome.message);
      return outcome.decided ? 0 : 1;
    }

    console.error('Usage: agent-ssh approvals list | approvals approve <id> | approvals reject <id>');
    return 1;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    console.error(`[cli-rpc] approvals ${verb ?? ''} failed: ${message}`);
    return 1;
  } finally {
    await client?.close().catch(() => {});
  }
}
