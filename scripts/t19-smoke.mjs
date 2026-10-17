// T-19 验收②：localhost 六步链路真实复跑（host serve 子进程 + stub stdio + docker sshd）。
// 用法：node scripts/t19-smoke.mjs   （前置：npm run build；docker sshd 集成环境在场）
import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { listPending, decideApproval } from '../build/guard/approval-queue.js';

const REPO = resolve(import.meta.dirname, '..');
const HOST_TOKEN = 't19-smoke-token-0123456789abcdef';
const results = [];
const ok = (name, cond, detail = '') => { results.push(`${cond ? 'PASS' : 'FAIL'} ${name}${detail ? ' — ' + detail : ''}`); if (!cond) process.exitCode = 1; };

const work = mkdtempSync(join(process.env.USERPROFILE ?? tmpdir(), 't19-smoke-'));
const queueDir = join(work, 'approvals');
// Windows：审批队列隐私检查对目录与其父目录都要求仅属主——tmp 继承 ACL
// 过宽，对 work 根收紧（queueDir 新建时自然继承私有）。
if (process.platform === 'win32') {
  spawnSync('icacls', [work, '/inheritance:r', '/grant:r', `${process.env.USERNAME}:(OI)(CI)F`], { stdio: 'ignore' });
}
const configPath = join(work, 'config.toml');
writeFileSync(configPath, `
[defaults]
approvalSurfaces = ["queue"]

[[profiles]]
name = "admin"
host = "127.0.0.1"
port = 2222
user = "admin"
auth = "password"
role = "admin"
group = "dev"
approvalPolicy = "ask-all"
`, 'utf8');

// ① Host 守护子进程
const hostLog = [];
const host = spawn(process.execPath, [join(REPO, 'build', 'index.js'), 'host', 'serve', '--port=0', `--config=${configPath}`], {
  cwd: REPO, stdio: ['ignore', 'ignore', 'pipe'], windowsHide: true,
  env: { ...process.env, AGENT_SSH_TOKEN: HOST_TOKEN, AGENT_SSH_QUEUE_DIR: queueDir, SSH_MCP_PASSWORD: 'secret' },
});
host.stderr.setEncoding('utf8');
host.stderr.on('data', (c) => hostLog.push(c));
const port = await new Promise((res, rej) => {
  const t = setTimeout(() => rej(new Error('host not ready')), 15_000);
  host.stderr.setEncoding('utf8');
  let buf = '';
  host.stderr.on('data', (c) => { buf += c; const m = /host-rpc-ready port=(\d+)/.exec(buf); if (m) { clearTimeout(t); res(Number(m[1])); } });
  host.once('exit', (c2) => { clearTimeout(t); rej(new Error(`host exited ${c2}: ${buf.slice(0, 200)}`)); });
});
ok('host serve 就绪', true, `port=${port}`);

// ② 队列裁决泵（跨进程批准）
let pumpOn = true;
const pump = setInterval(() => {
  if (!pumpOn) return;
  void (async () => { try { for (const p of await listPending({ dir: queueDir })) await decideApproval(p.id, 'approved', { dir: queueDir, by: 't19-smoke' }); } catch {} })();
}, 50);

// ③ stub stdio 客户端
const transport = new StdioClientTransport({
  command: process.execPath, args: [join(REPO, 'build', 'index.js')],
  env: { ...process.env, AGENT_SSH_HOST_ADDR: `127.0.0.1:${port}`, AGENT_SSH_TOKEN: HOST_TOKEN, SSH_MCP_DISABLE_MAIN: '1', SSH_MCP_ADMIN_PASSWORD: 'secret' },
  stderr: 'pipe',
});
const client = new Client({ name: 't19-smoke', version: '0.0.0' });
await client.connect(transport);
const deadline = Date.now() + 10_000;
let tools = [];
while (Date.now() < deadline) { tools = (await client.listTools()).tools; if (tools.length === 23) break; await new Promise((r) => setTimeout(r, 100)); }
ok('tools/list=23（stub→Host manifest）', tools.length === 23, `got ${tools.length}`);

// ④ list-connections（真实 SSH 触达前哨）
const lc = await client.callTool({ name: 'list-connections', arguments: {} });
ok('list-connections 可调（agent 面经 RPC）', Array.isArray(lc.content));

// ⑤ read-command 真实执行（docker sshd）
const rc = await client.callTool({ name: 'read-command', arguments: { profile: 'admin', command: 'echo t19-ok' } });
const rcText = (rc.content ?? []).map((s) => s.text ?? '').join('');
ok('read-command 真实执行（SSH 到容器）', rcText.includes('t19-ok'), rcText);

// ⑥ 破坏性命令→队列→批准→执行
const dc = await client.callTool({ name: 'run-command', arguments: { profile: 'admin', command: 'rm -rf /tmp/t19-smoke-dir && echo destructive-ok' } });
const dcText = (dc.content ?? []).map((s) => s.text ?? '').join('');
ok('破坏性命令经队列批准后执行', dcText.includes('destructive-ok'), dcText);

// ⑦ PTY 吞吐基线（§8：交互首字节 +1 RTT 量级）
// v2 修正（2026-10-17 真机复跑发现）：pty 系入参为 name（非 session/command）——
// 旧版传错参数，基线实为校验错误文本的假测量（T-19 原报"4-5ms/2.2s"作废）。
// 真机重测基线见 docs/reports/2026-10-17-T19-真机复跑与PTY基线重测.md。
const po = await client.callTool({ name: 'pty-open', arguments: { profile: 'admin', name: 'smokepty' } });
if (!po.isError) {
  const t0 = Date.now();
  await client.callTool({ name: 'pty-write', arguments: { profile: 'admin', name: 'smokepty', input: 'seq 1 2000\n' } });
  let bytes = 0, firstMs = -1, cursor = 0, done = false;
  for (let i = 0; i < 200 && !done; i++) {
    const pr = await client.callTool({ name: 'pty-read', arguments: { profile: 'admin', name: 'smokepty', cursor } });
    const t = (pr.content ?? []).map((s) => s.text ?? '').join('');
    let out = t, next = cursor;
    try { const j = JSON.parse(t); out = String(j.output ?? ''); next = Number(j.cursor ?? cursor); } catch {}
    if (firstMs < 0 && out.length > 0) firstMs = Date.now() - t0;
    bytes += out.length; cursor = next;
    if (out.includes('2000')) done = true;
  }
  const wall = Date.now() - t0;
  ok('PTY 交互基线（首字节时延）', firstMs >= 0 && done, `firstByte=${firstMs}ms total=${wall}ms chars=${bytes}`);
  await client.callTool({ name: 'pty-close', arguments: { profile: 'admin', name: 'smokepty' } });
} else {
  ok('PTY 交互基线', false, `pty-open 失败: ${((po.content ?? []).map((s) => s.text ?? '').join('')).slice(0, 120)}`);
}

// ⑧ 会话收尾
await client.callTool({ name: 'close-session', arguments: { name: 'admin' } }).catch(() => {});
pumpOn = false; clearInterval(pump);
await client.close().catch(() => {});
await new Promise((r) => { host.once('exit', r); spawnSync('taskkill', ['/PID', String(host.pid), '/T', '/F'], { stdio: 'ignore' }); });
if (process.exitCode === 1) console.log(`[keep-workdir] ${work}`); else rmSync(work, { recursive: true, force: true });

console.log('=== T-19 六步链路冒烟结果 ===');
for (const r of results) console.log(r);
if (process.exitCode === 1) {
  console.log('=== host stderr（末 2000 字）===');
  console.log(hostLog.join('').slice(-2000));
}
