// T-19 残留项：Linux 真机复跑六步链路 + PTY 吞吐基线（stub → Host → 真实 SSH 目标）。
// v2 修正（首轮教训）：pty 系工具入参为 name(+cursor)，非 session/command——首轮与
// t19-smoke.mjs 均传错参数，"吞吐读数"实为校验错误文本的假测量；本轮全部调用严格
// 断言 isError 并解析 JSON 读响应的 cursor 链式读取。
// 用法：
//   T19_REAL_HOST=192.168.2.132 T19_REAL_USER=openclaw T19_REAL_PASSWORD=*** \
//   node scripts/t19-real-machine.mjs        （前置：npm run build）
import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import net from 'node:net';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { listPending, decideApproval } from '../build/guard/approval-queue.js';

const REPO = resolve(import.meta.dirname, '..');
const HOST = process.env.T19_REAL_HOST || '192.168.2.132';
const USER = process.env.T19_REAL_USER || 'openclaw';
const PASSWORD = process.env.T19_REAL_PASSWORD;
if (!PASSWORD) { console.error('need T19_REAL_PASSWORD'); process.exit(1); }
const MARK = `t19real-${Date.now().toString(36)}`;
const HOST_TOKEN = 't19-real-token-0123456789abcdef';
const results = [];
const t0run = Date.now();
const ok = (name, cond, detail = '') => { results.push(`${cond ? 'PASS' : 'FAIL'} ${name}${detail ? ` — ${detail}` : ''}`); if (!cond) process.exitCode = 1; };
const fail = (msg) => { console.error(`[abort] ${msg}`); process.exit(2); };

const work = mkdtempSync(join(process.env.USERPROFILE ?? tmpdir(), 't19-real-'));
const queueDir = join(work, 'approvals');
if (process.platform === 'win32') {
  spawnSync('icacls', [work, '/inheritance:r', '/grant:r', `${process.env.USERNAME}:(OI)(CI)F`], { stdio: 'ignore' });
}
const configPath = join(work, 'config.toml');
writeFileSync(configPath, `
[defaults]
approvalSurfaces = ["queue"]

[[profiles]]
name = "real"
host = "${HOST}"
port = 22
user = "${USER}"
auth = "password"
role = "admin"
group = "dev"
approvalPolicy = "ask-all"
`, 'utf8');

// ① Host 守护（凭证级联在 Host 侧解析）
const hostLog = [];
const host = spawn(process.execPath, [join(REPO, 'build', 'index.js'), 'host', 'serve', '--port=0', `--config=${configPath}`], {
  cwd: REPO, stdio: ['ignore', 'ignore', 'pipe'], windowsHide: true,
  env: { ...process.env, AGENT_SSH_TOKEN: HOST_TOKEN, AGENT_SSH_QUEUE_DIR: queueDir, SSH_MCP_REAL_PASSWORD: PASSWORD },
});
host.stderr.setEncoding('utf8');
host.stderr.on('data', (c) => hostLog.push(c));
const port = await new Promise((res, rej) => {
  const t = setTimeout(() => rej(new Error('host not ready')), 20_000);
  let buf = '';
  host.stderr.on('data', (c) => { buf += c; const m = /host-rpc-ready port=(\d+)/.exec(buf); if (m) { clearTimeout(t); res(Number(m[1])); } });
  host.once('exit', (c2) => { clearTimeout(t); rej(new Error(`host exited ${c2}: ${buf.slice(0, 300)}`)); });
});
ok('① host serve 就绪', true, `port=${port}`);

// ② 队列裁决泵
let pumpOn = true;
const pump = setInterval(() => {
  if (!pumpOn) return;
  void (async () => { try { for (const p of await listPending({ dir: queueDir })) await decideApproval(p.id, 'approved', { dir: queueDir, by: 't19-real' }); } catch {} })();
}, 50);

// ③ stub stdio 客户端
const transport = new StdioClientTransport({
  command: process.execPath, args: [join(REPO, 'build', 'index.js')],
  env: { ...process.env, AGENT_SSH_HOST_ADDR: `127.0.0.1:${port}`, AGENT_SSH_TOKEN: HOST_TOKEN, SSH_MCP_DISABLE_MAIN: '1' },
  stderr: 'pipe',
});
const client = new Client({ name: 't19-real', version: '0.0.0' });
await client.connect(transport);
const call = async (name, args) => {
  const r = await client.callTool({ name, arguments: args });
  const t = (r.content ?? []).map((s) => s.text ?? '').join('');
  if (r.isError) fail(`${name} isError: ${t.slice(0, 200)}`);
  return t;
};
const deadline = Date.now() + 15_000;
let tools = [];
while (Date.now() < deadline) { tools = (await client.listTools()).tools; if (tools.length === 23) break; await new Promise((r) => setTimeout(r, 100)); }
ok('① stub→Host manifest（tools=23）', tools.length === 23, `got ${tools.length}`);

// ④ 步骤一：exec
const rc = await call('read-command', { profile: 'real', command: `echo ${MARK}-exec` });
ok('② exec（read-command 真机执行）', rc.includes(`${MARK}-exec`), rc.slice(0, 100));

// ⑤ 步骤二：大输出治理
const big = await call('run-command', { profile: 'real', command: 'seq 1 200000' });
ok('③ 大输出截断（≈1MB 上限生效）', big.length > 500_000 && big.length <= 1_100_000, `chars=${big.length}`);

// ⑥ 步骤三：PTY（name+cursor 链式读取；严格断言）
const SESS = 'realsess';
await call('pty-open', { profile: 'real', name: SESS });
const readOnce = async (cursor) => {
  const t = await call('pty-read', { profile: 'real', name: SESS, cursor });
  try { const j = JSON.parse(t); return { out: String(j.output ?? ''), cursor: Number(j.cursor ?? cursor), total: j.totalBytes, dropped: j.droppedBytes }; }
  catch { return { out: t, cursor, total: undefined, dropped: undefined }; }
};
// 就绪探测：等 shell banner（真机 motd 可能数秒）
let cur = 0, ready = false;
for (let i = 0; i < 100 && !ready; i++) { const r = await readOnce(cur); if (r.out.length > 0) ready = true; cur = r.cursor; await new Promise((s) => setTimeout(s, 100)); }
ok('④ PTY 会话就绪（真机 banner 到达）', ready, ready ? '' : '10s 内无输出');
// 交互往返
const tEcho = Date.now();
await call('pty-write', { profile: 'real', name: SESS, input: `echo ${MARK}-pty\n` });
let echoMs = -1;
for (let i = 0; i < 160 && echoMs < 0; i++) { const r = await readOnce(cur); if (r.out.includes(`${MARK}-pty`)) echoMs = Date.now() - tEcho; cur = r.cursor; await new Promise((s) => setTimeout(s, 25)); }
ok('④ PTY 交互往返（真机）', echoMs >= 0, `roundTrip=${echoMs}ms`);
// 吞吐：紧循环排空（无 sleep），测真实上限
const drain = async (until, budgetMs) => {
  const t0 = Date.now();
  let chars = 0, firstMs = -1, rpcs = 0, rpcMs = 0, done = false, stall = 0, lastChars = 0, tail = '';
  while (Date.now() - t0 < budgetMs) {
    const tc = Date.now();
    const r = await readOnce(cur);
    rpcMs += Date.now() - tc; rpcs++; cur = r.cursor; chars += r.out.length; tail = (tail + r.out).slice(-400);
    if (firstMs < 0 && r.out.length > 0) firstMs = Date.now() - t0;
    if (until(tail)) { done = true; break; }
    if (chars === lastChars) { if (++stall > 40) break; } else { stall = 0; lastChars = chars; }
  }
  return { chars, wall: Date.now() - t0, firstMs, rpcs, avgRpc: rpcs ? Math.round(rpcMs / rpcs) : -1, done };
};
await call('pty-write', { profile: 'real', name: SESS, input: 'seq 1 2000\n' });
const b2 = await drain((tail) => tail.includes('1999') && tail.includes('2000'), 60_000);
ok('④ PTY 吞吐基线（2000 行排空）', b2.done && b2.chars > 7_000, `chars=${b2.chars} total=${b2.wall}ms firstByte=${b2.firstMs}ms rpc=${b2.rpcs} 次(均 ${b2.avgRpc}ms) → ≈${Math.round(b2.chars / 1024 / (b2.wall / 1000))}KB/s`);
await call('pty-write', { profile: 'real', name: SESS, input: 'seq 1 20000\n' });
const b3 = await drain((tail) => tail.includes('19999') && tail.includes('20000'), 180_000);
ok('④ PTY 持续吞吐（20000 行排空）', b3.done && b3.chars > 80_000, `chars=${b3.chars} total=${b3.wall}ms firstByte=${b3.firstMs}ms rpc=${b3.rpcs} 次(均 ${b3.avgRpc}ms) → ≈${Math.round(b3.chars / 1024 / (b3.wall / 1000))}KB/s`);
await call('pty-close', { profile: 'real', name: SESS });

// ⑦ 步骤四：SFTP 过审批 + 回读
const remoteFile = `/tmp/${MARK}.txt`;
const upContent = `${MARK}-sftp-roundtrip`;
const up = await call('sftp-upload', { profile: 'real', remotePath: remoteFile, content: upContent });
const cat = await call('read-command', { profile: 'real', command: `cat ${remoteFile}` });
ok('⑤ SFTP 过审批闭环（上传→回读一致）', cat.includes(upContent), `upload=${up.slice(0, 60)} cat=${cat.slice(0, 60)}`);
await call('run-command', { profile: 'real', command: `rm -f ${remoteFile}` });

// ⑧ 步骤五：端口转发（local：本机监听 → 经真机抵达其自身 22 口）
const listenPort = 20000 + Math.floor(Math.random() * 20000);
const fo = await call('forward-open', { profile: 'real', mode: 'local', listenHost: '127.0.0.1', listenPort, targetHost: '127.0.0.1', targetPort: 22 });
const fwdId = /Forward ([\w-]+)/.exec(fo)?.[1] ?? '';
const banner = await new Promise((res) => {
  const s = net.connect(listenPort, '127.0.0.1');
  s.setTimeout(8_000);
  let got = '';
  s.on('data', (d) => { got += d.toString(); if (got.includes('SSH-')) { s.destroy(); res(got.trim()); } });
  s.on('timeout', () => { s.destroy(); res(''); });
  s.on('error', () => res(''));
});
ok('⑥ 端口转发（隧道内取到真机 SSH banner）', banner.startsWith('SSH-2.0'), `${banner.slice(0, 50) || '(empty)'}`);
await call('forward-close', { profile: 'real', id: fwdId });
const afterClose = await new Promise((res) => {
  const s = net.connect(listenPort, '127.0.0.1');
  s.setTimeout(2_000);
  s.on('error', () => res('refused'));
  s.on('timeout', () => { s.destroy(); res('still-open'); });
  s.on('connect', () => { s.destroy(); res('still-open'); });
});
ok('⑥ 转发撤销后拒绝新连', afterClose === 'refused', afterClose);

// ⑨ 步骤六：审计核验（Host 审计落在 config 旁：${configPath}.audit.log）
await new Promise((r) => setTimeout(r, 500));
const auditBody = readFileSync(`${configPath}.audit.log`, 'utf8');
const auditHit = {
  exec: auditBody.includes(`${MARK}-exec`),
  pty: auditBody.includes(`pty:open ${SESS}`) && auditBody.includes(`pty:write ${SESS}`),
  sftp: auditBody.includes(remoteFile),
  approver: auditBody.includes('cli:t19-real'),
  callerClass: (auditBody.match(/rpcCallerClass":"agent"/g) ?? []).length,
  forward: auditBody.includes('forward:open'),
};
ok('⑦ 审计核验', auditHit.exec && auditHit.pty && auditHit.sftp && auditHit.approver && auditHit.forward && auditHit.callerClass > 0, JSON.stringify(auditHit));

// ⑩ 收尾
pumpOn = false; clearInterval(pump);
await client.close().catch(() => {});
await new Promise((r) => { host.once('exit', r); spawnSync('taskkill', ['/PID', String(host.pid), '/T', '/F'], { stdio: 'ignore' }); });
if (process.exitCode === 1) console.log(`[keep-workdir] ${work}`); else rmSync(work, { recursive: true, force: true });

console.log('=== T-19 真机复跑结果（v2）===');
for (const r of results) console.log(r);
if (process.exitCode === 1) {
  console.log('=== host stderr（末 2000 字）===');
  console.log(hostLog.join('').slice(-2000));
}
