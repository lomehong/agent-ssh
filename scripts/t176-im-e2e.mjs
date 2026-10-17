// T-17.6 端到端验收（可重复执行）：Host + 飞书 bot + 真机 SSH + 人工卡片决定。
// 用法：FEISHU_APP_ID/SECRET、IM_OPEN_ID、T19_REAL_PASSWORD 经 env 注入；npm run build 后运行。
// 两用例：read-only 一键批准；destructive 卡片校验码（2.0 form）批准。审计断言 approver=im:<open_id>。
// → 【人工在飞书点批准】→ 命令执行返回 → 审计核验 approver=im:<open_id>。
// 两个用例：①read-only（一键批准）②destructive（卡片校验码输入）。
import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

const REPO = resolve(import.meta.dirname, '..');
const APP_ID = process.env.FEISHU_APP_ID;
const APP_SECRET = process.env.FEISHU_APP_SECRET;
const OPEN_ID = process.env.IM_OPEN_ID;
const PASSWORD = process.env.T19_REAL_PASSWORD;
if (!APP_ID || !APP_SECRET || !OPEN_ID || !PASSWORD) { console.error('need FEISHU_APP_ID/SECRET, IM_OPEN_ID, T19_REAL_PASSWORD'); process.exit(1); }
const MARK = `ime2e-${Date.now().toString(36)}`;
const HOST_TOKEN = 'im-e2e-token-0123456789abcdef';
const results = [];
const ok = (name, cond, detail = '') => { results.push(`${cond ? 'PASS' : 'FAIL'} ${name}${detail ? ` — ${detail}` : ''}`); if (!cond) process.exitCode = 1; };

const work = mkdtempSync(join(process.env.USERPROFILE ?? tmpdir(), 'im-e2e-'));
const queueDir = join(work, 'approvals');
if (process.platform === 'win32') {
  spawnSync('icacls', [work, '/inheritance:r', '/grant:r', `${process.env.USERNAME}:(OI)(CI)F`], { stdio: 'ignore' });
}
const configPath = join(work, 'config.toml');
writeFileSync(configPath, `
[defaults]
approvalSurfaces = ["im", "queue"]

[[profiles]]
name = "real"
host = "192.168.2.132"
port = 22
user = "openclaw"
auth = "password"
role = "admin"
group = "dev"
approvalPolicy = "ask-all"

[im]
appId = "${APP_ID}"
appSecret = "${APP_SECRET}"
allowedUsers = ["${OPEN_ID}"]
`, 'utf8');

const hostLog = [];
const host = spawn(process.execPath, [join(REPO, 'build', 'index.js'), 'host', 'serve', '--port=0', `--config=${configPath}`], {
  cwd: REPO, stdio: ['ignore', 'ignore', 'pipe'], windowsHide: true,
  env: { ...process.env, AGENT_SSH_TOKEN: HOST_TOKEN, AGENT_SSH_QUEUE_DIR: queueDir, SSH_MCP_REAL_PASSWORD: PASSWORD },
});
host.stderr.setEncoding('utf8');
host.stderr.on('data', (c) => { hostLog.push(c); process.stderr.write('[host] ' + c); });
const port = await new Promise((res, rej) => {
  const t = setTimeout(() => rej(new Error('host not ready')), 20_000);
  let buf = '';
  host.stderr.on('data', (c) => { buf += c; const m = /host-rpc-ready port=(\d+)/.exec(buf); if (m) { clearTimeout(t); res(Number(m[1])); } });
  host.once('exit', (c2) => { clearTimeout(t); rej(new Error(`host exited ${c2}`)); });
});
// 等 bot 长连接建立（日志行）
await new Promise((res) => {
  const t = setTimeout(res, 15_000);
  const iv = setInterval(() => { if (hostLog.join('').includes('im bot connected')) { clearTimeout(t); clearInterval(iv); res(); } }, 200);
  setTimeout(() => clearInterval(iv), 15_000);
});
ok('① Host 起且飞书长连接建立', hostLog.join('').includes('im bot connected'), `rpc port=${port}`);

const transport = new StdioClientTransport({
  command: process.execPath, args: [join(REPO, 'build', 'index.js')],
  env: { ...process.env, AGENT_SSH_HOST_ADDR: `127.0.0.1:${port}`, AGENT_SSH_TOKEN: HOST_TOKEN, SSH_MCP_DISABLE_MAIN: '1' },
  stderr: 'pipe',
});
const client = new Client({ name: 'im-e2e', version: '0.0.0' });
await client.connect(transport);
const call = async (name, args) => {
  // SDK 版本的 Client 级 requestOptions 键不生效——按调用显式传（等人工审批，11 分钟预算）。
  const r = await client.callTool({ name, arguments: args }, undefined, { timeout: 660_000 });
  return { isError: !!r.isError, text: (r.content ?? []).map((s) => s.text ?? '').join('') };
};

// ── 用例①：read-only（卡片一键批准）──
console.log('\n>>> 用例①：卡片已发往飞书（read-only：echo）——请在飞书点【批准】');
const t1 = Date.now();
const r1 = await call('read-command', { profile: 'real', command: `echo ${MARK}-im-approved` });
ok('② read-only 经飞书卡片人工批准后执行', !r1.isError && r1.text.includes(`${MARK}-im-approved`), `${((Date.now() - t1) / 1000).toFixed(0)}s ${r1.text.slice(0, 80)}`);

// ── 用例②：destructive（卡片校验码输入）──
console.log('\n>>> 用例②：卡片已发往飞书（destructive：rm -rf 沙箱目录）——请输入卡片上的 4 位校验码后点【批准】');
const t2 = Date.now();
const r2 = await call('run-command', { profile: 'real', command: `rm -rf /tmp/${MARK}-dir && echo ${MARK}-im-destructive-ok` });
ok('③ destructive 经卡片校验码人工批准后执行', !r2.isError && r2.text.includes(`${MARK}-im-destructive-ok`), `${((Date.now() - t2) / 1000).toFixed(0)}s ${r2.text.slice(0, 80)}`);

// ── 审计核验 ──
await new Promise((r) => setTimeout(r, 500));
const auditBody = readFileSync(`${configPath}.audit.log`, 'utf8');
const imApproved = (auditBody.match(/"approver":"im:ou_[a-f0-9]+"/g) ?? []).length;
ok('④ 审计：approver=im:<open_id> ×2（两用例均经飞书面）', imApproved >= 2, `count=${imApproved}`);
ok('⑤ 审计：命令与 rpcCallerClass 留痕', auditBody.includes(`${MARK}-im-approved`) && auditBody.includes('rpcCallerClass":"agent"'));

await client.close().catch(() => {});
await new Promise((r) => { host.once('exit', r); spawnSync('taskkill', ['/PID', String(host.pid), '/T', '/F'], { stdio: 'ignore' }); });
if (process.exitCode === 1) console.log(`[keep-workdir] ${work}`); else rmSync(work, { recursive: true, force: true });
console.log('\n=== T-17.6 飞书 E2E 结果 ===');
for (const r of results) console.log(r);
