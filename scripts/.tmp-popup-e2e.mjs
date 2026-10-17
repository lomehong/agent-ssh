// 桌面弹窗实测辅助：经 stub 发破坏性命令（触发审批推送），等待人工在
// 独立弹窗中决定。用法：T19_REAL_PASSWORD=*** node scripts/.tmp-popup-e2e.mjs
import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { listPending, decideApproval } from '../build/guard/approval-queue.js';

const REPO = resolve(import.meta.dirname, '..');
const work = mkdtempSync(join(process.env.USERPROFILE ?? tmpdir(), 'popup-e2e-'));
const queueDir = join(work, 'approvals');
if (process.platform === 'win32') {
  spawnSync('icacls', [work, '/inheritance:r', '/grant:r', `${process.env.USERNAME}:(OI)(CI)F`], { stdio: 'ignore' });
}
const configPath = join(work, 'config.toml');
writeFileSync(configPath, `
[defaults]
approvalSurfaces = ["desktop", "queue"]

[[profiles]]
name = "real"
host = "192.168.2.132"
port = 22
user = "openclaw"
auth = "keychain"
keychainEntry = "ssh-mcp/real"
role = "admin"
group = "dev"
approvalPolicy = "ask-all"
`, 'utf8');

const host = spawn(process.execPath, [join(REPO, 'build', 'index.js'), 'host', 'serve', '--port=0', `--config=${configPath}`], {
  cwd: REPO, stdio: ['ignore', 'ignore', 'pipe'], windowsHide: true,
  env: { ...process.env, AGENT_SSH_TOKEN: 'popup-e2e-token-0123456789abcdef', AGENT_SSH_QUEUE_DIR: queueDir },
});
const port = await new Promise((res, rej) => {
  const t = setTimeout(() => rej(new Error('host not ready')), 20_000);
  let buf = '';
  host.stderr.on('data', (c) => { buf += c; const m = /host-rpc-ready port=(\d+)/.exec(buf); if (m) { clearTimeout(t); res(Number(m[1])); } });
});

const transport = new StdioClientTransport({
  command: process.execPath, args: [join(REPO, 'build', 'index.js')],
  env: { ...process.env, AGENT_SSH_HOST_ADDR: `127.0.0.1:${port}`, AGENT_SSH_TOKEN: 'popup-e2e-token-0123456789abcdef', SSH_MCP_DISABLE_MAIN: '1' },
  stderr: 'pipe',
});
const client = new Client({ name: 'popup-e2e', version: '0' });
await client.connect(transport);
console.log('>>> 发破坏性命令（触发审批推送）——请在桌面弹窗/主窗审批卡中处理');
const t0 = Date.now();
const r = await client.callTool({ name: 'run-command', arguments: { profile: 'real', command: 'rm -rf /tmp/popup-e2e-dir && echo popup-e2e-ok' } }, undefined, { timeout: 300_000 });
const text = (r.content ?? []).map((x) => x.text ?? '').join('');
console.log('RESULT:', r.isError ? 'ERR ' + text.slice(0, 120) : text.slice(0, 120), `(${((Date.now() - t0) / 1000).toFixed(0)}s)`);
await client.close().catch(() => {});
await new Promise((r) => { host.once('exit', r); spawnSync('taskkill', ['/PID', String(host.pid), '/T', '/F'], { stdio: 'ignore' }); });
rmSync(work, { recursive: true, force: true });
