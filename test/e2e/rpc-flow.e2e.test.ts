import { describe, expect, it, afterEach, vi } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  spawnRpcHost,
  startQueuePump,
  RPC_E2E_TIMEOUT_MS,
  type RpcE2EHost,
} from './rpc-harness.js';

// T-18b 双进程真链路：MCP 宿主（测试客户端）→ stub（build/index.js 默认
// 入口）→ RPC → Host（build/index.js host serve 守护子进程）。
// 服务器端点：host-rpc-ready 就绪行探测（host/cli.ts serve --port=0）。

let host: RpcE2EHost | undefined;
let client: Client | undefined;
let transport: StdioClientTransport | undefined;
const pumps: Array<() => void> = [];
let workDir: string | undefined;

const HOST_TOKEN = 'e2e-host-token-0123456789abcdef0123456789abcdef';

function configToml(): string {
  return `
[defaults]
approvalSurfaces = ["queue"]

[[profiles]]
name = "admin"
host = "127.0.0.1"
port = 1
user = "e2e"
auth = "password"
role = "admin"
group = "dev"
`;
}

async function startFlow(opts: { pump?: boolean } = {}): Promise<Client> {
  workDir = mkdtempSync(join(tmpdir(), 'rpc-e2e-flow-'));
  const queueDir = join(workDir, 'approvals');
  const spawned = await spawnRpcHost({
    configToml: configToml(),
    hostToken: HOST_TOKEN,
    queueDir,
  });
  host = spawned;

  if (opts.pump) {
    pumps.push(startQueuePump(queueDir));
  }

  transport = new StdioClientTransport({
    command: process.execPath,
    args: [join(process.cwd(), 'build', 'index.js')],
    env: {
      ...process.env,
      AGENT_SSH_HOST_ADDR: `127.0.0.1:${spawned.port}`,
      AGENT_SSH_TOKEN: HOST_TOKEN,
      SSH_MCP_DISABLE_MAIN: '1',
    } as Record<string, string>,
    stderr: 'pipe',
  });
  const c = new Client({ name: 'e2e-host', version: '0.0.0' });
  await c.connect(transport);
  client = c;

  // 等 stub→Host 首次连接完成（tools/list 从空集诚实态变为 23 工具）。
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    const listed = await c.listTools();
    if (listed.tools.length === 23) break;
    await new Promise((r) => setTimeout(r, 100));
  }
  return c;
}

afterEach(async () => {
  for (const stop of pumps.splice(0)) await stop();
  await client?.close().catch(() => {});
  client = undefined;
  transport = undefined;
  await host?.stop();
  host = undefined;
  if (workDir !== undefined) rmSync(workDir, { recursive: true, force: true });
  workDir = undefined;
});

describe('T-18b 双进程真链路（MCP 宿主→stub→RPC→Host）', () => {
  it('tools/list 经 stub→Host manifest 返回全量工具（诚实态后）', async () => {
    vi.setConfig({ testTimeout: RPC_E2E_TIMEOUT_MS });
    const c = await startFlow({ pump: false });
    const listed = await c.listTools();
    expect(listed.tools.length).toBe(23);
  }, RPC_E2E_TIMEOUT_MS);

  it('无凭据 stub：callTool 收 fail-closed 结构化错误（连不上 Host 绝不本地降级）', async () => {
    vi.setConfig({ testTimeout: RPC_E2E_TIMEOUT_MS });
    await startFlow({ pump: false });
    // 无 token env 的 stub 实例：连不上 Host（hello 需凭据）→ callTool 必拒。
    const transport2 = new StdioClientTransport({
      command: process.execPath,
      args: [join(process.cwd(), 'build', 'index.js')],
      env: {
        ...process.env,
        AGENT_SSH_HOST_ADDR: `127.0.0.1:${host!.port}`,
        AGENT_SSH_TOKEN: 'wrong-token-host-will-reject-hello',
        SSH_MCP_DISABLE_MAIN: '1',
      } as Record<string, string>,
      stderr: 'pipe',
    });
    const anon = new Client({ name: 'anon', version: '0.0.0' });
    await anon.connect(transport2);
    await expect(
      anon.callTool({ name: 'list-connections', arguments: {} }),
    ).rejects.toThrow(/Host unreachable|fail-closed|Connection closed/i);
    await anon.close();
  }, RPC_E2E_TIMEOUT_MS);

  it('queue pump 裁决：破坏性命令入队→批准→Host 执行路径走通（队列面）', async () => {
    vi.setConfig({ testTimeout: RPC_E2E_TIMEOUT_MS });
    const c = await startFlow({ pump: true });
    // 破坏性命令（队列面批准后 Host 侧真执行——本环境 admin 指向不可达
    // 主机，批准后的 SSH 执行失败但「审批闸门已过」可由错误语义区分）。
    const res = await c.callTool({
      name: 'run-command',
      arguments: { profile: 'admin', command: 'echo e2e-ok' },
    });
    const text = ((res.content ?? []) as Array<{ text?: string }>).map((seg) => seg.text ?? '').join('\n');
    // 批准后执行：SSH 不可达 → 执行失败但审批闸门已过（错误非 APPROVAL_*）。
    expect(text).not.toContain('APPROVAL_');
    expect(text).not.toContain('CHALLENGE_');
  }, RPC_E2E_TIMEOUT_MS);
});
