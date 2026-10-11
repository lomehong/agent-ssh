/**
 * stub 进程入口（T-16）：MCP 宿主 spawn 的纯单向前端，stdio 传输。
 *
 * 凭据注入（D6）：AGENT_SSH_HOST_ADDR / AGENT_SSH_TOKEN / AGENT_SSH_HOST_PIN
 * 经 env；`--host-addr` 可覆盖地址（令牌禁走 argv）。
 * 缺令牌/缺地址 = OperatorError 退出（fail-fast，不猜默认）。
 */
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { OperatorError } from '../errors.js';
import { SERVER_VERSION } from '../version.js';
import { startStub } from './stub.js';

export async function stubMain(argv: string[] = process.argv.slice(2)): Promise<void> {
  const env = process.env;
  const hostAddrFlag = argv.indexOf('--host-addr');
  const hostAddr =
    (hostAddrFlag >= 0 ? argv[hostAddrFlag + 1] : undefined) ?? env.AGENT_SSH_HOST_ADDR;
  const token = process.env.AGENT_SSH_TOKEN;
  const pin = env.AGENT_SSH_HOST_PIN;

  if (!hostAddr) {
    throw new OperatorError(
      'AGENT_SSH_HOST_ADDR is required (env or --host-addr host:port). The stub dials the host daemon; without an address it refuses to start.',
    );
  }
  if (!token) {
    throw new OperatorError(
      'AGENT_SSH_TOKEN is required (env). The token never travels on argv (D6); re-run `host init` if lost.',
    );
  }

  const server = new McpServer(
    { name: 'agent-ssh', version: SERVER_VERSION },
    { capabilities: { tools: {}, resources: {} } },
  );
  const handle = await startStub({
    server,
    hostAddr,
    token,
    ...(pin ? { pin } : {}),
  });

  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error(`agent-ssh stub v${SERVER_VERSION} running on stdio (host: ${hostAddr})`);

  const shutdown = (): void => {
    void handle.close().then(() => process.exit(0));
  };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
  // stdio EOF = 宿主离开（index.ts 同款纪律）。
  process.stdin.on('end', shutdown);
  process.stdin.on('close', shutdown);
}

const isCliEnabled = process.env.SSH_MCP_DISABLE_MAIN !== '1';
if (isCliEnabled) {
  stubMain().catch((error) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exit(1);
  });
}