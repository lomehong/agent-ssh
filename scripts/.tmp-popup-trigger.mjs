// 触发器（fire-and-forget）：发破坏性命令入队即退——审批闭环由队列+Host 完成，
// 不依赖触发方存活（真实 Agent 场景：Agent 可断开，审批照走）。
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
const transport = new StdioClientTransport({
  command: 'node',
  args: ['E:/Development/Code/nodejs/agent-ssh/build/index.js'],
  env: {
    ...process.env,
    AGENT_SSH_HOST_ADDR: '127.0.0.1:7788',
    AGENT_SSH_TOKEN: 'jMZAYRlvBwGdzE-9th7P3vkMAPsHjLwzu50GsD1SKvk',
    SSH_MCP_DISABLE_MAIN: '1',
  },
});
const client = new Client({ name: 'popup-trigger', version: '0' });
await client.connect(transport);
await new Promise((r) => setTimeout(r, 1200));
client.callTool({ name: 'run-command', arguments: { profile: 'real', command: 'rm -rf /tmp/popup-real-dir && echo popup-real-ok' } }).catch(() => {});
await new Promise((r) => setTimeout(r, 4000)); // 留时间让入队+推送发出
await client.close().catch(() => {});
console.log('triggered and detached');
