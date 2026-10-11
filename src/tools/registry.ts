import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { ConnectionRegistry } from '../ssh/connection-registry.js';
import type { PolicyEngine } from '../policy/engine.js';
import type { AuditStore } from '../audit/store.js';
import { createPipeline, type ToolDeps } from './pipeline.js';
import { registerSessionTools } from './session-tools.js';
import { registerCommandTools } from './command-tools.js';
import { registerFileTools } from './file-tools.js';
import { registerTransferTools } from './transfer-tools.js';
import { registerPtyTools } from './pty-tools.js';
import { registerForwardTools } from './forward-tools.js';

// 重新导出，让既有引用方对工具层保持单一入口。
export { TOOL_DESCRIPTIONS, getToolHashes } from './descriptions.js';
export { registerResources } from './resources.js';

/**
 * 把全部 MCP 工具装配到服务器上。
 *
 * handler 按主题分为四组（会话、命令、文本式
 * 文件传输、流式文件传输），共用一条经审计的管线——在这里构建。
 * 正是这种拆分保证了管线是
 * 「调用方输入 → 远程命令」的唯一通路：想绕过策略或审计的 handler，
 * 必须越过 `pipeline` 去够 registry，
 * 而它并没有被给予 registry。
 */
export function registerTools(
  server: McpServer,
  registry: ConnectionRegistry,
  policy: PolicyEngine,
  audit: AuditStore,
  opts: Omit<ToolDeps, 'server' | 'registry' | 'policy' | 'audit'> = {},
) {
  const deps: ToolDeps = { server, registry, policy, audit, ...opts };
  const pipeline = createPipeline(deps);

  registerSessionTools(deps, pipeline);
  registerCommandTools(deps, pipeline);
  registerFileTools(deps, pipeline);
  registerTransferTools(deps, pipeline);
  registerPtyTools(deps, pipeline);
  registerForwardTools(deps, pipeline);
}
