/**
 * Host 工具清单（T-15 验收 2，方案 §2.1/§11 D3）。
 *
 * 23 工具 + 3 resources + 工具描述哈希——哈希复用 getToolHashes 纪律
 * （sha256(描述) 前 16 hex，即 --dumpToolHashes 的同一事实源），保住
 * 「manifest 变更可被宿主侧核对」的能力。单连接内 manifest 不可变（D3）：
 * 本模块是纯函数，调用方（Host 装配）在启动时构建一次并缓存。
 * 契约样本见 test/fixtures/rpc/protocol-golden.json（K6）。
 */
import { RPC_PROTOCOL_VERSION } from './protocol.js';
import { TOOL_DESCRIPTIONS, getToolHashes } from '../tools/descriptions.js';

export interface ManifestTool {
  name: string;
  description: string;
  descriptionHash: string;
  /**
   * 工具入参 JSON Schema。T-16b 起 Host 侧产出真实 schema（从工具注册面
   * 提取）；未提供时 stub 以空对象 schema 透传（tools/list 仍可见该工具）。
   */
  inputSchema?: Record<string, unknown>;
}

export interface ManifestResource {
  uri: string;
  name: string;
  description: string;
}

export interface HostToolManifest {
  protocolVersion: string;
  tools: ManifestTool[];
  resources: ManifestResource[];
}

/** Host 暴露的 3 个 MCP 资源（与 tools/resources.ts 注册面一一对应）。 */
export const RPC_RESOURCES: ManifestResource[] = [
  {
    uri: 'ssh://connections',
    name: 'connections',
    description: 'List all SSH profiles and their connection status',
  },
  {
    uri: 'ssh://connections/{profile}',
    name: 'profile',
    description: 'Get details for a specific SSH profile',
  },
  {
    uri: 'ssh://sessions/{profile}/{session}',
    name: 'session',
    description: 'Get metadata for a specific session',
  },
];

export function buildToolManifest(protocolVersion = RPC_PROTOCOL_VERSION): HostToolManifest {
  const hashes = getToolHashes();
  return {
    protocolVersion,
    tools: Object.entries(TOOL_DESCRIPTIONS).map(([name, description]) => ({
      name,
      description,
      descriptionHash: hashes[name]!,
    })),
    resources: RPC_RESOURCES,
  };
}
