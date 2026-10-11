import { describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import { TOOL_DESCRIPTIONS, getToolHashes } from '../../../src/tools/descriptions.js';
import { RPC_PROTOCOL_VERSION } from '../../../src/rpc/protocol.js';
import { RPC_RESOURCES, buildToolManifest } from '../../../src/rpc/manifest.js';

describe('Host 工具清单（T-15 验收 2，D3 描述哈希）', () => {
  it('23 个工具，与 TOOL_DESCRIPTIONS 一一对应且哈希同源', () => {
    const manifest = buildToolManifest();
    expect(manifest.tools).toHaveLength(23);
    const hashes = getToolHashes();
    for (const tool of manifest.tools) {
      expect(TOOL_DESCRIPTIONS[tool.name]).toBe(tool.description);
      expect(tool.descriptionHash).toBe(hashes[tool.name]);
      // 哈希可独立复核：sha256(描述) 前 16 hex
      expect(tool.descriptionHash).toBe(
        createHash('sha256').update(tool.description).digest('hex').slice(0, 16),
      );
    }
  });

  it('3 个 resources 与 tools/resources.ts 注册面一一对应', () => {
    const manifest = buildToolManifest();
    expect(manifest.resources).toEqual([
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
    ]);
    expect(RPC_RESOURCES).toHaveLength(3);
  });

  it('携带协议版本且生成是确定性的（单连接内不可变，D3）', () => {
    const a = buildToolManifest();
    const b = buildToolManifest();
    expect(a.protocolVersion).toBe(RPC_PROTOCOL_VERSION);
    expect(JSON.stringify(a)).toBe(JSON.stringify(b));
  });
});
