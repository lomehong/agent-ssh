import { describe, expect, it } from 'vitest';
import { verifyPassword } from '../../../src/rpc/auth.js';
import { buildHostInitArtifacts } from '../../../src/host/init.js';

describe('host init 生成器（T-15 验收 6，方案 §6 五步引导的核心）', () => {
  it('agent 令牌 ≥256bit（43 字符 base64url）', () => {
    const a = buildHostInitArtifacts();
    expect(a.agentToken).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it('口令哈希可被 verifyPassword 正确校验、错误口令拒绝', () => {
    const a = buildHostInitArtifacts();
    expect(verifyPassword('correct horse', a.operatorHash)).toBe(true);
    expect(verifyPassword('wrong', a.operatorHash)).toBe(false);
  });

  it('骨架 TOML 内嵌哈希但不含令牌明文（落盘最小化，评审 jc2），键面走新契约', () => {
    const a = buildHostInitArtifacts({ agentToken: 'A'.repeat(43) });
    expect(a.configToml).not.toContain('A'.repeat(43));
    expect(a.configToml).toContain('approvalSurfaces = ["desktop", "queue"]');
    expect(a.configToml).toContain('init 打印一次');
    expect(a.configToml).not.toContain('approvalChannel');
  });

  it('同口令两次生成：盐不同哈希不同（防彩虹表），骨架随哈希变化', () => {
    const a = buildHostInitArtifacts();
    const b = buildHostInitArtifacts();
    expect(a.operatorHash).not.toBe(b.operatorHash);
    expect(a.configToml).not.toBe(b.configToml);
  });
});
