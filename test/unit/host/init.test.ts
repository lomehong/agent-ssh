import { describe, expect, it } from 'vitest';
import { buildHostInitArtifacts } from '../../../src/host/init.js';

// D15 后 init 不再产出口令哈希（单令牌模型：主人 2026-10-17 裁决）——
// 本套件钉住「令牌仍 ≥256bit、骨架可加载、无口令残留」的新契约。
describe('host init 生成器（T-15 验收 6；D15 后无口令产物）', () => {
  it('agent 令牌 ≥256bit（43 字符 base64url）', () => {
    const a = buildHostInitArtifacts();
    expect(a.agentToken).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it('D15：不再产出 operator 口令哈希（单令牌模型，口令已取消）', () => {
    const a = buildHostInitArtifacts();
    expect(a.operatorHash).toBe('');
    expect(a.configToml).not.toMatch(/operatorPasswordHash/);
  });

  it('骨架 TOML 不含令牌明文（落盘最小化，评审 jc2），键面走新契约', () => {
    const a = buildHostInitArtifacts({ agentToken: 'A'.repeat(43) });
    expect(a.configToml).not.toContain('A'.repeat(43));
    expect(a.configToml).toContain('approvalSurfaces = ["desktop", "queue"]');
    expect(a.configToml).toContain('init 打印一次');
    expect(a.configToml).not.toContain('approvalChannel');
  });

  it('两次生成：令牌互异（防重放），骨架确定性（不含任何随机秘密）', () => {
    const a = buildHostInitArtifacts();
    const b = buildHostInitArtifacts();
    expect(a.agentToken).not.toBe(b.agentToken);
    // 落盘最小化：骨架不含令牌/哈希 → 恒等（确定性），秘密只走 stdout 一次。
    expect(a.configToml).toBe(b.configToml);
  });
});
