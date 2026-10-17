import { describe, it, expect, afterEach } from 'vitest';
import { makeConfigDir, type ConfigDir } from './helpers.js';

// K1（cutover 值域迁移）：旧键 approvalChannel 随 elicitation 通道整体移除。
// 旧配置拷到 Host 机必须在这里显式失败并附迁移指引——绝不静默映射，
// 让「以为还在审批」的配置悄悄改变语义。schema 侧 superRefine 钉死拒绝；
// 本文件钉死「拒绝 + 指引 + 新键可用 + 缺省值」四件事。

let configDir: ConfigDir | undefined;

afterEach(async () => {
  await configDir?.cleanup();
  configDir = undefined;
});

async function load(content: string) {
  configDir = await makeConfigDir('approval-surfaces-cutover-');
  const path = await configDir.write(content);
  const { loadConfig } = await import('../../../src/config/loader.js');
  return loadConfig(path);
}

describe('approvalChannel → approvalSurfaces cutover（K1）', () => {
  it('旧键 approvalChannel 显式拒绝，错误信息附迁移指引', async () => {
    await expect(load(`
[[profiles]]
name = "dev"
host = "localhost"
user = "test"

[defaults]
approvalChannel = "both"
`)).rejects.toThrow(/approvalChannel[\s\S]*approvalSurfaces[\s\S]*'both' → \['desktop','queue'\]/);
  });

  it('新键 approvalSurfaces 合法值可用', async () => {
    const config = await load(`
[[profiles]]
name = "dev"
host = "localhost"
user = "test"

[defaults]
approvalSurfaces = ["desktop", "queue"]
`);
    expect(config.defaults.approvalSurfaces).toEqual(['desktop', 'queue']);
    // 'im' 值本身合法，但要求 [im] 节与 queue 在场（T-17.6 面一致性，
    // 详见 im-section.test.ts）——此处只验值域，不含 im。
  });

  it('缺省 → ["desktop","queue"]（桌面推送 + CLI 队列兜底）', async () => {
    const config = await load(`
[[profiles]]
name = "dev"
host = "localhost"
user = "test"
`);
    expect(config.defaults.approvalSurfaces).toEqual(['desktop', 'queue']);
  });

  it('approvalSurfaces 里的未知面被 zod 枚举拒绝', async () => {
    await expect(load(`
[[profiles]]
name = "dev"
host = "localhost"
user = "test"

[defaults]
approvalSurfaces = ["sms"]
`)).rejects.toThrow(/approvalSurfaces/);
  });
});
