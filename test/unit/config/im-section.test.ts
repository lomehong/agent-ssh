import { describe, it, expect, afterEach } from 'vitest';
import { makeConfigDir, type ConfigDir } from './helpers.js';

// [im] 节与审批面一致性（T-17.6）：im 面要求 [im] 配置与 queue 兜底在场；
// operatorPasswordHash（init 产物键）随本票补入 schema——此前 init 生成的
// 配置会被 strict 校验拒载，serve 链路对 init 产物根本走不通（顺手修复）。

let configDir: ConfigDir | undefined;

afterEach(async () => {
  await configDir?.cleanup();
  configDir = undefined;
});

async function load(content: string) {
  configDir = await makeConfigDir('im-section-');
  const path = await configDir.write(content);
  const { loadConfig } = await import('../../../src/config/loader.js');
  return loadConfig(path);
}

const PROFILES = `
[[profiles]]
name = "dev"
host = "localhost"
user = "test"
`;

describe('[im] 节与面一致性（T-17.6）', () => {
  it('surfaces 含 im 而 [im] 缺席 → 启动期拒绝（不静默降级）', async () => {
    await expect(load(`
[defaults]
approvalSurfaces = ["im", "queue"]
${PROFILES}
`)).rejects.toThrow(/no \[im\] section/);
  });

  it('surfaces 含 im 而无 queue → 拒绝（队列是唯一等待机制）', async () => {
    await expect(load(`
[defaults]
approvalSurfaces = ["im"]
${PROFILES}

[im]
appId = "cli_x"
appSecret = "s"
allowedUsers = ["ou_me"]
`)).rejects.toThrow(/without "queue"/);
  });

  it('[im] 完整配置可用，值透传', async () => {
    const config = await load(`
[defaults]
approvalSurfaces = ["im", "queue"]
${PROFILES}

[im]
appId = "cli_test"
appSecret = "sec"
allowedUsers = ["ou_a", "ou_b"]
chatId = "oc_g"
commandDetail = "truncated"
`);
    expect(config.im).toMatchObject({
      appId: 'cli_test',
      appSecret: 'sec',
      allowedUsers: ['ou_a', 'ou_b'],
      chatId: 'oc_g',
      commandDetail: 'truncated',
    });
  });

  it('[im] 缺必填键被 strict 拒绝', async () => {
    await expect(load(`
${PROFILES}

[im]
appId = "cli_test"
`)).rejects.toThrow();
  });

  it('operatorPasswordHash（init 产物键）现在可加载并透传（顺手修复验证）', async () => {
    const config = await load(`
[defaults]
operatorPasswordHash = "salt:abc"
approvalSurfaces = ["queue"]
${PROFILES}
`);
    expect(config.defaults.operatorPasswordHash).toBe('salt:abc');
  });

  it('im 节缺席 = IM 面未部署（合法常态）', async () => {
    const config = await load(`
[defaults]
approvalSurfaces = ["desktop", "queue"]
${PROFILES}
`);
    expect(config.im).toBeUndefined();
  });
});
