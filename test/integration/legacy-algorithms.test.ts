import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { ConnectionRegistry } from '../../src/ssh/connection-registry.js';
import { setupEnv, createAppConfig } from './fixtures.js';
import { isSshServerUp, assertAvailable, SSH_HOST } from './helpers.js';
import type { AppConfig, Profile } from '../../src/types.js';

// The network-device compatibility axis, end to end: a server that offers ONLY
// legacy algorithms (docker/legacy-sshd) must be unreachable under the frozen
// allowlist and reachable through a profile.algorithms override. This is what
// distinguishes "the override parses" from "the override actually negotiates".
//
// The same file carries the keyboard-interactive E2E: hosts that offer password
// auth only through that method must be reachable with the flag on.

const LEGACY_PORT = 2228;
const ADMIN_PORT = 2222;

let env: ReturnType<typeof setupEnv>;
let registry: ConnectionRegistry;

function legacyConfig(withOverride: boolean): AppConfig {
  const base = createAppConfig();
  const template = base.profiles.find((p) => p.name === 'admin')!;
  const legacy: Profile = {
    ...template,
    name: 'legacy-switch',
    host: SSH_HOST,
    port: LEGACY_PORT,
    user: 'legacyuser',
    deviceType: 'huawei',
    keyboardInteractive: false,
    ...(withOverride
      ? {
          algorithms: {
            kex: { append: ['diffie-hellman-group1-sha1'] },
            cipher: { append: ['aes128-cbc', '3des-cbc'] },
            serverHostKey: { append: ['ssh-rsa'] },
            hmac: { append: ['hmac-sha1'] },
          },
        }
      : {}),
  };
  return { ...base, profiles: [...base.profiles, legacy] };
}

const legacyUp = isSshServerUp(SSH_HOST, LEGACY_PORT)
  .then((up) => assertAvailable(up, `legacy sshd (${SSH_HOST}:${LEGACY_PORT})`));

beforeAll(async () => {
  env = setupEnv();
  process.env.SSH_MCP_LEGACY_SWITCH_PASSWORD = 'legacypass';
});

afterAll(async () => {
  await registry?.closeAll();
  env?.restore();
});

describe.skipIf(!(await legacyUp))('legacy algorithm negotiation (network-device axis)', () => {
  it('refuses to negotiate under the frozen allowlist', async () => {
    const r = new ConnectionRegistry(legacyConfig(false), 'insecure');
    await expect(r.getOrCreate('legacy-switch')).rejects.toThrow(/SSH connection/);
    await r.closeAll();
  }, 30000);

  it('connects through a profile.algorithms override and runs a command', async () => {
    registry = new ConnectionRegistry(legacyConfig(true), 'insecure');
    const conn = await registry.getOrCreate('legacy-switch');
    const result = await conn.exec('whoami');
    expect(result.exitCode).toBe(0);
    expect(result.stdout.trim()).toBe('legacyuser');
  }, 30000);

  it('reaches an admin host with keyboard-interactive answering enabled', async () => {
    process.env.SSH_MCP_KI_ADMIN_PASSWORD = 'secret';
    const base = createAppConfig();
    const template = base.profiles.find((p) => p.name === 'admin')!;
    const ki: Profile = {
      ...template,
      name: 'ki-admin',
      host: SSH_HOST,
      port: ADMIN_PORT,
      user: 'admin',
      auth: 'password',
      keyboardInteractive: true,
    };
    const r = new ConnectionRegistry({ ...base, profiles: [ki] }, 'insecure');
    const conn = await r.getOrCreate('ki-admin');
    const result = await conn.exec('whoami');
    expect(result.exitCode).toBe(0);
    expect(result.stdout.trim()).toBe('admin');
    await r.closeAll();
  }, 30000);
});
