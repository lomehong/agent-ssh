import { readFile } from 'fs/promises';
import { resolve } from 'path';
import type { Profile, ResolvedCredentials } from '../types.js';
import { OperatorError } from '../errors.js';

let keyringGet: ((service: string, account: string) => Promise<string | null>) | null = null;
let keyringSet: ((service: string, account: string, password: string) => Promise<void>) | null = null;

export function isKeychainAvailable(): boolean {
  return keyringGet !== null;
}

export async function initKeychain(): Promise<boolean> {
  try {
    // @ts-ignore —— 可选依赖，可能未安装
    const mod: any = await import('@napi-rs/keyring');
    keyringGet = async (service: string, account: string) => {
      const entry = new mod.Entry(service, account);
      return (await entry.getPassword()) || null;
    };
    keyringSet = async (service: string, account: string, password: string) => {
      const entry = new mod.Entry(service, account);
      await entry.setPassword(password);
    };
    return true;
  } catch {
    return false;
  }
}

export async function setKeychainEntry(service: string, account: string, password: string): Promise<void> {
  if (!keyringSet) throw new OperatorError('Keychain not initialized. Install @napi-rs/keyring.');
  await keyringSet(service, account, password);
}

export async function resolveCredentials(profile: Profile): Promise<ResolvedCredentials> {
  const creds: ResolvedCredentials = {};

  const envPrefix = `SSH_MCP_${profile.name.toUpperCase().replace(/[^A-Z0-9]/g, '_')}`;

  if (process.env.SSH_AUTH_SOCK && profile.auth === 'agent') {
    creds.agentSocket = process.env.SSH_AUTH_SOCK;
  }

  // 降到更弱的凭据来源时必须告警而不是静默：申请 OS 密钥链的 profile
  // 若实际拿到的是环境变量，其安全姿态已不同于运维的配置意图。
  // 这种偏离必须显式暴露给运维。
  if (profile.auth === 'keychain' && !keyringGet) {
    console.error(
      `Profile "${profile.name}" requests auth = "keychain" but @napi-rs/keyring is unavailable ` +
      '(it is an optional dependency). Falling back to the remaining credential sources.',
    );
  }

  if (profile.auth === 'keychain' && profile.keychainEntry && keyringGet) {
    try {
      const [service, account] = profile.keychainEntry.split('/');
      const secret = await keyringGet(service || 'ssh-mcp', account || profile.name);
      if (secret) {
        if (profile.keyRef) {
          creds.privateKey = secret;
        } else {
          creds.password = secret;
        }
      }
    } catch (err) {
      console.error(`Keychain lookup failed for ${profile.keychainEntry}:`, err);
    }
  }

  if (process.env[`${envPrefix}_PASSWORD`]) {
    creds.password = creds.password || process.env[`${envPrefix}_PASSWORD`];
  } else if (process.env.SSH_MCP_PASSWORD) {
    creds.password = creds.password || process.env.SSH_MCP_PASSWORD;
  }

  if (process.env[`${envPrefix}_SUDO_PASSWORD`]) {
    creds.sudoPassword = process.env[`${envPrefix}_SUDO_PASSWORD`];
  } else if (process.env.SSH_MCP_SUDO_PASSWORD) {
    creds.sudoPassword = process.env.SSH_MCP_SUDO_PASSWORD;
  }

  if (process.env[`${envPrefix}_PASSPHRASE`]) {
    creds.passphrase = process.env[`${envPrefix}_PASSPHRASE`];
  } else if (process.env.SSH_MCP_PASSPHRASE) {
    creds.passphrase = process.env.SSH_MCP_PASSPHRASE;
  }

  const keyPath = profile.keyRef || process.env[`${envPrefix}_KEY`] || process.env.SSH_MCP_KEY;
  if (keyPath && !creds.privateKey) {
    try {
      creds.privateKey = await readFile(resolve(keyPath.replace(/^~/, process.env.HOME || '~')), 'utf8');
    } catch (err: any) {
      if (err.code !== 'ENOENT') throw err;
    }
  }

  if (profile.cert && creds.privateKey) {
    const certPath = process.env[`${envPrefix}_CERT`]
      || (keyPath ? `${keyPath.replace(/\.pub$/, '')}-cert.pub` : undefined);
    if (certPath) {
      try {
        creds.certificate = await readFile(resolve(certPath.replace(/^~/, process.env.HOME || '~')), 'utf8');
      } catch (err: any) {
        if (err.code !== 'ENOENT') throw err;
      }
    }
  }

  if (!creds.password && !creds.privateKey && !creds.agentSocket) {
    // 指出 profile 申请的是哪种方式，而不是罗列全部四种——
    // 这就是「修好你选的那个」与「哪个省事选哪个」的差别，
    // 而最省事的就是环境里的明文密码。
    const asked = profile.auth;
    const why: Record<string, string> = {
      agent: 'SSH_AUTH_SOCK is unset or the agent holds no usable key',
      key: `no key was read${profile.keyRef ? ` from ${profile.keyRef}` : ' — keyRef is not set on the profile'}`,
      keychain: `the OS keychain returned nothing${profile.keychainEntry ? ` for "${profile.keychainEntry}"` : ' — keychainEntry is not set on the profile'}`,
      password: `SSH_MCP_PASSWORD and SSH_MCP_${profile.name.toUpperCase().replace(/[^A-Z0-9]/g, '_')}_PASSWORD are both unset`,
    };

    throw new OperatorError(
      `No credentials resolved for profile "${profile.name}", which asks for auth = "${asked}": ${why[asked] ?? 'nothing was found'}.\n` +
      'Fix that method rather than switching to another if you can — the fallbacks are ordered by how much ' +
      'they expose. In order: an SSH agent (nothing on disk), an encrypted key with SSH_MCP_KEY, the OS ' +
      `keychain, and last a password in SSH_MCP_PASSWORD, which is readable by every process running as you.`,
    );
  }

  return creds;
}
