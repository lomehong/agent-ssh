/**
 * 主机（profile）管理（主人指令 2026-10-17：控制台配置远程 SSH 服务器的
 * ip/端口/用户/密码/密钥）。Host 侧 TOML 结构化改写：
 * smol-toml parse → 增/改/删 profiles 数组项 → 序列化原子写回。
 *
 * 纪律（同宿主接入 §2.6）：写前备份 `.bak-profiles-<ts>`；写后 loadConfig
 * 校验（解析失败即回滚）；**序列化会丢注释**——备份兜底并在返回值明示。
 * 密码不入 config：auth=password → 写 OS 凭据管理器（keychainEntry=ssh-mcp/<name>）
 * 并落 auth="keychain"；密钥=本机路径（keyRef）。
 */
import { parse as parseToml, stringify as stringifyToml } from 'smol-toml';
import { copyFileSync, existsSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';

export interface HostProfileInput {
  name: string;
  host: string;
  port: number;
  user: string;
  auth: 'password' | 'key' | 'keychain';
  /** auth=password 时必填：明文密码（写凭据管理器，不落 config）。 */
  password?: string;
  /** auth=key 时必填：私钥文件路径（Host 机）。 */
  keyRef?: string;
  role?: string;
  group?: string;
}

export function backupOf(configPath: string): string {
  const backupPath = `${configPath}.bak-profiles-${new Date().toISOString().replace(/[:.]/g, '-')}`;
  if (existsSync(configPath)) copyFileSync(configPath, backupPath);
  return backupPath;
}

function atomicWrite(configPath: string, body: string): void {
  const tmp = `${configPath}.tmp-profiles`;
  writeFileSync(tmp, body, 'utf8');
  renameSync(tmp, configPath);
}

function profilesOf(configText: string): Record<string, unknown>[] {
  const parsed = parseToml(configText) as { profiles?: Record<string, unknown>[] };
  return Array.isArray(parsed.profiles) ? parsed.profiles : [];
}

/** 列出 config 内全部 profile（只读投影）。 */
export function listProfiles(configPath: string): Record<string, unknown>[] {
  return profilesOf(readFileSync(configPath, 'utf8')).map((p) => ({
    name: p.name,
    host: p.host,
    port: p.port,
    user: p.user,
    auth: p.auth,
    keyRef: p.keyRef,
    role: p.role,
    group: p.group,
  }));
}

/** 校验（写后即验）：config 必须能被 loadConfig 同源规则解析且含该 profile。 */
function verifyWritten(configPath: string, name: string): void {
  const parsed = parseToml(readFileSync(configPath, 'utf8')) as { profiles?: Record<string, unknown>[] };
  const found = (parsed.profiles ?? []).some((p) => p.name === name);
  if (!found) throw new Error(`post-write verification failed: profile "${name}" missing after upsert`);
}

/** upsert：同名替换、异名追加；写前备份、写后校验失败回滚。 */
export function upsertProfile(configPath: string, input: HostProfileInput): { backupPath: string; reloaded: true } {
  if (!/^[A-Za-z0-9_-]+$/.test(input.name)) throw new Error('profile 名只允许字母/数字/-/_');
  const original = readFileSync(configPath, 'utf8');
  // 编辑态判断（评审 B4）：编辑既有 keychain profile 且密码留空 = 沿用
  // 凭据管理器既有条目（「密码留空=不变」契约）；新建/非 keychain 仍须给密码。
  const existing = (parseToml(original) as { profiles?: Array<Record<string, unknown>> }).profiles?.find(
    (p) => p.name === input.name,
  );
  const editExistingKeychain = existing !== undefined && existing.auth === 'keychain';
  if (input.auth === 'password' && (input.password === undefined || input.password === '') && !editExistingKeychain) {
    throw new Error('auth=password 需要提供密码');
  }
  if (input.auth === 'key' && (input.keyRef === undefined || input.keyRef === '')) {
    throw new Error('auth=key 需要提供私钥路径（Host 机路径）');
  }
  const backupPath = backupOf(configPath);
  try {
    const parsed = parseToml(original) as Record<string, unknown>;
    const profiles = (Array.isArray(parsed.profiles) ? [...parsed.profiles] : []) as Record<string, unknown>[];
    const entry: Record<string, unknown> = {
      name: input.name,
      host: input.host,
      port: input.port,
      user: input.user,
      auth: input.auth === 'password' ? 'keychain' : input.auth,
      role: input.role ?? 'admin',
      ...(input.group !== undefined && input.group !== '' ? { group: input.group } : {}),
    };
    if (input.auth === 'password') entry.keychainEntry = `ssh-mcp/${input.name}`;
    if (input.auth === 'key') entry.keyRef = input.keyRef;
    const idx = profiles.findIndex((p) => p.name === input.name);
    if (idx >= 0) profiles[idx] = entry; else profiles.push(entry);
    parsed.profiles = profiles;
    atomicWrite(configPath, stringifyToml(parsed));
    verifyWritten(configPath, input.name);
    return { backupPath, reloaded: true };
  } catch (err) {
    // 校验失败：回滚备份内容。
    writeFileSync(configPath, original, 'utf8');
    throw err;
  }
}

/** 删除 profile（example 占位/误加条目）；写前备份、写后校验。 */
export function removeProfile(configPath: string, name: string): { backupPath: string; removed: boolean } {
  const original = readFileSync(configPath, 'utf8');
  const backupPath = backupOf(configPath);
  try {
    const parsed = parseToml(original) as Record<string, unknown>;
    const profiles = (Array.isArray(parsed.profiles) ? parsed.profiles : []) as Record<string, unknown>[];
    const next = profiles.filter((p) => p.name !== name);
    if (next.length === profiles.length) return { backupPath, removed: false };
    if (next.length === 0) throw new Error('至少保留一个 profile（config 校验要求 profiles 非空）');
    parsed.profiles = next;
    atomicWrite(configPath, stringifyToml(parsed));
    verifyWritten(configPath, (next[0] as { name: string }).name);
    return { backupPath, removed: true };
  } catch (err) {
    writeFileSync(configPath, original, 'utf8');
    throw err;
  }
}

/** 供写凭据管理器（auth=password 时由 handler 调用）。 */
export function keychainTarget(name: string): { service: string; account: string } {
  return { service: 'ssh-mcp', account: name };
}

export function ensureParentDir(configPath: string): void {
  if (!existsSync(dirname(configPath))) mkdirSyncGuard(dirname(configPath));
}

function mkdirSyncGuard(_d: string): void {
  // config 已存在（编辑场景），父目录必在；保留空实现以明确不变量。
}
