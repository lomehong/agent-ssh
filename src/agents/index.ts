/**
 * 宿主接入适配器（T-21g，控制台 v2 设计 §2.6）：识别本机 Agent 宿主并
 * 结构化写入/移除 agent-ssh 的 MCP 条目。
 *
 * 七纪律：①结构化改写（JSON/TOML 解析后只 upsert `agent-ssh` 键）②写前自动
 * 备份（.bak-agent-ssh-<ts>）③条目内容自部署描述同源生成 ④幂等 ⑤写后回读
 * 校验失败即回滚 ⑥明示"重启宿主后生效" ⑦移除只删自己的键。
 *
 * 执行侧=Host TS（评审裁决）：桌面只发 RPC；避免 TS/Rust 双实现（K6）。
 */
import { existsSync, readFileSync, writeFileSync, copyFileSync, renameSync, mkdirSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, dirname } from 'node:path';

export interface HostDescriptor {
  id: 'omp' | 'claude' | 'cursor' | 'opencode' | 'codex' | 'gemini';
  name: string;
  /** 安装指纹（存在即视为已安装）。 */
  detected: boolean;
  configPath: string;
  /** 该宿主是否支持自动接入（配置格式已知且可结构化改写）。 */
  supported: boolean;
  /** 配置文件已存在且含 agent-ssh 条目。 */
  configured: boolean;
  note?: string;
}

export interface AgentDeployment {
  nodePath: string;
  hostEntry: string;
  port: number;
  token: string;
}

interface HostSpec {
  id: HostDescriptor['id'];
  name: string;
  /** 安装指纹（相对用户主目录）。 */
  fingerprints: string[];
  configPath: string;
  supported: boolean;
  note?: string;
}

const SPECS: HostSpec[] = [
  { id: 'omp', name: 'oh-my-pi (omp)', fingerprints: ['.omp', '.bun/bin/omp.exe'], configPath: '.omp/agent/mcp.json', supported: true },
  { id: 'claude', name: 'Claude Code', fingerprints: ['.claude', '.claude.json'], configPath: '.claude.json', supported: true, note: '写入全局 mcpServers 节（所有项目可用）' },
  { id: 'cursor', name: 'Cursor', fingerprints: ['.cursor'], configPath: '.cursor/mcp.json', supported: true },
  { id: 'opencode', name: 'opencode', fingerprints: ['.config/opencode'], configPath: '.config/opencode/opencode.json', supported: true, note: '键名与他家居异：mcp.{name}.command 数组合一 + environment' },
  { id: 'codex', name: 'Codex CLI', fingerprints: ['.codex'], configPath: '.codex/config.toml', supported: true, note: 'TOML 格式' },
  { id: 'gemini', name: 'Gemini CLI', fingerprints: ['.gemini'], configPath: '.gemini/settings.json', supported: true },
];

/** MCP 条目名（全部宿主统一，幂等更新的键）。 */
export const ENTRY_NAME = 'agent-ssh';

function home(): string {
  return homedir();
}

/** 部署描述（%APPDATA%\ssh-mcp\desktop.json）——条目内容单一事实源。 */
export function loadDeployment(): AgentDeployment {
  const base = process.env.APPDATA ?? join(homedir(), 'AppData', 'Roaming');
  const raw = readFileSync(join(base, 'ssh-mcp', 'desktop.json'), 'utf8');
  const v = JSON.parse(raw) as Record<string, unknown>;
  const str = (k: string): string => {
    const x = v[k];
    if (typeof x !== 'string' || x === '') throw new Error(`desktop.json missing key: ${k}`);
    return x;
  };
  const port = typeof v.port === 'number' ? v.port : Number.parseInt(String(v.port), 10);
  if (!Number.isInteger(port) || port <= 0) throw new Error('desktop.json port invalid');
  return { nodePath: str('nodePath'), hostEntry: str('hostEntry'), port, token: str('token') };
}

export function scanHosts(): HostDescriptor[] {
  const homeDir = home();
  return SPECS.map((spec) => {
    const detected = spec.fingerprints.some((f) => existsSync(join(homeDir, f)));
    const configPath = join(homeDir, spec.configPath);
    const configured = detected && spec.supported && existsSync(configPath) && hasEntry(configPath, spec.id);
    return {
      id: spec.id,
      name: spec.name,
      detected,
      configPath,
      supported: spec.supported,
      configured,
      ...(spec.note !== undefined ? { note: spec.note } : {}),
    };
  });
}

function hasEntry(configPath: string, id: HostDescriptor['id']): boolean {
  try {
    if (id === 'codex') {
      const body = readFileSync(configPath, 'utf8');
      return new RegExp(`\\[mcp_servers\\.${ENTRY_NAME}\\]`).test(body);
    }
    const json = JSON.parse(readFileSync(configPath, 'utf8')) as Record<string, unknown>;
    const root = id === 'opencode' ? (json.mcp as Record<string, unknown> | undefined) : (json.mcpServers as Record<string, unknown> | undefined);
    return root?.[ENTRY_NAME] !== undefined;
  } catch {
    return false;
  }
}

/** 条目内容（同源 desktop.json；env 形态全宿主一致，command 形态按宿主）。 */
function entryFor(id: HostDescriptor['id'], dep: AgentDeployment): Record<string, unknown> {
  const env = { AGENT_SSH_HOST_ADDR: `127.0.0.1:${dep.port}`, AGENT_SSH_TOKEN: dep.token };
  if (id === 'opencode') {
    return { type: 'local', command: [dep.nodePath, dep.hostEntry], environment: env, enabled: true };
  }
  return { command: dep.nodePath, args: [dep.hostEntry], env, enabled: true, type: 'stdio' };
}

function upsertJson(configPath: string, id: HostDescriptor['id'], entry: Record<string, unknown>, backupPath: string): void {
  const original = readFileSync(configPath, 'utf8');
  const json = original.trim() === '' ? {} : (JSON.parse(original) as Record<string, unknown>);
  if (id === 'opencode') {
    const mcp = (json.mcp as Record<string, unknown> | undefined) ?? {};
    mcp[ENTRY_NAME] = entry;
    json.mcp = mcp;
  } else {
    const servers = (json.mcpServers as Record<string, unknown> | undefined) ?? {};
    servers[ENTRY_NAME] = entry;
    json.mcpServers = servers;
  }
  writeVerified(configPath, JSON.stringify(json, null, 2) + '\n', backupPath, () => hasEntry(configPath, id), original);
}

/** Codex 的 TOML 最小结构化写：锚定插入/替换 `[mcp_servers.agent-ssh]` 块。 */
function upsertToml(configPath: string, dep: AgentDeployment, backupPath: string): void {
  const original = readFileSync(configPath, 'utf8');
  const block = [
    `[mcp_servers.${ENTRY_NAME}]`,
    `command = "${dep.nodePath}"`,
    `args = ["${dep.hostEntry}"]`,
    `env = { AGENT_SSH_HOST_ADDR = "127.0.0.1:${dep.port}", AGENT_SSH_TOKEN = "${dep.token}" }`,
    '',
  ].join('\n');
  const re = new RegExp(`\\[mcp_servers\\.${ENTRY_NAME}\\][\\s\\S]*?(?=\\n\\[|$)`);
  const body = re.test(original) ? original.replace(re, block) : `${original.replace(/\n*$/, '\n\n')}${block}`;
  writeVerified(configPath, body, backupPath, () => hasEntry(configPath, 'codex'), original);
}

/** 写 + 回读校验；失败回滚原内容（纪律⑤）。 */
function writeVerified(configPath: string, body: string, backupPath: string, verify: () => boolean, original: string): void {
  mkdirSync(dirname(configPath), { recursive: true });
  if (existsSync(configPath)) copyFileSync(configPath, backupPath);
  writeFileSync(configPath, body, 'utf8');
  if (!verify()) {
    if (existsSync(configPath)) writeFileSync(configPath, original, 'utf8');
    throw new Error(`write verification failed, rolled back (backup: ${backupPath})`);
  }
}

export interface ConfigureResult {
  configPath: string;
  backupPath: string | null;
  created: boolean;
}

/** 一键接入：upsert agent-ssh 条目（备份+校验+回滚纪律全程）。 */
export function configureHost(id: HostDescriptor['id'], dep: AgentDeployment): ConfigureResult {
  const spec = SPECS.find((s) => s.id === id);
  if (spec === undefined || !spec.supported) throw new Error(`unsupported host: ${id}`);
  const configPath = join(home(), spec.configPath);
  const backupPath = `${configPath}.bak-agent-ssh-${new Date().toISOString().replace(/[:.]/g, '-')}`;
  const created = !existsSync(configPath);
  const entry = entryFor(id, dep);
  if (id === 'codex') upsertToml(configPath, dep, backupPath);
  else upsertJson(configPath, id, entry, backupPath);
  return { configPath, backupPath: existsSync(backupPath) ? backupPath : null, created };
}

/** 移除：只删 agent-ssh 键（还原语义），其余内容不动。 */
export function removeHost(id: HostDescriptor['id']): { configPath: string; removed: boolean } {
  const spec = SPECS.find((s) => s.id === id);
  if (spec === undefined || !spec.supported) throw new Error(`unsupported host: ${id}`);
  const configPath = join(home(), spec.configPath);
  if (!existsSync(configPath)) return { configPath, removed: false };
  if (id === 'codex') {
    const body = readFileSync(configPath, 'utf8');
    const re = new RegExp(`\\n?\\[mcp_servers\\.${ENTRY_NAME}\\][\\s\\S]*?(?=\\n\\[|$)`);
    if (!re.test(body)) return { configPath, removed: false };
    writeFileSync(configPath, body.replace(re, ''), 'utf8');
    return { configPath, removed: true };
  }
  const json = JSON.parse(readFileSync(configPath, 'utf8')) as Record<string, unknown>;
  const root = (id === 'opencode' ? json.mcp : json.mcpServers) as Record<string, unknown> | undefined;
  if (root?.[ENTRY_NAME] === undefined) return { configPath, removed: false };
  delete root[ENTRY_NAME];
  writeFileSync(configPath, JSON.stringify(json, null, 2) + '\n', 'utf8');
  return { configPath, removed: true };
}

/** 测试与校验辅助：临时改名自检（renameSync 仅被测试消费）。 */
export const _internal = { renameSync };
