import { readFile, stat } from 'fs/promises';
import { homedir, platform } from 'os';
import { join, dirname } from 'path';
import { parse as parseTOML } from 'smol-toml';
import { configSchema, type RawConfig } from './schema.js';
import { OperatorError, ConfigNotFoundError, UnconfiguredError } from '../errors.js';
import { assertPrivateOnWindows, type AclOptions } from './windows-acl.js';
import type { AppConfig, Profile, Defaults } from '../types.js';

export function getConfigPath(customPath?: string): string {
  if (customPath) return customPath;

  const home = homedir();
  const p = platform();

  if (p === 'darwin') {
    return join(home, 'Library', 'Application Support', 'ssh-mcp', 'config.toml');
  }
  if (p === 'win32') {
    return join(process.env.APPDATA || join(home, 'AppData', 'Roaming'), 'ssh-mcp', 'config.toml');
  }
  const xdgConfig = process.env.XDG_CONFIG_HOME || join(home, '.config');
  return join(xdgConfig, 'ssh-mcp', 'config.toml');
}

/**
 * 检查除属主之外无人能触及配置文件——它保存着决定本服务器将运行什么
 * 的主机、角色与策略规则。
 *
 * 两个平台的答案刻意不同。POSIX 一律拒绝：「仅属主可及」在那里
 * 没有歧义，`chmod` 一行可修。Windows 拒绝可被其他账户*修改*的配置、
 * 报告只能被*读*的配置，因为读暴露正是该平台真正含糊之处——
 * 见 windows-acl.ts 的 `waived`。
 *
 * 模式位是 POSIX 的答案，在 Windows 上毫无意义——这就是 #138 的全部：
 * Node 在那里为每个可读文件合成 `0o666`，于是 `& 0o077` 无条件非零，
 * 史上所有 Windows 配置一律被拒。它开出的 `chmod 600` 也解除不了——
 * Windows 11 实测：`chmod(path, 0o600)` 之后模式仍是 `0o666`，
 * 因为那里的 `fs.chmod` 只拨只读位。一字不差照做，
 * 运维回到原点。
 * they started.
 */
export async function checkPermissions(filePath: string, opts: AclOptions = {}): Promise<void> {
  return platform() === 'win32'
    ? assertPrivateOnWindows(filePath, opts)
    : checkPosixMode(filePath);
}

/**
 * 单独拆出，让它自己的拒绝不会回流进那条容忍 ENOENT 的 `catch`。
 * 它们此前能幸免，只是因为 OperatorError 不带 `.code`——
 * 这是巧合，不是设计。
 */
async function checkPosixMode(filePath: string): Promise<void> {
  const dir = dirname(filePath);
  const modeOf = async (path: string): Promise<number | null> => {
    try {
      return (await stat(path)).mode & 0o777;
    } catch (err: any) {
      if (err.code === 'ENOENT') return null;
      throw err;
    }
  };

  // 先测文件、后 stat 目录——与 main 原来的顺序一致：先批量 stat 两个，
  // 会让一个 0644 的文件在目录中途消失时走 ENOENT 分支而被放行。
  // vanished in between took the ENOENT path and was accepted.
  const fileMode = await modeOf(filePath);
  if (fileMode === null) return;

  if (fileMode & 0o077) {
    throw new OperatorError(
      `Config file ${filePath} is group/world accessible (mode ${fileMode.toString(8)}). ` +
      `Required: 0600. Run: chmod 600 ${filePath}`,
    );
  }
  const dirMode = await modeOf(dir);
  if (dirMode !== null && dirMode & 0o077) {
    throw new OperatorError(
      `Config directory ${dir} is group/world accessible (mode ${dirMode.toString(8)}). ` +
      `Required: 0700. Run: chmod 700 ${dir}\n` +
      // 官方 Docker 镜像以 0755 创建该目录，于是把配置 bind-mount 到
      // 默认路径的容器每次启动都会撞上它，而且无法对镜像里烘焙的
      // 路径做 chmod。
      'If the directory is not yours to change — a container image, or a mount point — ' +
      'bind-mount a 0700 directory over it, or point --config at one you control.',
    );
  }
}

export async function loadConfig(customPath?: string, opts: AclOptions = {}): Promise<AppConfig> {
  const configPath = getConfigPath(customPath);

  let raw: string;
  try {
    raw = await readFile(configPath, 'utf8');
  } catch (err: any) {
    // 对显式指向空处的 --config 也一样。它过去以原始系统错误逃逸
    // （"ENOENT: no such file or directory, open ..."），
    // 意思一样，词汇却是系统调用的。
    if (err.code === 'ENOENT') throw new ConfigNotFoundError(configPath);
    // 这里其余一切仍是运维的文件——被当作 --config 传入的目录、
    // 拒绝读取的 mode 或 ACL、消失的挂载。它们过去同样裸奔，
    // `reportFatal` 带着我们自己的帧的堆栈打印它们：
    // 正是这次改动要移除的呈现方式。
    // `.code` 被保留的理由与 ConfigNotFoundError 相同：有包装脚本靠它
    // 区分「不可读，重新挂载再试」与「不存在，去装一遍」，
    // 一条分支保留、相邻分支丢弃，是只执行了一半的规则。
    // the adjacent one is a half-applied rule.
    throw Object.assign(
      new OperatorError(`Config file ${configPath} could not be read: ${err.message}`),
      { code: err.code, cause: err },
    );
  }

  await checkPermissions(configPath, opts);

  let parsed: unknown;
  try {
    parsed = parseTOML(raw);
  } catch (err: any) {
    throw new OperatorError(`Failed to parse TOML config at ${configPath}: ${err.message}`);
  }

  const result = configSchema.safeParse(parsed);
  if (!result.success) {
    // 根级问题的 path 为空，过去会渲染成一个光秃秃的冒号。
    // 根 schema 来者不拒时不可达；如今未知的顶层节会走到这里。
    // top-level section reaches it now.
    const issues = result.error.issues
      .map((i) => `  ${i.path.length ? i.path.join('.') : '(root)'}: ${i.message}`)
      .join('\n');
    throw new OperatorError(`Config validation error:\n${issues}`);
  }

  return normalizeConfig(result.data);
}

/**
 * `0` 表示不限制——本配置文件里 `commandQuotaPerDay` 与
 * `approvalGrantTtlMs` 已有的约定。
 *
 * 它必须被*映射*而不只是被允许。`sanitizeCommand` 测的是
 * `cleaned.length > maxChars`，一个字面 `0` 到那里会以
 * "Command is too long (max 0 characters)" 拒绝一切非空命令——
 * 比这个写法本要修掉的问题更糟。
 *
 * MAX_SAFE_INTEGER 是 `parseMaxChars` 对 `--maxChars=none` 的产物，
 * 这样标志与配置文件交给后续代码的就是同一个 Profile，
 * 而不是「不设限」的两种拼法（#123）。
 */
function uncapZero(maxChars: number): number {
  return maxChars === 0 ? Number.MAX_SAFE_INTEGER : maxChars;
}

/**
 * 让每个 profile 对照 [defaults] 解析。这些键每一个都被文档写明
 * 是 profile 继承的默认值，因此全部必须级联——一个被 schema
 * 接受却从不生效的键，是在无声地无视运维的配置
 * （一个永不生效的 `approvalMode` 是安全降级，
 * 不只是小划伤）。
 */
function normalizeConfig(raw: RawConfig): AppConfig {
  // commandMaxChars 在这里和下面的 profile 上都要映射，让 `0`
  // 在 AppConfig 的任何角落都不存活。把原始值留在 `defaults` 上，
  // 等于让一个对象携带「不限制」的两种编码——`profile.maxChars`
  // 是 MAX_SAFE_INTEGER，`defaults.commandMaxChars` 是 0——
  // 而类型系统不提供任何区分。buildAppConfig 的快速启动路径
  // 恰好直接照抄（`maxChars: defaults.commandMaxChars`），
  // 其正确仅仅因为那条路径的值来自从不返回 0 的 parseMaxChars。
  // 靠另一个表面的巧合才正确，
  // 在错误编码会拒绝一切非空命令的情况下，
  // 不是该留着的性质。
  const defaults: Defaults = {
    ...raw.defaults,
    commandMaxChars: uncapZero(raw.defaults.commandMaxChars),
  };

  const profiles: Profile[] = raw.profiles.map((p) => ({
    ...p,
    timeout: p.timeout ?? defaults.commandTimeoutMs,
    maxChars: uncapZero(p.maxChars ?? defaults.commandMaxChars),
    maxOutputBytes: p.maxOutputBytes ?? defaults.commandMaxOutputBytes,
    approvalPolicy: p.approvalPolicy ?? defaults.approvalMode,
    sessionMaxPerConnection: p.sessionMaxPerConnection ?? defaults.sessionMaxPerConnection,
    sessionIdleTimeoutMs: p.sessionIdleTimeoutMs ?? defaults.sessionIdleTimeoutMs,
    sessionBackgroundMaxMs: p.sessionBackgroundMaxMs ?? defaults.sessionBackgroundMaxMs,
    commandQuotaPerDay: p.commandQuotaPerDay ?? defaults.commandQuotaPerDay,
    transferMaxBytes: p.transferMaxBytes ?? defaults.transferMaxBytes,
    transferTimeoutMs: p.transferTimeoutMs ?? defaults.transferTimeoutMs,
  }));

  // 原样透传。对 DEFAULT_RULES 的分层由 mergePolicyRules() 负责，
  // loader 自己不带任何可能出错的策略语义。
  // wrong.
  const overrideWarning = algorithmsOverrideWarning(profiles);
  if (overrideWarning) console.error(overrideWarning);
  // 审批面一致性（T-17.6）：'im' 面要求 [im] 节与 'queue' 兜底在场——
  // 队列是唯一等待机制（bot 的决定也写队列文件），无 queue 的 im 是
  // 「schema 接受但永远等待超时」的形态；含 im 而无凭证同理。启动期
  // 拒绝，不静默降级。
  const surfaces = defaults.approvalSurfaces;
  if (surfaces.includes('im')) {
    if (raw.im === undefined) {
      throw new Error('Config error: approvalSurfaces includes "im" but no [im] section (appId/appSecret/allowedUsers) is configured.');
    }
    if (!surfaces.includes('queue')) {
      throw new Error('Config error: approvalSurfaces includes "im" without "queue" — the queue is the only wait mechanism (im decides write queue files); add "queue".');
    }
  }
  return {
    defaults,
    profiles,
    policy: raw.policy,
    ...(raw.im !== undefined ? { im: raw.im } : {}),
    ...(raw.http !== undefined ? { http: raw.http } : {}),
  };
}

/**
 * 对放宽 FROZEN_ALGORITHMS 的 profile 的加载时通告。
 *
 * 导出为纯函数，消息无需子进程即可断言。放宽白名单就是
 * 降低传输下限：运维必须在启动时看到它——按 profile、
 * 列明涉及的类别——而不是从一次不合预期的协商失败里发现它。
 * negotiate the way they expected.
 */
export function algorithmsOverrideWarning(profiles: Profile[]): string | null {
  const overridden = profiles.filter((p) => p.algorithms !== undefined);
  if (overridden.length === 0) return null;
  const described = overridden
    .map((p) => `${p.name} [${Object.keys(p.algorithms!).join(', ')}]`)
    .join(', ');
  return (
    `Warning: ${overridden.length} profile(s) override the frozen algorithm allowlist: ${described}. ` +
    `Legacy algorithms lower the transport security floor; keep the override scoped to the hosts that need it. ` +
    `Commands on these profiles are marked algorithmsOverride=true in the audit log.`
  );
}

export function getProfile(config: AppConfig, name?: string): Profile {
  const targetName = name || config.defaults.defaultProfile;
  if (!targetName) {
    // 回落到 profiles[0] 意味着：配置了多台主机而未选默认时，
    // 不带 profile 参数的命令会打到恰好排在第一台的主机上——
    // 无声无息，而排第一的往往是生产。一个 profile 没有歧义；
    // 多于一个就是调用方必须回答的问题。
    // unambiguous; more than one is a question the caller has to answer.
    if (config.profiles.length > 1) {
      const names = config.profiles.map((p) => p.name).join(', ');
      throw new OperatorError(
        `No profile selected and no default configured, but ${config.profiles.length} profiles exist: ${names}. ` +
        `Pass a "profile" argument, or set defaults.defaultProfile in the config.`,
      );
    }
    // 防御性：查找助手不得交回被标成 `Profile` 的 `undefined`——
    // 空列表上的 `profiles[0]` 过去正是如此——那会在下游某处变成
    // TypeError，而不是这里的一句解释。这是不变量，不是产品规则。
    // 「未配置的服务器拒绝干活」的决定在 `ConnectionRegistry`，
    // 它同时守着本分支和下面的按名分支；走到这一行说明
    // 有调用方绕过了 registry。
    if (config.profiles.length === 0) throw new UnconfiguredError(getConfigPath());
    return config.profiles[0];
  }
  const profile = config.profiles.find((p) => p.name === targetName);
  if (!profile) throw new OperatorError(`Profile "${targetName}" not found`);
  return profile;
}
