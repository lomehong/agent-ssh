import { getProfile as getConfigProfile, getConfigPath } from '../config/loader.js';
import { UnconfiguredError } from '../errors.js';
import type { AppConfig, Profile, ConnectionInfo } from '../types.js';
import { resolveCredentials } from '../config/credential-resolver.js';
import { SSHConnection } from './connection.js';
import type { HostKeyMode } from './host-key.js';
import type { ClientChannel } from 'ssh2';

export class ConnectionRegistry {
  private connections = new Map<string, SSHConnection>();
  private pending = new Map<string, Promise<SSHConnection>>();
  private knownHostsStore = new Map<string, string>();
  private hostKeyMode: HostKeyMode;
  private config: AppConfig;

  constructor(config: AppConfig, hostKeyMode: HostKeyMode = 'tofu') {
    this.config = config;
    this.hostKeyMode = hostKeyMode;
  }

  /** Dynamic (SOCKS) forwarding opt-in from [defaults] — read by the forward tools' preCheck. */
  isDynamicAllowed(): boolean {
    return this.config.defaults.allowDynamicForwarding;
  }

  async getOrCreate(profileName?: string): Promise<SSHConnection> {
    const profile = this.getProfile(profileName);

    const existing = this.connections.get(profile.name);
    if (existing && existing.isConnected()) {
      return existing;
    }

    const inFlight = this.pending.get(profile.name);
    if (inFlight) {
      return inFlight;
    }

    const promise = (async () => {
      try {
        let conn = this.connections.get(profile.name);

        // ProxyJump 连接跑在堡垒机上转发的通道之上。
        // 连接一旦断开，该通道即死，重连同一个 SSHConnection
        // 等于复用一具尸体、必然失败——在重试逻辑重建它之前，
        // 这曾让每次重连都白白烧掉一次工具调用。
        // 丢弃对象，让下面的代码重建这一跳。
        if (conn && profile.via && !conn.isConnected()) {
          await conn.close().catch(() => {});
          this.connections.delete(profile.name);
          conn = undefined;
        }

        if (!conn) {
          let bastionSock: ClientChannel | undefined;
          if (profile.via) {
            const bastionConn = await this.getOrCreate(profile.via);
            const bastionClient = bastionConn.getClient();
            bastionSock = await new Promise<ClientChannel>((resolve, reject) => {
              bastionClient.forwardOut('', 0, profile.host, profile.port, (err: Error | undefined, stream: ClientChannel) => {
                if (err) reject(new Error(`ProxyJump via "${profile.via}" failed: ${err.message}`));
                else resolve(stream);
              });
            });
          }
          conn = new SSHConnection(
            profile,
            await resolveCredentials(profile),
            this.knownHostsStore,
            this.hostKeyMode,
            bastionSock,
        // 裸 PTY 会话的边界来自 [defaults]（计划第 ③ 层）。
            {
              idleTimeoutMs: this.config.defaults.ptySessionIdleTimeoutMs,
              maxLifetimeMs: this.config.defaults.ptySessionMaxLifetimeMs,
              bufferBytes: this.config.defaults.ptySessionBufferBytes,
            },
            this.config.defaults.allowDynamicForwarding,
          );
          this.connections.set(profile.name, conn);
        }
        await conn.ensureConnected();
        return conn;
      } catch (err) {
        this.connections.delete(profile.name);
        throw err;
      } finally {
        this.pending.delete(profile.name);
      }
    })();

    this.pending.set(profile.name, promise);
    return promise;
  }

  get(profileName?: string): SSHConnection | undefined {
    const profile = this.getProfile(profileName);
    return this.connections.get(profile.name);
  }

  /**
    * 未配置时拒绝一切。
   *
    * 服务器如今以 `profiles: []` 启动，让目录或客户端的「添加服务器」流程
    * 能读到 `tools/list`（见 cli.ts）。状态从「可读」变为「拒绝」正是在这里，
    * 而它放在这里而不是 loader 的 `getProfile`，有一个实测原因：
    * loader 的空检查只能放在「未按名字找到 profile」分支里，于是未配置服务器上
    * 调用 `run-command` 且传 `profile: "prod"` 的客户端会得到
    * `Profile "prod" not found`——这句话告诉运维「你打错了名字」，
    * 而事实是根本没有配置，还漏掉了这次改动本要交付的配置路径。
    * 在查找之前先检查，
    * 两种情况都覆盖。
   */
  assertConfigured(): void {
    if (this.config.profiles.length === 0) throw new UnconfiguredError(getConfigPath());
  }

  getProfile(profileName?: string): Profile {
    this.assertConfigured();
    return getConfigProfile(this.config, profileName);
  }

  listConnections(): ConnectionInfo[] {
    return Array.from(this.connections.values()).map((c) => c.toInfo());
  }

  listAllProfiles(): Profile[] {
    return this.config.profiles;
  }

  reapIdleConnections(): void {
    const idleThreshold = Date.now() - this.config.defaults.connectionIdleReapMs;
    const viaTargets = new Set(
      this.config.profiles
        .map((p) => p.via)
        .filter((v): v is string => !!v),
    );
    for (const [name, conn] of this.connections) {
      if (viaTargets.has(name)) continue;
      const info = conn.toInfo();
      if (info.sessionCount === 0 && info.lastActivity && info.lastActivity.getTime() < idleThreshold) {
        conn.close().catch(() => {});
        this.connections.delete(name);
      }
    }
  }

  async closeAll(): Promise<void> {
    // 并行执行，理由同 SessionManager.closeAll：现在每个连接都要等它的会话
    // 走完信号阶梯，串行化会把这段等待按 profile 数量成倍放大。
    //
    await Promise.all([...this.connections.values()].map((conn) => conn.close().catch(() => {})));
    this.connections.clear();
  }
}
