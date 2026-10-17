/**
 * `agent-ssh host` 子命令（T-18a）：serve=守护常驻；init=初始化向导。
 *
 * serve：loadConfig → startHost（引擎+RPC 面+pidfile/日志接线）→ 常驻；
 *        stdin EOF 不退出（守护语义，区别于 stub）。pidfile 单实例强制。
 * init：buildHostInitArtifacts → 写配置骨架（存在则拒）+ stderr 打印
 *       agent 令牌（一次，提示经 env 注入 stub，D6）。
 */
import { existsSync, writeFileSync } from 'node:fs';
import { loadConfig, getConfigPath } from '../config/loader.js';
import { buildHostInitArtifacts } from './init.js';
import { startHost } from './main.js';
import { acquirePidfile } from '../rpc/pidfile.js';

function pidfilePath(): string {
  // 与审批队列同域（agent-ssh 命名空间）；T-17.5b pidfile.ts 的调用方。
  const base = process.env.AGENT_SSH_PID_DIR
    ?? (process.platform === 'win32'
      ? `${process.env.LOCALAPPDATA ?? process.env.APPDATA}\\agent-ssh`
      : `${process.env.HOME ?? '/tmp'}/.agent-ssh`);
  return `${base}\\host.pid`.replaceAll('\\', '/');
}

export async function runHostCli(args: string[]): Promise<number> {
  const verb = args[0] ?? 'serve';

  if (verb === 'init') {
    const configPath = getConfigPath();
    if (existsSync(configPath)) {
      console.error(`[host-init] 配置已存在（${configPath}）——拒绝覆盖。手工迁移或删除后重试。`);
      return 1;
    }
    const artifacts = buildHostInitArtifacts();
    writeFileSync(configPath, artifacts.configToml, { flag: 'wx' });
    console.error(`[host-init] 配置骨架已写入 ${configPath}`);
    console.error(`[host-init] AGENT_SSH_TOKEN=${artifacts.agentToken}`);
    console.error('[host-init] ↑ 令牌仅此一次打印——经 env 注入 stub（D6 禁 argv），丢失请重跑 init 轮换。');
    console.error('[host-init] 下一步：agent-ssh host serve 启动守护。');
    return 0;
  }

  if (verb === 'serve') {
        // 旗标解析（approvals 文法同源：只接受 --x=v 等号形式）。
    // 评审 T-18b 教训：indexOf('--config') 是精确匹配，等号形式永远 -1——
    // 须按前缀解析；前缀须含 --（初版两连错：精确匹配+漏 -- 前缀）。
    const flagValue = (name: string): string | undefined => {
      const entry = args.find((a) => a.startsWith(`--${name}=`));
      return entry === undefined ? undefined : entry.slice(name.length + 3);
    };
    const portRaw = flagValue('port');
    const portArg = portRaw !== undefined ? Number(portRaw) : 0;
    if (!Number.isInteger(portArg) || portArg < 0 || portArg > 65_535) {
      console.error('[host-serve] invalid --port');
      return 1;
    }
    const configPath = flagValue('config') ?? getConfigPath();
    if (!existsSync(configPath)) {
      console.error(`[host-serve] 配置不存在（${configPath}）——先运行 agent-ssh host init。`);
      return 1;
    }
    const config = await loadConfig(configPath);
    const pid = acquirePidfile(pidfilePath());
    const host = await startHost({
      config,
      agentToken: process.env.AGENT_SSH_TOKEN ?? '',
      auditPath: `${configPath}.audit.log`,
      configFilePath: configPath,
      port: portArg,
      ...(process.env.AGENT_SSH_QUEUE_DIR ? { approvalQueueDir: process.env.AGENT_SSH_QUEUE_DIR } : {}),
    });
    console.error(`host-rpc-ready port=${host.port} (pidfile ${pidfilePath()})`);
    // 守护语义：stdin EOF 不退出；SIGTERM/SIGINT → stop（停机梯在 startHost 内）。
    const shutdown = (): void => {
      void host.stop().then(() => {
        pid.release();
        process.exit(0);
      });
    };
    process.on('SIGTERM', shutdown);
    process.on('SIGINT', shutdown);
    // 常驻：保持事件循环（RPC 任务的读循环保活）。
    await new Promise<never>(() => {});
    return 0;
  }

  console.error('Usage: agent-ssh host serve | agent-ssh host init');
  return 1;
}
