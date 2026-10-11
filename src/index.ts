#!/usr/bin/env node

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { reportFatal, OperatorError } from './errors.js';
import { ConnectionRegistry } from './ssh/connection-registry.js';
import { PolicyEngine, resolvePolicyRules } from './policy/engine.js';
import { AuditStore } from './audit/store.js';
import { registerTools, registerResources, getToolHashes } from './tools/registry.js';
import { transferForbiddenDirs } from './tools/forbidden-dirs.js';
import { initKeychain } from './config/credential-resolver.js';
import { getConfigPath } from './config/loader.js';
import { SERVER_VERSION } from './version.js';
import {
  parseArgv,
  buildAppConfig,
  checkRemovedFlags,
  flagEnabled,
  parseOpaUrl,
  parseOpaTimeout,
  resolveHostKeyMode,
} from './cli.js';

async function main() {
  const argv = parseArgv();
  checkRemovedFlags(argv);

  // approvals CLI 是子命令而非标志面：它与服务器启动路径
  // 毫无共享（无配置、无密钥链、无传输），运行它绝不能
  // 起一个会把 shell 吊死的 stdio 服务器。
  const positionals = process.argv.slice(2).filter((a) => !a.startsWith('--'));
  if (positionals[0] === 'approvals') {
    const { runApprovalsCli } = await import('./cli.js');
    process.exit(await runApprovalsCli(process.argv.slice(2)));
  }
  if (positionals[0] === 'run' || positionals[0] === 'info') {
    const { runDirectCli } = await import('./cli-direct.js');
    process.exit(await runDirectCli(positionals[0] as 'run' | 'info', process.argv.slice(3)));
  }

  if (argv.dumpToolHashes !== undefined) {
    console.log(JSON.stringify(getToolHashes(), null, 2));
    return;
  }

  const config = await buildAppConfig(argv);
  const hostKeyMode = resolveHostKeyMode(argv);
  const entropyScan = flagEnabled(argv, 'auditEntropyScan');
  const tamperEvident = flagEnabled(argv, 'auditTamperEvident');

  await initKeychain();

  if (argv.otelEndpoint) {
    const { initTracing } = await import('./observability/tracer.js');
    await initTracing(argv.otelEndpoint as string, (argv.otelServiceName as string) || 'ssh-mcp');
  }

  // 传输根大门所需的、且不许它自己去够的一切：
  // 实际加载了哪个配置文件，以及哪些目录是禁区。
  const localPath = {
    transferRoot: config.defaults.transferRoot,
    configPath: getConfigPath(argv.config || undefined),
    forbidden: transferForbiddenDirs(),
  };

  const registry = new ConnectionRegistry(config, hostKeyMode);
  const policy = new PolicyEngine(resolvePolicyRules(config.profiles, config.policy));
  const audit = new AuditStore(undefined, entropyScan, tamperEvident);

  if ('opaUrl' in argv) {
    // 要的是「存在」而不是真值——这正是 `flagEnabled` 当初要防的坑。
    // 空格分隔的 `--opaUrl http://…` 会存成 null，旧守卫于是把它
    // 静默丢弃，连运维要的 `--opaFailClosed` 一起丢。
    policy.setOpaUrl(
      parseOpaUrl(argv.opaUrl),
      flagEnabled(argv, 'opaFailClosed'),
      parseOpaTimeout(argv.opaTimeoutMs),
    );
    console.error(`OPA sidecar enabled: ${argv.opaUrl}`);
  } else if (flagEnabled(argv, 'opaFailClosed')) {
    throw new OperatorError('--opaFailClosed does nothing without --opaUrl.');
  }

  // 一个 McpServer 只能绑一个传输，HTTP 需要每会话一个。
  const createMcpServer = (): McpServer => {
    // SDK 1.30 里 capabilities 从 serverInfo 挪到了 ServerOptions。
    const server = new McpServer(
      { name: 'SSH MCP Server', version: SERVER_VERSION },
      { capabilities: { tools: {}, resources: {} } },
    );
    registerTools(server, registry, policy, audit, {
      approvalGrantTtlMs: config.defaults.approvalGrantTtlMs,
      approvalSurfaces: config.defaults.approvalSurfaces,
      localPath,
    });
    registerResources(server, registry);
    return server;
  };

  const transportMode = argv.transport || 'stdio';

  if (transportMode === 'http') {
    // T-15（Host 分离架构 v2）：HTTP 传输整体废止——凭证与信任域分离后，
    // Agent 侧不再有持凭证的长驻服务可暴露。审批走 Host 的 RPC 审批面
    // （方案 §2.2/§6）；此处显式报错而非静默落到 stdio，避免运维以旧旗标
    // 得到意料外的传输形态。旗标清理随 T-18a。
    throw new OperatorError(
      '--transport=http was removed: the HTTP transport is abolished in the Host 分离架构 (v2). ' +
      'Run the MCP frontend on stdio (default) and start `agent-ssh host` for the credential-holding daemon.',
    );
  }

  {
    const transport = new StdioServerTransport();
    await createMcpServer().connect(transport);
    console.error('SSH MCP Server v2 running on stdio');
  }

  const reaperInterval = setInterval(() => {
    // 会话回收先于连接回收被 await，这个顺序承重：
    // 现在关闭后台会话会信号其命令，而 `reapIdleConnections` 以
    // `sessionCount` 为门，会话一关它就归零。若不 await 就发射，
    // 连接会在第一个信号后微秒级被拆，
    // TERM 与 KILL 两级被丢——对 INT 无视的命令就这样
    // 活过了自己的回收。
    void (async () => {
      const conns = registry.listConnections()
        .map((info) => registry.get(info.profile))
        .filter((c): c is NonNullable<typeof c> => Boolean(c));
      await Promise.all(conns.map((conn) => conn.reapExpiredSessions().catch(() => {})));
      registry.reapIdleConnections();
    })();
  }, 60_000);

  /**
    * 拆除在进程无视一切退出之前，还有多久。
   *
    * 一条 kill 阶梯（3 秒）加余量。会话与连接并发关闭，所以这是
    * 总预算而非按会话的预算。Docker 默认停止宽限 10 秒、Kubernetes
    * 30 秒，本值稳稳落在两者之内——重点是放弃时机由我们选，
    * 而不是中途被 SIGKILL。
   */
  const SHUTDOWN_BUDGET_MS = 5000;

  let isShuttingDown = false;
  const cleanup = async () => {
    if (isShuttingDown) return;
    isShuttingDown = true;
    console.error('Shutting down SSH MCP Server...');
    clearInterval(reaperInterval);
    // 先冲审计。本注释的早期版本声称会话拆除会写出被旧顺序丢弃的
    // 审计记录——并非如此：src/ssh/ 下没有任何东西碰审计存储，
    // 只有 `close-session` 工具会，而那条记录在工具调用内已写出并 await。
    // 所以这次重排什么也没救回来，反而把最终冲刷放到了一个如今要等
    // kill 阶梯的拆除后面。先冲刷不会丢拆除不写的记录，
    // 还能在宽限期末尾的 SIGKILL 下幸存。
    try { await audit.close(); } catch (e) { console.error('audit.close failed:', e); }
    // 有界，让 `process.exit(0)` 是被刻意到达的，而不是被容器运行时
    // 的 SIGKILL 打断。拆除现在并发进行，诚实的上限是一条 kill
    // 阶梯加余量，而非每会话一条。
    try {
      await Promise.race([
        registry.closeAll(),
        new Promise((resolve) => setTimeout(resolve, SHUTDOWN_BUDGET_MS).unref()),
      ]);
    } catch (e) { console.error('closeAll failed:', e); }
    process.exit(0);
  };

  if (transportMode !== 'http') {
    // SDK 的 stdio 传输只监听 'data' 和 'error'，客户端不发信号就退出时，
    // 本进程会带着打开的 SSH 连接继续活着。把 stdin 的 EOF 视作
    // 客户端离开。
    const onStdinClosed = () => { void cleanup(); };
    process.stdin.on('end', onStdinClosed);
    process.stdin.on('close', onStdinClosed);
  }

  process.on('SIGINT', cleanup);
  process.on('SIGTERM', cleanup);
}

const isTestMode = process.env.SSH_MCP_TEST === '1';
const isCliEnabled = process.env.SSH_MCP_DISABLE_MAIN !== '1';

if (isCliEnabled || isTestMode) {
  main().catch((error) => {
    process.exit(reportFatal(error));
  });
}
