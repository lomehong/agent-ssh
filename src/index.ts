#!/usr/bin/env node

/**
 * agent-ssh 入口（T-18a 入口切换后的薄分发器，方案 §6）：
 * - `agent-ssh approvals …` / `run` / `info`：operator 面，经 RPC 连 Host（src/cli-rpc.ts）；
 * - `agent-ssh host serve|init`：Host 守护与初始化（src/host/main.ts+cli.ts）；
 * - 默认（无子命令）：MCP stub 前端——纯单向 stdio，连 Host 守护（src/stub/main.ts）。
 *
 * 旧 stdio 直连引擎与 HTTP 传输已废止（T-15/T-18a）：等价资产在
 * src/host/main.ts（startHost 继承回收器与停机梯）。
 * --transport=http 显式报错而非静默回落（评审 H5/T-15 登记）。
 */

import { OperatorError, reportFatal } from './errors.js';

async function main(): Promise<void> {
  const positionals = process.argv.slice(2).filter((a) => !a.startsWith('-'));
  const argv = Object.fromEntries(
    process.argv.slice(2)
      .filter((a) => a.startsWith('--'))
      .map((a) => {
        const eq = a.indexOf('=');
        return eq === -1 ? [a.slice(2), null] : [a.slice(2, eq), a.slice(eq + 1)];
      }),
  ) as Record<string, string | null>;

  if (positionals[0] === 'approvals') {
    const { runApprovalsCli } = await import('./cli-rpc.js');
    process.exit(await runApprovalsCli(process.argv.slice(2)));
  }
  if (positionals[0] === 'run' || positionals[0] === 'info') {
    const { runDirectCli } = await import('./cli-rpc.js');
    process.exit(await runDirectCli(positionals[0] as 'run' | 'info', process.argv.slice(3)));
  }
  if (positionals[0] === 'host') {
    const { runHostCli } = await import('./host/cli.js');
    process.exit(await runHostCli(process.argv.slice(3)));
  }
  if (argv.transport === 'http') {
    // T-15/T-18a：HTTP 传输整体废止——显式报错而非静默回落。
    throw new OperatorError(
      '--transport=http was removed: the HTTP transport is abolished in the Host 分离架构 (v2). ' +
      'Run the MCP frontend on stdio (default) and start `agent-ssh host serve` for the credential-holding daemon.',
    );
  }

  // 默认：MCP stub 前端（纯单向 stdio）。需要 Host 守护在场：
  //   agent-ssh host serve   （凭证守护，另机/另窗常驻）
  // 窗口期语义见 src/stub/stub.ts（零工具诚实态，绝不本地降级）。
  const { stubMain } = await import('./stub/main.js');
  await stubMain(process.argv.slice(2));
}

main().catch((error) => {
  process.exit(reportFatal(error));
});
