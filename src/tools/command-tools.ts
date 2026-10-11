import { z } from 'zod';
import { shellSingleQuote } from '../guard/sanitizer.js';
import { TOOL_DESCRIPTIONS as D } from './descriptions.js';
import { commandOutput, textResult } from './results.js';
import { PolicyRefusedError, type ToolDeps, type Pipeline } from './pipeline.js';
import type { CommandResult } from '../types.js';

/** 在远程主机上执行命令的工具。 */
export function registerCommandTools(
  { server, registry, policy }: ToolDeps,
  pipeline: Pipeline,
) {
  const { runAudited, execAndReport, defaultProfileName } = pipeline;

  // ─── read-command ──────────────────────────────────────────────────────
  server.tool(
    'read-command',
    D["read-command"],
    {
      command: z.string().describe('Read-only shell command (must be in the allowlist)'),
      profile: z.string().optional().describe('Profile name'),
    },
    { readOnlyHint: true },
    async ({ command, profile }, extra) => {
      return runAudited(
        command,
        { toolName: 'read-command', failureClass: 'read-only', enforceClass: 'read-only', profile, extra },
        execAndReport(),
      );
    },
  );

  // ─── run-command ───────────────────────────────────────────────────────
  server.tool(
    'run-command',
    D["run-command"],
    {
      command: z.string().describe('Shell command to execute'),
      profile: z.string().optional().describe('Profile name'),
      session: z.string().optional().describe('Run in an existing interactive session (stateful)'),
      tty: z.boolean().optional().describe('Allocate a pseudo-terminal'),
    },
    { destructiveHint: true },
    async ({ command, profile, session, tty }, extra) => {
      return runAudited(
        command,
        { toolName: 'run-command', failureClass: 'safe', profile, session, extra },
        async (rt) => {
          // 会话运行会保留调用方的 shell 状态；普通 exec 不会。
          let audited: CommandResult;
          if (session) {
            const sess = rt.conn.getSession(session);
            if (!sess) throw new Error(`Session "${session}" not found`);
            audited = await sess.run(rt.command, undefined, rt.abortSignal);
          } else {
            audited = await rt.conn.exec(rt.command, {
              tty, onProgress: rt.onProgress, abortSignal: rt.abortSignal,
            });
          }
          return { audited, output: commandOutput(audited) };
        },
      );
    },
  );

  // ─── privileged-command ────────────────────────────────────────────────
  server.tool(
    'privileged-command',
    D["privileged-command"],
    {
      command: z.string().describe('Command to execute with sudo'),
      profile: z.string().optional().describe('Profile name'),
    },
    { destructiveHint: true },
    async ({ command, profile }, extra) => {
      return runAudited(
        command,
        {
          toolName: 'privileged-command',
          failureClass: 'privileged',
          profile,
          extra,
          // 也要对裸命令本身做评估：否则 sudo 包装器
          // 会把被禁命令藏进带引号的 `sh -c` 参数里。
          preCheck: (cleanCmd) => {
            // 在这里解析而不是在 `runAudited` 之前：`defaultProfileName` 会触达
            // `registry.getProfile()`——它在未配置的服务器上会拒绝；若在管线
            // 的 try 之外，该拒绝会逃逸且不留审计记录。`preCheck`
            // 在其内部运行。
            const rawEval = policy.evaluate(
              cleanCmd,
              registry.getProfile(defaultProfileName(profile)),
            );
            if (rawEval.decision === 'deny') {
              throw new PolicyRefusedError(
                `POLICY_DENIED: ${rawEval.reason || 'Command not allowed'}`,
                rawEval,
              );
            }
          },
          wrap: (cleanCmd) => `sudo -p "" -S sh -c ${shellSingleQuote(cleanCmd)}`,
        },
        (rt) => {
          const sudoPassword = rt.conn.getSudoPassword();
          return execAndReport({ stdin: sudoPassword ? sudoPassword + '\n' : undefined })(rt);
        },
      );
    },
  );

  // ─── signal-process ────────────────────────────────────────────────────
  server.tool(
    'signal-process',
    D["signal-process"],
    {
      pid: z.number().int().min(1).describe('Process ID to signal (positive integer)'),
      signal: z.enum(['INT', 'TERM', 'KILL']).default('TERM').describe('Signal to send'),
      profile: z.string().optional().describe('Profile name'),
    },
    { destructiveHint: true },
    async ({ pid, signal, profile }, extra) => {
      return runAudited(
        `kill -${signal} ${pid}`,
        { toolName: 'signal-process', failureClass: 'destructive', profile, extra, synthetic: true },
        async (rt) => {
          const { audited, output } = await execAndReport()(rt);
          // `kill` 成功时是静默的——因此要确认已发送的信号，
          // 而不是返回空结果。
          const silentSuccess = !output.isError && !audited.stdout.trim() && !audited.stderr.trim();
          return {
            audited,
            output: silentSuccess ? textResult(`Signal ${signal} sent to PID ${pid}`) : output,
          };
        },
      );
    },
  );
}
