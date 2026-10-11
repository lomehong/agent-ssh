import type { CommandResult } from '../types.js';
import { redactText } from '../guard/redactor.js';

export function syntheticSuccess(profile: string): CommandResult {
  return { exitCode: 0, stdout: '', stderr: '', durationMs: 0, profile };
}

export type ToolResult = { content: { type: 'text'; text: string }[]; isError?: boolean };

export function textResult(text: string): ToolResult {
  return { content: [{ type: 'text' as const, text }] };
}

/**
 * 为客户端渲染 CommandResult。非零退出（或被信号杀死）
 * 以 `isError` 返回，附脱敏 stderr 与退出状态，
 * 使远程命令的失败不会被误读成一次空的成功。
 */
export function commandOutput(result: CommandResult) {
  // ssh2 在进程死于信号时会报告 exitCode 为 null。
  const failed = result.exitCode !== 0 || Boolean(result.signal);
  // entropyScan 与 SFTP、会话输出两条路径保持一致。没有它，一次普通的
  // `env` 转储会把高熵机密直接交给模型——
  // 因为正则层只认识固定的令牌形态。
  const stdout = redactText(result.stdout, { entropyScan: true });
  const stderr = redactText(result.stderr, { entropyScan: true });

  const parts: string[] = [];
  if (stdout) parts.push(stdout);
  if (stderr) parts.push(`[stderr]\n${stderr}`);
  if (failed) {
    parts.push(result.signal ? `[killed by SIG${result.signal}]` : `[exit ${result.exitCode}]`);
  }

  const content = [{ type: 'text' as const, text: parts.join('\n\n') }];
  return failed ? { content, isError: true } : { content };
}
