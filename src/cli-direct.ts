import { loadConfig, getProfile, getConfigPath } from './config/loader.js';
import { ConnectionRegistry } from './ssh/connection-registry.js';
import { AuditStore } from './audit/store.js';
import { classifyCommand, findForbiddenMatch } from './policy/classifier.js';
import { redactText } from './guard/redactor.js';
import { positionalsOf, parseArgv } from './cli.js';

/**
 * `agent-ssh run` / `agent-ssh info` — the human's direct line (agent-ssh T-09).
 *
 * The MCP tools serve the model; these subcommands serve the operator at a
 * shell. Same connection machinery, same audit log, different trust posture:
 * the person typing the command IS the approver, so there is no approval gate —
 * but the classification, the redaction and the audit record all still apply,
 * because "human at the keyboard" must remain distinguishable from "model at
 * the tool" in the log (approver: "cli-direct").
 */

function auditDir(): string {
  // Mirrors AuditStore's platform layout so direct runs land in the same log
  // the MCP server writes (imported lazily to keep this module's import graph
  // flat — see runDirectCli for the store itself).
  return process.env.AGENT_SSH_AUDIT_DIR || '';
}

export async function runDirectCli(verb: 'run' | 'info', args: string[]): Promise<number> {
  // Usage check BEFORE any config load: a malformed invocation must fail fast
  // without touching the platform config path.
  if (verb === 'run') {
    const words = positionalsOf(args).join(' ').trim();
    if (words.length === 0) {
      console.error('Usage: agent-ssh run [--profile=<name>] <command> [words...]');
      return 1;
    }
    // 禁止名单在配置加载之前生效（T-13/审计 High-1 整改）：红线优先于一切，
    // 且此处无配置可写审计——拒绝文本走 stderr 交给操作者。
    const forbidden = findForbiddenMatch(words);
    if (forbidden !== null) {
      console.error(`[cli-direct] 拒绝：命令命中禁止名单（${forbidden}）。禁止名单对人工与模型一视同仁；确需此类操作请在服务器 shell 上自行评估执行。`);
      return 1;
    }
  }
  const flags = parseArgv(args);
  const config = await loadConfig(flags.config || undefined);
  const profileName = flags.profile || undefined;
  const profile = getProfile(config, profileName);

  if (verb === 'info') {
    console.log(`profile     : ${profile.name}`);
    console.log(`host        : ${profile.user}@${profile.host}:${profile.port}`);
    console.log(`auth        : ${profile.auth}${profile.keyRef ? ` (${profile.keyRef})` : ''}`);
    console.log(`role/group  : ${profile.role} / ${profile.group ?? '(inferred)'}`);
    console.log(`deviceType  : ${profile.deviceType ?? 'generic'}`);
    console.log(`algorithms  : ${profile.algorithms ? `OVERRIDDEN (${Object.keys(profile.algorithms).join(', ')})` : 'frozen allowlist'}`);
    console.log(`approval    : ${profile.approvalPolicy}`);
    console.log(`config      : ${getConfigPath(flags.config || undefined)}`);
  }

  const registry = new ConnectionRegistry(config, 'insecure');
  const auditDirPath = auditDir() || undefined;
  const audit = new AuditStore(auditDirPath);
  void auditDirPath;

  const startedAt = Date.now();
  try {
    const conn = await registry.getOrCreate(profile.name);
    if (verb === 'info') {
      const connected = conn.isConnected();
      console.log(`connect     : ${connected ? 'OK' : 'FAILED'} (${Date.now() - startedAt}ms)`);
      console.log(`sessions    : ${conn.listSessions().length} active, ${conn.listPtySessions().length} raw-pty`);
      await conn.close();
      return connected ? 0 : 1;
    }

    // The command was validated before config load (see above).
    const command = positionalsOf(args).join(' ').trim();
    const parsed = classifyCommand(command);
    const result = await conn.exec(command);
    if (result.stdout) process.stdout.write(result.stdout + (result.stdout.endsWith('\n') ? '' : '\n'));
    if (result.stderr) process.stderr.write(result.stderr + (result.stderr.endsWith('\n') ? '' : '\n'));
    await audit.record({
      mcpRequestId: 0,
      profile: profile.name,
      user: profile.user,
      command: redactText(command),
      commandClass: parsed.class,
      binary: parsed.binary,
      decision: 'allow',
      ruleId: 'cli-direct',
      exitCode: result.exitCode,
      durationMs: result.durationMs,
      approver: 'cli-direct',
    });
    console.error(`[cli-direct] ${profile.name} exit=${result.exitCode} class=${parsed.class} ${result.durationMs}ms`);
    return result.exitCode;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    console.error(`[cli-direct] ${verb} failed on "${profile.name}": ${redactText(message)}`);
    try {
      await audit.record({
        mcpRequestId: 0,
        profile: profile.name,
        user: getSafeUser(config, profileName),
        command: redactText(verb),
        commandClass: 'safe',
        binary: `cli:${verb}`,
        decision: 'deny',
        ruleId: 'cli-direct-error',
        error: message,
      });
    } catch { /* audit must not mask the operator's error */ }
    return 1;
  }
}

function getSafeUser(config: Parameters<typeof getProfile>[0], profileName?: string): string {
  try {
    return getProfile(config, profileName).user;
  } catch {
    return '(unresolved)';
  }
}

/** Exported for tests: the verbs this module owns. */
export const DIRECT_VERBS = ['run', 'info'] as const;

export function getConfigPathForTests(): string {
  return getConfigPath();
}
