import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { registerTools, registerResources } from '../../../src/tools/registry.js';
import { PolicyEngine, DEFAULT_RULES, type PolicyRules } from '../../../src/policy/engine.js';
import { AuditStore } from '../../../src/audit/store.js';
import type { CommandResult, Profile } from '../../../src/types.js';
import type { CloseOutcome } from '../../../src/ssh/session.js';
import { ConnectionRegistry } from '../../../src/ssh/connection-registry.js';
import { defaultsFromArgv } from '../../../src/cli.js';
import type { ToolDeps } from '../../../src/tools/pipeline.js';
import { listPending, decideApproval } from '../../../src/guard/approval-queue.js';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

type ToolOpts = Omit<ToolDeps, 'server' | 'registry' | 'policy' | 'audit'>;

/**
 * In-process MCP client + server over InMemoryTransport, with the SSH layer
 * stubbed. The point is the handler layer — enforceClass, the approval gate,
 * output redaction, exit-status reporting and audit records — which is where
 * every per-request security decision lives and which had no tests at all.
 */

export const testProfile: Profile = {
  name: 'dev',
  group: 'dev',
  host: 'stub',
  port: 22,
  user: 'tester',
  auth: 'password',
  tty: false,
  keyboardInteractive: false,
  timeout: 5000,
  maxChars: 5000,
  maxOutputBytes: 1_048_576,
  role: 'admin',
  readOnly: false,
  announceAgent: true,
  approvalPolicy: 'ask-destructive',
  cert: false,
  sessionMaxPerConnection: 5,
  sessionIdleTimeoutMs: 60_000,
  sessionBackgroundMaxMs: 3_600_000,
  commandQuotaPerDay: 0,
  transferMaxBytes: 268_435_456, transferTimeoutMs: 300_000,
};

export interface ExecCall {
  command: string;
  stdin?: string;
}

export interface Harness {
  client: Client;
  execCalls: ExecCall[];
  auditRecords: any[];
  ptyWrites: Array<{ name: string; input: string }>;
  /** What the stubbed exec returns; override per test. */
  setExecResult(result: Partial<CommandResult>): void;
  /** Whether the client approves elicitation prompts. */
  setApproval(approve: boolean): void;
  /** How many times the client was actually prompted. elicitation 移除后恒 0（墓碑计数）。 */
  approvalPrompts(): number;
  /** 队列面已作出的裁决数（自动裁决泵）—— elicitation 时代的 prompt 计数的等价观测量。 */
  approvalDecisions(): number;
  /**
   * What `closeSession` reports; override per test.
   *
   * Configurable because the stub used to return `void`, so `outcome === 'unsignalled'` was
   * never true and the branch that warns the caller a stop was not dispatched was dead in
   * every unit test — including the ones written to cover it.
   */
  setCloseOutcome(outcome: CloseOutcome): void;
  close(): Promise<void>;
}

export async function createHarness(
  overrides: Partial<Profile> = {},
  toolOpts: ToolOpts = {},
  rules: PolicyRules = DEFAULT_RULES,
): Promise<Harness> {
  const profile: Profile = { ...testProfile, ...overrides };
  const execCalls: ExecCall[] = [];
  const auditRecords: any[] = [];
  let approve = true;
  let closeOutcome: CloseOutcome = 'closed';
  let approvalPrompts = 0;
  let approvalDecisions = 0;
  let execResult: Partial<CommandResult> = {};

  const makeResult = (command: string): CommandResult => ({
    stdout: `stdout for ${command}`,
    stderr: '',
    exitCode: 0,
    durationMs: 1,
    profile: profile.name,
    ...execResult,
  });

  const sessions = new Map<string, any>();

  const conn: any = {
    profile,
    async exec(command: string, opts: any = {}) {
      execCalls.push({ command, stdin: opts.stdin });
      return makeResult(command);
    },
    getSudoPassword: () => 'sudo-secret',
    getSession: (name: string) => sessions.get(name),
    // Matches SSHConnection.listSessions(): Session objects, not SessionInfo —
    // the handler calls toInfo() itself.
    listSessions: () => [...sessions.values()],
    async openSession({ name, type }: any) {
      const session = {
        toInfo: () => ({ id: name, name, profile: profile.name, type, status: 'active', createdAt: new Date(), lastActivity: new Date(), ttlMs: 1000 }),
        run: async (command: string) => { execCalls.push({ command }); return makeResult(command); },
        readOutput: () => 'session output line',
      };
      sessions.set(name, session);
      return session;
    },
    async closeSession(name: string): Promise<CloseOutcome> {
      sessions.delete(name);
      return closeOutcome;
    },
    // Raw-PTY stubs (agent-ssh): pty-write's audit/alert path needs a session
    // to write to; inputs are recorded for assertions.
    ptyWrites: [] as Array<{ name: string; input: string }>,
    openPtySession: async ({ name }: any) => ({
      name, profile: profile.name, createdAt: new Date(), lastActivity: new Date(),
      closed: false, cursor: 0, totalBytes: 0, droppedBytes: 0, transcriptBytes: 0, transcriptFrozen: false,
    }),
    writePtySession(name: string, input: string) {
      (conn as any).ptyWrites.push({ name, input });
      return { delivered: true, note: '' };
    },
    readPtySession: () => ({ output: '', cursor: 0, totalBytes: 0, droppedBytes: 0, skippedBytes: 0, promptDetected: false }),
    resizePtySession: () => {},
    closePtySession: () => ({ outcome: 'closed' as const }),
    listPtySessions: () => [],
    toInfo: () => ({
      profile: profile.name, host: profile.host, port: profile.port, user: profile.user,
      status: 'connected', sessionCount: sessions.size, activeChannels: 0,
    }),
  };

  const registry: any = {
    getOrCreate: async () => conn,
    get: () => conn,
    getProfile: () => profile,
    listConnections: () => [conn.toInfo()],
    listAllProfiles: () => [profile],
  };

  // Capture audit records instead of writing to disk.
  const audit = { record: async (r: any) => { auditRecords.push(r); } } as unknown as AuditStore;

  // 审批面接线（T-15：elicitation 移除后）：调用方未显式管理队列时，harness
  // 自持一个 queue 面目录 + 自动裁决泵——setApproval(true/false) 决定泵对
  // 每个待审条目投 approve/reject，等价于旧 elicitation 时代「客户端按旗标
  // 应答」的语义。调用方显式传 approvalQueueDir 即视为自行管理队列，泵不启动。
  const ownsQueueDir = toolOpts.approvalQueueDir === undefined;
  const queueDir = toolOpts.approvalQueueDir ?? mkdtempSync(join(tmpdir(), 'tools-harness-queue-'));
  const effectiveToolOpts: ToolOpts = {
    ...toolOpts,
    approvalSurfaces: toolOpts.approvalSurfaces ?? ['queue'],
    approvalQueueDir: queueDir,
    approvalQueuePollMs: toolOpts.approvalQueuePollMs ?? 5,
  };
  let pumpTimer: NodeJS.Timeout | undefined;
  const pump = async (): Promise<void> => {
    try {
      for (const p of await listPending({ dir: queueDir })) {
        const outcome = await decideApproval(p.id, approve ? 'approved' : 'rejected', { dir: queueDir, by: 'harness-pump' });
        // 只计生效裁决：同条目的重复泵询（竞态输家）不算人工决定次数。
        if (outcome.decided) approvalDecisions++;
      }
    } catch {
      // 队列瞬态（撕裂读等）下个 tick 重试；测试断言不依赖泵的静默失败。
    }
  };

  const server = new McpServer(
    { name: 'test', version: '0.0.0' },
    { capabilities: { tools: {}, resources: {} } },
  );
  registerTools(server, registry, new PolicyEngine(rules), audit, effectiveToolOpts);
  registerResources(server, registry);

  const client = new Client(
    { name: 'test-client', version: '0.0.0' },
    { capabilities: { elicitation: {} } },
  );
  // elicitation 通道已随 H2 移除（T-15）：不注册任何 elicitation 处理器——
  // 若有代码路径再发 elicitation 请求，SDK 会以未支持错误失败，测试即红
  // （审批走 queue 面的自动裁决泵，approvalPrompts 计数恒 0）。
  if (ownsQueueDir) {
    pumpTimer = setInterval(() => { void pump(); }, 5);
  }

  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);

  return {
    client,
    execCalls,
    auditRecords,
    ptyWrites: (conn as any).ptyWrites,
    setExecResult(result) { execResult = result; },
    setApproval(value) { approve = value; },
    setCloseOutcome(outcome) { closeOutcome = outcome; },
    approvalPrompts: () => approvalPrompts,
    approvalDecisions: () => approvalDecisions,
    async close() {
      if (pumpTimer !== undefined) clearInterval(pumpTimer);
      await client.close();
      await server.close();
      if (ownsQueueDir) rmSync(queueDir, { recursive: true, force: true });
    },
  };
}

/**
 * The same handler layer, wired to a real `ConnectionRegistry` that has no profiles.
 *
 * A real registry rather than a stub, because the thing under test is the guard inside it
 * and a stub would only re-state the expectation. What this adds over the e2e probe is the
 * audit store: a refused tool call has to leave a record, and for eight of the eleven tools
 * it did not — the profile was resolved above `runAudited`'s try, so the `OperatorError`
 * escaped before `auditFailure` could see it, and an operator watching an unconfigured
 * server get probed saw an empty log rather than the probing.
 */
export async function createUnconfiguredHarness(): Promise<Pick<Harness, 'client' | 'auditRecords' | 'close'>> {
  const auditRecords: any[] = [];
  const registry = new ConnectionRegistry({ defaults: defaultsFromArgv({}), profiles: [] });
  const audit = { record: async (r: any) => { auditRecords.push(r); } } as unknown as AuditStore;

  const server = new McpServer(
    { name: 'test', version: '0.0.0' },
    { capabilities: { tools: {}, resources: {} } },
  );
  registerTools(server, registry, new PolicyEngine(DEFAULT_RULES), audit, {});
  registerResources(server, registry);

  const client = new Client({ name: 'test-client', version: '0.0.0' }, { capabilities: {} });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);

  return {
    client,
    auditRecords,
    async close() { await client.close(); await server.close(); },
  };
}

/** Flatten a CallToolResult's text content. */
export function textOf(result: any): string {
  return (result.content ?? []).map((c: any) => c.text ?? '').join('\n');
}
