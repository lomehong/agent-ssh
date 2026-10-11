import { ErrorCode, McpError } from '@modelcontextprotocol/sdk/types.js';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { PolicyEvaluation } from '../types.js';

export interface ApprovalResult {
  approved: boolean;
  approver?: string;
  /**
   * 在「根本无法询问客户端」时设置，区别于「问了但被拒」。
   * 两者都拒绝命令；只有其一是用户亲手所为，
   * 告诉读者「拒绝了一条他从未见过的命令」会让他
   * 去找错地方。
   */
  unavailable?: string;
}

/**
  * 一个人读完一条破坏性命令并做出决定，有多长时间。
 *
  * 显式声明是因为 SDK 的 DEFAULT_REQUEST_TIMEOUT_MSEC 是 60 秒，
  * 在这里继承它，等于让人类的阅读时间继承一个为
  * 机器往返选的默认值。走开一会儿、或在琢磨一个
  * 陌生对话框的运维，会眼睁睁看着请求过期、命令
  * 被拒（#91）。
 *
  * 十分钟长到足以被打断后回来，仍有边界，
  * 让永不作答的客户端无法把一次工具调用永久吊着。
 */
export const APPROVAL_TIMEOUT_MS = 600_000;

/**
  * 请 MCP 客户端确认一条破坏性或特权命令。
 *
  * 用 SDK 的类型化 `Server.elicitInput()` 而不是手搓的
  * `elicitation/create` 信封，让协议变更炸掉构建，
  * 而不是静默废掉守着每条破坏性命令的那道门。
 *
  * fail-closed：任何错误（客户端不支持 elicitation、传输
  * 失败、超时、畸形应答）都拒绝命令。失败要记日志，
  * 因为一个因无人注意的原因而总是拒绝的门，
  * 本身就是另一种故障。
 */
export async function requestApproval(
  server: McpServer,
  command: string,
  profileName: string,
  evaluation: PolicyEvaluation,
): Promise<ApprovalResult> {
  const message = `Confirm ${evaluation.commandClass} command on "${profileName}":\n\n${command}`;

  try {
    const result = await server.server.elicitInput(
      {
        message,
        requestedSchema: {
          type: 'object',
          properties: {
            confirm: {
              type: 'boolean',
              title: 'Approve this command?',
            },
          },
          // 刻意不要求 `confirm`。协议已在 `action` 里携带
          // 决定，accept 与 decline 是不同的结果，再要求一个布尔等于
          // 让用户把同一句话说两遍——而且客户端会把必填布尔
          // 渲染成 accept/decline 行旁边的复选框。点了 Accept
          // 却没勾选，提交的是缺必填字段的表单，客户端
          // 产不出有效结果、只能发 `cancel`，到这里就成了
          // "User did not approve this command"。用户选的是批准，
          // 却被告知他拒绝了（#91）。
          //
        },
      },
      { timeout: APPROVAL_TIMEOUT_MS },
    );

    // 由 `action` 决定。客户端仍发送该字段时的显式 `confirm: false`
    // 会被尊重——对明确的「不」拒绝执行毫无成本，
    // 把它读成批准则无可辩解。
    if (result.action === 'accept' && result.content?.confirm !== false) {
      return { approved: true, approver: 'mcp-client' };
    }
    return { approved: false };
  } catch (err) {
    const timedOut = err instanceof McpError && err.code === ErrorCode.RequestTimeout;
    const cause = err instanceof Error ? err.message : String(err);

    // stderr 仍会打一份进运维日志，但它不能是唯一一份：
    // 对 stdio MCP 服务器那是一份没人读的客户端日志文件，
    // 所以调用方也拿到诊断，才能摆到用户面前。
    console.error(
      `Approval request failed for ${evaluation.commandClass} command on "${profileName}" — denying. ` +
      `${timedOut ? `No answer within ${APPROVAL_TIMEOUT_MS / 1000}s.` : 'Does this client support elicitation?'} ` +
      `Cause: ${cause}`,
    );

    // 点名原因，而不是瞎猜。这条消息的引入是为了不让
    // APPROVAL_DENIED 一词遮住两种不同的失败，结果它自己对
    // catch 到的每个错误都冠以「客户端不支持 elicitation」，
    // 超时也不例外——同一个缺陷，长在修复自己的补丁里。
    return {
      approved: false,
      unavailable: timedOut
        ? `no answer arrived within ${APPROVAL_TIMEOUT_MS / 1000}s, so it was refused rather than left ` +
          `pending. The prompt may still be open in your client; approve the command again once you are ` +
          `ready to answer it.`
        : `this MCP client could not be asked to approve it. The likely cause is a client without ` +
          `elicitation support; a transport failure or a malformed reply does the same. Approval fails ` +
          `closed, so the command was refused rather than run. Underlying error: ${cause}`,
    };
  }
}
