/**
 * `agent-ssh host init` 的核心生成逻辑（T-15 验收 6，方案 §6 五步引导）。
 *
 * 纯函数：给定 operator 口令（与可选的既有 agent 令牌），产出
 * 配置骨架（TOML 文本）、agent 令牌、口令 scrypt 哈希。交互式口令输入、
 * 文件落盘与可选自签证书（openssl 依赖）由 CLI 包装层承担（本仓约定：
 * 交互与 IO 不进纯核心，测试直接钉产物形态）。
 * 五步对应：①骨架 ②agent 令牌 ③口令哈希 ④⑤证书/pin=CLI 层可选步骤。
 */
import { generateAgentToken, hashPassword } from '../rpc/auth.js';

export interface HostInitArtifacts {
  /** 写入 Host 机 config.toml 的骨架（含指引注释）。 */
  configToml: string;
  /** 经 env AGENT_SSH_TOKEN 注入 stub 的 agent 令牌（≥256bit，init 时打印一次）。 */
  agentToken: string;
  /** operator 口令的 scrypt 哈希（salt:hash hex），落 Host 配置。 */
  operatorHash: string;
}

export function buildHostInitArtifacts(
  operatorPassword: string,
  opts: { agentToken?: string } = {},
): HostInitArtifacts {
  const agentToken = opts.agentToken ?? generateAgentToken();
  const operatorHash = hashPassword(operatorPassword);
  const configToml = `# agent-ssh Host 配置（由 \`agent-ssh host init\` 生成，${new Date().toISOString()}）
# 凭证引用与策略都在 Host 机；本文件不出 Host（方案 §1 信任域）。

[defaults]
# 审批面集合：desktop=桌面审批端（T-17.5）/ im=飞书 bot（T-17.6）/
# queue=文件队列+approvals CLI（兜底，建议常驻集合）。
approvalSurfaces = ["desktop", "queue"]

# agent 令牌经 env AGENT_SSH_TOKEN 注入 stub（禁走 argv，D6）：
#   AGENT_SSH_TOKEN=${agentToken}

# operator 口令哈希（scrypt，salt:hash）。由 init 交互输入生成；
# 校验在 auth.session.start，明文口令不落任何盘。
operatorPasswordHash = "${operatorHash}"

# transferRoot 未设置：流式文件工具持续拒绝，直到显式指名目录（缺省即拒绝）。

[[profiles]]
# name = "example"
# host = "example.example"
# user = "operator"
`;
  return { configToml, agentToken, operatorHash };
}
