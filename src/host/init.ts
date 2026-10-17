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
  // 安全纪律（评审 T-15 jc2）：agent 令牌明文不进 config.toml——令牌经 init
  // 输出（stdout，一次）交运维注入 stub 的 env（D6 禁 argv）；配置里只留
  // 指引注释。落盘最小化：哈希是配置里唯一的秘密衍生材料。
  //
  // 骨架必须可加载（T-17.6 部署顺手修复：profiles 全注释曾撞 schema
  // min(1)——init 产物 serve 直拒「no profiles」，init→serve 链走不通）。
  // example 指向不可达主机：可加载、连接必拒，与「缺省即拒绝」同哲学。
  const configToml = `# agent-ssh Host 配置（由 \`agent-ssh host init\` 生成，${new Date().toISOString()}）
# 凭证引用与策略都在 Host 机；本文件不出 Host（方案 §1 信任域）。

[defaults]
# 审批面集合：desktop=桌面审批端（T-17.5）/ im=飞书 bot（T-17.6）/
# queue=文件队列+approvals CLI（兜底，建议常驻集合）。
approvalSurfaces = ["desktop", "queue"]

# agent 令牌由 init 打印一次，经 env AGENT_SSH_TOKEN 注入 stub
#（禁走 argv，D6；明文不入本文件——丢失时重跑 init 轮换）。

# operator 口令哈希（scrypt，salt:hash）。由 init 交互输入生成；
# 校验在 auth.session.start，明文口令不落任何盘。
operatorPasswordHash = "${operatorHash}"

# transferRoot 未设置：流式文件工具持续拒绝，直到显式指名目录（缺省即拒绝）。

# 骨架占位 profile：可加载但不可达（example.example 无法解析）——
# 替换成你的真实主机，或删除后加入自己的。
[[profiles]]
name = "example"
host = "example.example"
user = "operator"
`;
  return { configToml, agentToken, operatorHash };
}
