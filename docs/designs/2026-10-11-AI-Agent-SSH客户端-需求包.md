# 结构化需求包：AI Agent SSH 客户端（agent-ssh）

- 日期：2026-10-11
- 准入状态：**通过**（2026-10-11 主人裁决 B1 决策门后解除阻断；下一站 architect-design）
- 拷问轮次：2 轮（3 轮上限内闭合，剩余未决分支全部登记待确认/设计阶段项）
- 自报 ≠ 完成：本需求包为架构师自报版本，主人对准入结论的整体确认以会话回执为准

## 决策记录（主人裁决，2026-10-11）

| # | 分支 | 裁决 |
|---|---|---|
| R1 系统形态 | MCP Server + CLI 双外壳（主人自定义） | 共享核心库 |
| R2 能力范围 | 大输出治理 + PTY 交互 + SFTP + 端口转发全量入首版 | |
| R3 安全强度 | 完整治理（审批闭环 + 审计 + 脱敏 + 配额） | |
| R4 技术栈 | TypeScript + Node.js | |
| R5 目标平台 | Linux/Unix + 网络设备 | |
| R6 审批落地 | 内建审批队列 + CLI 审批 | |
| R7 验证环境 | 容器 + 模拟器 + 主人实机抽验 | |
| R8 **路线（B1 决策门）** | **B：fork ssh-mcp 补缺**（非自建白手起家） | 基座=github.com/tufantunc/ssh-mcp（MIT，v2.18.0） |
| R9 目标设备厂商 | 华为/华三 + 思科 + 锐捷 | 具体型号待补（实机抽验前必须落实） |
| R10 仓库名 | **agent-ssh**（fork 后新仓名） | 可见性=私有起步（提问默认，主人未表异议，可随时改） |

## 可验收目标（可度量）

1. 任一支持 MCP 的宿主（dsh / omp / Claude Code 等）经 stdio 接入后，Agent 能完成完整闭环：选择主机 → 执行命令 → 取回结构化结果（exit code / stdout / stderr / 耗时）→ 断开（基座已有能力，fork 后回归保障）；
2. 大输出治理：超阈值输出被截断并落盘，Agent 经回读工具分页取回，单次工具响应不超过配置上限（基座已有，定标后复核）；
3. **真 PTY 交互会话（补缺重点）**：Agent 能开启真 PTY 会话，与 Linux shell 及华为/华三/思科/锐捷网络设备 CLI 完成多轮交互（识别提示符 → 发命令 → 读回显 → 关分页）；
4. SFTP：上传 / 下载 / 远端列目录；大文件流式不经模型上下文（基座已有，Windows 侧除外——继承上游限制）；
5. **端口转发（补缺）**：本地 / 远程 / 动态转发可经工具建立与撤销；
6. **CLI 审批闭环（补缺重点）**：审批不依赖宿主 elicitation——高危命令落内建待审批队列，人工经 CLI approve/reject，超时过期 fail-closed；宿主支持 elicitation 时双通道并存；
7. **网络设备兼容（补缺）**：SSH 算法协商可配置（兼容老设备 ssh-rsa/CBC/KEX 旧算法），三厂商设备实测矩阵通过；
8. 安全治理闭环（基座继承 + fork 校验）：命令五类分级、角色×主机组矩阵、审计三层脱敏、每日配额熔断全链路在 fork 版本回归通过；
9. 验收演示：容器 Linux + 模拟网络设备跑通「执行 → 大输出治理 → SFTP → 高危 CLI 审批闭环」全链路；主人实机抽验（真实网络设备）通过。

## 范围（做）

| 域 | 内容 | 来源 |
|---|---|---|
| 基座 | fork ssh-mcp（MIT）：exec/会话/SFTP/命令分级/角色矩阵/审批 elicitation/审计/配额/OPA/凭证级联（agent→keychain→env→key）/host key TOFU/Windows OpenSSH 支持 | R8 继承 |
| 补缺·PTY | 真 PTY 交互会话通道（区别于上游 printf 标记模拟），网络设备 CLI 可用 | R5/R9 |
| 补缺·算法 | 算法协商白名单可配置，覆盖三厂商老设备 | R9 |
| 补缺·审批 | 内建审批队列 + CLI 审批入口（approve/reject/超时 fail-closed），与上游 elicitation 双通道 | R6 |
| 补缺·转发 | 本地/远程/动态端口转发工具 | R2 |
| 外壳 | MCP Server（stdio，上游已有）+ CLI 补全（审批入口/调试/直连执行） | R1 |
| 治理复核 | fork 后对基座安全机制做代码级审计与回归（供应链审计） | 新增（R8 引入） |
| 工程化 | monorepo（上游单包结构评估后定）、测试矩阵（容器 Linux + 三厂商设备模拟器 + 实机抽验） | R4/R7 |

## 不做项（显式排除）

- 白手起家自研基座（R8 已裁决走 fork；上游 MIT 协议允许，保留版权与许可声明）
- 多主机批量并行执行（列 P1）
- Web UI / 审批面板（首版无；审批入口 = CLI + 宿主 elicitation）
- 对接 dsh 委托账本 L2+（R6 裁决内建审批队列；架构预留对接扩展点）
- 命令语义级风险分析（首版沿用上游静态规则 + 正则；不做 NLP 级判定）
- 默认配置支持 root 账号（红线：沿用上游「never root」立场）
- 上游 Windows 流式 SFTP 缺口在本仓补齐（继承上游限制，列 P2；Windows OpenSSH 基本能力随基座免费获得）

## 假设（每条标注依据）

1. 运行于 Agent 同机、stdio 传输；跨机共享部署不在首版（依据：R1 + 上游已有 HTTP 传输可后续启用）〔待确认 #3〕
2. 审计日志 = 上游本地 JSONL（三层脱敏，防篡改链可选），保留期可配置（依据：R3 + 上游机制继承）〔待确认 #4〕
3. fork 基线取 ssh-mcp v2.18.0（2026-10-11 npm latest 实测），fork 时以当时最新 stable 重钉（依据：registry 实取）〔设计阶段执行〕
4. 具体网络设备型号由主人后续补齐；设计阶段按三厂商主流型号假设推进（依据：R9）〔实机抽验前必须落实〕
5. ssh2 库经算法配置后对三厂商设备的 PTY 兼容性——**未验证**，设计阶段以 spike 解除（依据：上游 RFC 9142 白名单偏严 vs 老设备旧算法现实）

## 阻断项

- ~~B1 业务取舍：自建 vs 复用~~ **已解除**——2026-10-11 主人裁决 R8：fork ssh-mcp 补缺（见决策记录）。
- 当前无阻断项，**可进入 architect-design**。

## 待确认（不阻断设计启动）

1. 具体网络设备型号清单（决定 PTY 测试矩阵与实机抽验对象；实机抽验前必须落实）；
2. 仓库可见性正式确认（当前按私有起步推进）；
3. 部署假设确认（Agent 同机 stdio 为主，HTTP 传输是否纳入首版）；
4. 审计日志留存期与存储策略；
5. 安全参数基线（审批超时、每日配额、输出截断阈值——可设计阶段给默认值后主人确认）；
6. 需求包最终落点（随 agent-ssh 仓建立迁移 or 留本仓归档）。

## 专项评审触发（命中决策门）

- **高风险变更门**：fork 一个安全敏感项目并改动其核心审批/分级逻辑——真 PTY 通道与 CLI 审批的新增必须过 architect-review 专项核查（新增执行通道 = 新增攻击面）；
- **供应链门**（R8 引入）：fork 基座代码与依赖审计（上游 SBOM/provenance 继承或重建）、与上游的安全通告跟踪机制；
- **Compliance 门**：若目标服务器含公司生产设施或客户资产，凭证管理与审计留存需对照公司信息安全政策评审（由主人判定是否命中）；
- **Unknown 门**：ssh2 对三厂商设备的算法/PTY 兼容性未验证（设计阶段 spike 解除，见假设 5）。

## 六项覆盖检查表

| # | 检查 | 结论 | 证据来源 |
|---|---|---|---|
| ① 需求覆盖 | 通过 | 主人原话四条逐项归属：做（形态/能力四域/目标平台）；「各类操作」收敛为 exec+PTY+SFTP+端口转发，无悬空条目 | 决策记录 R1-R7 + 本包「范围」节 |
| ② 系统覆盖 | 通过 | 新仓 agent-ssh（fork），宿主中立；消费方=任意 MCP 宿主 + CLI 人工；外部基座依赖已显式化（ssh-mcp fork + 供应链审计触发）；无存量系统改动 | 套件架构地图（architect-knowledge/reference/dsh-suite-architecture-map.md）+ 本机 digital-twin/ 目录实测（2026-10-11，套件内无 SSH 能力成员，排除重复建设） |
| ③ 证据覆盖 | 通过（2 处待验证已登记） | ssh-mcp 能力面=README 全文实取 + npm registry 元数据；套件无既有能力=实测；设备兼容性=未验证（假设 5）；@hypnosis 替代项=仅元数据未核 | registry.npmjs.org/ssh-mcp/latest、raw.githubusercontent.com/tufantunc/ssh-mcp（2026-10-11 实取） |
| ④ 风险覆盖 | 通过 | 安全=基座治理机制继承 + 新增通道专项评审（高风险门）；供应链=fork 审计门（新增）；兼容=三厂商旧算法（假设 5 spike）；异常=超时/断连/输出洪泛（上游机制+设计覆盖）；状态机=审批 fail-closed | 本包范围/决策记录/专项评审触发节 |
| ⑤ 验证覆盖 | 通过 | 单测（补缺模块）+ 基座回归（fork 必做）+ 容器 Linux 集成 + 三厂商 PTY 模拟器 + 主人实机抽验（R7）；纯新增系统回滚=停用即回滚 | R7 + 可验收目标 9 |
| ⑥ 不确定性治理 | 通过 | 6 项待确认显式登记；5 项假设标注依据；阻断项 B1 已裁决解除；无擅自补全 | 本包「待确认」「假设」「阻断项」节 |

## 准入五问结论（最终）

1. **问题与方案匹配**：匹配——主人主动提出场景，非方案找问题；
2. **价值依据**：主人自述需求（自有 Agent 体系远程运维）〔推断：与主人 agent 基础设施布局相关，未追问〕；
3. **范围是否受控**：**警示**——首版含基座继承 + 4 项补缺，范围仍偏大。缓解：拆票按曳光弹切片（fork 跑通回归 → CLI 审批 → 真 PTY/Linux → PTY/网络设备+算法 → SFTP 复核 → 端口转发），每片独立可验收；
4. **可复用既有能力**：已闭环——Reuse 语义升级为 **fork 复用（R8）**：套件内无（已核），生态 ssh-mcp（MIT）作基座，差异化补缺聚焦真 PTY/网络设备/CLI 审批/端口转发/算法配置；
5. **验收可逆**：可逆——纯新增系统，停用即回滚，无存量数据迁移。

## 调研与证据记录

- 套件成员核查：`E:\Development\Code\nodejs\digital-twin` 目录清单（2026-10-11 实测，11 已核成员无 SSH 能力）；官方 checkout `@deepseek-ai/dsh-api-remotes@0.2.1-alpha.2`（package.json 自述 "Remote BFF assembly for application-selected Host capabilities"，web 平台 BFF，推断与 SSH agent 工具无关，未做源码级核验）；知识地图「dsh-remote」待蒸馏条目在本地两仓均未找到对应源码，维持「能力未核」。
- ssh-mcp：[npm](https://www.npmjs.com/package/ssh-mcp) · [GitHub README](https://github.com/tufantunc/ssh-mcp)（registry.npmjs.org/ssh-mcp/latest 与 raw.githubusercontent.com 实取，2026-10-11）：14 工具、五类命令分级、角色×主机组矩阵、elicitation 审批（10 分钟超时 fail-closed）、审计三层脱敏 + 防篡改链可选、配额熔断、OPA 只收窄不放宽、凭证四级级联、TOFU+pin、RFC 9142 算法白名单、Linux/Alpine/Dropbear/Windows OpenSSH 实测、MIT、SLSA L2 + SBOM。
- @hypnosis/ssh-mcp-server：[npm](https://www.npmjs.com/package/@hypnosis/ssh-mcp-server)（仅 registry 元数据；README 实取失败）：OpenSSH 外部进程路线。
- 生态检索：socket.dev / npm 检索结果 ≥6 个同类项目（品类成熟，佐证 fork 优于自研）。
