# 可执行技术方案：agent-ssh（AI Agent SSH 客户端，fork ssh-mcp 补缺）

```yaml
---
title: agent-ssh 技术方案
status: 已落定          # 草稿 → 已评审 → 已落定（主人确认后） → 已执行
requirement: docs/designs/2026-10-11-AI-Agent-SSH客户端-需求包.md
author: 架构师 Agent（digital-architect 总仓）
created: 2026-10-11
finalized: 2026-10-11（主人确认落定，会话内 ask_user 回执「确认落定，继续拆票」）
review:
  score: 54
  conclusion: 通过（2026-10-11 评审；落定待主人确认）
---
```

> 落点说明：目标项目 agent-ssh 仓尚未建立，本方案暂落本仓 `docs/designs/`，建仓后随需求包一并迁移（需求包待确认 #6）。

## 0. 一句话与五问速答

| 五问 | 速答 |
|---|---|
| 改哪里？ | 新建仓 agent-ssh = fork ssh-mcp@v2.18.0（MIT），新增四个补缺模块：真 PTY 会话、CLI 审批队列、端口转发、算法协商配置；不动 dsh 套件任何成员 |
| 为什么改？ | 给 AI Agent 一条带完整治理（分级/审批/审计/配额）的远程 SSH 执行通道；网络设备场景上游基座不可用（模拟会话非真 PTY） |
| 影响谁？ | 仅新仓自身；各 MCP 宿主（dsh/omp/Claude Code 等）为纯消费方零改动；上游 ssh-mcp 仓不改（fork 独立演进） |
| 如何验证？ | fork 后先跑上游测试套件全绿作回归基线，再以新增单测 + 容器集成 + ssh2 Server 模式设备模拟器 + 主人实机抽验分层验证 |
| 还有什么没有确认？ | 5 项（见 §6），最关键 = U2：PTY 会话内命令无法逐条过分类器（字节流本质），需主人确认五层缓解对策 |

## 1. 需求覆盖（10 分）

### Do（做）

| # | 需求条目 | 方案响应 | 来源（需求包条目号） |
|---|---|---|---|
| 1 | MCP Server + CLI 双外壳 | 基座继承（stdio+HTTP 传输、14 工具）；CLI 补审批子命令与直连执行 | R1 |
| 2 | 连接管理（多主机/凭证/host key） | 基座继承：TOML profiles、凭证四级级联（agent→keychain→env→key）、TOFU+pin | R8 继承 |
| 3 | 命令执行（exec/状态会话） | 基座继承：read-command/run-command/privileged-command、interactive/background session | R8 继承 |
| 4 | **真 PTY 交互会话** | 新增 `src/pty/`：`conn.shell({ pty })` 真伪终端通道；deviceType 驱动分页关闭与提示符策略；工具面新增 open/read/write/resize/close 五原语 | R5/R9，可验收目标 3 |
| 5 | **CLI 审批闭环** | 新增 `src/approval/`：审批请求文件化队列 + 状态机（pending→approved/rejected/expired）+ `agent-ssh approvals` CLI 子命令；与上游 elicitation 双通道可配 | R6，可验收目标 6 |
| 6 | **端口转发** | 新增 `src/forward/`：local（forwardOut）/remote（forwardIn）/dynamic（SOCKSv5）三模式 + 生命周期工具 | R2，可验收目标 5 |
| 7 | **算法协商可配置** | profile.algorithms 透传 ssh2 connect 配置（精确列表或 append/prepend/remove）；keyboard-interactive 认证透传（网络设备常用）；默认仍上游 RFC 9142 白名单 | R9，可验收目标 7 |
| 8 | 大输出治理 | 基座继承（commandMaxOutputBytes/maxChars/截断）；PTY 通道按同一策略接环形缓冲+落盘+分页回读 | R2 |
| 9 | 安全治理（分级/矩阵/审计/配额） | 基座继承 + 补缺模块全部纳入 policy engine（PTY 会话开启=需审批类；转发目标走 denylist；全量审计） | R3/R6 |
| 10 | 目标平台 Linux + 华为/华三/思科/锐捷 | PTY 通道 + deviceType 档案（分页关闭命令/提示符模式/字符编码），设备模拟器测试矩阵 | R5/R9 |

### Don't（不做，显式排除）

| # | 排除项 | 排除原因 |
|---|---|---|
| 1 | 白手自研基座 | R8 已裁决 fork；重复建设违反 Reuse 纪律 |
| 2 | 多主机批量并行执行 | P1（Q8 裁决），单机串行先曳光 |
| 3 | Web UI / 审批面板 | 首版无；审批入口 = CLI + 宿主 elicitation |
| 4 | 对接 dsh 账本 L2+ | R6 内建审批；架构预留（审批入口抽象为接口） |
| 5 | 向上游 ssh-mcp 提 PR 的义务 | fork 独立演进；有价值的补缺可后续酌情回馈上游，不作为承诺 |
| 6 | PTY 会话内命令逐条语义分类 | 技术不可行（PTY 为字节流，见 §6 U2）；列 P2 探索内容级正则告警 |
| 7 | 上游 Windows 流式 SFTP 缺口补齐 | 继承上游限制，P2 |
| 8 | root 账号默认支持 | 红线继承上游「never root」 |

### To Confirm（待确认）

| # | 待确认项 | 问谁 | 状态 |
|---|---|---|---|
| 1 | U2：PTY 会话内命令不过分类器的五层缓解对策是否接受 | 主人 | **已裁决：接受**（2026-10-11，见 §8） |
| 2 | U3：安全参数默认值（审批超时/配额/截断阈值） | 主人 | **已裁决：方案默认值档**（2026-10-11，见 §8） |
| 3 | 三厂商具体设备型号清单（实机抽验对象与测试矩阵） | 主人 | 待确认（不阻断设计） |
| 4 | 仓库可见性（当前按私有起步） | 主人 | 待确认（不阻断） |
| 5 | npm 包名（agent-ssh 或 @lomehong/agent-ssh scope） | 主人 | 待确认（不阻断） |

## 2. 系统覆盖（10 分）

### 组件与变更类型

| 服务/插件/仓库 | 变更类型 | 关键依赖 | 缺席降级影响 |
|---|---|---|---|
| agent-ssh（新建仓） | 增 | ssh2@^1.17、@modelcontextprotocol/sdk@^1.30、smol-toml、vitest（沿用上游依赖树） | 不适用（新系统） |
| ssh-mcp 上游仓 | 不动（fork 只读基线） | — | 不适用 |
| dsh 套件 11+4 成员 | 不动 | — | 不适用（纯消费方关系） |
| MCP 宿主（dsh/omp/Claude Code） | 不动 | 各宿主 MCP 客户端能力（elicitation 支持度异构——队列通道兜底） | 无 elicitation 的宿主：审批走 CLI 队列，功能不缺失 |

### 调用链与数据流（补缺部分）

```
MCP 宿主 Agent                      人工（本机）
     │ stdio                              │ CLI
     ▼                                    ▼
agent-ssh MCP Server ──► policy engine（分级/矩阵/denylist/配额）
     │                          │
     │ run-command/exec ──► ssh2 exec（基座路径不动）
     │ open-pty-session ──► 审批队列/elicitation ──► ssh2 shell({pty})（新）
     │ open-port-forward ──► denylist+角色 ──► forwardOut/forwardIn/SOCKS（新）
     ▼                                    ▼
审计日志（JSONL，三层脱敏）◄── 全通道统一留痕（含 PTY 会话输入输出、审批决定）
```

数据主责：审批队列状态 = `~/.agent-ssh/approvals/`（agent-ssh 私有域）；审计 = 上游 audit 目录；设备凭证 = 上游凭证级联。一致性边界：审批状态机单机单文件原子写（沿用上游 config/audit 的写纪律）。

### 访客可见性红线检查

不适用——本系统不涉 dsh 会话/渠道/活动视图（独立 MCP server，无分身人格面）。显式声明而非默认无风险：**红线不触发的依据是组件边界**（agent-ssh 不注入任何宿主会话 state）。

- 范围外参与方：目标服务器/网络设备的账号与 AAA 体系（建议侧记账为文档红线，不在本系统控制内）；
- 对照 `architect-knowledge/reference/dsh-suite-architecture-map.md` 核对结论：无遗漏——项目不属套件、不改任何套件成员；宿主侧唯一交互是标准 MCP 协议。

## 3. 证据覆盖（10 分）

| 关键结论 | 证据类型 | 证据出处 | 核对人 |
|---|---|---|---|
| 基座为 ssh-mcp@2.18.0，MIT，14 工具含分级/矩阵/审批/审计/配额 | Code（registry 元数据+README 全文） | registry.npmjs.org/ssh-mcp/latest + github.com/tufantunc/ssh-mcp README（2026-10-11 实取） | 架构师 |
| 上游交互会话非真 PTY（printf 标记模拟，POSIX shell 限定） | Code（README「Interactive Sessions」节） | 同上；Windows/网络设备明确 ❌ | 架构师 |
| ssh2 原生支持真 PTY：`shell()` + Pseudo-TTY settings（cols/rows/term/modes）+ 终端模式表 | Code（README API 节） | github.com/mscdex/ssh2 README「Pseudo-TTY settings」「Terminal modes」（2026-10-11 实取） | 架构师 |
| ssh2 原生支持三模式端口转发：forwardOut（本地/连接跳跃）、forwardIn（远程）、SOCKSv5（动态） | Code（README 客户端示例节） | 同上「Forward local/remote/dynamic」示例 | 架构师 |
| ssh2 支持算法覆盖：connect config `algorithms`（cipher/hmac/kex/compress，精确列表或 append/prepend/remove） | Code（README connect(config) API） | 同上 L804 实测行 | 架构师 |
| ssh2 支持 keyboard-interactive 认证事件与 subsys（netconf） | Code（README events/示例） | 同上 | 架构师 |
| ssh2 支持 keepalive（interval/countMax）与 readyTimeout——异常处理地基 | Code（README connect config） | 同上 L958/960/978 | 架构师 |
| 套件内无既有 SSH 能力，无重复建设 | Architecture | 本机 digital-twin/ 目录实测 + 套件架构地图（2026-10-11） | 架构师 |
| 业务意图：Agent 安全远程运维通道，网络设备三厂商 | Business | 需求包决策记录 R1-R10（主人裁决 2026-10-11） | 主人 |
| 上游 profile 已有 `tty` 配置位但语义未核（README 显示 `tty = false`） | Unknown | 需求包假设 5 + 本方案 U1——fork 第一票源码核查 | 待核 |

> 四层装载记录：业务层=需求包+meta 全部（准入阶段已读）；架构层=套件地图（不适用结论已声明）；系统层=上游 ssh-mcp README 全文 + ssh2 README 全文（当前行为以代码/上游文档为准）；基建层=凭证级联/审计/传输为上游既成事实，新增模块沿用同一布局（审批队列目录权限对齐上游 config ACL 检查逻辑）。未发现知识与代码冲突。

## 4. 风险覆盖（10 分）

| 风险类 | 有无涉及 | 分析与对策 |
|---|---|---|
| Compatibility 兼容 | 有 | 三厂商设备旧算法（ssh-rsa/CBC/旧 KEX）：默认保持上游 RFC 9142 白名单，profile.algorithms 显式放宽 + 审计 warning；PTY 语义差异（分页/提示符/编码）由 deviceType 档案驱动；老设备不支持 modern KEX 时可能握手失败——spike 票前置验证（U4） |
| Exception 异常 | 有 | 断连/超时：keepalive + readyTimeout + 空闲会话回收（上游 sessionIdleTimeoutMs 模式复用）；PTY 输出洪泛：环形缓冲+截断落盘+分页回读；审批服务（CLI 不在场）：超时 expired fail-closed |
| Cache 缓存 | 不适用 | 无缓存面；连接复用属上游连接池语义，不动 |
| MQ 消息 | 不适用 | 无消息队列 |
| State 状态机 | 有 | 审批队列 pending→approved/rejected/expired，单向流转，expire 判定在读取时惰性执行+写回；PTY 会话 open/active/idle/closed；转发条目 active/closed——三者均文件/内存态，进程重启语义：审批 pending 保留（文件化），PTY/转发随连接消亡（显式记录于审计） |
| Security 安全 | 有（重点） | ①PTY 新攻击面：会话内命令不过分类器（U2 五层对策：开启需审批/全量审计/双超时/最小权限红线/P2 内容告警）；②审批队列防篡改：目录 0700 文件 0600 + Windows ACL 对齐上游检查 + 审批请求含完整命令指纹（hash）防替换；③**agent 不可自批红线**：MCP 工具面绝不暴露 approve/reject 动作，审批仅经本机 CLI 或宿主 elicitation 由人执行；④转发滥用：目标 denylist+viewer 禁转发+dynamic 默认关；⑤供应链：fork 基线审计门（依赖树/上游 SBOM 对账）+ 上游安全通告跟踪 |

## 5. 验证覆盖（10 分）

| 验证手段 | 内容 | 可执行入口（命令/脚本/场景） |
|---|---|---|
| Unit 单测 | 审批队列状态机（含并发/过期/指纹校验）、deviceType 档案（分页命令生成/提示符匹配）、forward 管理器、config schema 扩展 | `npm run test:unit`（沿用上游 vitest 结构） |
| Contract 契约 | MCP 工具 schema（新工具 input/output 契约快照）；CLI 子命令输出契约 | vitest 契约快照 + `@modelcontextprotocol/inspector` 手动核 |
| Regression 回归 | **fork 第一票：上游测试套件全绿**（含其 docker compose 集成 fixtures：Debian/Alpine/Dropbear/Windows OpenSSH 矩阵中可本机执行部分）；补缺模块合入后重跑 | `npm test` + `docker compose --profile test up -d --build` |
| Monitoring 监控 | 上游 OTel 继承；新增 span：pty.session.open/close、approval.request/decide、forward.open/close | `--otelEndpoint` 沿用 |
| Rollback 回滚 | 纯新增系统停用即回滚；补缺模块独立 commit 序列可逐个 revert；上游基线 tag 永久可回 | git tag `upstream-v2.18.0-baseline` |

**实机抽验（主人参与）**：华为/华三/思科/锐捷各 ≥1 台真实设备，走 PTY 全流程（登录→关分页→执行 show/display 类命令→退出），验证提示符识别与审计留痕。

## 6. 不确定性治理（10 分）

| # | 类型 | 描述 | 处置 |
|---|---|---|---|
| U1 | Unknown | 上游 profile `tty = false` 字段语义未核（可能已部分支持 PTY 通道） | fork 第一票源码核查；本方案按「上游无真 PTY 工具」推进（README 明确交互会话为 printf 模拟），核查后修正，不阻塞 |
| U2 | **Human Decision（决策门）** | PTY 会话内命令无法逐条过命令分类器（字节流本质，非 exec 通道）。缓解五层：①会话开启默认需人工审批（纳入破坏性类）；②会话输入输出全量审计+脱敏；③空闲+总时长双超时；④文档红线：设备接入用最小权限账号+设备侧 AAA 记账兜底；⑤P2 探索内容级正则告警 | **已裁决（2026-10-11 主人）：接受五层对策**，内容告警维持 P2 |
| U3 | **Human Decision（决策门）** | 安全参数默认值：审批超时 10min（对齐上游 elicitation）、每日配额 200/主机（上游默认）、PTY 输出单次回读 32KB/总量 1MB、PTY 会话总时长上限 2h | **已裁决（2026-10-11 主人）：按方案默认值档落**，写入配置默认，运行时可调 |
| U4 | Unknown | 三厂商具体型号/系统版本与 ssh2 的算法+PTY 实际兼容性 | spike 票：先对设备模拟器验证代码路径，实机抽验终验；主人待补型号清单（需求包待确认 #1） |
| U5 | Conflict | 无 | 四层装载未发现知识库与代码/上游文档冲突（本设计不涉套件成员内部行为） |

## 7. 任务拆解（落定后填——拆解预案，ticket-split quiz 迭代后定稿）

| 序 | 任务（预案） | 可验收条目 | 阻断边 |
|---|---|---|---|
| T1 | fork 建仓 + 回归基线 | 上游测试套件全绿；U1 源码核查结论；供应链审计门通过（依赖树+SBOM 对账）；upstream 基线 tag | — |
| T2 | 配置 schema 扩展（deviceType/algorithms/approvalChannel/keyboardInteractive） | schema 校验+未知键报错（沿上游纪律）+透传单测 | T1 |
| T3 | 真 PTY 会话（Linux/generic 优先） | open/read/write/resize/close 五原语工具；大输出治理接入；会话开启过审批门 | T2 |
| T4 | CLI 审批队列 + 双通道 | 队列状态机单测全绿；`agent-ssh approvals` CLI；无 elicitation 宿主闭环可用；agent 不可自批红线测试 | T2 |
| T5 | 网络设备 deviceType 档案 + 设备模拟器 | 华为/华三/思科/锐捷四档案（关分页+提示符）；ssh2 Server 模拟器集成测试通过 | T3 |
| T6 | 端口转发三模式 + 授权 | 三模式工具+生命周期；denylist/viewer 限制/dynamic 默认关的单测 | T2 |
| T7 | 端到端验收 | 容器全链路演示（执行→大输出→SFTP→CLI 审批闭环）+ 主人实机四厂商抽验通过 | T3,T4,T5,T6 |

## 8. 决策门记录

| 命中门 | 决策 | 决策人/时间 |
|---|---|---|
| Business Trade-off（需求阶段 B1：自建 vs fork） | fork ssh-mcp 补缺 | 主人 / 2026-10-11（需求包 R8） |
| Human Decision（U2 PTY 安全取舍） | 接受五层缓解对策（开启需审批/全量审计/双超时/最小权限红线/告警 P2） | 主人 / 2026-10-11 |
| Human Decision（U3 安全参数） | 按方案默认值档落（审批超时 10min/配额 200/PTY 回读 32KB·1MB/会话上限 2h） | 主人 / 2026-10-11 |
| High-risk Change（PTY 新执行通道） | 触发 architect-review 专项核查（§4 Security + U2 已裁决对策） | 待评审 |
