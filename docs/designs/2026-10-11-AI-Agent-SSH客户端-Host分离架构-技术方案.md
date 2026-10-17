# 可执行技术方案：agent-ssh Host 分离架构（凭证与 AI Agent 信任域隔离）· 修订版 v2

```yaml
---
title: agent-ssh Host 分离架构技术方案
status: 已落定        # v2 经二轮评审（7.7/10）+ 主人裁决（帧上限-a/飞书 SDK/bin 改名/scrypt）收口，2026-10-11
requirement: docs/designs/2026-10-11-AI-Agent-SSH客户端-需求包.md（R3 重申；R6 elicitation 半边被本方案取代，见 §12）
author: 架构师 Agent（与主人共同评审）
created: 2026-10-11
revision:
  - v3.1（勘误，2026-10-11）：§3.3 auth.session.start/renew 合行拆分——renew 对 operator=✅（凭现有会话滑动续期），与 §3.2 自洽；源自 T-14 实现评审规格轴 F2
  - v3（收口落定）：二轮评审裁决闭合——帧上限 4MB(a)/飞书官方 SDK/bin 改名 agent-ssh/口令哈希内置 scrypt；K1-K9 收口入文（cutover 值域行、供应链改写、票表 K3/K4 调整、K7 串行化、票级验收条件）
  - v2：吸纳一轮评审 H1-H6/M1-M8 全部修复 + 主人裁决（H1-a / D1' / D2-a / D8 审批面 / elicitation 移除 / Tauri）；M10 经代码取证判定虚警关闭（二轮评审正式撤销）
  - v1：初稿（评审对象，见同目录评审记录）
review:
  score: v1 轮 5.8/10；v2 轮 7.7/10
  conclusion: 二轮评审：修复纪律可信、无结构性返工、建议进拆票；裁决项已全部闭合（v3）
---
```

> **取代声明**：本方案架构级取代同日《AI-Agent-SSH客户端-技术方案》（该文件已加"已被取代"标注）。需求包 R6"宿主 elicitation 双通道并存"的 elicitation 半边被 §4 审批面设计取代（队列与双通道精神保留，通道载体升级）；需求包假设 1（同机 stdio）随架构废止而失效；待确认 #3（HTTP 传输首版与否）被事实关闭（HTTP 传输随 http.ts 删除）。

---

## 0. 一句话与五问速答

| 五问 | 速答 |
|---|---|
| 改哪里？ | 单体拆两进程：**薄 stub**（MCP 前端，无凭证）+ **Host 守护**（唯一持凭证方）；间以自定义 RPC；新增**审批面**三载体（Tauri 桌面审批端 / 飞书 bot / CLI）；elicitation 通道移除；http.ts 与 stdio 直连路径删除 |
| 为什么改？ | 凭证移出 Agent 信任域（v1 不变）；v2 增强：审批 UX 升级为自有原生通道，同时关闭 v1 评审 H2 的自批洞 |
| 影响谁？ | 本仓（大重构 + 新增 Rust 子项目）；MCP 宿主零改动（23 工具契约冻结；`sftp-upload-file`/`sftp-download-file`/`forward-open` 三工具**位置语义重定义**，见 §5）；上游传输层分叉弃用 |
| 如何验证？ | 分层判据（§9）：Host 内部逻辑保持 in-process 单测；integration/e2e 双进程化；开工前冻结失败基线；红线测试四项 + 令牌矩阵；真实 Linux 复跑 |
| 还有什么没有确认？ | 无未裁决项（D1'-D14 全部落定，见 §12，含帧上限 4MB/飞书 SDK/bin 改名/scrypt）；T-08 四厂商实机抽验仍按台账挂起 |

---

## 1. 威胁模型

### 1.1 现架构的结构性缺陷（不变）

Agent（具备本机文件读取能力的编码代理）与凭证同机同用户，`cat config.toml` 即击穿全部工具面治理。**实际路径核对**（修正 v1 臆写）：配置在 `%APPDATA%\ssh-mcp\config.toml`（loader.ts:19-21，**fork 后仍是 ssh-mcp 目录名，未改名**）；审批队列在 `%LOCALAPPDATA%\agent-ssh\approvals`（approval-queue.ts:49-58）——两套命名并存，cutover 清单见 §7。

### 1.2 攻击树（v2 修订：+A8/A9；H2 洞因 elicitation 移除而闭合）

| # | 攻击路径 | 对策 | 残余风险 |
|---|---|---|---|
| A1 | Agent 读宿主机文件窃取凭证 | 凭证只在 Host 机；Agent 机无凭证材料（stub 仅持 Host 地址 + agent 令牌） | Host 机失陷（接受：个人使用，Host 即信任锚） |
| A2 | Agent 持 agent 令牌直连 RPC 绕过 stub | **设计内允许**：该令牌能力被 Host 治理完全包裹（§3.3 方法×令牌矩阵）；stub 非安全边界，Host 才是 | 无新增 |
| A3 | Agent 自批 | 三重关闭：①agent 类令牌/会话**服务端判定**（客户端自报 class 不可信，M3）；②`approval.*` 仅收 operator 会话/IM 绑定决定；③**elicitation 反向通道已移除**（v1 H2 的洞不复存在——Agent 无任何可应答的审批载体） | operator 口令输入期间的进程内存窗（A9 声明） |
| A4 | RPC 窃听/重放 | 非环回绑定强制 TLS（fail-closed 拒明文）；帧上限 1MB（继承 http.ts 先例）防无界缓冲；审批超时判定用**单调钟**（防时钟回拨延长窗口，M4） | 个人使用接受自签+固定 |
| A5 | stub 被篡改后"好心"直连 | stub 模块结构性无 ssh2/凭证代码路径（依赖边界测试钉死，§9）；断连一律结构化错误 | stub 诚实性是**声明的安全假设**（非"残余风险：无"，v1 表述修正） |
| A6 | Host 机会话数据泄露 | 三层脱敏 + 转录上限冻结沿用 | 与现架构持平且面更小 |
| A7 | 伪造 Host（中间人） | **部署时分发显式 pin**：`AGENT_SSH_HOST_PIN`（一票否决、任何模式不可覆盖、错误信息对齐 HOST_KEY_PIN_MISMATCH 纪律）——v1 的自动 TOFU 在无状态 stub 上不成立（评审 H3），已废弃 | 自签证书管理成本（部署时一次性） |
| A8 | IM 审批面：飞书账号被盗=冒充审批人 | bot token 只存 Host；per-request 单次消费决策令牌（绑定请求 id+命令指纹）；IM 账号开两步验证（运维要求写入文档） | IM 账号安全成为新信任锚（明示） |
| A9 | 桌面审批端同机攻击（键盘记录/读窗体/合成输入/**同用户进程内存读取**——Windows 同用户无需管理员即可读同用户进程内存，K8-④） | 磁盘零 operator 秘密（交互式口令→内存态短时会话）；破坏性类**输入校验码**（Host 生成、仅窗口可见、单次有效、**Host 侧 3 次失败作废+60s TTL**——本地计数不可信）抬升门槛 | **明示出界**："诚实但好奇"**精确定义 = 仅文件系统读取**的 Agent，此威胁下零泄露；超出该定义（内存读取/UI 自动化/键盘记录）= 整机沦陷级，范围外 |
| A10 | RPC 认证爆破 | 继承 http.ts AuthFailureLimiter 失败限速模式 + `timingSafeEqual` 常时比较 + 令牌 ≥256bit 熵（M9） | 无 |

### 1.3 明确不解决（不变 + 补）

Host 机物理/管理员级沦陷；目标机侧 AAA；MCP 宿主恶意（治理在 Host 覆盖）；**整机恶意软件**（A9 出界声明）。

---

## 2. 目标架构

### 2.1 组件与进程拓扑（v2：审批面三载体，elicitation 移除）

```
┌─ Agent 机（不可信域）────────────┐      ┌─ Host 机（信任锚）────────────────────┐
│                                  │      │                                        │
│  MCP 宿主 ─stdio─► stub          │      │  agent-ssh host（守护进程）            │
│                     │ 出站 RPC   │◄────►│   ├─ RPC server（认证/令牌/会话）     │
│  （stub 纯单向：                   │      │   ├─ tools 管线 + policy/guard       │
│    tool.call/manifest/resource）  │      │   ├─ ssh/pty/forward 连接与通道      │
│                                  │      │   ├─ audit/转录（唯一落盘）           │
│  审批面 A：Tauri 桌面审批端 ──────┼─────►│   ├─ 审批队列状态机（唯一事实源）     │
│   （托盘+原生弹窗，Rust 核持会话） │      │   └─ 审批面 B：飞书 bot（长连接出站） │
│  审批面 C：CLI（approvals 等）────┼─────►│                                        │
└──────────────────────────────────┘      └───────────────┬────────────────────────┘
                                                          │ SSH
                                                          ▼
                                                    目标服务器
```

| 组件 | 形态 | 持有 | 绝不持有 |
|---|---|---|---|
| stub | MCP 宿主子进程 | Host 地址、agent 令牌（env/arg；**禁走 argv**，进程列表可见——D6 补充） | 凭证/策略/审计/ssh2 |
| Host | 守护进程（Windows 计划任务/手动，D5'） | 全部引擎 + 配置 + 审批队列 + bot token + operator 口令哈希 | —— |
| 桌面审批端 | Tauri 2 应用（`approver/` 子项目）：Rust 核（tokio：RPC 连接+会话令牌）+ Webview（仅渲染） | 内存态短时 operator 会话 | 磁盘上任何 operator 秘密；口令 |
| 飞书 bot | Host 进程内模块 | bot token（Host 侧） | —— |
| CLI | 按需进程 | 每次调用的交互式口令 | 磁盘秘密（脚本场景可显式 `--session-token` 经 stdin，明示风险） |

### 2.2 调用链（v2）

```
Agent 调工具：      宿主 ─MCP─► stub ─RPC tool.call─► Host 管线 ─策略─► ssh2 ─► 目标
审批（桌面，在电脑旁）：Host 入队 ─approval.pending 推送─► 桌面端弹原生窗 ─人点按钮─► approval.decide(operator 会话)─► 状态机
审批（IM，离开电脑）：Host 入队 ──飞书长连接出站──► 手机推送+内联按钮 ─人点─► bot 回传(单次决策令牌)─► 状态机
审批（兜底）：      CLI approvals list/approve/reject（交互式口令→会话）
多面仲裁：          三面同时收推送，先决定者生效；状态机"status 必须 pending"天然仲裁，后到者收"已决定"；飞书消息编辑为"已在桌面端批准"（D11）
CLI 直连执行：      agent-ssh run ─RPC cli.run(会话)─► Host（过分类+禁止名单，approver=cli-direct）
```

**elicitation 处置**：MCP 反向弹窗通道整体移除（H2 闭合手段）。MCP 宿主的 elicitation 能力闲置；审批 UX 全面由自有通道承担。stub 因此成为**纯单向客户端**——v1 的反向请求机制从协议中删除。

### 2.3 数据主责与状态

| 数据 | 位置 | 备注 |
|---|---|---|
| config.toml（凭证引用）| Host 机 | `keyRef` 若指向 keychain（机器+用户绑定）**迁机必断，须重录**（§7） |
| host key TOFU 库 | Host 进程内 Map + profile `trustedHostKey` 持久 | 进程内部分迁机后重放首连窗口（§7 明示） |
| 审批队列文件 | Host 机 | 唯一事实源；三审批面共用 |
| 审计 JSONL / PTY 转录 | Host 机 | 新增 `rpcCallerClass`（agent/operator）字段 |
| PTY/会话/转发状态 | Host 内存 | stub 崩溃/宿主重启会话存活（空闲/生存期兜底）；**语义披露**：会话为 Host 域，任何 agent 连接可 pty-list 并附着既有会话（个人多宿主=同人，预期行为；多人化时列为债务 §13-6） |
| 桌面审批端 | Agent 机 | 仅内存会话令牌 + 渲染态 |

---

## 3. RPC 协议规格 v0.2

### 3.1 传输与帧

- JSON-RPC 2.0 over TCP，`\n` 分帧；**单帧上限 4MB，进出同值**（主人裁决 v3，D12），超限断连并审计（防无界缓冲 DoS）。取值依据：最大合法截断工具响应实测 1,056,768B（full-chain.test.ts:87 注释原值）+ JSON 包装膨胀，及 `sftp-upload` 内联 content 的入站大参数——4MB 留一倍余量；T-14 边界测试钉死"最大合法响应过单帧"；
- Host 默认绑 `127.0.0.1`；绑定非环回地址时**强制 TLS，否则启动即拒**。环回判定复用 http.ts:277-357 的实现（含 IPv6 `::1`/`[::1]` 文法）；
- TLS：自签证书 + **部署时分发显式 pin**（`AGENT_SSH_HOST_PIN`，A7）；`host.hello` 回显证书指纹供带外核对；
- 保活：`host.ping` 双向；stub/审批端断线指数退避重连（上限后向宿主/托盘报错态）。

### 3.2 认证：静态令牌（agent）+ 会话令牌（operator）

**agent 类（静态）**：Host 初始化时生成（≥256bit），经 env `AGENT_SSH_TOKEN` 注入 stub。**设计内允许 Agent 读取**——权力被 §3.3 矩阵包裹。

**operator 类（会话制，D1'）**：无静态 operator 令牌。`auth.session.start {password}` → Host 验证（**Node 内置 `crypto.scrypt`**+盐 哈希比对，`timingSafeEqual`，失败限速——零新依赖，v3 裁决 D13）→ 换发**内存态会话令牌**（默认 TTL 30min 滑动续期，进程退出即灭）。桌面端/CLI 用之。

**类别判定（M3）**：服务端按凭据查表判定类别——agent 静态令牌表 / operator 会话表 / IM 绑定表。请求里的 `class` 字段**仅作展示，不作判定**。谎报类别=按真实凭据判。

**IM 决定（A8）**：bot 通道不走会话制——决定消息携带 per-request 单次消费决策令牌（Host 入队时生成、绑定 id+指纹、仅随该次推送下发）。

### 3.3 方法×凭据矩阵（红线执行点）

| 方法 | agent 令牌 | operator 会话 | IM 决定令牌 | 说明 |
|---|---|---|---|---|
| `host.hello` / `host.ping` | ✅ | ✅ | — | 版本握手/保活 |
| `host.toolManifest` | ✅ | ✅ | — | 23 工具 + **resources 段 + 工具描述哈希**（保住 dumpToolHashes 纪律，D3 补充） |
| `tool.call` | ✅ | ✅ | — | MCP 工具语义原样 |
| `resource.list` / `resource.read` | ✅ | ✅ | — | 3 个 MCP 资源透传 |
| `auth.session.start` | ❌ | ❌（凭口令；无凭据态放行，agent/operator/IM 凭据一律拒） | — | 失败限速 + 常时比较（v3.1 勘误：原与 renew 合行致 renew 语义含混） |
| `auth.session.renew` | ❌ | ✅（凭现有会话，滑动续期） | — | 与 §3.2 滑动 TTL 自洽（v3.1 勘误） |
| `approval.subscribe` | ❌ | ✅ | — | 订阅 `approval.pending` / `approval.settled` 推送 |
| `approval.list` | `FORBIDDEN` | ✅ | — | agent 类调用 → `-32002` + 审计（**红线测试钉死**） |
| `approval.decide` | `FORBIDDEN` | ✅ | ✅（单次消费） | 指纹不匹配拒绝（沿用） |
| `cli.run` / `cli.info` | `FORBIDDEN` | ✅ | — | approver=cli-direct；过分类+禁止名单 |
| `host.admin.rotateToken` | `FORBIDDEN` | ✅ | — | 在线轮换 agent 令牌（M9 收口，不后拖 P2） |

矩阵红线测试 = **全方法 × 凭据态 7 态**（agent / operator / 无凭据 / 已过期会话 / 谎报 class / IM 决定令牌 / 已轮换旧令牌）枚举断言；**JIT 审批授权仅经 operator 决定派生，协议无独立"创建授权"方法**（K8-⑥ 暗门断言：反射枚举全部方法 × agent 令牌，断言无 grant/approve 语义可达）。

### 3.4 stub 启动期 Host 不可达（M5 定义）

stub 先完成 MCP `initialize`（零工具），后台退避重试 `hello`+manifest；成功后注册 23 工具并发 `tools/list_changed`。Agent 在窗口期看到的是**空工具集**（可发现的诚实状态），而非假工具或挂死。Host 重启 → stub 重连重拉 manifest；**单连接内 manifest 不可变**，变更仅经 Host 重启+重连（D3 不变量）。

### 3.5 失效语义（fail-closed 全表，v2 补全 6 项）

| 故障 | 行为 |
|---|---|
| stub 连不上 Host | 工具不可达（§3.4）；**绝不本地降级**（结构性保证） |
| Host 重启 | SSH 会话消亡（同现架构）；队列 pending 保留；审批端/stub 自动重连 |
| stub 崩溃 | Host 侧会话按超时回收；Agent 重连续用（§2.3 语义披露） |
| **Host 不在线** | **产品整体不可用**（工具/审批/CLI 全灭）——不保留直连的唯一代价，明示于 README + D5' 自启方案 + `host.ping` 健康检查一行命令（H6） |
| TLS 握手失败 / pin 不匹配 | 即断，错误对齐 HOST_KEY_PIN_MISMATCH 措辞；不降级不重试明文 |
| manifest 拉取中途断连 | 放弃本次，退避重试；零工具状态保持 |
| 时钟回拨 | 审批窗口判定用单调钟（performance.now 基准），墙钟仅用于审计展示 |
| Host 双实例竞态 | pidfile/文件锁单实例强制，二次启动 fail-fast（D5' 补充） |
| 反向推送途中断连（审批面） | 该面错过此请求不影响他面；重连后 `approval.list` 补偿 |
| 认证失败风暴 | AuthFailureLimiter 限速（继承 http.ts 模式） |
| 协议版本不匹配 | `host.hello` 显式拒绝（错误码+双方版本）；升级顺序：先 Host 后 stub/审批端（会话全灭预告写入 runbook，D5'） |

### 3.6 协议版本化

`protocolVersion` 语义化，独立于 npm 版本；同仓同发布。**契约夹具防漂移**：`test/fixtures/rpc/*.golden.json` **由 TS 协议类型单测生成、Rust 侧只消费**（K6 归属 T-14 验收；Rust CI 触发对拍）——TS/Rust 双实现的单一事实源（Tauri 裁决的连带要求）。

---

## 4. 审批面设计（D8，v2 新增）

### 4.1 桌面审批端（Tauri 2，D9）

- **结构**：Rust 核（tokio：RPC 连接、会话令牌、托盘、原生通知）+ Webview（仅渲染，经 Tauri command 取数据/回决定，**秘密不进 JS 上下文**）；
- **认证**：启动/解锁时交互式输 operator 口令 → `auth.session.start` → 内存态会话（30min 滑动）；锁屏/超时回锁；
- **窗口**：profile、类别、**完整命令全文**（等宽）、指纹短形、过期倒计时；多请求堆叠；[拒绝] [批准]；**破坏性类默认启用输入校验码**（D10：Host 生成 4 位码，仅窗口可见、单次有效——挡 UI 自动化点击）；
- **常驻**：托盘图标显未决数；Windows 登录自启（Tauri autostart 插件，可选）；原生 toast 通知；
- **产物**：`approver/` 子项目（独立构建，NSIS 安装包 ~10MB 级；需 Rust 工具链）。

### 4.2 飞书 bot（离开电脑，D8-A）

- Host 进程内模块，**官方 SDK（`@larksuiteoapi/node-sdk`，主人裁决 v3/D13）长连接（WebSocket 客户端）纯出站**——NAT 免疫、零入站暴露；内联按钮走 SDK 的交互卡片回调（自实现该面是 bug 窝点，弃自实现路线）；
- 模块纪律（K5）：独立 error domain（未捕获异常不得拖垮 Host）+ 异步非阻塞启动；bot token 落 Host 配置（0600）；**主人侧外部前置**：飞书开放平台应用申请（T-17.6 开工条件）；
- 失效语义（K5）：WS 断开 / token 失效 / 出站被防火墙挡 → Host 审计一条 `im.unreachable` + 桌面端托盘显示"IM 面离线"（审批不静默丢失，CLI 队列兜底仍在）；
- 入队时推送：profile/类别/完整命令（**明示代价**：命令全文经飞书服务器；脱敏档位可配：全文/截断+类别，默认全文——裁决依据完整性优先；**截断档必须叠加 redactor 脱敏**，截断≠脱敏，命令常含内嵌凭证）/过期时间 + 内联按钮；
- 决定回传绑定 per-request 单次消费令牌（A8）；已在他面决定 → 消息编辑为"已在桌面端批准"；
- bot token 只存 Host；运维要求：飞书账号开两步验证（写入 README）。

### 4.3 CLI（兜底）与 JIT 预授权（补充手段）

- `agent-ssh approvals list/approve/reject`：交互式口令→会话，语义同现（全文展示、指纹校验、decidedBy 入审计 `approver=cli:`）；
- **10min 窗口不动**（U3 裁决维持）：人不在且没看到推送 → 过期 fail-closed → Agent 收结构化拒绝可重发。移动/桌面通道的价值是"看得到就来得及批"，不是无限期等人；
- **计划内离开**用既有 `approvalGrantTtlMs` JIT 预授权（绑定命令+profile+类别）提前放行，与实时通道互补。

### 4.4 approver 字段语义

`approver` 取值扩展：`desktop:<os 用户>` / `im:<飞书 user_id>` / `cli:<用户>`（现有）；operator 会话与 IM 绑定均 Host 侧登记。

---

## 5. 位置语义重定义（H1 裁决 a）

| 工具 | v1 语义 | v2 语义（Host 机侧） | 处置 |
|---|---|---|---|
| `sftp-upload-file` / `sftp-download-file` | `localPath` = 服务进程本机 transferRoot 内 | **= Host 机 transferRoot** | 工具描述如实改写；**Windows Host 上本就禁用（上游 ACL 限制）明示**；Agent 机↔Host 机文件搬运需求列 P2（协议 v2 文件流，债务 §13-7） |
| `forward-open` local/dynamic | 监听开在服务进程侧 | **监听开在 Host 机**（Host 机经目标机隧穿，仍有真实用途） | 描述改写 |
| `forward-open` remote | 目标机监听 | 不变 | — |

需求包 R2 中"Agent 经本机转发/上传下载"的能力预期相应收窄为 Host 机侧——登记为契约微调（M8 治理项）。

---

## 6. 模块迁移映射（v2 修正版）

| 现模块 | 去向 | 要点 |
|---|---|---|
| `policy/ guard/ audit/ ssh/ pty/ forward/ devices/ config/` | Host 原样迁入 | 零语义改动 |
| `tools/` | Host | 注册改向 manifest 登记（含 resources + 描述哈希） |
| `guard/elicitation.ts` | **删除** | elicitation 通道移除；审批走 §4 三面。管线中 elicitation 分支删除，`approvalChannel` 配置改为面集合 `['desktop','im','queue']` |
| `transport/http.ts` | **删除** | 连带：http 系测试 ~90 例**删除并登记**；`packaging.e2e.test.ts:151` bearerToken 断言同步移除（评审 H5 点名的隐性依赖）；AuthFailureLimiter/环回判定/帧上限模式**搬入 rpc/** 后再删 |
| `index.ts` | 重写为 Host 装配 | **继承资产**（M6 修正）：60s 回收器（回收顺序承重）与停机梯（审计先行冲刷 + kill 阶梯）整体搬入 Host；stub 入口另行新建 |
| `cli.ts` / `cli-direct.ts` | CLI 重写连接层 | 直连代码删除；operator 会话认证（D1'） |
| `observability/tracer.ts` | Host | 既有 span 不变 + `rpc.request`（含 callerClass）；审批面事件 span（approval.push/decide 已有 decide） |
| （新增）`rpc/` | Host+stub 共用 TS | 帧/认证/矩阵/会话/推送分发 |
| （新增）`stub/` | stub | 纯单向：hello→manifest→注册透传；§3.4 启动机 |
| （新增）`approver/` | **Tauri 2 子项目（Rust+TS 前端）** | §4.1；Rust RPC 客户端 + 契约夹具消费 |

**依赖边界强制**（红线③可实现化，评审建议采纳为无新工具链方案）：vitest 单测解析 `stub/*.ts` 的 import 语句对照白名单断言（不引 dependency-cruiser）；Host 侧 ssh2 正常。

**首次引导流（M7）**：`agent-ssh host init` —— 生成配置骨架 → 生成 agent 令牌（打印待注入 env）→ 交互式设置 operator 口令（哈希落 Host 配置）→ 可选生成自签证书+打印 pin。五步串联文档化；operator 凭据"鸡蛋问题"由 init 时本机交互解决（此刻 Host 尚未监听公网）。

---

## 7. 切换（cutover）数据清单（H4 补全，路径以实码为准）

| 数据 | 现位置（实码核对） | 迁移动作 |
|---|---|---|
| config.toml | `%APPDATA%\ssh-mcp\config.toml`（**ssh-mcp 名**） | 拷至 Host 机同路径；**keychain 型凭证必断，Host 机重录**（@napi-rs/keyring 机器+用户绑定） |
| 私钥/env 凭证 | Agent 机各处 | 私钥文件拷 Host 机（权限收紧）；env 级联改在 Host 机注入 |
| host key TOFU | 进程内 Map（不持久）+ profile `trustedHostKey` | profile pin 随 config 走；TOFU 部分**重放首连窗口**（人肉确认一次，明示） |
| 审计 JSONL / PTY 转录 | 本机 audit 目录（ssh-mcp 布局） | 可搬可不搬（明示"不迁移=历史留在 Agent 机"）；新记录只在 Host |
| 审批队列 | `%LOCALAPPDATA%\agent-ssh\approvals`（agent-ssh 名） | pending 无需迁移（过期语义）；目录建制由 Host 新建 |
| config `approvalChannel` 值域 | 现值域 `['elicitation','queue','both']` 默认 both（schema.ts:155） | **K1：旧值（elicitation/both）在新值域下 Host 起不来**——zod 显式拒绝 + 错误信息附迁移指引（如 `both`→面集合），**不得静默映射**；T-15 迁移测试钉死 |
| MCP 宿主配置 | 各宿主 mcp 配置 | spawn 命令改为新 bin 名（D14：ssh-mcp→agent-ssh）+ 追加 env（`AGENT_SSH_HOST_ADDR/TOKEN`）——T-19 主人侧操作项 |

---

## 8. 可用性与运维（H6 补全）

- **明示**：Host 不在线 = 产品全灭（工具/审批/CLI）；README 置顶 + `host.ping` 一行健康检查；
- D5'：首版手动 `agent-ssh host` + **Windows 计划任务开机自启文档**（NSSM/WinSW 备选）；pidfile 单实例；升级顺序 runbook（先 Host，会话全灭预告）；
- 性能：本地 loopback 一跳可忽略；远端 Host 首字节 +1 RTT，PTY 交互实测吞吐基线列入 T-19 验收。

---

## 9. 验证覆盖（H5 修正：分层口径 + 基线冻结）

| 层 | 口径 |
|---|---|
| Unit（in-process 保留） | 现有 unit 78 文件（名义 78/33/7；qa 实测可跑 76/30/6，差异为环境跳过——**口径以基线冻结清单为准**，K9 口径标注）；**保持原样**（PolicyEngine 直调等无理由双进程化）；新增：rpc 帧/矩阵/会话/重连；Rust 侧 `cargo test`（审批端）+ 契约夹具两侧对拍 |
| Integration/E2E（双进程化） | integration 33 文件 + e2e 7 文件 + `test/e2e/harness.ts`（唯一 spawn 接缝）+ legacy spawn 3 文件改经 stub→Host；http 系 ~90 例**删除并登记**（含 packaging:151） |
| 红线四项 | ①矩阵枚举（§3.3 全方法×凭据态，含谎报 class）；②stub 无凭证断言 = env 白名单 + 日志正则 +（抽验级）heap snapshot；③stub 无 ssh2 = import 白名单单测；④IM/桌面决定跨请求重放必拒 + 单次消费 |
| 基线冻结 | 开工前把当前失败集（文件×用例×定性）存 `docs/reports/`；判据 = **同语义映射后失败集不扩大**（删除项单列） |
| 双进程 harness | 端口分配/进程树清理/就绪探测/per-test 状态隔离/TLS 夹具——随 T-14.5 垂直切片票落地（评审 M1） |
| 抽验 | 真实 Linux 复跑六步链路（经 stub→Host）；T-08 四厂商仍挂起 |

---

## 10. 风险覆盖（增量行）

| 类 | 要点 |
|---|---|
| Security | §1.2 攻击树 A1-A10（新增 A8 IM 信任锚 / A9 同机桌面出界声明） |
| Availability | §8（H6 全套） |
| Performance | §8 吞吐基线 |
| State | §2.3（会话跨 stub 存活的语义披露） |
| 治理链 | 旧方案标"已被取代"（本次已加）；需求包三处失效项在 §取代声明 登记；Compliance 门沿用旧方案记录 |
| 供应链 | **v2"零新依赖"声明作废（K2，v3 改写）**：新增面 = 飞书官方 SDK（Host 侧运行时依赖，显式声明入 package.json）+ Tauri/Rust 依赖树（**Cargo.lock 入库 + cargo-deny 策略**）+ NSIS 安装分发面；口令哈希用 Node 内置 scrypt（不引 argon2）；帧/JSON-RPC 仍自实现零依赖；上游安全通告跟踪不再适用传输层（分叉弃用） |

---

## 11. 任务拆解（v2 定稿票表）

| 票 | 任务 | 验收要点 | 阻断边 |
|---|---|---|---|
| T-14 | RPC 协议层 | 帧（4MB 上限/非法输入/**最大合法截断响应 1,056,768B 过帧边界测试**）/agent 令牌/operator 会话（scrypt+限速+常时比较）/方法×凭据矩阵（**7 态**，含 JIT 暗门断言）/推送分发/重连退避/hello 版本握手/环回判定+非环回拒明文（**无 pin 时 fail-closed 拒连**，K8-①）/pin 一票否决；golden.json 夹具由 TS 单测生成（K6）；单测全绿 | — |
| T-14.5 | **垂直切片 + 双进程 harness** | 1-2 工具真链路（最小 Host 装配+stub 透传）；harness 五件套（端口/清理/就绪/隔离/TLS 夹具）+ **双进程用例超时预算**（vitest 默认 5s 不够，K9-⑤） | T-14 |
| T-15 | Host 进程装配 | 引擎迁入（**继承回收器+停机梯**）；manifest（resources+哈希）；rpcCallerClass 审计；**队列决定按 id 串行化（K7：现 decideApproval 为非原子读-判-写）+"并发双决定仅一生效"用例**；approvalChannel 旧值显式拒绝+迁移指引（K1 测试）；守护日志去向与轮转（Windows 计划任务下 stdout 可见性）；`host init` 引导；pidfile 单实例；http.ts 删除（连带 http 系测试+packaging:151 登记） | T-14.5 |
| T-16 | stub 前端 | a) fake-Host：hello/manifest/§3.4 启动机/断连 fail-closed/无 ssh2 断言；b) 真 Host：23 工具透传+resources | T-14.5（b 需 T-15） |
| T-17 | CLI 改造 | approvals/run/info 经 RPC（口令→会话）；旧直连删除 | T-14 |
| T-17.5a | **桌面端骨架**（K3 拆票） | cargo 工程+Rust RPC 客户端+契约夹具对拍（Rust CI job）；无 UI | T-15 |
| T-17.5b | **桌面端审批闭环** | 口令→会话+弹窗（完整命令**纯文本渲染 textNode+锁 CSP+零远程内容**，K8-③）+决定+**校验码 Host 侧 3 次失败作废+60s TTL**（K8-②，桌面端本地计数不可信）；会话令牌 zeroize 纪律（K8-⑦） | T-17.5a |
| T-17.5c | **桌面端常驻化** | 托盘（含"IM 面离线"在线态）/自启/锁屏/NSIS 分发 | T-17.5b |
| T-17.6 | **飞书 bot（P1：D1' 下为 UX 增强非安全必需）** | 官方 SDK 长连接出站；推送+内联按钮；**IM 决策令牌 ≥128bit + user_id ∈ 绑定表校验**（群聊防他人代点，K8-⑤）；跨面仲裁+消息编辑；**外部前置：主人申请开放平台应用**；失效语义（§4.2 K5） | T-15 |
| T-18a | 入口切换+传输废止 | 默认入口切 stub；**bin 改名 ssh-mcp→agent-ssh（D14，随破坏性变更一并做）**；stdio 直连路径删除；删测数登记；forward-open 结果文本标注"Host 机"；http 旗标清理与 --dumpToolHashes 存废处置 | T-15/16/17 |
| T-18b | 测试迁移+红线改写（**K4 解绑：仅挂 T-18a**） | e2e/边界 integration 双进程化（隔离粒度=**per-file 复用 Host + per-test mkdtemp**，K9-④）；红线四项全绿（④含**重放+过期+单次消费三断言**与并发双决定用例；审批面自身验收下放 T-17.5b/17.6）；基线冻结对照；时钟回拨不延长窗口用例；import type 豁免与传递依赖口径定义（T-16a 可判前提，K9-⑨） | T-18a |
| T-19 | 收口+主人迁移 | localhost E2E + 真实 Linux 复跑（**前提清单：目标机/账号**，K9-⑧）；吞吐基线；README/SECURITY/DEVICE-ONBOARDING/init runbook（含零审批面配置的静默行为明示、宿主 tools/list_changed 支持差异说明）；**主人宿主 env 切换+真实验收** | T-18b |
| T-20 / T-21a-g | Host 桌面化（控制台托管，已实施）与桌面控制台 v2（五视图+宿主接入） | **规格源=docs/designs/2026-10-17-桌面控制台-v2-设计.md**（本表不复制票面，避免双源）；T-20 已实施（a4c971a） | — |

---

## 12. 决策记录（全部已裁决）

| # | 决策 | 裁决 |
|---|---|---|
| H1 位置语义 | 三选一 | **a**：Host 机侧语义+描述改写（主人同意） |
| D1' 操作员通道 | 修正版 | operator 面 = 桌面审批端 + 飞书 bot + CLI（**任意机器可跑，含 Agent 机**——交互式口令→内存会话，磁盘零秘密）；**无静态 operator 令牌**；红线由拓扑+凭据分离保证（主人同意，含移动审批需求） |
| D2 链路加密 | — | **a** 自签+部署时分发 pin（H3 修复并入） |
| D3 manifest | — | hello 后拉取+版本字段；含 resources+描述哈希；单连接内不可变 |
| D4 cli.run 姿态 | — | 维持现状语义；**标注 D4←D1' 依赖已满足**；hostKeyMode 改继承 Host（语义变化明示：对人工更安全） |
| D5' Host 守护 | — | 首版手动+计划任务自启文档；pidfile；升级 runbook；host.ping 健康检查 |
| D6 stub 注入 | — | env 为主 + `--host-addr`；**token 禁走 argv**；`AGENT_SSH_HOST_PIN` 并入；地址文法（含 IPv6）与优先级定义 |
| D7 多连接 | — | 多 stub 连接；无 elicitation 路由问题（通道已删）；连接数+在途上限（对齐 MAX_SESSIONS=64 先例）；JIT 授权跨连接共享、配额全局单池——均披露为预期语义 |
| D8 审批面 | — | 飞书 bot（A）+ 桌面审批端 + CLI 兜底；elicitation 移除（取代 R6 半边）；10min 窗口维持 |
| D9 桌面端技术栈 | — | **Tauri 2**（主人裁决，否决 Electron 建议）；Rust 核持密；契约夹具防 TS/Rust 漂移 |
| D10 校验码 | — | 破坏性类默认启用 |
| D11 双推送 | — | 不抑制；飞书消息编辑标注"桌面端已连接/已批准" |
| D12 帧上限（v3） | 二轮评审规格级冲突三选一 | **a：进出统一 4MB**；边界测试（最大合法截断响应 1,056,768B 过帧）入 T-14 |
| D13 飞书连接（v3） | SDK vs 自实现 WS | **官方 SDK**（`@larksuiteoapi/node-sdk`）；连带：口令哈希用 Node 内置 scrypt，不引 argon2 |
| D14 bin 改名（v3） | 文档 agent-ssh vs 实码 bin ssh-mcp 不一致 | **改名 agent-ssh**，随 T-18a 入口切换执行（破坏性变更一并做） |

## 13. 债务清单（个人使用假设，多人化触发）

沿用评审记录 §5 八项，新增：**§13-9 TS/Rust 协议双实现**——契约夹具对拍为过渡手段，多人化/协议 v2 时考虑 codegen（JSON Schema → 双语言）。

## 14. 术语表

| 术语 | 指 |
|---|---|
| 宿主 | MCP 宿主应用（dsh/omp/Claude Code…），spawn stub 的那方 |
| Host | `agent-ssh host` 守护进程（信任锚） |
| stub | `agent-ssh` MCP 前端进程（纯单向客户端） |
| 审批面 | 批准/拒绝的三个操作员载体：桌面审批端 / 飞书 bot / CLI |
| 位置语义 | "localPath / local 转发监听"相对哪台机器（本方案：Host 机） |
