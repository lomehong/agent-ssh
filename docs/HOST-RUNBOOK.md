# agent-ssh Host Runbook（部署·升级·迁移）

> 面向：部署与运维 agent-ssh Host 分离架构（v2）的工程师。
> 架构速览：**stub**（`agent-ssh` 默认入口，纯单向 MCP 前端，零凭证）→ RPC（JSON-RPC 2.0 over TCP，\n 分帧 4MB）→ **Host 守护**（`agent-ssh host serve`，持 SSH 凭证+审批面+审计）。
> **铁律：Host 不在线 = 产品全灭。** stub 零工具诚实态，绝不本地降级。

## 一、首次部署（host init 五步）

> 术语注记：此处「五步」指部署动作五步；方案 §6 另有「init 产物五件套」（含证书/pin 件）——
> CLI 当前实现①②③（config/token/口令哈希），证书与 pin 件随 TLS 夹具补齐（T-17.5b pin 路径）。

```bash
# ① 生成配置骨架 + agent 令牌（令牌仅此一次打印——丢失重跑 init 轮换）
AGENT_SSH_OPERATOR_PASSWORD='<≥8字符口令>' agent-ssh host init

# ② 启动 Host 守护（常驻；pidfile 单实例强制）
AGENT_SSH_TOKEN='<①打印的令牌>' agent-ssh host serve        # --port=0 缺省 OS 分配
#   就绪行：host-rpc-ready port=<N>（stderr）

# ③ 宿主（Claude Code / Cursor 等）接 stub——spawn 命令与 env：
#   command: agent-ssh            （默认入口=stub，stdio）
#   env: AGENT_SSH_HOST_ADDR=127.0.0.1:<②的端口>
#        AGENT_SSH_TOKEN=<①的令牌>
#        AGENT_SSH_HOST_PIN=<可选，传输层 PIN（如启用）>

# ④ 健康检查
#   宿主侧任意工具调用前可 ping（host.ping，agent 面允许）；
#   stub 层面 tools/list 返回 23 工具=链路通；返回空集=未连上（诚实态）。

# ⑤ 审批面（可选）：队列面默认开（破坏性命令落文件队列）；
#   决定：agent-ssh approvals list / approve <id> / reject <id>
#   桌面端（Tauri 壳）收 approval.pending 推送携校验码决定。
```

安全红线：令牌经 **env** 注入（绝不经 argv——`ps` 泄露面）；配置文件 ACL 仅属主可写（Host 启动强制校验）。

## 二、升级顺序（先 Host 后 stub）

1. **预告**：升级窗口内所有 agent 会话将全灭（stub 连不上旧 Host 即 fail-closed）——提前通知使用方。
2. **先升 Host**：停旧守护（SIGTERM→停机梯）→ 换新二进制 → `host serve`（配置兼容则免 init；破坏性变更见 CHANGELOG）。
3. **再升 stub**：更新 npm 包（宿主重启即生效）。
4. **验证**：`host.ping` + tools/list 23 工具 + 一次破坏性命令走审批闸门。

## 三、从 v1（ssh-mcp）迁移清单（主人侧操作）

1. **config 拷贝**：`%APPDATA%\ssh-mcp\config.toml` → 同路径继续用（目录名未改，数据安全）；
   **keychain**：同机同用户迁移**无需重录**（credential-resolver 的 service 命名空间未随包名变更，
   缺省前缀仍 `ssh-mcp`）；跨机/跨用户才需重录——条目与机器+用户绑定（DPAPI/Keychain 语义），非包名所致。
2. **宿主配置**：MCP 宿主 spawn 命令 `ssh-mcp` → `agent-ssh`，补 env 三件（HOST_ADDR/TOKEN/HOST_PIN，见上节③）；
   stub 亦接受 `--host-addr=host:port` 旗标（等价 env，二选一）。
3. **TOFU 首连**：Host 守护是**新进程**——主机密钥信任不跨进程保留，首连需重新确认（或 profile `trustedHostKey` 显式固定——唯一跨重启手段）。
4. **审批面**：`approvalChannel` 配置键已废止（v2 审批面=Host config `approvalSurfaces`）；elicitation 依赖随 stub 移除，审批走队列/桌面端。
   **零审批面注意**：`approvalSurfaces` 不含任何可达面（如只有 `im` 且飞书面未接）时，破坏性命令一律
   `APPROVAL_UNAVAILABLE` 拒绝——配置不静默降级，是 fail-closed 设计（评审 T-19 硬违规 3 补录）。
5. **HTTP 传输**：已整体废止（`--transport=http` 显式报错）；远程场景=Host 监听 + 反向代理 TLS（骨架明文环回，TLS 夹具随 T-17.5b pin 路径）。

## 四、宿主 tools/list_changed 支持差异

MCP 宿主对 `notifications/tools/list_changed` 的支持不一：

- stub 在**与 Host 的 manifest 拉取失败/恢复**时向宿主发 `tools/list_changed`（连接态切换：连上=23 工具，断开=空集诚实态）；
- 不支持该通知的宿主：工具列表停留在连接时刻——Host 宕机后工具仍在列表但调用必拒（fail-closed 错误，非假成功）；
- 验证方法：断 Host → tools/list 应为空集（支持 list_changed 的宿主）或调用报 Host unreachable（不支持者）——两者都是诚实语义。

## 五、飞书 bot 审批面（[im]，T-17.6）

离开电脑时的审批通道：Host 经官方 SDK（`@larksuiteoapi/node-sdk`）**长连接纯出站**推送交互卡片（NAT 免疫、零入站暴露），点卡片按钮即决定；破坏性类需输入卡片下发的校验码。**运维前提：飞书账号开启两步验证**（IM 账号即审批身份）。

**配置（Host 配置文件内，0600 纪律随 config 全局检查）**：

```toml
[defaults]
approvalSurfaces = ["desktop", "im", "queue"]   # im 要求 queue 同在（队列是唯一等待机制）

[im]
appId = "cli_xxx"
appSecret = "…"                  # 仅存 Host 配置，不出 Host 机
allowedUsers = ["ou_xxx"]        # open_id 绑定表：卡片点击者必须在内
# chatId = "oc_xxx"              # 可选：推送到群；缺省私聊 allowedUsers[0]
# commandDetail = "truncated"    # 缺省 full=命令全文（经飞书服务器）；truncated=截断+脱敏
```

**开放平台侧四步**（一次）：① 权限管理开启 `im:message` 系（含 `以应用身份发消息`）；② 事件与回调 → 订阅方式 = **长连接**（已验证可用）；③ 事件与回调 → 添加事件 `im.message.receive_v1` 与卡片交互回调；④ 可用范围加入自己并发布版本。**获取自己的 open_id**：给 bot 发一条消息，Host 日志打印 `im.message from open_id=ou_…`，填入 allowedUsers 即完成闭环。

**失效语义（K5）**：WS 断开/token 失效 → 审计 `im-unreachable` + Host 日志 `im.unreachable`；审批不丢失（队列+CLI 兜底仍在）；Host 重启后自动补发存量未决卡片。**审计落点提示**：Host 审计写在**配置文件旁**（`<config>.audit.log`），平台目录旧 `audit.log` 是单体时代遗留。

## 六、桌面控制台（T-20/T-21）

`agent-ssh 控制台`（Tauri 桌面应用）是 Host 的推荐运行形态：**启动即托管拉起 Host**（supervisor
探活/崩溃自愈/随退而停），开机自启即 Host 在——「忘启 Host=全灭」结构性消除。五视图：审批（队列流）、
历史审批（`approval.history`）、审计日志（`audit.query`，含轮转序列归并）、连接与配额、设置（自启开关/
口令轮换/审批面状态/**宿主接入**）。部署描述 `%APPDATA%\ssh-mcp\desktop.json`（nodePath/hostEntry/
configPath/port/token，0600）是控制台与 start-host.cmd 的单一事实源。宿主接入=一键向本机 Agent 宿主
（omp/Claude Code/Cursor/opencode/Codex/Gemini）写入 agent-ssh MCP 条目（结构化改写+自动备份+回读
校验+回滚；写入后重启对应宿主生效）。历史审批流水在桌面控制台/`approval.history`（`approvals list`
CLI 仅看 pending）。

## 七、故障速查

| 症状 | 原因 | 处置 |
|---|---|---|
| stub 启动即退：`AGENT_SSH_HOST_ADDR is required` | 宿主 env 缺地址 | 补 env（③） |
| stub 循环 `connect failed (retrying)` | Host 未启动/端口错 | 起 `host serve`，对准就绪行端口 |
| `CHALLENGE_REJECTED` | 破坏性 decide 码错/过期（60s TTL/3 败作废） | 重新拉 pending 取新码 |
| `im.unreachable`（日志/审计） | 飞书 WS 断开、token 失效或出站被挡 | 审批未丢（队列兜底）；查网络/凭证后重启 Host 自动补发 |
| `pidfile` 占用 | 活守护在跑（正常单实例）或陈旧 pidfile | **陈旧 pidfile 自动接管，勿手清**——活进程下手清会绕过单实例→双守护风险；先确认无 `host serve` 进程再动 |
| config ACL 拒绝 | 配置目录权限过宽 | 按提示 icacls 两条命令收紧 |
