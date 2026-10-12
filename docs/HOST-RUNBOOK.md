# agent-ssh Host Runbook（部署·升级·迁移）

> 面向：部署与运维 agent-ssh Host 分离架构（v2）的工程师。
> 架构速览：**stub**（`agent-ssh` 默认入口，纯单向 MCP 前端，零凭证）→ RPC（JSON-RPC 2.0 over TCP，\n 分帧 4MB）→ **Host 守护**（`agent-ssh host serve`，持 SSH 凭证+审批面+审计）。
> **铁律：Host 不在线 = 产品全灭。** stub 零工具诚实态，绝不本地降级。

## 一、首次部署（host init 五步）

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
   **keychain 凭证需重录**（条目命名空间随包名变更）。
2. **宿主配置**：MCP 宿主 spawn 命令 `ssh-mcp` → `agent-ssh`，补 env 三件（HOST_ADDR/TOKEN/HOST_PIN，见上节③）。
3. **TOFU 首连**：Host 守护是**新进程**——主机密钥信任不跨进程保留，首连需重新确认（或 profile `trustedHostKey` 显式固定——唯一跨重启手段）。
4. **审批面**：`approvalChannel` 配置键已废止（v2 审批面=Host config `approvalSurfaces`）；elicitation 依赖随 stub 移除，审批走队列/桌面端。
5. **HTTP 传输**：已整体废止（`--transport=http` 显式报错）；远程场景=Host 监听 + 反向代理 TLS（骨架明文环回，TLS 夹具随 T-17.5b pin 路径）。

## 四、宿主 tools/list_changed 支持差异

MCP 宿主对 `notifications/tools/list_changed` 的支持不一：

- stub 在**与 Host 的 manifest 拉取失败/恢复**时向宿主发 `tools/list_changed`（连接态切换：连上=23 工具，断开=空集诚实态）；
- 不支持该通知的宿主：工具列表停留在连接时刻——Host 宕机后工具仍在列表但调用必拒（fail-closed 错误，非假成功）；
- 验证方法：断 Host → tools/list 应为空集（支持 list_changed 的宿主）或调用报 Host unreachable（不支持者）——两者都是诚实语义。

## 五、故障速查

| 症状 | 原因 | 处置 |
|---|---|---|
| stub 启动即退：`AGENT_SSH_HOST_ADDR is required` | 宿主 env 缺地址 | 补 env（③） |
| stub 循环 `connect failed (retrying)` | Host 未启动/端口错 | 起 `host serve`，对准就绪行端口 |
| `CHALLENGE_REJECTED` | 破坏性 decide 码错/过期（60s TTL/3 败作废） | 重新拉 pending 取新码 |
| `pidfile` 占用 | 旧守护未退/僵死 | 清 pidfile 或杀旧进程树 |
| config ACL 拒绝 | 配置目录权限过宽 | 按提示 icacls 两条命令收紧 |
