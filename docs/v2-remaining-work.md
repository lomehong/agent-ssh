# SSH MCP v2 — 剩余工作 / TODO

> 更新于 2026-08-08。Backlog 已关闭——剩余两项有意推迟到 v2.1。

---

## 已完成（15 项）

| 项 | 日期 | 说明 |
|-------|-------|----------|
| WD-1 | 2026-07-11 | OS 密钥链接线（`initKeychain()`） |
| WD-2 | 2026-07-11 | ProxyJump 接线（`via` 字段 → `forwardOut`） |
| WD-3 | 2026-07-11 | SSH CA 证书接线（`cert` → 自动探测 `-cert.pub`） |
| WD-4 | 2026-07-11 | OPA 文档 + README 更新 |
| P1-A | 2026-07-11 | 进度通知（500ms 节流，字节数 + stdout 尾部） |
| P1-B | 2026-07-11 | 取消处理器（AbortSignal → stream signal） |
| P1-C | 2026-07-11 | MCP Resources（`ssh://connections`、`ssh://connections/{profile}`、`ssh://sessions/{profile}/{session}`） |
| P2-H | 2026-07-11 | HTTP 限流（令牌桶，MCP 感知的 429 + Retry-After，1MB 请求体上限） |
| P2-J | 2026-07-11 | CI 中的 CodeQL（security-extended + security-and-quality） |
| P2-M | 2026-07-11 | 合规映射（SOC 2、PCI-DSS、ISO 27001、HIPAA） |
| P2-N | 2026-07-11 | 工具描述哈希（`--dumpToolHashes`，随发布产物输出） |
| **P2-C** | 2026-08-08 | **OTEL 追踪** — `src/observability/tracer.ts`、`--otelEndpoint` / `--otelServiceName`；span 覆盖 connection、session 与 policy 三层。依赖已显式声明（`@opentelemetry/resources`、`semantic-conventions`——此前仅靠 npm 提升才碰巧能解析） |
| **P2-I** | 2026-08-08 | **changesets 发布管线** — 添加 major changeset（`changeset status` → 2.0.0）、`changesets.yml` workflow、README 迁移章节、针对已移除 v1 标志的启动守卫 |
| **P2-L** | 2026-08-08 | **按 Profile 的命令配额** — `commandQuotaPerDay`、滚动 24 小时窗口、在策略放行后强制执行、以 `command-quota` ruleId 记入审计 |
| **P2-A** | 2026-08-08 | **JIT 审批授权** — `approvalGrantTtlMs`，绑定完整命令 + profile + 类别，以 `approver: "jit-grant"` 记入审计，默认关闭 |

## 已取消（6 项）

| 项 | 原因 |
|-------|-------|
| P1-D 组合会话引用（`@`） | 价值低——LLM 用显式参数工作得更好 |
| P2-E 交互式密码提示 | 与 MCP 不兼容——stdin 是 JSON-RPC 管道，不是 TTY |
| **P2-B** asciinema 会话录制 | 录制会击穿本项目处处执行的脱敏：原始会话 I/O（sudo 密码、文件内容）会落盘。做脱敏则回放损坏，不做则泄露机密。价值抵不上这个代价 |
| **P2-D** age 加密配置 | 文档撰写时凭据还在配置文件里；**v2 已将其移出**（agent → keychain → env → key file）。剩下的可加密对象只有主机名与策略，而它们本就处于 `0600`/`0700` 保护之下。没有剩下值得为此引入新加密依赖的东西 |
| **P2-F** 动态连接 | 直接扩大 README 所警示的 lethal trifecta：被提示注入的 agent 可以连到未预先声明的主机。虽可用 opt-in 收窄，但换来的灵活性抵不上风险 |
| **P2-K** Sigstore 审计签名 | 现有哈希链已具备防篡改能力。Sigstore 能让它可被外部验证，但只在有合规审计要求的环境里增值——目前不足以正当化新依赖 |

---

## 剩余（2 项 — v2.1）

#### P2-G: WebUI（审批队列 + 审计查看器）
- **说明：** HTTP server + 极简 SPA——连接状态、实时审批队列、审计日志查看器
- **工作量：** ~500+ 行，新增依赖，类似独立子项目
- **状态：** 推迟到 v2.1/v2.2。相关开放 PR：#60、#61、#62、#63

#### PR #64: 配置热重载
- **说明：** 不重启即应用 TOML 配置变更
- **备注：** `SessionManager` 与 `CommandQuota` 如今在**调用时**读取 profile（构造时不再做快照），即热重载所需的形态已就绪
- **状态：** 推迟到 v2.1

---

## 当前统计

| 类别 | 总数 | 已完成 | 已取消 | 剩余 |
|----------|:------:|:----------:|:-----:|:-----:|
| P0 安全 | 10 | 10 | 0 | 0 |
| P1 核心功能 | 7 | 6 | 1 | 0 |
| P2 加固 | 14 | 9 | 5 | 1（WebUI） |
| 会话架构 | 7 | 7 | 0 | 0 |
| 死代码清理（WD） | 4 | 4 | 0 | 0 |
| **合计** | **42** | **36** | **6** | **1** |

**270 个测试、33 个测试文件、25 个源文件。**

> 发布状态见 `docs/v2-release-readiness-report.md`。距 2.0.0 标签仅剩的真实条件，
> 是该报告中的 §5 人工验证轮。

