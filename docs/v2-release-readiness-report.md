# ssh-mcp v2 — 发布就绪报告

> 初版：2026-08-08 · **更新：2026-08-08（修复之后）**
> 分支：`v2`（相对 main 领先 74 个提交）
> 方法：构建 + 测试运行，8 项专家代码评审（security、correctness、backend、tests、performance、craft、ai-antipatterns、api-contract），开放的 issue/PR 对照，随后修复全部发现并逐项以测试验证。

---

## 1. 总体结论

**结论：APPROVE（有条件）——在真实服务器上完成人工验证轮之后，即可打 2.0.0 标签。**

首次评审时有 9 个发布阻塞项和 12 个高优先级项。**已全部关闭。** 此外，修复过程中又暴露出首次评审未能发现的 5 个以上缺陷（下文以 ⚡ 标记）——因为在补上测试覆盖之前它们不可见。

| 指标 | 最初 | 现在 |
|---|---|---|
| 测试数量 | 183 | **321**（其中 6 个需要 Windows 主机，为 opt-in） |
| 套件状态 | 182/183（1 红） | **315/315**，连续运行稳定 |
| 构建 + 类型检查 | 构建干净，测试不在 tsc 范围 | **两者皆干净**（新增 `npm run typecheck`） |
| 发布阻塞项 | 9 | **0** |
| 高优先级项 | 12 | **0** |

**剩余工作不阻塞发布**，但建议执行：用真实 MCP 客户端做一轮人工验证（§5）。

---

## 2. 构建与测试状态

| 检查 | 结果 |
|---|---|
| `npm run build`（tsc） | ✅ 干净 |
| `npm run typecheck`（src + test） | ✅ 干净——**新增**，此前测试不在 tsc 覆盖内 |
| `npm test` | ✅ **315/315** + 6 个 opt-in Windows 测试（39 个文件） |
| 连续运行稳定性 | ✅ 3/3 干净 |

### 测试覆盖增长的来源

新增的测试组：
- **MCP handler 层** —— 28 个测试（`test/unit/tools/`）。此前覆盖为**零**，而那正是客户端真正调用的层。
- **主机密钥验证** —— 7 个集成测试。此前集成测试*全部*以 `'insecure'` 模式连接。
- **ProxyJump** —— 4 个测试 + 开启转发的堡垒容器。此前覆盖为零。
- **stdin 生命周期** —— 2 个测试（#53）。
- **`sanitizeCommand` property 测试**、denylist/group/cascade/deny-mode 测试、SFTP 通道与上限测试、后台会话行完整性测试、会话重开竞态测试。

### 验证方法

对每项关键修复，都**临时移除修复、验证测试确实变红**：

| 修复 | 移除后 |
|---|---|
| `sftp.end()` | `CHANNEL_OPEN_FAILURE` |
| `sanitizeCommand` 控制字符清理 | 3 个测试变红 |
| ProxyJump 重连 | 重连测试变红 |
| `hostVerifier` | 7 个测试中 5 个变红 |
| `open-session` annotations | 会话测试变红 |
| 后台会话行拼接 | 长行测试变红 |
| 会话逐出守卫 | 重开测试变红 |
| stdin EOF 处理器 | 挂起直到 8 秒超时 |

有一个 property 测试**本身也被修复**：`fc.string()` 默认不产生 CR/LF/NUL，导致即使移除 sanitizer 也能通过。生成器被改为包含这些字符。

---

## 3. 已关闭的发现

### 发布阻塞项（9/9）

| # | 发现 | 解决 |
|---|---|---|
| B1 | 命令失败看起来像成功（`exitCode`/`stderr` 被丢弃） | 非零退出现在返回 `isError` + 脱敏 stderr + 退出码。覆盖 PR #66/#67 的主题 |
| B2 | `curl`/`wget` 被当作「只读」→ SSRF、数据外传、写远程文件 | 移出白名单；降为 `safe` 类别，可在策略下使用 |
| B3 | SFTP 通道泄露（约 10 次操作耗尽 `MaxSessions`） | `finally { sftp.end() }`；关闭 issue #34 一类问题 |
| B4 | `approvalPolicy = "deny"` 并不拒绝 | 真实的拒绝决定。修正了固化错误行为的既有测试 |
| B5 | `[defaults]` 的大多数键不生效 | 完整级联；`workdir` 生效；移除 `hostFingerprint`/`caFingerprint`；schema `.strict()` |
| B6 | HTTP 只支持一个客户端，之后永久死亡 | 每会话一个 transport + `MAX_SESSIONS` 上限。已实测验证 |
| B7 | 审批流为手写 `as any` | 改用 SDK 的类型化 `elicitInput()`；保留 fail-closed，但现在有日志 |
| B8 | SFTP 下载无大小上限 | `stat` + 流级双重上限 |
| B9 | 413 污染 keep-alive socket（EPIPE） | `Connection: close` + flush 后 destroy |
| B10 | 5 个 v1 旧测试文件未提交 | 已提交 |
| B11 | 版本 1.5.0、无 changeset、无迁移说明 | Major changeset（→ 已验证 **2.0.0**）、README 迁移章节、针对已移除 v1 标志的启动守卫 |

### 高优先级（12/12）

`sanitizeCommand` property 测试 · 握手计时器清理 · ProxyJump 重连 · 审计完整性（运行后失败的命令不再记成「deny」） · sanitize 拒绝记入审计 · OPA fail-open 日志 · denylist 单一来源 · 显式 `group` 字段 · 依赖显式声明（OTEL、keyring、engines） · 会话缓冲扫描 · SFTP denylist · 主机密钥测试覆盖。

> **备注——H5 的第一版方案是错的：** 把两份 denylist 盲目合并，会让 `rm -rf /tmp/x` 连经批准都无法运行。这两个清单其实是**不同的东西**：`FORBIDDEN_PATTERNS`（绝不放行）与 `DESTRUCTIVE_PATTERNS`（经批准放行）。此后明确区分。

### ⚡ 修复过程中暴露的新缺陷（5+）

这些在首次评审中**未被发现**——补上测试覆盖后才可见：

| 发现 | 影响 | 如何被发现 |
|---|---|---|
| ⚡ **`open-session` 经 MCP 完全无法工作** | v2 的招牌特性以死亡状态走向发布。`{}` 被传进 annotations 槽位；SDK 把空对象当作 Zod schema（`isZodRawShape({})` → `true`），吞掉 callback 槽位 → 每次调用报 `"cb is not a function"` | 第一个 handler 测试运行时 |
| ⚡ 策略拒绝向审计写入伪造记录 | denylist/审批拒绝未携带真实决定 | handler 审计测试 |
| ⚡ 审计不记录 `ruleId` | 无法区分 denylist 与角色绑定拒绝 | handler 审计测试 |
| ⚡ 命令输出的熵扫描处于关闭状态 | `env` 转储把高熵机密交给模型 | 脱敏测试 |
| ⚡ 交互式会话输出解析错误 | 行计数 + `printf` 启发式；依赖 PTY 回显顺序，不稳定 | 连续运行稳定性分析 |
| ⚡ 后台会话输出损坏 | chunk 边界处行被切断 + 每 chunk 之间多出空行 | 长行回归测试 |
| ⚡ 7 个既有类型错误 | 测试不在 tsc 覆盖内 | 加入 `tsconfig.test.json` 时 |
| ⚡ **busybox ash 上每次会话打开耗时 3 秒** | 提示符检测在原始缓冲区上匹配；ash 在提示符之后发送 ANSI 光标查询（`ESC[6n`），匹配被跳过并落到 3 秒上限 | 加入 Alpine/ash 镜像时 |
| ⚡ **Windows 上交互式会话 60 秒静默超时** | cmd.exe 接受通道并显示 `>` 提示符，即打开*看起来成功*；随后每条命令都等满超时并报 "timed out"。如今握手在打开时即失败并说明原因（5 秒） | 连接真实 Windows 主机时 |
| ⚡ **Dropbear 主机上会话/SFTP 打开如同掷硬币** | Dropbear 间歇性拒绝在上一通道释放后立即打开新通道；SFTP 流量下甚至会直接断开连接。用原生 ssh2 也能复现——不是我们的代码问题，但它让我们的工具在这类主机上不可靠 | 加入 Dropbear 镜像时 |

---

## 4. 剩余工作（不阻塞发布）

| 项 | 状态 |
|---|---|
| PR #60-#63 WebUI | 推迟到 v2.1 |
| PR #64 配置热重载 | 推迟到 v2.1。`SessionManager` 与 `CommandQuota` 如今在调用时读取 profile——所需形态已就绪 |
| Issue #27 「description 之后无输出」 | ❓ v2 已移除 `description` 参数；场景不明确，需人工验证 |

`docs/v2-remaining-work.md` 中的 9 项已全部了结：4 项完成
（OTEL、changesets、命令配额、JIT 审批），4 项有理由地取消
（asciinema、age 配置、动态连接、sigstore），WebUI 推迟。

代码结构方面本轮关闭的内容：移除了 `SessionManager`
（`SSHConnection` 464 → 374 行），`tools/registry.ts` 按主题拆分
（704 行 → 最大 267 行），开启 `noUnusedLocals`/`noUnusedParameters`。

### 测试基础设施的已知限制

`vitest.config.ts` 中的 `fileParallelism: false` 是**必需**的。并行开启时，集成测试文件会把并发 SSH 握手数乘起来，连接在握手完成前被丢弃——测试既报错又*被静默跳过*。实测：并行下开局 2 错误/4 跳过，第二轮起逐文件崩溃；串行下连续 8 轮干净。耗时无差异（~24 秒）。

这是本地 macOS/Docker Desktop 端口转发层的特性（sshd 什么都不记录，裸 TCP 正常，约 30 秒后自愈），且修复前的基线上也能看到同一模式。CI 在 Linux 上用 service container 直接走网络，预期不会波及——**但这未经核实。**

---

## 5. 真实服务器上的验证

初版报告把本节写成 12 条**人工**清单。当时 handler 层完全没有测试。如今 `test/e2e/` 下已有一套套件：把编译后的服务器经**真实 stdio/HTTP 传输**、用**真实 MCP SDK client** 驱动，连到 Docker 里的真实 SSH 服务器——没有任何 mock。§5 的 9 项现在每次运行都自动验证。

### 已自动化的部分（`npm run test:e2e`）

| 项 | 位置 |
|---|---|
| 全部 11 个工具经真实客户端 | `e2e/tools.e2e.test.ts` |
| 审批流：提示到达、拒绝能拦住命令（文件原地未动） | `e2e/approval.e2e.test.ts` |
| 失败命令 → 客户端看到退出码与 stderr | `e2e/tools.e2e.test.ts` |
| `read-command` + `curl` 拒绝 | `e2e/tools.e2e.test.ts` |
| `[defaults]` 级联经真实配置加载（`ask-all`、`deny`、配额、JIT 授权） | `e2e/approval.e2e.test.ts` |
| HTTP：两个并发客户端，其一离开后第三个能连入 | `e2e/http.e2e.test.ts` |
| `/health` 无需令牌、`/status` 需要令牌 | `e2e/http.e2e.test.ts` |
| TOFU 记录、错误指纹拒绝、strict 模式 | `integration/host-key.test.ts` |
| **不同 shell（Alpine + busybox ash）与不同 sshd（Dropbear）**：算法协商、会话协议、CWD/env、退出码、priming、SFTP | `integration/shell-compat.test.ts` |
| ProxyJump 断开 + 重连 | `integration/proxy-jump.test.ts` |
| **pnpm（严格解析器）下 OTEL 依赖链可解析** | `e2e/packaging.e2e.test.ts` |
| 已移除的 v1 标志在启动时被拒绝 | `e2e/packaging.e2e.test.ts` |

pnpm 测试是 H11 的真实验证：`@opentelemetry/resources` 与
`semantic-conventions` 此前仅靠 npm 提升才能解析，也就是说，用 pnpm/yarn-pnp
安装已发布包的用户，tracing 会在运行时崩掉。

### Windows 支持——实测结论

README 曾无条件地宣称「Windows 支持」。对照真实主机实测后，支持是**部分的**：

| | Linux/BSD/macOS | Windows OpenSSH |
|---|:---:|:---:|
| exec 工具、SFTP、后台会话 | ✅ | ✅ |
| **交互式会话** | ✅ | ❌ |

原因不是可修复的 bug，而是协议的本质：会话协议用 `printf` 标记包裹命令并读取
`$?`/`$PWD`——cmd.exe 里这些都不存在。把 PowerShell 设为 `DefaultShell` 也无济于事；
协议是 POSIX 专属的，不只是「非 cmd」。README 已按此表更新。

### Docker 给不了的——剩余真实人工清单（2 项）

- [ ] **在 Claude Desktop 中运行一条破坏性命令，亲眼确认审批提示出现。**
      我们能测协议，测不了客户端是否真的渲染提示。关键点：若客户端不支持 elicitation，
      服务器会 fail-closed 并**拒绝每一条破坏性命令**——产品会显得「坏了」。B7 为此
      加了 stderr 日志，需要人工看一次。
- [x] ~~**Windows OpenSSH。**~~ **已完成**——已对照真实 Windows 11 主机
      （build 26200，UTM 虚拟机）测试。`integration/windows-compat.test.ts`，
      经 `SSH_MCP_WIN_HOST/_USER/_PASSWORD` opt-in。结论：支持是真实的但**部分**——
      exec 工具、后台会话与 SFTP 可用；交互式会话不可用（见下）。旧版 OpenSSH 7.x 仍未测试。
- [ ] **在 Linux 上把 CI 看到一次绿**（带 `SSH_MCP_REQUIRE_SERVERS=1`）。

除此之外，真实网络条件（NAT/防火墙空闲超时——`keepalive` 存在的理由）在 Docker
loopback 里完全不会出现；这是已知的覆盖缺口。

---

## 6. Issue/PR 覆盖状态（最新）

**已覆盖：**

| Issue/PR | 状态 |
|---|---|
| #44 命令注入 | ✅ sanitizer + property 测试 + PoC 回归 |
| #42、#43 日志信息泄露 | ✅ 三层脱敏，且命令输出也做熵扫描 |
| #47、#51、#37 zod/SDK | ✅ |
| #32 环境变量 | ✅ |
| #25、#35 加密密钥 | ✅ |
| #46 提权区分 | ✅ |
| #55、#56、#58、#59 TOML/审计/审批 | ✅ |
| #28、#41、#38 Docker/HTTP/SFTP | ✅ HTTP 已支持多会话 |
| #34 PTY/通道耗尽 | ✅ exec **与** SFTP 两侧 |
| #36、#23 只读区分 | ✅ 移除 `curl`/`wget` 后主张成立 |
| #66、#67 退出码 vs stderr | ✅ 随 B1 关闭 |
| #53 stdin 关闭时退出 | ✅ 带测试 |
| #45 `--workdir` | ✅ 已实现（exec、后台、交互式） |

**未覆盖：** #64（热重载）、#60-#63（WebUI，有意推迟）、#27（不明确——需人工验证）、#33（lethal trifecta：结构性风险，经 B2 已大幅收窄）。

---

## 7. 结论

初版报告的判断——「问题不在设计，而在于最后 10% 没有完成」——是正确的，那 10% 已关闭。占主导的模式「schema/文档里有定义、但最后一环没有接上的特性」已被系统性清除。

这一过程还暴露出首次评审未能捕获的 5 个以上缺陷；全部在补上测试覆盖后才可见。其中之一（`open-session`）曾让 v2 的招牌特性之一完全失效。

人工验证轮（§5）完成后，**即可打 2.0.0 标签。**

