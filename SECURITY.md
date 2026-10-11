# 安全政策

## 报告漏洞

如果你在 SSH MCP Server 中发现安全漏洞，请负责任地报告：

1. **不要**开公开的 GitHub issue。
2. 私下报告，任选其一：
   - [发起私有安全通告](https://github.com/tufantunc/ssh-mcp/security/advisories/new)——推荐，报告、修复与 CVE 会保持在同一线索内；或
   - 发邮件至 <tufan.tunc.91@gmail.com>。
3. 请包含：
   - 漏洞描述
   - 复现步骤
   - 受影响版本
   - 潜在影响

### 披露时间线

| 时间 | 内容 |
|---|---|
| 72 小时内 | 确认收到报告，以及是否可复现 |
| 7 天内 | 给出评估：受影响版本、严重程度、是否计划修复 |
| 90 天内 | 协调式公开披露；修复版本发布后可提前 |

在修复版本发布之前、或 90 天期满之前（以先到者为准），请对漏洞保密。除非报告者另有要求，会在安全通告中署名致谢。

## 威胁模型

SSH MCP Server 让 LLM 智能体能够经 SSH 在远程主机上执行 shell 命令。这带来 **「Lethal Trifecta（致命三要素）」** 风险（Simon Willison 的框架）：

1. **能访问私密数据** —— SSH 会话可达目标主机的文件系统
2. **暴露于不可信内容** —— LLM 可能已通过工具结果摄入提示注入的数据
3. **能向外通信** —— SSH 会话具备网络访问能力，可外传数据

### v2 的缓解措施

| 风险 | 缓解 |
|------|------------|
| 经工具输出的提示注入 | 命令分类器 + 策略引擎 + 对归类为 `destructive` 或 `privileged` 的命令做人工审批——实际范围比听起来窄，见下文 `ask-destructive` 的说明 |
| 经 CLI 参数泄露凭据（CWE-214） | 凭据从环境变量/配置文件/SSH agent 加载——绝不走 CLI 参数 |
| sudo 密码进入进程列表（CWE-522） | sudo 密码经 SSH 通道 stdin 管道传入，不用命令行 `printf` |
| 经元数据的命令注入 | 净化器从所有元数据剥离 CR/LF/NUL；`description` 功能已移除 |
| MITM 攻击 | 默认 TOFU 主机密钥验证，**仅限单进程存续期**——见下文「主机密钥信任不跨重启保留」。profile 上的 `trustedHostKey` 是此处唯一能跨重启保留的控制 |
| 弱 SSH 算法 | 按 RFC 9142 冻结算法白名单（无 SHA-1、无 CBC、无 ssh-rsa） |
| PTY 会话泄露（MaxSessions） | 交互式会话是有界的，不是不存在：`sessionMaxPerConnection`（默认 5）、`sessionIdleTimeoutMs`（10 分钟）、`sessionBackgroundMaxMs`（1 小时），并有回收器每 60 秒清扫过期会话。一次性命令走 `exec()`，不占用通道。没有持久的 `su` shell |
| agent 行为无界 | 按 profile 的 RBAC、速率限制、拒绝清单、审批模式 |
| Bearer 令牌猜测 | `--authFailureLimit`——按客户端计的预算，仅在认证失败时消耗，默认开启 |

## 停止一条命令

有六种东西能停止一条命令，它们在 exec 通道上的升级方式全部相同——立即 `SIGINT`，1 秒后 `SIGTERM`，2 秒后 `SIGKILL`，然后关闭通道：

| 触发 | 策略检查 | 审计记录 |
|---|---|---|
| 命令自身的超时 | 无 | 失败命令自身的记录 |
| MCP 客户端取消请求 | 无 | 失败命令自身的记录 |
| 请求已超时后才到达的通道 | 无 | 仅 trace（`ssh.exec.lateStop`） |
| 对后台会话执行 `close-session` | **无** | 有（`session:close …`，`ruleId session-release`） |
| 会话回收器（空闲 TTL，或 `sessionBackgroundMaxMs`，默认 1 小时） | 无 | **无** |
| 连接拆除——关机，或空闲连接回收器 | 无 | **无** |

**这份清单上没有任何一项经过策略门，其中两项不留任何记录。** 前四项是服务器在停止「策略在启动时已授权」的东西，其权限严格小于启动它的权限。`close-session` 被审计是因为它由调用方发起，但它被刻意设计为*不可拒绝*：若把它纳入策略引擎，一个 `readOnly` profile 可能打开一个后台会话，然后被拒绝关闭它的许可，而此后一小时内再无别的办法停掉那条命令。一个「拒绝的后果是你要停的东西继续跑」的控制，比没有控制更糟。

最后两行是在把这个服务器指向重要东西之前需要掂量的：一个超出 TTL 的后台 `tail -f` 会被定时器 `SIGKILL`——没有工具调用、没有策略检查、没有审计行。请相应地设置 `sessionBackgroundMaxMs` 与空闲 TTL。

### 主机密钥信任不跨重启保留

TOFU 在进程存活期间真实存在，进程退出即消失。它背后的存储是每个 `ConnectionRegistry` 新建的一个 `Map`（`src/ssh/connection-registry.ts`）；没有任何东西把它读写到磁盘，也没有任何东西查询 `~/.ssh/known_hosts`。所以「首次连接接受、此后验证」的确切含义是*在本进程内*验证。

这在服务器最常见的部署形态里最要紧。stdio MCP 服务器随客户端启动与退出，因此每个会话都会发生一次新的接受，能够在链路上拦截的攻击者必须在每次启动时赢一次，而不是一辈子赢一次。能让换钥显形的失配错误，只对进程已经见过的密钥触发。

**profile 上的 `trustedHostKey` 是唯一能跨重启保留的控制。** 把你期待的指纹固定下来。它在 `verifyHostKey`（`src/ssh/host-key.ts`）中先于所有其他分支被应答。它从不*读*存储，因此空存储不会削弱它，过期条目也不能覆盖它；它只在 `tofu` 下写入，且只写入空槽位——见下文，因为那次写入正是同主机上未固定 profile 被评判的基准。凡重要的东西都用它。

2.8.0 之前，本节声称该固定「在 `connection.ts` 中、在任何存储查询之前检查，所以空存储不会削弱它」。在 `strict` 模式下这不成立，而且恰好在要紧的方向上：固定当时只是一道只拒不禁的门，它能拒绝错误的密钥，却不能满足其后的存储检查。如今在所有模式下，它都是它所命名主机的权威。

被固定的 profile 在 `tofu` 下仍会把密钥记入存储、且只写入空槽位，因此同一 `host:port` 上未固定的 profile 是在与「经固定验证的指纹」比较，而不是相信自己的首次使用——也绝不会与某个*其他*固定 profile 覆盖写入的值比较。`strict` 下不记录：那里存储是未固定 profile 获准的唯一途径，用固定值播种存储等于「固定一个 profile、放行其余全部」。`insecure` 下也不记录，那里存储本来就不起决定作用。

结论：未固定的 profile 在 2.8.0 中的体验没有任何变化。模式与固定只对携带它们的 profile 生效。

**`--hostKeyMode=strict` 意味着「每台主机都必须被固定」。** strict 拒绝任何密钥尚未受信的主机，而它查询的存储只在 `tofu` 下被写入——两个写入点都是，而 strict 按定义到不了那里。由于模式在启动时固定，更早的 `tofu` 连接也无法为它播种。所以固定是满足 strict 的唯一途径，而 strict 值得设置的理由只有一个：它把「缺失固定」变成拒绝，而不是首次使用即接受。

2.8.0 之前，这个组合连不上任何主机。strict 曾对每次连接的每台主机抛 `HOST_KEY_UNKNOWN`——实测：存储保持零条目的情况下连续两次连接——而匹配的 `trustedHostKey` 也不起作用，因为固定从不写存储，它的门又跑在本来会查询存储的函数之前。拒绝消息自己的建议「用 trustedHostKey 固定密钥」，恰恰是那条不起作用的建议。

与固定矛盾的密钥在**所有**模式下都被拒绝为 `HOST_KEY_PIN_MISMATCH`，`insecure` 也不例外。这是刻意的，且早于那次修复——旧门位于模式检查之前，这个顺序被保留了下来，因为丢掉它就等于「把回归伪装成清理」。没有任何模式能覆盖固定，拒绝消息也不提供这种模式。

**`ask-destructive` 拦截的比名字暗示的少，`kill` 是常态而不是例外。** 在「永不放行」清单之外，产生 `destructive` 类别的只有五件事：模式 `/rm\s+-rf?\s+\//`、在原本白名单的二进制上出现取消资格的参数（`find … -delete`、`find … -exec`）、本进程无法静态解析的命令词（`$VAR` 作为命令）、交给本进程读不懂的解释器的程序（`python3 -c`、`perl -e`、`node -e`、`php -r`，以及经管道到达的程序），以及本服务器合成的两条作用于目标机的命令（`sftp:upload`、`session:open`）。**`awk` 不在其中**：它的程序不被上述任何机制读取，因此 `awk 'BEGIN{system("...")}'` 的归类与 2.5.1 上完全一样是 `safe`。提权归类为 `privileged` 而非 `destructive`；本模式对两者都设门。普通的写动词不在以上任何一类。对照随版本发布的分类器实测，下面这些都是 `safe`，而 `safe` 在本模式下不触发提示：

```
rm -f /etc/passwd          mv /etc/passwd /tmp/x       truncate -s0 /etc/passwd
rm -r -f /                 rm --recursive --force /    rm -rf ~
shred /dev/sda             systemctl stop nginx        kill -9 <pid>
```

所以 `ask-destructive` 在提权和 `rm -rf /path` 上买到一次提示。在写操作、换拼法的删除、服务控制、信号上买不到。**`ask-all` 才是管住写操作的模式**，对指向重要东西的 profile，它才是正确的默认。`readOnly` profile，或绑定中不含 `safe` 的角色，是真正覆盖这组命令的另外两个控制——这里说的是命令集意义上的覆盖，不是本文件开头威胁模型表格意义上的。

**爆炸半径是进程组，不是单个进程。** OpenSSH 以对命令进程组执行 `killpg()` 来响应 `signal` 通道请求（`session.c` 的 `session_signal_req`），因此普通的进程树确实会死——对照 10.3p1 实测：shell 及其子进程同属一个进程组，一次 `SIGKILL` 请求后两者都消失。这是本服务器的行为而非协议保证：RFC 4254 §6.9 未规定送达语义，sshd 对 forced-command 与 subsystem 会话拒绝信号请求，其他服务器（本项目也测试 Dropbear）可能不同。

**没有任何东西确认信号请求已被送达。** 对 `exec` 而言，错误里没有告警只说明请求已派发，不说明进程已死；完全无法派发时错误会明说（「无法发送信号，进程可能仍在主机上运行」）。`ssh.unstopped` span 属性为每一次「有通道可发信号」的 `exec` 停止携带同一事实——通道尚不存在就触发的超时改记 `ssh.stopDeferred`，其结果落在单独的 `ssh.exec.lateStop` span 上。`close-session` 在工具结果与审计记录的退出码中报告自己的结局，而不是靠 span：它区分「确认关闭」「信号已派发但未生效」与「完全无法派发」三种情形。

### 交互式会话在基于名称的分类之外

`run-command` 对每次输入单独分类，但交互式会话是一个持久的 PTY shell，保留上一条输入留下的状态。于是命令词可以被一次调用重定义、被下一次调用使用，而两次调用都归类为低危：

```
alias ls='sudo id'              safe        allowed
ls                              read-only   allowed — runs sudo id

export PATH=/tmp/mine:$PATH     safe        allowed
cat /etc/hosts                  read-only   allowed — runs /tmp/mine/cat

ls() { sudo id; }               safe        allowed
```

分类器对变量已经有所回应，但达不到「拒绝」的强度：`S=sudo` 后执行 `$S id` 会归类为 `destructive`，因为含 `$` 的命令词无法静态解析，于是它会到达审批门——在 `ask-destructive` 或 `ask-all` 下提示，在 `deny` 或该角色/层级未绑定 `destructive` 之处直接拒绝，在 `auto` 下放行。而别名、shell 函数与 `PATH` 的情形连这一步都到不了：它们归类为 `safe` 或 `read-only`，低于触发提示的类别，因为命令词只是个普通名字，看不出任何不对劲。这个差别就是缺口，宽度正好一个类别。

**这不是靠更狠的分类能修好的。** 状态活在远程 shell 里，不在本服务器，基于名称的分类器不可能知道名字在另一端意味着什么。请把「能打开交互式会话」本身当作它实际是的那种特权来对待：

- 自 2.6.0 起，打开交互式会话归类为 `destructive`，因此默认规则下 `operator` 在 `prod` 上根本打不开，`admin` 会被提示。2.6.0 之前它是 `safe`。
- 在授予 `destructive` 的 profile 上，`approvalPolicy = "ask-all"` 是同时覆盖第一次与第二次调用的控制。
- `readOnly` profile 不受影响：它只持有 `read-only`，根本设置不了别名。

### `read-only` 由文法授予，不由二进制名授予

一条命令只有当命令词之后的每个参数都能在该二进制声明的文法下被证明是数据时（`src/policy/classifier.ts` 的 `READERS`、`src/policy/reader-grammar.ts`），才归类为 `read-only`——而不是因为第一个词在白名单上。文法未列出的选项、已列选项的缩写、含未列出字母的短选项簇、携带未加引号 shell 通配符（`*`、`?`、`[`）的参数，或形如该二进制会写入的目标的操作数——任一出现，整条命令都会降为 `safe` 而不是 `read-only`。

`read-only` 是 `readOnly` profile 被限制的类别，是 `viewer` 在 prod 与 staging 上持有的类别（dev 上的 viewer 还额外持有 `safe`），也是 `read-command` 要求的类别；除 dev 上的 viewer 外，这些场景都拒绝 `safe`。所以过去在旧的「只看名字」规则下能跑的命令，如今在同一个 profile、角色或工具下可能被拒绝。拒绝消息会指出被拒的词，调用方因此能看出同一命令的哪种写法仍然合格，而不是断定该二进制被整体封禁。

`DISQUALIFYING_ARGS` 不受此影响，仍然最先运行：无论 reader 文法接受什么，它仍然可以把命令抬到 `safe` 之上，并对所有角色生效，包括 `operator` 与 `admin`。文法只在 `read-only` 与 `safe` 之间做决定。

**残留风险，如实记录而非闭合：**

- **DNS/ICMP 出口。** `dig`、`nslookup`、`host`、`ping` 与 `traceroute` 能经它们发出的查询与探测泄露少量数据。它们都不能修改主机，所以保持 `read-only`；若出口是敏感点，请经 profile 策略收紧（denylist，或去掉该角色）。
- **Windows 上的 UNC 路径操作数。** 形如 UNC 路径的操作数（`\\host\share\x`）传给 `cat`、`sort` 之类 reader 时，会让 Windows 主机向所指的 SMB 服务器认证，可能泄露 NTLM 凭据。主机本身未被更改，所以这落在 `read-only` 契约之外——该契约针对的是写入，不是向外的认证尝试。
- **`git status` 可能写 `.git/index`。** 当缓存的 stat 数据过期时，它会顺手刷新；它不写任何被跟踪内容、引用或配置。想连这个也关掉的主机可设置 `GIT_OPTIONAL_LOCKS=0`。
- **`*`、`?`、`[` 之外的 glob 字符。** 未加引号的 glob 检查覆盖每个 POSIX shell 都会展开的字符。若远程登录 shell 是 zsh 且开启了非默认的 `extendedglob` 选项，`^`、`#` 与 `~` 也会被当作 glob 操作符，而它们不被检查。请为本服务器登录所用的账户保持 `extendedglob` 关闭。
- **`'any'` 文法条目是未经验证的断言，不是证明。** 没有测试能证明一个二进制完全不存在写模式。缓解在于 `READERS` 中每个 `'any'` 条目都带源码注释，写明查过什么、发现了什么；没有此类断言的条目不接受任何参数。

## 安全部署指南

1. **绝不用 root 运行。** 创建专用的低权限服务账户。
2. **使用按命令限定的 sudoers**，而不是一刀切的 `NOPASSWD: ALL`。
3. **为生产 profile 启用 `ask-all` 审批模式。** 随版本默认的 `ask-destructive` 拦截的远比名字暗示的少——在把它用于重要东西之前，先读下文关于它的说明。
4. **限制目标主机的网络出口**（iptables/Cilium），防止数据外传。
5. 监控/观察类访问使用**只读 profile**（`readOnly = true`）。
6. 定期**复查审计日志**——所有命令都经脱敏后记录。
7. **收紧配置文件权限**——目录 `chmod 700`、文件 `chmod 600`；在 Linux 与 macOS 上不满足则服务器拒绝启动，且只做 `chmod 600` 满足不了目录检查。Windows 没有模式位：ACL 应只授予你的账户、`SYSTEM` 与 `Administrators`，`%APPDATA%` 下的配置会自动继承这一点。该平台上此类发现是报告而非强制——需要强制请用 `--strictConfigAcl`。

## 支持的版本

| 版本 | 支持状态 |
|---------|-----------|
| 2.x     | 是       |
| 1.x     | 否（已停止维护）  |

## 贡献者安全检查清单

- [ ] CLI 参数、错误信息、日志中不出现机密
- [ ] 所有用户输入经净化（与 shell 交互的数据中无 CR/LF/NUL）
- [ ] sudo 密码经 stdin 管道传入，不走 argv
- [ ] 错误消息使用固定字符串，不做 `${buffer}` 插值
- [ ] 新工具声明 MCP 注解（`readOnlyHint`、`destructiveHint`）
- [ ] 测试覆盖安全边界（净化器的 property 测试）

## 合规映射

SSH MCP Server v2 实现的控制项可映射到常见安全框架。本映射说明哪些特性支撑哪些具体控制要求——它**不**构成正式认证。完整部署的合规姿态由**部署方**负责。

### 独立评估

下表中的所有内容都是**自评估**。唯一持续的外部评读是 [OpenSSF Scorecard](https://scorecard.dev/viewer/?uri=github.com/tufantunc/ssh-mcp)：它每周、以及每当 `main` 或分支保护发生变更时重新评分并发布结果。发现项也会与 CodeQL 一起进入仓库的 Security 标签页。

请按它实际度量的东西来读它：**供应链与开发过程**——有没有安全政策、依赖是否固定并及时更新、代码扫描是否开启、发布是否签名、历史能否被重写。它对下表描述的运行时控制只字未提；没有任何自动化评分器会去执行策略引擎。高分意味着这个项目以「篡改难以隐藏」的方式构建，而不意味着某次部署是安全的。

### SOC 2（AICPA 信任服务准则）

| 控制项 | 说明 | SSH MCP v2 特性 |
|---------|-------------|-------------------|
| CC6.1 | 逻辑与物理访问控制 | 带 RBAC 的策略引擎（viewer/operator/admin）、按 profile 的 `readOnly` 标志、denylist 强制执行 |
| CC6.6 | 网络访问安全 | TOFU 主机密钥验证（按进程；`trustedHostKey` 固定——见「主机密钥信任不跨重启保留」）、RFC 9142 算法白名单、无 agent 转发的 `via` ProxyJump |
| CC7.1 | 系统监控 | 审计日志（JSONL + ECS 字段）、三层输出脱敏（字段/正则/熵） |
| CC7.2 | 安全事件检测 | 命令分类（read-only/safe/destructive/privileged）、策略拒绝日志 |
| CC8.1 | 变更管理 | `approvalPolicy` 模式（auto/ask-destructive/ask-all/deny）、对归类为 `destructive` 或 `privileged` 的命令做 MCP elicitation；`ask-all` 覆盖每条命令 |
| CC9.1 | 风险缓解 | 凭据级联（agent > keychain > env，绝不 CLI 参数）、配置文件与目录权限检查（0600/0700）、Windows 上的 ACL 检查 |

### PCI-DSS v4.0

| 要求 | 说明 | SSH MCP v2 特性 |
|-------------|-------------|-------------------|
| Req. 6.5 | 安全编码 | 命令净化器（剥离 CR/LF/NUL）、错误消息卫生（不泄露机密）、property 测试 |
| Req. 7.2 | 最小权限 | 按 profile 的 RBAC、`readOnly` profile、按命令的 denylist |
| Req. 8.3 | 认证 | SSH agent / 密钥 / 密钥链认证、SSH CA 证书支持、无明文 CLI 凭据 |
| Req. 10.2 | 审计轨迹 | 只追加的 JSONL 审计日志、MCP requestId 关联、可选的防篡改哈希链 |
| Req. 10.4 | 审计日志保护 | 三层脱敏（字段/正则/熵）、日志轮转、审计文件 0600 权限 |

### ISO/IEC 27001:2022

| 附录 A 控制项 | 说明 | SSH MCP v2 特性 |
|-----------------|-------------|-------------------|
| A.8.2 | 特权访问权限 | RBAC 角色、策略引擎、审批模式、denylist |
| A.8.5 | 安全认证 | 凭据级联、CLI 参数无机密、keychain + SSH agent + CA 证书支持 |
| A.8.23 | 网页过滤 | `--transport http` 要求 bearer 认证、按客户端的 `--rateLimit` 令牌桶、`--allowedHosts` Host 头白名单 |
| A.12.4 | 日志与监控 | 带 ECS 字段的审计日志、哈希链选项、脱敏 |
| A.13.1 | 网络安全控制 | 主机密钥验证、冻结算法、ProxyJump 隧道 |
| A.14.2 | 开发中的安全 | property 测试（fast-check）、SAST（Semgrep）、机密扫描（gitleaks）、npm 溯源 |

### HIPAA（45 CFR §164.312）

| 要求 | 说明 | SSH MCP v2 特性 |
|-------------|-------------|-------------------|
| §164.312(a)(1) | 访问控制 | 策略引擎 RBAC、按 profile 的 readOnly、会话限制 |
| §164.312(b) | 审计控制 | 含命令/用户/主机/决策的 JSONL 审计日志、哈希链防篡改 |
| §164.312(c)(1) | 完整性 | 脱敏管线防止日志中的 PHI 泄露、错误卫生 |
| §164.312(d) | 人员或实体认证 | 凭据级联（agent/keychain/key/CA 证书）、主机密钥验证 |
| §164.312(e)(1) | 传输安全 | 采用 RFC 9142 算法的 SSH、TOFU 主机密钥验证（按进程；`trustedHostKey` 固定）、无 agent 转发 |

