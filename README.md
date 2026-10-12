# agent-ssh（Host 分离架构 v2）

> **⚠️ 架构通告（v2，2026-10）**：本包已切换 **Host 分离架构**——`agent-ssh` 默认入口是
> **纯单向 MCP stub 前端**，SSH 凭证只存在于一旁的 **Host 守护**（`agent-ssh host serve`）。
> **Host 不在线 = 产品全灭**（stub 零工具诚实态，绝不本地降级，fail-closed）。
> 首次部署走 [HOST-RUNBOOK](docs/HOST-RUNBOOK.md)（host init 五步→serve→宿主接 env）；
> 从 v1（ssh-mcp）升级见同文档「升级顺序」节（先 Host 后 stub，切换窗口会话全灭预告）。
> 健康检查：宿主侧 `host.ping`；stub 启动需要 env `AGENT_SSH_HOST_ADDR` + `AGENT_SSH_TOKEN`。

[![NPM Version](https://img.shields.io/npm/v/ssh-mcp)](https://www.npmjs.com/package/ssh-mcp)
[![Downloads](https://img.shields.io/npm/dm/ssh-mcp)](https://www.npmjs.com/package/ssh-mcp)
[![CI](https://github.com/tufantunc/ssh-mcp/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/tufantunc/ssh-mcp/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/tufantunc/ssh-mcp/badge)](https://scorecard.dev/viewer/?uri=github.com/tufantunc/ssh-mcp)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/15082/badge)](https://www.bestpractices.dev/projects/15082)
[![codecov](https://codecov.io/gh/tufantunc/ssh-mcp/graph/badge.svg?branch=main)](https://codecov.io/gh/tufantunc/ssh-mcp)
[![License](https://img.shields.io/github/license/tufantunc/ssh-mcp)](./LICENSE)
[![GitHub issues](https://img.shields.io/github/issues/tufantunc/ssh-mcp)](https://github.com/tufantunc/ssh-mcp/issues)

**SSH MCP Server** 是一个安全优先的 Model Context Protocol 服务器，让 LLM 智能体以受控方式通过 SSH 访问远程主机——具备命令分类、基于策略的授权、人工审批（human-in-the-loop）与完整的审计日志。

> **这个服务器所要管理的风险。** 把 shell 权限交给 LLM，等于把私密数据、不可信输入和网络出口放进了同一个地方——即 Simon Willison 所说的 ["lethal trifecta"](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/)。提示注入没有通用解，因此 ssh-mcp 假定任何命令都可能受攻击者影响：先分类再执行，按「角色 × 主机组」矩阵授权，破坏性操作一律先过审批，且无论结果如何都留有记录。这缩小的是爆炸半径，不是消除风险。有两件事始终由你负责：**绝不要把它指向 root 账户**，以及**绝不要在生产 profile 上设置 `auto` 审批**。完整威胁模型见 [SECURITY.md](./SECURITY.md)。

---

## 快速开始

### 1. 安装

```bash
npm install -g ssh-mcp
```

### 2. 配置

没有配置时服务器依然会启动，客户端因此能完成 MCP 握手并读取 `tools/list`——但在完成配置之前，**每一次工具调用都会被拒绝**，拒绝消息会给出下面这条路径。这一步完成之前，主机上不会运行任何东西。

在对应平台的路径创建配置文件：

| 平台 | 路径 |
|---|---|
| Linux | `~/.config/ssh-mcp/config.toml`（或 `$XDG_CONFIG_HOME/ssh-mcp/config.toml`） |
| macOS | `~/Library/Application Support/ssh-mcp/config.toml` |
| Windows | `%APPDATA%\ssh-mcp\config.toml` |

```toml
[defaults]
defaultProfile = "dev"
approvalMode = "ask-destructive"

[[profiles]]
name = "dev"
host = "192.168.1.100"
port = 22
user = "deploy"           # 不要用 root！
auth = "key"
keyRef = "~/.ssh/id_ed25519"
role = "admin"
approvalPolicy = "auto"    # dev 环境可以宽松
```

```bash
chmod 700 ~/.config/ssh-mcp && chmod 600 ~/.config/ssh-mcp/config.toml
```

配置文件决定了本服务器认可哪些主机、角色和策略规则，因此它会检查「除你之外无人能读到它」——并对两类平台区别处理，因为这个问题的答案在其中一个平台上要清晰得多。

**Linux 和 macOS：强制执行。** 对文件*和*目录同时执行上面的模式检查——这正是命令里带 `chmod 700` 的原因：默认 umask 下 `mkdir -p` 建出的目录是 0755。不满足则拒绝启动。「仅属主可访问」在这里没有歧义，`chmod` 一行就能修好。

**Windows：按 ACL 实际允许的内容区别对待。** Windows 没有模式位，所以改为读取 ACL——而且读暴露与写暴露不做同等处理，因为 Windows 对其中一件事的判定远比另一件清晰。

| 若 ACL 允许其他账户…… | 默认行为 |
|---|---|
| 只能**读取**配置 | 报告，服务器照常启动 |
| **修改**配置 | 拒绝 |
| 什么都不能（连 ACL 都没有） | 拒绝——那等于人人完全控制 |
| ……以及 ACL 本身无法读取时 | 拒绝，例外：`icacls` 不存在或检查超时 |

`%APPDATA%` 下的配置会继承你本人、`SYSTEM` 与 `Administrators` 的访问权，无需额外处理。放在别处的则不然：`C:\` 下的文件默认继承*每个本地账户*的**读**权限和*每个已认证账户*的**修改**权限。无论哪种情况，修复所需的两条 `icacls` 命令都会写在提示消息里。

读暴露只报告不拒绝，因为那正是 Windows 确实比 POSIX 含糊的地方，而在这上面一律拒绝曾把一个放在文档指定位置的配置挡在门外（[#138](https://github.com/tufantunc/ssh-mcp/issues/138)）。写暴露则一律拒绝，因为它毫不含糊：另一个账户若能改写这份「决定本服务器认可哪些主机、角色与审批策略」的文件，那是授权绕过，不是信息泄露。

两个标志可以整体调整这套行为：`--strictConfigAcl` 把检查反对的一切都变为拒绝，包括只读授权；`--allowUncheckedConfigAcl` 把一切都变为报告，不拒绝任何情况。两种组合都不会让你无路可走——这正是 #138 的教训。

### 退出码

| 退出码 | 含义 |
|---|---|
| `0` | 正常关闭 |
| `1` | 服务器自身缺陷——带堆栈打印，请提交报告 |
| `2` | 调用方式或配置问题——以消息打印，无堆栈 |

把一切非零退出码都视为失败的监督程序无需改动。若它靠匹配 `1` 来发现启动故障，那也应同时匹配 `2`。

「什么都不配置」启动**不**属于退出码 2 的情形——自加入无配置内省能力的那个版本起：服务器会照常启动以便被描述，转而逐个拒绝工具调用。原先靠非零退出码来发现「未配置部署」的监督程序，应改为盯住 stderr 上的 `starting unconfigured`，或在 HTTP 传输下读取 `GET /health` 返回的 `configured` 字段。

### 3. 通过环境变量设置凭据

```bash
export SSH_MCP_PASSWORD="your-password"        # 若使用 auth=password
# 或者使用 SSH agent（推荐）：
export SSH_AUTH_SOCK="$SSH_AUTH_SOCK"           # agent 已在运行时该变量已设置
```

### 4. 从 MCP 客户端连接

**Claude Code：**
```bash
claude mcp add --transport stdio ssh-mcp -- ssh-mcp
```

**Claude Desktop / Cursor / Windsurf：**
```json
{
  "mcpServers": {@NL@@    "ssh-mcp": {@NL@@      "command": "ssh-mcp",
      "env": {@NL@@        "SSH_MCP_PASSWORD": "your-password"
      }
    }
  }
}
```

**绝不要把密码放进 CLI 参数**——它们会经由 `ps aux` 暴露。请使用环境变量、配置文件、SSH agent 或操作系统密钥链。

---

## 工具（23 个）

| 工具 | 用途 | readOnly | destructive |
|------|---------|:--------:|:----------:|
| `list-connections` | 发现可用主机与连接状态 | ✅ | — |
| `list-sessions` | 列出各主机的活动会话 | ✅ | — |
| `open-session` | 创建命名的交互式（有状态）或后台会话 | — | — |
| `close-session` | 关闭会话。后台会话的命令会先收到信号（INT/TERM/KILL），再丢弃其通道 | — | ✅ |
| `read-session-output` | 读取后台会话的输出（如 `tail -f`） | ✅ | — |
| `read-command` | 执行白名单内的只读命令（`ls`、`cat`、`grep` 等） | ✅ | — |
| `run-command` | 执行任意命令（破坏性/特权命令需审批，除非 `approvalPolicy = "auto"`） | — | — |
| `privileged-command` | 以 sudo 执行（需审批，除非 `approvalPolicy = "auto"`） | — | ✅ |
| `sftp-upload` | 通过 SFTP 上传文件（无条件覆盖目标） | — | ✅ |
| `sftp-download` | 通过 SFTP 下载文件 | ✅ | — |
| `sftp-list` | 列出远程目录，条目数与字节数均有上限 | ✅ | — |
| `sftp-upload-file` | 将本地文件流式传输到远程主机，绝不经过模型上下文 | — | ✅ |
| `sftp-download-file` | 将远程文件流式传输到本地磁盘，绝不经过模型上下文 | — | ✅ |
| `signal-process` | 向远程 PID 发送 INT/TERM/KILL | — | ✅ |
| `pty-open` | 打开裸 PTY 会话——真正的伪终端，你直接读写其字节流。适用于 POSIX 标记会话无法工作的网络设备 CLI（华为/华三/思科/锐捷）。需通过审批门 | — | ✅ |
| `pty-read` | 读取自上个游标以来的新 PTY 输出（单次有上限；报告丢弃/跳过的字节数） | ✅ | — |
| `pty-write` | 向 PTY 发送原始输入——换行需自行包含。裸 PTY 中的内容无法做命令分类：门在 pty-open；每次写入都被审计并记录转录 | — | — |
| `pty-resize` | 调整 PTY 会话尺寸（行 × 列） | — | — |
| `pty-close` | 关闭 PTY 会话（信号阶梯，然后丢弃通道） | — | ✅ |
| `pty-list` | 列出裸 PTY 会话的状态、游标与转录大小 | ✅ | — |
| `forward-open` | 打开端口转发：local（本地监听 → 经主机抵达目标）、remote（主机监听 → 连接落到目标）、dynamic（本地 SOCKS5，除非 allowDynamicForwarding=true 否则禁用）。破坏性下限 + 对完整「监听→目标」对的拒绝清单 | — | ✅ |
| `forward-close` | 关闭指定转发并销毁其活动连接 | — | ✅ |
| `forward-list` | 列出活动转发的模式、监听地址、目标与连接数 | ✅ | — |

### 裸 PTY 会话（agent-ssh）

`open-session` 的交互模式用 printf 标记包裹每条命令，以取回退出码和 CWD——这套协议依赖 POSIX shell，面对网络设备 CLI 会立即失效。裸 PTY 工具就是答案：`pty-open` 分配一个真正的伪终端（真 PTY，而非标记协议），把字节流交到你手上。`pty-write` 发送你输入的任何内容（换行自行包含：`"screen-length 0 temporary\n"`），`pty-read` 返回自你上个游标以来的全部输出，单次上限 32KB。

由于字节流无法做命令分类，安全门设在**打开**这一步：`pty-open` 按破坏性分类并走审批门。每次写入都被审计；每个会话都有转录（经脱敏，存放在审计日志旁，上限 10MB）；会话在空闲上限（`ptySessionIdleTimeoutMs`，默认 10 分钟）或生存期上限（`ptySessionMaxLifetimeMs`，默认 2 小时）到达后自行终止。请在设备上使用专用的低权限账户——转录是补偿性控制，不是授权。

### 设备档案（agent-ssh）

profile 上的 `deviceType`（`huawei` | `h3c` | `cisco` | `ruijie` | `generic`）让裸 PTY 会话学会对应厂商的方言：会话打开后，档案中的关分页命令会自动发送（华为 VRP `screen-length 0 temporary`、华三 `screen-length disable`、思科/锐捷 `terminal length 0`），且每次 `pty-read` 都会报告缓冲区尾部是否止于该厂商的提示符——即网络设备版的「命令执行完毕」。编码目前为 UTF-8；遗留的 GB2312/GBK 设备输出是 `src/devices/archives.ts` 中已登记的缺口，不是暗含的假设。

### 流式文件传输

`sftp-upload`/`sftp-download` 让文件*内容*经过模型上下文：出去时内容是参数，回来时是响应。传一段配置片段时这正是你要的；传一个 200 MB 的 tar 包或任何二进制文件时，这恰恰是你不要的。

这两个工具对已存在目标的处理方式也不同，批准字符串如今写明了区别。`sftp-upload` 无条件覆盖，并且每次都带 `--overwrite`，因为它本来就是无条件覆盖；`sftp-upload-file` 则拒绝执行，除非你传 `overwrite: true`，此时才携带该标志。由于 `sftp-upload` 的内容是参数而非本地文件名，它的批准字符串还带有 `--bytes=<n> --sha256=<32 hex>`——否则对同一路径的两次上传会生成相同的字符串，一次批准就同时覆盖两次，审计者也无法分辨落地的是哪一组字节。摘要用 128 位而非短前缀，因为这个结论必须能顶住「两次载荷都由调用方挑选」的情形，而不只是防偶然重复。

`[policy].denylist` 的模式会针对整个字符串做匹配，并且对五个 SFTP 工具还会针对远程路径本身单独匹配——按原样、按词法规范化后、以及按 Windows 的读法各一次（见「策略引擎」）。为路径写的规则（如 `authorized_keys$`）因此不依赖字符串里路径的位置，也不依赖文件的拼写。锚定在*整个字符串*上的规则（`^sftp:upload /root/.*$`）则不然：这个布局由我们掌控、可能变化，所以请锚定在路径上。

`sftp-upload-file` 与 `sftp-download-file` 改为在远程主机与本地磁盘之间流式传输。字节本身及其 base64 编码都不会到达模型——响应是一个字节数和两个路径。

这两个传输工具**默认关闭，直到你配置 `defaults.transferRoot`**，在那之前会拒绝并给出解释。（`sftp-list` 没有本地一侧，无需这些。）该目录就是它们本地可达范围的全部：

```toml
[defaults]
transferRoot = "/srv/ssh-mcp-transfers"
transferMaxBytes = 268435456        # 每次传输 256MB
transferTimeoutMs = 300000          # 5 分钟内无字节移动即超时
```

每次调用都会检查，且任何一项不满足都是拒绝而不是降级：目录必须是 `0700` 且属主为运行本服务器的账户，父目录不得对组或其他人可写，且不得与 ssh-mcp 安装目录、配置目录、审计日志目录或 `~/.ssh` 重叠。调用方路径被限制在该目录内，符号链接一律拒绝而不跟随；下载会先写到同级的 `.part` 文件再原子发布，因此失败的传输不会在目标位置留下写了一半的文件。

`transferTimeoutMs` 是**空闲**预算，不是总预算：它限制一次元数据往返，或拷贝过程中无字节移动的一段，并在有进展时重新计时。慢但仍在推进的大文件传输不受影响；停滞的通道仍会在一个窗口内失败。这就是为什么上面的字节上限不需要除以它——若按总预算计，256MB 的上限就等于「仅当链路能持续跑出 900 KB/s」。

Windows 上不可用：传输根目录还无法在 Windows 上验证其私有性；两个传输工具在该平台直接拒绝，而不是写进一个其他账户可能读得到的目录。

`sftp-upload-file` 接受可选的 `mode`（1–511；setuid、setgid 与粘滞位会被拒绝）。省略时，新建的远程文件以 `0600` 发布；覆盖已有文件时继承被替换文件的权限位——仅权限位本身，不含 setuid 或 setgid。

一次传输获得授权的范围包含这些参数：策略引擎分类的字符串、人读到的审批提示、以及审计记录，在给出 `--overwrite` 与 `--mode` 时都会如实写明。因此批准某路径的一次上传，不等于批准同路径的另一次上传；审批授权（`approvalGrantTtlMs`）也不能带着不同的 mode 重放。

### 交互式会话

会话在多条命令之间维持状态（CWD、环境变量）：

```
Agent: open-session(name="deploy", type="interactive")
Agent: run-command(session="deploy", command="cd /opt/myapp")
Agent: run-command(session="deploy", command="git pull")    # 在 /opt/myapp 中执行
Agent: run-command(session="deploy", command="npm ci")      # CWD 保持
Agent: close-session(name="deploy")
```

### 后台会话

长时间运行的进程（日志、构建）：

```
Agent: open-session(name="logs", type="background", command="tail -f /var/log/syslog")
Agent: read-session-output(name="logs", lines=20)   # 轮询
Agent: close-session(name="logs")
```

### 远程主机支持

已在以下环境测试：Linux（Debian/bash、Alpine/busybox ash）、Dropbear，以及 Windows 11 上的 Windows OpenSSH。

| | Linux / BSD / macOS | Windows OpenSSH |
|---|:---:|:---:|
| `read-command`、`run-command`、`privileged-command`、`signal-process` | ✅ | ✅ |
| `sftp-upload`、`sftp-download` | ✅ | ✅ |
| `sftp-list` | ✅ | ✅ |
| `sftp-upload-file`、`sftp-download-file` | ✅ | ❌（本地一侧无法验证） |
| 后台会话 | ✅ | ✅ |
| **交互式会话** | ✅ | ❌ |

**交互式会话需要 POSIX shell**（sh、bash、ash、zsh）。其原理是用 `printf` 标记包裹每条命令，并从结尾读取 `$?` 与 `$PWD`——这些东西在 `cmd.exe`（Windows OpenSSH 的默认 shell）里都不存在。对这类主机打开交互会话会立即失败并给出明确错误，而不是超时；其余功能一切正常。

把 PowerShell 设为 OpenSSH 的 `DefaultShell` 也无济于事：这套协议是 POSIX 专属的，不只是「非 `cmd`」的问题。

---

## 配置

### Profile 选项

```toml
[defaults]
defaultProfile = "dev"
sessionMaxPerConnection = 5
sessionIdleTimeoutMs = 600000       # 10 分钟
sessionBackgroundMaxMs = 3600000    # 1 小时
commandTimeoutMs = 60000
commandMaxChars = 5000              # 0 = 不限制；配置文件里 --maxChars=none 的写法
commandMaxOutputBytes = 1048576     # 1MB
connectionIdleReapMs = 900000       # 15 分钟
commandQuotaPerDay = 0              # 0 = 不限制；防止 agent 失控的熔断器
approvalGrantTtlMs = 0              # 0 = 每次都提示；见「审批授权」
approvalMode = "ask-destructive"    # auto | ask-destructive | ask-all | deny
# transferRoot = "/srv/ssh-mcp-transfers"   # 启用流式文件工具；见上文
transferMaxBytes = 268435456        # 每次流式传输 256MB
transferTimeoutMs = 300000          # 5 分钟内无字节移动即超时（按空闲计，非总时长）

[[profiles]]
name = "prod-web-1"
host = "10.0.1.50"
port = 22
user = "deploy"
auth = "agent"                      # agent | key | password | keychain
keyRef = "~/.ssh/id_ed25519"        # auth=key 时使用
keychainEntry = "ssh-mcp/prod"      # auth=keychain 时使用（需要 @napi-rs/keyring）
via = "bastion"                     # ProxyJump——经由 bastion profile 路由
group = "prod"                      # 策略层级：prod | staging | dev，或自定义（见 [policy]）
workdir = "/var/www"
trustedHostKey = "SHA256:..."       # 固定主机密钥（可选）
tty = false
# agent-ssh：网络设备兼容（仅为该主机放宽冻结的算法白名单——
# 解析基于冻结的基础配置，绝不是 ssh2 的默认值）。
# 每项覆盖在加载时都会告警，并在审计日志中把相关命令标记为 algorithmsOverride=true。
# 旧式算法名会降低传输安全下限；请把覆盖范围收紧到具体主机。
# algorithms = { kex = { append = "diffie-hellman-group1-sha1" }, cipher = ["aes128-cbc", "3des-cbc"], serverHostKey = { append = "ssh-rsa" }, hmac = { append = "hmac-sha1" } }
# deviceType = "huawei"               # generic | huawei | h3c | cisco | ruijie（关分页/提示符特性）
# keyboardInteractive = false         # 用解析出的密码回答 keyboard-interactive 提示
role = "operator"                   # viewer | operator | admin
readOnly = false
approvalPolicy = "ask-all"
cert = false                        # SSH CA 证书认证——自动探测 keyRef-cert.pub
announceAgent = true                # 向该主机发送 AI_AGENT=ssh-mcp（见下文）；对不受你控制的主机请清除
sessionMaxPerConnection = 3         # 按 profile 覆盖
sessionIdleTimeoutMs = 300000       # 生产环境更严格
commandQuotaPerDay = 200            # 按 profile 覆盖
maxChars = 2000                     # 按 profile 覆盖；生产环境更严格
transferMaxBytes = 16777216         # 按 profile 覆盖；transferRoot 不能按 profile 设置
transferTimeoutMs = 60000           # 按 profile 覆盖

# 可选。合并到内建角色矩阵之上；见下文「策略引擎」。
# roleBindings 按 role 再按 tier 索引，因此下面这段只改 prod 上的 operator，
# operator 的其他 tier 以及 viewer、admin 都保持默认。
[policy]
denylist = ["^terraform\\s+destroy", "\\.ssh/authorized_keys$"]

[policy.roleBindings.operator]
prod = ["read-only", "safe", "destructive"]
```

未知的节与键是启动错误，不是告警—— typo 不可能让你在以为自己覆盖过的配置上跑在默认值上。这条规则也延伸到角色与层级名称：你写在 `[policy.roleBindings]` 下的每个角色/层级，都必须能被某个 profile 达到；每个 profile 的 role 与 tier 也必须能解析到真实绑定。两个方向都在启动时检查。

### 主机侧标识

本服务器运行的每条命令都会以环境变量 `AI_AGENT=ssh-mcp` 的形式向主机表明身份，运维人员因此能从任何读取会话环境的东西——比如一段 `/etc/profile` 脚本或 `ForceCommand` 包装器——分辨出 agent 会话与真人的会话。它覆盖命令可以运行的全部三种通道：一次性命令、后台会话与交互式会话。SFTP 传输不携带它，因为本服务器使用的 SSH 库无法在 subsystem 通道上发送环境请求。

**只有主机选择接受，该变量才会进入会话**，即在 `sshd_config` 中配置 `AcceptEnv AI_AGENT`。没有这一行时 sshd 会忽略它，会话环境不变——这一点对照过完全没有 `AcceptEnv` 机制的 Dropbear，以及默认配置的 Windows OpenSSH：命令照常运行，退出码不变，变量只是不在。

**但无论主机是否接受，请求都会发给每台主机。** `AcceptEnv` 是服务器关于「存储什么」的策略，不是对「本客户端发送什么」的门。未接受的主机——包括怀有敌意的主机——依然能从线上看出驱动会话的是 agent 而非真人。这就是 profile 上存在 `announceAgent = false` 的原因：对任何不受你控制的主机设置它，就不会向其发送任何内容。它默认开启，因为从中受益的，正是运营着「你可控主机」的那些运维。

我们刻意不发送版本号。版本号会把敌意主机的侦察范围缩小到某个具体构建，而工具名本身不会。（SSH 传输本来就会在 identification string 中暴露*库*版本——那是所有使用该库的程序共有的一个版本号。）

请把这个变量当作礼节性标签，而不是身份证明。任何 SSH 客户端都能设置它，任何 agent 也都能省略它，所以它适用于归因「你本来就已信任」的会话，不得用作授权或入侵检测的输入。权威的归因属于完成认证的那把密钥或那个主体。

### ProxyJump（堡垒机）

经堡垒机/跳板机抵达内网主机。`via` 字段指定要穿隧的 profile 名：

```toml
[[profiles]]
name = "bastion"
host = "bastion.example.com"
user = "deploy"
auth = "agent"

[[profiles]]
name = "internal-db"
host = "10.0.1.50"                 # 内网 IP——无法直接到达
user = "dbadmin"
auth = "key"
keyRef = "~/.ssh/db_key"
via = "bastion"                     # 经 bastion 隧道
```

不做 agent 转发——只有一条经 `forwardOut` 的 TCP 隧道。堡垒机连接保持不断，可供多台内网主机复用。

### SSH CA 证书

面向采用中心化 SSH 证书颁发机构（CA）的企业环境：

```toml
[[profiles]]
name = "prod-db"
host = "db.internal"
user = "admin"
auth = "key"
keyRef = "~/.ssh/id_ed25519"
cert = true                         # 启用 CA 证书认证
```

证书文件按 OpenSSH 惯例自动探测（`keyRef` + `-cert.pub`，如 `~/.ssh/id_ed25519-cert.pub`）。可用环境变量 `SSH_MCP_<NAME>_CERT` 覆盖路径。证书按 ssh2 惯例与私钥拼接。

### 凭据解析顺序

1. **SSH agent**（`SSH_AUTH_SOCK`）——进程内存中无密钥材料
2. **操作系统密钥链**（macOS Keychain / Windows 凭据管理器 / Linux Secret Service）——需要 `auth = "keychain"` 与 `@napi-rs/keyring`
3. **环境变量**——`SSH_MCP_PASSWORD`、`SSH_MCP_KEY`、`SSH_MCP_SUDO_PASSWORD`，或按 profile 的 `SSH_MCP_<NAME>_PASSWORD`
4. **密钥文件**——`keyRef` 路径或环境变量 `SSH_MCP_KEY`

**绝不走 CLI 参数。** v2 彻底移除了 `--password`、`--sudoPassword`、`--suPassword`。

---

## 策略引擎

### 角色

| 角色 | Dev | Staging | Prod |
|------|-----|---------|------|
| **viewer** | read-only | read-only | read-only |
| **operator** | read-only, safe, destructive | read-only, safe, destructive | read-only, safe |
| **admin** | 全部 | 全部 | read-only, safe, destructive |

应用哪一列由 profile 的 `group` 决定。请显式设置——否则层级会从 profile 名称猜测（`prod`/`staging`/`dev`、`local`、`test`、`sandbox`），且**无法识别的名称一律解析为 `prod`**，即最严格的一档。因此一台名为 `web-01` 的生产主机会按生产对待，而不是悄悄拿到 dev 权限。

注意这对 `sudo` 意味着什么：**`admin` 在 `prod` 上没有 `privileged`**，因此 `privileged-command` 在那里会被设计性拒绝——包括 quick-start profile，它没有名字可推断，同样落到 `prod`。如果那台主机不是生产环境，请明说：

```bash
npx ssh-mcp --host=10.0.0.5 --user=deploy --group=dev
```

```toml
[[profiles]]
name = "build-box"
group = "dev"
```

### 配置矩阵

上面的表格是默认值，不是上限。可选的 `[policy]` 节会在启动时合并到其上——于是在一台你如实标注为 `prod` 的主机上开放 sudo，就成了配置文件里一行可评审的改动，而不是重新贴标签：

```toml
[policy.roleBindings.admin]
prod = ["read-only", "safe", "destructive", "privileged"]
```

合并发生在 role *与* tier 两个深度。上面那段只改 `prod` 上的 `admin`，别无其他：`admin` 在 `staging` 与 `dev` 上保持默认，`viewer` 与 `operator` 也不受影响。默认值没听说过的角色与层级会被新增而非拒绝——这正是自定义 `group` 能解析到真实绑定、而不是回落到最严格一档的机制：

```toml
[[profiles]]
name = "build-box"
role = "admin"
group = "tier-1"

[policy.roleBindings.admin]
"tier-1" = ["read-only", "safe", "destructive"]
```

额外的拒绝模式放在同一节，叠加在「永不放行」清单之上而不是替换它：

```toml
[policy]
denylist = ["^terraform\\s+destroy", "\\.ssh/authorized_keys$"]
```

每个模式都是一个正则表达式，对每次调用的命令字符串做匹配。对五个 SFTP 工具，它还会针对远程路径本身以三种方式匹配：按原样；按规范化读法（`//` 与 `/./` 折叠、`..` 相对其前一段解析、结尾 `/` 去除、`\` 按 `/` 读）；以及按 **Windows 读法**（不区分大小写地匹配）。拒绝消息会说明是哪一条命中。

Windows 读法对应的是 Win32 实际解析路径的结果——在 Windows 11（build 26200）上经 SFTP 实测：大小写变体、结尾的成串点与空格、`::$DATA` 默认流拼写都指向同一个文件，因此「抓得住一种拼写却放走另一种」的规则是绕过，不是区别。在规范化读法的基础上，它还会剥掉这些拼写、把盘符相对路径（`C:x/…`）锚定到其盘符（实际解析位置取决于本服务器无法看见的进程状态，锚定是 fail-closed 的读法）、去掉 `\\?\` 与 `\\.\` 设备前缀，并保留 UNC 根（`\\server\share\…` → `//server/share/…`）。它不区分大小写地匹配，因此为 `authorized_keys` 写的规则也能抓住 `Authorized_Keys`；在 POSIX 目标上这是两个不同的文件，但向拒绝一侧出错正是本引擎在所有其他地方一致采取的方向。

这些读法**不会**做的事：

- **在目标机上解析任何东西。** 相对路径保持相对，因此锚定在 `/root/` 的规则看不到 `.ssh/authorized_keys`；符号链接不跟随；8.3 短名（`AUTHOR~1`）也不展开——任何词法读法都做不到，要知道长名必须查目标自己的目录列表。
- **单独检测 `sftp-upload-file` 或 `sftp-download-file` 的本地路径。** 那一侧由 `transferRoot` 限制。本地路径确实会出现在这两个工具的命令字符串末尾，因此锚定字符串末尾的模式仍能在那里命中，这一点一直如此。

所以路径规则请锚定在结尾的路径段上：`\.ssh/authorized_keys$` 对绝对、相对与 Windows 拼写一视同仁——包括各自的大小写、结尾点与 `::$DATA` 变体。为命令写的模式也会作用于 SFTP 路径——`^rm` 会拒绝下载名为 `rmlist.txt` 的文件。

一条性能说明：这些模式是跑在调用方提供的路径字节上的普通正则——受远程路径长度上限约束，与命令字符串一直以来的暴露面相同。请优先使用锚定的线性模式；一个灾难性回溯的模式会卡死它命中的那次工具调用。

由于角色与层级名称是自由字符串，合并本身无法区分「新增自定义角色」与「既有角色的拼写错误」。启动时的交叉检查可以，下列情形都在启动时失败，而不是在使用点才暴露：

- 命令类别不在 `read-only | safe | destructive | privileged` 之内——`priviledged` 这样的拼写错误不会解析成一个空授权，然后在命令被拒绝时被误读成一项策略决定；
- 配置中任何位置出现无法识别的节或键——解析器看不懂的块是错误，而不是「正常启动但你配置的行为一项都没生效」；
- `[policy.roleBindings]` 下没有任何 profile 使用的角色或层级——`[policy.roleBindings.operater]` 不会作为第四个角色悄悄并入，而你本想收紧的那些 profile 也不会继续跑在默认值上；
- 某个 profile 的 `role` 没有绑定，或其 tier 在该角色下没有绑定——主机不会因为一个没人写下来的理由落到 `read-only`。

最后一条同样覆盖你没显式设置的 tier。没有 `group` 的 profile 仍会按名称解析出一个 tier，而这个推断出的 tier 也必须在该 profile 的角色下存在。

某角色在某个 tier 下没有任何绑定时授予 `read-only`，绝不会授予其他 tier 的类别。tier 之间没有回落：矩阵还是编译期内置时，回落到 `prod` 等于回落到某角色最严格的格子；如今 `[policy]` 块可以直接写下那个格子。

OPA sidecar 不是通往同一授权的后门。OPA 只对本地策略已经放行的命令做评估，所以它只能收紧、绝不能放宽。放宽只发生在这里，别无他处。

### 命令分类

每条命令在执行前都会被分类：

- **read-only**：白名单内的命令（`ls`、`cat`、`grep`、`df`、`stat`、`systemctl status` 等），且仅当每个参数都能在该二进制声明的文法下被证明是数据时——见下文
- **safe**：非破坏性变更（`npm install`、`git pull` 等）
- **destructive**：需要审批的变更（`rm -rf /tmp/build` 等）
- **privileged**：`sudo`、`su`、`doas`、`pkexec`

**`read-only` 由参数文法授予，而不是只看二进制名。** 白名单二进制的参数列表会逐词对照为它声明的文法（`src/policy/reader-grammar.ts`）检查：文法未列出的选项、已列选项的缩写、携带未列出字母的短选项簇、带未加引号 shell 通配符（`*`、`?`、`[`）的参数，或形如该二进制会写入的目标的操作数——任一出现，整条命令都降为 `safe`。这正是 `readOnly` profile 被限制的范围，是 `viewer` 在 prod 与 staging 上持有的权限（dev 上的 viewer 还额外持有 `safe`），也是 `read-command` 的要求——除 dev 上的 viewer 外，这些场景都拒绝 `safe`，因此过去在旧的「只看名字」规则下能跑的命令，现在可能被拒绝。拒绝消息会指出被拒的那个词（例如：`` `journalctl` 仅在其文法列出的选项与操作数下才是只读的；`--foo` 在那里不被接受 ``），调用方能看清同一命令的哪种写法仍然可用。由此遗留的风险见 [SECURITY.md](./SECURITY.md)。

另有一份 **forbidden** 清单，无论角色与审批策略如何都绝不放行：`rm -rf /`、`mkfs`、`dd of=/dev/`、`shutdown`、`curl|sh`、fork 炸弹、对 `/etc/cron`、`/etc/systemd` 或 `authorized_keys` 的写入、`iptables -F`，以及递归的 `chmod 777 /` / `chown /`。可通过策略 denylist 追加你自己的模式；非法模式在启动时即报错，不会静默降级。

### 审批模式

- `auto` —— 无提示（仅限 dev！）
- `ask-destructive` —— 对破坏性/特权命令提示（默认）。比字面意思更窄：在「永不放行」清单之外，`destructive` 指形如 `rm -rf /path` 的模式、带写入/执行标志的 `find`、无法解析的命令词、交给本服务器读不懂的解释器的程序（`python3 -c`、`perl -e`、`node -e`、经管道到达的程序——但不含 `awk`，它的程序不会被读取），以及 `sftp-upload`/交互式 `open-session`——提权归类为 `privileged`，同样提示。普通的写操作、服务控制与信号不在其列。在生产上依赖它之前先读 [SECURITY.md](./SECURITY.md)。
- `ask-all` —— 每条命令都提示
- `deny` —— 直接拒绝破坏性/特权命令（不提示）

### 审批授权（just-in-time）

`approvalGrantTtlMs` 允许一次显式审批在限定时间内覆盖同一 profile 上**完全相同**命令的重复执行（例如 `300000` 即五分钟）。它存在的原因是：在迭代任务中每隔几秒批准一次 `rm -rf /tmp/build`，会把你训练成对提示无脑点确认——这比一个你深思熟虑后给出的授权更不安全。

授权绑定于精确的命令文本、profile 与命令类别：批准 `rm -rf /tmp/build` 不覆盖 `rm -rf /tmp/build-prod`，不覆盖另一台主机上的同一命令，也不覆盖升级为 `sudo` 的同一命令。由授权覆盖的运行会在审计日志中记为 `approver: "jit-grant"`，与真人首次作答保持可区分。

**默认关闭**（`0` = 每次都提示）。自动审批削弱了让破坏性命令变得安全的这道门，因此开启它应当是一个郑重的决定。

#### 应答审批提示

> **v2 分离架构**：elicitation 路径随 stub 移除——审批走 Host 的 `approvalSurfaces`（队列 CLI/
> 桌面端，见下节）。本小节保留为上游 elicitation 行为的历史说明。

审批经 MCP elicitation 请求完成，你看到的就是客户端的对话框。接受即批准该命令——没有需要再填的第二个字段。

你有 **10 分钟**作答。超时后请求过期，命令被拒绝而不是悬而未决，拒绝消息会说明原因；提示框可能还开在你的客户端里，若是这样，准备好后再运行一次命令即可。如果客户端完全不支持 elicitation，所有破坏性与特权命令都会被拒绝并报 `APPROVAL_UNAVAILABLE` 注明原因——审批在设计上就是 fail-closed 的。

#### 审批面（Host 分离架构 v2）

Elicitation 需要客户端支持。分离架构下审批面由 Host 配置 `approvalSurfaces`（默认 `["desktop", "queue"]`）决定，与 MCP 宿主解耦：

- `desktop` —— 桌面审批端（Tauri 壳）收 `approval.pending` 推送，人工携校验码决定（破坏性类）。
- `im` —— 飞书面（T-17.6，需飞书开放平台前置）。
- `queue` —— 绝不询问客户端；每条破坏性命令都在文件队列中等待人工处理（`agent-ssh approvals` CLI 或桌面端决定）。

队列位于平台数据目录下（`…/agent-ssh/approvals/`，每条待审命令一个 JSON 文件，`0700` 目录内 `0600` 权限）。服务器会把精确的命令打印到 stderr：

```bash
APPROVAL_QUEUED id=173…-a1b2c3 — a destructive command on "prod-web-1" is waiting for a human.
Decide with: agent-ssh approvals approve 173…-a1b2c3   (or reject 173…-a1b2c3).
```

```bash
agent-ssh approvals list              # 全部待审请求，含已等待时长与剩余时间
agent-ssh approvals approve <id>      # 打印完整载荷，然后记录决定
agent-ssh approvals reject <id>
```

每条决定都会记录**是谁**运行的 CLI；审计日志显示为 `approver: "cli:<user>"`，与 `mcp-client` 和 `jit-grant` 可区分。过期后请求被标记为过期并拒绝——与 elicitation 超时一样 fail-closed。决定文件带有其所见载荷的指纹；一旦文件内容与指纹不符，服务器宁拒不跑——绝不执行一个未经批准的东西。我们刻意**不在 MCP 工具面上提供 approve 动词**——模型可以请求、等待、被拒绝，但只有拥有 shell 权限的人才能放行破坏性命令。

### 命令配额

`commandQuotaPerDay` 限制一个 profile 在滚动 24 小时窗口内可运行的命令数（0 = 不限制）。审批门拦住的是*破坏性*命令，HTTP 限流器限制的是请求速率，但两者都不限制总工作量——一个被提示注入的 agent 循环执行允许的命令，两条限制都拦不住它。配额就是为这种情况准备的熔断器。

计数发生在策略放行之后、执行之前，因此被拒绝的命令不消耗预算。窗口是滑动的，不在午夜重置——按午夜重置的话，agent 可以在重置前花完整个配额，重置后又立刻再来一份。

### 外部策略引擎（OPA）

面向统一采用 Open Policy Agent / Rego 的组织：

```bash
ssh-mcp --opaUrl=http://localhost:8181
```

设置 `--opaUrl` 后，内建引擎放行的命令会再交给 OPA 评估。**OPA 只能收紧。** 内建引擎已拒绝的命令直接返回拒绝，根本不会咨询 OPA，因此 sidecar 回答 `allow` 也给不了角色绑定扣下的类别。要放宽，请改 `[policy]`。

OPA 故障时回落到本地决定，并每分钟记录一条告警。这是默认行为，因为 OPA 是*额外*的拒绝层，停掉全部工作是更糟的失败——但如果运维是把 OPA *当作*授权门部署的，故障期间这道门就没了，而唯一的信号是一行 MCP 客户端通常会丢弃的 stderr。`--opaFailClosed` 让「门不可用」等于「否」；拒绝信息带 `ruleId: "opa-unavailable"`，审计记录因此说明「门当时不可用」，而不是暗示某条策略拒绝了命令。

请求结构参照 AuthZEN Access Evaluation 契约建模：

```json
{
  "input": {@NL@@    "subject": { "role": "operator", "profile": "prod-web-1" },
    "action": { "tool": "run-command", "commandClass": "destructive" },
    "resource": { "command": "rm -rf /tmp/cache", "binary": "rm", "host": "10.0.1.50" },
    "context": { "readOnly": false }
  }
}
```

对五个 SFTP 工具，`resource` 还携带三个路径键：`remotePath`（按原样的路径），以及 `remotePathNormalized` 与 `remotePathWindows`——即本地 denylist 所用的同两种读法，规则因此可以在不解析 `command`、不用 Rego 重实现读法的情况下匹配规范拼写。其他工具省略全部三个键，空路径亦然。`remotePath` 是**按原样**——`/root//.ssh/x` 传过来就是这个拼写，对目录做 `startswith` 的规则会漏掉它：请匹配结尾的路径段，或匹配规范化后的键。`remotePathWindows` 保留传入的大小写；要不区分大小写，请在策略里对两侧做 `lower()`。请匹配字段而不是整个 `resource` 对象——它的键因工具而异。

OPA 以 `{ "result": true/false }` 应答。若 OPA 拒绝（`result: false`），即使内建引擎放行，命令也会被拦截。若 OPA 不可达，默认按内建引擎的决定执行（fail-open，避免锁死访问）；`--opaFailClosed` 则改为拒绝。一个没有布尔 `result` 的 200 应答按不可达处理——OPA 对未定义文档就是这么答的，因此写错包名或未激活 bundle 是一次故障，而不是默许。

Rego 策略示例（`ssh-mcp.rego`）：
```rego
package ssh.mcp

default allow := false

# admin 在 dev 主机上通过 OPA 门。内建策略仍叠加在其上生效：
# 这不会放宽角色绑定扣下的任何权限。
allow if {@NL@@  input.subject.role == "admin"
  startswith(input.subject.profile, "dev")
}

# 拒绝 prod 上的所有破坏性命令
deny if {@NL@@  input.action.commandClass == "destructive"
  startswith(input.subject.profile, "prod")
}
```

---

## 安全

### 威胁模型

完整威胁模型、漏洞报告政策与部署检查清单见 [SECURITY.md](./SECURITY.md)。

### 供应链

发布产物携带签名证明（attestation），经 [Sigstore](https://www.sigstore.dev/) 发布并记入其公开透明日志。它们存放在**两个不同的存储**里，这决定了各自如何验证：

| 证明 | 谓词 | 存储方 | 起始版本 |
|---|---|---|---|
| 构建溯源——[SLSA](https://slsa.dev/) Build **Level 2** | `slsa.dev/provenance/v1` | npm | 每个版本 |
| SBOM——CycloneDX 与 SPDX | `cyclonedx.org/bom`、`spdx.dev/Document` | GitHub | v2.4.0 之后的版本 |

溯源来自 npm [trusted publishing](https://docs.npmjs.com/trusted-publishers)：发布工作流用短时效 OIDC 令牌认证，不落任何存储的凭据，因此不存在可泄露的长期 npm 令牌。

```bash
npm audit signatures        # 溯源，对照已安装的依赖树

npm pack ssh-mcp            # SBOM 证明绑定在 tarball 上，先取下来
gh attestation verify ssh-mcp-*.tgz --repo tufantunc/ssh-mcp --predicate-type https://cyclonedx.org/bom
```

最后一条命令的两个标志都缺一不可。`gh attestation verify` 默认匹配 SLSA 谓词，不加 `--predicate-type` 会把 SBOM 过滤掉并报告「未找到」——而它本要找的溯源存放在 npm 的存储里，不在 `--repo` 查询的 GitHub 存储里。SPDX 那份用 `https://spdx.dev/Document`。

两份 SBOM 也附加在每个 [GitHub release](https://github.com/tufantunc/ssh-mcp/releases) 上，供阅读而非校验。

**Level 2，而非 3。** 溯源由通用的 GitHub 托管 runner 签名——`builder.id` 是 `https://github.com/actions/runner/github-hosted`——构建过程本身能影响它；Build L3 要求一个它影响不到的隔离 builder。当前 L3 与 trusted publishing 不兼容：该设置保持默认时 npm 会开启自己的溯源，然后忽略一切外部生成的溯源。所以今天上 L3 意味着退回长期 npm 令牌——用一个等级数字换掉上述性质。

### 安全默认值

- 所有示例均使用**非 root** 用户
- **TOFU** 主机密钥验证（首次连接接受、此后验证——限于单进程内；见 [SECURITY.md](./SECURITY.md#主机密钥信任不跨重启保留)）
- **RFC 9142** 算法白名单（无 SHA-1、无 CBC、无 ssh-rsa）
- **提权仅用 exec()**（`privileged-command` 不接受 `session`，sudo 永远不在持久 shell 中运行——修复 PTY 泄露。交互式会话为普通命令而设；这一条讲的是提权，不是说所有路径都是 exec 通道）
- **sudo 经 stdin 传递**（不走 argv——修复进程列表泄露）
- **净化器**从所有元数据中剥离 CR/LF/NUL
- 审计日志**三层脱敏**（字段 → 正则 → 熵）
- **CLI 参数不携带机密**（用环境变量、密钥链或配置）
- **agent 身份明示而非隐藏**——每条命令都告诉主机 `AI_AGENT=ssh-mcp`，包括从未同意存储它的主机；指向不受控主机的 profile 请清除 `announceAgent`（见[主机侧标识](#主机侧标识)）

### 加固检查清单

- [ ] 在目标主机上创建专用的低权限服务账户
- [ ] 使用按命令限定的 `sudoers`，而不是 `NOPASSWD: ALL`
- [ ] 为生产 profile 启用 `ask-all` 审批
- [ ] 限制目标主机的网络出口
- [ ] 监控类 profile 使用 `readOnly = true`
- [ ] 定期复查审计日志
- [ ] 执行 `chmod 700 <config dir> && chmod 600 config.toml`（Windows：`%APPDATA%` 下的 ACL 已受限）

---

## 传输方式

> **v2 分离架构**：MCP 宿主↔stub 走 stdio；stub↔Host 走 RPC over TCP（见 HOST-RUNBOOK）。
> 本节的 **HTTP 传输已废止**（`--transport=http` 显式报错）；远程场景=Host 监听+反向代理 TLS。
> 下文 HTTP 节保留为 v1 历史说明，其中旗标/端点在 v2 均不存在。

### stdio（默认）

面向本地 MCP 客户端（Claude Code、Cursor、Windsurf）。无网络暴露。

```bash
ssh-mcp                          # 从 XDG 路径读取配置
ssh-mcp --config=/path/to.toml   # 自定义配置路径
```

### HTTP（可选）

面向置于带 TLS 的反向代理之后的远程/Web 客户端：

```bash
ssh-mcp --transport=http --httpPort=3000 --bearerToken=secret
ssh-mcp --transport=http --httpPort=3000 --bearerToken=secret --rateLimit=60
```

| 标志 | 默认值 | 说明 |
|------|---------|-------------|
| `--bearerToken` | 必填 | 用于认证的 Bearer 令牌（`GET /health` 以外的所有路由） |
| `--httpPort` | 3000 | HTTP 监听端口 |
| `--httpHost` | 127.0.0.1 | 绑定地址 |
| `--rateLimit` | 0（关闭） | 每客户端每分钟已认证请求上限（0 = 不限制） |
| `--httpSessionTtl` | 1800000 | HTTP 上 MCP 客户端会话的空闲超时，单位 ms（有请求在途或 SSE 流打开的会话不过期）。达到 64 会话上限时，新客户端会逐出最久不活跃且无请求在途的会话；仅当无其他可逐出时才逐出持有 SSE 流的会话 |
| `--authFailureLimit` | 10 | 每客户端每分钟允许的认证失败次数（0 = 关闭） |
| `--trustProxy` | false | 从 `X-Forwarded-For` 读取客户端地址，但仅在对端是代理时——裸标志意味着对端为 loopback |
| `--trustedProxies` | — | 允许发送 `X-Forwarded-For` 的对端地址，逗号分隔。为空表示仅 loopback |

端点：`POST /`（MCP Streamable HTTP）、`GET /status`、`GET /health`

`GET /health` 返回 `{"healthy": true, "configured": <bool>}`。无论哪种情况都是 `200`——`healthy` 表示存活；`configured` 在未设置任何 profile 时为 false，典型场景是配置 bind mount 静默没有挂上：服务器照常绑端口，但拒绝每一次工具调用。`GET /status` 返回 profile 列表本身，仍在 bearer 令牌保护之后。

`--rateLimit` 是按客户端计的预算，键的取法与下面的认证失败预算一致，每个已认证请求都会消耗它：`POST /` 与其余 MCP 路由、`GET /status`，以及对不存在路径的已认证请求。`GET /health` 永不消耗；错误令牌同样不消耗，因此未认证流量花不掉正常客户端的预算。预算耗尽时服务器返回 HTTP 429 和 JSON-RPC 错误体，`Retry-After` 给出距该客户端下一个请求被接受的秒数。

认证失败单独限流，且默认开启。`--rateLimit` 从来看不到错误的 bearer 令牌，因为认证检查先于限流器应答——猜令牌本可以跑满网络速度。`--authFailureLimit` 给每个客户端一个独立的小预算，只在 401 时消耗；正确令牌永不动用它，正常客户端不会限流自己。地址一旦耗尽预算，其后的所有请求都要等待——包括带正确令牌的请求，这是刻意的：否则应答「猜的那次」就等于告诉调用方哪个令牌是对的。客户端按 socket 地址区分，此预算与 `--rateLimit` 皆然。**在反向代理之后，这意味着所有客户端共享同一份两种预算**，所以代理归你管时请设置 `--trustProxy`——服务器第一次在未设置该标志时见到 `X-Forwarded-For` 会打印告警。`--trustProxy` 取*最右*一条 `X-Forwarded-For` 条目，即代理自己追加的那一跳；其左的全部来自客户端，读最左一条等于让客户端自选预算或花掉受害者的预算。这只有「代理确实追加了条目」时才成立，因此该头部**仅在对端是代理时**才读——裸 `--trustProxy` 表示对端为 loopback，即上面的部署；代理在别处时用 `--trustedProxies` 指定。头部无法按地址解读、或对端不受信时，服务器回落到 socket 地址并说明一次，因此「标志没生效」不会是无声的。默认只假定一跳可信。格式非法的 `--authFailureLimit` 在启动时被拒绝，而不是静默关闭检查；只有 `0` 才是关闭。

IPv6 客户端按其 /64 而非完整地址区分，两种预算皆然。/64 通常是运营方分配给用户的最小块，因此共享一个 /64 的主机——同一家庭或办公网络、或托管商放在同一 /64 的客户——共享一份预算，如同一个 IPv4 NAT 后面的主机。携带 IPv4 地址的 IPv6 地址（IPv4-mapped，或 NAT64 前缀 `64:ff9b::/96`）按那个 IPv4 客户端计。使用自有前缀的 NAT64 或 SIIT 转换器无法识别：其转换的所有 IPv4 客户端共享该前缀的 /64，即共享一份预算。

**务必在反向代理（Caddy/nginx）终结 TLS。** 服务器只监听 `127.0.0.1`。

---

## Docker

```bash
# 构建
docker build -t ssh-mcp .

# 运行（配置文件 + 环境变量提供凭据）
docker run -i \
  -v ./config.toml:/home/appuser/.config/ssh-mcp/config.toml:ro \
  -e SSH_MCP_PASSWORD=secret \
  ssh-mcp
```

或使用 docker-compose：

```bash
docker-compose --profile app up
```

Docker 镜像以非 root 的 UID 65532 运行，基础镜像为最小化的 `node:22-slim`。

---

## CLI 标志（v2）

> **v2 分离架构**：下表中旧直连服务器的旗标（`--host/--user/--password/--group/--transport=http/
> --bearerToken/--httpPort` 等）已随 stdio 直连与 HTTP 传输废止——传入即显式报错（removed in v2）。
> 现役命令面：`agent-ssh`（stub：`--host-addr` 或 env）／`agent-ssh host serve|init`（`--port=0`
> `--config=路径`）／`agent-ssh approvals …`。权威清单见 [HOST-RUNBOOK](docs/HOST-RUNBOOK.md)。

机密**绝不**通过 CLI 参数传递。

| 标志 | 默认值 | 说明 |
|------|---------|-------------|
| `--config` | 平台配置目录（见[配置](#2-配置)） | TOML 配置文件路径 |
| `--host` | — | 快速启动：SSH 主机（生成单 profile 配置） |
| `--user` | — | 快速启动：SSH 用户名 |
| `--port` | 22 | 快速启动：SSH 端口 |
| `--key` | — | 快速启动：私钥路径 |
| `--workdir` | — | 快速启动：命令与会话的工作目录 |
| `--group` | prod | 快速启动：策略层级——`prod`、`staging` 或 `dev` |
| `--timeout` | 60000 | 命令超时，单位 ms |
| `--maxChars` | 5000 | 命令最大长度（`none` 或 `0` 关闭上限；配置文件中同一设置为 `commandMaxChars = 0`） |
| `--sessionMax` | 5 | 每连接最大并发会话数 |
| `--sessionTtl` | 600000 | SSH 会话空闲超时，单位 ms |
| `--transport` | stdio | `stdio` 或 `http` |
| `--httpPort` | 3000 | HTTP 传输端口 |
| `--httpHost` | 127.0.0.1 | HTTP 绑定地址 |
| `--bearerToken` | — | HTTP 传输认证用 Bearer 令牌（`--transport=http` 时必填） |
| `--rateLimit` | 0 | 每客户端每分钟已认证请求上限（0 = 不限制） |
| `--httpSessionTtl` | 1800000 | HTTP 上 MCP 客户端会话的空闲超时，单位 ms（有请求在途或 SSE 流打开的会话不过期）。达到 64 会话上限时，新客户端会逐出最久不活跃且无请求在途的会话；仅当无其他可逐出时才逐出持有 SSE 流的会话 |
| `--authFailureLimit` | 10 | 每客户端每分钟允许的认证失败次数（0 = 关闭） |
| `--trustProxy` | false | 从 `X-Forwarded-For` 读取客户端地址，但仅在对端是代理时——裸标志意味着对端为 loopback |
| `--trustedProxies` | — | 允许发送 `X-Forwarded-For` 的对端地址，逗号分隔。为空表示仅 loopback |
| `--allowedHosts` | 绑定地址 + localhost | DNS 重绑定防护接受的 Host 头，逗号分隔 |
| `--hostKeyMode` | `tofu` | `tofu \| strict \| insecure`。`strict` 只接受用 `trustedHostKey` 固定的主机。见 [SECURITY.md](./SECURITY.md#主机密钥信任不跨重启保留) |
| `--insecureHostKey` | false | 对没有 `trustedHostKey` 的主机关闭主机密钥验证——已固定的主机依然拒绝（仅限测试！） |
| `--allowUncheckedConfigAcl` | false | Windows：报告全部 ACL 发现，不拒绝任何情况 |
| `--strictConfigAcl` | false | Windows：对每项 ACL 发现都拒绝，包括只读过度授权 |
| `--disableApproval` | false | 跳过审批门（仅限快速启动 profile） |
| `--opaUrl` | — | 外部策略用 OPA sidecar URL |
| `--opaFailClosed` | false | OPA 不可达期间拒绝一切命令，而不是回落本地策略 |
| `--opaTimeoutMs` | 10000 | 等待 OPA sidecar 的时长。调低让 fail-open 更早触发；调高让故障更迟被发现 |
| `--commandQuota` | 0（关闭） | 每 profile 每 24h 滚动窗口的最大命令数 |
| `--approvalGrantTtl` | 0（关闭） | 批准后该时长（ms）内自动批准完全相同的命令 |
| `--auditEntropyScan` | false | 在审计中启用基于熵的机密扫描 |
| `--auditTamperEvident` | false | 启用哈希链防篡改审计日志 |
| `--otelEndpoint` | — | OpenTelemetry 追踪的 OTLP/HTTP 端点 |
| `--otelServiceName` | ssh-mcp | 追踪 span 上报的服务名 |
| `--dumpToolHashes` | — | 打印工具描述的 SHA-256 哈希后退出 |

---

## 从 v1 迁移

v2 是破坏性版本。传入已移除的标志现在会在启动时失败并给出替代方式，而不是拖到之后才报一个莫名其妙的认证错误。

### 工具

| v1 | v2 | 说明 |
|----|----|-------|
| `exec` | `read-command` | 白名单内的只读命令。读取操作请优先用它。 |
| `exec` | `run-command` | 任意命令。破坏性与特权命令经审批门，除非 `approvalPolicy = "auto"`。 |
| `sudo-exec` | `privileged-command` | 需审批，除非 `approvalPolicy = "auto"`。密码经 stdin 管道传入。 |
| `description` 参数 | — | 已移除。它是注入向量（#44），且从未到达过主机。 |

**命令结果现在携带状态。** v1 中失败的命令以 `Error (code N)` 拒绝。v2 中非零退出码会作为错误结果返回，包含退出码与 stderr——空响应不再意味着「成功了」。

### 标志

| v1 标志 | 替代方式 |
|---------|-------------|
| `--password` | 环境变量 `SSH_MCP_PASSWORD`（或 `SSH_MCP_<PROFILE>_PASSWORD`） |
| `--suPassword` | 环境变量 `SSH_MCP_SUDO_PASSWORD` |
| `--sudoPassword` | 环境变量 `SSH_MCP_SUDO_PASSWORD` |
| `--disableSudo` | 使用禁止 `privileged` 类别的角色/策略 |

凭据移出命令行，是因为在 Linux 上 CLI 参数经 `/proc/<pid>/cmdline` 对全体用户可读（CWE-214）。凭据现在经 SSH agent → 操作系统密钥链 → 环境变量 → 密钥文件的级联解析。

### 示例

```jsonc
// v1
{ "command": "npx", "args": ["ssh-mcp", "--host=1.2.3.4", "--user=root", "--password=hunter2"] }

// v2 —— 凭据走环境变量
{
  "command": "npx",
  "args": ["ssh-mcp", "--host=1.2.3.4", "--user=root"],
  "env": { "SSH_MCP_PASSWORD": "hunter2" }
}
```

多台主机时，请改用 TOML 配置文件（见[配置](#配置)）并传 `--config <path>`；profile 承载每台主机的角色与审批策略。

### 主机密钥验证

v1 不验证主机密钥。v2 默认 trust-on-first-use，并把密钥记录**在内存中、进程存续期内**；同一进程内之后的失配会使连接失败。任何东西都不落盘，也不查询 `~/.ssh/known_hosts`，因此重启后重新接受——见 [SECURITY.md](./SECURITY.md#主机密钥信任不跨重启保留)。请用 profile 里的 `trustedHostKey` 显式固定，这是这里唯一能跨重启保留的控制，且任何主机密钥模式都不能覆盖它——因此 `--insecureHostKey` 只是针对未固定主机的选择退出（仅限测试环境）。

---

## 测试

```bash
# 启动测试 SSH 服务器。--build 很重要：compose 会复用已有镜像，
# fixture 的改动（比如 alpine 目标的 AcceptEnv 行）就永远不会生效，
# 在集成套件里表现为产品故障。
docker compose --profile test up -d --build

# 运行全部测试
npm test

# 仅运行单元测试
npm test -- test/unit/

# 带覆盖率运行
npm run coverage
```

## MCP Inspector

```bash
npm run inspect
```

---

## 参与贡献

见 [CONTRIBUTING.md](./CONTRIBUTING.md)。所有 PR 请遵循[安全检查清单](./SECURITY.md#贡献者安全检查清单)。

## 支持

如果 SSH MCP Server 对你有帮助，欢迎给仓库点星或[赞助](https://github.com/sponsors/tufantunc)！

## 收录于

[![SSH MCP Server on Glama](https://glama.ai/mcp/servers/tufantunc/ssh-mcp/badge)](https://glama.ai/mcp/servers/tufantunc/ssh-mcp)

同时收录于[官方 MCP registry](https://registry.modelcontextprotocol.io)，条目为 `io.github.tufantunc/ssh-mcp`。

