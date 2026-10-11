# 致谢

v2 是一次近乎全部重写，这意味着许多社区贡献塑造了最终结果，却没有以提交的形式被合并。GitHub 的贡献者图谱只统计被合并的提交，所以有了这个文件，记录图谱记录不了的东西。

## 改变了设计的反馈问题

- **[@BlackBird-BB](https://github.com/BlackBird-BB)** —— 发现凭据只能通过命令行标志传递，任何本地用户都可读到（CVE-2026-7038）。移除这条路是 v2 做的第一件事。
- **[@codyaverett](https://github.com/codyaverett)**，与 [@amosroger91](https://github.com/amosroger91) 和 [@apage43](https://github.com/apage43) —— 在 [#33](https://github.com/tufantunc/ssh-mcp/issues/33) 中论证了 Lethal Trifecta 风险并列出缓解措施。策略引擎、命令分类、审批流与审计日志全部可以追溯到那个帖子。
- **[@msexxeta](https://github.com/msexxeta)** —— 报告输出消失、命令文本泄露进结果（[#27](https://github.com/tufantunc/ssh-mcp/issues/27)），并提议用生成的标记取代提示符检测（[#46](https://github.com/tufantunc/ssh-mcp/pull/46)）。v2 的会话协议正是这样工作的。
- **[@wbern](https://github.com/wbern)** —— 要求把只读命令区分出来，以便 agent 能被放心授权使用（[#23](https://github.com/tufantunc/ssh-mcp/issues/23)）。这就是存在独立 `read-command` 的原因。
- **[@jonathanbird](https://github.com/jonathanbird)** —— 要求 `readOnlyHint`（[#36](https://github.com/tufantunc/ssh-mcp/issues/36)），并指出给 `exec` 加注解并不属实。拆分工具正是对这一异议的回应。
- **[@sunjl17](https://github.com/sunjl17)** —— 遇到「the input device is not a TTY」（[#31](https://github.com/tufantunc/ssh-mcp/issues/31)），现为每次调用可选的 `tty` 参数。
- **[@veithly](https://github.com/veithly)** —— 无法使用加密私钥（[#25](https://github.com/tufantunc/ssh-mcp/issues/25)），现已支持并有测试。
- **[@deevus](https://github.com/deevus)** —— 要求通过环境变量配置（[#32](https://github.com/tufantunc/ssh-mcp/issues/32)）；`SSH_MCP_KEY` 即其要求的变量。
- **[@Blackspell01](https://github.com/Blackspell01)** —— 报告 `sudo` 在 v2 中失效（[#91](https://github.com/tufantunc/ssh-mcp/issues/91)），并在第一个修复未解决问题后持续跟进。那个帖子最终横跨三个版本共挖出四个独立缺陷：一个永远到不了 `privileged` 类别的快速启动 profile；一个因包含该词而拒绝 `last reboot` 的拒绝清单；一个选择 Accept 却被回以「你已拒绝」的审批对话框；以及 `--disableApproval`——他们被告知使用的变通办法——静默无效。正是截图（而非概述）让后两个缺陷有可能被发现。

## 被合并的贡献

- **[@nordscope-fi](https://github.com/nordscope-fi)** —— 把角色矩阵做成可配置的（[#108](https://github.com/tufantunc/ssh-mcp/pull/108)，关闭 [#95](https://github.com/tufantunc/ssh-mcp/issues/95)），随后在关键方向上超出了任务书。他们自己的复审在任何人看到分支之前，就在合并代码里发现了一个原型污染漏洞。评审中他们纠正了我的一个断言——我曾归因于移除 tier 回落的一项成本实际不可达——并给出了真正可达的情形：一个部分自定义角色，其所有 profile 都未设置 `group`，于是静默拿到生产环境的授权，全程没有任何拼写错误可拦截。如今在启动时拒绝这类配置的校验出自他们，连我们俩都没要求的推断 tier 情形也包括在内。

  随后他们从同一故障的另一端诊断了 [#91](https://github.com/tufantunc/ssh-mcp/issues/91) 的审批对话框，客户端日志显示两次响应相隔 30 秒。在协议自身的 accept/decline 之上再要求一个 `confirm` 布尔值，导致客户端渲染出一个复选框，不勾选就点 Accept 会提交一个非法表单——客户端于是发送 `cancel`，用户被告知「你已拒绝」。移除它的论证出自他们，而且是对的：`action` 本身已经携带决定。为核实这一主张而阅读消费方代码，又发现了两个缺陷，包括三个从未起过作用的 CLI 标志。

## 社区贡献的实现

精神上被合并、而非以提交形式——这些 PR 基于 v1 构建，无法 rebase 到重写版上，但它们抵达了同样的设计。

- **[@Isla-Liu](https://github.com/Isla-Liu)** —— TOML profile 配置（#55）、脱敏审计日志（#56）、审批模式（#58）与按 profile 的审批设置（#59）：v2 的四个核心机制。还指出未显式选择时多 profile 配置会静默指向第一台主机（#54）——这个 bug v2 一直带着，直到以共同作者身份修复。WebUI（#60–#63）与配置热重载（#64）提案仍然开放。
- **[@ta5n](https://github.com/ta5n)** —— Docker 打包与多主机连接池（#28）。
- **[@mario-chamuty](https://github.com/mario-chamuty)** —— SFTP 传输工具（#38）。
- **[@henrik-koren](https://github.com/henrik-koren)** —— 面向多主机执行的 HTTP 传输（#41）。
- **[@mikusnuz](https://github.com/mikusnuz)** —— 加密密钥的 passphrase 支持（#35）。
- **[@burtherman](https://github.com/burtherman)** —— 以退出码而非 stderr 输出判定命令成败（#67）。
- **[@donejeh](https://github.com/donejeh)** —— 默认工作目录（#45）。
- **[@hamb3r](https://github.com/hamb3r)** 与 **[@GautamKumarOffical](https://github.com/GautamKumarOffical)** —— 让 v1 在 SDK 与 zod 的滚动更新下保持可用（#37、#51）。
- **[@glebtv](https://github.com/glebtv)** 与 **[@Ghits01](https://github.com/Ghits01)** —— 在 #23 与 #25 上提出更简单替代方案的评审意见。

