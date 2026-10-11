# 为 ssh-mcp 做贡献

感谢你有兴趣为 ssh-mcp 做贡献！非常欢迎你的帮助。请遵循以下指引，让整个流程对每个人都顺畅。

## 如何贡献

1. **Fork 仓库**，并从 `main` 创建你的分支。
2. **把你的 fork 克隆**到本地。
3. **起一个描述性强的分支名**（例如 `feature/add-ssh-support` 或 `bugfix/fix-connection-issue`）。
4. **进行修改**，提交信息清晰、简洁。
5. **测试你的修改**，确保没有破坏任何东西（见[测试](#测试)）。
6. **推送到你的 fork**，并向 `main` 分支提交 Pull Request（PR）。

## 测试

新功能与缺陷修复必须附带覆盖它们的自动化测试。单元测试放在 `test/unit/` 下；凡改变服务器与 SSH 主机交互方式的修改，还需要在 `test/integration/` 下补集成测试。缺陷修复应包含一个「没有该修复就会失败」的测试。新增或改变行为却不带测试的 PR，在合并前会被要求补上。

用 `npm test` 运行测试套件。集成测试依赖 Docker 测试服务器；启动方法见 [README 的测试一节](README.md#测试)。

## 代码风格
- 遵循现有的代码风格与约定。
- 编写清晰、有描述性的提交信息。
- 在有助于澄清的地方添加注释。

## Issue 与缺陷
- 发现缺陷请提交 issue，并附上详细的复现步骤。
- 想处理某个已有 issue，请在其中留言告知他人。

## 功能请求
- 提 PR 之前，先开 issue 讨论新功能。
- 描述清楚你提议的功能及其使用场景。

## Pull Request
- 确保你的 PR 与最新的 `main` 分支保持同步。
- 为新增或变更的行为附带测试（见[测试](#测试)）。
- 在 PR 描述中引用相关 issue（例如 `Closes #12`）。
- 及时回应反馈和修改要求。
- **添加 changeset：** 推送前运行 `npm run changeset`，选择版本类型（patch/minor/major）并写一段简短的 changelog 条目，确保你的修改出现在发布说明中。

### Changeset 示例

```bash
npm run changeset
# 选择 ssh-mcp
# 新功能选 minor，修复选 patch
# 填写示例："Add ProxyJump support for bastion connections"
```

这会在 `.changeset/` 下生成一个文件——请随你的 PR 一起提交。PR 合并后，changesets 机器人会开一个 "Version Packages" PR，自动提升版本号、更新 CHANGELOG.md 并发布到 npm。发布到 npm 的同时，新版本也会同步上架[官方 MCP registry](https://registry.modelcontextprotocol.io)。

### server.json

`server.json` 是 MCP registry 的登记条目。其中两个版本字段——条目自身的 `version` 与它指向的 npm 版本——由 `npm run version` 从 `package.json` 写入，因此在 "Version Packages" PR 中已自动提升，不要手工编辑。文件中其余内容均为手工维护；如果你修改 `title` 或 `description`，注意 registry schema 对这两个字段都限制 100 字符，`test/unit/sync-server-json.test.ts` 对此有断言。

## 评审标准

`.review-pro/` 目录存放本项目变更评审所依据的标准——`node/` 覆盖通用 Node.js 服务器关注点（安全、正确性、API 契约、测试、性能），`ssh-mcp/` 覆盖本代码库特有的信号：进度与取消、OTEL、HTTP 限流、ProxyJump、CA 证书以及 MCP resources。

它们都是纯 markdown。开 PR 前通读与你改动相关的文件，就是一份现成的检查清单，且无需安装任何东西。凡触及策略引擎（policy engine）、审计链（audit chain）或主机密钥（host-key）处理的改动，尤其值得对照 `.review-pro/ssh-mcp/security.md` 检查。

这些文件同时也是 [review-pro](https://github.com/tufantunc/review-pro)（`npx review-pro`）的评审规则来源，该工具会按它们执行自动化评审。该工具由上游作者维护在另一个独立仓库；用与不用完全可选，CI 不会运行它，不用它也不会阻塞任何 PR。

## 行为准则
- 在所有互动中保持尊重与包容。
- 如有需要，参见 [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)。

感谢你帮助 ssh-mcp 变得更好！

