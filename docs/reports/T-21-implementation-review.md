# 桌面控制台 v2 实现——系统性审查报告

- 审查人：digital-architect（双轴子代理×2 + 分身亲核 D15 安全模型）
- 审查对象：git 0bd782c..HEAD（T-21a~g 七票 + D15 单令牌模型 13ab1e2 + T-22 主机管理 a29ec7c）
- 日期：2026-10-17
- 基线：TS 全量（本轮 4 failed/100 passed——3 既有环境族 + registry.test 新面孔已另登记）；cargo test 9/9；tsc 0

## 总评

**测试与骨架高保真**：K8-③ 红线干净（CSP 锁/零 innerHTML/命令全文 createTextNode）、矩阵 SPEC 独立抄录+7 态×全方法+谎报按真实凭据、D15 裁决钉进 matrix.test（:196-205 载主人裁决理由）、前轮评审 3 硬违规全部落实（agents.* 归 Host TS 侧/设计改引实存提交 c2ad495/README 通告同步）、六宿主适配器与设计表逐行合。**缺口集中在宿主接入 remove 路径、D15 文档漂移、审计可追责性三处。**

## A 级缺口（须修——安全/纪律实质）

| # | 缺口 | 证据 | 修法 |
|---|---|---|---|
| A1 | **宿主接入 remove 路径违反七纪律**：无写前备份、无回读校验、失败无回滚（纪律②⑤只落在 configure） | src/agents/index.ts:183-188（codex 正则删块后 writeFileSync 直写）、:190-195（JSON 删键直写） | remove 复用 configure 同套备份/回读/回滚 |
| A2 | **codex TOML 写/删均为正则文本插桩**（违「绝无文本插桩」①），回读校验 hasEntry 仅正则测头部（:96-99）非解析回读 | src/agents/index.ts:133-145、:184-188 | 引入 TOML 解析器结构化改写（设计 §2.6① 原文即要求） |
| A3 | **D15 裁决未回写设计文档（规格漂移）**：全仓 grep D15 零命中（13ab1e2 无 .md 改动，裁决仅存 commit message+matrix.test 注释）；设计正文 :23/:129 仍写「agent 一律 FORBIDDEN」与现行单令牌模型**直接冲突** | matrix.test.ts:196-205（钉新模型+载主人理由）vs 设计正文 | 设计文档补 D15 节（主人裁决原话：约束=SSH 凭证隔离；知情接受 Agent 自批残余风险；补偿=审计全程+可追责）+正文 :23/:129 同步改写 |
| A4 | **decide 审计 by 自报可伪造（D15 补偿弱化）**：host/main.ts decide handler `by = input.by 非空即用`——agent 令牌直连可自报 `by="desktop:human"` 伪造追责链。D15 的补偿承诺是「审计全程可追责」，自报 by 使其弱化 | src/host/main.ts decide handler | 面身份由 Host 按凭据强制前缀（agent 令牌→强制 `agent:` 前缀，拒自报；与 T-17.6 IM 面 `im:` 强制同型） |

## B 级缺口（应修——契约/诚实性）

| # | 缺口 | 证据 |
|---|---|---|
| B1 | agents.configure 无 UI 二次确认（评审建议①文档采纳 UI 未落；ui.js:511 直调，全文件唯一 confirm 在 :567） | ui.js:511 |
| B2 | **PTY 强关未实现且 T-21d.yaml:12 自报未披露**（诚实性缺口：设计 §2.4 走 tool.call pty-close） | main.rs 无 tool.call 桥、ui.js:401 仅显示计数 |
| B3 | audit.query 时间范围过滤两侧均缺（cursor 书面弃二元组为登记取舍 ✓） | query.ts:7-10 |
| B4 | 「密码留空=不变」断裂：keychain 主机编辑留空必抛（host/main.ts:360 映射 password→profiles-edit.ts:70-72 空即抛）；UI 承诺落空 | ui.js:609、index.html:90 |
| B5 | D15 残留死代码：main.rs:274-285 change_password 仍注册（提交声称已删）、HostState.pin 死字段、auth.ts:146-156 rotatePassword/会话表无入口 | 各处 |

## C 级（登记即可）

- 连接循环无条件每 3s 重连+重订阅（无活性检测；subscribe_approvals 返回值忽略 main.rs:112）——推送丢失同型隐患；
- handleNotUnlocked 静默 return（与注释「显示提示」漂移）+renderUnlockHint 全无调用（死代码）；
- AGENT_SSH_TOKEN 明文落宿主配置 env（MCP env 形态架构使然，建议设计文档补豁免登记）。

## 红线核验（干净项）

- K8-③：CSP 锁（index.html:6-7）、零 innerHTML/eval、命令全文 createTextNode（ui.js:101/271/349）✅
- 矩阵红线：SPEC 独立抄录+7 态×全方法+谎报按真实凭据（M3）✅；D15 钉模型测试载主人裁决理由 ✅
- 前轮评审 3 硬违规落实 ✅（agents.* 归 Host TS/设计改引 c2ad495/README 同步）

## 建议处置顺序

1. A1+A2 一起修（宿主接入纪律补全，T-21g 范围回补）；
2. A3 文档回写（设计文档 D15 节+:23/:129 同步——裁决已在 matrix.test/commit message 有据）；
3. A4 by 强制前缀（小改+测试）；
4. B1/B2 一次小票（二次确认+PTY 强关或显式降范围登记）；
5. B3/B4/B5、C 级随下一功能票顺带。
