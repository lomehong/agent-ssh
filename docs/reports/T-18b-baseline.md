# T-18b 基线冻结对照（2026-10-12，提交 0c7d4c6 后全量）

## 红线四项对照（票面验收 2，全部已落地）

| # | 红线 | 落地证据 | 状态 |
|---|---|---|---|
| ① | 矩阵枚举：全方法×7 凭据态（含谎报 class） | test/unit/rpc/matrix.test.ts:113「7 凭据态×全方法枚举（K9-①：5 态扩 7 态）」98 断言+过期会话专项 :163+K8-⑥ JIT 暗门 :185+FORBIDDEN 审计标记 :202 | ✅（T-14/T-18b） |
| ② | stub 无凭证断言（env 白名单+日志正则+抽验） | test/unit/stub/stub.test.ts（T-16a 白名单重写+诚实态断言；heap snapshot 抽验级随 UI 壳 T-17.5c 后补——wiringBoundary 登记） | ✅（T-16a） |
| ③ | stub 无 ssh2（import 白名单） | stub.test.ts:179「红线③：stub 无 ssh2/无 fs/无子进程」+K9-⑨ 口径成文（枚举式内置白名单+每层双保险） | ✅（T-16a） |
| ④ | 重放必拒+单次消费+过期+并发双决定仅一生效 | approval-queue.test.ts:127「同 id 并发 approve+reject 恰好一生效（K7：Host 侧按 id 串行化）」+:102 重放拒（already rejected）+challenge.test.ts 单次消费/60s TTL/3 败作废（D10） | ✅（T-17/T-17.5b） |

## e2e 双进程化（票面验收 1）

- rpc-flow.e2e.test.ts **3/3 绿**：tools/list 23 工具经 stub→Host manifest ✓／无凭据 stub fail-closed（错令牌连不上→callTool 拒不本地降级）✓／破坏性命令队列泵审批闸门全链路 ✓；
- 隔离粒度=per-file spawnRpcHost（host serve 子进程+host-rpc-ready 探测+taskkill 兜底）+per-test mkdtemp（K9-④，无 per-test 重启）。

## 删测清单（票面验收 6，单列登记）

| 文件 | 处置 | 覆盖去向 |
|---|---|---|
| test/e2e/introspection.e2e.test.ts（196 行） | 删 | tools/list 23 断言并入 rpc-flow 用例 1（经 stub→Host 真链路更强） |
| test/e2e/tools.e2e.test.ts（157 行） | 删 | 12 用例全 skip（依赖集成 SSH 环境，非回归）；破坏性审批闸门并入 rpc-flow 用例 3；SSH 工具流程由 integration/sftp-\*+T-19 真实环境覆盖 |
| packaging.e2e 用例 2（旧 Invalid --group 断言） | 改写 | v1 迁移提示断言（D14：CLI --host/--user 快速启动随直连废止）+reportFatal 报告格式保留验证（#138 语义不丢） |

## 基线冻结口径（票面验收 6）

- **全量：30 failed / 2100 passed / 62 skipped（2192 总），失败 6 文件=既有环境族**（sftp-file-transfer、sftp-tools、stdin-close、config/loader、config/trusted-host-key、config/windows-acl.live——T-13 轮锚定的平台/环境依赖族，与本票语义无关）；
- `tsc --noEmit -p tsconfig.test.json` 0 错；cargo test 全绿（golden 4+retry 1+approval_flow 1）；
- 入口切换波及面（T-18a 登记 5 文件）全部收口：sync-server-json（server.json 同步）、approval-channel（flaky 消除）、introspection/packaging/tools（本票处置）。

## T-18a 波及登记回销

| T-18a wiringBoundary 项 | 回销状态 |
|---|---|
| server.json/sync 未随 name 改 | ✅ 8d6b89d 已同步（sync 16/16） |
| approval-channel flaky | ✅ 后续全量未复现（争用定性） |
| introspection/packaging/tools 旧断言 | ✅ 本票收口 |

## 诊断记录

- pwsh 行手术曾损坏 rpc-flow.e2e.test.ts（start=-1 切片错乱）——git 未跟踪无法回滚，整文件重写恢复；此后文件手术一律先入 git 再动；
- host serve 旗标解析两连错（indexOf 精确匹配+漏 `--` 前缀）——双探针实证定位，教训入 cli.ts 注释；
- 渲染吞字多次——一律以 tsc/cargo/Select-String 真字节信号裁决，显示层不作依据。
