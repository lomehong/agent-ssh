# 设备接入指引（agent-ssh）

> 面向：把 agent-ssh 接入真实网络设备（华为 / 华三 / 思科 / 锐捷）的运维与安全人员。
> 前置阅读：README「Raw PTY sessions」「Device archives」两节。本文只讲接入动作与安全红线。

## 1. 接入前检查单（安全红线）

- [ ] **专用最小权限账号**：为 agent 单独建账号（如 `agent-op`），只授予只读级 CLI 权限（display/show 类）；**绝不用 root/admin/超级管理员**。
- [ ] **设备侧 AAA 记账兜底**：在设备/网管侧开启 TACACS+/RADIUS 命令记账——本工具的审计日志记录了 agent 侧的每次输入输出，但设备侧记账是独立于本系统的第二道留痕，两者都开。
- [ ] **审批面确认**：接入生产设备前，确认 Host 配置 `approvalSurfaces`（默认 `["desktop", "queue"]`，分离架构 v2 语义）与 `approvalPolicy`（生产建议 `ask-all`）符合贵方变更管理要求；raw PTY 会话的开启永远要过人工审批。
- [ ] **算法协商**：老设备若握手失败，在 profile 上按需放开 `algorithms`（见 README 配置节）——放开即降低传输安全下限，范围只限该设备。
- [ ] 不配置 root/超级管理员；`readOnly = true` 的监控类 profile 只允许只读命令。

## 2. Profile 模板（按厂商替换 deviceType 与关分页命令说明）

```toml
[[profiles]]
name = "huawei-core-01"          # 建议命名含厂商与编号
host = "10.0.0.9"
port = 22
user = "agent-op"                # 专用最小权限账号
auth = "password"                # 或 key / keyboardInteractive=true（老设备常见）
password 由 SSH_MCP_HUAWEI_CORE_01_PASSWORD 环境变量提供
deviceType = "huawei"            # huawei | h3c | cisco | ruijie | generic
group = "prod"                   # 策略层级：prod 最严
approvalPolicy = "ask-all"       # 生产建议逐条审批
# algorithms = { kex = { append = "diffie-hellman-group1-sha1" } }   # 仅老设备握手失败时按需放开
```

`deviceType` 生效的行为：PTY 会话打开后自动发送该厂商的关分页命令（huawei=`screen-length 0 temporary`，h3c=`screen-length disable`，cisco/ruijie=`terminal length 0`），`pty-read` 返回 `promptDetected` 字段提示设备是否就绪。

## 3. 标准操作序列（raw PTY）

```
pty-open(name="hw1")                      # 过审批门；批准后进入设备 CLI
pty-read(name="hw1", cursor=0)            # 读 banner + 关分页回显 + 提示符；返回新 cursor
pty-write(name="hw1", input="display version\n")   # 注意自带换行
pty-read(name="hw1", cursor=<上次返回>)    # 读回显；promptDetected=true 表示可发下一条
pty-close(name="hw1")                     # 用完即关；空闲/寿命超时也会自动回收
```

## 4. 审计与留痕

- 每条命令/每次会话开启/每次写入：审计日志（`~/.local/share/agent-ssh/audit.log` 等，平台路径见 README），三层脱敏，可选防篡改链。
- raw PTY 会话全程转录：`pty-transcripts/<会话>.log`（与审计日志同目录侧，脱敏，10MB 上限冻结）。
- 审批留痕：`approver` 字段区分 `mcp-client`（宿主弹窗）、`cli:<用户>`（审批队列）、`jit-grant`（限时重放）。

## 5. 已知边界（诚实清单）

- **GB2312/GBK 设备输出**：传输层按 UTF-8 解码，老设备中文输出可能乱码——缺口登记于 `src/devices/archives.ts`，出现后再补解码层。
- **Windows 流式 SFTP**：继承上游限制（`sftp-upload-file/download-file` 在 Windows 拒绝）。
- **命令分类不覆盖 PTY 内容**：PTY 是字节流，`pty-write` 的内容不做命令分类——这是主人裁决的安全取舍（五层缓解，见技术方案 §6 U2），依赖第 1 节的账号最小权限与设备侧记账兜底。
