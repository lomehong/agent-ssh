#!/bin/sh
# 集成测试服务器用的 linuxserver.io custom-cont-init 钩子。
#
# sshd 默认 `MaxStartups 10:30:100`：并发未认证握手超过 10 个就开始
# 随机丢连接。集成套件并行跑测试文件、每个都开真实 SSH 连接，
# 套件长大后就越过了这条线——产生失败，更糟的是*跳过*：
# 探测被丢会让测试文件跳过自己，而降级的运行
# 看起来仍是绿的。
#
#
# MaxSessions 因同样理由调高：多个测试在同一条连接上
# 并发持有通道（会话、SFTP）。
#
# 仅测试夹具——这些不是生产适用值。
CONFIG=/config/sshd/sshd_config

if [ -f "$CONFIG" ]; then
  sed -i 's/^[#[:space:]]*MaxStartups.*/MaxStartups 100:30:200/' "$CONFIG"
  grep -q '^MaxStartups' "$CONFIG" || echo 'MaxStartups 100:30:200' >> "$CONFIG"

  sed -i 's/^[#[:space:]]*MaxSessions.*/MaxSessions 50/' "$CONFIG"
  grep -q '^MaxSessions' "$CONFIG" || echo 'MaxSessions 50' >> "$CONFIG"

  echo "[test-server-init] MaxStartups/MaxSessions raised for the integration suite"
fi
