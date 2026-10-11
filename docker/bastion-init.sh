#!/bin/sh
# linuxserver.io custom-cont-init 钩子。
#
# 基础 openssh-server 镜像自带 AllowTcpForwarding no，会让
# direct-tcpip 通道（ProxyJump / `profile.via` 所用）以
# "Channel open failure: open failed" 失败。这台主机存在的唯一意义，
# 是让集成套件对着真实 sshd 练堡垒机路径。
#
# 仅测试夹具——不要把它当生产堡垒机的样板。
CONFIG=/config/sshd/sshd_config

if [ -f "$CONFIG" ]; then
  sed -i 's/^[#[:space:]]*AllowTcpForwarding.*/AllowTcpForwarding yes/' "$CONFIG"
  grep -q '^AllowTcpForwarding yes' "$CONFIG" || echo 'AllowTcpForwarding yes' >> "$CONFIG"
  echo "[bastion-init] AllowTcpForwarding enabled for ProxyJump tests"
fi
