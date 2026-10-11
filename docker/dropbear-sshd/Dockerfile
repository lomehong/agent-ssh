# 另一种 sshd *实现*，不只是另一个 shell。
#
# 嵌入式设备、路由器与许多极简镜像上跑的就是 Dropbear。
# 它支持的算法集远窄于 OpenSSH，因此这是唯一能检验
# FROZEN_ALGORITHMS 还能否与非 OpenSSH 对端协商的测试目标——
# 一张只有 OpenSSH 满足的冻结清单，会把一整类主机锁在门外。
#
#
# openssh-sftp-server 单独安装，因为 dropbear 自身不带 SFTP
# 子系统。
FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc

RUN apk add --no-cache dropbear openssh-sftp-server

RUN adduser -D -s /bin/ash dropuser \
 && echo 'dropuser:droppass' | chpasswd

RUN mkdir -p /etc/dropbear \
 && dropbearkey -t ed25519 -f /etc/dropbear/dropbear_ed25519_host_key \
 && dropbearkey -t rsa -s 3072 -f /etc/dropbear/dropbear_rsa_host_key

EXPOSE 2222
# -F 前台，-E 记到 stderr，-p 端口。密码认证保持开启（-s 会关掉它），root 登录关闭（-w）。
# would disable it), root login disabled (-w).
CMD ["dropbear", "-F", "-E", "-w", "-p", "2222"]
