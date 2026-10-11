# 一个开启转发的 SSH 夹具，基于固定版本的基底构建，
# 让配置在镜像构建时就是确定的。
#
# 存在原因：原版 linuxserver openssh-server 镜像自带
# AllowTcpForwarding no，且其 /custom-cont-init.d 钩子运行于
# sshd 服务生成 /config/sshd/sshd_config 之前——本仓库 compose
# 实测（2026-10-11）：钩子的 `[ -f ]` 守卫静默失败，所有转发
# 通道被拒，恰是 ProxyJump 测试要抓的故障形态。
# 在 init 期打补丁赢不了这场竞速；自己 owning 镜像构建才行。
#
#
# 两个服务构建此镜像（ssh-bastion 用于 ProxyJump，ssh-forward
# 用于转发工具）；两个用户都烘焙进镜像，服务间只差端口映射。
# port mapping.
FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc

RUN apk add --no-cache openssh-server bash && ssh-keygen -A

RUN adduser -D -s /bin/bash bastion \
 && echo 'bastion:bastionpass' | chpasswd \
 && adduser -D -s /bin/bash forwarder \
 && echo 'forwarder:forwardpass' | chpasswd

RUN sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config \
 && sed -i 's/^#\?Port .*/Port 2222/' /etc/ssh/sshd_config \
 && sed -i '/^AllowTcpForwarding/d' /etc/ssh/sshd_config \
 && printf 'AllowTcpForwarding yes\nMaxStartups 100:30:200\nMaxSessions 50\n' >> /etc/ssh/sshd_config

EXPOSE 2222
CMD ["/usr/sbin/sshd", "-D", "-e"]
