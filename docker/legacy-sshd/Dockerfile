# 只讲旧算法的 sshd：网络设备兼容轴。
#
# 本夹具不提供任何冻结（仅现代）算法白名单能接受的东⻄，
# 因此默认客户端配置必然协商失败，而 `profile.algorithms` 覆盖
# 必须能连上。它建模的是出厂即 ssh-rsa / CBC / DH-group1 时代
# 默认的旧网络设备（华为/华三/思科/锐捷线）——没有它，覆盖路径
# 只能测「不崩」，永远测不了「真的协商成功」。
#
#
# Alpine 3.20 带 OpenSSH 9.x，显式列出这些旧名时仍会*启用*它们
# （它们只是不在默认集合里）。若未来基底镜像彻底移除某个，
# 集成测试会以协商错误失败，从这条注释查起。
# negotiation error and this comment is where to start.
FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc

RUN apk add --no-cache openssh-server && ssh-keygen -A

RUN adduser -D -s /bin/ash legacyuser \
 && echo 'legacyuser:legacypass' | chpasswd

RUN sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config \
 && sed -i 's/^#\?Port .*/Port 2222/' /etc/ssh/sshd_config \
 && printf 'KexAlgorithms diffie-hellman-group1-sha1\nCiphers aes128-cbc,3des-cbc\nHostKeyAlgorithms ssh-rsa\nMACs hmac-sha1\n' >> /etc/ssh/sshd_config

EXPOSE 2222
CMD ["/usr/sbin/sshd", "-D", "-e"]
