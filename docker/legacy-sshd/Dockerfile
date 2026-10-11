# A legacy-algorithms-only sshd: the network-device compatibility axis.
#
# This fixture offers NOTHING the frozen (modern-only) algorithm allowlist can
# accept, so a default client config must fail to negotiate and a
# `profile.algorithms` override must connect. It models the older network gear
# (Huawei/H3C/Cisco/Ruijie lines) that ships ssh-rsa / CBC / DH-group1 era
# defaults — without it, the override path could only be tested for "does not
# crash", never for "actually negotiates".
#
# Alpine 3.20 carries OpenSSH 9.x, which still *enables* these legacy names when
# they are listed explicitly (they are merely out of the default sets). If a
# future base image drops one entirely, the integration test will fail with a
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
