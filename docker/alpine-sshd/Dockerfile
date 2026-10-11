# 一个刻意区别于 linuxserver 测试服务器的目标。
#
# 那些都是 Debian 系用户态加 bash。这个是 Alpine + busybox
# `ash` 登录 shell——会话协议真正要扛住的就是它：`bind` 是这里
# 不存在的 bash 内建，`set -o history` 不支持，默认提示符也不同。
# 哨兵协议或 shell priming 若悄悄依赖 bash，就在这里现形。
# the shell priming quietly depend on bash, this is where it shows.
FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc

RUN apk add --no-cache openssh-server && ssh-keygen -A

RUN adduser -D -s /bin/ash alpineuser \
 && echo 'alpineuser:alpinepass' | chpasswd

RUN sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config \
 && sed -i 's/^#\?Port .*/Port 2222/' /etc/ssh/sshd_config \
 && printf '\nMaxStartups 100:30:200\nMaxSessions 50\n' >> /etc/ssh/sshd_config

# 想查看哪些会话由 agent 驱动的运维用 AcceptEnv 选择加入；
# 否则 sshd 无视客户端请求。这一行让该声明可从会话观察到，
# 也是 test/integration/shell-compat.test.ts 的集成用例
# 真正能证伪的东西。
RUN printf 'AcceptEnv AI_AGENT\n' >> /etc/ssh/sshd_config

EXPOSE 2222
CMD ["/usr/sbin/sshd", "-D", "-e"]
