# A forwarding-enabled SSH fixture, built from a pinned base so the config is
# deterministic at IMAGE BUILD time.
#
# Why this exists: the stock linuxserver openssh-server image ships
# AllowTcpForwarding no, and its /custom-cont-init.d hooks run BEFORE the sshd
# service generates /config/sshd/sshd_config — measured on this repo's compose
# (2026-10-11): the hook's `[ -f ]` guard fails silently and every forwarded
# channel is refused, which is exactly the failure mode the ProxyJump tests
# existed to catch. Patching at init time cannot win that race; owning the
# image build does.
#
# Two services build this image (ssh-bastion for ProxyJump, ssh-forward for the
# forwarding tools); both users are baked in so the services differ only by
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
