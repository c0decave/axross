FROM docker.io/library/debian:bullseye-slim

# rsh-server (rshd) listens on TCP 514. We add a single unprivileged
# user 'axuser' with ~/.rhosts authorising access from the
# test runner.
#
# bullseye-slim is pinned because rsh-redone-server was dropped from
# bookworm onwards. Acceptable for a *test* container — the legacy
# r-services era predates that distro by a decade anyway.
#
# We install rsh-redone-server FIRST (which pulls openbsd-inetd as
# a dep and lets the postinst's update-inetd succeed), then strip
# openbsd-inetd and add xinetd plus a hand-written xinetd snippet.
# openbsd-inetd's bullseye build silently fails to bind in a Docker
# container; xinetd works.
#
# bullseye reached end of life and its pool left deb.debian.org: the
# image's sources.list still names deb.debian.org, whose indexes then
# point at .deb files that answer 404 ("Failed to fetch ...
# perl-modules-5.32_5.32.1-4+deb11u5_all.deb 404 Not Found"). The
# release now lives on archive.debian.org, whose Release files carry
# an expired Valid-Until, hence the check is switched off for apt.

RUN printf '%s\n' \
        'deb http://archive.debian.org/debian bullseye main' \
        'deb http://archive.debian.org/debian-security bullseye-security main' \
        > /etc/apt/sources.list \
 && rm -f /etc/apt/sources.list.d/* \
 && printf 'Acquire::Check-Valid-Until "false";\n' > /etc/apt/apt.conf.d/99archive

RUN apt-get update && DEBIAN_FRONTEND=noninteractive \
    apt-get install --no-install-recommends -y \
        rsh-redone-server net-tools iputils-ping coreutils \
 && DEBIAN_FRONTEND=noninteractive \
    apt-get install --no-install-recommends -y xinetd \
 && DEBIAN_FRONTEND=noninteractive \
    apt-get purge -y openbsd-inetd update-inetd \
 && rm -rf /var/lib/apt/lists/*

# Write the xinetd snippet ourselves so we don't depend on
# rsh-redone-server's update-inetd hook.
RUN cat > /etc/xinetd.d/rsh <<'EOF'
service shell
{
    type            = UNLISTED
    port            = 514
    socket_type     = stream
    protocol        = tcp
    wait            = no
    user            = root
    server          = /usr/sbin/in.rshd
    log_on_failure  += USERID
    disable         = no
}
EOF

RUN cat > /etc/xinetd.d/rlogin <<'EOF'
service login
{
    type            = UNLISTED
    port            = 513
    socket_type     = stream
    protocol        = tcp
    wait            = no
    user            = root
    server          = /usr/sbin/in.rlogind
    log_on_failure  += USERID
    disable         = no
}
EOF

# Create the test user with a wide-open .rhosts. The IP shows up as
# 10.99.0.x inside the lab; '+ +' is the wildcard accept-anywhere
# entry — fine inside the test sandbox, NEVER on a real network.
# Absolute paths: this RUN executes as root, so `~` would be /root and
# axuser would get neither the .rhosts nor the seeded ~/data.
RUN useradd -m -s /bin/bash axuser && \
    echo "+ +" > /home/axuser/.rhosts && \
    chmod 600 /home/axuser/.rhosts && \
    chown axuser:axuser /home/axuser/.rhosts && \
    install -d -m 0755 -o axuser -g axuser /home/axuser/data && \
    echo "hello from rshd" > /home/axuser/data/seed.txt && \
    chown axuser:axuser /home/axuser/data/seed.txt

EXPOSE 513 514
CMD ["/usr/sbin/xinetd", "-dontfork", "-stayalive"]
