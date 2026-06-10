FROM alpine:3.20

RUN apk add --no-cache openssh-server openssh-sftp-server && \
    ssh-keygen -A && \
    adduser -D -s /bin/sh testuser && \
    echo "testuser:testpass123" | chpasswd && \
    mkdir -p ~/.ssh ~/data && \
    echo "Hello from SFTP server" > ~/data/readme.txt && \
    dd if=/dev/urandom of=~/data/bigfile.bin bs=1M count=5 2>/dev/null && \
    mkdir -p ~/data/subdir && \
    echo "nested file" > ~/data/subdir/nested.txt && \
    ln -s ~/data/readme.txt ~/data/link_to_readme && \
    chown -R testuser:testuser ~

# Allow password auth and sftp
RUN sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "Subsystem sftp /usr/lib/ssh/sftp-server" >> /etc/ssh/sshd_config && \
    echo "PermitRootLogin no" >> /etc/ssh/sshd_config

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
