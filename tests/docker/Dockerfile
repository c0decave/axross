FROM alpine:3.20

RUN apk add --no-cache openssh-server openssh-sftp-server && \
    ssh-keygen -A && \
    adduser -D -s /bin/sh testuser && \
    echo "testuser:testpass123" | chpasswd && \
    mkdir -p /home/testuser/.ssh /home/testuser/data && \
    echo "Hello from SFTP server" > /home/testuser/data/readme.txt && \
    dd if=/dev/urandom of=/home/testuser/data/bigfile.bin bs=1M count=5 2>/dev/null && \
    mkdir -p /home/testuser/data/subdir && \
    echo "nested file" > /home/testuser/data/subdir/nested.txt && \
    ln -s /home/testuser/data/readme.txt /home/testuser/data/link_to_readme && \
    chown -R testuser:testuser /home/testuser

# Allow password auth and sftp
RUN sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "Subsystem sftp /usr/lib/ssh/sftp-server" >> /etc/ssh/sshd_config && \
    echo "PermitRootLogin no" >> /etc/ssh/sshd_config

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
