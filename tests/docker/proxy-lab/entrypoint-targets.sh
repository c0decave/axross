#!/bin/sh
/usr/sbin/sshd -e
httpd -p 80 -h /srv/www
redis-server --protected-mode no --daemonize yes >/dev/null
# anonymous FTP (read-only), passive data connections on random ports
exec tcpsvd -vE 0.0.0.0 21 ftpd -w -a labuser /srv/ftp
