#!/bin/sh
# ncsa helper in this build accepts apr1 / md5-crypt, not {SHA}.
hash=$(openssl passwd -apr1 "$LAB_PROXY_PASSWORD")
echo "$LAB_PROXY_USER:$hash" > /etc/squid/htpasswd
exec squid -N -d 1 -f /etc/squid/squid.conf
