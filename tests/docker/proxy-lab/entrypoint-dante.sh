#!/bin/sh
sockd -D -f /etc/sockd-open.conf
exec sockd -f /etc/sockd-auth.conf
