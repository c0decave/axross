"""webdav_quota.py — print WebDAV quota across a list of endpoints.

For each ``http(s)://user:pw@host/dav`` URL, opens a session and
prints ``(total, used, free)`` from the server's RFC 4331
``DAV:quota-*`` properties. Servers that don't expose quota
properties just return ``(0, 0, 0)``.

Usage::

    quota_report(["http://alice:pw@nextcloud.example/remote.php/dav/files/alice"])
"""
from __future__ import annotations


def quota_report(urls: list[str]) -> dict[str, tuple[int, int, int]]:
    out: dict[str, tuple[int, int, int]] = {}
    for url in urls:
        try:
            sess = axross.open_url(url)
        except (OSError, ImportError):
            out[url] = (0, 0, 0)
            continue
        try:
            out[url] = sess.disk_usage("/")
        finally:
            sess.close()
    return out
