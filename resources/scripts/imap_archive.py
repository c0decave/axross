"""imap_archive.py — archive an IMAP folder to .eml files on disk.

Walks an IMAP folder via the IMAP backend (which already exposes
mailboxes as filesystem dirs and messages as ``.eml`` blobs) and
copies each message to a local directory with the same name.

Cap on the number of messages keeps the script polite for shared
mailboxes.

Usage::

    sess = axross.open("work-mail")
    archive(sess, "INBOX", "/tmp/work-inbox", limit=200)
"""
from __future__ import annotations


def archive(sess, mailbox: str, dst_dir: str, limit: int = 100) -> int:
    local = axross.localfs()
    items = sess.list_dir(f"/{mailbox}")
    items = items[-limit:]
    import os
    os.makedirs(dst_dir, exist_ok=True)
    n = 0
    for it in items:
        if it.is_dir:
            continue
        try:
            data = axross.read_bytes(sess, f"/{mailbox}/{it.name}")
        except OSError:
            continue
        axross.write_bytes(local, os.path.join(dst_dir, it.name), data)
        n += 1
    return n
