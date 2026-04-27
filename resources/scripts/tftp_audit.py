"""tftp_audit.py — wordlist scan across a list of TFTP servers.

For every host in HOSTS, opens a TftpSession with the bundled common-
filename wordlist and reports any hits. Output is grouped by host so
a single review pass shows which devices are leaking what.

Usage::

    hits = audit(["10.0.0.1", "10.0.0.2"])
    for host, found in hits.items():
        for filename, size in found:
            print(f"{host:<15s}  {filename}  ({size} bytes)")
"""
from __future__ import annotations


def audit(hosts: list[str], wordlist: list[str] | None = None,
          port: int = 69) -> dict[str, list[tuple[str, int]]]:
    out: dict[str, list[tuple[str, int]]] = {}
    for host in hosts:
        try:
            sess = axross.open_url(f"tftp://{host}:{port}/")
        except (OSError, ImportError):
            out[host] = []
            continue
        try:
            hits = axross.find_tftp_files(sess, wordlist=wordlist)
            out[host] = [(item.name, item.size) for item in hits]
        finally:
            sess.close()
    return out
