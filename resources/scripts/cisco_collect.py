"""cisco_collect.py — collect IOS show-output across a host list.

Connects to every host with the supplied credentials, pulls each
listed ``show`` command via the Cisco-Telnet backend, and writes the
output to ``<out_dir>/<host>/<show-cmd>.txt``.

Useful for inventory snapshots before a network change window.

Usage::

    bundle = collect(
        hosts=["10.0.0.1", "10.0.0.2"],
        username="netops", password="…", enable_password="…",
        commands=["running-config", "version", "ip-route"],
        out_dir="/tmp/cisco-snapshot",
    )
"""
from __future__ import annotations

import os

DEFAULT_COMMANDS = ["running-config", "version", "interfaces", "ip-route"]


def collect(hosts: list[str],
            username: str, password: str,
            enable_password: str = "",
            commands: list[str] = None,
            out_dir: str = "/tmp/cisco-snapshot") -> dict[str, list[str]]:
    commands = commands or DEFAULT_COMMANDS
    saved: dict[str, list[str]] = {}
    local = axross.localfs()
    for host in hosts:
        try:
            sess = axross.open_url(
                f"cisco-telnet://{host}:23/",
                username=username, password=password,
                enable_password=enable_password,
            )
        except OSError as exc:
            saved[host] = [f"(connect failed: {exc})"]
            continue
        host_dir = os.path.join(out_dir, host)
        os.makedirs(host_dir, exist_ok=True)
        files: list[str] = []
        try:
            for cmd in commands:
                try:
                    blob = axross.read_bytes(sess, f"/show/{cmd}.txt")
                except OSError as exc:
                    blob = f"(error: {exc})".encode("utf-8")
                target = os.path.join(host_dir, f"{cmd}.txt")
                axross.write_bytes(local, target, blob)
                files.append(target)
        finally:
            sess.close()
        saved[host] = files
    return saved
