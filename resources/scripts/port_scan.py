"""port_scan.py — small-and-fast TCP port probe.

Iterates a (host, port) list and reports which ones answer within
TIMEOUT seconds. Pure stdlib via :func:`axross.port_open`. Default
list is the OWASP "Common Service Discovery" set so the script is
useful out-of-the-box for a quick lab check.

Usage::

    open_ports = scan(["10.99.0.32", "10.99.0.41"], COMMON_PORTS)
"""
from __future__ import annotations

import concurrent.futures

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 88, 110, 111, 123,
    135, 137, 138, 139, 143, 161, 389, 427,
    443, 445, 465, 514, 587, 631, 636, 873,
    993, 995, 1080, 1194, 1433, 1521, 2049,
    2375, 3000, 3306, 3389, 5432, 5900, 5985,
    6379, 8000, 8080, 8443, 9000, 9100, 11211,
    27017, 50000,
]


def scan(hosts: list[str], ports: list[int] = None,
         timeout: float = 1.0,
         workers: int = 64) -> dict[str, list[int]]:
    """Concurrent TCP-connect scan. ``hosts`` is a list of IP / DNS
    names; ``ports`` defaults to ``COMMON_PORTS``. Returns
    ``{host: [open_ports]}``."""
    ports = ports or COMMON_PORTS
    out: dict[str, list[int]] = {h: [] for h in hosts}

    def _probe(host_port):
        host, port = host_port
        return host, port, axross.port_open(host, port, timeout=timeout)

    pairs = [(h, p) for h in hosts for p in ports]
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        for host, port, is_open in ex.map(_probe, pairs):
            if is_open:
                out[host].append(port)
    for h in out:
        out[h].sort()
    return out
