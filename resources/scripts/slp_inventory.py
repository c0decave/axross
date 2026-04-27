"""slp_inventory.py — discover SLP services across a host list.

Hits each host on UDP/427 with an SLPv2 SrvTypeRqst, then for every
service type returned issues a SrvRqst to enumerate the URLs.
Classic SLP inventory pattern; useful for ESXi / WBEM / IPP fleet
audits and for the post-CVE-2023-29552 hygiene sweep.

We deliberately do NOT broadcast / multicast — :func:`axross.slp_discover`
refuses those targets. Pass each host explicitly.

Usage::

    inv = inventory(["10.0.0.10", "10.0.0.11"])
    for host, types in inv.items():
        for stype, urls in types.items():
            for url, ttl in urls:
                print(f"{host}\\t{stype}\\t{url}\\t{ttl}")
"""
from __future__ import annotations


def inventory(hosts: list[str], scope: str = "DEFAULT",
              timeout: float = 3.0) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for host in hosts:
        try:
            out[host] = axross.slp_discover(host, scope=scope)
        except (OSError, ValueError) as exc:
            out[host] = {"_error": str(exc)}
    return out
