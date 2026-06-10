"""Docker-lab examples for protocol-backed scripting APIs.

Start the lab from ``tests/docker`` and run with
``AXROSS_LIVE_SCRIPTING_EXAMPLE_TESTS=1``. Each service is probed
before use; unavailable services are reported as skipped.
"""

from __future__ import annotations

import socket
from typing import Any

COVERS = (
    "open_url",
    "ssh_hostkey",
    "http_probe",
    "time_skew",
    "tcp_banner",
    "ping",
    "port_open",
    "port_scan",
    "find_tftp_files",
    "imap_search",
    "imap_set_flags",
    "ldap_search",
    "snmp_get",
    "snmp_walk",
    "SnmpVar",
)

SSH = ("10.99.0.10", 22)
FTP = ("10.99.0.30", 21)
WEBDAV = ("10.99.0.32", 80)
IMAP = ("10.99.0.36", 143)
TFTP = ("10.99.0.41", 69)
LDAP = ("10.99.0.45", 389)
SNMP = ("10.99.0.44", 1161)


def _tcp_open(host: str, port: int, timeout: float = 0.7) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _close(backend: Any) -> None:
    close = getattr(backend, "close", None) or getattr(backend, "disconnect", None)
    if close:
        close()


def _skip(results: dict, name: str, reason: str) -> None:
    results[name] = {"skipped": reason}


def run() -> dict:
    """Run live examples against reachable Docker-lab services."""
    import axross

    results: dict[str, dict] = {}

    if _tcp_open(*SSH):
        key = axross.ssh_hostkey(SSH[0], SSH[1], timeout=5.0)
        banner = axross.tcp_banner(SSH[0], SSH[1], timeout=2.0, max_bytes=80)
        pings = axross.ping(SSH[0], port=SSH[1], timeout=2.0, count=2)
        ports = axross.port_scan(SSH[0], [22, 2222], timeout=0.5)
        results["ssh_diagnostics"] = {
            "key_type": key.key_type,
            "banner": banner.decode("ascii", errors="replace").strip(),
            "reachable": [p.reachable for p in pings],
            "open_ports": ports,
        }
    else:
        _skip(results, "ssh_diagnostics", "ssh-alpha not reachable")

    if _tcp_open(*FTP):
        ftp = axross.open_url("ftp://ftpuser:ftp123@10.99.0.30/", ftp_passive=True)
        try:
            axross.write_text(ftp, "/scripting-example.txt", "ftp example", overwrite=True)
            body = axross.read_text(ftp, "/scripting-example.txt")
            axross.remove(ftp, "/scripting-example.txt", confirm=True)
            results["ftp"] = {"round_trip": body}
        finally:
            _close(ftp)
    else:
        _skip(results, "ftp", "ftp-server not reachable")

    if _tcp_open(*WEBDAV):
        probe = axross.http_probe("http://10.99.0.32/", timeout=5.0)
        skew = axross.time_skew("10.99.0.32", source="http", port=80, timeout=5.0)
        dav = axross.open_url("http://davuser:dav123@10.99.0.32/")
        try:
            axross.write_text(dav, "/scripting-example.txt", "webdav example", overwrite=True)
            body = axross.read_text(dav, "/scripting-example.txt")
            axross.remove(dav, "/scripting-example.txt", confirm=True)
            results["webdav"] = {
                "status": probe.status,
                "skew_source": skew.source,
                "round_trip": body,
            }
        finally:
            _close(dav)
    else:
        _skip(results, "webdav", "webdav-server not reachable")

    if _tcp_open(*IMAP):
        imap = axross.open_url("imap://imapuser:imap123@10.99.0.36/", imap_ssl=False)
        try:
            uids = axross.imap_search(imap, "ALL", mailbox="INBOX")
            if uids:
                axross.imap_set_flags(imap, uids[0], ["\\Seen"], mailbox="INBOX", mode="add")
                axross.imap_set_flags(imap, uids[0], ["\\Seen"], mailbox="INBOX", mode="remove")
            results["imap"] = {"uids": uids}
        finally:
            _close(imap)
    else:
        _skip(results, "imap", "imap-server not reachable")

    # TFTP is UDP; instantiate and let the read timeout decide.
    try:
        tftp = axross.open_url("tftp://10.99.0.41/")
        hits = axross.find_tftp_files(tftp, wordlist=["readme.txt", "configs/dhcpd.conf"])
        results["tftp"] = {"hits": hits}
        _close(tftp)
    except Exception as exc:  # noqa: BLE001 - lab may be down or optional dep absent
        _skip(results, "tftp", str(exc))

    if _tcp_open(*LDAP):
        try:
            ldap = axross.open_url(
                "ldap://10.99.0.45/",
                username="cn=admin,dc=axross,dc=test",
                password="ldapadmin123",
            )
            try:
                rows = axross.ldap_search(
                    ldap,
                    "ou=people,dc=axross,dc=test",
                    "(objectClass=inetOrgPerson)",
                    attributes=["cn", "mail", "uid"],
                )
                results["ldap"] = {"rows": len(rows)}
            finally:
                _close(ldap)
        except Exception as exc:  # noqa: BLE001 - optional ldap3 may be absent
            _skip(results, "ldap", str(exc))
    else:
        _skip(results, "ldap", "ldap-server not reachable")

    try:
        sys_name = axross.snmp_get(
            SNMP[0],
            "1.3.6.1.2.1.1.5.0",
            community="public",
            port=SNMP[1],
            timeout=1.5,
            retries=0,
        )
        walked = axross.snmp_walk(
            SNMP[0],
            "1.3.6.1.2.1.1",
            community="public",
            port=SNMP[1],
            timeout=1.5,
            retries=0,
            max_vars=5,
        )
        results["snmp"] = {
            "sys_name": str(sys_name.value),
            "walked": len(walked),
        }
    except Exception as exc:  # noqa: BLE001 - UDP service/optional dep may be absent
        _skip(results, "snmp", str(exc))

    return results


if __name__ == "__main__":
    for service, result in run().items():
        print(f"{service}: {result}")
