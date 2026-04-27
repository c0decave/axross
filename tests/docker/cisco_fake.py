"""Tiny Cisco-IOS-flavoured Telnet daemon for axross integration tests.

Speaks just enough of the IOS user-experience to let
``core.telnet_cisco.CiscoTelnetSession`` round-trip through every code
path in the wire-protocol layer:

* login banner + ``Username:`` / ``Password:`` prompt sequence
* user-mode prompt ``Switch>``
* ``enable`` -> ``Password:`` -> privileged prompt ``Switch#``
* ``terminal length 0`` accepted (paging off)
* ``show <subcmd>`` returns canned output for a curated set of commands
  and a generic ``% Invalid input detected`` for unknown ones
* ``exit`` / ``logout`` / ``quit`` close the session

Designed to be deterministic and free of any real Cisco IP — every
fixture is hand-written here so we never have to pull in or distribute
licensed IOS images. One client at a time per port; fork a thread per
connection so multiple test workers can hit the same instance.
"""
from __future__ import annotations

import logging
import os
import socket
import socketserver
import sys

LOG = logging.getLogger("cisco_fake")

HOSTNAME = os.environ.get("CISCO_HOSTNAME", "Switch")
USERNAME = os.environ.get("CISCO_USERNAME", "admin")
PASSWORD = os.environ.get("CISCO_PASSWORD", "cisco123")
ENABLE_PASSWORD = os.environ.get("CISCO_ENABLE", "enablesecret")
PORT = int(os.environ.get("CISCO_PORT", "23"))
BIND = os.environ.get("CISCO_BIND", "0.0.0.0")

USER_PROMPT = f"{HOSTNAME}>"
PRIV_PROMPT = f"{HOSTNAME}#"

BANNER = (
    "\r\n"
    "User Access Verification\r\n"
    "\r\n"
)

# Canned ``show`` responses. Trim each block to a few realistic lines —
# the goal is parser exercise, not deep IOS fidelity.
SHOWS: dict[str, str] = {
    "version": (
        "Cisco IOS Software, Catalyst L3 Switch Software (CAT3K_CAA-UNIVERSALK9-M),\r\n"
        " Version 16.12.4, RELEASE SOFTWARE (fc1)\r\n"
        "Copyright (c) 1986-2020 by Cisco Systems, Inc.\r\n"
        "\r\n"
        f"{HOSTNAME} uptime is 4 weeks, 2 days, 17 hours, 3 minutes\r\n"
        "System image file is \"flash:/cat3k_caa-universalk9.16.12.04.SPA.bin\"\r\n"
        "cisco WS-C3650-24TS (MIPS) processor with 4194304K bytes of memory.\r\n"
    ),
    "running-config": (
        "Building configuration...\r\n"
        "\r\n"
        "Current configuration : 1024 bytes\r\n"
        "!\r\n"
        "version 16.12\r\n"
        "service timestamps debug datetime msec\r\n"
        "service timestamps log datetime msec\r\n"
        "no service password-encryption\r\n"
        "!\r\n"
        f"hostname {HOSTNAME}\r\n"
        "!\r\n"
        "ip routing\r\n"
        "!\r\n"
        "interface Vlan1\r\n"
        " ip address 192.0.2.1 255.255.255.0\r\n"
        "!\r\n"
        "line vty 0 4\r\n"
        " login\r\n"
        " transport input telnet\r\n"
        "!\r\n"
        "end\r\n"
    ),
    "startup-config": (
        "Using 1024 out of 524288 bytes\r\n"
        "!\r\n"
        f"hostname {HOSTNAME}\r\n"
        "end\r\n"
    ),
    "interfaces": (
        "Vlan1 is up, line protocol is up\r\n"
        "  Hardware is Ethernet SVI, address is 0011.2233.4455 (bia 0011.2233.4455)\r\n"
        "  Internet address is 192.0.2.1/24\r\n"
        "  MTU 1500 bytes, BW 1000000 Kbit/sec, DLY 10 usec,\r\n"
        "GigabitEthernet1/0/1 is up, line protocol is up (connected)\r\n"
        "  Hardware is Gigabit Ethernet, address is 0011.2233.4456 (bia 0011.2233.4456)\r\n"
        "  MTU 1500 bytes, BW 1000000 Kbit/sec, DLY 10 usec,\r\n"
    ),
    "ip route": (
        "Codes: L - local, C - connected, S - static, R - RIP, M - mobile, B - BGP\r\n"
        "       D - EIGRP, EX - EIGRP external, O - OSPF, IA - OSPF inter area\r\n"
        "\r\n"
        "Gateway of last resort is 192.0.2.254 to network 0.0.0.0\r\n"
        "\r\n"
        "S*    0.0.0.0/0 [1/0] via 192.0.2.254\r\n"
        "      192.0.2.0/24 is variably subnetted, 2 subnets, 2 masks\r\n"
        "C        192.0.2.0/24 is directly connected, Vlan1\r\n"
        "L        192.0.2.1/32 is directly connected, Vlan1\r\n"
    ),
    "ip interface brief": (
        "Interface              IP-Address      OK? Method Status                Protocol\r\n"
        "Vlan1                  192.0.2.1       YES NVRAM  up                    up\r\n"
        "GigabitEthernet1/0/1   unassigned      YES unset  up                    up\r\n"
        "GigabitEthernet1/0/2   unassigned      YES unset  down                  down\r\n"
    ),
    "vlan brief": (
        "VLAN Name                             Status    Ports\r\n"
        "---- -------------------------------- --------- -------------------------------\r\n"
        "1    default                          active    Gi1/0/1, Gi1/0/2\r\n"
        "10   users                            active\r\n"
        "20   servers                          active\r\n"
    ),
    "arp": (
        "Protocol  Address          Age (min)  Hardware Addr   Type   Interface\r\n"
        "Internet  192.0.2.1               -   0011.2233.4455  ARPA   Vlan1\r\n"
        "Internet  192.0.2.10             12   aabb.ccdd.ee01  ARPA   Vlan1\r\n"
    ),
    "mac address-table": (
        "          Mac Address Table\r\n"
        "-------------------------------------------\r\n"
        "Vlan    Mac Address       Type        Ports\r\n"
        "----    -----------       --------    -----\r\n"
        "   1    aabb.ccdd.ee01    DYNAMIC     Gi1/0/1\r\n"
        "   1    aabb.ccdd.ee02    DYNAMIC     Gi1/0/1\r\n"
    ),
    "cdp neighbors detail": (
        "-------------------------\r\n"
        "Device ID: neighbor-router.lab\r\n"
        "Entry address(es):\r\n"
        "  IP address: 192.0.2.254\r\n"
        "Platform: cisco ISR4321/K9, Capabilities: Router Switch IGMP\r\n"
        "Interface: GigabitEthernet1/0/1, Port ID (outgoing port): GigabitEthernet0/0/0\r\n"
    ),
    "lldp neighbors detail": (
        "------------------------------------------------\r\n"
        "Local Intf: Gi1/0/1\r\n"
        "Chassis id: aabb.ccdd.eeff\r\n"
        "Port id: Gi0/0/0\r\n"
        "System Name: neighbor-router.lab\r\n"
    ),
    "inventory": (
        "NAME: \"1\", DESCR: \"WS-C3650-24TS\"\r\n"
        "PID: WS-C3650-24TS    , VID: V03, SN: FDO9999XYZ1\r\n"
    ),
    "clock": (
        "*04:25:17.123 UTC Sat Apr 26 2026\r\n"
    ),
    "logging": (
        "Syslog logging: enabled (0 messages dropped, 1 messages rate-limited)\r\n"
        "    Console logging: level debugging, 12 messages logged\r\n"
        "    Buffer logging: level debugging, 12 messages logged\r\n"
    ),
}


def _send(conn: socket.socket, data: str) -> None:
    conn.sendall(data.encode("utf-8", "replace"))


def _recv_line(conn: socket.socket, echo: bool) -> str | None:
    """Read one line terminated by LF (the axross telnet client sends
    CRLF). Returns None on EOF / socket error. Echoes each char back
    when ``echo`` is true so the IOS user-prompt feel is preserved
    (passwords are silent). CR characters are stripped before return,
    so callers see clean text."""
    buf = bytearray()
    while True:
        try:
            chunk = conn.recv(1)
        except OSError:
            return None
        if not chunk:
            return None
        b = chunk[0]
        # Telnet IAC negotiation: skip the next two bytes per IAC.
        if b == 0xff:
            try:
                conn.recv(2)
            except OSError:
                return None
            continue
        if b == 0x0a:
            # LF terminates the line. Strip a trailing CR (CRLF is what
            # the axross telnet client always sends).
            if buf.endswith(b"\r"):
                buf.pop()
            if echo:
                conn.sendall(b"\r\n")
            return buf.decode("utf-8", "replace")
        if b in (0x7f, 0x08):  # backspace
            if buf:
                buf.pop()
                if echo:
                    conn.sendall(b"\b \b")
            continue
        if b == 0x0d:
            # CR — buffer it and wait for the paired LF on the next
            # iteration. We strip the trailing CR before returning so
            # callers always see clean text. Bare-CR (no following LF)
            # is unusual; we accept it as still-buffered until a real
            # terminator arrives or the socket closes.
            buf.append(b)
            continue
        if b < 0x20:
            continue
        buf.append(b)
        if echo:
            conn.sendall(bytes([b]))


def _resolve_show(line: str) -> str:
    """Match ``line`` (post-``show`` text) against the SHOWS table.
    Allows trailing tokens (e.g. ``running-config | include ip``) by
    stripping after the first ``|``."""
    body = line.split("|", 1)[0].strip().lower()
    if body in SHOWS:
        return SHOWS[body]
    # ``show ip`` collapses to first prefix match for convenience.
    for k, v in SHOWS.items():
        if body == k.split(" ", 1)[0]:
            return v
    return f"% Invalid input detected at '^' marker.\r\n"


class _Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        conn: socket.socket = self.request
        peer = self.client_address
        LOG.info("connection from %s", peer)
        try:
            self._serve(conn)
        except Exception:  # noqa: BLE001
            LOG.exception("session crashed for %s", peer)
        finally:
            try:
                conn.close()
            except OSError:
                pass
            LOG.info("connection closed: %s", peer)

    def _serve(self, conn: socket.socket) -> None:
        _send(conn, BANNER)
        # Login dance.
        _send(conn, "Username: ")
        u = _recv_line(conn, echo=True)
        if u is None:
            return
        _send(conn, "Password: ")
        p = _recv_line(conn, echo=False)
        if p is None:
            return
        if u.strip() != USERNAME or p != PASSWORD:
            _send(conn, "% Login invalid\r\n\r\n")
            return
        privileged = False
        prompt = USER_PROMPT
        while True:
            # Real IOS emits a newline before re-prompting (the previous
            # ``show`` output ends with one; after a silent password
            # input there's an explicit \r\n before the prompt). Always
            # prepending CRLF satisfies CiscoTelnetSession's PROMPT_RE
            # which requires the prompt to be at the start of a line.
            _send(conn, "\r\n" + prompt + " ")
            line = _recv_line(conn, echo=True)
            if line is None:
                return
            cmd = line.strip()
            if not cmd:
                continue
            low = cmd.lower()
            if low in ("exit", "logout", "quit"):
                _send(conn, "\r\n")
                return
            if low.startswith("terminal "):
                # ``terminal length 0`` etc. — accept silently.
                continue
            if low == "enable":
                _send(conn, "Password: ")
                pw = _recv_line(conn, echo=False)
                if pw == ENABLE_PASSWORD:
                    privileged = True
                    prompt = PRIV_PROMPT
                else:
                    _send(conn, "% Access denied\r\n")
                continue
            if low == "disable":
                privileged = False
                prompt = USER_PROMPT
                continue
            if low.startswith("show "):
                # ``show running-config`` requires privileged on real
                # IOS. Mirror that — it's the difference the test
                # suite cares about.
                sub = cmd[5:].strip()
                if not privileged and sub.lower() in (
                    "running-config", "startup-config"
                ):
                    _send(conn, "% Invalid input detected at '^' marker.\r\n")
                    continue
                _send(conn, _resolve_show(sub))
                continue
            if low == "write memory" or low == "wr mem" or low == "copy run start":
                if not privileged:
                    _send(conn, "% Privilege required\r\n")
                    continue
                _send(conn, "Building configuration...\r\n[OK]\r\n")
                continue
            if low == "clear counters" or low.startswith("clear counters "):
                if not privileged:
                    _send(conn, "% Privilege required\r\n")
                    continue
                target = cmd[len("clear counters"):].strip() or "all"
                _send(conn, f"Clear \"show interface\" counters on "
                            f"{target} interface(s) [confirm]\r\n")
                continue
            _send(conn, f"% Unknown command or computer name: {cmd}\r\n")


class _ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("CISCO_LOGLEVEL", "INFO"),
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    LOG.info("cisco_fake listening on %s:%d (user=%s)", BIND, PORT, USERNAME)
    server = _ThreadingTCPServer((BIND, PORT), _Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        LOG.info("shutdown via SIGINT")
        return 0
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
