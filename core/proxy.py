"""Proxy socket creation for tunneling SSH through SOCKS and HTTP proxies."""
from __future__ import annotations

import base64
import ipaddress
import logging
import os
import socket
from dataclasses import dataclass

log = logging.getLogger(__name__)
MAX_HTTP_CONNECT_HEADER = 8192


# ---------------------------------------------------------------------------
# SSRF guard
# ---------------------------------------------------------------------------

# When the proxy host resolves to one of these network ranges, axross
# by default refuses to route through it — that way an imported /
# attacker-controlled profile can't silently make us proxy via the
# cloud-metadata endpoint (AWS 169.254.169.254, GCP/Azure variants)
# or the user's own loopback services (127.0.0.0/8).
#
# Users running axross from inside a private network genuinely need
# to proxy through RFC1918 IPs — they opt in via
# ``AXROSS_ALLOW_PRIVATE_PROXY=1``. The guard is a safety net, not a
# hard wall; no backend protocol requires a proxy to RFC1918.
_DENY_BY_DEFAULT = (
    ipaddress.ip_network("127.0.0.0/8"),        # loopback
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("169.254.0.0/16"),     # link-local / AWS IMDS
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("10.0.0.0/8"),         # RFC1918
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),           # ULA
    ipaddress.ip_network("0.0.0.0/8"),          # RFC5735 "this network"
    ipaddress.ip_network("224.0.0.0/4"),        # multicast
    ipaddress.ip_network("ff00::/8"),
)


def _resolve_ips(host: str) -> list[ipaddress._BaseAddress]:
    """Return all IPs the host resolves to (v4 + v6). Empty if unknown."""
    out: list[ipaddress._BaseAddress] = []
    # Literal IPs first — skip DNS.
    try:
        return [ipaddress.ip_address(host)]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return out
    for info in infos:
        sockaddr = info[4]
        try:
            out.append(ipaddress.ip_address(sockaddr[0]))
        except ValueError:
            continue
    return out


def _assert_proxy_host_not_private(host: str) -> None:
    """Raise :class:`ConnectionError` if the proxy host is in a
    deny-by-default range. Callers can opt in with
    ``AXROSS_ALLOW_PRIVATE_PROXY=1``.
    """
    if os.environ.get("AXROSS_ALLOW_PRIVATE_PROXY") == "1":
        return
    ips = _resolve_ips(host)
    if not ips:
        # Failed to resolve — let the normal connect path surface the
        # error; we don't want to second-guess DNS.
        return
    for ip in ips:
        for net in _DENY_BY_DEFAULT:
            if ip in net:
                raise ConnectionError(
                    f"Proxy host {host!r} resolves to {ip} which is in "
                    f"the deny-by-default range {net}. Set "
                    f"AXROSS_ALLOW_PRIVATE_PROXY=1 to override."
                )


@dataclass
class ProxyConfig:
    """Proxy configuration."""

    proxy_type: str  # "none", "socks4", "socks5", "http"
    host: str = ""
    port: int = 0
    username: str = ""
    password: str = ""

    @property
    def enabled(self) -> bool:
        return self.proxy_type != "none" and bool(self.host)


def _is_ipv6_literal(host: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET6, host)
    except OSError:
        return False
    return True


def _resolve_target_host(
    host: str,
    port: int,
    family: int,
) -> str:
    """Resolve a host to a concrete address for a specific address family."""
    try:
        addr_infos = socket.getaddrinfo(host, port, family, socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise ConnectionError(f"Cannot resolve host {host!r}: {e}") from e
    if not addr_infos:
        raise ConnectionError(f"Cannot resolve host {host!r} for requested address family")
    return addr_infos[0][4][0]


def _validate_endpoint_host(host: str, label: str) -> None:
    if not host:
        raise ConnectionError(f"{label} must not be empty")
    if any(ch in host for ch in ("\r", "\n", "\x00")):
        raise ConnectionError(f"{label} contains invalid control characters")
    if any(ch.isspace() for ch in host):
        raise ConnectionError(f"{label} must not contain whitespace")


def _preferred_proxy_family(host: str, port: int) -> int:
    """Pick a socket family that can reach the proxy itself."""
    try:
        addr_infos = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror:
        return socket.AF_INET6 if _is_ipv6_literal(host) else socket.AF_INET
    if not addr_infos:
        return socket.AF_INET
    return addr_infos[0][0]


def create_proxy_socket(
    proxy: ProxyConfig,
    target_host: str,
    target_port: int,
    timeout: float = 10.0,
    family: int = socket.AF_UNSPEC,
) -> socket.socket:
    """Create a connected socket that tunnels through the proxy to the target.

    Returns a socket suitable for passing to paramiko.Transport().

    Raises:
        ConnectionError: If proxy connection fails.
        ImportError: If PySocks is not installed (for SOCKS proxies).
    """
    _validate_endpoint_host(proxy.host, "Proxy host")
    _validate_endpoint_host(target_host, "Target host")
    # SSRF guard: refuse to proxy through a deny-listed private /
    # metadata address unless the user has explicitly opted in.
    _assert_proxy_host_not_private(proxy.host)
    if proxy.proxy_type in ("socks4", "socks5"):
        return _create_socks_socket(proxy, target_host, target_port, timeout, family)
    elif proxy.proxy_type == "http":
        return _create_http_connect_socket(proxy, target_host, target_port, timeout, family)
    else:
        raise ValueError(f"Unknown proxy type: {proxy.proxy_type}")


def _create_socks_socket(
    proxy: ProxyConfig,
    target_host: str,
    target_port: int,
    timeout: float,
    family: int,
) -> socket.socket:
    """Create socket through SOCKS4/5 proxy using PySocks."""
    import socks

    socks_type = socks.SOCKS4 if proxy.proxy_type == "socks4" else socks.SOCKS5
    resolved_target = target_host
    rdns = proxy.proxy_type == "socks5"

    if proxy.proxy_type == "socks4":
        if family == socket.AF_INET6 or _is_ipv6_literal(target_host):
            raise ConnectionError("SOCKS4 does not support IPv6 targets; use SOCKS5 instead")
        # SOCKS4a can resolve hostnames remotely, but explicit family selection
        # requires local resolution to an IPv4 literal.
        rdns = family == socket.AF_UNSPEC

    if family in (socket.AF_INET, socket.AF_INET6):
        resolved_target = _resolve_target_host(target_host, target_port, family)
        rdns = False

    proxy_family = _preferred_proxy_family(proxy.host, proxy.port)
    s = socks.socksocket(proxy_family, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.set_proxy(
        socks_type,
        proxy.host,
        proxy.port,
        rdns=rdns,
        username=proxy.username or None,
        password=proxy.password or None,
    )

    log.info(
        "Connecting through %s proxy %s:%d to %s:%d",
        proxy.proxy_type.upper(),
        proxy.host,
        proxy.port,
        target_host,
        target_port,
    )

    try:
        s.connect((resolved_target, target_port))
    except socket.timeout as exc:
        s.close()
        log.warning(
            "Timeout (%.1fs) through %s proxy %s:%d -> %s:%d",
            timeout, proxy.proxy_type.upper(),
            proxy.host, proxy.port, target_host, target_port,
        )
        raise ConnectionError(
            f"Timeout connecting through {proxy.proxy_type.upper()} proxy "
            f"{proxy.host}:{proxy.port}"
        ) from exc
    except (OSError, socks.ProxyError) as e:
        s.close()
        log.warning(
            "%s proxy %s:%d refused tunnel to %s:%d: %s",
            proxy.proxy_type.upper(), proxy.host, proxy.port,
            target_host, target_port, e,
        )
        raise ConnectionError(f"SOCKS proxy connection failed: {e}") from e

    return s


def _create_http_connect_socket(
    proxy: ProxyConfig,
    target_host: str,
    target_port: int,
    timeout: float,
    family: int,
) -> socket.socket:
    """Create socket through HTTP CONNECT proxy."""
    _validate_endpoint_host(proxy.host, "Proxy host")
    _validate_endpoint_host(target_host, "Target host")
    # Resolve proxy address (supports IPv4 and IPv6 proxy hosts)
    try:
        proxy_addrs = socket.getaddrinfo(
            proxy.host, proxy.port, socket.AF_UNSPEC, socket.SOCK_STREAM
        )
    except socket.gaierror as e:
        raise ConnectionError(f"Cannot resolve proxy host {proxy.host!r}: {e}") from e
    if not proxy_addrs:
        raise ConnectionError(f"Cannot resolve proxy host: {proxy.host}")

    # Try each resolved address
    last_error: Exception | None = None
    sock: socket.socket | None = None

    for af, socktype, proto, canonname, sockaddr in proxy_addrs:
        s: socket.socket | None = None
        try:
            s = socket.socket(af, socktype, proto)
            s.settimeout(timeout)
            s.connect(sockaddr)
            sock = s
            break
        except OSError as e:
            last_error = e
            if s is not None:
                s.close()

    if sock is None:
        log.warning(
            "Cannot reach HTTP proxy %s:%d: %s",
            proxy.host, proxy.port, last_error,
        )
        raise ConnectionError(
            f"Cannot connect to HTTP proxy {proxy.host}:{proxy.port}: {last_error}"
        ) from last_error

    connect_host = target_host
    if family in (socket.AF_INET, socket.AF_INET6):
        connect_host = _resolve_target_host(target_host, target_port, family)

    # Format target for CONNECT — bracket IPv6 literals
    if _is_ipv6_literal(connect_host):
        connect_target = f"[{connect_host}]:{target_port}"
    else:
        connect_target = f"{connect_host}:{target_port}"

    # Build CONNECT request
    headers = f"CONNECT {connect_target} HTTP/1.1\r\nHost: {connect_target}\r\n"

    if proxy.username:
        creds = base64.b64encode(f"{proxy.username}:{proxy.password}".encode()).decode()
        headers += f"Proxy-Authorization: Basic {creds}\r\n"

    headers += "\r\n"

    log.info("HTTP CONNECT to %s through %s:%d", connect_target, proxy.host, proxy.port)

    try:
        sock.sendall(headers.encode("ascii"))

        # Read until the end of headers without consuming tunnel payload bytes.
        response = b""
        while b"\r\n\r\n" not in response and len(response) < MAX_HTTP_CONNECT_HEADER:
            chunk = sock.recv(1)
            if not chunk:
                break
            response += chunk

        if b"\r\n\r\n" not in response:
            sock.close()
            raise ConnectionError("HTTP CONNECT returned an incomplete or oversized header")

        response_text = response.decode("ascii", errors="replace")
        status_line = response_text.split("\r\n")[0]
        status_parts = status_line.split(" ", 2)

        if len(status_parts) < 2 or status_parts[1] != "200":
            sock.close()
            raise ConnectionError(f"HTTP CONNECT failed: {status_line}")

        log.debug("HTTP CONNECT established: %s", status_line)
        return sock

    except (socket.timeout, OSError) as e:
        sock.close()
        log.warning(
            "HTTP CONNECT %s via %s:%d failed: %s",
            connect_target, proxy.host, proxy.port, e,
        )
        raise ConnectionError(f"HTTP CONNECT failed: {e}") from e


def create_direct_socket(
    host: str,
    port: int,
    timeout: float = 10.0,
    family: int = socket.AF_UNSPEC,
) -> socket.socket:
    """Create a direct TCP socket supporting IPv4 and IPv6.

    Tries all resolved addresses, returning the first successful connection.
    """
    _validate_endpoint_host(host, "Target host")
    try:
        addr_infos = socket.getaddrinfo(host, port, family, socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise ConnectionError(f"Cannot resolve host {host!r}: {e}") from e
    if not addr_infos:
        raise ConnectionError(f"Cannot resolve host: {host}")

    last_error: Exception | None = None
    for af, socktype, proto, canonname, sockaddr in addr_infos:
        s: socket.socket | None = None
        try:
            s = socket.socket(af, socktype, proto)
            s.settimeout(timeout)
            s.connect(sockaddr)
            log.debug("Connected to %s (af=%s)", sockaddr, af)
            return s
        except OSError as e:
            last_error = e
            if s is not None:
                s.close()

    raise ConnectionError(f"Cannot connect to {host}:{port}: {last_error}")
