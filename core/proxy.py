"""Proxy socket creation for tunneling SSH through SOCKS and HTTP proxies."""

from __future__ import annotations

import base64
import contextlib
import ipaddress
import logging
import os
import socket
import threading
from dataclasses import dataclass

log = logging.getLogger(__name__)
MAX_HTTP_CONNECT_HEADER = 8192

# Serialises the ``socket.create_connection`` patch used by
# :func:`patched_create_connection` so two threads patching for
# different profiles can't see each other's replacement function.
_CREATE_CONNECTION_LOCK = threading.Lock()


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
    ipaddress.ip_network("127.0.0.0/8"),  # loopback
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local / AWS IMDS
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("10.0.0.0/8"),  # RFC1918
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),  # ULA
    ipaddress.ip_network("0.0.0.0/8"),  # RFC5735 "this network"
    ipaddress.ip_network("224.0.0.0/4"),  # multicast
    ipaddress.ip_network("ff00::/8"),
    ipaddress.ip_network("100.64.0.0/10"),  # RFC6598 CGNAT / shared space
    ipaddress.ip_network("::/128"),  # unspecified
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


# Loopback ports of this process's own :class:`core.proxy_http.LocalProxyShim`
# instances. The shim is how HTTP-only libraries reach NTLM / HTTPS / SOCKS
# proxies; its loopback address is not a user-supplied proxy host, so the
# deny-list must not refuse it. The shim's *upstream* is guarded when the
# shim is created.
_LIVE_SHIM_PORTS: set[int] = set()
_SHIM_PORTS_LOCK = threading.Lock()


def _register_shim_port(port: int, live: bool) -> None:
    with _SHIM_PORTS_LOCK:
        (_LIVE_SHIM_PORTS.add if live else _LIVE_SHIM_PORTS.discard)(port)


def _assert_proxy_host_not_private(host: str, port: int | None = None) -> None:
    """Raise :class:`ConnectionError` if the proxy host is in a
    deny-by-default range. Callers can opt in with
    ``AXROSS_ALLOW_PRIVATE_PROXY=1``.
    """
    from core.security_mode import current_policy

    if port is not None and host in ("127.0.0.1", "localhost"):
        with _SHIM_PORTS_LOCK:
            if port in _LIVE_SHIM_PORTS:
                return
    if os.environ.get("AXROSS_ALLOW_PRIVATE_PROXY") == "1" and current_policy().allow_private_proxy:
        return
    ips = _resolve_ips(host)
    if not ips:
        # Failed to resolve — let the normal connect path surface the
        # error; we don't want to second-guess DNS.
        return
    for ip in ips:
        # ``::ffff:169.254.169.254`` is an IPv6Address and is never "in"
        # an IPv4 network, yet the kernel connects to the v4 target.
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        for net in _DENY_BY_DEFAULT:
            if ip.version == net.version and ip in net:
                raise ConnectionError(
                    f"Proxy host {host!r} resolves to {ip} which is in "
                    f"the deny-by-default range {net}. Set "
                    f"AXROSS_ALLOW_PRIVATE_PROXY=1 to override."
                )


_PROXY_TRANSPORTS = ("socks4", "socks5", "http", "https")
_PROXY_AUTH_SCHEMES = ("basic", "ntlm", "negotiate", "kerberos")


def parse_proxy_type(proxy_type: str) -> tuple[str, str]:
    """Split ``"https+ntlm"`` into ``("https", "ntlm")``.

    The proxy kind stays one string (``socks4``, ``socks5``, ``http``,
    ``https``, optionally ``+basic`` / ``+ntlm`` / ``+negotiate`` /
    ``+kerberos`` on the HTTP kinds) so profiles, scripts and every backend
    constructor keep the same five ``proxy_*`` fields.
    """
    base, plus, auth = (proxy_type or "").lower().partition("+")
    if base not in _PROXY_TRANSPORTS:
        raise ValueError(f"Unknown proxy type: {proxy_type}")
    if plus and not auth:
        raise ValueError(f"Unknown proxy type: {proxy_type}")
    if auth and auth not in _PROXY_AUTH_SCHEMES:
        raise ValueError(f"Unknown proxy authentication scheme: {auth!r}")
    if auth and base.startswith("socks"):
        raise ValueError("SOCKS proxies authenticate with username/password only")
    return base, auth


def compose_proxy_type(transport: str, auth: str = "") -> str:
    """Inverse of :func:`parse_proxy_type`: ``("https", "ntlm")`` ->
    ``"https+ntlm"``. Raises ``ValueError`` for combinations that do not
    exist (an auth scheme on SOCKS, an unknown transport)."""
    kind = f"{transport}+{auth}" if auth else transport
    parse_proxy_type(kind)
    return kind


def is_valid_proxy_type(proxy_type: str) -> bool:
    """``True`` for ``none`` and every kind :func:`parse_proxy_type` accepts."""
    if (proxy_type or "none").lower() == "none":
        return True
    try:
        parse_proxy_type(proxy_type)
    except ValueError:
        return False
    return True


def default_proxy_ca_file() -> str:
    """CA bundle that verifies an HTTPS proxy's certificate when the
    config carries none: ``AXROSS_PROXY_CA_FILE``, else the setting in
    Tools > Network & Proxy, else the system store (empty string)."""
    env = os.environ.get("AXROSS_PROXY_CA_FILE", "")
    if env:
        return env
    try:
        from core import proxy_settings

        return proxy_settings.load().ca_file
    except Exception:  # noqa: BLE001 - settings are optional here
        return ""


@dataclass
class ProxyConfig:
    """Proxy configuration."""

    proxy_type: str  # "none", "socks4", "socks5", "http", "https" (+ "+ntlm" ...)
    host: str = ""
    port: int = 0
    username: str = ""
    password: str = ""
    ca_file: str = ""  # pinned CA for an HTTPS proxy's certificate

    def __post_init__(self) -> None:
        self.proxy_type = (self.proxy_type or "none").lower()
        if self.proxy_type != "none" and self.transport == "https" and not self.ca_file:
            self.ca_file = default_proxy_ca_file()

    @property
    def enabled(self) -> bool:
        return _proxy_enabled_or_raise(self.proxy_type, self.host)

    @property
    def transport(self) -> str:
        """``socks4`` / ``socks5`` / ``http`` / ``https`` (``none`` stays)."""
        if self.proxy_type == "none":
            return "none"
        return self.proxy_type.partition("+")[0]

    @property
    def auth_scheme(self) -> str:
        """``""`` (Basic when a username is set), ``basic``, ``ntlm``,
        ``negotiate`` or ``kerberos``."""
        return self.proxy_type.partition("+")[2]

    @property
    def needs_shim(self) -> bool:
        """``True`` when an HTTP-only library cannot use this proxy
        directly (TLS to the proxy, NTLM / Negotiate, or SOCKS)."""
        return self.transport != "http" or self.auth_scheme not in ("", "basic")


def _proxy_enabled_or_raise(proxy_type: str, host: str) -> bool:
    """Return whether a proxy should be used, failing closed on
    half-configured proxies.

    ``proxy_type='none'`` is an explicit opt-out. Any other type means
    the caller expects proxy routing; an empty host must not silently
    become a direct connection.
    """
    ptype = (proxy_type or "none").lower()
    if ptype == "none":
        return False
    if not host:
        raise ValueError(f"proxy_type={ptype!r} requires proxy_host; refusing direct traffic.")
    return True


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


def _validate_proxy_url_host(host: str) -> None:
    """Validate a proxy host before embedding it in a URL authority."""
    _validate_endpoint_host(host, "Proxy host")
    if _is_ipv6_literal(host):
        return
    if any(
        ch in host
        for ch in (
            "/",
            "\\",
            "@",
            "?",
            "#",
            "[",
            "]",
            ":",
            ";",
            "'",
            '"',
            "`",
            "$",
            "&",
            "|",
            "(",
            ")",
            "<",
            ">",
        )
    ):
        raise ValueError(
            "Proxy host contains delimiter characters; pass only the "
            "hostname/IP and keep the port in the separate port field."
        )


def _validate_proxy_port(port: int) -> int:
    """Return a validated proxy port.

    Port ``0`` is used in profiles as "unset", but once a proxy host
    is configured there is no sensible default. Refuse it centrally
    so every transport path fails before opening a direct or malformed
    connection.
    """
    try:
        value = int(port)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Proxy port must be an integer; got {port!r}") from exc
    if not (1 <= value <= 65535):
        raise ValueError(
            f"Proxy port must be in range 1..65535 when proxy_host is set; got {value}"
        )
    return value


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
    if not proxy.enabled:
        raise ValueError("create_proxy_socket requires an enabled proxy config")
    _validate_proxy_url_host(proxy.host)
    _validate_endpoint_host(target_host, "Target host")
    proxy = ProxyConfig(
        proxy.proxy_type,
        proxy.host,
        _validate_proxy_port(proxy.port),
        proxy.username,
        proxy.password,
        proxy.ca_file,
    )
    # SSRF guard: refuse to proxy through a deny-listed private /
    # metadata address unless the user has explicitly opted in.
    _assert_proxy_host_not_private(proxy.host, proxy.port)
    transport, auth = parse_proxy_type(proxy.proxy_type)
    if transport in ("socks4", "socks5"):
        return _create_socks_socket(proxy, target_host, target_port, timeout, family)
    if transport == "http" and auth in ("", "basic"):
        return _create_http_connect_socket(proxy, target_host, target_port, timeout, family)
    from core.proxy_http import open_connect_tunnel

    return open_connect_tunnel(proxy, target_host, target_port, timeout, family)


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
            timeout,
            proxy.proxy_type.upper(),
            proxy.host,
            proxy.port,
            target_host,
            target_port,
        )
        raise ConnectionError(
            f"Timeout connecting through {proxy.proxy_type.upper()} proxy {proxy.host}:{proxy.port}"
        ) from exc
    except (OSError, socks.ProxyError) as e:
        s.close()
        log.warning(
            "%s proxy %s:%d refused tunnel to %s:%d: %s",
            proxy.proxy_type.upper(),
            proxy.host,
            proxy.port,
            target_host,
            target_port,
            e,
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
            proxy.host,
            proxy.port,
            last_error,
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
    except (socket.timeout, OSError) as e:
        sock.close()
        log.warning(
            "HTTP CONNECT %s via %s:%d failed: %s",
            connect_target,
            proxy.host,
            proxy.port,
            e,
        )
        raise ConnectionError(f"HTTP CONNECT failed: {e}") from e

    if b"\r\n\r\n" not in response:
        sock.close()
        raise ConnectionError("HTTP CONNECT returned an incomplete or oversized header")

    status_line = response.decode("ascii", errors="replace").split("\r\n")[0]
    status_parts = status_line.split(" ", 2)
    status = status_parts[1] if len(status_parts) >= 2 else ""
    if status == "200":
        log.debug("HTTP CONNECT established: %s", status_line)
        return sock

    sock.close()
    if status == "407":
        from core.proxy_http import ProxyAuthError

        if proxy.username:
            raise ProxyAuthError("proxy rejected the username / password (407)")
        raise ProxyAuthError("proxy requires authentication (407); set a username and password")
    raise ConnectionError(f"HTTP CONNECT failed: {status_line}")


def build_requests_proxies(
    proxy_type: str,
    host: str,
    port: int,
    username: str = "",
    password: str = "",
    ca_file: str = "",
) -> dict[str, str]:
    """Build a ``requests``-style proxies dict from ProxyConfig fields.

    The returned dict assigns to ``requests.Session().proxies`` and
    works for any HTTP-based backend: WebDAV, OneDrive, Dropbox,
    Exchange, WinRM, Azure (via custom transport), even boto3 (via
    ``BotoConfig(proxies=...)``).

    Returns ``{}`` when no proxy is configured. SOCKS5 uses the
    ``socks5h://`` scheme so DNS resolution happens at the proxy
    side — this matches how ``create_proxy_socket`` handles SOCKS5
    via PySocks (``rdns=True``).

    Routes through the SSRF guard so the requests path gets the same
    deny-list as ``create_proxy_socket``.
    """
    proxy_type = (proxy_type or "none").lower()
    if not _proxy_enabled_or_raise(proxy_type, host):
        return {}
    _validate_proxy_url_host(host)
    port = _validate_proxy_port(port)
    _assert_proxy_host_not_private(host, port)
    transport, auth = parse_proxy_type(proxy_type)
    if transport == "https" or auth not in ("", "basic"):
        # TLS to the proxy, NTLM and Negotiate are not something requests /
        # urllib3 can do: they talk to a loopback shim that does.
        from core.proxy_http import shim_for

        shim = shim_for(ProxyConfig(proxy_type, host, port, username, password, ca_file))
        return {"http": shim.url, "https": shim.url}
    if transport == "http":
        scheme = "http"
    elif transport == "socks4":
        # "socks4a": the proxy resolves host names, like create_proxy_socket.
        scheme = "socks4a"
    else:
        scheme = "socks5h"  # 'h' = remote DNS via the proxy (safer)

    # Password without username is meaningless (no auth identity).
    # Refuse it loudly rather than silently emit a credential-free URL
    # — the alternative is the user thinking the proxy auth was set
    # when in fact the password got dropped on the floor.
    if password and not username:
        raise ValueError(
            "Proxy password set without a proxy username — refusing to "
            "drop the credential silently. Set the username too, or "
            "clear the password.",
        )

    from urllib.parse import quote

    cred = ""
    if username:
        cred = quote(username, safe="")
        if password:
            cred += ":" + quote(password, safe="")
        cred += "@"

    # IPv6 literals must be bracketed in a URL so the port separator
    # ``:`` isn't ambiguous against the address's own colons.
    if _is_ipv6_literal(host):
        host_part = f"[{host}]"
    else:
        host_part = host

    url = f"{scheme}://{cred}{host_part}:{int(port)}"
    return {"http": url, "https": url}


def apply_session_proxy(session, profile_or_config) -> None:
    """Set ``session.proxies`` on a ``requests.Session`` from either
    a :class:`ProxyConfig` instance or a ConnectionProfile-like
    object exposing ``proxy_type`` / ``proxy_host`` / ``proxy_port``
    / ``proxy_username`` / ``get_proxy_password()``.

    Idempotent: a no-op when the source has no proxy configured.
    """
    if session is None or not hasattr(session, "headers"):
        return
    if isinstance(profile_or_config, ProxyConfig):
        cfg = profile_or_config
        if not cfg.enabled:
            return
        proxies = build_requests_proxies(
            cfg.proxy_type,
            cfg.host,
            cfg.port,
            cfg.username,
            cfg.password,
            cfg.ca_file,
        )
    else:
        # ConnectionProfile-like (has proxy_host, proxy_port, proxy_*).
        prof = profile_or_config
        ptype = getattr(prof, "proxy_type", "none") or "none"
        host = getattr(prof, "proxy_host", "") or ""
        if not _proxy_enabled_or_raise(ptype, host):
            return
        ppassword = ""
        if hasattr(prof, "get_proxy_password"):
            try:
                ppassword = prof.get_proxy_password() or ""
            except Exception:  # noqa: BLE001 — keyring failures shouldn't break connect
                ppassword = ""
        proxies = build_requests_proxies(
            ptype,
            host,
            int(getattr(prof, "proxy_port", 0) or 0),
            getattr(prof, "proxy_username", "") or "",
            ppassword,
        )
    lock_requests_session_to_profile_proxy(session, proxies)


def lock_requests_session_to_profile_proxy(
    session,
    proxies: dict[str, str] | None = None,
) -> None:
    """Make a requests-like session obey only the profile proxy.

    ``requests`` honours ``HTTP_PROXY`` / ``HTTPS_PROXY`` from the process
    environment by default. Axross profiles are explicit per-connection
    routing decisions, so SDK sessions we control should not silently
    inherit environment proxies. When *proxies* is given, attach that
    profile proxy after disabling environment inheritance.
    """
    if session is None:
        return
    try:
        session.trust_env = False
    except Exception as exc:  # noqa: BLE001 - SDK-private objects vary
        if proxies:
            raise OSError(
                "Proxy configured but the requests-like session refused "
                "trust_env=False; refusing direct traffic."
            ) from exc
    if proxies:
        if not hasattr(session, "proxies"):
            raise OSError(
                "Proxy configured but the requests-like session has no "
                "'proxies' attribute; refusing direct traffic."
            )
        session.proxies = dict(proxies)


def proxy_config_from_kwargs(kwargs: dict) -> "ProxyConfig | None":
    """Build a :class:`ProxyConfig` from the ``proxy_*`` kwargs every
    backend constructor receives. Returns ``None`` when no proxy is
    configured and raises ``ValueError`` for a half-configured one."""
    ptype = (kwargs.get("proxy_type") or "none").lower()
    host = kwargs.get("proxy_host") or ""
    if not _proxy_enabled_or_raise(ptype, host):
        return None
    return ProxyConfig(
        proxy_type=ptype,
        host=host,
        port=int(kwargs.get("proxy_port") or 0),
        username=kwargs.get("proxy_username") or "",
        password=kwargs.get("proxy_password") or "",
        ca_file=kwargs.get("proxy_ca_file") or "",
    )


def effective_http_proxy(proxy: "ProxyConfig") -> "ProxyConfig":
    """An HTTP proxy config any HTTP-only library can use.

    A plain ``http`` proxy (Basic auth) is returned unchanged. Everything
    else (SOCKS, TLS to the proxy, NTLM / Negotiate) is fronted by the
    loopback :class:`core.proxy_http.LocalProxyShim`: the returned config
    points at it and carries no credentials, because the shim holds them.
    """
    if not proxy.needs_shim:
        return proxy
    from core.proxy_http import shim_for

    shim = shim_for(proxy)
    return ProxyConfig("http", shim.host, shim.port)


def _peer_is_same_user(peer: tuple, root_ok: bool = False, server: tuple | None = None) -> bool:
    """True when the loopback client at *peer* belongs to our uid
    (or, with *root_ok*, to root: kernel mounts and the iSCSI daemon).

    A loopback listener is reachable by every local account; without
    this check another user on the host could ride the tunnel (and the
    proxy credentials behind it). Reads ``/proc/net/tcp{,6}``; where
    that is unavailable (non-Linux) there is nothing to compare, so the
    peer is accepted.

    The client socket is identified by its full address pair: a source
    port can appear on several rows at once (a ``TIME_WAIT`` leftover is
    reported with uid 0), so *server* -- the accepted socket's own
    address -- selects the right one, and ``TIME_WAIT`` rows never count.
    """
    if not os.path.exists("/proc/net/tcp"):
        return True
    host, port = peer[0], peer[1]
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    want_remote = None
    if server is not None:
        try:
            want_remote = (ipaddress.ip_address(server[0]), int(server[1]))
        except ValueError:
            return False
    uid = os.getuid()

    def decode(field: str, v6: bool):
        addr, prt = field.rsplit(":", 1)
        raw = bytes.fromhex(addr)
        if v6:
            # /proc stores IPv6 as four little-endian 32-bit words.
            raw = b"".join(raw[i : i + 4][::-1] for i in range(0, 16, 4))
            parsed = ipaddress.IPv6Address(raw)
            if parsed.ipv4_mapped is not None:
                parsed = parsed.ipv4_mapped
        else:
            parsed = ipaddress.IPv4Address(raw[::-1])
        return parsed, int(prt, 16)

    for table, v6 in (("/proc/net/tcp", False), ("/proc/net/tcp6", True)):
        try:
            with open(table, encoding="ascii") as fh:
                rows = fh.read().splitlines()[1:]
        except OSError:
            continue
        for row in rows:
            fields = row.split()
            if len(fields) < 8 or fields[3] == "06":  # 06 = TIME_WAIT
                continue
            try:
                local = decode(fields[1], v6)
                remote = decode(fields[2], v6)
            except ValueError:
                continue
            if local != (ip, port):
                continue
            if want_remote is not None and remote != want_remote:
                continue
            owner = int(fields[7])
            return owner == uid or (root_ok and owner == 0)
    return False


class LocalTunnel:
    """Loopback TCP listener that relays every connection through a proxy.

    Many client libraries (psycopg, pymongo, ldap3, ``svn://``) open the
    TCP connection themselves and offer no proxy hook. Pointing them at
    ``tunnel.host:tunnel.port`` makes each connection they open travel
    through the configured SOCKS / HTTP-CONNECT proxy to the real
    target. Bound to 127.0.0.1 only, restricted to the owning uid and
    capped in concurrent connections.
    """

    def __init__(
        self,
        proxy: "ProxyConfig",
        target_host: str,
        target_port: int,
        timeout: float = 10.0,
        max_connections: int = 64,
        allow_root_peers: bool = False,
    ) -> None:
        if not proxy.enabled:
            raise ValueError("LocalTunnel requires an enabled proxy config")
        self._allow_root_peers = allow_root_peers
        self._proxy = proxy
        self._target = (target_host, int(target_port))
        self._timeout = timeout
        self._slots = threading.BoundedSemaphore(max_connections)
        self._listener: socket.socket | None = None
        self._closed = threading.Event()
        self._active: set[socket.socket] = set()
        self._active_lock = threading.Lock()
        self.host = "127.0.0.1"
        self.port = 0

    # -- lifecycle ---------------------------------------------------------
    def start(self) -> "LocalTunnel":
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind((self.host, 0))
        listener.listen(16)
        self.port = listener.getsockname()[1]
        self._listener = listener
        threading.Thread(target=self._accept_loop, name="axross-proxy-tunnel", daemon=True).start()
        return self

    def close(self) -> None:
        self._closed.set()
        if self._listener is not None:
            # close() alone leaves a blocked accept() holding the fd, so
            # the port would keep accepting; shutdown wakes it first.
            with contextlib.suppress(OSError):
                self._listener.shutdown(socket.SHUT_RDWR)
            with contextlib.suppress(OSError):
                self._listener.close()
        with self._active_lock:
            active = list(self._active)
        for sock in active:
            with contextlib.suppress(OSError):
                sock.shutdown(socket.SHUT_RDWR)
            with contextlib.suppress(OSError):
                sock.close()

    def __enter__(self) -> "LocalTunnel":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.close()

    # -- relay -------------------------------------------------------------
    def _accept_loop(self) -> None:
        assert self._listener is not None
        while not self._closed.is_set():
            try:
                client, peer = self._listener.accept()
            except OSError:
                return
            if not _peer_is_same_user(peer, self._allow_root_peers, client.getsockname()[:2]):
                log.warning("proxy tunnel: dropped connection from foreign local user %s", peer)
                client.close()
                continue
            if not self._slots.acquire(blocking=False):
                log.warning("proxy tunnel: connection cap reached, dropping %s", peer)
                client.close()
                continue
            threading.Thread(target=self._relay, args=(client,), daemon=True).start()

    def _track(self, sock: socket.socket, add: bool) -> None:
        with self._active_lock:
            (self._active.add if add else self._active.discard)(sock)

    def _relay(self, client: socket.socket) -> None:
        upstream: socket.socket | None = None
        try:
            try:
                upstream = create_proxy_socket(
                    self._proxy, self._target[0], self._target[1], timeout=self._timeout
                )
            except (OSError, ValueError) as exc:
                log.warning("proxy tunnel: %s:%d unreachable via proxy: %s", *self._target, exc)
                return
            upstream.settimeout(None)
            client.settimeout(None)
            self._track(client, True)
            self._track(upstream, True)
            relay_both(client, upstream)
        finally:
            for sock in (client, upstream):
                if sock is not None:
                    self._track(sock, False)
                    with contextlib.suppress(OSError):
                        sock.close()
            self._slots.release()


def _pump_half(src: socket.socket, dst: socket.socket) -> None:
    """Copy *src* to *dst* until *src* ends.

    A clean end of stream is passed on as a half-close (``SHUT_WR`` on
    *dst*) so the reply still flowing the other way arrives — a client
    that sends its request and closes its write side waits for exactly
    that. Only an error tears both sockets down."""
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        for sock in (src, dst):
            with contextlib.suppress(OSError):
                sock.shutdown(socket.SHUT_RDWR)
        return
    with contextlib.suppress(OSError):
        dst.shutdown(socket.SHUT_WR)


def relay_both(client: socket.socket, upstream: socket.socket) -> None:
    """Relay both directions until both have ended.

    No deadline on the second direction: a half-closed connection is
    held exactly as long as an idle open one would be, and the owner
    (tunnel or shim) closes every tracked socket when it shuts down."""
    back = threading.Thread(target=_pump_half, args=(upstream, client), daemon=True)
    back.start()
    _pump_half(client, upstream)
    back.join()


def open_tunnel(
    kwargs: dict, target_host: str, target_port: int, timeout: float = 10.0
) -> "LocalTunnel | None":
    """Start a :class:`LocalTunnel` for the ``proxy_*`` kwargs, or return
    ``None`` when no proxy is configured (caller connects directly)."""
    cfg = proxy_config_from_kwargs(kwargs)
    if cfg is None:
        return None
    _validate_endpoint_host(target_host, "Target host")
    return LocalTunnel(cfg, target_host, int(target_port), timeout=timeout).start()


def create_udp_proxy_socket(proxy: "ProxyConfig", timeout: float = 10.0) -> socket.socket:
    """UDP socket relayed through a SOCKS5 proxy (UDP ASSOCIATE).

    ``sendto`` / ``recvfrom`` work like on a plain datagram socket.
    SOCKS4 and HTTP CONNECT are TCP-only, so they raise
    :class:`ConnectionError` rather than silently going direct.
    """
    if not proxy.enabled:
        raise ValueError("create_udp_proxy_socket requires an enabled proxy config")
    if proxy.transport != "socks5":
        raise ConnectionError(
            f"{proxy.proxy_type} proxies cannot carry UDP; use a SOCKS5 proxy or remove the proxy."
        )
    import socks

    _validate_proxy_url_host(proxy.host)
    _assert_proxy_host_not_private(proxy.host)
    s = socks.socksocket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    s.set_proxy(
        socks.SOCKS5,
        proxy.host,
        _validate_proxy_port(proxy.port),
        username=proxy.username or None,
        password=proxy.password or None,
    )
    return s


class ProxyUnsupportedError(OSError):
    """A proxy is configured for a backend that cannot honour it.

    Raised instead of connecting directly: a profile that says "use this
    proxy" must never silently send traffic around it.
    """


def refuse_unsupported_proxy(
    protocol: str,
    proxy_type: str = "none",
    proxy_host: str = "",
    reason: str = "",
) -> None:
    """Fail closed when *protocol* cannot use the configured proxy.

    No-op when no proxy is configured. The remedy is part of the message:
    remove the proxy from the profile (an explicit decision to connect
    directly) or route at the OS / network layer.
    """
    if (proxy_type or "none").lower() == "none" and not proxy_host:
        return
    detail = f" {reason}" if reason else ""
    raise ProxyUnsupportedError(
        f"{protocol} cannot be tunnelled through the configured "
        f"{proxy_type or 'unknown'} proxy.{detail} Remove the proxy from "
        "the profile to connect directly, or route this traffic at the "
        "OS / network layer. See docs/PROXY_SUPPORT.md."
    )


def build_urllib3_proxy_manager(proxy: "ProxyConfig"):
    """urllib3 pool manager that sends everything through *proxy*.

    SOCKS proxies resolve names remotely (``socks5h`` / ``socks4a``) so
    internal host names are not looked up locally.
    """
    from urllib.parse import quote

    _validate_proxy_url_host(proxy.host)
    _assert_proxy_host_not_private(proxy.host, proxy.port)
    port = _validate_proxy_port(proxy.port)
    if proxy.transport != "socks4" and proxy.transport != "socks5" and proxy.needs_shim:
        import urllib3

        shim = effective_http_proxy(proxy)
        return urllib3.ProxyManager(f"http://{shim.host}:{shim.port}")
    auth = ""
    if proxy.username:
        auth = quote(proxy.username, safe="")
        if proxy.password:
            auth += ":" + quote(proxy.password, safe="")
        auth += "@"
    host = f"[{proxy.host}]" if _is_ipv6_literal(proxy.host) else proxy.host
    if proxy.transport == "http":
        import urllib3

        # urllib3 ignores userinfo in a ProxyManager URL: the credentials
        # have to travel as a Proxy-Authorization header, or every request
        # meets a 407.
        headers = (
            urllib3.make_headers(proxy_basic_auth=f"{proxy.username}:{proxy.password}")
            if proxy.username
            else None
        )
        return urllib3.ProxyManager(f"http://{host}:{port}", proxy_headers=headers)
    from urllib3.contrib.socks import SOCKSProxyManager

    scheme = "socks5h" if proxy.transport == "socks5" else "socks4a"
    return SOCKSProxyManager(f"{scheme}://{auth}{host}:{port}")


class _SocketModuleShim:
    """Stand-in for the ``socket`` module whose ``socket()`` factory hands
    out SOCKS5-relayed datagram sockets; everything else is delegated."""

    def __init__(self, proxy: "ProxyConfig") -> None:
        self._proxy = proxy

    def socket(self, family=socket.AF_INET, type=socket.SOCK_STREAM, *args, **kwargs):  # noqa: A002
        if type != socket.SOCK_DGRAM:
            raise ConnectionError("proxied module may only open datagram sockets")
        return create_udp_proxy_socket(self._proxy, timeout=10.0)

    def __getattr__(self, name: str):
        return getattr(socket, name)


_UDP_PATCH_LOCK = threading.Lock()


@contextlib.contextmanager
def patched_module_udp_socket(module, proxy: "ProxyConfig | None"):
    """Temporarily make ``module.socket.socket(AF_INET, SOCK_DGRAM)`` a
    SOCKS5 UDP relay (for libraries such as tftpy that create their UDP
    socket internally). Scoped and serialised like
    :func:`patched_create_connection`. Yields untouched without a proxy.
    """
    if proxy is None:
        yield
        return
    if proxy.transport != "socks5":
        raise ConnectionError(
            f"{proxy.proxy_type} proxies cannot carry UDP; use a SOCKS5 proxy or remove the proxy."
        )
    with _UDP_PATCH_LOCK:
        original = module.socket
        module.socket = _SocketModuleShim(proxy)
        try:
            yield
        finally:
            module.socket = original


def warn_unsupported_proxy(
    protocol: str,
    proxy_type: str = "none",
    proxy_host: str = "",
    reason: str = "",
) -> None:
    """Log a consistent warning when a backend receives proxy kwargs
    it cannot honour.

    This is intentionally non-fatal: some direct-construction paths
    accept ``**kwargs`` for forward compatibility. A warning is enough
    to stop users from believing their traffic is tunnelled when it is
    not, while keeping old scripts from breaking merely because they
    passed a shared kwargs dict.
    """
    if (proxy_type or "none").lower() == "none" and not proxy_host:
        return
    detail = f" {reason}" if reason else ""
    log.warning(
        "%s backend does not support SOCKS/HTTP proxy tunnelling in "
        "axross; proxy_type=%r proxy_host=%r will be ignored.%s",
        protocol,
        proxy_type,
        proxy_host,
        detail,
    )


@contextlib.contextmanager
def patched_create_connection(profile_or_config):
    """Temporarily override ``socket.create_connection`` so it routes
    through the proxy.

    Use as a context manager around a third-party library call that
    internally uses :func:`socket.create_connection` and exposes no
    other proxy hook (smbprotocol, adb-shell, …). Same scoping
    discipline as :func:`core.smb_client._patched_gethostname`: a
    process-global lock serialises the patch across threads.

    Yields without patching when no proxy is configured.
    """
    proxy_cfg: "ProxyConfig | None" = None
    if isinstance(profile_or_config, ProxyConfig):
        if profile_or_config.enabled:
            proxy_cfg = profile_or_config
    else:
        prof = profile_or_config
        ptype = getattr(prof, "proxy_type", "none") or "none"
        host = getattr(prof, "proxy_host", "") or ""
        if _proxy_enabled_or_raise(ptype, host):
            ppassword = ""
            if hasattr(prof, "get_proxy_password"):
                try:
                    ppassword = prof.get_proxy_password() or ""
                except Exception:  # noqa: BLE001
                    ppassword = ""
            proxy_cfg = ProxyConfig(
                proxy_type=ptype,
                host=host,
                port=int(getattr(prof, "proxy_port", 0) or 0),
                username=getattr(prof, "proxy_username", "") or "",
                password=ppassword,
            )
    if proxy_cfg is None:
        yield
        return

    proxy_cfg = ProxyConfig(
        proxy_cfg.proxy_type,
        proxy_cfg.host,
        _validate_proxy_port(proxy_cfg.port),
        proxy_cfg.username,
        proxy_cfg.password,
        proxy_cfg.ca_file,
    )

    with _CREATE_CONNECTION_LOCK:
        original = socket.create_connection

        def proxied(address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, **kwargs):
            host, port = address
            t = timeout if timeout is not socket._GLOBAL_DEFAULT_TIMEOUT else 10.0
            return create_proxy_socket(
                proxy_cfg,
                host,
                int(port),
                timeout=float(t),
            )

        socket.create_connection = proxied  # type: ignore[assignment]
        try:
            yield
        finally:
            socket.create_connection = original  # type: ignore[assignment]


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
