"""HTTP and HTTPS proxy transport with Basic / NTLM / Negotiate auth,
plus a loopback HTTP-proxy shim.

Two things live here because plain ``socks`` / ``HTTP CONNECT`` in
:mod:`core.proxy` is not enough for corporate proxies:

* :func:`open_connect_tunnel` — a CONNECT client that can reach the proxy
  over **TLS** (an "HTTPS proxy") and authenticate with **Basic**,
  **NTLM** or **Negotiate / Kerberos** (via ``pyspnego``). The result is
  a plain connected socket like :func:`core.proxy.create_proxy_socket`
  returns for every other proxy type.

* :class:`LocalProxyShim` — a tiny HTTP proxy on 127.0.0.1. Libraries that
  only understand ``http://host:port`` proxies (requests, botocore, the
  svn client, urllib3) cannot speak NTLM, TLS-to-the-proxy or SOCKS
  themselves; they talk to the shim, and the shim talks to the real
  proxy. One mechanism, every HTTP-based backend.

TLS to the proxy always verifies the proxy certificate and name
(system CAs, or the pinned ``ca_file``). There is deliberately no
"insecure" switch.
"""

from __future__ import annotations

import atexit
import base64
import contextlib
import logging
import re
import socket
import ssl
import threading
from dataclasses import dataclass, field
from urllib.parse import urlsplit

log = logging.getLogger(__name__)

MAX_HEADER_BYTES = 65536
MAX_AUTH_ROUNDS = 5
MAX_BUFFERED_BODY = 16 * 1024 * 1024

_HOP_BY_HOP = {
    "connection",
    "proxy-connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}


class ProxyAuthError(ConnectionError):
    """The proxy refused the credentials or offered no usable scheme."""


# ---------------------------------------------------------------------------
# Wire helpers
# ---------------------------------------------------------------------------
@dataclass
class _Response:
    status: int
    reason: str
    headers: list[tuple[str, str]] = field(default_factory=list)
    keepalive: bool = True

    def get_all(self, name: str) -> list[str]:
        name = name.lower()
        return [v for k, v in self.headers if k == name]

    def get(self, name: str, default: str = "") -> str:
        vals = self.get_all(name)
        return vals[0] if vals else default


def _read_head(sock: socket.socket, limit: int = MAX_HEADER_BYTES) -> bytes:
    """Read up to and including the blank line, byte by byte so tunnel
    payload that follows is never consumed."""
    buf = bytearray()
    while not buf.endswith(b"\r\n\r\n"):
        if len(buf) >= limit:
            raise ConnectionError("proxy response header too large")
        chunk = sock.recv(1)
        if not chunk:
            raise ConnectionError("proxy closed the connection during the handshake")
        buf += chunk
    return bytes(buf)


def _parse_response(head: bytes) -> _Response:
    lines = head.decode("latin-1").split("\r\n")
    parts = lines[0].split(" ", 2)
    if len(parts) < 2 or not parts[0].startswith("HTTP/") or not _ascii_digits(parts[1]):
        raise ConnectionError(f"malformed proxy response: {lines[0][:80]!r}")
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if not line:
            continue
        name, sep, value = line.partition(":")
        if sep:
            headers.append((name.strip().lower(), value.strip()))
    resp = _Response(int(parts[1]), parts[2] if len(parts) > 2 else "", headers)
    conn = (resp.get("proxy-connection") or resp.get("connection")).lower()
    resp.keepalive = conn != "close" and not (parts[0] == "HTTP/1.0" and conn != "keep-alive")
    return resp


def _discard_body(sock: socket.socket, resp: _Response) -> None:
    """Consume the body of a non-2xx response so the connection can carry
    the next auth leg. A response that cannot be framed ends keep-alive."""
    if resp.get("transfer-encoding").lower() == "chunked":
        total = 0
        while True:
            size_line = _read_line(sock)
            token = size_line.split(b";")[0].strip()
            if not _CHUNK_SIZE.fullmatch(token):
                raise ConnectionError(f"malformed chunk size in proxy response: {token[:40]!r}")
            size = int(token, 16)
            if size == 0:
                while _read_line(sock):  # trailers
                    pass
                return
            total += size
            if total > MAX_BUFFERED_BODY:
                resp.keepalive = False
                return
            _read_exact(sock, size + 2)
    length = resp.get("content-length")
    if _ascii_digits(length):
        n = int(length)
        if n > MAX_BUFFERED_BODY:
            resp.keepalive = False
            return
        _read_exact(sock, n)
        return
    # No framing: the body runs to EOF, so the connection is done.
    resp.keepalive = False


_CHUNK_SIZE = re.compile(rb"[0-9A-Fa-f]+")


def _ascii_digits(text: str) -> bool:
    """``str.isdigit()`` for ASCII only: it also accepts "²", which int()
    refuses, and other scripts' digits, which no HTTP number uses."""
    return text.isascii() and text.isdigit()


def _read_line(sock: socket.socket) -> bytes:
    buf = bytearray()
    while not buf.endswith(b"\r\n"):
        chunk = sock.recv(1)
        if not chunk:
            raise ConnectionError("connection closed while reading a proxy response")
        buf += chunk
        if len(buf) > 4096:
            raise ConnectionError("overlong line in proxy response")
    return bytes(buf[:-2])


def _read_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(min(65536, n - len(buf)))
        if not chunk:
            raise ConnectionError("connection closed while reading a proxy response body")
        buf += chunk
    return bytes(buf)


def _challenges(resp: _Response, scheme: str) -> list[bytes] | None:
    """Tokens of every ``Proxy-Authenticate: <scheme> [token]`` header, or
    ``None`` when the proxy does not offer *scheme* at all."""
    found: list[bytes] | None = None
    for value in resp.get_all("proxy-authenticate"):
        head, _, rest = value.strip().partition(" ")
        if head.lower() != scheme:
            continue
        found = found or []
        rest = rest.strip()
        try:
            found.append(base64.b64decode(rest, validate=True) if rest else b"")
        except ValueError:
            found.append(b"")
    return found


def _offered(resp: _Response) -> str:
    names = []
    for value in resp.get_all("proxy-authenticate"):
        names.append(value.strip().split(" ", 1)[0])
    return ", ".join(dict.fromkeys(names)) or "none"


# ---------------------------------------------------------------------------
# Connection to the proxy itself
# ---------------------------------------------------------------------------
def tls_context_for(ca_file: str = "") -> ssl.SSLContext:
    """Verifying context for the TLS leg to the proxy. A pinned *ca_file*
    replaces the system store (private corporate CA)."""
    ctx = ssl.create_default_context(cafile=ca_file or None)
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def connect_to_proxy(cfg, timeout: float) -> socket.socket:
    """TCP (and for ``https`` TLS) connection to the proxy host itself."""
    try:
        infos = socket.getaddrinfo(cfg.host, cfg.port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ConnectionError(f"Cannot resolve proxy host {cfg.host!r}: {exc}") from exc
    last: Exception | None = None
    sock: socket.socket | None = None
    for af, socktype, proto, _canon, sockaddr in infos:
        s = socket.socket(af, socktype, proto)
        try:
            s.settimeout(timeout)
            s.connect(sockaddr)
            sock = s
            break
        except OSError as exc:
            last = exc
            s.close()
    if sock is None:
        raise ConnectionError(f"Cannot connect to proxy {cfg.host}:{cfg.port}: {last}") from last
    if cfg.transport == "https":
        try:
            ctx = tls_context_for(cfg.ca_file)
            sock = ctx.wrap_socket(sock, server_hostname=cfg.host)
        except (ssl.SSLError, OSError) as exc:
            with contextlib.suppress(OSError):
                sock.close()
            raise ConnectionError(
                f"TLS to proxy {cfg.host}:{cfg.port} failed ({exc}). The proxy "
                "certificate must be valid for that name; for a private CA set "
                "the proxy CA file (Tools > Network & Proxy)."
            ) from exc
    return sock


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------
def effective_auth(cfg) -> str:
    """Auth scheme to use: explicit one, else Basic when a user is set."""
    return cfg.auth_scheme or ("basic" if cfg.username else "")


def _basic_value(cfg) -> str:
    return "Basic " + base64.b64encode(f"{cfg.username}:{cfg.password}".encode()).decode()


def _spnego_context(cfg, scheme: str):
    """pyspnego client context for NTLM / Negotiate / Kerberos."""
    try:
        import spnego
    except ImportError as exc:  # pragma: no cover - smbprotocol pulls it in
        raise ProxyAuthError(
            "NTLM / Negotiate proxy authentication needs the 'pyspnego' package."
        ) from exc
    protocol = {"ntlm": "ntlm", "negotiate": "negotiate", "kerberos": "kerberos"}[scheme]
    try:
        return spnego.client(
            cfg.username or None,
            cfg.password or None,
            hostname=cfg.host,
            service="HTTP",
            protocol=protocol,
        )
    except Exception as exc:  # noqa: BLE001 - provider errors vary widely
        raise ProxyAuthError(_spnego_hint(scheme, exc)) from exc


def _spnego_hint(scheme: str, exc: Exception) -> str:
    text = f"{scheme} proxy authentication could not start: {exc}."
    if scheme in ("negotiate", "kerberos"):
        text += (
            " Kerberos needs the optional 'gssapi' package and a valid ticket "
            "(kinit); without them only NTLM inside Negotiate is possible and "
            "only when a username and password are set."
        )
    return text


def _auth_header_value(scheme: str, token: bytes) -> str:
    name = "NTLM" if scheme == "ntlm" else "Negotiate"
    return f"{name} {base64.b64encode(token).decode()}"


def _challenge_name(scheme: str) -> str:
    return "ntlm" if scheme == "ntlm" else "negotiate"


def _token_step(ctx, scheme: str, token: bytes | None) -> bytes:
    try:
        out = ctx.step(token)
    except Exception as exc:  # noqa: BLE001 - SpnegoError and friends
        raise ProxyAuthError(f"{scheme} proxy authentication failed: {exc}") from exc
    return out or b""


# ---------------------------------------------------------------------------
# CONNECT client
# ---------------------------------------------------------------------------
def _format_target(host: str, port: int) -> str:
    try:
        socket.inet_pton(socket.AF_INET6, host)
        return f"[{host}]:{port}"
    except OSError:
        return f"{host}:{port}"


def _request_bytes(method: str, target: str, extra: list[tuple[str, str]]) -> bytes:
    lines = [f"{method} {target} HTTP/1.1"]
    lines.extend(f"{k}: {v}" for k, v in extra)
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")


def open_connect_tunnel(
    cfg,
    target_host: str,
    target_port: int,
    timeout: float = 10.0,
    family: int = socket.AF_UNSPEC,
) -> socket.socket:
    """Connected socket to ``target_host:target_port`` through an HTTP or
    HTTPS proxy, authenticated per ``cfg``. The proxy host is resolved by
    the caller's SSRF guard; the target is passed to the proxy as written
    (name resolution happens at the proxy)."""
    target = _format_target(target_host, target_port)
    sock = connect_to_proxy(cfg, timeout)
    try:
        _connect_handshake(sock, cfg, target)
        return sock
    except BaseException:
        with contextlib.suppress(OSError):
            sock.close()
        raise


def _connect_handshake(sock: socket.socket, cfg, target: str) -> None:
    scheme = effective_auth(cfg)
    base = [("Host", target), ("Proxy-Connection", "keep-alive")]

    def send(extra: list[tuple[str, str]]) -> _Response:
        sock.sendall(_request_bytes("CONNECT", target, base + extra))
        resp = _parse_response(_read_head(sock))
        if resp.status != 200:
            _discard_body(sock, resp)
        return resp

    if scheme in ("", "basic"):
        extra = [("Proxy-Authorization", _basic_value(cfg))] if scheme == "basic" else []
        resp = send(extra)
        _expect_ok(resp, scheme, cfg)
        return

    ctx = _spnego_context(cfg, scheme)
    name = _challenge_name(scheme)
    token = _token_step(ctx, scheme, None)
    resp = send([("Proxy-Authorization", _auth_header_value(scheme, token))])
    for _ in range(MAX_AUTH_ROUNDS):
        if resp.status == 200:
            _finish_mutual(ctx, resp, name)
            return
        if resp.status != 407:
            raise ConnectionError(f"HTTP CONNECT failed: {resp.status} {resp.reason}")
        offered = _challenges(resp, name)
        if offered is None:
            raise ProxyAuthError(
                f"proxy does not offer {scheme.upper()} authentication (offers: {_offered(resp)})"
            )
        if not resp.keepalive:
            raise ProxyAuthError(
                f"proxy closed the connection during {scheme.upper()} authentication; "
                "connection-oriented schemes need keep-alive"
            )
        challenge = offered[-1]
        if not challenge:
            # Bare "NTLM": the proxy restarts the handshake (previous token rejected).
            raise ProxyAuthError(f"{scheme.upper()} authentication was rejected by the proxy")
        reply = _token_step(ctx, scheme, challenge)
        resp = send([("Proxy-Authorization", _auth_header_value(scheme, reply))])
    raise ProxyAuthError(f"{scheme.upper()} authentication did not complete")


def _finish_mutual(ctx, resp: _Response, name: str) -> None:
    """Negotiate may return a final mutual-auth token with the 200."""
    if name != "negotiate":
        return
    tokens = _challenges(resp, name)
    if tokens and tokens[-1] and not getattr(ctx, "complete", True):
        with contextlib.suppress(Exception):
            ctx.step(tokens[-1])


def _expect_ok(resp: _Response, scheme: str, cfg) -> None:
    if resp.status == 200:
        return
    if resp.status == 407:
        if scheme == "basic":
            raise ProxyAuthError("proxy rejected the username / password (407)")
        raise ProxyAuthError(
            f"proxy requires authentication (offers: {_offered(resp)}); set the proxy "
            "username, password and authentication scheme"
        )
    raise ConnectionError(f"HTTP CONNECT failed: {resp.status} {resp.reason}")


# ---------------------------------------------------------------------------
# Loopback shim
# ---------------------------------------------------------------------------
def _split_authority(authority: str, default_port: int) -> tuple[str, int]:
    authority = authority.strip()
    if authority.startswith("["):
        host, _, rest = authority[1:].partition("]")
        port = rest.lstrip(":")
    else:
        host, _, port = authority.rpartition(":")
        if not host:
            host, port = authority, ""
    return host, int(port) if _ascii_digits(port) else default_port


class LocalProxyShim:
    """HTTP proxy on 127.0.0.1 that forwards through an arbitrary upstream
    :class:`core.proxy.ProxyConfig` (SOCKS, HTTPS, NTLM, ...)."""

    def __init__(self, upstream, timeout: float = 15.0, max_connections: int = 64) -> None:
        self._upstream = upstream
        self._timeout = timeout
        self._slots = threading.BoundedSemaphore(max_connections)
        self._listener: socket.socket | None = None
        self._closed = threading.Event()
        self._active: set[socket.socket] = set()
        self._lock = threading.Lock()
        self.host = "127.0.0.1"
        self.port = 0

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"

    # -- lifecycle ---------------------------------------------------------
    def start(self) -> "LocalProxyShim":
        from core import proxy as _proxy

        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind((self.host, 0))
        listener.listen(32)
        self.port = listener.getsockname()[1]
        self._listener = listener
        _proxy._register_shim_port(self.port, True)
        threading.Thread(target=self._accept_loop, name="axross-proxy-shim", daemon=True).start()
        return self

    def close(self) -> None:
        from core import proxy as _proxy

        self._closed.set()
        if self._listener is not None:
            with contextlib.suppress(OSError):
                self._listener.shutdown(socket.SHUT_RDWR)
            with contextlib.suppress(OSError):
                self._listener.close()
        _proxy._register_shim_port(self.port, False)
        with self._lock:
            active = list(self._active)
        for sock in active:
            with contextlib.suppress(OSError):
                sock.shutdown(socket.SHUT_RDWR)
            with contextlib.suppress(OSError):
                sock.close()

    # -- accept ------------------------------------------------------------
    def _accept_loop(self) -> None:
        from core import proxy as _proxy

        assert self._listener is not None
        while not self._closed.is_set():
            try:
                client, peer = self._listener.accept()
            except OSError:
                return
            if not _proxy._peer_is_same_user(peer, server=client.getsockname()[:2]):
                log.warning("proxy shim: dropped connection from foreign local user %s", peer)
                client.close()
                continue
            if not self._slots.acquire(blocking=False):
                client.close()
                continue
            threading.Thread(target=self._serve, args=(client,), daemon=True).start()

    def _track(self, sock: socket.socket, add: bool) -> None:
        with self._lock:
            (self._active.add if add else self._active.discard)(sock)

    # -- one client connection --------------------------------------------
    def _serve(self, client: socket.socket) -> None:
        upstream: socket.socket | None = None
        try:
            self._track(client, True)
            client.settimeout(30)
            head, leftover = self._read_request_head(client)
            if head is None:
                return
            request_line, headers = head
            method, target, _version = request_line
            if method.upper() == "CONNECT":
                upstream = self._connect_method(client, target, leftover)
            else:
                upstream = self._plain_method(client, request_line, headers, leftover)
            if upstream is None:
                return
            self._track(upstream, True)
            upstream.settimeout(None)
            client.settimeout(None)
            from core.proxy import relay_both

            relay_both(client, upstream)
        except Exception as exc:  # noqa: BLE001 - never let a client kill the thread noisily
            log.debug("proxy shim: connection ended: %s", exc)
        finally:
            for sock in (client, upstream):
                if sock is not None:
                    self._track(sock, False)
                    with contextlib.suppress(OSError):
                        sock.close()
            self._slots.release()

    @staticmethod
    def _read_request_head(client: socket.socket):
        buf = bytearray()
        while b"\r\n\r\n" not in buf:
            if len(buf) > MAX_HEADER_BYTES:
                LocalProxyShim._reply(client, 431, "Request Header Fields Too Large", "too large")
                return None, b""
            chunk = client.recv(4096)
            if not chunk:
                return None, b""
            buf += chunk
        head, _, leftover = bytes(buf).partition(b"\r\n\r\n")
        lines = head.decode("latin-1").split("\r\n")
        parts = lines[0].split(" ")
        if len(parts) != 3:
            LocalProxyShim._reply(client, 400, "Bad Request", "malformed request line")
            return None, b""
        headers: list[tuple[str, str]] = []
        for line in lines[1:]:
            name, sep, value = line.partition(":")
            if sep:
                headers.append((name.strip(), value.strip()))
        return ((parts[0], parts[1], parts[2]), headers), leftover

    @staticmethod
    def _reply(client: socket.socket, code: int, reason: str, body: str) -> None:
        payload = body.encode("utf-8", errors="replace")
        msg = (
            f"HTTP/1.1 {code} {reason}\r\nContent-Type: text/plain; charset=utf-8\r\n"
            f"Content-Length: {len(payload)}\r\nConnection: close\r\n\r\n"
        ).encode("latin-1") + payload
        with contextlib.suppress(OSError):
            client.sendall(msg)

    def _open_upstream(self, host: str, port: int) -> socket.socket:
        from core.proxy import _validate_endpoint_host, create_proxy_socket

        _validate_endpoint_host(host, "Target host")
        return create_proxy_socket(self._upstream, host, port, timeout=self._timeout)

    def _connect_method(self, client, target: str, leftover: bytes):
        host, port = _split_authority(target, 443)
        try:
            upstream = self._open_upstream(host, port)
        except (OSError, ValueError) as exc:
            # 502, not 407: the client must not think it has to authenticate
            # to the local shim; the cause is in the body.
            self._reply(client, 502, "Bad Gateway", f"axross proxy: {exc}")
            return None
        client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        if leftover:
            upstream.sendall(leftover)
        return upstream

    def _plain_method(self, client, request_line, headers, leftover: bytes):
        method, target, _version = request_line
        parts = urlsplit(target)
        if parts.scheme.lower() != "http" or not parts.hostname:
            self._reply(client, 400, "Bad Request", "only absolute http:// URIs are proxied")
            return None
        host, port = parts.hostname, parts.port or 80
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        fwd = [(k, v) for k, v in headers if k.lower() not in _HOP_BY_HOP]
        if not any(k.lower() == "host" for k, _ in fwd):
            fwd.insert(0, ("Host", parts.netloc.rsplit("@", 1)[-1]))
        body_len = 0
        for k, v in headers:
            if k.lower() == "content-length" and _ascii_digits(v):
                body_len = int(v)
        if any(k.lower() == "transfer-encoding" for k, _ in headers):
            self._reply(client, 501, "Not Implemented", "chunked request bodies are not supported")
            return None
        try:
            if self._upstream.transport in ("http", "https"):
                return self._via_http_proxy(client, method, target, fwd, body_len, leftover)
            upstream = self._open_upstream(host, port)
        except (OSError, ValueError) as exc:
            self._reply(client, 502, "Bad Gateway", f"axross proxy: {exc}")
            return None
        # Origin-form to the origin server; one request per connection.
        fwd.append(("Connection", "close"))
        upstream.sendall(_request_bytes(method, path, fwd))
        if leftover:
            upstream.sendall(leftover)
        return upstream

    def _via_http_proxy(self, client, method, target, fwd, body_len: int, leftover: bytes):
        """Plain-HTTP request through an HTTP(S) upstream proxy, doing the
        auth handshake on the real request (CONNECT to port 80 is usually
        forbidden by proxy policy). Returns the authenticated upstream
        socket; the caller relays everything that follows."""
        from core.proxy import _assert_proxy_host_not_private

        cfg = self._upstream
        _assert_proxy_host_not_private(cfg.host, cfg.port)
        scheme = effective_auth(cfg)
        if body_len > MAX_BUFFERED_BODY:
            raise ConnectionError("request body too large for an authenticated proxy")
        body = leftover
        client.settimeout(30)
        while len(body) < body_len:
            chunk = client.recv(min(65536, body_len - len(body)))
            if not chunk:
                raise ConnectionError("client closed before sending the full request body")
            body += chunk
        body, pipelined = body[:body_len], body[body_len:]
        base = [(k, v) for k, v in fwd if k.lower() != "content-length"]
        has_body = body_len > 0 or method.upper() in ("POST", "PUT", "PATCH")

        def request(extra: list[tuple[str, str]], with_body: bool) -> bytes:
            hdrs = base + extra
            if has_body:
                hdrs = hdrs + [("Content-Length", str(len(body) if with_body else 0))]
            return _request_bytes(method, target, hdrs) + (body if with_body else b"")

        sock = connect_to_proxy(cfg, self._timeout)
        try:
            if scheme in ("", "basic"):
                # One request per upstream connection. The relay that follows
                # is raw bytes, so a second request the client sent on a
                # kept-alive connection would reach the proxy without the
                # Proxy-Authorization header. With "close" the client opens
                # a new connection, and that one is authenticated again;
                # pipelined bytes are dropped for the same reason.
                extra = [("Proxy-Authorization", _basic_value(cfg))] if scheme == "basic" else []
                close = [("Connection", "close"), ("Proxy-Connection", "close")]
                sock.sendall(request(extra + close, True))
                return sock
            ctx = _spnego_context(cfg, scheme)
            name = _challenge_name(scheme)
            keep = [("Proxy-Connection", "keep-alive")]
            token = _token_step(ctx, scheme, None)
            for rnd in range(MAX_AUTH_ROUNDS):
                auth = [("Proxy-Authorization", _auth_header_value(scheme, token))]
                # NTLM's first leg carries no body (the proxy answers 407 either
                # way); every other leg is a complete request.
                with_body = scheme != "ntlm" or rnd > 0
                sock.sendall(request(keep + auth, with_body))
                resp = _parse_response(_read_head(sock))
                if resp.status != 407:
                    client.sendall(_serialize_status(resp))  # body follows via the relay
                    if pipelined:
                        sock.sendall(pipelined)
                    return sock
                _discard_body(sock, resp)
                offered = _challenges(resp, name)
                if offered is None:
                    raise ProxyAuthError(
                        f"proxy does not offer {scheme.upper()} (offers: {_offered(resp)})"
                    )
                if not offered[-1]:
                    raise ProxyAuthError(f"{scheme.upper()} authentication was rejected")
                if not resp.keepalive:
                    raise ProxyAuthError(
                        f"proxy closed the connection during {scheme.upper()} authentication"
                    )
                token = _token_step(ctx, scheme, offered[-1])
            raise ProxyAuthError(f"{scheme.upper()} authentication did not complete")
        except BaseException:
            with contextlib.suppress(OSError):
                sock.close()
            raise


def _serialize_status(resp: _Response) -> bytes:
    """Re-emit a response whose head we already consumed (body follows on
    the upstream socket the caller relays next)."""
    lines = [f"HTTP/1.1 {resp.status} {resp.reason}"]
    lines.extend(f"{k}: {v}" for k, v in resp.headers)
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")


# ---------------------------------------------------------------------------
# Shim registry
# ---------------------------------------------------------------------------
_SHIMS: dict[tuple, LocalProxyShim] = {}
_SHIMS_LOCK = threading.Lock()


def shim_for(cfg) -> LocalProxyShim:
    """Process-wide shim for *cfg* (started on first use)."""
    from core.proxy import _assert_proxy_host_not_private, _validate_proxy_url_host

    _validate_proxy_url_host(cfg.host)
    _assert_proxy_host_not_private(cfg.host, cfg.port)
    key = (cfg.proxy_type, cfg.host, int(cfg.port), cfg.username, cfg.password, cfg.ca_file)
    with _SHIMS_LOCK:
        shim = _SHIMS.get(key)
        if shim is None or shim._closed.is_set():
            shim = LocalProxyShim(cfg).start()
            _SHIMS[key] = shim
        return shim


def close_all_shims() -> None:
    with _SHIMS_LOCK:
        shims = list(_SHIMS.values())
        _SHIMS.clear()
    for shim in shims:
        shim.close()


atexit.register(close_all_shims)
