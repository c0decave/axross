"""Fake HTTP / HTTPS forward proxies for the proxy tests.

``FakeHttpProxy`` speaks CONNECT and absolute-form requests, optionally
over TLS, and can demand Basic, NTLM or Negotiate authentication. NTLM and
Negotiate are verified by pyspnego's *server* implementation, so a client
that sends a wrong password or a malformed message is really rejected.
"""

from __future__ import annotations

import base64
import datetime as dt
import os
import socket
import ssl
import tempfile
import threading
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


# ---------------------------------------------------------------------------
# Certificates
# ---------------------------------------------------------------------------
class TestPki:
    """One CA and any number of server certificates, written to a temp dir."""

    __test__ = False  # not a pytest class

    def __init__(self) -> None:
        self.dir = Path(tempfile.mkdtemp(prefix="axross-pki-"))
        self._ca_key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "axross test CA")])
        now = dt.datetime.now(dt.timezone.utc)
        self._ca = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(self._ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(self._ca_key.public_key()),
                critical=False,
            )
            .sign(self._ca_key, hashes.SHA256())
        )
        self.ca_file = str(self.dir / "ca.pem")
        Path(self.ca_file).write_bytes(self._ca.public_bytes(serialization.Encoding.PEM))

    def issue(self, *names: str, days: int = 30) -> tuple[str, str]:
        """(cert_file, key_file) valid for the given DNS names / IPs."""
        import ipaddress

        key = ec.generate_private_key(ec.SECP256R1())
        sans = []
        for n in names:
            try:
                sans.append(x509.IPAddress(ipaddress.ip_address(n)))
            except ValueError:
                sans.append(x509.DNSName(n))
        now = dt.datetime.now(dt.timezone.utc)
        # A negative *days* issues an already expired certificate.
        start = now - dt.timedelta(days=10 if days < 0 else 1)
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])]))
            .issuer_name(self._ca.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(start)
            .not_valid_after(now + dt.timedelta(days=days))
            .add_extension(x509.SubjectAlternativeName(sans), critical=False)
            .add_extension(
                x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self._ca_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
            )
            .sign(self._ca_key, hashes.SHA256())
        )
        stem = f"srv-{len(list(self.dir.glob('srv-*.pem')))}"
        cert_file = str(self.dir / f"{stem}.pem")
        key_file = str(self.dir / f"{stem}.key")
        Path(cert_file).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        Path(key_file).write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        return cert_file, key_file


# ---------------------------------------------------------------------------
# NTLM credential store for pyspnego's server side
# ---------------------------------------------------------------------------
def install_ntlm_users(users: dict[str, str], domain: str = "DOM") -> str:
    """Point ``NTLM_USER_FILE`` at a store holding *users*; returns the path."""
    f = tempfile.NamedTemporaryFile("w", suffix=".ntlm", delete=False)
    for user, password in users.items():
        f.write(f"{domain}:{user}:{password}\n")
    f.close()
    os.environ["NTLM_USER_FILE"] = f.name
    return f.name


# ---------------------------------------------------------------------------
# Proxy
# ---------------------------------------------------------------------------
def _read_head(conn: socket.socket) -> bytes | None:
    buf = bytearray()
    while b"\r\n\r\n" not in buf:
        chunk = conn.recv(4096)
        if not chunk:
            return None
        buf += chunk
        if len(buf) > 65536:
            return None
    return bytes(buf)


class FakeHttpProxy:
    """Forward proxy on loopback.

    ``auth``: ``None`` (open), ``"basic"``, ``"ntlm"`` or ``"negotiate"``.
    ``routes`` maps ``(host, port)`` as asked in CONNECT to a real loopback
    endpoint. ``tls=(cert_file, key_file)`` makes it an HTTPS proxy.
    """

    def __init__(
        self,
        routes: dict | None = None,
        *,
        auth: str | None = None,
        users: dict[str, str] | None = None,
        tls: tuple[str, str] | None = None,
        offer: tuple[str, ...] | None = None,
        close_after_407: bool = False,
    ) -> None:
        self.routes = dict(routes or {})
        self.auth = auth
        self.users = dict(users or {"alice": "s3cret"})
        self.offer = offer  # override the schemes advertised in 407
        self.close_after_407 = close_after_407
        self.connects: list[str] = []  # CONNECT authorities that were allowed
        self.plain_requests: list[tuple[str, str]] = []  # (method, absolute target)
        self.denied = 0
        self.legs: list[str] = []  # Proxy-Authorization scheme names seen, in order
        self._ctx: ssl.SSLContext | None = None
        if tls:
            self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self._ctx.load_cert_chain(*tls)
        if auth in ("ntlm", "negotiate"):
            install_ntlm_users(self.users)
        self._listener = socket.socket()
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(16)
        self.port = self._listener.getsockname()[1]
        self._stop = threading.Event()
        threading.Thread(target=self._serve, daemon=True).start()

    # -- lifecycle ---------------------------------------------------------
    def close(self) -> None:
        self._stop.set()
        try:
            self._listener.close()
        except OSError:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # -- serving -----------------------------------------------------------
    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                raw, _ = self._listener.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(raw,), daemon=True).start()

    def _handle(self, raw: socket.socket) -> None:
        conn = raw
        try:
            if self._ctx is not None:
                conn = self._ctx.wrap_socket(raw, server_side=True)
            conn.settimeout(10)
            state: dict = {}
            while True:
                head = _read_head(conn)
                if head is None:
                    return
                if self._request(conn, head, state):
                    return
        except (OSError, ssl.SSLError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    @staticmethod
    def _headers(head: bytes) -> tuple[list[str], dict[str, str]]:
        lines = head.split(b"\r\n\r\n", 1)[0].decode("latin-1").split("\r\n")
        hdrs: dict[str, str] = {}
        for line in lines[1:]:
            name, _, value = line.partition(":")
            hdrs[name.strip().lower()] = value.strip()
        return lines, hdrs

    def _challenge(self, conn, scheme_offers: list[str], extra: str = "") -> None:
        body = b"proxy authentication required"
        lines = ["HTTP/1.1 407 Proxy Authentication Required"]
        for offer in scheme_offers:
            lines.append(f"Proxy-Authenticate: {offer}")
        lines += [
            "Proxy-Connection: close" if self.close_after_407 else "Proxy-Connection: keep-alive",
            f"Content-Length: {len(body)}",
            "",
            "",
        ]
        conn.sendall("\r\n".join(lines).encode("latin-1") + body)
        self.denied += 1

    def _authorised(self, conn, hdrs: dict[str, str], state: dict) -> bool:
        """True when the request may proceed; otherwise a 407 was sent."""
        header = hdrs.get("proxy-authorization", "")
        scheme, _, rest = header.partition(" ")
        if scheme:
            self.legs.append(scheme.lower())
        if self.auth is None:
            return True
        if self.auth == "basic":
            want = base64.b64encode(f"alice:{self.users['alice']}".encode()).decode()
            if scheme.lower() == "basic" and rest.strip() == want:
                return True
            self._challenge(conn, list(self.offer or ('Basic realm="axross"',)))
            return False
        # ntlm / negotiate: connection-oriented, state lives on the socket.
        name = "NTLM" if self.auth == "ntlm" else "Negotiate"
        offers = list(self.offer or (name,))
        if state.get("authed"):
            return True
        if scheme.lower() != name.lower():
            self._challenge(conn, offers)
            return False
        import spnego

        try:
            ctx = state.get("ctx") or spnego.server(
                protocol="ntlm" if self.auth == "ntlm" else "negotiate"
            )
            state["ctx"] = ctx
            out = ctx.step(base64.b64decode(rest))
        except Exception:  # noqa: BLE001 - bad token / wrong password
            state.pop("ctx", None)
            self._challenge(conn, offers)
            return False
        if ctx.complete:
            state["authed"] = True
            return True
        self._challenge(conn, [f"{name} {base64.b64encode(out or b'').decode()}"])
        return False

    def _request(self, conn, head: bytes, state: dict) -> bool:
        """Handle one request; True when the connection is finished."""
        lines, hdrs = self._headers(head)
        method, target, _version = lines[0].split(" ", 2)
        if not self._authorised(conn, hdrs, state):
            return self.close_after_407
        if method.upper() == "CONNECT":
            host, _, port = target.rpartition(":")
            host = host.strip("[]")
            real = self.routes.get((host, int(port)))
            if real is None:
                conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                return True
            self.connects.append(target)
            upstream = socket.create_connection(real, timeout=5)
            conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            self._relay(conn, upstream)
            return True
        # absolute-form request
        self.plain_requests.append((method, target))
        from urllib.parse import urlsplit

        parts = urlsplit(target)
        real = self.routes.get((parts.hostname, parts.port or 80))
        if real is None:
            conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            return True
        upstream = socket.create_connection(real, timeout=5)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        header_block, _, body = head.partition(b"\r\n\r\n")
        rest = header_block.split(b"\r\n", 1)[1]
        kept = [
            line
            for line in rest.split(b"\r\n")
            if not line.lower().startswith((b"proxy-", b"connection:"))
        ]
        upstream.sendall(
            f"{method} {path} HTTP/1.1\r\n".encode()
            + b"\r\n".join(kept)
            + b"\r\nConnection: close\r\n\r\n"
            + body
        )
        # Collect the rest of a request body announced by Content-Length.
        want = int(hdrs.get("content-length", "0") or 0)
        got = len(body)
        while got < want:
            chunk = conn.recv(65536)
            if not chunk:
                break
            upstream.sendall(chunk)
            got += len(chunk)
        self._relay(conn, upstream, one_way=True)
        return True

    @staticmethod
    def _relay(a: socket.socket, b: socket.socket, one_way: bool = False) -> None:
        done = threading.Event()

        def pump(src, dst):
            try:
                while True:
                    data = src.recv(65536)
                    if not data:
                        break
                    dst.sendall(data)
            except (OSError, ssl.SSLError):
                pass
            finally:
                done.set()

        threading.Thread(target=pump, args=(b, a), daemon=True).start()
        if not one_way:
            threading.Thread(target=pump, args=(a, b), daemon=True).start()
        done.wait(30)
        for s in (a, b):
            try:
                s.close()
            except OSError:
                pass


class OriginHttpServer:
    """Plain HTTP origin that echoes method, path and body as JSON-ish text."""

    def __init__(self) -> None:
        self.requests: list[tuple[str, str, bytes]] = []
        self._listener = socket.socket()
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(16)
        self.port = self._listener.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        while True:
            try:
                conn, _ = self._listener.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        try:
            head = _read_head(conn)
            if head is None:
                return
            header_block, _, body = head.partition(b"\r\n\r\n")
            first = header_block.split(b"\r\n")[0].decode().split(" ")
            hdrs = {
                k.strip().lower(): v.strip()
                for k, _, v in (
                    line.decode("latin-1").partition(":")
                    for line in header_block.split(b"\r\n")[1:]
                )
            }
            want = int(hdrs.get("content-length", "0") or 0)
            while len(body) < want:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                body += chunk
            self.requests.append((first[0], first[1], body))
            payload = f"{first[0]} {first[1]} {len(body)}".encode()
            conn.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: "
                + str(len(payload)).encode()
                + b"\r\nConnection: close\r\n\r\n"
                + payload
            )
        except OSError:
            pass
        finally:
            conn.close()

    def close(self) -> None:
        self._listener.close()
