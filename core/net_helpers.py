"""Generic network + search helpers re-exported as ``axross.*``.

This is the "Tier 2" surface from docs/API_GAPS.md (slice 2). Each
helper is small, has no per-backend coupling, and uses libraries
already in the axross dep set (stdlib + cryptography + requests +
paramiko + dnspython).

Design notes:

* Every helper has a hard timeout default in the single-digit-seconds
  range. A REPL user typing ``axross.dns_records('example.com')``
  should never hang the prompt.
* Every helper that returns bytes/text caps the size — the user can
  pass a larger cap explicitly. Defaults are generous (1 MiB / 10 MiB).
* Every helper raises a built-in exception on failure (``OSError``,
  ``TimeoutError``, ``ValueError``) — no axross-private exception
  types in the user-facing API.
* Where a helper *probes* (port scan, banner grab) it MUST distinguish
  ``definitely-closed`` from ``filtered/timeout`` so the user can
  make policy decisions.
"""
from __future__ import annotations

import concurrent.futures
import difflib
import fnmatch
import hashlib
import ipaddress
import logging
import os
import re
import socket
import ssl
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Iterable, Iterator

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Banner / TCP probes
# ---------------------------------------------------------------------------


def tcp_banner(host: str, port: int, *, timeout: float = 3.0,
               max_bytes: int = 4096, send: bytes | None = None) -> bytes:
    """Connect to ``host:port`` and read up to ``max_bytes`` of the
    server's initial response. Useful for service-ID probes (SSH,
    FTP, SMTP, IMAP all greet with a banner).

    ``send`` is an optional payload to send first — needed for HTTP
    (``b"HEAD / HTTP/1.0\\r\\n\\r\\n"``) and other protocols that
    don't speak first.

    Raises ``OSError`` (incl. ``TimeoutError`` subclass) on connect or
    read failure. Returns ``b""`` if the server accepts the connection
    but sends no bytes within the timeout.
    """
    with socket.create_connection((host, int(port)), timeout=timeout) as sock:
        sock.settimeout(timeout)
        if send:
            try:
                sock.sendall(send)
            except OSError:
                return b""
        out = bytearray()
        deadline = time.monotonic() + timeout
        while len(out) < max_bytes and time.monotonic() < deadline:
            try:
                chunk = sock.recv(min(4096, max_bytes - len(out)))
            except (TimeoutError, socket.timeout):
                break
            if not chunk:
                break
            out.extend(chunk)
        return bytes(out)


@dataclass(frozen=True)
class PingResult:
    """Outcome of a TCP-ping. ``rtt_ms`` is ``None`` when the host
    didn't accept the connection within the timeout; otherwise it's
    the round-trip in milliseconds (connect-only, no full TLS/TCP
    handshake)."""
    host: str
    port: int
    reachable: bool
    rtt_ms: float | None


def ping(host: str, *, port: int = 80,
         timeout: float = 3.0,
         count: int = 1) -> list[PingResult]:
    """TCP-based reachability probe — connect to ``host:port`` and
    measure RTT. Returns one ``PingResult`` per ``count`` attempt.

    Why TCP and not ICMP: ICMP raw sockets need CAP_NET_RAW (root
    on Linux). A TCP-connect to a known-listening port is the
    standard "no-privileges" reachability probe and works through
    most firewalls that pass HTTP/HTTPS but drop ICMP.

    ``port`` defaults to 80 — adjust to the service the host is
    expected to run (22 for SSH boxes, 443 for web, 53 for DNS,
    389 for LDAP, …). The probe never sends any application data;
    the connect is closed cleanly the moment the 3-way handshake
    completes.

    ``count`` lets a script gather a few samples to spot variance
    without rolling its own loop. Returns one ``PingResult`` per
    attempt, in attempt order.
    """
    out: list[PingResult] = []
    for _ in range(int(count)):
        start = time.monotonic()
        try:
            with socket.create_connection((host, int(port)),
                                          timeout=float(timeout)):
                rtt_ms = (time.monotonic() - start) * 1000.0
                out.append(PingResult(
                    host=host, port=int(port),
                    reachable=True, rtt_ms=rtt_ms,
                ))
        except OSError:
            out.append(PingResult(
                host=host, port=int(port),
                reachable=False, rtt_ms=None,
            ))
    return out


def port_open(host: str, port: int, *, timeout: float = 3.0) -> bool:
    """True iff a TCP connect to ``host:port`` succeeds within
    ``timeout`` seconds. Pure stdlib — no privileges needed.

    NOTE: this is a duplicate of the helper in core.scripting; it
    lives here so ``port_scan`` can call it without an import cycle.
    """
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except OSError:
        return False


_PORT_SCAN_MAX_CONCURRENCY = 1024


def port_scan(host: str, ports: Iterable[int], *, timeout: float = 1.0,
              concurrency: int = 64) -> list[int]:
    """Concurrent TCP-connect scan. Returns the sorted list of
    ports that accepted a connection within ``timeout``.

    ``concurrency`` caps the number of in-flight connects so we
    don't trip per-host conntrack limits or open thousands of FDs.
    Default 64 is friendly for any modern Linux box; hard ceiling
    is ``_PORT_SCAN_MAX_CONCURRENCY`` (1024) — anything above that
    would blow through ``ulimit -n`` and fail in confusing ways.
    F37.

    Use a generator for huge port ranges::

        axross.port_scan(\"10.0.0.1\", range(1, 65536), concurrency=128)
    """
    if concurrency < 1:
        raise ValueError("port_scan: concurrency must be >= 1")
    if concurrency > _PORT_SCAN_MAX_CONCURRENCY:
        raise ValueError(
            f"port_scan: concurrency capped at {_PORT_SCAN_MAX_CONCURRENCY} "
            f"(would blow through ulimit -n; got {concurrency})"
        )
    port_list = sorted({int(p) for p in ports})
    open_ports: list[int] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = {
            pool.submit(port_open, host, p, timeout=timeout): p
            for p in port_list
        }
        for fut in concurrent.futures.as_completed(futures):
            if fut.result():
                open_ports.append(futures[fut])
    return sorted(open_ports)


# ---------------------------------------------------------------------------
# TLS / SSH host-key inspection
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TlsCert:
    """Parsed peer certificate. ``raw_der`` is the binary DER blob
    so callers can re-parse with their own tooling if needed."""
    subject: str
    issuer: str
    san: list[str]
    not_before: datetime
    not_after: datetime
    serial: int
    sha256: str
    raw_der: bytes


def tls_cert(host: str, port: int = 443, *, timeout: float = 5.0,
             sni: str | None = None,
             verify: bool = False) -> TlsCert:
    """TLS handshake against ``host:port`` and return the parsed
    leaf certificate.

    ``sni`` defaults to ``host`` so virtual-hosted servers return the
    right cert. Pass ``sni=""`` to disable SNI.

    ``verify=False`` (the default) means we accept self-signed and
    expired certs — this helper is for INSPECTION (the user wants to
    see what's there), not for authenticated connection. Set
    ``verify=True`` and the system trust-store applies.

    Raises ``OSError`` on connect failure, ``ssl.SSLError`` on
    handshake failure.
    """
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    server_hostname = sni if sni is not None else host
    with socket.create_connection((host, int(port)), timeout=timeout) as raw:
        raw.settimeout(timeout)
        with ctx.wrap_socket(raw, server_hostname=server_hostname or None) as tls:
            der = tls.getpeercert(binary_form=True) or b""
    if not der:
        raise OSError(f"TLS handshake to {host}:{port} returned no peer cert")
    return _parse_der(der)


def _parse_der(der: bytes) -> TlsCert:
    """Parse a DER-encoded X.509 cert. Uses ``cryptography`` (already
    in the axross dep set)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    cert = x509.load_der_x509_certificate(der)
    # Subject + Issuer as RFC 2253 strings
    try:
        subject = cert.subject.rfc4514_string()
    except Exception:  # noqa: BLE001
        subject = ""
    try:
        issuer = cert.issuer.rfc4514_string()
    except Exception:  # noqa: BLE001
        issuer = ""
    san: list[str] = []
    try:
        ext = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName,
        )
        for n in ext.value:
            san.append(str(n.value))
    except x509.ExtensionNotFound:
        pass
    sha256 = cert.fingerprint(hashes.SHA256()).hex()
    return TlsCert(
        subject=subject,
        issuer=issuer,
        san=san,
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
        serial=cert.serial_number,
        sha256=sha256,
        raw_der=der,
    )


@dataclass(frozen=True)
class SshHostKey:
    """SSH host key as returned by paramiko's transport handshake.
    ``key_type`` is paramiko's name (``ssh-ed25519``, ``ssh-rsa``,
    ``ecdsa-sha2-nistp256`` …). ``fingerprint_sha256`` is the standard
    base64 form OpenSSH's ``ssh-keygen -l`` prints."""
    host: str
    port: int
    key_type: str
    fingerprint_sha256: str
    fingerprint_md5: str
    raw: bytes


def ssh_hostkey(host: str, port: int = 22, *, timeout: float = 5.0) -> SshHostKey:
    """Connect, complete the SSH KEX, fetch the server's host key
    and return its fingerprints. NO authentication is attempted.

    Raises ``OSError`` on connect, ``paramiko.SSHException`` on KEX
    failure.
    """
    import base64
    import paramiko
    sock = socket.create_connection((host, int(port)), timeout=timeout)
    try:
        t = paramiko.Transport(sock)
        try:
            t.start_client(timeout=timeout)
            key = t.get_remote_server_key()
        finally:
            try:
                t.close()
            except Exception:  # noqa: BLE001
                pass
    finally:
        try:
            sock.close()
        except OSError:
            pass
    raw = key.asbytes()
    sha256 = base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")
    md5 = hashlib.md5(raw).hexdigest()
    md5_colons = ":".join(md5[i:i + 2] for i in range(0, len(md5), 2))
    return SshHostKey(
        host=host, port=int(port),
        key_type=key.get_name(),
        fingerprint_sha256=f"SHA256:{sha256}",
        fingerprint_md5=f"MD5:{md5_colons}",
        raw=raw,
    )


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------


def dns_records(name: str, rtype: str = "A", *,
                resolver: str | None = None,
                timeout: float = 3.0) -> list[str]:
    """Return DNS records of ``rtype`` for ``name``. Uses ``dnspython``
    so we get TXT/MX/SRV/CAA/NAPTR records in addition to the basic
    A / AAAA / CNAME / NS / PTR.

    ``resolver`` is an optional DNS server IP — falls back to system
    resolvers when ``None``.

    Returned values are textual: ``["1.2.3.4"]`` for A, ``["10 mail.x"]``
    for MX, etc. — already formatted, so the caller doesn't need to
    know the rdata structure.
    """
    try:
        import dns.resolver  # type: ignore
    except ImportError as exc:
        raise OSError(
            "dns_records requires dnspython — install with "
            "`pip install dnspython` (or via the axross[dns] extra)"
        ) from exc
    res = dns.resolver.Resolver()
    if resolver:
        res.nameservers = [resolver]
    res.lifetime = float(timeout)
    res.timeout = float(timeout)
    try:
        answers = res.resolve(name, rtype.upper())
    except dns.resolver.NoAnswer:
        return []
    except dns.resolver.NXDOMAIN:
        return []
    return [r.to_text() for r in answers]


def dns_reverse(ip: str, *, resolver: str | None = None,
                timeout: float = 3.0) -> list[str]:
    """PTR lookup for an IP. Returns a list (most addresses have at
    most one PTR but the protocol allows multiple)."""
    try:
        import dns.resolver  # type: ignore
        import dns.reversename  # type: ignore
    except ImportError as exc:
        raise OSError(
            "dns_reverse requires dnspython — install with "
            "`pip install dnspython`"
        ) from exc
    rev = dns.reversename.from_address(ip)
    res = dns.resolver.Resolver()
    if resolver:
        res.nameservers = [resolver]
    res.lifetime = float(timeout)
    res.timeout = float(timeout)
    try:
        answers = res.resolve(rev, "PTR")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return []
    return [r.to_text() for r in answers]


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------


def _streaming_gunzip_partial(data: bytes) -> bytes:
    """Decompress as much of a gzip stream as possible without
    requiring an EOF marker. Used by :func:`http_probe` when
    ``raw_cap`` clipped the wire bytes mid-stream — the gzip-bomb
    guard. Returns whatever the decompressor produced; no exception
    when the trailer is missing."""
    import zlib
    # gzip stream uses zlib with a 32-byte gzip header; ``wbits=31``
    # tells zlib to expect that header.
    decomp = zlib.decompressobj(31)
    try:
        return decomp.decompress(data) + decomp.flush()
    except zlib.error:
        return b""


@dataclass(frozen=True)
class HttpProbe:
    """Result of an :func:`http_probe` call. ``redirect_chain`` lists
    every URL we were redirected through (incl. the original); ``cert``
    is non-None for HTTPS responses."""
    status: int
    url: str
    headers: dict[str, str]
    body: bytes
    truncated: bool
    redirect_chain: list[str]
    cert: TlsCert | None


def http_probe(url: str, *, method: str = "GET",
               headers: dict[str, str] | None = None,
               body: bytes | str | None = None,
               timeout: float = 10.0,
               allow_redirects: bool = True,
               body_cap: int = 1024 * 1024,
               raw_cap: int | None = None,
               verify: bool = True) -> HttpProbe:
    """Lightweight HTTP/HTTPS probe via ``requests``. Returns the
    response status, headers, body (up to ``body_cap``), redirect
    chain, and the TLS leaf cert when applicable.

    Why not raw ``requests.request`` — this helper sets sane defaults
    (timeout, body cap, captures redirect chain), and unconditionally
    parses the TLS cert via ``tls_cert`` so a script can audit a
    deployment without two round-trips.

    ``verify=True`` honours the system trust-store. Set False to
    inspect a self-signed cert (the cert info is still returned).

    F36: ``body_cap`` clips the DECODED body. A hostile gzip-encoded
    response can amplify ~1000x — a 1 KiB compressed payload can
    decode to >1 GiB, blowing through ``body_cap`` long after the
    raw stream has eaten our memory budget. ``raw_cap`` caps the
    on-the-wire bytes BEFORE decompression; defaults to
    ``max(body_cap * 4, 8 MiB)`` which is generous for legitimate
    Content-Encoding ratios but stops a real bomb.
    """
    import requests
    from urllib.parse import urlparse
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"http_probe: unsupported scheme {parsed.scheme!r}")
    if raw_cap is None:
        raw_cap = max(body_cap * 4, 8 * 1024 * 1024)
    resp = requests.request(
        method.upper(), url,
        headers=headers,
        data=body,
        timeout=timeout,
        allow_redirects=allow_redirects,
        verify=verify,
        stream=True,
    )
    # Read raw (encoded) bytes first with a hard cap, then decode in
    # memory. This way a gzip-bomb response can't exhaust memory just
    # because the decoded body would have crossed body_cap eventually.
    raw_compressed = resp.raw.read(raw_cap + 1, decode_content=False)
    raw_truncated = len(raw_compressed) > raw_cap
    raw_compressed = raw_compressed[:raw_cap]
    encoding = resp.headers.get("Content-Encoding", "").lower()
    if encoding == "gzip":
        import gzip
        try:
            decoded = gzip.decompress(raw_compressed)
        except (OSError, EOFError):
            # Truncated by raw_cap → no clean EOF marker. Return what
            # decompresses incrementally rather than raising; we
            # still flag truncation below.
            decoded = _streaming_gunzip_partial(raw_compressed)
    elif encoding == "deflate":
        import zlib
        try:
            decoded = zlib.decompress(raw_compressed)
        except zlib.error:
            try:
                decoded = zlib.decompress(raw_compressed, -zlib.MAX_WBITS)
            except zlib.error:
                decoded = raw_compressed
    elif encoding == "br":
        try:
            import brotli  # type: ignore
            decoded = brotli.decompress(raw_compressed)
        except Exception:  # noqa: BLE001
            decoded = raw_compressed
    else:
        decoded = raw_compressed
    truncated = len(decoded) > body_cap or raw_truncated
    body_bytes = bytes(decoded[:body_cap])
    chain = [r.url for r in resp.history] + [resp.url]
    cert: TlsCert | None = None
    if parsed.scheme == "https":
        try:
            host = urlparse(resp.url).hostname or parsed.hostname
            port = urlparse(resp.url).port or 443
            cert = tls_cert(host, port, sni=host, verify=False)
        except Exception as exc:  # noqa: BLE001
            log.debug("tls_cert side-fetch failed for %s: %s", resp.url, exc)
    return HttpProbe(
        status=resp.status_code,
        url=resp.url,
        headers={k: v for k, v in resp.headers.items()},
        body=body_bytes,
        truncated=truncated,
        redirect_chain=chain,
        cert=cert,
    )


# ---------------------------------------------------------------------------
# Subnet / address arithmetic
# ---------------------------------------------------------------------------


def subnet_hosts(cidr: str) -> list[str]:
    """Iterate every usable host in ``cidr`` (e.g. ``"10.0.0.0/29"``).
    Returns a list of IP strings — for /29 that's 6 addresses, for
    /24 it's 254. Refuses ranges larger than /16 to prevent the user
    from accidentally enumerating 65k addresses they didn't mean to.
    """
    net = ipaddress.ip_network(cidr, strict=False)
    if net.num_addresses > 65_536:
        raise ValueError(
            f"subnet_hosts({cidr!r}) would yield {net.num_addresses} "
            "addresses; refuse anything larger than /16. Iterate "
            "with ip_network() directly if you really mean it."
        )
    return [str(ip) for ip in net.hosts()]


# ---------------------------------------------------------------------------
# Find / grep / diff across any FileBackend
# ---------------------------------------------------------------------------


def find_files(
    backend,
    path: str,
    *,
    pattern: str | None = None,
    ext: str | None = None,
    mtime_after: datetime | None = None,
    mtime_before: datetime | None = None,
    size_min: int | None = None,
    size_max: int | None = None,
    max_depth: int | None = None,
    follow_links: bool = False,
) -> Iterator:
    """Recursive walk of ``backend`` rooted at ``path``, filtered by
    every non-None criterion. Yields :class:`models.file_item.FileItem`.

    ``pattern`` is a glob (``*.txt``); ``ext`` is shorthand (".txt"
    or "txt", case-insensitive). Supplying both ANDs them.

    ``follow_links`` is OFF by default — symlink-loop bombs are a
    classic find footgun. Set True only when you trust the tree.
    """
    if pattern is not None and not isinstance(pattern, str):
        raise TypeError("pattern must be a glob string or None")
    norm_ext = None
    if ext:
        norm_ext = ext.lower().lstrip(".")
    yield from _walk(
        backend, path,
        pattern=pattern, norm_ext=norm_ext,
        mtime_after=mtime_after, mtime_before=mtime_before,
        size_min=size_min, size_max=size_max,
        max_depth=max_depth, depth=0,
        follow_links=follow_links,
    )


def _walk(backend, path, *, pattern, norm_ext, mtime_after, mtime_before,
          size_min, size_max, max_depth, depth, follow_links):
    try:
        items = backend.list_dir(path)
    except Exception as exc:  # noqa: BLE001
        log.debug("find_files: skipping unreadable %s: %s", path, exc)
        return
    for item in items:
        full = backend.join(path, item.name)
        is_link = getattr(item, "is_link", False)
        if not item.is_dir:
            if pattern and not fnmatch.fnmatchcase(item.name, pattern):
                continue
            if norm_ext and not item.name.lower().endswith("." + norm_ext):
                continue
            if size_min is not None and item.size < size_min:
                continue
            if size_max is not None and item.size > size_max:
                continue
            if mtime_after is not None and item.modified < mtime_after:
                continue
            if mtime_before is not None and item.modified > mtime_before:
                continue
            # Yield the FileItem with `name` rewritten to the full path
            # so the caller can pass it straight to backend.open_read.
            # FileItem is a frozen dataclass — use dataclasses.replace.
            try:
                import dataclasses as _dc
                yield _dc.replace(item, name=full)
            except (TypeError, ValueError):
                # Non-dataclass FileItem-shaped object; fall back.
                yield item
        else:
            if is_link and not follow_links:
                continue
            if max_depth is not None and depth >= max_depth:
                continue
            yield from _walk(
                backend, full,
                pattern=pattern, norm_ext=norm_ext,
                mtime_after=mtime_after, mtime_before=mtime_before,
                size_min=size_min, size_max=size_max,
                max_depth=max_depth, depth=depth + 1,
                follow_links=follow_links,
            )


@dataclass(frozen=True)
class ArchiveEntry:
    """One entry from :func:`archive_inspect`. ``size`` is the
    uncompressed size in bytes; ``compressed_size`` is what's actually
    on disk (None when the format doesn't track it separately —
    tar). ``modified`` is a UTC datetime when known."""
    name: str
    size: int
    compressed_size: int | None
    is_dir: bool
    modified: datetime | None


def archive_inspect(path: str, *,
                    max_entries: int = 100_000) -> list[ArchiveEntry]:
    """List the entries inside ``path`` without extracting. Detects
    the archive type by extension first (``.zip`` / ``.tar*`` /
    ``.7z``) and falls through to magic-byte sniffing for unknown
    suffixes.

    Supported:
    * ZIP / JAR / WAR — stdlib ``zipfile``
    * TAR + gzip/bzip2/xz/zstd compression — stdlib ``tarfile``
    * 7z — ``py7zr`` (axross[archive] extra)

    Caps result at ``max_entries`` so a zip-bomb-shaped archive
    can't fill memory. Raises ``OSError`` for malformed archives
    or unsupported formats; ``ValueError`` for truncated input.
    """
    import os as _os
    import zipfile as _zip
    import tarfile as _tar
    if not _os.path.isfile(path):
        raise OSError(f"archive_inspect: not a file: {path!r}")
    lower = path.lower()
    # Try by extension first (cheapest, most reliable for well-named files).
    if lower.endswith(".zip") or lower.endswith(".jar") or lower.endswith(".war"):
        return _archive_inspect_zip(path, max_entries)
    if any(lower.endswith(s) for s in
           (".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tbz",
            ".tar.xz", ".txz", ".tar.zst", ".tzst")):
        return _archive_inspect_tar(path, max_entries)
    if lower.endswith(".7z"):
        return _archive_inspect_7z(path, max_entries)
    # Fallback — sniff magic bytes.
    with open(path, "rb") as fh:
        head = fh.read(64)
    if head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06"):
        return _archive_inspect_zip(path, max_entries)
    if head.startswith(b"7z\xbc\xaf\x27\x1c"):
        return _archive_inspect_7z(path, max_entries)
    if (head[257:262] == b"ustar" or head.startswith(b"\x1f\x8b")
            or head.startswith(b"BZh") or head.startswith(b"\xfd7zXZ")):
        # gzip / bzip2 / xz wrap a tar in practice.
        return _archive_inspect_tar(path, max_entries)
    raise OSError(
        f"archive_inspect: cannot identify {path!r} (unknown magic / extension)"
    )


def _archive_inspect_zip(path: str, max_entries: int) -> list[ArchiveEntry]:
    import zipfile as _zip
    out: list[ArchiveEntry] = []
    try:
        with _zip.ZipFile(path) as zf:
            for info in zf.infolist():
                modified: datetime | None = None
                try:
                    modified = datetime(*info.date_time)
                except (ValueError, TypeError):
                    pass
                out.append(ArchiveEntry(
                    name=info.filename,
                    size=info.file_size,
                    compressed_size=info.compress_size,
                    is_dir=info.is_dir(),
                    modified=modified,
                ))
                if len(out) >= max_entries:
                    break
    except _zip.BadZipFile as exc:
        raise ValueError(f"archive_inspect: malformed ZIP: {exc}") from exc
    return out


def _archive_inspect_tar(path: str, max_entries: int) -> list[ArchiveEntry]:
    import tarfile as _tar
    from datetime import timezone as _tz
    out: list[ArchiveEntry] = []
    try:
        # Auto-detect compression via mode "r:*".
        with _tar.open(path, "r:*") as tf:
            for member in tf:
                modified = None
                if member.mtime is not None:
                    try:
                        modified = datetime.fromtimestamp(
                            member.mtime, tz=_tz.utc,
                        )
                    except (ValueError, OSError):
                        pass
                out.append(ArchiveEntry(
                    name=member.name,
                    size=member.size or 0,
                    compressed_size=None,  # tar doesn't track this
                    is_dir=member.isdir(),
                    modified=modified,
                ))
                if len(out) >= max_entries:
                    break
    except _tar.ReadError as exc:
        raise ValueError(f"archive_inspect: malformed TAR: {exc}") from exc
    return out


def _archive_inspect_7z(path: str, max_entries: int) -> list[ArchiveEntry]:
    try:
        import py7zr  # type: ignore
    except ImportError as exc:
        raise OSError(
            "archive_inspect 7z support requires py7zr — install with "
            "`pip install axross[archive]`"
        ) from exc
    out: list[ArchiveEntry] = []
    try:
        with py7zr.SevenZipFile(path, mode="r") as sz:
            for info in sz.list():
                out.append(ArchiveEntry(
                    name=info.filename,
                    size=info.uncompressed,
                    compressed_size=info.compressed,
                    is_dir=bool(getattr(info, "is_directory", False)),
                    modified=getattr(info, "creationtime", None),
                ))
                if len(out) >= max_entries:
                    break
    except Exception as exc:  # noqa: BLE001 — py7zr raises various
        raise ValueError(f"archive_inspect: malformed 7z: {exc}") from exc
    return out


@dataclass(frozen=True)
class TimeSkew:
    """Result of a :func:`time_skew` measurement. ``offset_seconds``
    is positive when the remote source is AHEAD of local; negative
    when behind. ``rtt_seconds`` is the round-trip used to compute
    the offset (useful for confidence: small RTT → tight offset).
    ``source`` records which protocol answered."""
    host: str
    source: str        # "ntp" | "http" | "tls"
    offset_seconds: float
    rtt_seconds: float


def time_skew(host: str, *, source: str = "http",
              port: int | None = None,
              timeout: float = 5.0) -> TimeSkew:
    """Measure clock drift of ``host`` vs. the local clock.

    ``source``:
    * ``"ntp"``  — query an NTP server (default port 123/UDP).
                    Most accurate; needs ntplib.
    * ``"http"`` — fetch the URL ``http(s)://host[:port]/`` and
                    parse the ``Date:`` response header. Universal
                    fallback — every HTTP/1.1 server emits Date.
    * ``"tls"``  — TLS 1.2 ServerHello carries gmt_unix_time in
                    the random field; we'd need a custom handshake
                    to read it (the timestamp was REMOVED in TLS 1.3
                    for privacy reasons). Not implemented in this
                    helper — raises NotImplementedError pointing
                    at HTTP as the practical alternative.

    Returns ``TimeSkew(offset_seconds, rtt_seconds, source)``.
    Positive offset = remote ahead, negative = remote behind.
    """
    if source == "ntp":
        return _time_skew_ntp(host, port=port or 123, timeout=timeout)
    if source == "http":
        return _time_skew_http(host, port=port, timeout=timeout)
    if source == "tls":
        raise NotImplementedError(
            "time_skew(source='tls') needs a custom TLS 1.2 handshake "
            "to read gmt_unix_time from ServerHello (TLS 1.3 removed "
            "it for privacy). Use source='http' or 'ntp' instead."
        )
    raise ValueError(
        f"time_skew source must be ntp/http/tls, got {source!r}"
    )


def _time_skew_ntp(host: str, *, port: int, timeout: float) -> TimeSkew:
    try:
        import ntplib  # type: ignore
    except ImportError as exc:
        raise OSError(
            "time_skew(source='ntp') requires ntplib — install with "
            "`pip install ntplib` (or via the axross[ntp] extra)"
        ) from exc
    client = ntplib.NTPClient()
    start = time.monotonic()
    try:
        resp = client.request(host, port=int(port),
                              timeout=float(timeout), version=3)
    except Exception as exc:  # noqa: BLE001 — ntplib raises various
        raise OSError(f"time_skew NTP {host}: {exc}") from exc
    rtt = time.monotonic() - start
    # ntplib already computes a 4-stamp offset (T1/T2/T3/T4 NTP
    # algorithm) — use it directly. Sign convention matches:
    # positive = remote ahead.
    return TimeSkew(
        host=host, source="ntp",
        offset_seconds=float(resp.offset),
        rtt_seconds=rtt,
    )


def _time_skew_http(host: str, *, port: int | None,
                    timeout: float) -> TimeSkew:
    """HEAD the host's root URL and parse Date:. Tries HTTPS first
    (most servers redirect HTTP→HTTPS anyway), falls back to HTTP.
    The chosen scheme is encoded in TimeSkew.source as ``http``."""
    import requests
    from email.utils import parsedate_to_datetime
    schemes = ["https", "http"]
    if port:
        # Caller specified a port — only one scheme works for it.
        schemes = ["https"] if port == 443 else ["http"]
    last_exc: Exception | None = None
    for scheme in schemes:
        url = f"{scheme}://{host}"
        if port:
            url += f":{port}"
        url += "/"
        # Use BOTH clocks: monotonic for the RTT (drift-free, doesn't
        # jump on NTP step), and time.time() for the absolute baseline
        # we compare against the remote Date: header (which is in
        # Unix-epoch seconds).
        start_wall = time.time()
        start_mono = time.monotonic()
        try:
            resp = requests.head(url, timeout=float(timeout),
                                 allow_redirects=False, verify=False)
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            continue
        rtt = time.monotonic() - start_mono
        date_hdr = resp.headers.get("Date")
        if not date_hdr:
            last_exc = OSError(f"{url} returned no Date: header")
            continue
        remote = parsedate_to_datetime(date_hdr).timestamp()
        # The Date header was generated at approximately
        # start_wall + rtt/2 in our clock — half the RTT is the
        # one-way travel time on each leg.
        local_at_send = start_wall + rtt / 2
        offset = remote - local_at_send
        return TimeSkew(
            host=host, source="http",
            offset_seconds=offset, rtt_seconds=rtt,
        )
    raise OSError(f"time_skew HTTP {host}: {last_exc}")


@dataclass(frozen=True)
class WhoisInfo:
    """Result of a :func:`whois` lookup. ``kind`` is ``"ip"`` for
    address lookups (RIR / ASN data) or ``"domain"`` for registrar
    queries. Some fields will be ``None`` when the source registry
    doesn't expose them."""
    query: str
    kind: str       # "ip" or "domain"
    asn: int | None
    asn_description: str | None
    country: str | None
    cidr: str | None
    registry: str | None       # ARIN / RIPE / APNIC / LACNIC / AFRINIC
    raw: dict


def whois(query: str, *, timeout: float = 5.0) -> WhoisInfo:
    """RIR / ASN / registrar lookup.

    Auto-detects whether ``query`` is an IP (v4 or v6) or a domain
    name. IPs go through ``ipwhois`` (RDAP-aware, no flat-file
    parsing); domains aren't yet supported by this helper — they
    raise NotImplementedError pointing at the system ``whois``
    binary, which is the practical fallback (registrar WHOIS is a
    free-text mess that's hard to parse cleanly without a third-
    party service).
    """
    try:
        ip = ipaddress.ip_address(query)
        is_ip = True
    except ValueError:
        is_ip = False
    if not is_ip:
        raise NotImplementedError(
            "whois() supports only IP addresses today. For domains, "
            "shell out to the system `whois` binary or use a "
            "domain-specific service (registrars publish text-only "
            "WHOIS that's hard to parse cleanly)."
        )
    try:
        from ipwhois import IPWhois  # type: ignore
    except ImportError as exc:
        raise OSError(
            "whois() requires ipwhois — install with "
            "`pip install ipwhois` (or via the axross[whois] extra)"
        ) from exc
    try:
        res = IPWhois(str(ip), timeout=int(timeout)).lookup_rdap(depth=1)
    except Exception as exc:  # noqa: BLE001 — ipwhois raises various
        raise OSError(f"whois({query}): {exc}") from exc
    asn_raw = res.get("asn")
    try:
        asn = int(asn_raw) if asn_raw not in (None, "NA", "") else None
    except (ValueError, TypeError):
        asn = None
    return WhoisInfo(
        query=str(ip),
        kind="ip",
        asn=asn,
        asn_description=res.get("asn_description") or None,
        country=res.get("asn_country_code") or None,
        cidr=res.get("asn_cidr") or None,
        registry=res.get("asn_registry") or None,
        raw=res,
    )


@dataclass(frozen=True)
class OuiInfo:
    """OUI (Organisationally Unique Identifier) lookup result.
    ``vendor`` is the short name (``"VMware"``); ``vendor_long`` the
    full registry entry (``"VMware, Inc."``). Both ``None`` when the
    OUI isn't in the database."""
    mac: str
    oui: str          # first 3 bytes, normalised to AA:BB:CC
    vendor: str | None
    vendor_long: str | None


def mac_lookup(mac: str) -> OuiInfo:
    """Look up the IEEE OUI vendor for a MAC address.

    Accepts every common MAC formatting:
    * ``00:1A:2B:3C:4D:5E``    (colon-separated)
    * ``00-1A-2B-3C-4D-5E``    (hyphen-separated)
    * ``001A.2B3C.4D5E``       (Cisco dotted-quad)
    * ``001A2B3C4D5E``         (12 hex chars, no separator)

    Uses the ``manuf`` package (Wireshark-derived OUI database).
    Raises ``OSError`` with an install hint when ``manuf`` isn't
    installed, ``ValueError`` for malformed MACs.

    Returns ``OuiInfo`` — when the OUI isn't in the registry, the
    ``vendor`` / ``vendor_long`` fields are None but the call
    doesn't raise (vendor-unknown is a valid answer for locally-
    administered or recently-allocated MACs).
    """
    try:
        import manuf as _manuf  # type: ignore
    except ImportError as exc:
        raise OSError(
            "mac_lookup requires manuf — install with "
            "`pip install manuf` (or via the axross[mac] extra)"
        ) from exc
    norm = _normalise_mac(mac)
    parser = _manuf.MacParser()
    info = parser.get_all(norm)
    return OuiInfo(
        mac=norm,
        oui=norm[:8],   # AA:BB:CC
        vendor=info.manuf or None,
        vendor_long=info.manuf_long or None,
    )


def _normalise_mac(mac: str) -> str:
    """Reduce the input to canonical ``AA:BB:CC:DD:EE:FF`` form
    (uppercase hex, colon-separated). Refuses inputs that aren't
    exactly 12 hex digits after stripping separators."""
    cleaned = mac.replace(":", "").replace("-", "").replace(".", "").strip()
    if len(cleaned) != 12 or not all(c in "0123456789abcdefABCDEF" for c in cleaned):
        raise ValueError(
            f"mac_lookup: {mac!r} is not a 12-hex-digit MAC address"
        )
    cleaned = cleaned.upper()
    return ":".join(cleaned[i:i + 2] for i in range(0, 12, 2))


def entropy(data: bytes, *, base: int = 2) -> float:
    """Shannon entropy of ``data`` in bits/byte (when ``base=2``).

    Cheap triage primitive: high-entropy blobs (>7.5 bits/byte) are
    almost certainly compressed or encrypted; low-entropy blobs are
    structured. Returns ``0.0`` for empty input.

    ``base`` is the log base — 2 gives bits/byte, math.e gives nats,
    10 gives dits. Default 2 matches what ``binwalk`` and most
    forensic tools report.
    """
    if not data:
        return 0.0
    import math as _math
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    h = 0.0
    log = _math.log
    for c in counts:
        if c == 0:
            continue
        p = c / n
        h -= p * log(p, base)
    return h


def magic_type(data: bytes, *, default: str = "application/octet-stream") -> str:
    """Detect file type by magic bytes. Returns the MIME type if
    recognised, ``default`` otherwise. Uses pure-Python ``puremagic``
    so no libmagic dep is needed at runtime.

    Pass ``data`` as the first ~1 KiB of the file (we only inspect
    the first 8 KiB regardless — feeding the whole file is wasteful
    but harmless).
    """
    try:
        import puremagic  # type: ignore
    except ImportError as exc:
        raise OSError(
            "magic_type requires puremagic — install with "
            "`pip install puremagic` (or via the axross[magic] extra)"
        ) from exc
    sample = data[:8192]
    if not sample:
        return default
    try:
        guesses = puremagic.magic_string(sample)
    except Exception:  # noqa: BLE001
        return default
    if not guesses:
        return default
    # puremagic returns confidence-sorted guesses; take the strongest.
    best = guesses[0]
    return getattr(best, "mime_type", "") or default


def text_encoding(data: bytes, *, sample_bytes: int = 65536) -> dict:
    """Guess the text encoding of ``data``. Returns a dict::

        {"encoding": "utf-8", "confidence": 0.99, "language": ""}

    Uses ``chardet`` so the detector understands legacy code pages
    (Windows-125x, Big5, Shift-JIS, …). For empty input returns
    ``{"encoding": None, "confidence": 0.0, ...}``.
    """
    try:
        import chardet  # type: ignore
    except ImportError as exc:
        raise OSError(
            "text_encoding requires chardet — install with "
            "`pip install chardet` (or via the axross[encoding] extra)"
        ) from exc
    out = chardet.detect(data[:int(sample_bytes)] or b"")
    return {
        "encoding": out.get("encoding"),
        "confidence": float(out.get("confidence") or 0.0),
        "language": out.get("language") or "",
    }


@dataclass(frozen=True)
class GrepHit:
    path: str
    line_no: int
    line: str


def grep(backend, path: str, pattern: str, *,
         max_size: int = 10 * 1024 * 1024,
         max_matches: int = 100,
         ignore_case: bool = False,
         binary: bool = False) -> list[GrepHit]:
    """Search ``backend:path`` for ``pattern`` (a regex). Returns up
    to ``max_matches`` hits.

    If ``path`` names a directory the search recurses. Files larger
    than ``max_size`` are skipped (set to 0 to disable). Set
    ``binary=True`` to also search files that contain NUL bytes.
    """
    flags = re.IGNORECASE if ignore_case else 0
    rx = re.compile(pattern, flags)
    hits: list[GrepHit] = []
    targets: list[str]
    try:
        item = backend.stat(path)
    except Exception as exc:
        raise OSError(f"grep: cannot stat {path!r}: {exc}") from exc
    if item.is_dir:
        targets = []
        for it in find_files(backend, path):
            targets.append(it.name)
    else:
        targets = [path]
    for tgt in targets:
        try:
            stat = backend.stat(tgt)
        except Exception:  # noqa: BLE001
            continue
        if max_size and stat.size > max_size:
            continue
        try:
            with backend.open_read(tgt) as fh:
                data = fh.read()
        except Exception as exc:  # noqa: BLE001
            log.debug("grep: skip unreadable %s: %s", tgt, exc)
            continue
        if not binary and b"\x00" in data[:8192]:
            continue
        try:
            text = data.decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            continue
        for ln, line in enumerate(text.splitlines(), 1):
            if rx.search(line):
                hits.append(GrepHit(path=tgt, line_no=ln, line=line))
                if len(hits) >= max_matches:
                    return hits
    return hits


def diff_files(b1, p1: str, b2, p2: str, *,
               max_bytes: int = 10 * 1024 * 1024,
               n_context: int = 3) -> list[str]:
    """Unified diff of two files, possibly on different backends.
    Returns a list of diff lines (incl. ``--- / +++`` headers). Empty
    list = no difference.
    """
    def _read(b, p):
        with b.open_read(p) as fh:
            data = fh.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise ValueError(
                f"diff_files: {p!r} exceeds {max_bytes} bytes; pass a "
                "larger max_bytes or chunk it yourself"
            )
        return data.decode("utf-8", errors="replace").splitlines()
    a = _read(b1, p1)
    b = _read(b2, p2)
    return list(difflib.unified_diff(
        a, b, fromfile=p1, tofile=p2, n=n_context, lineterm="",
    ))


# ---------------------------------------------------------------------------
# __all__ — every name re-exported from core.scripting
# ---------------------------------------------------------------------------

__all__ = [
    "tcp_banner", "port_open", "port_scan",
    "ping", "PingResult",
    "mac_lookup", "OuiInfo",
    "whois", "WhoisInfo",
    "time_skew", "TimeSkew",
    "tls_cert", "TlsCert",
    "ssh_hostkey", "SshHostKey",
    "dns_records", "dns_reverse",
    "http_probe", "HttpProbe",
    "subnet_hosts",
    "find_files",
    "grep", "GrepHit",
    "diff_files",
    "magic_type", "text_encoding",
    "entropy",
    "archive_inspect", "ArchiveEntry",
]
