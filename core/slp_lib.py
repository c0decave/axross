"""Minimal SLPv2 (RFC 2608) wire helper.

Purpose-built for axross's read-only SLP FileBackend: we only need
the *request* path (SrvTypeReq, SrvReq, AttrReq) and just enough of
the *reply* parser to extract URL lists and attribute strings. We
deliberately do NOT implement SrvReg / DAAdvert / amplification-
prone surfaces — the CVE-2023-29552 amp pattern (slpload-style)
needs SrvReg + a giant scope buffer, which this module simply
cannot produce.

References used while writing this:

* RFC 2608 — Service Location Protocol, Version 2
* RFC 2165 — Service Location Protocol (v1; for back-compat
  vocabulary; we don't speak v1)
* curesec/slpscan + curesec/slpload — packet shapes and field
  alignment in the wild
* CVE-2023-29552 — the public DoS amplification analysis that
  drove our refusal to expose SrvReg
"""
from __future__ import annotations

import logging
import secrets
import socket
import struct
from dataclasses import dataclass

log = logging.getLogger(__name__)

# Function-IDs we issue.
FN_SRV_REQ = 0x01
FN_SRV_RPLY = 0x02
FN_ATTR_REQ = 0x06
FN_ATTR_RPLY = 0x07
FN_SRV_TYPE_REQ = 0x09
FN_SRV_TYPE_RPLY = 0x0A

DEFAULT_PORT = 427
DEFAULT_TIMEOUT = 5.0

# Reasonable response cap. SLP replies are tiny in practice; refusing
# >256 KiB stops a hostile / runaway daemon from saturating us.
MAX_RESPONSE_BYTES = 256 * 1024


# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class _SlpHeader:
    """Parsed SLPv2 fixed header."""
    version: int
    function: int
    length: int
    flags: int
    xid: int
    lang_tag: bytes


def _build_header(function: int, body_len: int, xid: int | None = None,
                  lang_tag: bytes = b"en") -> bytes:
    """Build a 14-byte+lang fixed header. ``length`` is patched once
    we know the full packet size."""
    if xid is None:
        xid = secrets.randbits(16) or 1
    # Total length = 14 (fixed) + len(lang_tag) + body
    total_len = 14 + len(lang_tag) + body_len
    # Length field is 3 bytes (24-bit BE).
    len_bytes = total_len.to_bytes(3, "big")
    flags = 0
    next_ext = 0  # 3-byte zero
    next_ext_bytes = next_ext.to_bytes(3, "big")
    return struct.pack(
        ">BB", 2, function,
    ) + len_bytes + struct.pack(">H", flags) + next_ext_bytes + struct.pack(
        ">HH", xid, len(lang_tag),
    ) + lang_tag


def _parse_header(buf: bytes) -> _SlpHeader:
    if len(buf) < 16:
        raise ValueError("SLP packet too short for a header")
    version, function = struct.unpack_from(">BB", buf, 0)
    length = int.from_bytes(buf[2:5], "big")
    flags = struct.unpack_from(">H", buf, 5)[0]
    # bytes 7..10 are next-extension offset; we don't use them
    xid = struct.unpack_from(">H", buf, 10)[0]
    lt_len = struct.unpack_from(">H", buf, 12)[0]
    if 14 + lt_len > len(buf):
        raise ValueError("SLP packet truncated lang-tag")
    lang_tag = buf[14:14 + lt_len]
    return _SlpHeader(version, function, length, flags, xid, lang_tag)


# ---------------------------------------------------------------------------
# Packet builders
# ---------------------------------------------------------------------------

def _str_field(text: bytes) -> bytes:
    return struct.pack(">H", len(text)) + text


def build_srv_type_req(scope: bytes = b"DEFAULT") -> bytes:
    """``SrvTypeRqst`` — ask the server for the list of service types."""
    body = (
        struct.pack(">H", 0)             # PRList (length=0)
        + struct.pack(">H", 0xFFFF)      # NamingAuthority — 0xFFFF = "all"
        + _str_field(scope)
    )
    return _build_header(FN_SRV_TYPE_REQ, len(body)) + body


def build_srv_req(svc_type: bytes, scope: bytes = b"DEFAULT",
                  predicate: bytes = b"") -> bytes:
    """``SrvRqst`` — list URLs for one service type."""
    body = (
        struct.pack(">H", 0)             # PRList
        + _str_field(svc_type)
        + _str_field(scope)
        + _str_field(predicate)          # LDAP-style predicate, empty = match all
        + _str_field(b"")                # SLP SPI (no auth)
    )
    return _build_header(FN_SRV_REQ, len(body)) + body


def build_attr_req(url: bytes, scope: bytes = b"DEFAULT",
                   tags: bytes = b"") -> bytes:
    """``AttrRqst`` — fetch attributes for a specific service URL."""
    body = (
        struct.pack(">H", 0)             # PRList
        + _str_field(url)
        + _str_field(scope)
        + _str_field(tags)               # tag list (empty = all)
        + _str_field(b"")                # SPI
    )
    return _build_header(FN_ATTR_REQ, len(body)) + body


# ---------------------------------------------------------------------------
# Reply parsers
# ---------------------------------------------------------------------------

def _read_u16(buf: bytes, off: int) -> tuple[int, int]:
    if off + 2 > len(buf):
        raise ValueError(
            f"SLP u16 read at offset {off} would overrun buffer of length {len(buf)}"
        )
    try:
        value = struct.unpack_from(">H", buf, off)[0]
    except struct.error as exc:
        raise ValueError(f"SLP u16 read at offset {off}: {exc}") from exc
    return value, off + 2


def _read_str(buf: bytes, off: int) -> tuple[bytes, int]:
    length, off = _read_u16(buf, off)
    if off + length > len(buf):
        raise ValueError(
            f"SLP string of length {length} at offset {off} overruns "
            f"buffer of length {len(buf)}"
        )
    return buf[off:off + length], off + length


def _skip_url_auths(buf: bytes, off: int, count: int) -> int:
    """Walk ``count`` SLP URL-auth blocks starting at ``off``. Each
    block is::

        BSD            (u16)
        AuthBlockLen   (u16, includes itself)
        AuthBlockBody  (AuthBlockLen - 4 bytes)

    Returns the new offset after the last block. We pass
    ``num_url_auths=0`` in our requests, but a hostile server can
    return a SrvRply with auths set anyway — without this walk we'd
    misalign every subsequent URL record.
    """
    for _ in range(count):
        # BSD
        _bsd, off = _read_u16(buf, off)
        # AuthBlockLen includes the length field itself.
        auth_len, off = _read_u16(buf, off)
        if auth_len < 4:
            raise ValueError(f"SLP URL-auth block length {auth_len} < 4")
        body_len = auth_len - 4
        if off + body_len > len(buf):
            raise ValueError("SLP URL-auth block body overruns buffer")
        off += body_len
    return off


def parse_srv_type_reply(blob: bytes) -> list[str]:
    """Return the list of service-type strings from a ``SrvTypeRply``.

    Reply body: <error code (u16)> <length-of-list (u16)> <list bytes…>
    The list is comma-separated bytes of service-type names.
    """
    hdr = _parse_header(blob)
    if hdr.function != FN_SRV_TYPE_RPLY:
        raise ValueError(f"Expected SrvTypeRply, got fn={hdr.function:#x}")
    body_off = 14 + len(hdr.lang_tag)
    err_code, body_off = _read_u16(blob, body_off)
    if err_code != 0:
        log.debug("SLP SrvTypeRply error_code=%d", err_code)
    lst, _ = _read_str(blob, body_off)
    if not lst:
        return []
    return [s.decode("utf-8", "replace").strip()
            for s in lst.split(b",") if s.strip()]


def parse_srv_reply(blob: bytes) -> list[tuple[str, int]]:
    """Return ``[(url, lifetime), ...]`` from a ``SrvRply``.

    Body: <err_code (u16)> <url_count (u16)> [<reserved (u8)> <lifetime (u16)>
          <url_len (u16)> <url> <num_url_auths (u8)>] x N
    """
    hdr = _parse_header(blob)
    if hdr.function != FN_SRV_RPLY:
        raise ValueError(f"Expected SrvRply, got fn={hdr.function:#x}")
    body_off = 14 + len(hdr.lang_tag)
    err_code, body_off = _read_u16(blob, body_off)
    if err_code != 0:
        log.debug("SLP SrvRply error_code=%d", err_code)
    url_count, body_off = _read_u16(blob, body_off)
    out: list[tuple[str, int]] = []
    for _ in range(url_count):
        if body_off + 5 > len(blob):
            break
        body_off += 1                                  # reserved
        lifetime, body_off = _read_u16(blob, body_off)
        url, body_off = _read_str(blob, body_off)
        if body_off + 1 > len(blob):
            break
        # num_url_auths (u8) — we send requests with 0 auths, but
        # hostile servers can still return a SrvRply with auths set.
        # Walking each auth block keeps the parse aligned across the
        # remaining URL records instead of skipping a fixed 1 byte.
        num_auths = blob[body_off]
        body_off += 1
        if num_auths:
            try:
                body_off = _skip_url_auths(blob, body_off, num_auths)
            except ValueError as exc:
                log.debug("SLP SrvRply URL-auths walk failed: %s", exc)
                break
        out.append((url.decode("utf-8", "replace"), lifetime))
    return out


def parse_attr_reply(blob: bytes) -> str:
    """Return the attribute-list string from an ``AttrRply``.

    Body: <err_code (u16)> <attr_list_len (u16)> <attr_list bytes>
          <num_attr_auths (u8)>
    """
    hdr = _parse_header(blob)
    if hdr.function != FN_ATTR_RPLY:
        raise ValueError(f"Expected AttrRply, got fn={hdr.function:#x}")
    body_off = 14 + len(hdr.lang_tag)
    err_code, body_off = _read_u16(blob, body_off)
    if err_code != 0:
        log.debug("SLP AttrRply error_code=%d", err_code)
    attrs, _ = _read_str(blob, body_off)
    return attrs.decode("utf-8", "replace")


# ---------------------------------------------------------------------------
# Tiny request/response helpers
# ---------------------------------------------------------------------------

def query_udp(host: str, packet: bytes,
              port: int = DEFAULT_PORT,
              timeout: float = DEFAULT_TIMEOUT) -> bytes:
    """Send ``packet`` via UDP unicast to ``host:port`` and return the
    response bytes. Refuses to use multicast / broadcast addresses —
    callers must point at a single host. Validates that the reply
    came from the same host we sent to so an off-path attacker
    spoofing a UDP datagram cannot inject responses."""
    if host in ("239.255.255.253",) or host.startswith("224."):
        raise OSError(
            "SLP backend refuses to query multicast (CVE-2023-29552 mitigation)"
        )
    # Resolve the destination once so we can compare the reply's
    # source against the addresses the host name maps to. recvfrom
    # returns the on-wire address, which is what we compare.
    try:
        infos = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_DGRAM)
    except socket.gaierror as exc:
        raise OSError(f"SLP DNS resolution for {host}: {exc}") from exc
    expected_addrs = {info[4][0] for info in infos}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (host, port))
        # Discard datagrams from any source other than our destination
        # — an off-path attacker can otherwise race us with a spoofed
        # reply on the same ephemeral port.
        deadline = socket.getdefaulttimeout() or timeout
        import time as _time
        end_time = _time.monotonic() + deadline
        while True:
            remaining = end_time - _time.monotonic()
            if remaining <= 0:
                raise socket.timeout(
                    "SLP response timed out waiting for reply from expected source"
                )
            sock.settimeout(remaining)
            data, addr = sock.recvfrom(MAX_RESPONSE_BYTES)
            if addr[0] in expected_addrs and addr[1] == port:
                return data
            log.debug("SLP: dropping datagram from unexpected source %s", addr)
    finally:
        sock.close()


def query_tcp(host: str, packet: bytes,
              port: int = DEFAULT_PORT,
              timeout: float = DEFAULT_TIMEOUT) -> bytes:
    """TCP unicast variant. Some daemons require TCP for replies that
    won't fit in a UDP datagram."""
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.settimeout(timeout)
    try:
        sock.sendall(packet)
        chunks: list[bytes] = []
        received = 0
        while True:
            try:
                chunk = sock.recv(64 * 1024)
            except socket.timeout:
                break
            if not chunk:
                break
            chunks.append(chunk)
            received += len(chunk)
            if received > MAX_RESPONSE_BYTES:
                raise OSError(f"SLP TCP response exceeds {MAX_RESPONSE_BYTES} byte cap")
        return b"".join(chunks)
    finally:
        sock.close()
