"""A scripted LDAP server for the LDAP fuzz suite.

Speaks just enough BER for ldap3: answers BindRequest with success and
every SearchRequest with ``entries`` (``[(dn, {attr: [values]})]``) and a
SearchResultDone. ``mutate_search`` (bytes -> bytes) rewrites the raw
search answer before it is sent - the place mutants go in; after a
mutated answer the server hangs up, so a client waiting for a message
that will never complete sees EOF instead of its receive timeout.
"""

from __future__ import annotations

import socket

from fuzz_testkit import ScriptedServer


def _length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _length(len(content)) + content


def octets(value: bytes | str) -> bytes:
    return tlv(0x04, value.encode("utf-8") if isinstance(value, str) else value)


def integer(value: int) -> bytes:
    body = value.to_bytes(max(1, (value.bit_length() + 8) // 8), "big", signed=True)
    return tlv(0x02, body)


def ldap_result(op_tag: int, code: int = 0) -> bytes:
    return tlv(op_tag, tlv(0x0A, bytes([code])) + octets(b"") + octets(b""))


def message(msgid: int, op: bytes) -> bytes:
    return tlv(0x30, integer(msgid) + op)


def search_entry(dn: bytes | str, attrs: dict) -> bytes:
    attr_seq = b""
    for name, values in attrs.items():
        vals = b"".join(octets(v) for v in values)
        attr_seq += tlv(0x30, octets(name) + tlv(0x31, vals))
    return tlv(0x64, octets(dn) + tlv(0x30, attr_seq))


def _read_tlv(conn: socket.socket, buf: bytearray) -> bytes | None:
    """One complete BER element from *conn* (None on EOF)."""

    def need(n: int) -> bool:
        while len(buf) < n:
            chunk = conn.recv(65536)
            if not chunk:
                return False
            buf.extend(chunk)
        return True

    if not need(2):
        return None
    first = buf[1]
    if first < 0x80:
        header, length = 2, first
    else:
        n = first & 0x7F
        if not need(2 + n):
            return None
        header, length = 2 + n, int.from_bytes(buf[2 : 2 + n], "big")
    if not need(header + length):
        return None
    element = bytes(buf[: header + length])
    del buf[: header + length]
    return element


def _split(content: bytes) -> list[tuple[int, bytes]]:
    """The (tag, content) elements of a constructed BER value."""
    out, i = [], 0
    while i < len(content):
        tag, first = content[i], content[i + 1]
        if first < 0x80:
            hdr, length = 2, first
        else:
            n = first & 0x7F
            hdr, length = 2 + n, int.from_bytes(content[i + 2 : i + 2 + n], "big")
        out.append((tag, content[i + hdr : i + hdr + length]))
        i += hdr + length
    return out


class FakeLdapServer:
    def __init__(self) -> None:
        self.entries: list[tuple[bytes | str, dict]] = []
        self.mutate_search = None
        self.server = ScriptedServer(self._handle)
        self.port = self.server.port

    def search_answer(self, msgid: int, base: bytes = b"", scope: int = 1) -> bytes:
        """The entries (only the one named *base* for a BASE search,
        when there is one) and a SearchResultDone."""
        entries = self.entries
        if scope == 0:

            def raw(dn):
                return dn if isinstance(dn, bytes) else dn.encode("utf-8")

            named = [e for e in entries if raw(e[0]).lower() == base.lower()]
            entries = named or entries[:1]
        out = b"".join(message(msgid, search_entry(dn, attrs)) for dn, attrs in entries)
        return out + message(msgid, ldap_result(0x65))

    def _handle(self, conn: socket.socket) -> None:
        conn.settimeout(20)
        buf = bytearray()
        while True:
            element = _read_tlv(conn, buf)
            if element is None:
                return
            header = 2 if element[1] < 0x80 else 2 + (element[1] & 0x7F)
            parts = _split(element[header:])
            if len(parts) < 2:
                return
            msgid = int.from_bytes(parts[0][1], "big", signed=True)
            op_tag = parts[1][0]
            if op_tag == 0x60:  # BindRequest
                conn.sendall(message(msgid, ldap_result(0x61)))
            elif op_tag == 0x63:  # SearchRequest
                fields = _split(parts[1][1])
                base = fields[0][1]
                scope = fields[1][1][0] if len(fields) > 1 and fields[1][1] else 2
                answer = self.search_answer(msgid, base, scope)
                if self.mutate_search is not None:
                    conn.sendall(self.mutate_search(answer))
                    return
                conn.sendall(answer)
            elif op_tag == 0x42:  # UnbindRequest
                return
            else:
                conn.sendall(message(msgid, ldap_result(0x65, code=53)))

    def close(self) -> None:
        self.server.close()
