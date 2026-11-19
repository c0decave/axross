"""Local fake IMAP, POP3 and LDAP servers that offer STARTTLS, refuse it or
leave it out of their capabilities (a downgrade by a man in the middle), for
tests/test_mail_ldap_starttls.py.

Each server records the commands it got and whether each came over TLS
(``commands``: ``[(line or op, over_tls)]``), so a test can say that the
password never went out in clear text.
"""

from __future__ import annotations

import socket
import ssl

from fuzz_testkit import ScriptedServer, recv_line
from ldap_fuzz_server import _read_tlv, _split, ldap_result, message, tlv


def server_context(cert: str, key: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    return ctx


class _Base:
    def __init__(self, ctx: ssl.SSLContext, *, offer: bool = True, accept: bool = True,
                 preauth: bool = False) -> None:
        self.ctx = ctx
        #: STARTTLS (STLS) in the capabilities.
        self.offer = offer
        #: STARTTLS answered with OK (else NO / -ERR / protocolError).
        self.accept = accept
        self.preauth = preauth
        self.commands: list[tuple[str, bool]] = []
        self.server = ScriptedServer(self._handle)
        self.host, self.port = self.server.host, self.server.port

    def got(self, word: str) -> list[tuple[str, bool]]:
        return [c for c in self.commands if word.upper() in c[0].upper()]

    def close(self) -> None:
        self.server.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def _upgrade(self, conn: socket.socket):
        conn.settimeout(10)
        return self.ctx.wrap_socket(conn, server_side=True)


class StartTlsImapServer(_Base):
    def _caps(self, tls: bool) -> str:
        if tls:
            return "IMAP4rev1 AUTH=PLAIN"
        return "IMAP4rev1 LOGINDISABLED" + (" STARTTLS" if self.offer else "")

    def _handle(self, conn: socket.socket) -> None:
        conn.settimeout(10)
        tls = False
        if self.preauth:
            conn.sendall(b"* PREAUTH [CAPABILITY IMAP4rev1 STARTTLS] logged in\r\n")
        else:
            conn.sendall(b"* OK fake IMAP ready\r\n")
        while True:
            raw = recv_line(conn)
            if not raw:
                return
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            self.commands.append((line, tls))
            tag, _, rest = line.partition(" ")
            verb = rest.partition(" ")[0].upper()
            if verb == "CAPABILITY":
                conn.sendall(f"* CAPABILITY {self._caps(tls)}\r\n{tag} OK done\r\n".encode())
            elif verb == "STARTTLS":
                if not self.accept:
                    conn.sendall(f"{tag} NO not now\r\n".encode())
                    continue
                conn.sendall(f"{tag} OK begin TLS\r\n".encode())
                conn = self._upgrade(conn)
                tls = True
            elif verb in ("LOGIN", "AUTHENTICATE"):
                conn.sendall(f"{tag} OK logged in\r\n".encode())
            elif verb == "LIST":
                conn.sendall(f'* LIST (\\HasNoChildren) "/" "INBOX"\r\n{tag} OK done\r\n'.encode())
            elif verb == "LOGOUT":
                conn.sendall(f"* BYE\r\n{tag} OK bye\r\n".encode())
                return
            else:
                conn.sendall(f"{tag} OK done\r\n".encode())


class StartTlsPop3Server(_Base):
    def _handle(self, conn: socket.socket) -> None:
        conn.settimeout(10)
        tls = False
        conn.sendall(b"+OK fake POP3 ready\r\n")
        while True:
            raw = recv_line(conn)
            if not raw:
                return
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            self.commands.append((line, tls))
            verb = line.partition(" ")[0].upper()
            if verb == "CAPA":
                caps = "USER\r\n" + ("STLS\r\n" if self.offer and not tls else "")
                conn.sendall(f"+OK\r\n{caps}.\r\n".encode())
            elif verb == "STLS":
                if not self.accept:
                    conn.sendall(b"-ERR not now\r\n")
                    continue
                conn.sendall(b"+OK begin TLS\r\n")
                conn = self._upgrade(conn)
                tls = True
            elif verb == "QUIT":
                conn.sendall(b"+OK bye\r\n")
                return
            elif verb == "STAT":
                conn.sendall(b"+OK 0 0\r\n")
            else:
                conn.sendall(b"+OK\r\n")


STARTTLS_OID = b"1.3.6.1.4.1.1466.20037"


class StartTlsLdapServer(_Base):
    """``offer``/``accept``: the StartTLS extended operation is answered
    with success (then the TLS handshake) or with protocolError."""

    def _handle(self, conn: socket.socket) -> None:
        conn.settimeout(10)
        tls = False
        buf = bytearray()
        while True:
            element = _read_tlv(conn, buf)
            if element is None:
                return
            header = 2 if element[1] < 0x80 else 2 + (element[1] & 0x7F)
            parts = _split(element[header:])
            msgid = int.from_bytes(parts[0][1], "big", signed=True)
            op_tag = parts[1][0]
            if op_tag == 0x77:  # ExtendedRequest
                self.commands.append(("STARTTLS", tls))
                ok = self.offer and self.accept
                answer = ldap_result(0x78, code=0 if ok else 2)
                answer = tlv(0x78, answer[2:] + tlv(0x8A, STARTTLS_OID))
                conn.sendall(message(msgid, answer))
                if ok:
                    conn = self._upgrade(conn)
                    buf = bytearray()
                    tls = True
            elif op_tag == 0x60:  # BindRequest
                self.commands.append(("BIND", tls))
                conn.sendall(message(msgid, ldap_result(0x61)))
            elif op_tag == 0x63:  # SearchRequest
                self.commands.append(("SEARCH", tls))
                conn.sendall(message(msgid, ldap_result(0x65)))
            elif op_tag == 0x42:  # UnbindRequest
                return
            else:
                conn.sendall(message(msgid, ldap_result(0x65, code=53)))
