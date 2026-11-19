"""STARTTLS: what a man in the middle says in clear text before the TLS
handshake is not believed after it (the client side of CVE-2011-0411).

Round-3 review: imaplib keeps the untagged answers read before STARTTLS's
tagged OK. A "* LIST" put in front of the OK by anyone on the path was read
after the login as the server's own answer: the first LIST of the session
(the hierarchy separator) came from the attacker. Bytes after the OK are
dropped by every client (a new reader on the TLS socket).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from fake_ircd import self_signed  # noqa: E402
from starttls_servers import (  # noqa: E402
    StartTlsImapServer,
    StartTlsPop3Server,
    server_context,
)

from core import imap_client as IC  # noqa: E402
from core import pop3_client as PC  # noqa: E402
from core import tls_context  # noqa: E402
from fuzz_testkit import recv_line  # noqa: E402


@pytest.fixture
def trusted(tmp_path, monkeypatch):
    cert_path, key_path, _der = self_signed(tmp_path, "localhost")
    real = tls_context.client_tls_context

    def ctx(verify=True, *, label="TLS"):
        c = real(verify, label=label)
        if verify:
            c.load_verify_locations(cert_path)
        return c

    monkeypatch.setattr(tls_context, "client_tls_context", ctx)
    monkeypatch.setattr(IC, "IMAP_TIMEOUT", 5.0)
    return cert_path, key_path


class _InjectingImap(StartTlsImapServer):
    """Answers STARTTLS with untagged lines before the OK and plain text
    after it in the same packet; the real server's separator is "/"."""

    def _handle(self, conn):
        conn.settimeout(10)
        tls = False
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
                conn.sendall(
                    b'* LIST (\\Noselect) "#" "INJECTED"\r\n'
                    b"* CAPABILITY IMAP4rev1 AUTH=PLAIN INJECTEDCAP\r\n"
                    + f"{tag} OK begin TLS\r\n".encode()
                )
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


def test_sad_imap_answers_injected_before_starttls_are_dropped(trusted):
    with _InjectingImap(server_context(*trusted)) as srv:
        s = IC.ImapSession("localhost", srv.port, "u", "secret", tls_mode="starttls")
        sep = s._hierarchy_sep
        caps = {str(c).upper() for c in s._imap.capabilities}
        leftovers = dict(s._imap.untagged_responses)
        s.disconnect()
        logins = srv.got("LOGIN")
    assert logins and all(t for _l, t in logins)
    assert sep == "/"
    assert "INJECTEDCAP" not in caps
    assert "LIST" not in leftovers


class _InjectingPop3(StartTlsPop3Server):
    """Plain text after "+OK" of STLS in the same packet."""

    def _handle(self, conn):
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
                caps = "USER\r\n" + ("STLS\r\n" if not tls else "")
                conn.sendall(f"+OK\r\n{caps}.\r\n".encode())
            elif verb == "STLS":
                conn.sendall(b"+OK begin TLS\r\n+OK injected\r\n+OK injected\r\n")
                conn = self._upgrade(conn)
                tls = True
            elif verb == "QUIT":
                conn.sendall(b"+OK bye\r\n")
                return
            elif verb == "STAT":
                conn.sendall(b"+OK 0 0\r\n")
            elif verb == "PASS":
                conn.sendall(b"+OK real\r\n")
            else:
                conn.sendall(b"+OK\r\n")


def test_sad_pop3_text_after_stls_ok_is_dropped(trusted):
    with _InjectingPop3(server_context(*trusted)) as srv:
        s = PC.Pop3Session("localhost", srv.port, "u", "secret", tls_mode="starttls")
        s.disconnect()
        cmds = list(srv.commands)
    users = [c for c in cmds if c[0].upper().startswith(("USER", "PASS"))]
    assert users and all(t for _l, t in users), cmds
