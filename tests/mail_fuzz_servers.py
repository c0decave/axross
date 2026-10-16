"""Scriptable fake line-protocol servers (IMAP, POP3, NNTP) for fuzz suites.

Each server answers commands from a table ``verb -> bytes | callable``. A
callable gets the argument string (and, for IMAP, the tag) and returns raw
bytes, ``None`` to hang up, or ``STALL`` to go silent.
"""

from __future__ import annotations

import socket

from fuzz_testkit import ScriptedServer, recv_line, stall

STALL = object()


class _LineServer:
    greeting = b""

    def __init__(self, replies: dict | None = None) -> None:
        self.replies = {**self.default_replies(), **(replies or {})}
        self.commands: list[str] = []
        self.server = ScriptedServer(self._handle)
        self.host, self.port = self.server.host, self.server.port

    def default_replies(self) -> dict:
        return {}

    def close(self) -> None:
        self.server.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def _send(self, conn: socket.socket, out) -> bool:
        if out is None:
            return False
        if out is STALL:
            stall(conn, 15)
            return False
        conn.sendall(out)
        return True


class FakeImapServer(_LineServer):
    """IMAP4rev1 subset: CAPABILITY LOGIN LIST SELECT EXAMINE UID NOOP."""

    greeting = b"* OK fuzz IMAP4rev1 ready\r\n"

    def default_replies(self) -> dict:
        return {
            "CAPABILITY": b"* CAPABILITY IMAP4rev1 QUOTA\r\n",
            "LOGIN": b"",
            "NOOP": b"",
            "LIST": b'* LIST (\\HasNoChildren) "/" "INBOX"\r\n'
            b'* LIST (\\HasChildren) "/" "Archive"\r\n',
            "SELECT": b"* 2 EXISTS\r\n",
            "EXAMINE": b"* 2 EXISTS\r\n",
            "SEARCH": b"* SEARCH 1 2\r\n",
            "FETCH": b"* 1 FETCH (UID 1 RFC822.SIZE 120 "
            b'INTERNALDATE "01-Jan-2026 10:00:00 +0000" '
            b'ENVELOPE ("Thu, 1 Jan 2026 10:00:00 +0000" "Hello world" '
            b"NIL NIL NIL NIL NIL NIL NIL NIL))\r\n",
            "BODY": b"* 1 FETCH (UID 1 RFC822 {26}\r\nSubject: hi\r\n\r\nbody text\r\n)\r\n",
            "GETQUOTAROOT": b'* QUOTAROOT INBOX ""\r\n* QUOTA "" (STORAGE 10 512)\r\n',
            "LOGOUT": b"* BYE\r\n",
            "CLOSE": b"",
            "CREATE": b"",
        }

    def _handle(self, conn: socket.socket) -> None:
        conn.sendall(self.greeting)
        while True:
            raw = recv_line(conn)
            if not raw:
                return
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            self.commands.append(line)
            tag, _, rest = line.partition(" ")
            verb, _, arg = rest.partition(" ")
            verb = verb.upper()
            if verb == "UID":
                sub, _, arg = arg.partition(" ")
                verb = sub.upper()
                if verb == "FETCH" and "RFC822)" in arg:
                    verb = "BODY"
            reply = self.replies.get(verb, b"")
            if callable(reply):
                reply = reply(tag, arg)
            if reply is None or reply is STALL:
                self._send(conn, reply)
                return
            conn.sendall(reply + f"{tag} OK done\r\n".encode())
            if verb == "LOGOUT":
                return


class FakePop3Server(_LineServer):
    greeting = b"+OK fuzz POP3 ready\r\n"

    def default_replies(self) -> dict:
        return {
            "USER": b"+OK\r\n",
            "PASS": b"+OK\r\n",
            "STAT": b"+OK 2 300\r\n",
            "LIST": b"+OK\r\n1 100\r\n2 200\r\n.\r\n",
            "UIDL": b"+OK\r\n1 uid-a\r\n2 uid-b\r\n.\r\n",
            "TOP": b"+OK\r\nSubject: hello\r\nDate: Thu, 1 Jan 2026 10:00:00 +0000\r\n\r\n.\r\n",
            "RETR": b"+OK\r\nSubject: hello\r\n\r\nbody\r\n..dot-stuffed\r\n.\r\n",
            "NOOP": b"+OK\r\n",
            "QUIT": b"+OK bye\r\n",
            "CAPA": b"-ERR\r\n",
            "DELE": b"+OK\r\n",
            "RSET": b"+OK\r\n",
        }

    def _handle(self, conn: socket.socket) -> None:
        conn.sendall(self.greeting)
        while True:
            raw = recv_line(conn)
            if not raw:
                return
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            self.commands.append(line)
            verb, _, arg = line.partition(" ")
            reply = self.replies.get(verb.upper(), b"-ERR unknown\r\n")
            if callable(reply):
                reply = reply(arg)
            if not self._send(conn, reply):
                return
            if verb.upper() == "QUIT":
                return


class FakeNntpServer(_LineServer):
    greeting = b"200 fuzz NNTP ready\r\n"

    def default_replies(self) -> dict:
        return {
            "CAPABILITIES": b"101 caps\r\nVERSION 2\r\nREADER\r\nOVER\r\nLIST ACTIVE\r\n.\r\n",
            "MODE": b"200 reader\r\n",
            "AUTHINFO": b"281 ok\r\n",
            "LIST": b"215 list\r\ncomp.lang.python 0000000010 0000000001 y\r\n"
            b"alt.test 5 3 n\r\n.\r\n",
            "GROUP": b"211 2 1 2 comp.lang.python\r\n",
            "OVER": b"224 overview\r\n"
            b"1\tHello\tme@x\tThu, 1 Jan 2026 10:00:00 +0000\t<a@x>\t\t120\t5\r\n"
            b"2\tWorld\tme@x\tThu, 1 Jan 2026 11:00:00 +0000\t<b@x>\t\t220\t9\r\n.\r\n",
            "XOVER": None,
            "ARTICLE": b"220 1 <a@x>\r\nSubject: Hello\r\n\r\nbody\r\n..dot\r\n.\r\n",
            "BODY": b"222 1 <a@x>\r\nbody\r\n.\r\n",
            "HEAD": b"221 1 <a@x>\r\nSubject: Hello\r\n.\r\n",
            "STAT": b"223 1 <a@x>\r\n",
            "DATE": b"111 20260101100000\r\n",
            "QUIT": b"205 bye\r\n",
        }

    def _handle(self, conn: socket.socket) -> None:
        conn.sendall(self.greeting)
        while True:
            raw = recv_line(conn)
            if not raw:
                return
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            self.commands.append(line)
            verb, _, arg = line.partition(" ")
            reply = self.replies.get(verb.upper(), b"500 unknown\r\n")
            if verb.upper() == "XOVER" and reply is None:
                reply = self.replies["OVER"]
            if callable(reply):
                reply = reply(arg)
            if not self._send(conn, reply):
                return
            if verb.upper() == "QUIT":
                return
