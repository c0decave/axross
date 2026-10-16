"""IMAP connection state: a reconnect re-selects, sockets carry a timeout.

* ``_connect()`` kept ``_selected_mailbox`` from the dead connection, so
  after a reconnect ``_select_mailbox`` believed the mailbox was still
  selected and skipped SELECT. The next UID command ran in AUTH state
  and imaplib raised ``command UID illegal in state AUTH`` (not even an
  OSError) until the user happened to open another mailbox.
* Without a proxy, ``IMAP4`` / ``IMAP4_SSL`` were built without
  ``timeout=``: a server that stops answering hung the worker forever.

Driven end to end against an in-process IMAP server on 127.0.0.1.
"""

from __future__ import annotations

import socket
import sys
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.imap_client import ImapSession  # noqa: E402


class _FakeImapServer:
    def __init__(self) -> None:
        self._srv = socket.create_server(("127.0.0.1", 0))
        self.port = self._srv.getsockname()[1]
        self.sessions: list[list[str]] = []
        self._conns: list[socket.socket] = []
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        while True:
            try:
                conn, _ = self._srv.accept()
            except OSError:
                return
            self._conns.append(conn)
            commands: list[str] = []
            self.sessions.append(commands)
            threading.Thread(target=self._session, args=(conn, commands), daemon=True).start()

    @staticmethod
    def _session(conn: socket.socket, commands: list[str]) -> None:
        def send(text: str) -> None:
            conn.sendall(text.encode())

        try:
            send("* OK IMAP4rev1 ready\r\n")
            for raw in conn.makefile("rb"):
                tag, cmd, *_rest = raw.decode().rstrip("\r\n").split(" ", 2) + [""]
                cmd = cmd.upper()
                commands.append(cmd)
                if cmd == "CAPABILITY":
                    send(f"* CAPABILITY IMAP4rev1 UIDPLUS\r\n{tag} OK done\r\n")
                elif cmd == "LIST":
                    send(f'* LIST (\\HasNoChildren) "/" "INBOX"\r\n{tag} OK done\r\n')
                elif cmd in ("SELECT", "EXAMINE"):
                    send(f"* 1 EXISTS\r\n{tag} OK [READ-WRITE] done\r\n")
                elif cmd == "LOGOUT":
                    send(f"* BYE\r\n{tag} OK done\r\n")
                    break
                else:  # LOGIN, NOOP, UID ...
                    send(f"{tag} OK done\r\n")
        except OSError:
            pass
        finally:
            conn.close()

    def drop_connections(self) -> None:
        for c in self._conns:
            try:
                c.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        self._conns.clear()

    def stop(self) -> None:
        self.drop_connections()
        self._srv.close()


class ImapConnectionStateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.srv = _FakeImapServer()
        self.addCleanup(self.srv.stop)
        self.s = ImapSession("127.0.0.1", self.srv.port, "u", "p", use_ssl=False)

    def _wait_for_sessions(self, n: int) -> None:
        for _ in range(200):
            if len(self.srv.sessions) >= n:
                return
            threading.Event().wait(0.01)

    def test_happy_select_once_per_connection(self) -> None:
        self.s._select_mailbox("INBOX", readonly=False)
        self.s._select_mailbox("INBOX", readonly=False)
        self.assertEqual(self.srv.sessions[0].count("SELECT"), 1)

    def test_sad_reconnect_selects_the_mailbox_again(self) -> None:
        self.s._select_mailbox("INBOX", readonly=False)
        self.srv.drop_connections()
        self.s._select_mailbox("INBOX", readonly=False)
        self._wait_for_sessions(2)
        self.assertEqual(len(self.srv.sessions), 2)
        self.assertIn("SELECT", self.srv.sessions[1])

    def test_edge_direct_connection_has_a_socket_timeout(self) -> None:
        timeout = self.s._imap.sock.gettimeout()
        self.assertIsNotNone(timeout)
        self.assertGreater(timeout, 0)


if __name__ == "__main__":
    unittest.main()
