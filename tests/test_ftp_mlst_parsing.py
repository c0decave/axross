"""FTP MLST replies are parsed by their fact line, not by any line with '='.

RFC 3659 7.2: the MLST reply is ``250-<text>``, one fact line that starts
with a single space (``" facts SP pathname"``), then ``250 <text>``. The
server echoes the requested path in the first line, so a path that
contains ``=`` (Hive-style ``date=2024-01-01`` partitions) used to make
``stat`` take that framing line for the fact line: a directory came back
as an empty file.

Driven end to end against a fake control connection on a socketpair.
"""

from __future__ import annotations

import socket
import sys
import threading
import unittest
from ftplib import FTP
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import ftp_client as FC  # noqa: E402


class _FakeMlstServer:
    """Answers NOOP and MLST; MLST echoes the path the way RFC 3659 does."""

    def __init__(self, facts: dict[str, str]) -> None:
        self.facts = facts
        self.client_sock, self._srv = socket.socketpair()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        f = self._srv.makefile("rb")
        for raw in f:
            line = raw.decode().rstrip("\r\n")
            verb, _, arg = line.partition(" ")
            if verb == "NOOP":
                self._srv.sendall(b"200 ok\r\n")
            elif verb == "MLST" and arg in self.facts:
                reply = (
                    f"250-Listing {arg}\r\n {self.facts[arg]} {arg}\r\n250 End\r\n"
                )
                self._srv.sendall(reply.encode())
            else:
                self._srv.sendall(b"550 no such file\r\n")

    def ftp(self) -> FTP:
        ftp = FTP()
        ftp.sock = self.client_sock
        ftp.file = self.client_sock.makefile("r", encoding="utf-8")
        return ftp


def _session(ftp: FTP) -> FC.FtpSession:
    s = FC.FtpSession.__new__(FC.FtpSession)
    s._ftp = ftp
    s._host, s._username = "h", "u"
    s._has_mlsd = True
    return s


class MlstParsingTest(unittest.TestCase):
    def _session_for(self, facts: dict[str, str]) -> FC.FtpSession:
        srv = _FakeMlstServer(facts)
        self.addCleanup(srv.client_sock.close)
        return _session(srv.ftp())

    def test_happy_plain_directory_is_a_directory(self) -> None:
        s = self._session_for({"/data": "type=dir;modify=20260101120000;"})
        item = s.stat("/data")
        self.assertTrue(item.is_dir)
        self.assertEqual(item.modified.year, 2026)

    def test_sad_directory_with_equals_in_name_is_still_a_directory(self) -> None:
        path = "/data/date=2024-01-01"
        s = self._session_for({path: "type=dir;modify=20240101000000;"})
        item = s.stat(path)
        self.assertTrue(item.is_dir)
        self.assertEqual(item.modified.year, 2024)
        self.assertEqual(item.name, "date=2024-01-01")

    def test_sad_file_size_survives_equals_and_space_in_name(self) -> None:
        path = "/in/a b=c.txt"
        s = self._session_for({path: "type=file;size=1234;modify=20250505050505;"})
        item = s.stat(path)
        self.assertFalse(item.is_dir)
        self.assertEqual(item.size, 1234)

    def test_edge_mlst_facts_do_not_absorb_the_pathname(self) -> None:
        path = "/x/k=v; tail"
        s = self._session_for({path: "type=file;size=7;"})
        self.assertEqual(s.mlst(path), {"type": "file", "size": "7"})

    def test_edge_mlst_plain_path(self) -> None:
        s = self._session_for({"/f": "type=file;size=3;"})
        self.assertEqual(s.mlst("/f"), {"type": "file", "size": "3"})


class _FakeMlsdServer:
    """TCP control + PASV data channel; MLSD answers with fixed entry lines."""

    def __init__(self, entries: list[str]) -> None:
        self.entries = entries
        self._lsock = socket.create_server(("127.0.0.1", 0))
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        self.client_sock = socket.create_connection(self._lsock.getsockname(), timeout=5)

    def _serve(self) -> None:
        conn, _ = self._lsock.accept()
        self._lsock.close()
        data_l = None
        f = conn.makefile("rb")
        for raw in f:
            verb = raw.decode().rstrip("\r\n").partition(" ")[0]
            if verb == "NOOP":
                conn.sendall(b"200 ok\r\n")
            elif verb in ("TYPE", "OPTS"):
                conn.sendall(b"200 ok\r\n")
            elif verb == "PASV":
                data_l = socket.create_server(("127.0.0.1", 0))
                port = data_l.getsockname()[1]
                conn.sendall(
                    f"227 Entering Passive Mode (127,0,0,1,{port >> 8},{port & 0xFF})\r\n".encode()
                )
            elif verb == "MLSD" and data_l is not None:
                conn.sendall(b"150 here it comes\r\n")
                d, _ = data_l.accept()
                d.sendall("".join(e + "\r\n" for e in self.entries).encode())
                d.close()
                data_l.close()
                data_l = None
                conn.sendall(b"226 done\r\n")
            else:
                conn.sendall(b"502 no\r\n")
        conn.close()

    def ftp(self) -> FTP:
        ftp = FTP()
        ftp.sock = self.client_sock
        ftp.af = socket.AF_INET
        ftp.file = self.client_sock.makefile("r", encoding="utf-8")
        ftp.passiveserver = True
        return ftp


class MlsdListingTest(unittest.TestCase):
    def _names(self, entries: list[str]) -> list[str]:
        srv = _FakeMlsdServer(entries)
        self.addCleanup(srv.client_sock.close)
        s = _session(srv.ftp())
        return sorted(i.name for i in s.list_dir("/tmp"))

    def test_happy_children_are_listed(self) -> None:
        self.assertEqual(
            self._names(["type=file;size=3; a.txt", "type=dir; sub"]),
            ["a.txt", "sub"],
        )

    def test_sad_rfc3659_cdir_entries_are_not_children(self) -> None:
        # Verbatim shape of the RFC 3659 7.6.2 example listing.
        entries = [
            "Type=cdir;Modify=19981107085215;Perm=el; tmp",
            "Type=cdir;Unique=keVO1+ZF4;Modify=19990112030508;Perm=el; /tmp",
            "Type=pdir;Modify=19990112030508;Perm=el; ..",
            "Type=file;Size=25730;Modify=19940728095854;Perm=; capmux.tar.z",
        ]
        self.assertEqual(self._names(entries), ["capmux.tar.z"])

    def test_edge_dot_entries_without_type_are_still_dropped(self) -> None:
        self.assertEqual(
            self._names(["size=0; .", "size=0; ..", "type=file;size=1; x"]),
            ["x"],
        )


if __name__ == "__main__":
    unittest.main()
