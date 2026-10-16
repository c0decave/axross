"""Recursive FTP delete never follows a symbolic link into its target.

Without MLSD (vsftpd) the only directory probe is ``CWD``, and ``CWD``
into a symlink to a directory succeeds. A recursive delete then walked
into the link and deleted the files of the directory it points to.
Servers that offer MLSD but report a symlink with the type of its target
(ProFTPD without ``FactsOptions UseSlink``) did the same.

Driven end to end against a small FTP server on 127.0.0.1 that serves a
real temporary directory the way vsftpd does: ``CWD`` follows links,
``DELE`` unlinks the link itself, ``RMD`` refuses a link, ``LIST`` prints
``ls -l`` lines.
"""

from __future__ import annotations

import os
import posixpath
import socket
import stat
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import ftp_client as FC  # noqa: E402


class _DirFtpServer:
    """A one-client-at-a-time FTP server over a real directory tree.

    ``mlsd``: ``"none"`` answers MLSD/MLST with 500 (vsftpd);
    ``"follow"`` reports every entry with the type of its target
    (a server that lists symlinks as directories).
    ``list_style``: ``"unix"`` prints ``ls -l`` lines; ``"dos"`` prints
    IIS-style lines that carry no link information.
    """

    def __init__(self, root: Path, mlsd: str = "none", list_style: str = "unix") -> None:
        self.root = root
        self.mlsd = mlsd
        self.list_style = list_style
        self.commands: list[str] = []
        self._lsock = socket.create_server(("127.0.0.1", 0))
        self.port = self._lsock.getsockname()[1]
        self._stop = threading.Event()
        self._conns: list[socket.socket] = []
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._stop.set()
        for c in self._conns:
            try:
                c.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        try:
            # Wakes the accept() the server thread is blocked in.
            socket.create_connection(("127.0.0.1", self.port), timeout=1).close()
        except OSError:
            pass
        self._thread.join(timeout=5)
        self._lsock.close()
        assert not self._thread.is_alive()

    # --- helpers ---------------------------------------------------------

    def _real(self, cwd: str, arg: str) -> tuple[str, str]:
        virt = posixpath.normpath(posixpath.join(cwd, arg or "."))
        if virt.startswith("//"):
            virt = virt[1:]
        return virt, str(self.root) + ("" if virt == "/" else virt)

    def _unix_line(self, real: str, name: str) -> str:
        st = os.lstat(real)
        mtime = time.strftime("%b %d %H:%M", time.localtime(st.st_mtime))
        line = f"{stat.filemode(st.st_mode)}    1 owner    group {st.st_size:>8} {mtime} {name}"
        if stat.S_ISLNK(st.st_mode):
            line += " -> " + os.readlink(real)
        return line

    def _dos_line(self, real: str, name: str) -> str:
        st = os.stat(real) if os.path.exists(real) else os.lstat(real)
        size = "<DIR>" if os.path.isdir(real) else str(st.st_size)
        return f"10-15-26  12:00PM {size:>20} {name}"

    def _mlsd_line(self, real: str, name: str) -> str:
        kind = "dir" if os.path.isdir(real) else "file"  # follows links
        return f"type={kind};size={os.stat(real).st_size}; {name}"

    # --- protocol --------------------------------------------------------

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._lsock.accept()
            except OSError:
                return
            self._conns.append(conn)
            try:
                self._serve(conn)
            except OSError:
                pass
            finally:
                conn.close()

    def _send_data(self, conn, data_l, lines: list[str]) -> None:
        conn.sendall(b"150 here it comes\r\n")
        d, _ = data_l.accept()
        d.sendall("".join(x + "\r\n" for x in lines).encode())
        d.close()
        data_l.close()
        conn.sendall(b"226 done\r\n")

    def _serve(self, conn: socket.socket) -> None:
        cwd = "/"
        data_l = None
        conn.sendall(b"220 fake\r\n")
        f = conn.makefile("rb")
        for raw in f:
            line = raw.decode().rstrip("\r\n")
            verb, _, arg = line.partition(" ")
            verb = verb.upper()
            self.commands.append(line)
            virt, real = self._real(cwd, arg)
            if verb == "USER":
                conn.sendall(b"331 pw\r\n")
            elif verb == "PASS":
                conn.sendall(b"230 in\r\n")
            elif verb in ("OPTS", "TYPE", "NOOP"):
                conn.sendall(b"200 ok\r\n")
            elif verb == "QUIT":
                conn.sendall(b"221 bye\r\n")
                return
            elif verb == "PWD":
                conn.sendall(f'257 "{cwd}"\r\n'.encode())
            elif verb == "CWD":
                if os.path.isdir(real):  # follows symlinks, like chdir()
                    cwd = virt
                    conn.sendall(b"250 ok\r\n")
                else:
                    conn.sendall(b"550 not a dir\r\n")
            elif verb == "PASV":
                if data_l is not None:
                    data_l.close()
                data_l = socket.create_server(("127.0.0.1", 0))
                p = data_l.getsockname()[1]
                conn.sendall(f"227 Passive (127,0,0,1,{p >> 8},{p & 0xFF})\r\n".encode())
            elif verb in ("MLSD", "MLST") and self.mlsd == "none":
                conn.sendall(b"500 unknown command\r\n")
            elif verb == "MLST":
                if os.path.lexists(real):
                    conn.sendall(f"250-x\r\n {self._mlsd_line(real, virt)}\r\n250 end\r\n".encode())
                else:
                    conn.sendall(b"550 no\r\n")
            elif verb in ("MLSD", "NLST", "LIST") and data_l is not None:
                if os.path.isdir(real):
                    names = sorted(os.listdir(real))
                    pairs = [(os.path.join(real, n), n) for n in names]
                elif os.path.lexists(real):
                    pairs = [(real, posixpath.basename(virt))]
                else:
                    data_l.close()
                    data_l = None
                    conn.sendall(b"550 no\r\n")
                    continue
                if verb == "MLSD":
                    out = [self._mlsd_line(r, n) for r, n in pairs]
                elif verb == "NLST":
                    out = [n for _, n in pairs]
                elif self.list_style == "unix":
                    out = ["total 0"] + [self._unix_line(r, n) for r, n in pairs]
                else:
                    out = [self._dos_line(r, n) for r, n in pairs]
                self._send_data(conn, data_l, out)
                data_l = None
            elif verb == "SIZE":
                if os.path.isfile(real):
                    conn.sendall(f"213 {os.path.getsize(real)}\r\n".encode())
                else:
                    conn.sendall(b"550 no\r\n")
            elif verb == "DELE":
                try:
                    os.unlink(real)  # removes the link, never its target
                    conn.sendall(b"250 deleted\r\n")
                except OSError:
                    conn.sendall(b"550 cannot delete\r\n")
            elif verb == "RMD":
                try:
                    os.rmdir(real)
                    conn.sendall(b"250 removed\r\n")
                except OSError:
                    conn.sendall(b"550 cannot remove\r\n")
            else:
                conn.sendall(b"502 not implemented\r\n")


def _tree(tmp_path: Path) -> Path:
    root = tmp_path / "srv"
    (root / "target" / "sub").mkdir(parents=True)
    (root / "target" / "keep1.txt").write_text("1")
    (root / "target" / "sub" / "keep2.txt").write_text("2")
    (root / "doomed" / "inner").mkdir(parents=True)
    (root / "doomed" / "a.txt").write_text("a")
    (root / "doomed" / "inner" / "b.txt").write_text("b")
    os.symlink("../target", root / "doomed" / "link to dir")
    os.symlink("../target/keep1.txt", root / "doomed" / "filelink")
    os.symlink("target", root / "toplink")
    return root


def _target_intact(root: Path) -> bool:
    return (root / "target" / "keep1.txt").is_file() and (
        root / "target" / "sub" / "keep2.txt"
    ).is_file()


@pytest.fixture
def ftp_server(tmp_path):
    servers: list[_DirFtpServer] = []
    sessions: list[FC.FtpSession] = []

    def make(mlsd: str = "none", list_style: str = "unix"):
        root = _tree(tmp_path)
        srv = _DirFtpServer(root, mlsd=mlsd, list_style=list_style)
        servers.append(srv)
        s = FC.FtpSession("127.0.0.1", srv.port, "u", "p")
        sessions.append(s)
        return root, srv, s

    yield make
    for s in sessions:
        s.disconnect()
    for srv in servers:
        srv.close()


# --- happy ----------------------------------------------------------------


def test_happy_no_mlsd_recursive_delete_removes_link_not_target(ftp_server):
    root, _srv, s = ftp_server("none")
    assert s._has_mlsd is False
    s.remove("/doomed", recursive=True)
    assert not (root / "doomed").exists()
    assert _target_intact(root)


def test_happy_plain_tree_is_still_removed_without_mlsd(ftp_server):
    root, _srv, s = ftp_server("none")
    s.remove("/target", recursive=True)
    assert not (root / "target").exists()


def test_happy_fallback_listing_marks_links(ftp_server):
    _root, _srv, s = ftp_server("none")
    items = {i.name: i for i in s.list_dir("/doomed")}
    assert items["link to dir"].is_link
    assert not items["link to dir"].is_dir
    assert items["link to dir"].link_target == "../target"
    assert items["filelink"].is_link
    assert items["inner"].is_dir and not items["inner"].is_link


# --- sad ------------------------------------------------------------------


def test_sad_top_level_link_to_dir_is_unlinked_not_emptied(ftp_server):
    root, _srv, s = ftp_server("none")
    s.remove("/toplink", recursive=True)
    assert not os.path.lexists(root / "toplink")
    assert _target_intact(root)


def test_sad_non_recursive_remove_of_link_to_dir_removes_the_link(ftp_server):
    root, _srv, s = ftp_server("none")
    s.remove("/toplink")
    assert not os.path.lexists(root / "toplink")
    assert _target_intact(root)


def test_sad_mlsd_server_listing_links_as_dirs_does_not_follow(ftp_server):
    root, _srv, s = ftp_server("follow")
    assert s._has_mlsd is True
    s.remove("/doomed", recursive=True)
    assert not (root / "doomed").exists()
    assert _target_intact(root)


def test_sad_uncertain_type_refuses_recursive_delete(ftp_server):
    root, _srv, s = ftp_server("none", list_style="dos")
    with pytest.raises(OSError, match="[Rr]efus"):
        s.remove("/doomed", recursive=True)
    assert _target_intact(root)
    # Nothing was deleted before the refusal.
    assert (root / "doomed" / "a.txt").is_file()
    assert (root / "doomed" / "inner" / "b.txt").is_file()


# --- edge -----------------------------------------------------------------


def test_edge_mlsd_slink_fact_is_a_link() -> None:
    item = FC.FtpSession._mlsd_to_item("l", {"type": "OS.unix=slink:/etc"})
    assert item.is_link and not item.is_dir


def test_edge_unix_list_line_with_spaces_and_arrow_target() -> None:
    lines = [
        "total 2",
        "lrwxrwxrwx    1 owner    group        9 Oct 15 12:00 link to dir -> ../target",
        "drwxr-xr-x    2 owner    group     4096 Jan  1  2025 a b",
        "-rw-r--r--    1 1000     1000         3 Oct 15 12:00 x",
    ]
    parsed = FC._parse_unix_list(lines)
    assert FC._unix_entry(parsed, "link to dir") == ("l", "../target")
    assert FC._unix_entry(parsed, "a b") == ("d", "")
    assert FC._unix_entry(parsed, "x") == ("-", "")
    assert FC._unix_entry(parsed, "b") is None
    assert FC._parse_unix_list(["10-15-26  12:00PM   <DIR>  x"]) is None
    assert FC._parse_unix_list([]) == []


def test_edge_uncertain_type_still_allows_plain_rmdir(ftp_server):
    root, _srv, s = ftp_server("none", list_style="dos")
    (root / "empty").mkdir()
    s.remove("/empty")
    assert not (root / "empty").exists()
