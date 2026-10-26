"""remove() on every backend family the same way - a matrix over LocalFS,
RamFS and the shell backends (SCP, Telnet, rsh, ADB), whose commands run in
the local /bin/sh with GNU ls, as in tests/test_shell_listing_follows_a_
symlinked_folder.py. The pane deletes a listed entry with
``remove(path, recursive=item.is_dir)`` (ui/file_pane.py), the trash and
FUSE call it too.

Bug found with it: SCP and Telnet could not delete a symlink to a folder.
Their listing marks the link as no folder (``ls -la``: type ``l``), so the
pane asks for a non-recursive remove; remove() then tested ``test -d``,
which follows the link, and ran ``rmdir`` on it - "rmdir: failed to
remove ...: Not a directory". A link is now removed as a file, and never
through to the folder it points to.
"""

from __future__ import annotations

import os
import subprocess
import threading

import pytest

from core.adb_client import AdbSession
from core.local_fs import LocalFS
from core.ram_fs import RamFsSession
from core.rsh_client import RshSession
from core.scp_client import SCPSession, _Capabilities
from core.telnet_client import TelnetSession

_ENV = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C.UTF-8"}


def _sh(cmd: str) -> subprocess.CompletedProcess:
    return subprocess.run(["sh", "-c", cmd], capture_output=True, env=_ENV, timeout=30)


def _exec_pair(session):
    def run(cmd, timeout=30, stdin_data=None):
        p = _sh(cmd)
        if p.returncode != 0:
            raise OSError(f"Command failed (exit {p.returncode}): {p.stderr.decode()}")
        return p.stdout.decode()

    def raw(cmd, timeout=30, stdin_data=None):
        p = _sh(cmd)
        return (p.stdout + p.stderr).decode(), p.returncode

    session._exec = run
    session._exec_raw = raw
    return session


def _scp():
    s = object.__new__(SCPSession)
    s._caps = _Capabilities(has_env_prefix=False)
    return _exec_pair(s)


def _telnet():
    return _exec_pair(object.__new__(TelnetSession))


def _rsh():
    s = object.__new__(RshSession)

    def run_remote(cmd, *, stdin=None):
        p = _sh(cmd)
        if p.returncode != 0:
            raise OSError(p.stderr.decode())
        return p.stdout

    s._run_remote = run_remote
    return s


def _adb():
    s = object.__new__(AdbSession)
    s._conn_lock = threading.Lock()

    def shell(cmd):
        # adb shell has one stream and no exit status
        p = _sh(cmd.replace("ls -la", "ls -la --time-style=long-iso", 1))
        return (p.stdout + p.stderr).decode()

    s._shell = shell
    return s


class Disk:
    """A backend over a real folder (or RamFS) with the helpers the
    matrix needs."""

    def __init__(self, kind: str, tmp_path) -> None:
        self.kind = kind
        self.symlinks = kind != "ramfs"
        if kind == "ramfs":
            self.b = RamFsSession(f"rm-{id(self)}")
            self.root = "/t"
            self.b.mkdir(self.root)
        else:
            self.b = {"localfs": LocalFS, "scp": _scp, "telnet": _telnet, "rsh": _rsh, "adb": _adb}[
                kind
            ]()
            self.root = str(tmp_path / "t")
            os.mkdir(self.root)

    def p(self, rel: str) -> str:
        return self.root + "/" + rel

    def mkdir(self, rel: str) -> None:
        if self.kind == "ramfs":
            self.b.mkdir(self.p(rel))
        else:
            os.mkdir(self.p(rel))

    def write(self, rel: str, data: bytes = b"x") -> None:
        if self.kind == "ramfs":
            with self.b.open_write(self.p(rel)) as fh:
                fh.write(data)
        else:
            with open(self.p(rel), "wb") as fh:
                fh.write(data)

    def there(self, rel: str) -> bool:
        if self.kind == "ramfs":
            return self.b.exists(self.p(rel))
        return os.path.lexists(self.p(rel))


KINDS = ["localfs", "ramfs", "scp", "telnet", "rsh", "adb"]


@pytest.fixture(params=KINDS)
def disk(request, tmp_path):
    d = Disk(request.param, tmp_path)
    yield d
    if d.kind == "ramfs":
        d.b.disconnect()


# ------------------------------------------------------------------ happy
def test_happy_a_file_is_removed(disk):
    disk.write("f.txt")
    disk.b.remove(disk.p("f.txt"))
    assert not disk.there("f.txt")


def test_happy_an_empty_folder_is_removed_without_recursive(disk):
    disk.mkdir("empty")
    disk.b.remove(disk.p("empty"))
    assert not disk.there("empty")


def test_happy_a_tree_is_removed_recursively(disk):
    disk.mkdir("tree")
    disk.mkdir("tree/sub")
    disk.write("tree/sub/deep.txt")
    disk.write("tree/top.txt")
    disk.b.remove(disk.p("tree"), recursive=True)
    assert not disk.there("tree")


def test_happy_e2e_a_symlink_to_a_folder_is_deleted_as_the_pane_deletes_it(disk):
    """The pane passes recursive=item.is_dir; a listed link is no folder."""
    if not disk.symlinks:
        pytest.skip("RamFS has no symlinks")
    disk.mkdir("real")
    disk.write("real/keep.txt", b"KEEP")
    os.symlink("real", disk.p("link"))
    listed = {i.name: i for i in disk.b.list_dir(disk.root)}
    assert listed["link"].is_link and not listed["link"].is_dir
    disk.b.remove(disk.p("link"), recursive=listed["link"].is_dir)
    assert not disk.there("link")
    assert disk.there("real/keep.txt")


# -------------------------------------------------------------------- sad
def test_sad_a_full_folder_without_recursive_is_refused_and_kept(disk):
    disk.mkdir("full")
    disk.write("full/keep.txt")
    with pytest.raises(OSError):
        disk.b.remove(disk.p("full"))
    assert disk.there("full/keep.txt")


# ------------------------------------------------------------------- edge
def test_edge_a_recursive_remove_of_a_folder_link_never_empties_the_target(disk):
    if not disk.symlinks:
        pytest.skip("RamFS has no symlinks")
    disk.mkdir("real")
    disk.write("real/keep.txt", b"KEEP")
    os.symlink("real", disk.p("link"))
    disk.b.remove(disk.p("link"), recursive=True)
    assert not disk.there("link")
    assert disk.there("real/keep.txt")


def test_edge_a_dangling_symlink_is_removed(disk):
    if not disk.symlinks:
        pytest.skip("RamFS has no symlinks")
    os.symlink("nowhere", disk.p("dangling"))
    disk.b.remove(disk.p("dangling"))
    assert not disk.there("dangling")


def test_edge_names_with_spaces_quotes_and_a_leading_dash(disk):
    for name in ("with space.txt", "it's.txt", "-dash.txt"):
        disk.write(name)
        disk.b.remove(disk.p(name))
        assert not disk.there(name), name


@pytest.mark.parametrize("recursive", [False, True])
@pytest.mark.parametrize("kind", ["file", "folder"])
def test_edge_a_relative_name_with_a_leading_dash_is_a_name_not_an_option(
    tmp_path, kind, recursive
):
    """remove_command ends the options with ``--``: rsh's path guard asks
    every caller to, and a Telnet path is not made absolute."""
    from core.telnet_client import remove_command

    target = tmp_path / "-rf"
    if kind == "folder":
        target.mkdir()
    else:
        target.write_text("x")
    cmd = remove_command("-rf", recursive=recursive)
    p = subprocess.run(["sh", "-c", cmd], cwd=tmp_path, capture_output=True, env=_ENV)
    assert p.returncode == 0, p.stderr
    assert not os.path.lexists(target)
