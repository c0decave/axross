"""Round-5 security: archive extraction (MCP archive_extract, the GUI) and
the MCP writers that create new files are confined.

core.archive wrote each member by path (os.makedirs + os.open with
O_TRUNC, no O_NOFOLLOW, no dir_fd): another process writing in the same
tree swapped a folder the extraction had just created for a symlink to
``~/.config/autostart`` between the zip-slip check and the write, and the
next members landed there; a hard link planted at a member's name had the
outside file truncated and overwritten. Now every folder and file is made
beneath a descriptor of the new target (core.archive._Sink,
core.confined_fs.makedirs_beneath / open_beneath), files with O_EXCL.
mcp_groups._place_new opened by path with O_NOFOLLOW on the last component
only; it now creates through ConfinedLocalFS.create_new. The packer built
a confined backend's archive by path in the folder; now in its private
staging folder, placed with create_new."""

from __future__ import annotations

import os
import sys
import tarfile
import time
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import archive as A  # noqa: E402
from core import confined_fs as CF  # noqa: E402

posix_fd = pytest.mark.skipif(not CF.FD_CONFINED, reason="dir_fd confinement (POSIX)")


def _zip(path: Path, members: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w") as z:
        for name, data in members.items():
            z.writestr(name, data)
    return path


def _swap_before(monkeypatch, member: str, action):
    """Run *action()* right after *member* passed the zip-slip check and
    before it is written (the window another process races for)."""
    real = A._check_duplicate_member

    def hook(seen, dest, name):
        real(seen, dest, name)
        if name == member:
            action()
    monkeypatch.setattr(A, "_check_duplicate_member", hook)


# -- happy ------------------------------------------------------------------------------

def test_happy_zip_and_tar_still_extract_with_mode_and_time(tmp_path):
    arc = tmp_path / "a.zip"
    with zipfile.ZipFile(arc, "w") as z:
        info = zipfile.ZipInfo("d/run.sh", date_time=(2020, 1, 2, 3, 4, 6))
        info.create_system = 3
        info.external_attr = (0o100750) << 16
        z.writestr(info, b"#!/bin/sh\n")
        z.writestr("d/e/", b"")
        z.writestr("top.txt", b"top")
    out = tmp_path / "out"
    assert A.extract(str(arc), str(out)) == 2
    st = (out / "d" / "run.sh").stat()
    assert st.st_mode & 0o700 == 0o700 and not st.st_mode & 0o002
    assert time.localtime(st.st_mtime)[:5] == (2020, 1, 2, 3, 4)
    assert (out / "d" / "e").is_dir() and (out / "top.txt").read_bytes() == b"top"

    tgz = tmp_path / "b.tar.gz"
    src = tmp_path / "src"
    (src / "x").mkdir(parents=True)
    (src / "x" / "f").write_bytes(b"f")
    with tarfile.open(tgz, "w:gz") as tf:
        tf.add(src / "x", arcname="x")
    assert A.extract(str(tgz), str(tmp_path / "out2")) == 1
    assert (tmp_path / "out2" / "x" / "f").read_bytes() == b"f"


@posix_fd
def test_happy_extract_beneath_a_confined_backend(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    arc = _zip(root / "a.zip", {"sub/f.txt": b"x"})
    fs = CF.ConfinedLocalFS([str(root)])
    assert A.extract(str(arc), str(root / "a"), parent_dir=fs.parent_dir) == 1
    assert (root / "a" / "sub" / "f.txt").read_bytes() == b"x"
    assert A.extract_members(str(arc), str(root / "b"), ["sub/f.txt"],
                             parent_dir=fs.parent_dir) == 1


# -- sad --------------------------------------------------------------------------------

@posix_fd
def test_sad_a_folder_swapped_for_a_symlink_is_not_followed(tmp_path, monkeypatch):
    outside = tmp_path / "autostart"
    outside.mkdir()
    arc = _zip(tmp_path / "a.zip", {"sub/a.desktop": b"a", "sub/b.desktop": b"b"})
    out = tmp_path / "out"

    def swap():
        os.rename(out / "sub", out / "sub.moved")
        os.symlink(outside, out / "sub")
    _swap_before(monkeypatch, "sub/b.desktop", swap)
    with pytest.raises(A.UnsafeArchive, match="symbolic link"):
        A.extract(str(arc), str(out))
    assert os.listdir(outside) == []
    assert not out.exists()


@posix_fd
def test_sad_a_planted_hard_link_is_not_written_through(tmp_path, monkeypatch):
    victim = tmp_path / "bashrc"
    victim.write_bytes(b"original\n")
    arc = _zip(tmp_path / "a.zip", {"sub/a": b"a", "sub/b": b"evil\n"})
    out = tmp_path / "out"
    _swap_before(monkeypatch, "sub/b", lambda: os.link(victim, out / "sub" / "b"))
    with pytest.raises(A.UnsafeArchive, match="appeared"):
        A.extract(str(arc), str(out))
    assert victim.read_bytes() == b"original\n"


@posix_fd
def test_sad_place_new_does_not_follow_a_swapped_folder(tmp_path):
    from core import mcp_groups as G

    root = tmp_path / "root"
    (root / "w").mkdir(parents=True)
    outside = tmp_path / "autostart"
    outside.mkdir()
    fs = CF.ConfinedLocalFS([str(root)])

    class Env:
        def write_path(self, path, backend):
            # The check passed; then another process swaps the folder.
            if not os.path.islink(root / "w"):
                os.rename(root / "w", root / "w.moved")
                os.symlink(outside, root / "w")
            return path

    with pytest.raises(PermissionError):
        G._place_new(Env(), fs, str(root / "w" / "x.desktop"), b"[Desktop Entry]\n")
    assert os.listdir(outside) == []


# -- edge -------------------------------------------------------------------------------

@posix_fd
def test_edge_the_packer_builds_a_confined_archive_off_the_folder(tmp_path):
    from core import packer as PK

    root = tmp_path / "root"
    (root / "d").mkdir(parents=True)
    (root / "d" / "f.txt").write_bytes(b"hello")
    fs = CF.ConfinedLocalFS([str(root)])
    assert not PK._is_local(fs)                      # built in staging, placed by create_new
    result = PK.pack(fs, str(root / "d"), ["f.txt"], "bundle", PK.PackOptions(fmt="zip"))
    assert result.path == str(root / "d" / "bundle.zip")
    with zipfile.ZipFile(result.path) as z:
        assert z.read("f.txt") == b"hello"
    again = PK.pack(fs, str(root / "d"), ["f.txt"], "bundle", PK.PackOptions(fmt="zip"))
    assert again.path == str(root / "d" / "bundle (2).zip")
    assert sorted(os.listdir(root / "d")) == ["bundle (2).zip", "bundle.zip", "f.txt"]


@posix_fd
def test_edge_create_new_refuses_an_existing_name_and_a_link(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    (root / "taken").write_bytes(b"x")
    os.symlink(tmp_path, root / "link")
    fs = CF.ConfinedLocalFS([str(root)])
    with pytest.raises(FileExistsError):
        fs.create_new(str(root / "taken"))
    with pytest.raises(PermissionError):
        fs.create_new(str(root / "link" / "x"))
    with fs.create_new(str(root / "new"), 0o600) as fh:
        fh.write(b"n")
    assert (root / "new").stat().st_mode & 0o777 == 0o600


def test_edge_member_parts_normalise_and_refuse_escapes():
    assert A._member_parts("a/./b/../c") == ["a", "c"]
    assert A._member_parts("./") == []
    for bad in ("../x", "a/../../x", "/etc/x"):
        with pytest.raises(A.UnsafeArchive):
            A._member_parts(bad)
