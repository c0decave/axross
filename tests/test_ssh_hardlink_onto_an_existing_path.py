"""SSH hardlink() onto a path that exists is FileExistsError.

hardlink() ran a plain ``ln -- target link_path``. With a FOLDER at
link_path, ``ln`` makes the link inside it (``photos/data.bin``) and
exits 0, so hardlink() reported success for a link that is not where the
caller asked. (``ln -T`` refuses that, but is GNU only.) The remote shell
now tests the link path first; an existing file, folder or dangling
symlink there is FileExistsError, as link(2).
"""

from __future__ import annotations

import os

import pytest

from core.ssh_client import SSHSession
from tests.ssh_exec_testkit import ExecServer


@pytest.fixture
def ssh(tmp_path):
    (tmp_path / "data.bin").write_text("x")
    (tmp_path / "photos").mkdir()
    srv = ExecServer(shell=True, cwd=str(tmp_path))
    s = SSHSession.__new__(SSHSession)
    s._transport = srv.client_transport()
    try:
        yield s, tmp_path
    finally:
        srv.close()


# -- happy -------------------------------------------------------------------


def test_happy_a_free_name_gets_the_link(ssh):
    s, root = ssh
    s.hardlink(str(root / "data.bin"), str(root / "copy.bin"))
    assert os.path.samefile(root / "data.bin", root / "copy.bin")


# -- sad ---------------------------------------------------------------------


def test_sad_an_existing_folder_is_refused_and_nothing_lands_inside(ssh):
    s, root = ssh
    with pytest.raises(FileExistsError):
        s.hardlink(str(root / "data.bin"), str(root / "photos"))
    assert os.listdir(root / "photos") == []


def test_sad_an_existing_file_is_refused(ssh):
    s, root = ssh
    (root / "other.bin").write_text("keep")
    with pytest.raises(FileExistsError):
        s.hardlink(str(root / "data.bin"), str(root / "other.bin"))
    assert (root / "other.bin").read_text() == "keep"


# -- edge --------------------------------------------------------------------


def test_edge_a_dangling_symlink_counts_as_taken(ssh):
    s, root = ssh
    os.symlink(root / "nowhere", root / "dangling")
    with pytest.raises(FileExistsError):
        s.hardlink(str(root / "data.bin"), str(root / "dangling"))
    assert os.path.islink(root / "dangling")


def test_edge_a_missing_target_is_still_an_oserror(ssh):
    s, root = ssh
    with pytest.raises(OSError) as info:
        s.hardlink(str(root / "missing.bin"), str(root / "x.bin"))
    assert not isinstance(info.value, FileExistsError)
