"""SMB keeps the type of an error: smbprotocol's NT status reaches the
caller as FileNotFoundError / FileExistsError / NotADirectoryError /
IsADirectoryError / PermissionError with its errno.

SmbSession wrapped every failure as ``OSError(f"...: {e}")``: errno None,
so "not there" (stat, remove, open_read of a missing path), "exists"
(mkdir, rename) and "denied" looked alike. The transfer engine, the pane
and FUSE (which then answered ENOENT for a denied or dropped stat - see
tests/test_fuse_untyped_stat_error.py) could not tell them apart. And
smbclient normalizes a trailing backslash away, so a write or a rename to
"t/" made a FILE t and stat("g/") answered with the file g.

smbclient is replaced by tests/smb_fake_client.LocalSmbClient: a folder,
answered with the SMBOSError smbprotocol raises for each NT status.
"""

from __future__ import annotations

import errno
import os
import sys
from pathlib import Path

import pytest

pytest.importorskip("smbprotocol")
sys.path.insert(0, str(Path(__file__).resolve().parent))

from smb_fake_client import make_local_session  # noqa: E402
from smbprotocol.exceptions import SMBConnectionClosed, SMBOSError  # noqa: E402
from smbprotocol.header import NtStatus  # noqa: E402

from core import fuse_mount, smb_client  # noqa: E402


@pytest.fixture
def smb(tmp_path, monkeypatch):
    root = tmp_path / "share"
    (root / "d" / "sub").mkdir(parents=True)
    (root / "d" / "f").write_bytes(b"hello")
    (root / "g").write_bytes(b"other")
    s, fake = make_local_session(str(root))
    monkeypatch.setattr(smb_client, "smbclient", fake)
    return s, fake, root


def test_sad_not_found_is_file_not_found_with_its_errno(smb):
    s, _fake, _root = smb
    for call in (lambda: s.stat("/nope"), lambda: s.remove("/nope"),
                 lambda: s.remove("/nope", recursive=True), lambda: s.open_read("/nope"),
                 lambda: s.list_dir("/nope"), lambda: s.stat("/nothing/")):
        with pytest.raises(FileNotFoundError) as ctx:
            call()
        assert ctx.value.errno == errno.ENOENT
        assert "NtStatus 0xc0000034" in str(ctx.value)


def test_sad_exists_and_kind_errors_keep_their_class(smb):
    s, _fake, root = smb
    with pytest.raises(FileExistsError):
        s.mkdir("/d")
    with pytest.raises(NotADirectoryError):
        s.list_dir("/g")
    os.symlink(root / "nowhere", root / "dangling")
    with pytest.raises(FileExistsError):
        s.rename("/g", "/dangling")
    assert (root / "g").read_bytes() == b"other"


def test_sad_access_denied_is_permission_error_and_not_not_found(smb):
    s, fake, _root = smb

    def denied(unc, **_kw):
        raise SMBOSError(NtStatus.STATUS_ACCESS_DENIED, unc)

    fake.stat = denied
    with pytest.raises(PermissionError) as ctx:
        s.stat("/g")
    assert ctx.value.errno == errno.EACCES
    assert fuse_mount._stat_errno(ctx.value) == errno.EACCES


def test_edge_a_closed_connection_is_eio_on_a_mount(smb):
    s, fake, _root = smb

    def closed(unc, **_kw):
        raise SMBConnectionClosed("SMB socket was closed")

    fake.stat = closed
    with pytest.raises(OSError) as ctx:
        s.stat("/g")
    assert not isinstance(ctx.value, FileNotFoundError)
    assert fuse_mount._stat_errno(ctx.value) == errno.EIO


def test_sad_a_path_ending_in_a_slash_names_a_folder(smb):
    s, _fake, root = smb
    with pytest.raises(IsADirectoryError):
        with s.open_write("/t/") as fh:
            fh.write(b"data")
    assert not (root / "t").exists()
    with pytest.raises(IsADirectoryError):
        s.rename("/g", "/x/")
    assert (root / "g").read_bytes() == b"other" and not (root / "x").exists()
    with pytest.raises(NotADirectoryError):
        s.stat("/g/")
    with pytest.raises(NotADirectoryError):
        s.open_read("/g/")


def test_happy_folders_keep_working_with_a_slash(smb):
    s, _fake, root = smb
    assert s.stat("/d/").is_dir
    s.rename("/d", "/e/")  # a folder may be renamed to "e/", as rename(2) allows
    assert (root / "e" / "f").read_bytes() == b"hello"
    with s.open_read("/e/f") as fh:
        assert fh.read() == b"hello"
