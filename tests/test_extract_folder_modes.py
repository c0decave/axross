"""Extract gives each folder the mode the archive stores for it.

Review: every extracted folder came out 0755 (the default less the umask):
a 0700 folder of the archive - from system tar or axross's own Pack -
arrived open, and the 0644 files in it, private through their folder
before, readable to everyone. Now each folder member's mode applies, less
the umask - set once everything is written (a 0500 folder still gets its
files), and also for a folder made earlier for a file inside it.
"""

from __future__ import annotations

import io
import os
import stat
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import archive as A  # noqa: E402

pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX modes")


@pytest.fixture
def umask_022():
    old = os.umask(0o022)
    yield
    os.umask(old)


def _mode(path: Path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


def _tar(path: Path, entries) -> Path:
    """*entries*: (name, mode, data or None for a folder), in this order."""
    with tarfile.open(path, "w:gz") as tf:
        for name, mode, data in entries:
            info = tarfile.TarInfo(name)
            info.mode = mode
            if data is None:
                info.type = tarfile.DIRTYPE
                tf.addfile(info)
            else:
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
    return path


def test_happy_a_private_folder_stays_private(tmp_path, umask_022):
    archive = _tar(tmp_path / "s.tar.gz", [("secret", 0o700, None),
                                           ("secret/notes.txt", 0o644, b"private")])
    out = tmp_path / "out"
    A.extract(str(archive), str(out))
    assert _mode(out / "secret") == 0o700
    assert (out / "secret" / "notes.txt").read_bytes() == b"private"


def test_edge_a_folder_made_for_a_file_before_its_entry_gets_its_mode(tmp_path, umask_022):
    archive = _tar(tmp_path / "s.tar.gz", [("d/sub/f.txt", 0o644, b"x"),
                                           ("d/sub", 0o750, None),
                                           ("d", 0o711, None)])
    out = tmp_path / "out"
    A.extract(str(archive), str(out))
    assert _mode(out / "d") == 0o711
    assert _mode(out / "d" / "sub") == 0o750


def test_edge_a_read_only_folder_still_gets_its_files(tmp_path, umask_022):
    archive = _tar(tmp_path / "s.tar.gz", [("ro", 0o500, None), ("ro/f.txt", 0o644, b"x")])
    out = tmp_path / "out"
    try:
        A.extract(str(archive), str(out))
        assert (out / "ro" / "f.txt").read_bytes() == b"x"
        assert _mode(out / "ro") == 0o500
    finally:
        if (out / "ro").exists():
            os.chmod(out / "ro", 0o700)


def test_sad_the_umask_still_applies(tmp_path):
    archive = _tar(tmp_path / "s.tar.gz", [("open", 0o777, None), ("open/f", 0o666, b"x")])
    old = os.umask(0o027)
    try:
        A.extract(str(archive), str(tmp_path / "out"))
    finally:
        os.umask(old)
    assert _mode(tmp_path / "out" / "open") == 0o750


def test_happy_a_zip_folder_keeps_its_mode(tmp_path, umask_022):
    path = tmp_path / "s.zip"
    with zipfile.ZipFile(path, "w") as zf:
        info = zipfile.ZipInfo("secret/")
        info.create_system = 3
        info.external_attr = ((stat.S_IFDIR | 0o700) << 16) | 0x10
        zf.writestr(info, b"")
        member = zipfile.ZipInfo("secret/notes.txt")
        member.create_system = 3
        member.external_attr = (stat.S_IFREG | 0o644) << 16
        zf.writestr(member, b"private")
    out = tmp_path / "out"
    A.extract(str(path), str(out))
    assert _mode(out / "secret") == 0o700
