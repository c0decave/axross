"""A 7z whose folders are stored read-only (0555) or closed to listing
(0300, 0100) is extracted whole and leaves no temp folder: py7zr gives every member its
stored mode in the staging folder, whose walk then skipped a folder it
could not enter (files missing, success reported) and whose removal could
not empty a read-only one (up to a gigabyte left in /tmp). Needs a process
that folder rights apply to (not a root let in everywhere)."""
from __future__ import annotations

import os
import stat
import tempfile

import pytest

from core import archive as AR

py7zr = pytest.importorskip("py7zr")
pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX modes")


def _rights_are_checked(base: str) -> bool:
    """Whether this process is refused a folder it closed (not so for a
    root with CAP_DAC_OVERRIDE)."""
    probe = os.path.join(base, "probe")
    os.mkdir(probe, 0o000)
    try:
        os.listdir(probe)
        return False
    except PermissionError:
        return True
    finally:
        os.chmod(probe, 0o700)
        os.rmdir(probe)


@pytest.fixture
def base(tmp_path, monkeypatch):
    if not _rights_are_checked(str(tmp_path)):
        pytest.skip("this process is let into every folder")
    temp_root = tmp_path / "tmp"
    temp_root.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(temp_root))
    yield tmp_path
    for dirpath, dirnames, _ in os.walk(tmp_path):
        for d in dirnames:
            os.chmod(os.path.join(dirpath, d), stat.S_IRWXU)


@pytest.mark.parametrize("folder_mode", [0o555, 0o300, 0o100])
def test_sad_a_closed_folder_is_extracted_whole(base, folder_mode):
    src = base / "src"
    (src / "locked").mkdir(parents=True)
    (src / "inside.txt").write_text("inside")
    archive = base / "a.7z"
    os.chmod(src / "locked", folder_mode)  # an empty folder: its mode is stored
    with py7zr.SevenZipFile(archive, "w") as zf:
        zf.write(src / "locked", "locked")
        zf.write(src / "inside.txt", "locked/inside.txt")
    os.chmod(src / "locked", 0o755)
    out = base / "out"
    AR.extract(str(archive), str(out))
    os.chmod(out / "locked", 0o700)  # to look inside
    assert (out / "locked" / "inside.txt").read_text() == "inside"
    assert os.listdir(base / "tmp") == []


def test_sad_a_folder_stored_0000_is_extracted_whole(base):
    """py7zr's own writing could not finish one (it closed the folder, then
    set the time of a file inside); axross writes the members itself and
    sets the folder's mode last."""
    src = base / "src"
    (src / "locked").mkdir(parents=True)
    (src / "inside.txt").write_text("inside")
    archive = base / "a.7z"
    os.chmod(src / "locked", 0o000)
    with py7zr.SevenZipFile(archive, "w") as zf:
        zf.write(src / "locked", "locked")
        zf.write(src / "inside.txt", "locked/inside.txt")
    os.chmod(src / "locked", 0o755)
    out = base / "out"
    assert AR.extract(str(archive), str(out)) == 1
    os.chmod(out / "locked", 0o700)
    assert (out / "locked" / "inside.txt").read_text() == "inside"
    assert os.listdir(base / "tmp") == []


def test_sad_a_7z_with_too_many_members_is_refused_before_its_listing(tmp_path, monkeypatch):
    archive = tmp_path / "many.7z"
    with py7zr.SevenZipFile(archive, "w") as zf:
        for n in range(30):
            zf.writestr(b"x", f"m{n}")
    monkeypatch.setattr(AR, "MAX_LIST_ENTRIES", 20)
    monkeypatch.setattr(AR, "MAX_EXTRACT_FILES", 20)
    made = []
    monkeypatch.setattr(py7zr.SevenZipFile, "list",
                        lambda self: made.append(1) or [])
    with pytest.raises(AR.UnsafeArchive, match="30 entries"):
        AR.list_archive(str(archive))
    with pytest.raises(AR.UnsafeArchive, match="30 entries"):
        AR.extract(str(archive), str(tmp_path / "out"))
    assert made == []
