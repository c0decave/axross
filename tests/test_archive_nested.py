"""Archives inside archives, single members and member properties.

Operator (punch list 17): "tars/zips IN tars/zips also nested sollen auch
viewbar und extrahierbar sein"; (18): "in tars / zips auf einzelne dateien
klicken und extrahieren erlauben oder info properties ...".

Before, double-clicking a zip inside a tar in the archive preview opened it
in the hex viewer, a member had no right-click menu and no properties, and
Extract Selected always went next to the archive file on disk.
"""

from __future__ import annotations

import io
import os
import sys
import tarfile
import time
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import archive as ARCH  # noqa: E402


def _zip_bytes(members: dict[str, bytes], *, mode: int | None = None) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in members.items():
            info = zipfile.ZipInfo(name, date_time=(2024, 5, 6, 7, 8, 10))
            info.create_system = 3
            info.external_attr = ((mode if mode is not None else 0o100644) & 0xFFFF) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, data)
    return buf.getvalue()


def _tar_bytes(members: dict[str, bytes], *, compression: str = "") -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode=f"w:{compression}" if compression else "w") as tf:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o640
            info.mtime = 1_700_000_000
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


@pytest.fixture
def chain(tmp_path):
    """outer.tar holding inner.zip holding deep.tar.gz holding leaf.txt."""
    deep = _tar_bytes({"leaf.txt": b"leaf payload"}, compression="gz")
    inner = _zip_bytes({"note.txt": b"inside the zip", "deep.tar.gz": deep})
    outer = tmp_path / "data" / "outer.tar"
    outer.parent.mkdir()
    outer.write_bytes(_tar_bytes({"docs/inner.zip": inner, "readme.txt": b"top level"}))
    return outer


# --- core: happy -----------------------------------------------------------


def test_happy_a_zip_in_a_tar_is_extracted_for_viewing(chain, tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    path = ARCH.extract_nested_archive(str(chain), "docs/inner.zip", str(work), depth=1)
    assert os.path.basename(path) == "inner.zip" and path.startswith(str(work))
    names = {e.name for e in ARCH.list_archive(path)}
    assert names == {"note.txt", "deep.tar.gz"}


def test_happy_a_tar_gz_in_a_zip_in_a_tar(chain, tmp_path):
    work1, work2 = tmp_path / "w1", tmp_path / "w2"
    work1.mkdir()
    work2.mkdir()
    inner = ARCH.extract_nested_archive(str(chain), "docs/inner.zip", str(work1), depth=1)
    deep = ARCH.extract_nested_archive(inner, "deep.tar.gz", str(work2), depth=2)
    assert [e.name for e in ARCH.list_archive(deep)] == ["leaf.txt"]


def test_happy_listing_carries_mode_and_kind(tmp_path):
    zp = tmp_path / "m.zip"
    zp.write_bytes(_zip_bytes({"run.sh": b"#!/bin/sh\n"}, mode=0o100755))
    (entry,) = ARCH.list_archive(str(zp))
    assert entry.mode == 0o755 and entry.kind == "file"
    tp = tmp_path / "m.tar"
    with tarfile.open(tp, "w") as tf:
        info = tarfile.TarInfo("link")
        info.type = tarfile.SYMTYPE
        info.linkname = "target.txt"
        tf.addfile(info)
        dinfo = tarfile.TarInfo("d")
        dinfo.type = tarfile.DIRTYPE
        dinfo.mode = 0o750
        tf.addfile(dinfo)
    entries = {e.name: e for e in ARCH.list_archive(str(tp))}
    assert entries["link"].kind == "symlink"
    assert entries["d/"].kind == "dir" and entries["d/"].mode == 0o750


# --- core: sad -------------------------------------------------------------


def test_sad_deeper_than_the_limit_is_refused(chain, tmp_path):
    with pytest.raises(ARCH.UnsafeArchive, match="nested"):
        ARCH.extract_nested_archive(
            str(chain), "docs/inner.zip", str(tmp_path), depth=ARCH.MAX_NESTED_DEPTH + 1
        )
    assert list(tmp_path.iterdir()) == [chain.parent]


def test_sad_a_member_larger_than_the_cap_is_refused(chain, tmp_path, monkeypatch):
    monkeypatch.setattr(ARCH, "MAX_NESTED_ARCHIVE_BYTES", 100)
    work = tmp_path / "work"
    work.mkdir()
    with pytest.raises(ARCH.UnsafeArchive, match="larger"):
        ARCH.extract_nested_archive(str(chain), "docs/inner.zip", str(work), depth=1)
    assert list(work.iterdir()) == []


def test_sad_a_member_that_is_no_archive_is_refused(chain, tmp_path):
    with pytest.raises(ARCH.UnsafeArchive, match="not an archive"):
        ARCH.extract_nested_archive(str(chain), "readme.txt", str(tmp_path), depth=1)


def test_sad_a_missing_member_is_a_key_error(chain, tmp_path):
    with pytest.raises(KeyError):
        ARCH.extract_nested_archive(str(chain), "docs/nope.zip", str(tmp_path), depth=1)


def test_sad_a_bomb_member_is_refused_by_the_ratio_guard(tmp_path):
    bomb = b"\0" * (8 * 1024 * 1024)  # a "zip" of zeros: deflates far over 100:1
    outer = tmp_path / "outer.zip"
    with zipfile.ZipFile(outer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("bomb.zip", bomb)
    work = tmp_path / "work"
    work.mkdir()
    with pytest.raises(ARCH.UnsafeArchive):
        ARCH.extract_nested_archive(str(outer), "bomb.zip", str(work), depth=1)
    assert list(work.iterdir()) == []


def test_sad_a_traversing_member_name_is_refused(tmp_path):
    outer = tmp_path / "outer.tar"
    outer.write_bytes(_tar_bytes({"../evil.zip": _zip_bytes({"x": b"x"})}))
    work = tmp_path / "work"
    work.mkdir()
    with pytest.raises(ARCH.UnsafeArchive):
        ARCH.extract_nested_archive(str(outer), "../evil.zip", str(work), depth=1)
    assert not (tmp_path / "evil.zip").exists()


# --- core: edge ------------------------------------------------------------


def test_edge_the_deepest_allowed_level_opens(chain, tmp_path):
    path = ARCH.extract_nested_archive(
        str(chain), "docs/inner.zip", str(tmp_path), depth=ARCH.MAX_NESTED_DEPTH
    )
    assert os.path.isfile(path)


def test_edge_a_member_whose_extracted_size_lies_is_removed(chain, tmp_path, monkeypatch):
    real = ARCH.list_archive

    def lying(path):  # the listing claims 1 byte; the bytes are more
        return [
            ARCH.ArchiveEntry(e.name, 1, e.compressed, e.mtime, e.is_dir) for e in real(path)
        ]

    monkeypatch.setattr(ARCH, "list_archive", lying)
    monkeypatch.setattr(ARCH, "MAX_NESTED_ARCHIVE_BYTES", 100)
    work = tmp_path / "work"
    work.mkdir()
    with pytest.raises(ARCH.UnsafeArchive):
        ARCH.extract_nested_archive(str(chain), "docs/inner.zip", str(work), depth=1)
    assert list(work.iterdir()) == []


def test_edge_mode_text_and_type_of_a_member():
    from ui.archive_pane import member_info

    entry = ARCH.ArchiveEntry("a/b.tar.gz", 2048, 512, 1_700_000_000.0, False, 0o640, "file")
    info = dict(member_info(entry))
    assert info["Name"] == "a/b.tar.gz"
    assert info["Type"] == "Archive (TAR.GZ)"
    assert info["Size"] == "2048 bytes (2.0 KB)"
    assert info["Compressed"] == "512 bytes"
    assert info["Mode"] == "-rw-r----- (0640)"
    assert info["Modified"] == time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(1_700_000_000))
    unknown = dict(member_info(ARCH.ArchiveEntry("x", 0, 0, None, False)))
    assert unknown["Mode"] == "—" and unknown["Modified"] == "—"
    link = dict(member_info(ARCH.ArchiveEntry("l", 0, 0, None, False, 0o777, "symlink")))
    assert link["Type"] == "Symbolic link" and link["Mode"].startswith("l")


def test_edge_a_cancel_from_the_progress_callback_leaves_nothing(chain, tmp_path):
    work = tmp_path / "work"
    work.mkdir()

    def cancel(*_a):
        raise ARCH.ExtractCancelled("stop")

    with pytest.raises(ARCH.ExtractCancelled):
        ARCH.extract_nested_archive(
            str(chain), "docs/inner.zip", str(work), depth=1, progress=cancel
        )
    assert list(work.iterdir()) == []
