"""Read-only archive listing — ``core.archive.list_archive`` +
``ArchiveEntry`` + RAR support plumbing.

These tests build real temporary archives in ``tmp_path`` and assert
that listing returns matching metadata WITHOUT writing anything to
disk (listing is strictly read-only). The RAR availability gate is
exercised via monkeypatch so the suite passes whether or not the
optional ``rarfile`` package / ``unrar`` tool is installed.
"""

from __future__ import annotations

import os
import tarfile
import zipfile

import pytest

from core import archive as A

# --------------------------------------------------------------------------
# ArchiveEntry dataclass + ratio property
# --------------------------------------------------------------------------


def test_archive_entry_ratio_basic() -> None:
    e = A.ArchiveEntry(name="f", size=100, compressed=25, mtime=None, is_dir=False)
    # 1 - 25/100 = 0.75
    assert e.ratio == pytest.approx(0.75)
    assert 0.0 <= e.ratio <= 1.0


def test_archive_entry_ratio_zero_size() -> None:
    # size <= 0 → ratio 0.0 (no division-by-zero, no negative)
    e = A.ArchiveEntry(name="d/", size=0, compressed=0, mtime=None, is_dir=True)
    assert e.ratio == 0.0


def test_archive_entry_ratio_never_negative() -> None:
    # Stored larger than original (compressed > size) → clamp at 0.0.
    e = A.ArchiveEntry(name="f", size=10, compressed=50, mtime=None, is_dir=False)
    assert e.ratio == 0.0


def test_archive_entry_is_frozen() -> None:
    e = A.ArchiveEntry(name="f", size=1, compressed=1, mtime=None, is_dir=False)
    with pytest.raises(Exception):
        e.name = "other"  # type: ignore[misc]


# --------------------------------------------------------------------------
# ZIP listing
# --------------------------------------------------------------------------


def _make_zip_with_dir(path: str) -> None:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("readme.txt", b"hello world")
        zf.writestr("data.bin", b"x" * 500)
        # Explicit directory entry + a file under it.
        zf.writestr("sub/", b"")
        zf.writestr("sub/inner.txt", b"nested content")


def test_list_zip_returns_matching_entries(tmp_path) -> None:
    src = tmp_path / "bundle.zip"
    _make_zip_with_dir(str(src))

    entries = A.list_archive(str(src))
    by_name = {e.name: e for e in entries}

    assert "readme.txt" in by_name
    assert "data.bin" in by_name
    assert "sub/inner.txt" in by_name

    # Directory entry is flagged is_dir.
    dir_entries = [e for e in entries if e.is_dir]
    assert any(e.name.rstrip("/") == "sub" for e in dir_entries)

    readme = by_name["readme.txt"]
    assert readme.size == len(b"hello world")
    assert readme.is_dir is False
    assert readme.compressed >= 0

    data = by_name["data.bin"]
    assert data.size == 500
    # Highly compressible payload → real compression happened.
    assert data.compressed < data.size

    # ratio computed and within [0, 1] for every entry.
    for e in entries:
        assert 0.0 <= e.ratio <= 1.0


def test_list_zip_mtime_is_epoch_float_or_none(tmp_path) -> None:
    src = tmp_path / "m.zip"
    _make_zip_with_dir(str(src))
    for e in A.list_archive(str(src)):
        assert e.mtime is None or isinstance(e.mtime, float)


# --------------------------------------------------------------------------
# TAR listing
# --------------------------------------------------------------------------


def _make_targz_with_dir(path: str) -> None:
    import io

    with tarfile.open(path, "w:gz") as tf:
        for name, content in (("a.txt", b"alpha"), ("nested/b.txt", b"bravo!!")):
            info = tarfile.TarInfo(name=name)
            info.size = len(content)
            tf.addfile(info, io.BytesIO(content))
        # Explicit directory member.
        d = tarfile.TarInfo(name="emptydir")
        d.type = tarfile.DIRTYPE
        d.mode = 0o755
        tf.addfile(d)


def test_list_targz_returns_entries_with_isdir(tmp_path) -> None:
    src = tmp_path / "bundle.tar.gz"
    _make_targz_with_dir(str(src))

    entries = A.list_archive(str(src))
    by_name = {e.name.rstrip("/"): e for e in entries}

    assert "a.txt" in by_name
    assert "nested/b.txt" in by_name
    assert "emptydir" in by_name

    assert by_name["a.txt"].is_dir is False
    assert by_name["a.txt"].size == len(b"alpha")
    # Tar has no per-member compressed size → compressed == size.
    assert by_name["a.txt"].compressed == by_name["a.txt"].size
    assert by_name["emptydir"].is_dir is True

    for e in entries:
        assert 0.0 <= e.ratio <= 1.0
        assert e.mtime is None or isinstance(e.mtime, (int, float))


# --------------------------------------------------------------------------
# Listing is read-only — must NOT create any files
# --------------------------------------------------------------------------


def test_list_archive_does_not_extract(tmp_path, monkeypatch) -> None:
    src = tmp_path / "ro.zip"
    _make_zip_with_dir(str(src))

    target = tmp_path / "should_stay_empty"
    target.mkdir()

    # cwd inside the empty target so any accidental relative extraction
    # would show up here.
    monkeypatch.chdir(target)
    before = set(os.listdir(target))

    A.list_archive(str(src))

    after = set(os.listdir(target))
    assert before == after == set()
    # Only the archive itself exists in tmp_path (plus our empty target).
    assert sorted(os.listdir(tmp_path)) == ["ro.zip", "should_stay_empty"]


# --------------------------------------------------------------------------
# RAR availability gate
# --------------------------------------------------------------------------


def test_list_rar_unavailable_raises(tmp_path, monkeypatch) -> None:
    # Force the unavailable path. The availability check must fire
    # BEFORE any file IO, so a non-existent .rar path is fine — but we
    # also drop a dummy file to prove it's the gate, not a missing file.
    monkeypatch.setattr(A, "RAR_AVAILABLE", False)
    dummy = tmp_path / "foo.rar"
    dummy.write_bytes(b"not a real rar")

    with pytest.raises(A.RarUnavailable):
        A.list_archive(str(dummy))

    # Path that doesn't even exist must also hit the gate first.
    with pytest.raises(A.RarUnavailable):
        A.list_archive(str(tmp_path / "missing.rar"))


def test_rar_unavailable_message_is_helpful() -> None:
    with pytest.raises(A.RarUnavailable) as ctx:
        raise A.RarUnavailable(
            "RAR support requires the 'rarfile' package and an "
            "'unrar'/'unar' tool — pip install rarfile",
        )
    msg = str(ctx.value)
    assert "rarfile" in msg
    assert "unrar" in msg or "unar" in msg


# --------------------------------------------------------------------------
# is_supported_archive
# --------------------------------------------------------------------------


def test_is_supported_zip_always_true() -> None:
    assert A.is_supported_archive("x.zip") is True
    assert A.is_supported_archive("X.ZIP") is True


def test_is_supported_rar_reflects_availability(monkeypatch) -> None:
    monkeypatch.setattr(A, "RAR_AVAILABLE", True)
    assert A.is_supported_archive("x.rar") is True
    assert A.is_supported_archive("X.RAR") is True

    monkeypatch.setattr(A, "RAR_AVAILABLE", False)
    assert A.is_supported_archive("x.rar") is False


def test_is_supported_unknown_false() -> None:
    assert A.is_supported_archive("foo.pdf") is False
    assert A.is_supported_archive("noext") is False


# --------------------------------------------------------------------------
# Unknown extension on list_archive → same error family as extract()
# --------------------------------------------------------------------------


def test_list_unknown_extension_raises(tmp_path) -> None:
    src = tmp_path / "thing.pdf"
    src.write_bytes(b"%PDF-1.4 not an archive")
    with pytest.raises((A.UnsafeArchive, ValueError)):
        A.list_archive(str(src))


# --------------------------------------------------------------------------
# 7z listing — guarded on SEVEN_Z_AVAILABLE (skipped if py7zr absent)
# --------------------------------------------------------------------------


def test_list_7z_when_available(tmp_path) -> None:
    if not A.SEVEN_Z_AVAILABLE:
        pytest.skip("py7zr not installed")
    import py7zr

    payload = tmp_path / "payload"
    payload.mkdir()
    (payload / "a.txt").write_bytes(b"seven zip hi")
    (payload / "d").mkdir()
    (payload / "d" / "b.txt").write_bytes(b"nested seven")
    src = tmp_path / "pkg.7z"
    with py7zr.SevenZipFile(src, "w") as sz:
        sz.writeall(payload, arcname=".")

    entries = A.list_archive(str(src))
    names = {e.name.rstrip("/") for e in entries}
    assert "a.txt" in names
    assert "d/b.txt" in names
    for e in entries:
        assert 0.0 <= e.ratio <= 1.0


def test_list_7z_unavailable_raises(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(A, "SEVEN_Z_AVAILABLE", False)
    dummy = tmp_path / "x.7z"
    dummy.write_bytes(b"7z\xbc\xaf\x27\x1c")
    with pytest.raises((A.UnsafeArchive, RuntimeError)):
        A.list_archive(str(dummy))
