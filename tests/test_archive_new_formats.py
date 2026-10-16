"""Unpacking what the packer can make: .tar.zst and single-file .gz / .bz2 /
.xz / .zst. Before, "Extract" and the archive preview knew none of them."""

from __future__ import annotations

import bz2
import gzip
import lzma
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import archive as ARCH  # noqa: E402
from core import packer as PK  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

ZSTD = PK.FORMATS["zst"].available()[0]


def _zstd(data: bytes) -> bytes:
    import io

    buf = io.BytesIO()
    w = PK.zstd_writer(buf, 3)
    w.write(data)
    w.close()
    return buf.getvalue()


COMPRESS = {
    ".gz": gzip.compress,
    ".bz2": bz2.compress,
    ".xz": lzma.compress,
    ".zst": _zstd,
}


@pytest.fixture
def tree(tmp_path) -> Path:
    root = tmp_path / "src"
    (root / "d").mkdir(parents=True)
    (root / "d" / "x.txt").write_text("xx")
    return root


# --- happy -----------------------------------------------------------------


@pytest.mark.parametrize("suffix", [".gz", ".bz2", ".xz", ".zst"])
def test_happy_a_single_compressed_file_extracts(tmp_path, suffix) -> None:
    if suffix == ".zst" and not ZSTD:
        pytest.skip("no zstd")
    src = tmp_path / f"notes.txt{suffix}"
    src.write_bytes(COMPRESS[suffix](b"hello notes"))
    assert ARCH.is_supported_archive(src.name)
    assert ARCH.strip_archive_extension(src.name) == "notes.txt"
    listing = ARCH.list_archive(str(src))
    assert [(e.name, e.is_dir) for e in listing] == [("notes.txt", False)]
    target = tmp_path / "out"
    assert ARCH.extract(str(src), str(target)) == 1
    assert (target / "notes.txt").read_bytes() == b"hello notes"


def test_happy_tar_zst_from_the_packer_extracts(tree, tmp_path) -> None:
    if not ZSTD:
        pytest.skip("no zstd")
    result = PK.pack(LocalFS(), str(tree), ["d"], "bundle", PK.PackOptions(fmt="tar.zst"))
    assert ARCH.is_supported_archive(result.path)
    assert ARCH.strip_archive_extension(result.path) == "bundle"
    names = {e.name for e in ARCH.list_archive(result.path)}
    assert {"d/", "d/x.txt"} <= names
    out = tmp_path / "out"
    ARCH.extract(result.path, str(out))
    assert (out / "d" / "x.txt").read_text() == "xx"


def test_happy_tar_zst_without_stdlib_zstd_uses_the_package(tree, tmp_path, monkeypatch) -> None:
    # The binary runs Python 3.12: tarfile knows no zstd there, so the
    # archive is decompressed through backports.zstd first.
    if not ZSTD:
        pytest.skip("no zstd")
    result = PK.pack(LocalFS(), str(tree), ["d"], "bundle", PK.PackOptions(fmt="tar.zst"))
    monkeypatch.setattr(ARCH, "_tarfile_knows_zstd", lambda: False)
    out = tmp_path / "out"
    ARCH.extract(result.path, str(out))
    assert (out / "d" / "x.txt").read_text() == "xx"


import contextlib  # noqa: E402


@contextlib.contextmanager
def _forced(path):
    # Run the package path even where tarfile knows zstd.
    real = ARCH._tarfile_knows_zstd
    ARCH._tarfile_knows_zstd = lambda: False
    try:
        with ARCH._open_tar(str(path)) as tf:
            yield tf
    finally:
        ARCH._tarfile_knows_zstd = real


# --- sad -------------------------------------------------------------------


def test_sad_a_broken_single_file_is_an_error_and_leaves_nothing(tmp_path) -> None:
    src = tmp_path / "bad.txt.gz"
    src.write_bytes(b"\x1f\x8b\x08 not really gzip")
    target = tmp_path / "out"
    with pytest.raises(ARCH.UnsafeArchive, match="cannot decompress"):
        ARCH.extract(str(src), str(target))
    assert not target.exists()
    if ZSTD:
        bad = tmp_path / "bad.tar.zst"
        bad.write_bytes(b"\x28\xb5\x2f\xfd garbage")
        with pytest.raises(ARCH.UnsafeArchive):
            with ARCH._open_tar(str(bad)) if not ARCH._tarfile_knows_zstd() else _forced(bad):
                pass


def test_sad_a_single_file_bomb_is_refused(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(ARCH, "MAX_EXTRACT_TOTAL_BYTES", 10_000)
    src = tmp_path / "bomb.bin.gz"
    src.write_bytes(gzip.compress(b"\0" * 1_000_000))
    target = tmp_path / "out"
    with pytest.raises(ARCH.UnsafeArchive, match="cap"):
        ARCH.extract(str(src), str(target))
    assert not target.exists()


def test_sad_zst_without_any_zstd_is_not_offered(monkeypatch) -> None:
    monkeypatch.setattr(PK, "_zstd_module", lambda: None)
    assert not ARCH.is_supported_archive("a.tar.zst")
    assert not ARCH.is_supported_archive("a.zst")
    assert ARCH.is_supported_archive("a.gz")


# --- edge ------------------------------------------------------------------


def test_edge_tar_gz_is_still_a_tar_not_a_single_file(tree, tmp_path) -> None:
    result = PK.pack(LocalFS(), str(tree), ["d"], "bundle", PK.PackOptions(fmt="tar.gz"))
    assert ARCH.strip_archive_extension(result.path) == "bundle"
    names = {e.name for e in ARCH.list_archive(result.path)}
    assert "d/x.txt" in names


def test_edge_a_name_without_stem_still_gets_a_file(tmp_path) -> None:
    src = tmp_path / ".gz"
    src.write_bytes(gzip.compress(b"x"))
    out = tmp_path / "out"
    ARCH.extract(str(src), str(out))
    assert [p.read_bytes() for p in out.iterdir()] == [b"x"]


def test_edge_extract_members_of_a_single_file(tmp_path) -> None:
    src = tmp_path / "one.log.xz"
    src.write_bytes(lzma.compress(b"log line"))
    out = tmp_path / "out"
    ARCH.extract_members(str(src), str(out), ["one.log"])
    assert (out / "one.log").read_bytes() == b"log line"
    assert os.listdir(out) == ["one.log"]
