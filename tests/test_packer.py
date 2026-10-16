"""Packing files and folders: zip, tar.gz/.bz2/.xz/.zst, 7z (optionally
AES-256 with encrypted names) and single-file gz/bz2/xz/zst - from any
backend, never overwriting, never leaving a half-written archive."""

from __future__ import annotations

import bz2
import gzip
import io
import lzma
import os
import sys
import tarfile
import threading
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import packer as PK  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

FS = LocalFS()


@pytest.fixture
def tree(tmp_path) -> Path:
    root = tmp_path / "src"
    (root / "docs" / "deep").mkdir(parents=True)
    (root / "docs" / "a.txt").write_text("alpha")
    (root / "docs" / "deep" / "b.bin").write_bytes(os.urandom(200_000))
    (root / "empty").mkdir()
    (root / "top file ü.txt").write_text("top")
    return root


def _pack(tree: Path, fmt: str, names=("docs", "empty", "top file ü.txt"), **kw) -> PK.PackResult:
    opts = PK.PackOptions(fmt=fmt, **kw)
    return PK.pack(FS, str(tree), list(names), "bundle", opts)


def _zstd_ok() -> bool:
    return PK.FORMATS["tar.zst"].available()[0]


# --- happy -----------------------------------------------------------------


def test_happy_zip_holds_files_folders_and_empty_ones(tree) -> None:
    result = _pack(tree, "zip")
    assert result.path == str(tree / "bundle.zip")
    with zipfile.ZipFile(result.path) as zf:
        names = set(zf.namelist())
        assert {"docs/", "docs/a.txt", "docs/deep/", "docs/deep/b.bin", "empty/"} <= names
        assert "top file ü.txt" in names
        assert zf.read("docs/a.txt") == b"alpha"
        assert zf.read("docs/deep/b.bin") == (tree / "docs/deep/b.bin").read_bytes()
    assert result.files == 3 and result.bytes_in == 5 + 200_000 + 3


@pytest.mark.parametrize("fmt", ["tar.gz", "tar.bz2", "tar.xz", "tar.zst"])
def test_happy_tar_formats_round_trip(tree, fmt) -> None:
    if fmt == "tar.zst" and not _zstd_ok():
        pytest.skip(PK.FORMATS[fmt].available()[1])
    result = _pack(tree, fmt)
    assert result.path.endswith(".tar." + fmt.split(".")[1])
    if fmt == "tar.zst":
        raw = PK.zstd_decompress(Path(result.path).read_bytes())
        tf = tarfile.open(fileobj=io.BytesIO(raw))
    else:
        tf = tarfile.open(result.path)
    with tf:
        assert tf.extractfile("docs/a.txt").read() == b"alpha"
        assert tf.getmember("empty").isdir()
        assert tf.getmember("docs/deep/b.bin").size == 200_000


def test_happy_7z_round_trip(tree) -> None:
    py7zr = pytest.importorskip("py7zr")
    result = _pack(tree, "7z")
    with py7zr.SevenZipFile(result.path) as zf:
        assert "docs/a.txt" in zf.getnames()


def test_happy_7z_with_password_hides_names_and_content(tree, tmp_path) -> None:
    py7zr = pytest.importorskip("py7zr")
    result = _pack(tree, "7z", password="s3cret pass", encrypt_names=True)
    data = Path(result.path).read_bytes()
    assert b"a.txt" not in data and b"alpha" not in data
    with pytest.raises(Exception):  # noqa: B017 - py7zr raises its own types
        with py7zr.SevenZipFile(result.path) as zf:
            zf.getnames()
    out = tmp_path / "out"
    with py7zr.SevenZipFile(result.path, password="s3cret pass") as zf:
        zf.extractall(out)
    assert (out / "docs" / "a.txt").read_text() == "alpha"


@pytest.mark.parametrize(
    "fmt, opener",
    [("gz", gzip.decompress), ("bz2", bz2.decompress), ("xz", lzma.decompress), ("zst", None)],
)
def test_happy_single_file_compression(tree, fmt, opener) -> None:
    if fmt == "zst" and not _zstd_ok():
        pytest.skip("no zstd")
    result = PK.pack(FS, str(tree / "docs"), ["a.txt"], "a.txt", PK.PackOptions(fmt=fmt))
    assert result.path == str(tree / "docs" / f"a.txt.{fmt}")
    data = Path(result.path).read_bytes()
    plain = PK.zstd_decompress(data) if fmt == "zst" else opener(data)
    assert plain == b"alpha"


def test_happy_a_remote_folder_gets_the_archive_uploaded(tree, monkeypatch) -> None:
    uploads = []

    class Remote(LocalFS):
        def open_write(self, path, append=False):
            uploads.append(path)
            return super().open_write(path, append)

    monkeypatch.setattr(PK, "_is_local", lambda backend: not isinstance(backend, Remote))
    result = PK.pack(Remote(), str(tree), ["docs"], "up", PK.PackOptions(fmt="zip"))
    assert uploads == [str(tree / "up.zip")]
    with zipfile.ZipFile(result.path) as zf:
        assert zf.read("docs/a.txt") == b"alpha"


def test_happy_formats_report_what_they_can(tree) -> None:
    ids = list(PK.FORMATS)
    assert ids[:2] == ["zip", "tar.gz"]
    assert {"7z", "tar.zst", "gz", "zst"} <= set(ids)
    assert PK.FORMATS["7z"].encrypts and not PK.FORMATS["zip"].encrypts
    assert PK.FORMATS["gz"].single and not PK.FORMATS["tar.gz"].single


# --- sad -------------------------------------------------------------------


def test_sad_a_single_file_format_refuses_several_sources(tree) -> None:
    with pytest.raises(PK.PackError, match="one file"):
        PK.pack(FS, str(tree), ["docs", "top file ü.txt"], "x", PK.PackOptions(fmt="gz"))
    with pytest.raises(PK.PackError, match="one file"):
        PK.pack(FS, str(tree), ["docs"], "x", PK.PackOptions(fmt="zst"))


def test_sad_a_password_needs_7z(tree) -> None:
    with pytest.raises(PK.PackError, match="7z"):
        _pack(tree, "zip", password="pw")


def test_sad_an_existing_archive_is_never_overwritten(tree) -> None:
    (tree / "bundle.zip").write_bytes(b"precious")
    result = _pack(tree, "zip")
    assert result.path == str(tree / "bundle (2).zip")
    assert (tree / "bundle.zip").read_bytes() == b"precious"


def test_sad_a_file_that_changes_while_packing_fails_cleanly(tree, monkeypatch) -> None:
    real_open = LocalFS.open_read

    class Shrinking(LocalFS):
        def open_read(self, path):
            fh = real_open(self, path)
            if path.endswith("b.bin"):
                return io.BytesIO(fh.read(1000))  # shorter than its listing says
            return fh

    with pytest.raises(PK.PackError, match="changed"):
        PK.pack(Shrinking(), str(tree), ["docs"], "bundle", PK.PackOptions(fmt="tar.gz"))
    assert sorted(p.name for p in tree.iterdir()) == ["docs", "empty", "top file ü.txt"]


def test_sad_cancel_leaves_nothing_behind(tree) -> None:
    cancel = threading.Event()

    def progress(done, total, name):
        if done >= 1:
            cancel.set()

    with pytest.raises(PK.PackCancelled):
        PK.pack(
            FS, str(tree), ["docs", "top file ü.txt"], "bundle",
            PK.PackOptions(fmt="zip"), progress=progress, cancel=cancel,
        )
    assert not any(p.name.startswith(("bundle", ".axross-pack")) for p in tree.iterdir())


def test_sad_an_unavailable_format_says_why(tree, monkeypatch) -> None:
    monkeypatch.setattr(PK, "_zstd_module", lambda: None)
    ok, reason = PK.FORMATS["tar.zst"].available()
    assert not ok and "backports.zstd" in reason
    with pytest.raises(PK.PackError, match="backports.zstd"):
        _pack(tree, "tar.zst")


def test_sad_an_unreadable_source_is_an_error_not_a_partial_archive(tree) -> None:
    with pytest.raises(PK.PackError, match="missing.txt"):
        PK.pack(FS, str(tree), ["missing.txt"], "bundle", PK.PackOptions(fmt="zip"))
    assert not (tree / "bundle.zip").exists()


# --- edge ------------------------------------------------------------------


def test_edge_symlinks_are_skipped_and_reported(tree, tmp_path) -> None:
    secret = tmp_path / "secret.txt"
    secret.write_text("outside")
    (tree / "docs" / "link.txt").symlink_to(secret)
    result = _pack(tree, "zip", names=("docs",))
    with zipfile.ZipFile(result.path) as zf:
        assert "docs/link.txt" not in zf.namelist()
    assert result.skipped == ["docs/link.txt"]


def test_edge_too_many_files_is_refused(tree, monkeypatch) -> None:
    monkeypatch.setattr(PK, "MAX_PACK_FILES", 2)
    with pytest.raises(PK.PackError, match="more than 2"):
        _pack(tree, "zip")


def test_edge_default_names_and_levels() -> None:
    assert PK.default_name(["docs"]) == "docs"
    assert PK.default_name(["a.txt", "b.txt"], folder="/x/project") == "project"
    assert PK.default_name([], folder="/") == "archive"
    assert set(PK.LEVELS) == {"fast", "normal", "best"}
    with pytest.raises(PK.PackError):
        PK.PackOptions(fmt="rar")
    with pytest.raises(PK.PackError):
        PK.PackOptions(fmt="zip", level="ultra")


def test_edge_a_bad_archive_name_is_refused(tree) -> None:
    for bad in ("../escape", "sub/name", "", ".", ".."):
        with pytest.raises(PK.PackError):
            PK.pack(FS, str(tree), ["docs"], bad, PK.PackOptions(fmt="zip"))
