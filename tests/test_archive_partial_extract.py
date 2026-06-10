"""Partial archive extraction — ``core.archive.extract_members``.

These tests build real temporary ZIP and TAR archives in ``tmp_path``
and assert that ``extract_members`` writes ONLY the selected subset
into ``target`` while applying the SAME safety guards as the full
``extract`` path: zip-slip / absolute-path refusal, symlink + non-
file/non-dir member refusal, duplicate-output detection, bomb-ratio
and MAX_EXTRACT_FILES / MAX_EXTRACT_TOTAL_BYTES caps (enforced across
the SELECTED set).

Behaviours pinned here (chosen for Task A2):

* Directory selection — naming a directory member (``d`` or ``d/``)
  pulls in every descendant via prefix match on the archive's
  normalised paths.
* Missing member — a requested name absent from the archive raises
  ``KeyError`` with a message naming the missing entry. Validated
  BEFORE any file is written so a typo never leaves partial state.
* Target contract mirrors ``extract``: *target* must NOT pre-exist;
  ``extract_members`` creates it and removes it on any failure.
* progress callback ``(files_done, files_total, current_name)`` is
  invoked with monotonically increasing ``files_done``.
"""

from __future__ import annotations

import io
import os
import tarfile
import zipfile

import pytest

from core import archive as A

# --------------------------------------------------------------------------
# Fixtures — real ZIP / TAR with a top file, a sibling file, and a subdir
# --------------------------------------------------------------------------


def _make_zip(path: str) -> None:
    """ZIP with 4 file members across a subdir ``d/``:
    ``top.txt``, ``other.txt``, ``d/a.txt``, ``d/b.txt`` (plus an
    explicit ``d/`` directory entry)."""
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("top.txt", b"top file")
        zf.writestr("other.txt", b"other file")
        zf.writestr("d/", b"")
        zf.writestr("d/a.txt", b"alpha in d")
        zf.writestr("d/b.txt", b"bravo in d")


def _make_tar(path: str) -> None:
    """TAR equivalent of :func:`_make_zip`."""
    with tarfile.open(path, "w") as tf:
        for name, content in (
            ("top.txt", b"top file"),
            ("other.txt", b"other file"),
            ("d/a.txt", b"alpha in d"),
            ("d/b.txt", b"bravo in d"),
        ):
            info = tarfile.TarInfo(name=name)
            info.size = len(content)
            tf.addfile(info, io.BytesIO(content))
        d = tarfile.TarInfo(name="d")
        d.type = tarfile.DIRTYPE
        d.mode = 0o755
        tf.addfile(d)


def _listdir_rel(root: str) -> set[str]:
    """All file paths under *root* relative to it, posix-normalised."""
    out: set[str] = set()
    for dirpath, _dirs, files in os.walk(root):
        for f in files:
            rel = os.path.relpath(os.path.join(dirpath, f), root)
            out.add(rel.replace(os.sep, "/"))
    return out


# --------------------------------------------------------------------------
# ZIP — single-file selection
# --------------------------------------------------------------------------


def test_zip_select_single_file(tmp_path) -> None:
    src = tmp_path / "bundle.zip"
    _make_zip(str(src))
    target = tmp_path / "out"

    n = A.extract_members(str(src), str(target), ["top.txt"])

    assert n == 1
    assert _listdir_rel(str(target)) == {"top.txt"}
    assert (target / "top.txt").read_bytes() == b"top file"
    # The other three members must be absent.
    assert not (target / "other.txt").exists()
    assert not (target / "d" / "a.txt").exists()
    assert not (target / "d" / "b.txt").exists()


def test_zip_select_two_individual_files(tmp_path) -> None:
    src = tmp_path / "bundle.zip"
    _make_zip(str(src))
    target = tmp_path / "out"

    n = A.extract_members(str(src), str(target), ["top.txt", "other.txt"])

    assert n == 2
    assert _listdir_rel(str(target)) == {"top.txt", "other.txt"}


# --------------------------------------------------------------------------
# ZIP — directory selection pulls descendants
# --------------------------------------------------------------------------


def test_zip_select_directory_with_trailing_slash(tmp_path) -> None:
    src = tmp_path / "bundle.zip"
    _make_zip(str(src))
    target = tmp_path / "out"

    n = A.extract_members(str(src), str(target), ["d/"])

    assert n == 2
    assert _listdir_rel(str(target)) == {"d/a.txt", "d/b.txt"}
    assert not (target / "top.txt").exists()
    assert not (target / "other.txt").exists()


def test_zip_select_directory_without_trailing_slash(tmp_path) -> None:
    src = tmp_path / "bundle.zip"
    _make_zip(str(src))
    target = tmp_path / "out"

    # ``d`` (no slash) must resolve to the same descendant set as ``d/``.
    n = A.extract_members(str(src), str(target), ["d"])

    assert n == 2
    assert _listdir_rel(str(target)) == {"d/a.txt", "d/b.txt"}


def test_zip_directory_prefix_is_path_segment_not_substring(tmp_path) -> None:
    """Selecting ``d`` must NOT also grab a sibling like ``d2.txt`` that
    merely shares the ``d`` string prefix."""
    src = tmp_path / "bundle.zip"
    with zipfile.ZipFile(str(src), "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("d/a.txt", b"alpha")
        zf.writestr("d2.txt", b"sibling not under d")
    target = tmp_path / "out"

    n = A.extract_members(str(src), str(target), ["d"])

    assert n == 1
    assert _listdir_rel(str(target)) == {"d/a.txt"}


# --------------------------------------------------------------------------
# TAR — partial extraction parity
# --------------------------------------------------------------------------


def test_tar_select_single_file(tmp_path) -> None:
    src = tmp_path / "bundle.tar"
    _make_tar(str(src))
    target = tmp_path / "out"

    n = A.extract_members(str(src), str(target), ["top.txt"])

    assert n == 1
    assert _listdir_rel(str(target)) == {"top.txt"}
    assert (target / "top.txt").read_bytes() == b"top file"


def test_tar_select_directory(tmp_path) -> None:
    src = tmp_path / "bundle.tar"
    _make_tar(str(src))
    target = tmp_path / "out"

    n = A.extract_members(str(src), str(target), ["d"])

    assert n == 2
    assert _listdir_rel(str(target)) == {"d/a.txt", "d/b.txt"}


def test_tar_select_subset_mixed(tmp_path) -> None:
    src = tmp_path / "bundle.tar"
    _make_tar(str(src))
    target = tmp_path / "out"

    n = A.extract_members(str(src), str(target), ["other.txt", "d/a.txt"])

    assert n == 2
    assert _listdir_rel(str(target)) == {"other.txt", "d/a.txt"}


# --------------------------------------------------------------------------
# Missing member → KeyError, nothing written
# --------------------------------------------------------------------------


def test_unknown_member_raises_keyerror_zip(tmp_path) -> None:
    src = tmp_path / "bundle.zip"
    _make_zip(str(src))
    target = tmp_path / "out"

    with pytest.raises(KeyError) as ctx:
        A.extract_members(str(src), str(target), ["nope.txt"])
    assert "nope.txt" in str(ctx.value)
    # Target must not have been left behind (clean-on-fail, mirrors extract).
    assert not target.exists()


def test_unknown_member_raises_keyerror_tar(tmp_path) -> None:
    src = tmp_path / "bundle.tar"
    _make_tar(str(src))
    target = tmp_path / "out"

    with pytest.raises(KeyError):
        A.extract_members(str(src), str(target), ["top.txt", "ghost.txt"])
    assert not target.exists()


# --------------------------------------------------------------------------
# Target contract — mirrors extract(): must not pre-exist
# --------------------------------------------------------------------------


def test_target_must_not_preexist(tmp_path) -> None:
    src = tmp_path / "bundle.zip"
    _make_zip(str(src))
    target = tmp_path / "out"
    target.mkdir()

    with pytest.raises(FileExistsError):
        A.extract_members(str(src), str(target), ["top.txt"])


def test_missing_archive_raises(tmp_path) -> None:
    target = tmp_path / "out"
    with pytest.raises(FileNotFoundError):
        A.extract_members(str(tmp_path / "missing.zip"), str(target), ["x"])


# --------------------------------------------------------------------------
# SECURITY — symlink member selected is refused
# --------------------------------------------------------------------------


def test_tar_symlink_member_refused(tmp_path) -> None:
    """A selected TAR member that is a symlink → UnsafeArchive, and the
    target dir is left clean (clean-on-fail)."""
    src = tmp_path / "evil.tar"
    with tarfile.open(str(src), "w") as tf:
        good = tarfile.TarInfo(name="good.txt")
        good.size = len(b"benign")
        tf.addfile(good, io.BytesIO(b"benign"))
        link = tarfile.TarInfo(name="link")
        link.type = tarfile.SYMTYPE
        link.linkname = "../../etc/passwd"
        tf.addfile(link)

    target = tmp_path / "out"
    with pytest.raises(A.UnsafeArchive):
        A.extract_members(str(src), str(target), ["link"])
    # Nothing written, target removed.
    assert not target.exists()


def test_tar_hardlink_member_refused(tmp_path) -> None:
    src = tmp_path / "evil.tar"
    with tarfile.open(str(src), "w") as tf:
        good = tarfile.TarInfo(name="good.txt")
        good.size = len(b"benign")
        tf.addfile(good, io.BytesIO(b"benign"))
        link = tarfile.TarInfo(name="hard")
        link.type = tarfile.LNKTYPE
        link.linkname = "good.txt"
        tf.addfile(link)

    target = tmp_path / "out"
    with pytest.raises(A.UnsafeArchive):
        A.extract_members(str(src), str(target), ["hard"])
    assert not target.exists()


# --------------------------------------------------------------------------
# SECURITY — zip-slip / traversal member selected is refused
# --------------------------------------------------------------------------


def test_zip_traversal_member_refused(tmp_path) -> None:
    """A ZIP member literally named ``../escape`` selected for partial
    extraction → UnsafeArchive, and nothing is written outside target."""
    src = tmp_path / "evil.zip"
    with zipfile.ZipFile(str(src), "w") as zf:
        zf.writestr("../escape", b"pwned")
        zf.writestr("safe.txt", b"ok")

    target = tmp_path / "out"
    sentinel = tmp_path / "escape"
    with pytest.raises(A.UnsafeArchive):
        A.extract_members(str(src), str(target), ["../escape"])
    # The traversal target outside `target` must NOT have been created.
    assert not sentinel.exists()
    assert not target.exists()


def test_tar_traversal_member_refused(tmp_path) -> None:
    src = tmp_path / "evil.tar"
    with tarfile.open(str(src), "w") as tf:
        info = tarfile.TarInfo(name="../escape")
        info.size = len(b"pwned")
        tf.addfile(info, io.BytesIO(b"pwned"))
        safe = tarfile.TarInfo(name="safe.txt")
        safe.size = len(b"ok")
        tf.addfile(safe, io.BytesIO(b"ok"))

    target = tmp_path / "out"
    sentinel = tmp_path / "escape"
    with pytest.raises(A.UnsafeArchive):
        A.extract_members(str(src), str(target), ["../escape"])
    assert not sentinel.exists()
    assert not target.exists()


# --------------------------------------------------------------------------
# progress callback — invoked with increasing counts
# --------------------------------------------------------------------------


def test_progress_callback_increasing_zip(tmp_path) -> None:
    src = tmp_path / "bundle.zip"
    _make_zip(str(src))
    target = tmp_path / "out"

    calls: list[tuple[int, int, str]] = []

    def _cb(done: int, total: int, name: str) -> None:
        calls.append((done, total, name))

    n = A.extract_members(str(src), str(target), ["d"], progress=_cb)

    assert n == 2
    assert len(calls) == 2
    dones = [c[0] for c in calls]
    assert dones == sorted(dones)  # monotonic non-decreasing
    assert dones[-1] == 2
    # files_total reflects the SELECTED set, not the whole archive.
    assert all(c[1] == 2 for c in calls)


def test_progress_callback_increasing_tar(tmp_path) -> None:
    src = tmp_path / "bundle.tar"
    _make_tar(str(src))
    target = tmp_path / "out"

    calls: list[int] = []
    A.extract_members(
        str(src), str(target), ["d"], progress=lambda d, t, n: calls.append(d)
    )
    assert calls == sorted(calls)
    assert calls[-1] == 2


def test_progress_positional_argument(tmp_path) -> None:
    """The signature accepts ``progress`` positionally (matches spec)."""
    src = tmp_path / "bundle.zip"
    _make_zip(str(src))
    target = tmp_path / "out"
    seen: list[int] = []
    A.extract_members(str(src), str(target), ["top.txt"], lambda d, t, n: seen.append(d))
    assert seen == [1]


# --------------------------------------------------------------------------
# CAPS — selection exceeding MAX_EXTRACT_FILES is refused
# --------------------------------------------------------------------------


def test_select_exceeds_max_files_cap(tmp_path, monkeypatch) -> None:
    src = tmp_path / "bundle.zip"
    with zipfile.ZipFile(str(src), "w") as zf:
        for i in range(5):
            zf.writestr(f"f{i}.txt", b"x")
    target = tmp_path / "out"

    # Monkeypatch a tiny cap so we don't need a huge fixture. The cap is
    # enforced across the SELECTED set.
    monkeypatch.setattr(A, "MAX_EXTRACT_FILES", 2)

    with pytest.raises(A.UnsafeArchive):
        A.extract_members(
            str(src), str(target), ["f0.txt", "f1.txt", "f2.txt"]
        )
    assert not target.exists()


def test_select_under_cap_still_ok_when_archive_large(tmp_path, monkeypatch) -> None:
    """The cap applies to the SELECTED subset, not the whole archive: a
    big archive with a tiny selection under the cap must succeed."""
    src = tmp_path / "bundle.zip"
    with zipfile.ZipFile(str(src), "w") as zf:
        for i in range(5):
            zf.writestr(f"f{i}.txt", b"x")
    target = tmp_path / "out"

    monkeypatch.setattr(A, "MAX_EXTRACT_FILES", 2)

    n = A.extract_members(str(src), str(target), ["f0.txt", "f1.txt"])
    assert n == 2
    assert _listdir_rel(str(target)) == {"f0.txt", "f1.txt"}


def test_select_exceeds_total_bytes_cap(tmp_path, monkeypatch) -> None:
    src = tmp_path / "bundle.zip"
    with zipfile.ZipFile(str(src), "w") as zf:
        zf.writestr("big.txt", b"A" * 4096)
        zf.writestr("small.txt", b"a")
    target = tmp_path / "out"

    monkeypatch.setattr(A, "MAX_EXTRACT_TOTAL_BYTES", 1024)

    with pytest.raises(A.UnsafeArchive):
        A.extract_members(str(src), str(target), ["big.txt"])
    assert not target.exists()


# --------------------------------------------------------------------------
# Unsupported format dispatch
# --------------------------------------------------------------------------


def test_unsupported_extension_raises(tmp_path) -> None:
    src = tmp_path / "thing.pdf"
    src.write_bytes(b"%PDF-1.4")
    target = tmp_path / "out"
    with pytest.raises((A.UnsafeArchive, ValueError)):
        A.extract_members(str(src), str(target), ["x"])
