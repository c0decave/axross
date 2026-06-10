"""RAR extraction safety — preflight guards in ``core.archive._extract_rar``.

The optional ``rarfile`` package is NOT installed in CI / this env, so
these tests do NOT build a real ``.rar``. Instead they unit-test the
per-member preflight guard via a STUB: ``core.archive.RAR_AVAILABLE`` is
forced ``True`` and ``core.archive.rarfile`` is replaced with a fake
module whose ``RarFile(path)`` context manager yields stub ``RarInfo``
objects. The fake ``RarFile.extractall`` raises ``AssertionError`` if it
is ever reached — proving the preflight REFUSES a hostile member BEFORE
any extraction (and therefore before rarfile's ``_extract_one`` would
call ``os.symlink(raw_link_target, dst)`` with an unsanitized target).

Why this matters: rarfile extracts a symlink member by calling
``os.symlink(link_name, dstfn)`` where ``link_name`` is the RAW target
read straight out of the archive (see rarfile's ``_make_symlink``). A
member whose link target is ``../../../etc`` or an absolute path escapes
the extraction dir, and ``_extract``'s post-extraction
``_measure_tree_bytes`` net deliberately skips symlinks so it would NOT
catch it. The only defence is refusing symlink (and other non-file/
non-dir) members up front — which is what ``_extract_rar`` now does,
mirroring ``_extract_7z`` / ``_extract_tar``.

A real-archive roundtrip test is gated below (skipped unless both the
``rarfile`` package AND a backend tool are present).
"""

from __future__ import annotations

import os
import types

import pytest

from core import archive as A

# --------------------------------------------------------------------------
# Stub rarfile backend
# --------------------------------------------------------------------------


class _StubRarInfo:
    """Minimal stand-in for ``rarfile.RarInfo``.

    Exposes the 4.0+ predicate methods the extractor relies on
    (``is_dir`` / ``is_file`` / ``is_symlink`` — NOT the deprecated
    ``isdir``) plus ``filename`` / ``file_size`` / ``compress_size``.
    """

    def __init__(
        self,
        filename: str,
        *,
        is_dir: bool = False,
        is_file: bool = False,
        is_symlink: bool = False,
        file_size: int = 0,
        compress_size: int = 0,
    ) -> None:
        self.filename = filename
        self.file_size = file_size
        self.compress_size = compress_size
        self._is_dir = is_dir
        self._is_file = is_file
        self._is_symlink = is_symlink

    def is_dir(self) -> bool:
        return self._is_dir

    def is_file(self) -> bool:
        return self._is_file

    def is_symlink(self) -> bool:
        return self._is_symlink


class _StubRarFile:
    """Context-manager stand-in for ``rarfile.RarFile``.

    ``infolist()`` returns the stub members it was constructed with.
    ``extractall`` MUST never run — if the preflight is correct it
    raises before we get here. Reaching it is a test failure.
    """

    # The real RarFile records which members it was asked to extract;
    # the class attr lets a test inspect it if extraction were (wrongly)
    # reached. It never should be.
    last_extractall_members = None

    def __init__(self, members: list[_StubRarInfo]) -> None:
        self._members = members

    def __enter__(self) -> _StubRarFile:
        return self

    def __exit__(self, *exc) -> bool:
        return False

    def infolist(self) -> list[_StubRarInfo]:
        return list(self._members)

    def extractall(self, *args, **kwargs) -> None:  # pragma: no cover
        type(self).last_extractall_members = kwargs.get("members", args)
        raise AssertionError(
            "rarfile.extractall was called — preflight should have "
            f"refused the archive first (members={kwargs.get('members')!r})",
        )


class _RarCannotExec(Exception):
    """Stub mirror of ``rarfile.RarCannotExec`` (backend tool missing)."""


class _RarExecError(Exception):
    """Stub mirror of ``rarfile.RarExecError`` (backend tool failed)."""


def _install_stub_rarfile(monkeypatch, members: list[_StubRarInfo]) -> None:
    """Force RAR 'available' and swap in a fake ``rarfile`` module whose
    ``RarFile(path)`` yields *members*. The fake also carries the
    ``RarCannotExec`` / ``RarExecError`` types the extractor's ``except``
    tuple references — without them the catch clause would raise
    ``AttributeError`` instead of doing its job."""
    fake = types.ModuleType("rarfile")
    fake.RarFile = lambda _path: _StubRarFile(members)  # type: ignore[attr-defined]
    fake.RarCannotExec = _RarCannotExec  # type: ignore[attr-defined]
    fake.RarExecError = _RarExecError  # type: ignore[attr-defined]
    monkeypatch.setattr(A, "rarfile", fake)
    monkeypatch.setattr(A, "RAR_AVAILABLE", True)
    # Make sure the prior run's extractall trace can't leak across tests.
    _StubRarFile.last_extractall_members = None


def _assert_target_clean(target) -> None:
    """The target dir must be empty or absent — a refused archive must
    leave NOTHING on disk (``extract`` rolls back on any failure)."""
    if os.path.exists(target):
        assert os.listdir(target) == [], (
            f"target {target!r} not clean after refusal: "
            f"{os.listdir(target)!r}"
        )


# --------------------------------------------------------------------------
# CRITICAL: symlink member is refused BEFORE extraction
# --------------------------------------------------------------------------


def test_rar_symlink_member_refused_before_extraction(tmp_path, monkeypatch) -> None:
    members = [
        # Decoy regular file first — proves rollback / that we never
        # half-extracted before the symlink tripped the guard.
        _StubRarInfo("fine.txt", is_file=True, file_size=4, compress_size=4),
        # The attack: a symlink member. is_dir/is_file False, is_symlink
        # True. rarfile would os.symlink(raw_target, dst) for this.
        _StubRarInfo("evil", is_symlink=True),
    ]
    _install_stub_rarfile(monkeypatch, members)

    src = tmp_path / "payload.rar"
    src.write_bytes(b"stub - never parsed, RarFile is faked")
    target = tmp_path / "rar_sym_out"

    with pytest.raises(A.UnsafeArchive) as ctx:
        A.extract(str(src), str(target))
    assert "symlink" in str(ctx.value)

    # extractall must never have run.
    assert _StubRarFile.last_extractall_members is None
    _assert_target_clean(target)


# --------------------------------------------------------------------------
# CRITICAL: zip-slip member (../escape) is refused via _safe_member_path
# --------------------------------------------------------------------------


def test_rar_zipslip_member_refused(tmp_path, monkeypatch) -> None:
    members = [
        _StubRarInfo(
            "../escape",
            is_file=True,
            file_size=10,
            compress_size=10,
        ),
    ]
    _install_stub_rarfile(monkeypatch, members)

    src = tmp_path / "slip.rar"
    src.write_bytes(b"stub")
    target = tmp_path / "rar_slip_out"

    with pytest.raises(A.UnsafeArchive) as ctx:
        A.extract(str(src), str(target))
    assert "escape" in str(ctx.value)  # _safe_member_path message

    assert _StubRarFile.last_extractall_members is None
    _assert_target_clean(target)


# --------------------------------------------------------------------------
# A non-file / non-dir / non-symlink member (e.g. device node) is refused
# --------------------------------------------------------------------------


def test_rar_unsupported_type_member_refused(tmp_path, monkeypatch) -> None:
    members = [
        # Everything False — not a file, dir, or symlink. rarfile's
        # _extract_one would silently return None and skip it, but we
        # refuse the whole archive rather than guess.
        _StubRarInfo("weird"),
    ]
    _install_stub_rarfile(monkeypatch, members)

    src = tmp_path / "weird.rar"
    src.write_bytes(b"stub")
    target = tmp_path / "rar_weird_out"

    with pytest.raises(A.UnsafeArchive) as ctx:
        A.extract(str(src), str(target))
    assert "unsupported type" in str(ctx.value)

    assert _StubRarFile.last_extractall_members is None
    _assert_target_clean(target)


# --------------------------------------------------------------------------
# An empty / root-path member is refused
# --------------------------------------------------------------------------


def test_rar_empty_path_member_refused(tmp_path, monkeypatch) -> None:
    members = [_StubRarInfo("/", is_dir=True)]
    _install_stub_rarfile(monkeypatch, members)

    src = tmp_path / "rootpath.rar"
    src.write_bytes(b"stub")
    target = tmp_path / "rar_root_out"

    with pytest.raises(A.UnsafeArchive) as ctx:
        A.extract(str(src), str(target))
    assert "empty/root path" in str(ctx.value)

    assert _StubRarFile.last_extractall_members is None
    _assert_target_clean(target)


# --------------------------------------------------------------------------
# Sanity: a clean all-files archive DOES reach extractall with exactly the
# validated names (and only those). We let extractall short-circuit by
# raising AssertionError, so we assert on the captured members instead.
# --------------------------------------------------------------------------


def test_rar_clean_archive_passes_only_validated_names_to_extractall(
    tmp_path,
    monkeypatch,
) -> None:
    members = [
        _StubRarInfo("d", is_dir=True),
        _StubRarInfo("d/a.txt", is_file=True, file_size=5, compress_size=5),
        _StubRarInfo("b.txt", is_file=True, file_size=3, compress_size=3),
    ]
    _install_stub_rarfile(monkeypatch, members)

    src = tmp_path / "clean.rar"
    src.write_bytes(b"stub")
    target = tmp_path / "rar_clean_out"

    # extractall raises AssertionError by design once preflight passes;
    # catch it and verify it was handed ONLY the validated file names
    # (dirs are makedirs'd during preflight, not passed to extractall).
    with pytest.raises(AssertionError):
        A.extract(str(src), str(target))
    assert _StubRarFile.last_extractall_members == ["d/a.txt", "b.txt"]


# --------------------------------------------------------------------------
# Optional real-archive roundtrip — only when rarfile package + a backend
# tool are actually usable. Skipped in this env (rarfile not installed).
# --------------------------------------------------------------------------


@pytest.mark.skipif(
    not A.RAR_AVAILABLE,
    reason="rarfile package not installed",
)
def test_rar_real_symlink_archive_refused(tmp_path) -> None:  # pragma: no cover
    # TODO: when rarfile + an 'unrar'/'unar' backend are available,
    # build a real .rar containing a symlink member (e.g. via the unrar
    # toolchain or a checked-in fixture) and assert A.extract refuses it
    # with UnsafeArchive and leaves the target clean. The stub tests
    # above cover the guard logic; this would cover the real backend
    # surfacing is_symlink() correctly.
    pytest.skip("real-archive symlink fixture not yet provided")
