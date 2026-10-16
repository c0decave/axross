"""The default resume manifest directory belongs to the current user.

Before, manifests went to ``<tempdir>/axross-resume``. When another
local user had created that directory first, the 0700 chmod failed, the
failure was only logged at debug level, and the manifests (destination
paths, segment hashes) were written into and later loaded from a
directory that user controls.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from core import copy_resume as CR
from core.local_fs import LocalFS


class _RefusingDestFS(LocalFS):
    """Destination whose open fails, so the manifest written at the start
    of the copy stays on disk where the test can look for it."""

    def open_write(self, path, append=False):
        raise OSError("simulated: destination unavailable")


def _source(tmp_path: Path) -> str:
    src = tmp_path / "src.bin"
    src.write_bytes(os.urandom(CR.MIN_SEGMENT_SIZE + 17))
    return str(src)


def _run_failing_copy(tmp_path: Path) -> None:
    with pytest.raises(OSError, match="cannot open destination"):
        CR.resumable_copy(
            LocalFS(), _source(tmp_path), _RefusingDestFS(), str(tmp_path / "dst.bin"),
            segment_size=CR.MIN_SEGMENT_SIZE,
        )


@pytest.fixture(autouse=True)
def _private_tempdir(tmp_path, monkeypatch):
    """Keep every run, red or green, out of the host's real tempdir."""
    shared = tmp_path / "shared-tmp"
    shared.mkdir()
    monkeypatch.setattr(CR.tempfile, "gettempdir", lambda: str(shared))
    return shared


@pytest.fixture
def state_home(tmp_path, monkeypatch):
    home = tmp_path / "state"
    monkeypatch.setenv("XDG_STATE_HOME", str(home))
    return home


def test_foreign_shared_tempdir_is_never_used(tmp_path, monkeypatch, state_home):
    # Another user created <tempdir>/axross-resume first: we cannot
    # chmod it (EPERM, as the kernel answers a non-owner).
    foreign = tmp_path / "shared-tmp" / "axross-resume"
    foreign.mkdir()
    foreign.chmod(0o777)
    real_chmod = os.chmod

    def _chmod(path, mode, *a, **k):
        if Path(path) == foreign:
            raise PermissionError(1, "Operation not permitted", str(path))
        return real_chmod(path, mode, *a, **k)

    monkeypatch.setattr(CR.os, "chmod", _chmod)

    _run_failing_copy(tmp_path)

    assert list(foreign.iterdir()) == []
    assert len(list((state_home / "axross" / "resume").glob("*.json"))) == 1


def test_default_manifest_lands_in_private_state_dir(tmp_path, state_home):
    _run_failing_copy(tmp_path)
    resume_dir = state_home / "axross" / "resume"
    manifests = list(resume_dir.glob("*.json"))
    assert len(manifests) == 1
    assert stat.S_IMODE(resume_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE(manifests[0].stat().st_mode) == 0o600


def test_state_home_unset_falls_back_to_home_local_state(tmp_path, monkeypatch):
    monkeypatch.delenv("XDG_STATE_HOME", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    _run_failing_copy(tmp_path)
    resume_dir = tmp_path / "home" / ".local" / "state" / "axross" / "resume"
    assert len(list(resume_dir.glob("*.json"))) == 1


def test_resume_dir_owned_by_another_uid_is_refused(tmp_path, monkeypatch, state_home):
    resume_dir = state_home / "axross" / "resume"
    resume_dir.mkdir(parents=True)
    real_uid = os.geteuid()
    monkeypatch.setattr(CR.os, "geteuid", lambda: real_uid + 1)
    with pytest.raises(OSError, match="not owned by the current user"):
        CR.resumable_copy(
            LocalFS(), _source(tmp_path), _RefusingDestFS(), str(tmp_path / "dst.bin"),
            segment_size=CR.MIN_SEGMENT_SIZE,
        )
    assert list(resume_dir.iterdir()) == []
    assert list((tmp_path / "shared-tmp").iterdir()) == []


def test_symlinked_resume_dir_is_refused(tmp_path, state_home):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (state_home / "axross").mkdir(parents=True)
    (state_home / "axross" / "resume").symlink_to(elsewhere)
    with pytest.raises(OSError, match="refusing symlinked resume directory"):
        CR.resumable_copy(
            LocalFS(), _source(tmp_path), _RefusingDestFS(), str(tmp_path / "dst.bin"),
            segment_size=CR.MIN_SEGMENT_SIZE,
        )
    assert list(elsewhere.iterdir()) == []
    assert list((tmp_path / "shared-tmp").iterdir()) == []


def test_explicit_manifest_path_is_untouched_by_the_default(tmp_path, state_home):
    explicit = tmp_path / "mine" / "m.json"
    with pytest.raises(OSError, match="cannot open destination"):
        CR.resumable_copy(
            LocalFS(), _source(tmp_path), _RefusingDestFS(), str(tmp_path / "dst.bin"),
            segment_size=CR.MIN_SEGMENT_SIZE, manifest_path=explicit,
        )
    assert explicit.exists()
    assert not (state_home / "axross" / "resume").exists()
