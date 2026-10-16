"""POSIX-only calls never crash axross on Windows.

The first Windows CI run: the main window opened, and closing it ended the
process with 0xC0000409 - closeEvent saved the session, _write_private_text
called os.fchmod, which Windows does not have before Python 3.13, and an
exception inside a Qt virtual aborts PyQt6. Seven modules called
os.fchmod directly, copy_resume compared against os.geteuid, the SQLite
backend asked os.statvfs for its free space. core.posix_compat keeps
these calls in one place; a source guard keeps new ones out.
"""

from __future__ import annotations

import os
import re
import stat
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core import posix_compat as PC  # noqa: E402


@pytest.fixture
def windows_os(monkeypatch):
    """os without the POSIX-only functions, as on Windows before 3.13."""
    # statvfs stays: shutil.disk_usage needs it on POSIX (Windows has its own).
    for name in ("fchmod", "geteuid", "getuid"):
        monkeypatch.delattr(os, name, raising=False)


# --- happy ----------------------------------------------------------------


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX modes")
def test_happy_private_mode_is_set_where_the_os_has_it(tmp_path):
    path = tmp_path / "f"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT, 0o644)
    try:
        PC.fchmod_private(fd)
    finally:
        os.close(fd)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_happy_the_session_file_is_written_without_fchmod(windows_os, tmp_path):
    from ui.main_window import _write_private_text

    target = tmp_path / "session.json"
    _write_private_text(target, '{"ok": true}')
    assert target.read_text() == '{"ok": true}'


def test_happy_free_space_comes_from_shutil(tmp_path):
    total, used, free = PC.disk_usage(str(tmp_path))
    assert total > 0 and free > 0 and used >= 0


# --- sad ------------------------------------------------------------------


def test_sad_no_uid_where_the_os_has_none(windows_os):
    assert PC.effective_uid() is None


def test_sad_no_module_calls_the_posix_only_functions_directly():
    allowed = {
        "core/posix_compat.py",  # the one place
        "core/proxy.py",  # behind an os.path.exists("/proc/net/tcp") check
        "core/tmpfs_detect.py",  # inside except AttributeError
        "core/mtp_client.py",  # Linux gvfs paths only, inside except OSError
    }
    pattern = re.compile(r"\bos\.(fchmod|geteuid|getuid|statvfs)\(")
    offenders = []
    for path in sorted([*ROOT.glob("core/*.py"), *ROOT.glob("ui/*.py"), ROOT / "main.py"]):
        rel = path.relative_to(ROOT).as_posix()
        if rel in allowed:
            continue
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if pattern.search(line) and "hasattr(os" not in line:
                offenders.append(f"{rel}:{n}: {line.strip()}")
    assert offenders == []


# --- edge -----------------------------------------------------------------


def test_edge_copy_resume_accepts_its_directory_without_posix_owners(
    windows_os, tmp_path, monkeypatch
):
    from core import copy_resume as CR

    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    resume = CR._private_manifest_dir()  # no AttributeError, no refusal
    assert resume == tmp_path / "axross" / "resume" and resume.is_dir()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX uids")
def test_edge_the_uid_is_the_real_one_on_posix():
    assert PC.effective_uid() == os.geteuid()
