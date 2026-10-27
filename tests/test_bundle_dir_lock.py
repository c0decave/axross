"""A running one-file bundle keeps its unpacked folder when the temp cleaner runs.

PyInstaller unpacks the one-file binary into ``/tmp/_MEI*`` and holds no
lock on it. systemd-tmpfiles cleans ``/tmp`` by age every day (Arch's
``q /tmp 1777 root root 10d``): every file the process has not touched for
ten days - the Qt plugins, translations and extension modules a long-running
axross loads later - is deleted under it. Measured with the 0.14.102
binary and the age shortened to 2 s: 2907 of 2907 files gone, then
``import PyQt6.QtSvg`` -> ModuleNotFoundError. tmpfiles skips a folder on
which it finds a BSD lock (tmpfiles.d(5), "Age");
``core.frozen_archive.lock_bundle_dir`` holds a shared one for the life of
the process.

The cleaner here is the real ``systemd-tmpfiles --clean`` with a config of
our own (an age of one second on a scratch folder), so the tests show its
real rule, not a model of it.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import frozen_archive as FA  # noqa: E402

TMPFILES = shutil.which("systemd-tmpfiles")
needs_tmpfiles = pytest.mark.skipif(TMPFILES is None, reason="needs systemd-tmpfiles")
needs_flock = pytest.mark.skipif(os.name == "nt", reason="flock is POSIX")


def _bundle(tmp_path: Path) -> tuple[Path, Path]:
    """(the temp root, an unpacked-bundle-like folder in it)."""
    root = tmp_path / "tmp"
    meipass = root / "_MEItest"
    (meipass / "PyQt6" / "Qt6" / "plugins").mkdir(parents=True)
    (meipass / "PyQt6" / "QtSvg.abi3.so").write_bytes(b"\x7fELF")
    (meipass / "PyQt6" / "Qt6" / "plugins" / "libqsvg.so").write_bytes(b"\x7fELF")
    (meipass / "resources" / "i18n").mkdir(parents=True)
    (meipass / "resources" / "i18n" / "de.json").write_text("{}")
    return root, meipass


def _clean(tmp_path: Path, root: Path) -> None:
    """systemd-tmpfiles' age cleaning of *root*, every file older than 1 s."""
    conf = tmp_path / "clean.conf"
    conf.write_text(f"q {root} 1777 - - 1s\n")
    # Aged by waiting, not by os.utime: the cleaner also looks at the
    # change time, which utime itself sets to now.
    time.sleep(2.2)
    subprocess.run([TMPFILES, "--clean", str(conf)], check=True, capture_output=True,
                   timeout=60)


def _files(folder: Path) -> int:
    return sum(len(files) for _d, _s, files in os.walk(folder))


@pytest.fixture
def frozen(monkeypatch, tmp_path):
    root, meipass = _bundle(tmp_path)
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", str(meipass), raising=False)
    yield root, meipass
    FA._unlock_bundle_dir_for_tests(str(meipass))


# -- happy ----------------------------------------------------------------------------------

@needs_tmpfiles
@needs_flock
def test_happy_a_locked_bundle_folder_survives_the_temp_cleaner(frozen, tmp_path):
    root, meipass = frozen
    assert FA.lock_bundle_dir() is True
    _clean(tmp_path, root)
    assert _files(meipass) == 3
    assert (meipass / "PyQt6" / "QtSvg.abi3.so").read_bytes() == b"\x7fELF"


@needs_tmpfiles
def test_happy_control_an_unlocked_bundle_folder_is_emptied(tmp_path):
    """The rule the lock protects against, on this host: without it the
    same cleaning removes every file (the state of every release so far)."""
    root, meipass = _bundle(tmp_path)
    _clean(tmp_path, root)
    assert not meipass.exists() or _files(meipass) == 0


@needs_flock
def test_happy_the_lock_is_a_shared_flock_on_the_folder(frozen):
    import fcntl

    _root, meipass = frozen
    assert FA.lock_bundle_dir() is True
    fd = os.open(meipass, os.O_RDONLY)
    try:
        # another shared lock is granted, an exclusive one (the cleaner's) is not
        fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        fcntl.flock(fd, fcntl.LOCK_UN)
        with pytest.raises(BlockingIOError):
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally:
        os.close(fd)


def test_happy_main_locks_right_after_pinning_the_archive():
    body = (Path(__file__).resolve().parent.parent / "main.py").read_text().split(
        "def main() -> int:", 1)[1]
    assert body.index("pin_frozen_archive()") < body.index("lock_bundle_dir()") \
        < body.index("restore_loader_env(")


# -- sad ------------------------------------------------------------------------------------

def test_sad_not_frozen_locks_nothing(monkeypatch):
    monkeypatch.setattr(sys, "frozen", False, raising=False)
    assert FA.lock_bundle_dir() is False


def test_sad_a_missing_folder_is_reported_not_raised(monkeypatch, tmp_path, caplog):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path / "gone"), raising=False)
    assert FA.lock_bundle_dir() is False
    assert "not locked" in caplog.text


def test_sad_without_flock_nothing_is_locked(monkeypatch, tmp_path):
    monkeypatch.setitem(sys.modules, "fcntl", None)  # import fcntl -> ImportError
    assert FA.lock_bundle_dir(str(tmp_path)) is False
    assert str(tmp_path) not in FA._BUNDLE_DIR_LOCK


@needs_flock
def test_sad_a_folder_someone_holds_exclusively_is_reported(tmp_path, caplog):
    import fcntl

    fd = os.open(tmp_path, os.O_RDONLY)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert FA.lock_bundle_dir(str(tmp_path)) is False
        assert "not locked" in caplog.text
    finally:
        os.close(fd)


# -- edge -----------------------------------------------------------------------------------

@needs_flock
def test_edge_a_second_call_keeps_the_one_lock(frozen):
    _root, meipass = frozen
    assert FA.lock_bundle_dir() is True
    fd = FA._BUNDLE_DIR_LOCK[str(meipass)]
    assert FA.lock_bundle_dir() is True
    assert FA._BUNDLE_DIR_LOCK[str(meipass)] == fd


@needs_flock
def test_edge_the_lock_is_not_inherited_by_child_processes(frozen):
    """A child (a shell, a helper) must not keep the folder locked after
    axross ended; the bootloader removes it then."""
    _root, meipass = frozen
    assert FA.lock_bundle_dir() is True
    assert os.get_inheritable(FA._BUNDLE_DIR_LOCK[str(meipass)]) is False


def test_edge_no_meipass_on_a_frozen_process_locks_nothing(monkeypatch):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.delattr(sys, "_MEIPASS", raising=False)
    assert FA.lock_bundle_dir() is False


# -- e2e: the real one-file binary ------------------------------------------------------------

needs_bundle = pytest.mark.skipif(not os.environ.get("AXROSS_FROZEN_BINARY") or TMPFILES is None,
                                  reason="needs a built bundle and systemd-tmpfiles")


@needs_bundle
def test_e2e_a_running_bundle_imports_late_after_the_temp_cleaner_ran(tmp_path):
    """AXROSS_FROZEN_BINARY runs a --script that waits; the cleaner runs on
    its temp root; then the script imports a module it had not loaded."""
    temp, home = tmp_path / "tmp", tmp_path / "home"
    temp.mkdir()
    home.mkdir()
    go = tmp_path / "go"
    script = tmp_path / "late.py"
    script.write_text(
        "import os, sys, time\n"
        "print('started', flush=True)\n"
        f"while not os.path.exists({str(go)!r}):\n    time.sleep(0.05)\n"
        "import PyQt6.QtSvg\n"
        "print('late import ok', flush=True)\n")
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(home),
           "TMPDIR": str(temp), "QT_QPA_PLATFORM": "offscreen"}
    proc = subprocess.Popen([os.environ["AXROSS_FROZEN_BINARY"], "--script", str(script)],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env)
    try:
        seen = []
        for line in proc.stdout:
            seen.append(line)
            if line.strip() == "started":
                break
        assert seen and seen[-1].strip() == "started", "".join(seen)[-1500:]
        _clean(tmp_path, temp)
        go.write_text("")
        out, _ = proc.communicate(timeout=120)
    finally:
        if proc.poll() is None:
            proc.kill()
    assert "late import ok" in out, out[-1500:]
