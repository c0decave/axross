"""The paths of core.extensions no test reached (branch coverage, 86 %).

A marker of a process that ended but is not reaped yet (a zombie), a
marker naming another user's process, a marker that cannot be removed, an
extensions.json that is a folder or a list, names the loader must skip and
files it cannot read: each decides whether an extension is loaded, kept
off, or whether the user's settings survive a save.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import extensions as EX  # noqa: E402


@pytest.fixture(autouse=True)
def own_home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()
    EX.set_safe_mode(False)
    yield
    EX.set_safe_mode(False)


def _write_marker(pid: int, **extra) -> Path:
    folder = EX.activation_dir()
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"{pid}.json"
    path.write_text(json.dumps({"pid": pid, "ext_id": "user:hello", "name": "Hello",
                                "started": time.time(), **extra}))
    return path


def _info(name: str = "hello") -> EX.ExtensionInfo:
    return EX.ExtensionInfo(ext_id=f"user:{name}", source="user", module_name=name,
                            path=f"/nowhere/{name}.py", name=name.title())


# --- activation markers --------------------------------------------------------------

@pytest.mark.skipif(not Path("/proc/self/stat").exists(), reason="needs /proc")
def test_happy_a_marker_of_a_zombie_counts_as_ended():
    """The process ended inside activate() but its parent has not reaped it:
    kill(pid, 0) still succeeds, /proc says Z."""
    child = subprocess.Popen([sys.executable, "-c", "pass"])
    try:
        end = time.monotonic() + 10
        while time.monotonic() < end:
            state = Path(f"/proc/{child.pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
            if state == "Z":
                break
            time.sleep(0.02)
        assert state == "Z"
        path = _write_marker(child.pid, proc_start=EX._process_start(child.pid))
        found = EX.collect_stale_activations()
        assert [(f["pid"], f["reason"]) for f in found] == [(child.pid, "ended")]
        assert not path.exists()
    finally:
        child.wait()


@pytest.mark.skipif(os.name != "posix" or os.getuid() == 0, reason="needs a non-root user")
def test_sad_a_marker_naming_another_users_process_counts_as_ended():
    """pid 1 belongs to root: kill(1, 0) is refused. The marker's writer
    (always this user) is gone, so the pid was reused."""
    path = _write_marker(1)
    found = EX.collect_stale_activations()
    assert [(f["pid"], f["reason"]) for f in found] == [(1, "ended")]
    assert not path.exists()


def test_edge_the_start_time_of_a_gone_process_is_unknown():
    child = subprocess.Popen([sys.executable, "-c", "pass"])
    child.wait()
    assert EX._process_start(child.pid) is None
    assert EX._process_start(-5) is None


def test_edge_without_proc_a_live_process_counts_as_alive(monkeypatch):
    """macOS and the BSDs have no /proc: kill(pid, 0) alone decides."""
    real_exists = Path.exists
    monkeypatch.setattr(Path, "exists",
                        lambda self: False if str(self).startswith("/proc/") else real_exists(self))
    assert EX._process_alive(os.getppid(), 12345) is True


def test_sad_a_marker_that_cannot_be_removed_is_logged(caplog):
    marker = EX.activation_dir() / "4242.json"
    marker.mkdir(parents=True)  # a folder: unlink fails with IsADirectoryError
    with caplog.at_level(logging.WARNING, logger=EX.log.name):
        EX.end_activation(marker)
    assert EX.current_activation() is None
    assert any("Cannot remove the extension marker" in r.getMessage() for r in caplog.records)


def test_edge_a_marker_removed_already_is_fine(caplog):
    marker = EX.begin_activation(_info())
    assert marker is not None and EX.current_activation()[0] == "user:hello"
    marker.unlink()
    with caplog.at_level(logging.WARNING, logger=EX.log.name):
        EX.end_activation(marker)
    assert EX.current_activation() is None
    assert not caplog.records


def test_sad_an_unreadable_marker_that_cannot_be_removed_is_skipped():
    (EX.activation_dir() / "777.json").mkdir(parents=True)
    assert EX.collect_stale_activations() == []
    assert (EX.activation_dir() / "777.json").is_dir()


# --- extensions.json -----------------------------------------------------------------

def test_sad_a_settings_file_that_is_a_folder_is_never_replaced(caplog):
    folder = EX.settings_file()
    folder.mkdir(parents=True)
    (folder / "keep").write_text("x")
    assert EX.enabled_ids() == set()
    with pytest.raises(OSError, match="could not be kept aside"):
        EX.set_enabled("user:hello", True)
    assert (folder / "keep").read_text() == "x"


def test_sad_a_settings_file_that_is_a_list_is_kept_aside_before_a_save():
    path = EX.settings_file()
    path.parent.mkdir(parents=True)
    path.write_text('["user:old"]')
    assert EX.enabled_ids() == set()
    EX.set_enabled("user:hello", True)
    assert EX.enabled_ids() == {"user:hello"}
    kept = list(path.parent.glob("extensions.json.unreadable-*"))
    assert len(kept) == 1 and kept[0].read_text() == '["user:old"]'


# --- discovery -----------------------------------------------------------------------

_GOOD = 'EXTENSION = {"name": "X"}\n\ndef activate(api):\n    pass\n'


def test_edge_names_the_loader_cannot_import_are_skipped(tmp_path):
    folder = tmp_path / "ext"
    folder.mkdir()
    (folder / "good.py").write_text(_GOOD)
    (folder / "1bad.py").write_text(_GOOD)  # no identifier
    (folder / "has-dash.py").write_text(_GOOD)
    (folder / "pkg_no_init").mkdir()
    (folder / "pkg_link_init").mkdir()
    (folder / "pkg_link_init" / "__init__.py").symlink_to(folder / "good.py")
    (folder / "pkg").mkdir()
    (folder / "pkg" / "__init__.py").write_text(_GOOD)
    assert [name for name, _ in EX._candidates(folder)] == ["good", "pkg"]


def test_sad_a_file_that_is_no_utf8_cannot_be_read(tmp_path):
    path = tmp_path / "latin.py"
    path.write_bytes(b"# \xff\xfe caf\xe9\n" + _GOOD.encode())
    fields, error = EX._manifest(path)
    assert fields == {} and error.startswith("cannot read:")


def test_sad_a_file_that_vanished_cannot_be_read(tmp_path):
    fields, error = EX._manifest(tmp_path / "gone.py")
    assert fields == {} and error.startswith("cannot read:")


def test_edge_files_that_are_no_module_are_ignored(tmp_path):
    folder = tmp_path / "ext"
    folder.mkdir()
    (folder / "README.txt").write_text("x")
    (folder / "notes.md").write_text("x")
    assert EX._candidates(folder) == []


# --- Windows: kill(pid, 0) would send CTRL_C_EVENT, the kernel is asked instead -------

class _Kernel32:
    def __init__(self, handle=7, query_ok=True, code=259):
        self.handle, self.query_ok, self.code, self.closed = handle, query_ok, code, []

    def OpenProcess(self, access, inherit, pid):  # noqa: N802 - the Win32 name
        return self.handle

    def GetExitCodeProcess(self, handle, ref):  # noqa: N802
        ref._obj.value = self.code
        return self.query_ok

    def CloseHandle(self, handle):  # noqa: N802
        self.closed.append(handle)


@pytest.mark.parametrize(("kernel", "alive"), [
    (_Kernel32(), True),                    # STILL_ACTIVE
    (_Kernel32(code=0), False),             # exited
    (_Kernel32(handle=0), False),           # no such process / no access
    (_Kernel32(query_ok=False), False),     # the query failed
])
def test_edge_on_windows_the_kernel_decides_whether_the_writer_runs(monkeypatch, kernel, alive):
    import ctypes
    import types

    monkeypatch.setattr(ctypes, "windll", types.SimpleNamespace(kernel32=kernel), raising=False)
    monkeypatch.setattr(os, "name", "nt")
    assert EX._process_alive(4242, None) is alive
    assert kernel.closed == ([] if kernel.handle == 0 else [kernel.handle])


def test_edge_a_proc_stat_that_vanishes_while_read_counts_as_alive(monkeypatch):
    """The process ended between exists() and read_text(): not provably
    gone, so the marker is left for the next start."""
    real_read = Path.read_text

    def flaky(self, *a, **k):
        if str(self) == f"/proc/{os.getppid()}/stat":
            raise FileNotFoundError(str(self))
        return real_read(self, *a, **k)

    monkeypatch.setattr(Path, "read_text", flaky)
    assert EX._process_alive(os.getppid(), None) is True


# --- extensions.json that is not UTF-8 -------------------------------------------------
#
# Found by a mutation sweep of every hand-editable store: an extensions.json
# that is not UTF-8 (saved in Latin-1 by an editor, a damaged disk block)
# raised UnicodeDecodeError out of _read_settings - read_text() raises it,
# and only OSError was caught there. The main window reads the paused ids
# while it builds its ExtensionHost, so axross did not start.

_NOT_UTF8 = b'{"enabled": ["user:caf\xe9"], "paused": []}'


def _write_not_utf8() -> Path:
    path = EX.settings_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_NOT_UTF8)
    return path


def test_happy_a_utf8_settings_file_with_a_non_ascii_id_is_read():
    path = EX.settings_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('{"enabled": ["user:café"]}', encoding="utf-8")
    assert EX.enabled_ids() == {"user:café"}


def test_sad_a_settings_file_that_is_no_utf8_reads_as_unreadable(caplog):
    _write_not_utf8()
    with caplog.at_level(logging.WARNING, logger="core.extensions"):
        assert EX._read_settings() == ({}, False)
        assert EX.enabled_ids() == set()
        assert EX.paused_ids() == set()
        assert EX.suspended_ids() == set()
    assert "extensions.json" in caplog.text


def test_edge_a_save_over_a_settings_file_that_is_no_utf8_keeps_it_aside():
    path = _write_not_utf8()
    EX.set_enabled("user:hello", True)
    assert EX.enabled_ids() == {"user:hello"}
    kept = list(path.parent.glob("extensions.json.unreadable-*"))
    assert len(kept) == 1 and kept[0].read_bytes() == _NOT_UTF8


def test_e2e_the_main_window_starts_on_a_settings_file_that_is_no_utf8():
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")
    from PyQt6.QtCore import QEvent
    from PyQt6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication([])
    _write_not_utf8()
    from ui.main_window import MainWindow

    win = MainWindow()
    try:
        win._reconnect_timer.stop()
        win.show()
        app.processEvents()
        assert win.extension_host is not None
        assert not win.extension_host.is_paused("user:café")
    finally:
        win.close()
        win.deleteLater()
        app.sendPostedEvents(None, QEvent.Type.DeferredDelete)
        app.processEvents()
