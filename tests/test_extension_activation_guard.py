"""An extension whose activate() hung or crashed is skipped on the next start.

Incident: the Media Player extension's activate() hung natively (QAudioDecoder
-> cuInit) before the window was shown, and every later start hung the same
way. Now the host writes a marker (extension, pid, time) before it runs an
extension's code and removes it afterwards. A start that finds a marker of a
process that is gone (or one that has been activating for longer than the
startup watchdog's bound) does not load that extension: it stays switched on,
the user gets a notice with Try Again / Keep Off once the window is up, and
the log says why. ``--safe-mode`` loads no extension at the start at all.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import extensions as EX  # noqa: E402
from core import startup_guard as SG  # noqa: E402


def _info(name: str = "hello", source: str = "user") -> EX.ExtensionInfo:
    return EX.ExtensionInfo(
        ext_id=f"{source}:{name}", source=source, module_name=name,
        path=f"/nowhere/{name}.py", name=name.title(),
    )


def _dead_pid() -> int:
    proc = subprocess.Popen([sys.executable, "-c", "pass"])
    proc.wait()
    return proc.pid


def _write_marker(pid: int, ext_id: str = "user:hello", *, started: float | None = None,
                  **extra) -> Path:
    folder = EX.activation_dir()
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"{pid}.json"
    data = {"pid": pid, "ext_id": ext_id, "name": "Hello",
            "started": time.time() if started is None else started, **extra}
    path.write_text(json.dumps(data))
    return path


@pytest.fixture(autouse=True)
def own_home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    EX.set_safe_mode(False)
    yield
    EX.set_safe_mode(False)


# --- core: happy -------------------------------------------------------------


def test_happy_a_marker_lives_exactly_while_activate_runs():
    marker = EX.begin_activation(_info())
    assert marker is not None and marker.exists()
    data = json.loads(marker.read_text())
    assert data["pid"] == os.getpid()
    assert data["ext_id"] == "user:hello"
    assert data["name"] == "Hello"
    assert abs(data["started"] - time.time()) < 5
    ext_id, name, running = EX.current_activation()
    assert (ext_id, name) == ("user:hello", "Hello") and running >= 0
    EX.end_activation(marker)
    assert not marker.exists()
    assert EX.current_activation() is None


def test_happy_the_marker_folder_and_file_are_private():
    marker = EX.begin_activation(_info())
    try:
        assert (marker.parent.stat().st_mode & 0o777) == 0o700
        assert (marker.stat().st_mode & 0o777) == 0o600
    finally:
        EX.end_activation(marker)


def test_happy_a_marker_of_a_process_that_is_gone_is_collected():
    pid = _dead_pid()
    path = _write_marker(pid)
    (found,) = EX.collect_stale_activations()
    assert found["ext_id"] == "user:hello"
    assert found["pid"] == pid
    assert found["reason"] == "ended"
    assert not path.exists()


def test_happy_suspension_is_stored_beside_the_switch_and_cleared_by_it():
    EX.set_enabled("user:hello", True)
    EX.set_suspended("user:hello", True)
    assert EX.suspended_ids() == {"user:hello"}
    assert EX.enabled_ids() == {"user:hello"}  # it stays switched on
    EX.set_enabled("user:hello", True)  # switching it on again is a new try
    assert EX.suspended_ids() == set()
    EX.set_suspended("user:hello", True)
    EX.set_enabled("user:hello", False)
    assert EX.suspended_ids() == set() and EX.enabled_ids() == set()


def test_happy_safe_mode_is_a_switch_of_this_process():
    assert EX.safe_mode() is False
    EX.set_safe_mode(True)
    assert EX.safe_mode() is True


def test_happy_the_hung_bound_is_the_startup_watchdogs():
    assert EX.HUNG_ACTIVATION_SECONDS == SG.WATCHDOG_SECONDS
    assert 0 < EX.SLOW_ACTIVATE_SECONDS < EX.HUNG_ACTIVATION_SECONDS


# --- core: sad ---------------------------------------------------------------


def test_sad_an_unwritable_state_folder_never_stops_the_load(tmp_path, monkeypatch):
    blocker = tmp_path / "file-not-folder"
    blocker.write_text("x")
    monkeypatch.setattr(EX, "activation_dir", lambda: blocker / "sub")
    assert EX.begin_activation(_info()) is None
    EX.end_activation(None)  # no exception
    assert EX.current_activation() is None


def test_sad_a_malformed_marker_is_removed_and_ignored():
    folder = EX.activation_dir()
    folder.mkdir(parents=True)
    broken = folder / "123.json"
    broken.write_text("{not json")
    wrong = folder / "456.json"
    wrong.write_text(json.dumps({"pid": "x", "ext_id": 5}))
    foreign = folder / "notes.txt"
    foreign.write_text("keep me")
    assert EX.collect_stale_activations() == []
    assert not broken.exists() and not wrong.exists()
    assert foreign.exists()


def test_sad_a_missing_state_folder_has_nothing_to_collect():
    assert EX.collect_stale_activations() == []


def test_sad_a_marker_whose_pid_was_reused_by_another_process_is_stale():
    if not Path("/proc/self/stat").exists():
        pytest.skip("needs /proc")
    path = _write_marker(os.getppid(), proc_start=1)  # alive, but started at another time
    (found,) = EX.collect_stale_activations()
    assert found["reason"] == "ended"
    assert not path.exists()


# --- core: edge --------------------------------------------------------------


def test_edge_a_marker_of_a_running_process_is_left_alone():
    path = _write_marker(os.getppid())
    assert EX.collect_stale_activations() == []
    assert path.exists()


def test_edge_a_process_activating_for_longer_than_the_bound_counts_as_hung():
    # The hung process still runs (the user started axross again beside it):
    # the new start must not hang on the same extension.
    path = _write_marker(os.getppid(), started=time.time() - EX.HUNG_ACTIVATION_SECONDS - 5)
    (found,) = EX.collect_stale_activations()
    assert found["reason"] == "hung"
    assert path.exists()  # its owner removes it if it ever finishes


def test_edge_a_marker_with_this_processs_own_pid_is_from_an_earlier_life():
    # In a container a restarted axross often gets the pid the hung one had.
    path = _write_marker(os.getpid())
    (found,) = EX.collect_stale_activations()
    assert found["reason"] == "ended"
    assert not path.exists()


def test_edge_suspension_survives_an_unrelated_settings_change():
    EX.set_enabled("user:a", True)
    EX.set_suspended("user:a", True)
    EX.set_paused("user:b", True)
    EX.set_enabled("user:c", True)
    assert EX.suspended_ids() == {"user:a"}
    data = json.loads(EX.settings_file().read_text())
    assert data["enabled"] == ["user:a", "user:c"]


# --- the window --------------------------------------------------------------

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QEvent  # noqa: E402
from PyQt6.QtWidgets import QApplication, QMessageBox  # noqa: E402

APP = QApplication.instance() or QApplication([])


def pump(seconds: float = 0.05) -> None:
    end = time.time() + seconds
    while time.time() < end:
        APP.processEvents()
        time.sleep(0.01)


def write_ext(name: str, body: str) -> Path:
    folder = EX.extensions_dir()
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"{name}.py"
    path.write_text(
        f'EXTENSION = {{"name": "{name.title()}", "version": "1.0", "description": "test"}}\n\n'
        + textwrap.dedent(body)
    )
    return path


HELLO = """
def activate(api):
    api.add_menu_action("Say Hello", lambda: api.notify("Hello"))
"""


@pytest.fixture
def make_window():
    from ui.main_window import MainWindow

    made = []

    def make():
        win = MainWindow()
        win._reconnect_timer.stop()
        win.show()
        pump()
        made.append(win)
        return win

    yield make
    for win in made:
        win.close()
        win.deleteLater()
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    pump()


def _notices(win) -> list[QMessageBox]:
    return [w for w in win.findChildren(QMessageBox)
            if w.objectName() == "axExtensionStartNotice" and w.isVisible()]


def _button(box: QMessageBox, text: str):
    (button,) = [b for b in box.buttons() if b.text().replace("&", "") == text]
    return button


def test_happy_e2e_a_hung_extension_is_skipped_and_the_notice_offers_a_retry(make_window):
    write_ext("hello", HELLO)
    EX.set_enabled("user:hello", True)
    _write_marker(_dead_pid())
    win = make_window()
    host = win.extension_host
    assert "user:hello" not in host.loaded_ids()
    assert "earlier start" in host.error("user:hello")
    assert EX.enabled_ids() == {"user:hello"}
    assert EX.suspended_ids() == {"user:hello"}
    (box,) = _notices(win)
    assert not box.isModal()
    assert "Hello" in box.text()
    _button(box, "Try Again").click()
    pump()
    assert "user:hello" in host.loaded_ids()
    assert EX.suspended_ids() == set()
    assert _notices(win) == []
    assert not list(EX.activation_dir().glob("*.json"))


def test_happy_e2e_keep_off_switches_it_off(make_window):
    write_ext("hello", HELLO)
    EX.set_enabled("user:hello", True)
    _write_marker(_dead_pid())
    win = make_window()
    (box,) = _notices(win)
    _button(box, "Keep Off").click()
    pump()
    assert EX.enabled_ids() == set()
    assert EX.suspended_ids() == set()
    assert "user:hello" not in win.extension_host.loaded_ids()


def test_happy_a_normal_load_leaves_no_marker_and_logs_its_duration(make_window, caplog):
    write_ext("hello", HELLO)
    EX.set_enabled("user:hello", True)
    with caplog.at_level(logging.INFO, logger="ui.extension_host"):
        win = make_window()
    assert "user:hello" in win.extension_host.loaded_ids()
    assert not list(EX.activation_dir().glob("*.json"))
    assert any("Extension loaded: Hello (user:hello) in " in r.getMessage()
               for r in caplog.records)
    assert _notices(win) == []


def test_happy_a_slow_activate_is_logged_as_a_warning(make_window, caplog, monkeypatch):
    write_ext("slow", "import time\n\ndef activate(api):\n    time.sleep(0.3)\n")
    EX.set_enabled("user:slow", True)
    monkeypatch.setattr(EX, "SLOW_ACTIVATE_SECONDS", 0.1)
    with caplog.at_level(logging.INFO, logger="ui.extension_host"):
        make_window()
    (warning,) = [r for r in caplog.records if r.levelno == logging.WARNING
                  and "user:slow" in r.getMessage()]
    assert "took 0." in warning.getMessage()


def test_happy_safe_mode_loads_no_extension_at_the_start(make_window):
    write_ext("hello", HELLO)
    EX.set_enabled("user:hello", True)
    EX.set_safe_mode(True)
    win = make_window()
    host = win.extension_host
    assert host.loaded_ids() == []
    assert "safe mode" in host.error("user:hello")
    assert EX.enabled_ids() == {"user:hello"}
    # a deliberate switch-on in the session still loads it
    host.set_enabled("user:hello", True)
    assert "user:hello" in host.loaded_ids()


def test_sad_an_activate_that_raises_leaves_no_marker(make_window):
    write_ext("broken", "def activate(api):\n    raise RuntimeError('nope')\n")
    EX.set_enabled("user:broken", True)
    win = make_window()
    assert "nope" in win.extension_host.error("user:broken")
    assert not list(EX.activation_dir().glob("*.json"))
    assert _notices(win) == []


def test_sad_module_code_that_raises_on_import_leaves_no_marker(make_window):
    write_ext("badimport", "raise ImportError('gone')\n\ndef activate(api):\n    pass\n")
    EX.set_enabled("user:badimport", True)
    make_window()
    assert not list(EX.activation_dir().glob("*.json"))


def test_sad_closing_the_notice_keeps_it_suspended_for_the_next_start(make_window):
    write_ext("hello", HELLO)
    EX.set_enabled("user:hello", True)
    _write_marker(_dead_pid())
    win = make_window()
    (box,) = _notices(win)
    box.close()
    pump()
    assert EX.suspended_ids() == {"user:hello"}
    again = make_window()
    assert "user:hello" not in again.extension_host.loaded_ids()
    assert len(_notices(again)) == 1


def test_edge_the_marker_is_there_while_activate_runs(make_window):
    seen = EX.activation_dir() / f"{os.getpid()}.json"
    write_ext("peek", f"""
from pathlib import Path

SEEN = []

def activate(api):
    SEEN.append(Path({str(seen)!r}).exists())
    api.add_menu_action("Peek", lambda: None)
""")
    EX.set_enabled("user:peek", True)
    win = make_window()
    module = win.extension_host.module("user:peek")
    assert module.SEEN == [True]
    assert not seen.exists()


def test_edge_reload_retries_a_suspended_extension(make_window):
    write_ext("hello", HELLO)
    EX.set_enabled("user:hello", True)
    _write_marker(_dead_pid())
    win = make_window()
    for box in _notices(win):
        box.close()
    win.extension_host.reload()
    assert "user:hello" in win.extension_host.loaded_ids()
    assert EX.suspended_ids() == set()


def test_edge_a_marker_of_a_switched_off_extension_is_dropped_quietly(make_window):
    write_ext("hello", HELLO)
    _write_marker(_dead_pid())
    win = make_window()
    assert EX.suspended_ids() == set()
    assert _notices(win) == []
    assert not list(EX.activation_dir().glob("*.json"))


def test_edge_several_skipped_extensions_each_get_their_notice(make_window):
    write_ext("one", HELLO)
    write_ext("two", HELLO)
    EX.set_enabled("user:one", True)
    EX.set_enabled("user:two", True)
    _write_marker(_dead_pid(), "user:one")
    _write_marker(_dead_pid(), "user:two")
    win = make_window()
    assert win.extension_host.loaded_ids() == []
    assert len(_notices(win)) == 2
