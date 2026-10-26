"""The connection dialog asks which backends are installed off the GUI thread.

Measured 2026-10-25: the first Connect to Server… of a session froze the
window ~1.06 s (GUI thread CPU) - ConnectionDialog._setup_ui read
``info.available`` of every backend for the "(pip install axross[...])"
hints, and each first read imports the backend's packages (exchangelib,
azure-storage-blob, ...). The dialog now opens with the plain backend
names and adds the hints when a background check has the answers; the
labels are then the ones the synchronous dialog showed. Connect still
checks the chosen backend itself (_validate_backend_available).
"""

from __future__ import annotations

import os
import sys
import tempfile
import threading
import time
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QEvent, QTimer  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import backend_registry as BR  # noqa: E402

APP = QApplication.instance() or QApplication([])


@pytest.fixture()
def manager():
    from core.profiles import ProfileManager

    with tempfile.TemporaryDirectory() as tmp:
        with mock.patch("core.profiles.CONFIG_DIR", Path(tmp)), \
                mock.patch("core.profiles.PROFILES_FILE", Path(tmp) / "profiles.json"):
            yield ProfileManager()


@pytest.fixture
def dialogs():
    made = []
    yield made
    for dlg in made:
        dlg.close()
        dlg.deleteLater()
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)


def _open(dialogs, manager):
    from ui.connection_dialog import ConnectionDialog

    dlg = ConnectionDialog(manager)
    dialogs.append(dlg)
    return dlg


def wait_labels(dlg, timeout: float = 30.0) -> None:
    end = time.monotonic() + timeout
    while not dlg.labels_ready and time.monotonic() < end:
        APP.processEvents()
        time.sleep(0.005)
    assert dlg.labels_ready


def _expected_labels() -> list[str]:
    """The labels as the dialog made them before: name + hint when missing."""
    out = []
    for info in BR.all_backends():
        label = info.display_name
        if not info.available:
            if info.required_extra:
                label += f"  (pip install axross[{info.required_extra}])"
            elif info.install_hint:
                label += f"  (needs {info.install_hint})"
        out.append(label)
    return out


def _labels(dlg) -> list[str]:
    return [dlg._protocol_combo.itemText(i) for i in range(dlg._protocol_combo.count())]


@pytest.fixture
def probe_threads(monkeypatch):
    """Threads that read a backend's availability, every probe unresolved."""
    seen = []
    real = BR._available

    def recording(self):
        seen.append(threading.current_thread())
        return real(self)

    monkeypatch.setattr(BR.BackendInfo, "available", property(recording))
    return seen


# -- happy ---------------------------------------------------------------------


def test_happy_opening_reads_no_availability_on_the_gui_thread(dialogs, manager,
                                                               probe_threads) -> None:
    dlg = _open(dialogs, manager)
    assert threading.main_thread() not in probe_threads
    wait_labels(dlg)
    assert probe_threads and threading.main_thread() not in probe_threads


def test_happy_the_labels_are_the_ones_the_synchronous_dialog_showed(dialogs, manager) -> None:
    dlg = _open(dialogs, manager)
    wait_labels(dlg)
    assert _labels(dlg) == _expected_labels()
    assert dlg._protocol_ids == [i.protocol_id for i in BR.all_backends()]


def test_happy_before_the_answer_the_names_are_shown_and_sftp_is_chosen(dialogs, manager,
                                                                         monkeypatch) -> None:
    gate = threading.Event()
    real = BR._available
    monkeypatch.setattr(BR.BackendInfo, "available",
                        property(lambda self: (gate.wait(2), real(self))[1]))
    dlg = _open(dialogs, manager)
    assert _labels(dlg) == [i.display_name for i in BR.all_backends()]
    assert dlg._selected_protocol() == "sftp"
    gate.set()
    wait_labels(dlg)
    assert dlg._selected_protocol() == "sftp"  # the choice survives the relabel


# -- sad -----------------------------------------------------------------------


def test_sad_a_failing_check_keeps_the_names_and_crashes_nothing(dialogs, manager,
                                                                 monkeypatch) -> None:
    def broken(self):
        raise RuntimeError("probe exploded")

    monkeypatch.setattr(BR.BackendInfo, "available", property(broken))
    dlg = _open(dialogs, manager)
    wait_labels(dlg)
    assert _labels(dlg) == [i.display_name for i in BR.all_backends()]


def test_sad_connect_before_the_answer_still_refuses_a_missing_backend(dialogs, manager,
                                                                       monkeypatch) -> None:
    missing = next(i for i in BR.all_backends() if i.required_extra)
    gate = threading.Event()
    real = BR._available

    def slow(self):
        if threading.current_thread() is not threading.main_thread():
            gate.wait(2)  # the background check has no answer yet
        if self.protocol_id == missing.protocol_id:
            return False  # not installed, whatever this host has
        return real(self)

    monkeypatch.setattr(BR.BackendInfo, "available", property(slow))
    dlg = _open(dialogs, manager)
    assert not dlg.labels_ready
    dlg._protocol_combo.setCurrentIndex(dlg._protocol_ids.index(missing.protocol_id))
    offered = []
    with mock.patch("ui.connection_dialog.offer_features",
                    side_effect=lambda parent, key, text: offered.append(key)):
        assert dlg._validate_backend_available() is False
    assert offered == [f"backend:{missing.protocol_id}"]
    gate.set()
    wait_labels(dlg)
    index = dlg._protocol_ids.index(missing.protocol_id)
    assert dlg._protocol_combo.itemText(index).endswith(f"(pip install axross[{missing.required_extra}])")


# -- edge ----------------------------------------------------------------------


def test_edge_closing_before_the_answer_changes_nothing(dialogs, manager, monkeypatch) -> None:
    gate = threading.Event()
    real = BR._available
    monkeypatch.setattr(BR.BackendInfo, "available",
                        property(lambda self: (gate.wait(2), real(self))[1]))
    dlg = _open(dialogs, manager)
    dlg.reject()
    gate.set()
    end = time.monotonic() + 1
    while time.monotonic() < end:
        APP.processEvents()
    assert _labels(dlg) == [i.display_name for i in BR.all_backends()]


def test_edge_a_profile_opened_for_editing_keeps_its_protocol(dialogs, manager) -> None:
    from core.profiles import ConnectionProfile
    from ui.connection_dialog import ConnectionDialog

    profile = ConnectionProfile(name="ftp box", protocol="ftp", host="10.0.0.9", port=21)
    dlg = ConnectionDialog(manager, profile=profile)
    dialogs.append(dlg)
    wait_labels(dlg)
    assert dlg._selected_protocol() == "ftp"


# -- e2e -----------------------------------------------------------------------


def test_e2e_connect_to_server_of_the_window_opens_and_labels(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    from ui.connection_dialog import ConnectionDialog
    from ui.main_window import MainWindow

    win = MainWindow()
    seen = {}
    try:
        win._reconnect_timer.stop()
        win.show()

        def drive() -> None:
            try:
                dlg = next(w for w in APP.topLevelWidgets()
                           if isinstance(w, ConnectionDialog) and w.isVisible())
                wait_labels(dlg)
                seen["labels"] = _labels(dlg)
            except BaseException as exc:  # handed to the test after exec()
                seen["error"] = exc
            finally:
                for w in APP.topLevelWidgets():
                    if isinstance(w, ConnectionDialog) and w.isVisible():
                        w.reject()

        QTimer.singleShot(100, drive)
        win._on_connect()
        if "error" in seen:
            raise seen["error"]
        assert seen["labels"] == _expected_labels()
    finally:
        win.close()
        win.deleteLater()
        APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)
