"""Help > Features… asks what is installed off the GUI thread.

Measured 2026-10-25: the first Help > Features… of a session froze the
window ~0.95 s (GUI thread CPU) - FeaturesDialog.__init__ ran
core.features.collect(), whose backend probes import every optional
package (exchangelib, azure-storage-blob, ...) to see whether it loads.
The dialog now opens at once with "Checking what is installed…" and fills
the table when the answer arrives; a feature asked for (select) is
selected then. The table is the one the synchronous collect gave.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QEvent  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import features as F  # noqa: E402

APP = QApplication.instance() or QApplication([])


def wait_loaded(dlg, timeout: float = 30.0) -> None:
    end = time.monotonic() + timeout
    while not dlg.loaded and time.monotonic() < end:
        APP.processEvents()
        time.sleep(0.005)
    assert dlg.loaded, "the features never arrived"


def _rows(dlg) -> list[tuple]:
    return [tuple(dlg.table.item(r, c).text() for c in range(dlg.table.columnCount()))
            for r in range(dlg.table.rowCount())]


@pytest.fixture
def dialogs():
    made = []
    yield made
    for dlg in made:
        dlg.close()
        dlg.deleteLater()
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)


def _open(dialogs, **kw):
    from ui.features_dialog import FeaturesDialog

    dlg = FeaturesDialog(runner=lambda *a: None, **kw)
    dialogs.append(dlg)
    dlg.show()
    return dlg


# -- happy ---------------------------------------------------------------------


def test_happy_the_features_are_collected_off_the_gui_thread(dialogs, monkeypatch) -> None:
    threads = []
    real = F.collect
    monkeypatch.setattr(F, "collect",
                        lambda: (threads.append(threading.current_thread()), real())[1])
    dlg = _open(dialogs)
    wait_loaded(dlg)
    assert threads and threading.main_thread() not in threads


def test_happy_the_table_is_the_one_the_synchronous_collect_gave(dialogs) -> None:
    dlg = _open(dialogs)
    wait_loaded(dlg)
    expected = F.collect()
    assert [dlg.feature_at(r) for r in range(dlg.table.rowCount())] == expected
    missing = sum(1 for f in expected if not f.available)
    assert dlg.summary.text() == f"{len(expected)} features, {missing} missing"
    dlg.missing_only.setChecked(True)
    assert {row[2] for row in _rows(dlg)} <= {"Missing"}


def test_happy_opening_shows_that_it_is_checking(dialogs, monkeypatch) -> None:
    gate = threading.Event()
    real = F.collect
    monkeypatch.setattr(F, "collect", lambda: (gate.wait(10), real())[1])
    dlg = _open(dialogs)
    APP.processEvents()
    assert not dlg.loaded
    assert dlg.summary.text() == "Checking what is installed…"
    assert dlg.table.rowCount() == 0
    assert not dlg.install_button.isEnabled() and not dlg.copy_button.isEnabled()
    gate.set()
    wait_loaded(dlg)
    assert dlg.table.rowCount() > 0


# -- sad -----------------------------------------------------------------------


def test_sad_a_failing_collect_says_so_and_crashes_nothing(dialogs, monkeypatch) -> None:
    def broken():
        raise RuntimeError("probe exploded")

    monkeypatch.setattr(F, "collect", broken)
    dlg = _open(dialogs)
    wait_loaded(dlg)
    assert "probe exploded" in dlg.summary.text()
    assert dlg.table.rowCount() == 0


def test_sad_closing_while_it_checks_drops_the_answer(dialogs, monkeypatch) -> None:
    gate = threading.Event()
    real = F.collect
    monkeypatch.setattr(F, "collect", lambda: (gate.wait(10), real())[1])
    dlg = _open(dialogs)
    dlg.close()
    gate.set()
    end = time.monotonic() + 1
    while time.monotonic() < end:
        APP.processEvents()
    assert dlg.table.rowCount() == 0  # nothing filled into a closed window


# -- edge ----------------------------------------------------------------------


def test_edge_a_feature_asked_for_before_the_answer_is_selected_after_it(dialogs,
                                                                         monkeypatch) -> None:
    gate = threading.Event()
    real = F.collect
    monkeypatch.setattr(F, "collect", lambda: (gate.wait(10), real())[1])
    dlg = _open(dialogs)
    dlg.missing_only.setChecked(True)
    key = real()[3].key
    dlg.select(key)
    gate.set()
    wait_loaded(dlg)
    rows = sorted({i.row() for i in dlg.table.selectedIndexes()})
    assert [dlg.feature_at(r).key for r in rows] == [key]
    assert not dlg.missing_only.isChecked()


def test_edge_reload_while_checking_keeps_one_answer(dialogs, monkeypatch) -> None:
    calls = []
    real = F.collect

    def counted():
        calls.append(1)
        time.sleep(0.05)
        return real()

    monkeypatch.setattr(F, "collect", counted)
    dlg = _open(dialogs)
    dlg.reload()
    wait_loaded(dlg)
    assert dlg.table.rowCount() == len(real())
    assert 1 <= len(calls) <= 2


# -- e2e -----------------------------------------------------------------------


def test_e2e_help_features_of_the_window_opens_at_once_and_selects_a_feature(
        tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    from ui.main_window import MainWindow

    gate = threading.Event()
    real = F.collect
    monkeypatch.setattr(F, "collect", lambda: (gate.wait(10), real())[1])
    win = MainWindow()
    try:
        win._reconnect_timer.stop()
        win.show()
        key = next(f.key for f in real() if f.key.startswith("tool:"))
        win._show_features(key)
        dlg = win._features_dialog
        assert dlg.isVisible() and not dlg.loaded
        gate.set()
        wait_loaded(dlg)
        rows = sorted({i.row() for i in dlg.table.selectedIndexes()})
        assert [dlg.feature_at(r).key for r in rows] == [key]
    finally:
        gate.set()
        win.close()
        win.deleteLater()
        APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)
