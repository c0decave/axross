"""The file pane's destructive entries honour a profile's production flag.

Before: ``ConnectionProfile.production`` promised a tarpit countdown for
"the GUI right-click destructive entries" (core/profiles.py), but only the
scripting verbs used ``production_gate``: Delete, Rename, Move (F6),
Change Permissions and Move to Trash in a pane ran at once.

Now each of them asks ``ui.production_gate.confirm_production`` first:
once per connection session a countdown dialog, Esc / Cancel stops the
operation, the countdown running out lets it go ahead.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import Qt, QTimer  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication, QDialog, QInputDialog, QMessageBox  # noqa: E402

from core import safety_tarpit  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from core.profiles import ConnectionProfile  # noqa: E402
from models.file_item import FileItem  # noqa: E402
from ui import production_gate as PG  # noqa: E402

APP = QApplication.instance() or QApplication([])


@pytest.fixture(autouse=True)
def _fresh_tarpit(monkeypatch):
    monkeypatch.delenv(safety_tarpit.ENV_DISABLE, raising=False)
    safety_tarpit.reset_all()
    yield
    safety_tarpit.reset_all()


def _prod_fs(production: bool = True) -> LocalFS:
    fs = LocalFS()
    fs._axross_profile = ConnectionProfile(
        name="prod-box", protocol="sftp", host="prod.example", production=production
    )
    fs._axross_profile_key = f"key-{id(fs)}"
    return fs


def _dialog_answers(monkeypatch, *answers: int) -> list[str]:
    """Replace the countdown dialog's exec by canned answers; returns the
    operations it was shown for."""
    shown: list[str] = []
    queue = list(answers)
    real_init = PG.ProductionCountdownDialog.__init__

    def init(self, label, op_desc, seconds, parent=None):
        real_init(self, label, op_desc, seconds, parent)
        shown.append(op_desc)

    monkeypatch.setattr(PG.ProductionCountdownDialog, "__init__", init)
    monkeypatch.setattr(PG.ProductionCountdownDialog, "exec", lambda self: queue.pop(0))
    return shown


# -- the gate ---------------------------------------------------------------------


def test_happy_the_first_operation_shows_the_countdown_once_per_session(monkeypatch):
    shown = _dialog_answers(monkeypatch, QDialog.DialogCode.Accepted)
    fs = _prod_fs()
    assert PG.confirm_production(None, fs, "delete /etc/x") is True
    assert PG.confirm_production(None, fs, "delete /etc/y") is True
    assert shown == ["delete /etc/x"]


def test_sad_cancel_stops_and_asks_again_next_time(monkeypatch):
    shown = _dialog_answers(
        monkeypatch, QDialog.DialogCode.Rejected, QDialog.DialogCode.Accepted
    )
    fs = _prod_fs()
    assert PG.confirm_production(None, fs, "delete a") is False
    assert PG.confirm_production(None, fs, "delete b") is True
    assert shown == ["delete a", "delete b"]


def test_edge_no_dialog_without_a_production_profile(monkeypatch):
    shown = _dialog_answers(monkeypatch)
    assert PG.confirm_production(None, LocalFS(), "delete a") is True
    assert PG.confirm_production(None, _prod_fs(production=False), "delete a") is True
    assert shown == []


def test_edge_the_disable_switch_is_honoured(monkeypatch):
    shown = _dialog_answers(monkeypatch)
    monkeypatch.setenv(safety_tarpit.ENV_DISABLE, "1")
    assert PG.confirm_production(None, _prod_fs(), "delete a") is True
    assert shown == []


def test_happy_the_countdown_running_out_proceeds():
    dlg = PG.ProductionCountdownDialog("prod-box", "delete a", 0.3)
    assert dlg.exec() == QDialog.DialogCode.Accepted


def test_sad_escape_during_the_countdown_stops():
    dlg = PG.ProductionCountdownDialog("prod-box", "delete a", 5.0)
    QTimer.singleShot(100, lambda: QTest.keyClick(dlg, Qt.Key.Key_Escape))
    assert dlg.exec() == QDialog.DialogCode.Rejected


# -- the pane entries --------------------------------------------------------------


@pytest.fixture
def pane_on_prod():
    from ui.file_pane import FilePaneWidget

    tmp = tempfile.TemporaryDirectory()
    root = Path(tmp.name)
    fs = _prod_fs()
    pane = FilePaneWidget(fs)
    pane._current_path = str(root)
    yield pane, root
    pane.deleteLater()
    tmp.cleanup()


def _select(pane, *names: str):
    return mock.patch.object(
        pane,
        "selected_file_items",
        return_value=[FileItem(name=n, is_dir=False, size=1) for n in names],
    )


def _yes():
    return mock.patch.object(
        QMessageBox, "question", return_value=QMessageBox.StandardButton.Yes
    )


def _settle(pane, timeout: float = 5.0) -> None:
    """Delete and Move to Trash run in the background (ScanJob): wait until
    the check, the questions and the removal are through."""
    import time

    end = time.time() + timeout
    while time.time() < end:
        APP.processEvents()
        if not pane.removal_running and not pane.is_loading:
            return
        time.sleep(0.005)
    raise AssertionError("the delete did not finish")


def test_sad_a_cancelled_countdown_keeps_the_file_on_delete(pane_on_prod, monkeypatch):
    pane, root = pane_on_prod
    (root / "keep.txt").write_text("x")
    shown = _dialog_answers(monkeypatch, QDialog.DialogCode.Rejected)
    with _select(pane, "keep.txt"), _yes():
        pane._delete_selected()
        _settle(pane)
    assert (root / "keep.txt").exists()
    assert len(shown) == 1


def test_happy_an_accepted_countdown_deletes(pane_on_prod, monkeypatch):
    pane, root = pane_on_prod
    (root / "gone.txt").write_text("x")
    _dialog_answers(monkeypatch, QDialog.DialogCode.Accepted)
    with _select(pane, "gone.txt"), _yes():
        pane._delete_selected()
        _settle(pane)
    assert not (root / "gone.txt").exists()


def test_sad_a_cancelled_countdown_keeps_the_file_on_trash(pane_on_prod, monkeypatch):
    pane, root = pane_on_prod
    (root / "keep.txt").write_text("x")
    shown = _dialog_answers(monkeypatch, QDialog.DialogCode.Rejected)
    with _select(pane, "keep.txt"), _yes():
        pane._trash_selected()
        _settle(pane)
    assert (root / "keep.txt").exists()
    assert len(shown) == 1


def test_sad_a_cancelled_countdown_keeps_the_name(pane_on_prod, monkeypatch):
    pane, root = pane_on_prod
    (root / "old.txt").write_text("x")
    _dialog_answers(monkeypatch, QDialog.DialogCode.Rejected)
    with (
        _select(pane, "old.txt"),
        mock.patch.object(QInputDialog, "getText", return_value=("new.txt", True)),
    ):
        pane._rename_selected()
    assert (root / "old.txt").exists()
    assert not (root / "new.txt").exists()


def test_sad_a_cancelled_countdown_sends_no_move(pane_on_prod, monkeypatch):
    pane, _root = pane_on_prod
    _dialog_answers(monkeypatch, QDialog.DialogCode.Rejected)
    moved: list = []
    pane.move_requested.connect(moved.append)
    with mock.patch.object(pane, "selected_items", return_value=[FileItem(name="a")]):
        pane._move_to_target()
    assert moved == []


def test_sad_a_cancelled_countdown_opens_no_permissions_editor(pane_on_prod, monkeypatch):
    pane, root = pane_on_prod
    (root / "f.txt").write_text("x")
    _dialog_answers(monkeypatch, QDialog.DialogCode.Rejected)
    with (
        _select(pane, "f.txt"),
        mock.patch("ui.permissions_dialog.PermissionsDialog") as dialog,
    ):
        pane._show_permissions()
    dialog.assert_not_called()


def test_edge_a_local_pane_asks_nothing(monkeypatch):
    from ui.file_pane import FilePaneWidget

    shown = _dialog_answers(monkeypatch)
    with tempfile.TemporaryDirectory() as tmp:
        pane = FilePaneWidget(LocalFS())
        pane._current_path = tmp
        (Path(tmp) / "f.txt").write_text("x")
        with _select(pane, "f.txt"), _yes():
            pane._delete_selected()
            _settle(pane)
        assert not (Path(tmp) / "f.txt").exists()
        pane.deleteLater()
    assert shown == []
