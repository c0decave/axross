"""Right-click > Pack: one click for the common formats, or a dialog with
format, level and (7z) password; the work runs in the background."""

from __future__ import annotations

import os
import sys
import time
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication, QMenu  # noqa: E402

from core import packer as PK  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

APP = QApplication.instance() or QApplication([])


def wait_until(cond, timeout: float = 8.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        APP.processEvents()
        if cond():
            return True
        time.sleep(0.02)
    return cond()


@pytest.fixture
def folder(tmp_path) -> Path:
    root = tmp_path / "work"
    (root / "docs").mkdir(parents=True)
    (root / "docs" / "a.txt").write_text("alpha")
    (root / "one.log").write_text("log")
    return root


@pytest.fixture
def pane(folder):
    from ui.file_pane import FilePaneWidget

    p = FilePaneWidget(LocalFS())
    p.resize(700, 400)
    p.show()
    p.navigate(str(folder))
    yield p
    p.close()
    p.deleteLater()
    APP.processEvents()


def _select(pane, *names) -> None:
    from PyQt6.QtCore import QItemSelectionModel

    proxy = pane._table.model()
    sel = pane._table.selectionModel()
    sel.clearSelection()
    for row in range(proxy.rowCount()):
        if proxy.index(row, 0).data() in names:
            sel.select(
                proxy.index(row, 0),
                QItemSelectionModel.SelectionFlag.Select | QItemSelectionModel.SelectionFlag.Rows,
            )


def _pack_menu(pane) -> QMenu | None:
    for action in pane._build_context_menu().actions():
        if action.menu() is not None and action.text().replace("&", "") == "Pack":
            return action.menu()
    return None


# --- happy -----------------------------------------------------------------


def test_happy_the_pack_menu_offers_the_common_formats(pane) -> None:
    _select(pane, "docs", "one.log")
    menu = _pack_menu(pane)
    assert menu is not None
    labels = [a.text() for a in menu.actions() if not a.isSeparator()]
    assert labels[0] == "Pack as ZIP"
    assert "Pack as .tar.gz" in labels and "Pack as 7z" in labels
    assert labels[-1] == "Pack with Options…"
    assert not any(label.startswith("Compress") for label in labels)  # two items selected


def test_happy_one_click_zip_lands_in_the_folder(pane, folder) -> None:
    _select(pane, "docs", "one.log")
    pane.pack_selection("zip")
    assert wait_until(lambda: (folder / "work.zip").exists() and not pane.pack_running)
    with zipfile.ZipFile(folder / "work.zip") as zf:
        assert {"docs/a.txt", "one.log"} <= set(zf.namelist())
    proxy = pane._table.model()
    assert wait_until(
        lambda: "work.zip" in {proxy.index(r, 0).data() for r in range(proxy.rowCount())}
    )


def test_happy_a_single_file_can_be_compressed_on_its_own(pane, folder) -> None:
    _select(pane, "one.log")
    labels = [a.text() for a in _pack_menu(pane).actions()]
    assert "Compress as .gz" in labels
    pane.pack_selection("gz")
    assert wait_until(lambda: (folder / "one.log.gz").exists() and not pane.pack_running)


def test_happy_the_dialog_returns_name_format_level_and_password(pane, monkeypatch) -> None:
    from ui.pack_dialog import PackDialog

    dlg = PackDialog(["docs", "one.log"], "work", single_file=False, parent=pane)
    dlg.set_format("7z")
    assert dlg.password_edit.isEnabled()
    dlg.name_edit.setText("secret stuff")
    dlg.level_combo.setCurrentText("best")
    dlg.password_edit.setText("pw1")
    dlg.repeat_edit.setText("pw1")
    assert dlg.ok_button().isEnabled()
    name, opts = dlg.result_values()
    assert name == "secret stuff"
    assert (opts.fmt, opts.level, opts.password, opts.encrypt_names) == ("7z", "best", "pw1", True)
    assert dlg.target_label.text().endswith("secret stuff.7z")


# --- sad -------------------------------------------------------------------


def test_sad_mismatched_passwords_block_ok(pane) -> None:
    from ui.pack_dialog import PackDialog

    dlg = PackDialog(["docs"], "docs", single_file=False, parent=pane)
    dlg.set_format("7z")
    dlg.password_edit.setText("one")
    dlg.repeat_edit.setText("two")
    assert not dlg.ok_button().isEnabled()
    dlg.set_format("zip")  # no password for zip: the fields lock and clear
    assert not dlg.password_edit.isEnabled() and dlg.password_edit.text() == ""
    assert dlg.ok_button().isEnabled()


def test_sad_single_file_formats_are_off_for_folders_and_unavailable_ones_say_why(
    pane, monkeypatch
) -> None:
    from ui.pack_dialog import PackDialog

    monkeypatch.setattr(PK, "_zstd_module", lambda: None)
    dlg = PackDialog(["docs"], "docs", single_file=False, parent=pane)
    assert not dlg.format_enabled("gz")
    assert not dlg.format_enabled("tar.zst")
    assert "backports.zstd" in dlg.format_tooltip("tar.zst")
    assert dlg.format_enabled("zip")


def test_sad_a_failure_is_reported_and_leaves_nothing(pane, folder, monkeypatch) -> None:
    shown = []
    monkeypatch.setattr(
        "ui.file_pane.QMessageBox.warning", lambda *a, **k: shown.append(a[2]) or 0
    )
    _select(pane, "docs")
    monkeypatch.setattr(PK, "_collect", lambda *a: (_ for _ in ()).throw(PK.PackError("boom")))
    pane.pack_selection("zip")
    assert wait_until(lambda: shown and not pane.pack_running)
    assert "boom" in shown[0]
    assert sorted(p.name for p in folder.iterdir()) == ["docs", "one.log"]


# --- edge ------------------------------------------------------------------


def test_edge_nothing_selected_offers_no_pack_menu(pane) -> None:
    pane._table.clearSelection()
    assert _pack_menu(pane) is None


def test_edge_closing_the_pane_while_packing_is_safe(folder) -> None:
    from ui.file_pane import FilePaneWidget

    big = folder / "big.bin"
    big.write_bytes(os.urandom(8 * 1024 * 1024))
    p = FilePaneWidget(LocalFS())
    p.show()
    p.navigate(str(folder))
    _select(p, "big.bin")
    p.pack_selection("tar.xz")
    p.close()
    p.deleteLater()
    end = time.time() + 20
    while time.time() < end and any(x.name.startswith(".axross-pack-") for x in folder.iterdir()):
        APP.processEvents()
        time.sleep(0.05)
    assert not any(x.name.startswith(".axross-pack-") for x in folder.iterdir())
