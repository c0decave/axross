"""The metadata UI: the metadata dialog (one row per file with its fields
as key: value, Properties on double-click or right-click, filter, copy,
export, remove, recursive folders, cancel), the settings dialog, the side panel in
the image and media viewers (toggled with I), the pane's context menu and,
end to end through the real MainWindow offscreen, folder -> Show Metadata
(recursive) -> Export -> Remove -> Ctrl+Z."""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication, QFileDialog, QMessageBox  # noqa: E402

from core import metadata_formats as MF  # noqa: E402
from core import metadata_tools as MT  # noqa: E402
from core import open_limits as OL  # noqa: E402
from core import security_mode  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from core.ram_fs import RamFsSession  # noqa: E402
from tests import metadata_testkit as K  # noqa: E402
from ui import metadata_dialog as MD  # noqa: E402

APP = QApplication.instance() or QApplication([])


def wait_until(cond, timeout: float = 20.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        APP.processEvents()
        if cond():
            return True
        time.sleep(0.005)
    APP.processEvents()
    return cond()


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(OL, "SETTINGS_PATH", tmp_path / "settings.json")
    monkeypatch.setenv("AXROSS_OPERATION_JOURNAL", str(tmp_path / "ops.jsonl"))
    previous = security_mode.current_policy().name
    security_mode.set_policy("normal")
    yield
    security_mode.set_policy(previous)
    for w in QApplication.topLevelWidgets():
        if isinstance(w, (MD.MetadataDialog, MD.MetadataDetailsDialog)):
            w.close()
    APP.processEvents()


@pytest.fixture
def tree(tmp_path) -> Path:
    root = tmp_path / "photos"
    K.write(root / "a.jpg", K.jpeg_bytes())
    K.write(root / "b.png", K.png_bytes())
    K.write(root / "notes.txt", b"plain")
    K.write(root / "trip" / "c.docx", K.docx_bytes())
    return root


def _dialog(backend, targets, **kw) -> MD.MetadataDialog:
    dlg = MD.MetadataDialog(backend, targets, **kw)
    dlg.show()
    dlg.start()
    assert wait_until(lambda: dlg.idle)
    return dlg


# ---------------------------------------------------------------------------
# Dialog
# ---------------------------------------------------------------------------


def test_happy_dialog_lists_a_folder_and_goes_recursive(tree):
    dlg = _dialog(LocalFS(), [(str(tree), True)])
    assert dlg.file_names() == ["a.jpg", "b.png"]
    assert dlg.row_count() == 2  # one row per file
    assert dlg.field_count() > 10
    assert dlg.recursive_box.isVisible()
    dlg.recursive_box.setChecked(True)
    assert wait_until(lambda: dlg.idle and "c.docx" in dlg.file_names())
    assert dlg.file_names() == ["a.jpg", "b.png", "c.docx"]


def test_edge_a_long_path_keeps_the_file_name_visible(tree):
    # Seen on a screenshot: the File column cut the path at the end, so
    # every row showed the same folder prefix and never the file name.
    from PyQt6.QtCore import Qt

    dlg = _dialog(LocalFS(), [(str(tree), True)])
    assert dlg.table.textElideMode() == Qt.TextElideMode.ElideMiddle
    cell = dlg.table.item(0, 0)
    assert cell.text() == str(tree / "a.jpg")  # Copy and Export keep the full path
    assert str(tree / "a.jpg") in cell.toolTip()


def test_happy_one_row_per_file_lists_its_fields_as_key_value(tree):
    dlg = _dialog(LocalFS(), [(str(tree / "a.jpg"), False)])
    assert dlg.row_count() == 1
    summary = dlg.table.item(0, 1).text()
    assert "Make: SECRETMAKE · Model: SECRETMODEL" in summary
    assert "\n" not in summary


def test_edge_the_metadata_column_is_cut_at_the_end(tree):
    # The path is cut in the middle (its name stays visible); the field
    # list is cut at the end, so its first fields stay readable.
    from PyQt6.QtWidgets import QStyleOptionViewItem

    dlg = _dialog(LocalFS(), [(str(tree / "a.jpg"), False)])
    option = QStyleOptionViewItem()
    dlg.table.itemDelegateForColumn(1).initStyleOption(option, dlg.table.model().index(0, 1))
    assert option.textElideMode == Qt.TextElideMode.ElideRight


def test_sad_the_file_tooltip_does_not_hide_the_kept_hint(tree):
    dlg = _dialog(LocalFS(), [(str(tree), True)])
    tip = dlg.table.item(0, 0).toolTip()
    assert str(tree / "a.jpg") in tip
    assert "kept" in tip.lower()


def test_edge_a_long_value_is_cut_in_the_row_and_whole_in_properties(tmp_path):
    long_value = "x" * 500
    report = MT.MetadataReport(
        path=str(tmp_path / "f.jpg"), name="f.jpg", kind="image",
        fields=[MF.Field("EXIF", "Long", long_value), MF.Field("EXIF", "Short", "ok")],
    )
    line = MD.summary_line(report)
    assert len(line) < 200 and "Short: ok" in line
    details = MD.MetadataDetailsDialog(report)
    assert long_value in details.view.toPlainText()
    details.close()


def test_happy_filter_copy_and_export(tree, tmp_path, monkeypatch):
    dlg = _dialog(LocalFS(), [(str(tree), True)])
    dlg.filter_edit.setText("ducky")  # a field only a.jpg has
    assert [Path(r[0]).name for r in dlg.visible_rows()] == ["a.jpg"]
    dlg.filter_edit.setText("GPS")
    assert len(dlg.visible_rows()) == 2
    dlg.table.selectAll()
    dlg.copy_selection()
    lines = QApplication.clipboard().text().splitlines()
    assert lines and all("GPS" in line for line in lines)  # the matching fields
    assert {line.split("\t")[0] for line in lines} == {str(tree / "a.jpg"), str(tree / "b.png")}
    dlg.filter_edit.clear()
    out = tmp_path / "export.json"
    monkeypatch.setattr(QFileDialog, "getSaveFileName",
                        lambda *a, **k: (str(out), "JSON (*.json)"))
    dlg.export_button.click()
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["files"][0]["name"] == "a.jpg"


def test_happy_remove_from_the_dialog_cleans_and_signals(tree):
    dlg = _dialog(LocalFS(), [(str(tree), True)])
    changed = []
    dlg.changed.connect(lambda: changed.append(True))
    dlg.remove_button.click()
    assert wait_until(lambda: dlg.idle and changed)
    assert K.MARK not in (tree / "a.jpg").read_bytes()
    assert K.MARK not in (tree / "b.png").read_bytes()
    assert K.MARK in K.plain(tree / "trip" / "c.docx")  # not recursive
    assert "2" in dlg.status_label.text()
    assert wait_until(lambda: dlg.idle and dlg.removable_count() == 0)


def _row_of(dlg, name: str) -> int:
    rows = range(dlg.table.rowCount())
    return next(r for r in rows if Path(dlg.table.item(r, 0).text()).name == name)


def test_happy_double_click_opens_the_properties_of_that_file(tree):
    dlg = _dialog(LocalFS(), [(str(tree), True)])
    row = _row_of(dlg, "b.png")
    rect = dlg.table.visualRect(dlg.table.model().index(row, 1))
    # A real double-click starts with a press; the view only reports a
    # double-click on the index that press hit.
    QTest.mouseClick(dlg.table.viewport(), Qt.MouseButton.LeftButton, pos=rect.center())
    QTest.mouseDClick(dlg.table.viewport(), Qt.MouseButton.LeftButton, pos=rect.center())
    assert wait_until(lambda: dlg.details_dialogs)
    details = dlg.details_dialogs[-1]
    assert details.isVisible() and details.path == str(tree / "b.png")
    text = details.view.toPlainText()
    for f in dlg.reports()[row].fields:
        assert f.group in text and f.name in text and f.value in text
    # one line per field, grouped: never the whole set on one line
    assert text.count("\n") >= len(dlg.reports()[row].fields)
    assert "Orientation" in details.kept_names()
    assert details.close_corner is not None


def test_happy_right_click_properties_and_remove_for_the_selection(tree):
    dlg = _dialog(LocalFS(), [(str(tree), True)])
    dlg.table.selectRow(_row_of(dlg, "a.jpg"))
    menu = dlg.build_context_menu()
    actions = {a.text(): a for a in menu.actions() if a.text()}
    assert {"Properties…", "Copy", "Remove Metadata"} <= set(actions)
    actions["Properties…"].trigger()
    assert dlg.details_dialogs[-1].path == str(tree / "a.jpg")
    changed = []
    dlg.changed.connect(lambda: changed.append(True))
    actions["Remove Metadata"].trigger()
    assert wait_until(lambda: dlg.idle and changed)
    assert K.MARK not in (tree / "a.jpg").read_bytes()
    assert K.MARK in (tree / "b.png").read_bytes()  # not selected, not touched
    # the open Properties follow the new state of their file
    assert wait_until(lambda: dlg.details_dialogs[-1].report.removable == 0)


def test_sad_without_a_selection_the_file_actions_are_disabled(tree):
    dlg = _dialog(LocalFS(), [(str(tree), True)])
    dlg.table.clearSelection()
    actions = {a.text(): a for a in dlg.build_context_menu().actions() if a.text()}
    assert not actions["Properties…"].isEnabled()
    assert not actions["Remove Metadata"].isEnabled()


def test_sad_properties_remove_is_off_when_nothing_is_removable(tmp_path):
    bare = K.write(tmp_path / "bare.jpg", K.jpeg_bytes(orientation=None, everything=False))
    dlg = _dialog(LocalFS(), [(str(bare), False)])
    dlg.open_details(0)
    details = dlg.details_dialogs[-1]
    assert not details.remove_button.isEnabled()
    assert "version: 1.01" in dlg.table.item(0, 1).text()


def test_edge_properties_show_markup_as_text(tmp_path):
    report = MT.MetadataReport(
        path=str(tmp_path / "f.jpg"), name="f.jpg", kind="image",
        fields=[MF.Field("XMP", "<b>name</b>", '<img src="https://x.invalid/a.png">&amp;')],
    )
    details = MD.MetadataDetailsDialog(report)
    text = details.view.toPlainText()
    assert "<b>name</b>" in text and '<img src="https://x.invalid/a.png">&amp;' in text
    details.close()


def test_edge_a_file_that_could_not_be_read_shows_its_error(tmp_path):
    report = MT.MetadataReport(
        path=str(tmp_path / "f.jpg"), name="f.jpg", kind="image", error="truncated EXIF"
    )
    assert MD.summary_line(report).startswith("Error: truncated EXIF")
    details = MD.MetadataDetailsDialog(report)
    assert "truncated EXIF" in details.view.toPlainText()
    assert details.remove_button.isEnabled()  # a readable kind may still be cleaned
    details.close()


def test_happy_remove_action_on_files_runs_without_asking(tree, monkeypatch):
    asked = []
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: asked.append(a))
    dlg = MD.MetadataDialog(LocalFS(), [(str(tree / "a.jpg"), False)], action="remove")
    dlg.show()
    dlg.start()
    assert wait_until(lambda: K.MARK not in (tree / "a.jpg").read_bytes())
    assert asked == []


def test_sad_confirmation_when_enabled_and_declined(tree, monkeypatch):
    MT.set_confirm_before_remove(True)
    monkeypatch.setattr(QMessageBox, "question",
                        lambda *a, **k: QMessageBox.StandardButton.No)
    dlg = _dialog(LocalFS(), [(str(tree / "a.jpg"), False)])
    dlg.remove_button.click()
    APP.processEvents()
    assert wait_until(lambda: dlg.idle)
    assert K.MARK in (tree / "a.jpg").read_bytes()


def test_sad_errors_are_rows_not_crashes(tmp_path):
    bad = K.write(tmp_path / "bad.jpg", b"\xff\xd8\xff\xe1\xff\xffbroken")
    dlg = _dialog(LocalFS(), [(str(bad), False)])
    assert any("error" in " ".join(r).lower() or "range" in " ".join(r) for r in dlg.visible_rows())


def test_edge_cancel_a_running_scan(tree, monkeypatch):
    real = MT.read_metadata

    def slow(*a, **k):
        time.sleep(0.3)
        return real(*a, **k)

    monkeypatch.setattr(MT, "read_metadata", slow)
    dlg = MD.MetadataDialog(LocalFS(), [(str(tree), True)])
    dlg.show()
    dlg.start()
    assert wait_until(lambda: dlg.job.running)
    dlg.busy.cancel_button.click()
    assert wait_until(lambda: dlg.idle)
    assert "cancel" in dlg.status_label.text().lower()


def test_edge_remote_backend(tmp_path):
    ram = RamFsSession()
    ram.mkdir("/pics")
    with ram.open_write("/pics/x.webp") as fh:
        fh.write(K.webp_bytes())
    dlg = _dialog(ram, [("/pics", True)])
    assert dlg.file_names() == ["x.webp"]
    dlg.remove_button.click()
    assert wait_until(lambda: dlg.idle and dlg.removable_count() == 0)


def test_happy_settings_dialog_saves(monkeypatch):
    dlg = MD.MetadataSettingsDialog()
    assert dlg.in_place_radio.isChecked() and not dlg.confirm_box.isChecked()
    dlg.copy_radio.setChecked(True)
    dlg.confirm_box.setChecked(True)
    dlg.accept()
    assert MT.write_mode() == MT.MODE_COPY and MT.confirm_before_remove() is True


# ---------------------------------------------------------------------------
# Viewer panel
# ---------------------------------------------------------------------------


def test_happy_panel_loads_and_removes(tree):
    panel = MD.MetadataPanel()
    panel.show()
    removed = []
    panel.removed.connect(removed.append)
    panel.set_target(LocalFS(), str(tree / "a.jpg"))
    assert wait_until(lambda: panel.idle and panel.row_count() > 5)
    panel.remove_button.click()
    assert wait_until(lambda: removed)
    assert K.MARK not in (tree / "a.jpg").read_bytes()
    assert wait_until(lambda: panel.idle and panel.removable_count() == 0)
    panel.close()


def test_edge_hidden_panel_does_not_read(tree, monkeypatch):
    calls = []
    monkeypatch.setattr(MT, "read_metadata", lambda *a, **k: calls.append(a))
    panel = MD.MetadataPanel()
    panel.set_target(LocalFS(), str(tree / "a.jpg"))
    APP.processEvents()
    assert calls == []


def test_happy_image_viewer_toggles_the_panel_with_i(tree):
    from ui.image_viewer import ImageViewerDialog

    paths = [str(tree / "a.jpg"), str(tree / "b.png")]
    dlg = ImageViewerDialog(LocalFS(), paths[0], paths)
    try:
        dlg.show()
        dlg.activateWindow()  # the viewer's keys are window shortcuts
        assert QTest.qWaitForWindowActive(dlg)
        assert not dlg.metadata_panel.isVisible()
        QTest.keyClick(dlg, Qt.Key.Key_I)
        assert dlg.metadata_panel.isVisible()
        assert wait_until(lambda: dlg.metadata_panel.idle and dlg.metadata_panel.row_count() > 0)
        assert dlg.metadata_panel.path == paths[0]
        QTest.keyClick(dlg, Qt.Key.Key_Right)
        assert wait_until(lambda: dlg.metadata_panel.path == paths[1])
        assert wait_until(lambda: dlg.metadata_panel.idle and dlg.metadata_panel.row_count() > 0)
        dlg.metadata_panel.remove_button.click()
        assert wait_until(lambda: K.MARK not in (tree / "b.png").read_bytes())
        QTest.keyClick(dlg, Qt.Key.Key_I)
        assert not dlg.metadata_panel.isVisible()
    finally:
        dlg.close()


def test_happy_media_viewer_panel_follows_the_item(tree):
    from core.media_collect import IMAGE, MediaItem
    from ui.media_viewer import MediaViewer

    viewer = MediaViewer(LocalFS())
    viewer.resize(800, 600)
    viewer.show()
    viewer.activateWindow()
    assert QTest.qWaitForWindowActive(viewer)
    items = [MediaItem(str(tree / n), n, "", IMAGE, 1, 0.0) for n in ("a.jpg", "b.png")]
    viewer.set_items(items, 0)
    QTest.keyClick(viewer, Qt.Key.Key_I)
    assert viewer.metadata_panel.isVisible()
    assert wait_until(lambda: viewer.metadata_panel.idle and viewer.metadata_panel.row_count())
    viewer.next_item()
    assert wait_until(lambda: viewer.metadata_panel.path == str(tree / "b.png"))
    assert wait_until(lambda: viewer.metadata_panel.idle and viewer.metadata_panel.row_count())
    viewer.metadata_panel.remove_button.click()
    assert wait_until(lambda: K.MARK not in (tree / "b.png").read_bytes())
    viewer.shutdown()
    viewer.close()


# ---------------------------------------------------------------------------
# Pane + main window
# ---------------------------------------------------------------------------


@pytest.fixture
def window(tmp_path):
    from ui.main_window import MainWindow

    win = MainWindow()
    win.resize(1000, 700)
    win.show()
    APP.processEvents()
    yield win
    win.close()
    APP.processEvents()


def _pane_at(window, path: Path):
    pane = window._active_pane
    pane.navigate(str(path))
    assert wait_until(lambda: pane.current_path == str(path))
    return pane


def _menu_texts(pane) -> list[str]:
    return [a.text() for a in pane._build_context_menu().actions()]


def test_happy_context_menu_entries(window, tree):
    pane = _pane_at(window, tree)
    texts = _menu_texts(pane)
    for label in ("Show Metadata…", "Remove Metadata…", "Export Metadata…"):
        assert label in texts


def test_happy_tools_menu_has_metadata_settings(window):
    texts = [a.text() for m in window.menuBar().actions() if m.menu() for a in m.menu().actions()]
    assert any("Metadata Settings" in t for t in texts)


def test_e2e_folder_show_recursive_export_remove_undo(window, tree, tmp_path, monkeypatch):
    originals = {p: p.read_bytes() for p in tree.rglob("*") if p.is_file()}
    pane = _pane_at(window, tree)
    action = next(a for a in pane._build_context_menu().actions() if a.text() == "Show Metadata…")
    action.trigger()
    assert wait_until(lambda: pane.metadata_dialogs and pane.metadata_dialogs[-1].idle)
    dlg = pane.metadata_dialogs[-1]
    dlg.recursive_box.setChecked(True)
    assert wait_until(lambda: dlg.idle and "c.docx" in dlg.file_names())

    out = tmp_path / "export.csv"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *a, **k: (str(out), "CSV (*.csv)"))
    dlg.export_button.click()
    text = out.read_text(encoding="utf-8")
    assert text.startswith("path,kind,group,field,value") and "SECRETCREATOR" in text

    dlg.remove_button.click()
    assert wait_until(lambda: dlg.idle and dlg.removable_count() == 0)
    for p in originals:
        if p.suffix in (".jpg", ".png", ".docx"):
            assert K.MARK not in K.plain(p), p

    monkeypatch.setattr(QMessageBox, "question",
                        lambda *a, **k: QMessageBox.StandardButton.Yes)
    infos = []
    monkeypatch.setattr(QMessageBox, "information", lambda *a, **k: infos.append(a))
    monkeypatch.setattr(QMessageBox, "warning", lambda *a, **k: infos.append(a))
    undo = next(
        a
        for m in window.menuBar().actions()
        if m.menu()
        for a in m.menu().actions()
        if a.shortcut().toString() == "Ctrl+Z"
    )
    undo.trigger()  # Edit -> Undo Last Operation (Ctrl+Z)
    assert infos == []
    for p, data in originals.items():
        assert p.read_bytes() == data, p
