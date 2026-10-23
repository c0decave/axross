"""The archive preview dock: nested archives, single members, properties.

End to end through the real MainWindow and ArchivePaneWidget, offscreen,
with archives built in the test (punch list 17/18; see
tests/test_archive_nested.py for the core part).
"""

from __future__ import annotations

import io
import os
import sys
import tarfile
import time
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QEvent, Qt  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication, QMessageBox  # noqa: E402

from core import archive as ARCH  # noqa: E402
from ui.archive_pane import ArchivePaneWidget  # noqa: E402

APP = QApplication.instance() or QApplication([])


def pump(seconds: float = 0.05) -> None:
    end = time.time() + seconds
    while time.time() < end:
        APP.processEvents()
        time.sleep(0.01)


def _zip_bytes(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in members.items():
            info = zipfile.ZipInfo(name, date_time=(2024, 5, 6, 7, 8, 10))
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            zf.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED)
    return buf.getvalue()


def _tar_bytes(members: dict[str, bytes], compression: str = "") -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode=f"w:{compression}" if compression else "w") as tf:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o640
            info.mtime = 1_700_000_000
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


@pytest.fixture
def outer(tmp_path):
    deep = _tar_bytes({"leaf.txt": b"leaf payload"}, "gz")
    inner = _zip_bytes({"note.txt": b"inside the zip", "deep.tar.gz": deep})
    path = tmp_path / "data" / "outer.tar"
    path.parent.mkdir()
    path.write_bytes(_tar_bytes({"docs/inner.zip": inner, "readme.txt": b"top level"}))
    return path


@pytest.fixture
def window(monkeypatch):
    from ui.main_window import MainWindow

    # Success messages of an extraction are modal; record them instead.
    shown: list[tuple] = []
    monkeypatch.setattr(
        QMessageBox, "information",
        lambda *a, **k: shown.append(("info", a)) or QMessageBox.StandardButton.Ok,
    )
    monkeypatch.setattr(
        QMessageBox, "warning",
        lambda *a, **k: shown.append(("warning", a)) or QMessageBox.StandardButton.Ok,
    )
    win = MainWindow()
    win._reconnect_timer.stop()
    win.resize(1200, 800)
    win.show()
    win.shown_messages = shown
    pump()
    yield win
    win._cleanup_archive_tempdirs()
    win.close()
    win.deleteLater()
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    pump()


def _pane(win) -> ArchivePaneWidget:
    pane = win._archive_dock.widget()
    assert isinstance(pane, ArchivePaneWidget)
    return pane


def _index_of(pane: ArchivePaneWidget, member: str):
    model = pane._tree.model()
    stack = [model.invisibleRootItem()]
    while stack:
        parent = stack.pop()
        for row in range(parent.rowCount()):
            item = parent.child(row, 0)
            if item.data(Qt.ItemDataRole.UserRole) == member:
                return item.index()
            stack.append(item)
    raise AssertionError(member)


def _double_click(pane: ArchivePaneWidget, member: str) -> None:
    index = _index_of(pane, member)
    pane._tree.expandAll()
    pane._tree.scrollTo(index)
    pump()
    rect = pane._tree.visualRect(index)
    # A real double-click is press, release, double-click: the view emits
    # doubleClicked only for the row the press went to.
    QTest.mouseClick(pane._tree.viewport(), Qt.MouseButton.LeftButton, pos=rect.center())
    QTest.mouseDClick(pane._tree.viewport(), Qt.MouseButton.LeftButton, pos=rect.center())
    pump()


def _select(pane: ArchivePaneWidget, *members: str) -> None:
    from PyQt6.QtCore import QItemSelectionModel

    sel = pane._tree.selectionModel()
    sel.clearSelection()
    for member in members:
        sel.select(
            _index_of(pane, member),
            QItemSelectionModel.SelectionFlag.Select | QItemSelectionModel.SelectionFlag.Rows,
        )
    pump()


def _menu_action(pane: ArchivePaneWidget, command: str):
    menu = pane.build_context_menu()
    return next(a for a in menu.actions() if a.property("axCommand") == command)


def _wait(cond, timeout: float = 20.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        APP.processEvents()
        if cond():
            return True
        time.sleep(0.02)
    return cond()


# --- happy -----------------------------------------------------------------


def test_happy_e2e_double_click_opens_a_zip_in_a_tar_and_back_returns(window, outer):
    window.open_archive_pane(str(outer))
    _double_click(_pane(window), "docs/inner.zip")
    pane = _pane(window)
    assert pane.chain == ("outer.tar",)
    assert window._archive_dock.windowTitle() == "Archive: outer.tar › inner.zip"
    assert {e.name for e in pane._entries} == {"note.txt", "deep.tar.gz"}
    assert pane._btn_back.isVisible()
    _double_click(pane, "deep.tar.gz")  # a tar.gz in the zip in the tar
    pane = _pane(window)
    assert pane.chain == ("outer.tar", "inner.zip")
    assert [e.name for e in pane._entries] == ["leaf.txt"]
    QTest.mouseClick(pane._btn_back, Qt.MouseButton.LeftButton)
    pump()
    assert _pane(window).chain == ("outer.tar",)
    QTest.mouseClick(_pane(window)._btn_back, Qt.MouseButton.LeftButton)
    pump()
    top = _pane(window)
    assert top.chain == () and not top._btn_back.isVisible()
    assert window._archive_dock.windowTitle() == "Archive: outer.tar"


def test_happy_e2e_a_member_of_a_nested_archive_extracts_next_to_the_outer_one(window, outer):
    window.open_archive_pane(str(outer))
    _double_click(_pane(window), "docs/inner.zip")
    pane = _pane(window)
    _select(pane, "note.txt")
    _menu_action(pane, "extract-selected").trigger()
    target = outer.parent / "inner"
    assert _wait(lambda: (target / "note.txt").exists())
    assert (target / "note.txt").read_bytes() == b"inside the zip"
    assert not (target / "deep.tar.gz").exists()


def test_happy_e2e_extract_selected_to_a_chosen_folder(window, outer, tmp_path, monkeypatch):
    chosen = tmp_path / "chosen"
    chosen.mkdir()
    monkeypatch.setattr(
        "PyQt6.QtWidgets.QFileDialog.getExistingDirectory", lambda *a, **k: str(chosen)
    )
    window.open_archive_pane(str(outer))
    pane = _pane(window)
    _select(pane, "readme.txt")
    _menu_action(pane, "extract-selected-to").trigger()
    assert _wait(lambda: (chosen / "outer" / "readme.txt").exists())
    assert not (chosen / "outer" / "docs").exists()


def test_happy_e2e_properties_of_a_member(window, outer):
    window.open_archive_pane(str(outer))
    pane = _pane(window)
    _select(pane, "readme.txt")
    _menu_action(pane, "properties").trigger()
    dialog = pane._properties_dialog
    assert dialog is not None and dialog.isVisible()
    values = dialog.values()
    assert values["Name"] == "readme.txt"
    assert values["Type"] == "File"
    assert values["Size"] == "9 bytes"
    assert values["Mode"] == "-rw-r----- (0640)"
    assert values["Archive"] == "outer.tar"
    dialog.close()


def test_happy_e2e_properties_of_a_nested_archive_member_name_the_chain(window, outer):
    window.open_archive_pane(str(outer))
    _double_click(_pane(window), "docs/inner.zip")
    pane = _pane(window)
    _select(pane, "deep.tar.gz")
    _menu_action(pane, "properties").trigger()
    values = pane._properties_dialog.values()
    assert values["Type"] == "Archive (TAR.GZ)"
    assert values["Archive"] == "outer.tar › inner.zip"


# --- sad -------------------------------------------------------------------


def test_sad_a_nested_archive_past_the_depth_limit_stays_closed(window, outer, monkeypatch):
    monkeypatch.setattr(ARCH, "MAX_NESTED_DEPTH", 1)
    window.open_archive_pane(str(outer))
    _double_click(_pane(window), "docs/inner.zip")
    pane = _pane(window)
    assert pane.chain == ("outer.tar",)
    _double_click(pane, "deep.tar.gz")
    assert _pane(window) is pane  # still the zip
    kind, args = window.shown_messages[-1]
    assert kind == "warning" and "nested" in args[2]


def test_sad_a_broken_nested_archive_shows_its_error_in_the_view(window, tmp_path):
    outer = tmp_path / "outer.zip"
    with zipfile.ZipFile(outer, "w") as zf:
        zf.writestr("broken.zip", b"PK\x03\x04 this is not a zip")
    window.open_archive_pane(str(outer))
    _double_click(_pane(window), "broken.zip")
    pane = _pane(window)
    assert pane.chain == ("outer.zip",)
    assert pane.load_error is not None and "could not be read" in pane.load_error


def test_sad_properties_without_a_selection_offers_no_entry(window, outer):
    window.open_archive_pane(str(outer))
    pane = _pane(window)
    pane._tree.clearSelection()
    commands = [a.property("axCommand") for a in pane.build_context_menu().actions()]
    assert "properties" not in commands and "extract-selected" not in commands
    assert "extract-all" in commands


# --- edge ------------------------------------------------------------------


def test_edge_temp_folders_of_nested_archives_go_away(window, outer):
    window.open_archive_pane(str(outer))
    _double_click(_pane(window), "docs/inner.zip")
    _double_click(_pane(window), "deep.tar.gz")
    temps = [e["tempdir"] for e in window._archive_views if e["tempdir"]]
    assert len(temps) == 2 and all(os.path.isdir(t) for t in temps)
    QTest.mouseClick(_pane(window)._btn_back, Qt.MouseButton.LeftButton)
    pump()
    assert not os.path.exists(temps[1]) and os.path.isdir(temps[0])
    window.open_archive_pane(str(outer))  # a new top-level archive
    assert not os.path.exists(temps[0])
    assert [e["tempdir"] for e in window._archive_views] == [None]


def test_edge_a_folder_row_has_properties_with_its_contents(window, outer):
    window.open_archive_pane(str(outer))
    pane = _pane(window)
    _select(pane, "docs/")
    _menu_action(pane, "properties").trigger()
    values = pane._properties_dialog.values()
    assert values["Type"] == "Folder"
    assert values["Contents"].startswith("1 file")


def test_edge_the_menu_names_an_archive_member_open_archive(window, outer):
    window.open_archive_pane(str(outer))
    pane = _pane(window)
    _select(pane, "docs/inner.zip")
    action = _menu_action(pane, "open")
    assert action.text().replace("&", "") == "Open Archive"
    action.trigger()
    pump()
    assert _pane(window).chain == ("outer.tar",)


# --- round-2 verification ----------------------------------------------------


def _mnemonic(text: str) -> str | None:
    stripped = text.replace("&&", "")
    i = stripped.find("&")
    return stripped[i + 1].lower() if 0 <= i < len(stripped) - 1 else None


@pytest.mark.parametrize(
    "selection", [(), ("readme.txt",), ("docs/inner.zip",), ("docs/",), ("readme.txt", "docs/")]
)
def test_edge_member_menu_mnemonics_are_unique(window, outer, selection):
    """Qt cycles between entries that share a letter instead of running
    one: every underlined letter of the member menu is used once."""
    window.open_archive_pane(str(outer))
    pane = _pane(window)
    _select(pane, *selection)
    texts = [a.text() for a in pane.build_context_menu().actions() if not a.isSeparator()]
    used = [m for m in map(_mnemonic, texts) if m]
    assert len(used) == len(set(used)), (selection, texts)


def test_sad_a_view_change_during_the_nested_extraction_keeps_the_new_view(
    window, outer, tmp_path
):
    """The window stays live while a nested archive is extracted. When
    another archive is opened meanwhile, the finished extraction must not
    be stacked onto it (with the old chain) - its temp folder goes."""
    other = tmp_path / "other.zip"
    other.write_bytes(_zip_bytes({"x.txt": b"x"}))
    window.open_archive_pane(str(outer))
    real = window._extract_off_the_gui_thread
    workdirs: list[str] = []

    def meanwhile(text, work):
        def spy(progress):
            path = work(progress)
            workdirs.append(os.path.dirname(os.path.dirname(path)))
            return path

        window.open_archive_pane(str(other))  # the user opens another archive
        return real(text, spy)

    window._extract_off_the_gui_thread = meanwhile
    _double_click(_pane(window), "docs/inner.zip")
    assert [v["path"] for v in window._archive_views] == [str(other)]
    assert _pane(window).chain == () and _pane(window)._archive_path == str(other)
    assert workdirs and not os.path.exists(workdirs[0])


def test_edge_folder_properties_count_members_stored_with_backslashes(window, tmp_path):
    """Some Windows zip tools store ``dir\\file``; the tree shows them in
    ``dir/`` and the folder's Properties count them there too."""
    path = tmp_path / "win.zip"
    path.write_bytes(_zip_bytes({"dir\\a.txt": b"aaaa", "dir\\sub\\b.txt": b"bb"}))
    window.open_archive_pane(str(path))
    pane = _pane(window)
    rows = dict(pane.properties_rows("dir/"))
    assert rows["Contents"].startswith("2 file(s), 1 folder(s)"), rows
