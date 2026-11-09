"""The right-click menu is one short column, Open first.

UX review round 5 (major): about 47 top-level entries in two columns
(850x794 px); on a folder the first entry was "View Selected Media…" and
there was no Open. Now Open comes first (a folder opens in the pane, a file
in its viewer), then the core file operations, then submenus (Open With,
Pack, Metadata, Analyse, Links, Tags, More) - about twenty entries, one
column, every former entry still reachable.

Also from the review's minor list: the pane header no longer says
"Local [LOCAL]", the View menu has one Bookmarks entry besides the sidebar
toggle under Panels, Help > Features… has an underlined letter, and F2
selects the name without its extension.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QEvent, QItemSelectionModel  # noqa: E402
from PyQt6.QtWidgets import QApplication, QMenu  # noqa: E402

APP = QApplication.instance() or QApplication([])

#: Every command the menu offered before the restructuring (round 5).
FORMER = {
    "open-text", "open-hex", "view-selected-media", "copy-path", "cut", "rename",
    "copy-to-target", "move-to-target", "pack", "encrypt", "trash", "delete",
    "new-folder", "new-file", "xlink", "identify", "checksum", "versions",
    "permissions", "properties", "identify-folder", "metadata", "metadata-remove",
    "metadata-export", "duplicates", "refresh", "view-mode", "media-view", "bookmark",
    "trash-browser", "terminal",
}


def pump(seconds: float = 0.2) -> None:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        APP.processEvents()
        time.sleep(0.01)


@pytest.fixture
def window(tmp_path):
    from ui.main_window import MainWindow

    folder = tmp_path / "data"
    (folder / "Documents").mkdir(parents=True)
    (folder / "report.pdf").write_bytes(b"%PDF-1.4\n")
    win = MainWindow()
    win._reconnect_timer.stop()
    win.show()
    win._active_pane.navigate(str(folder))
    pump()
    yield win
    win.close()
    win.deleteLater()
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)


@pytest.fixture
def german(monkeypatch):
    from core import i18n

    monkeypatch.setattr(i18n, "_ACTIVE", i18n.Translator("de"))


def _menu(pane, name) -> QMenu:
    proxy = pane._table.model()
    sel = pane._table.selectionModel()
    sel.clearSelection()
    for row in range(proxy.rowCount()):
        if proxy.index(row, 0).data() == name:
            sel.select(proxy.index(row, 0), QItemSelectionModel.SelectionFlag.Select
                       | QItemSelectionModel.SelectionFlag.Rows)
    return pane._build_context_menu()


def _commands(menu: QMenu) -> set[str]:
    found = set()
    for action in menu.actions():
        if action.property("axCommand"):
            found.add(str(action.property("axCommand")))
        if action.menu() is not None:
            found |= _commands(action.menu())
    return found


def _entries(menu: QMenu) -> list:
    return [a for a in menu.actions() if not a.isSeparator()]


# --- happy -----------------------------------------------------------------


@pytest.mark.parametrize("name", ["Documents", "report.pdf"])
def test_happy_open_is_first_and_the_column_is_short(window, name):
    pane = window._active_pane
    menu = _menu(pane, name)
    first = _entries(menu)[0]
    assert first.property("axCommand") == "open" and first.font().bold()
    assert len(_entries(menu)) <= 24, [a.text() for a in _entries(menu)]
    # One column: the menu is no wider than one entry list needs.
    assert menu.sizeHint().width() < 520, menu.sizeHint()


def test_happy_open_on_a_folder_opens_it_in_the_pane(window):
    pane = window._active_pane
    menu = _menu(pane, "Documents")
    _entries(menu)[0].trigger()
    pump(0.5)
    assert pane.current_path.endswith("Documents")


def test_happy_every_former_entry_is_still_reachable(window):
    pane = window._active_pane
    commands = _commands(_menu(pane, "report.pdf")) | _commands(_menu(pane, "Documents"))
    assert FORMER <= commands, sorted(FORMER - commands)


# --- sad -------------------------------------------------------------------


def test_sad_german_folder_menu_starts_with_oeffnen_not_media(window, german):
    pane = window._active_pane
    menu = _menu(pane, "Documents")
    texts = [a.text().replace("&", "") for a in _entries(menu)]
    assert texts[0] == "Öffnen", texts
    assert "Ausgewählte Medien ansehen…" not in texts
    assert "Ins Ziel-Pane kopieren" in texts and "Ins Ziel-Pane verschieben" in texts


def test_sad_the_header_does_not_say_local_twice(german, window):
    label = window._active_pane._header_label.text()
    assert "Lokal" in label and "LOKAL" not in label


# --- edge ------------------------------------------------------------------


def test_edge_view_menu_has_one_bookmarks_entry_and_help_features_a_letter(window):
    bar = window.menuBar()
    view = next(a.menu() for a in bar.actions() if a.text() == "&View")
    labels = [a.text().replace("&", "") for a in view.actions() if not a.isSeparator()]
    assert labels.count("Bookmarks") == 1, labels
    help_menu = next(a.menu() for a in bar.actions() if a.text() == "&Help")
    assert "&Features…" in [a.text() for a in help_menu.actions()]


def test_edge_actions_menu_entries_have_letters_without_a_selection(window):
    pane = window._active_pane
    pane._table.clearSelection()
    actions = window.actions_menu
    actions.aboutToShow.emit()
    texts = [a.text() for a in actions.actions() if not a.isSeparator()]
    assert texts[:3] == ["Copy to Tar&get Pane", "Mo&ve to Target Pane", "Pac&k…"], texts
    assert "Copy to Target" not in [t.replace("&", "") for t in texts]


@pytest.mark.parametrize(
    ("name", "length"),
    [("report.pdf", 6), ("backup.tar.gz", 6), (".bashrc", 7), ("README", 6), ("a.b.c", 3)],
)
def test_edge_rename_selects_the_name_without_its_extension(name, length):
    from ui.file_pane import rename_stem_length

    assert rename_stem_length(name) == length
