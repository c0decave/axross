"""Round 3: the dialogs the pane's context menu opens fit a 1024x600
screen in English and German, and none of their texts is cut.

tests/test_dialogs_fit_small_screen.py walks the menu bar's windows; this
one opens those of a pane: Properties, Permissions, Show Checksum, Batch
Rename, Pack with Options, Extract, New Symlink, Compare Panes and the
File Already Exists question - each from the menu entry or the method the
entry calls, with real entries selected (long names among them).

Found with it: a name or path without blanks made Properties and
Permissions 1050-1080 px wide (past the screen), and where a window held
it to its width (Properties' path, File Already Exists, Show Checksum) a
QLabel - which wraps at blanks only - cut it off at the edge. Such values
are a ui.elided_label.WrapAnywhereLabel now. Permissions showed the name,
owner and group and Show Checksum the path as markup and with a bidi
override as it is.

A window fits when its size, minimum size and minimum size hint stay
within the screen less its frame. A text is cut when a label or button
is narrower than it needs (a word-wrapped label: lower than its text).
"""

from __future__ import annotations

import os
import sys
import time
import zipfile
from pathlib import Path
from unittest import mock

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6 import sip  # noqa: E402
from PyQt6.QtCore import QItemSelectionModel, QRect, QSize, Qt, QTimer  # noqa: E402
from PyQt6.QtWidgets import (  # noqa: E402
    QAbstractButton,
    QAbstractScrollArea,
    QApplication,
    QDialog,
    QLabel,
    QMenu,
    QMessageBox,
)

APP = QApplication.instance() or QApplication([])

SMALL_SCREEN = QRect(0, 0, 1024, 600)
SMALL_LIMIT = QSize(984, 560)
LONG = "quarterly-report-" + "x" * 120 + ".txt"


def pump(seconds: float = 0.0) -> None:
    end = time.monotonic() + seconds
    while True:
        for _ in range(5):
            APP.processEvents()
        if time.monotonic() >= end:
            return
        time.sleep(0.01)


def _wait(done, timeout: float = 10.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        pump()
        if done():
            return True
        time.sleep(0.01)
    return done()


@pytest.fixture(params=["en", "de"])
def language(request, monkeypatch):
    from core import i18n

    if request.param == "de":
        monkeypatch.setattr(i18n, "_ACTIVE", i18n.Translator("de"))
    return request.param


@pytest.fixture
def window(tmp_path, monkeypatch, language):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    from core import i18n
    from ui import main_window as MW
    from ui import screen_fit

    monkeypatch.setattr(i18n, "SETTINGS_FILE", home / "settings.json")
    monkeypatch.setattr(MW.MainWindow, "_SESSION_FILE", home / "session.json")
    monkeypatch.setattr(MW.MainWindow, "_RECENTS_FILE", home / "recents.json")
    monkeypatch.setattr(screen_fit, "available_geometry",
                        lambda widget=None: QRect(SMALL_SCREEN))
    folder = tmp_path / "data"
    folder.mkdir()
    (folder / "notes.txt").write_text("hello\n")
    (folder / LONG).write_text("long\n")
    (folder / "sub").mkdir()
    with zipfile.ZipFile(folder / "bundle.zip", "w") as zf:
        zf.writestr("inside.txt", "x")
    other = tmp_path / "other"
    other.mkdir()
    (other / "notes.txt").write_text("older\n")
    with mock.patch("pathlib.Path.home", return_value=home):
        win = MW.MainWindow()
    win._reconnect_timer.stop()
    win._quit_with_transfers = True
    win.resize(SMALL_SCREEN.width(), SMALL_SCREEN.height() - 40)
    win.show()
    pump(0.2)
    pane = win._panes[0]
    pane.navigate(str(folder))
    assert _wait(lambda: pane._table.model().rowCount() >= 4)
    win.test_folder, win.test_other = folder, other
    try:
        yield win
    finally:
        for widget in APP.topLevelWidgets():
            if widget is not win and widget.isVisible() and not sip.isdeleted(widget):
                widget.close()
        win.close()
        win.deleteLater()
        pump()


def _select(pane, *names) -> None:
    table = pane._table
    table.clearSelection()
    flags = QItemSelectionModel.SelectionFlag.Select | QItemSelectionModel.SelectionFlag.Rows
    for row in range(table.model().rowCount()):
        index = table.model().index(row, 0)
        if index.data() in names:
            table.selectionModel().setCurrentIndex(index, QItemSelectionModel.SelectionFlag.NoUpdate)
            table.selectionModel().select(index, flags)
    table.setFocus()
    assert len(pane.selected_file_items()) == len(names), names


def _fits(size: QSize) -> bool:
    return size.width() <= SMALL_LIMIT.width() and size.height() <= SMALL_LIMIT.height()


def _cut_texts(top) -> list[str]:
    """Labels and buttons of *top* narrower (or, wrapped, lower) than their
    text needs - outside a scroll area, where a text may scroll."""
    from ui.elided_label import WrapAnywhereLabel

    cut = []
    for widget in top.findChildren(WrapAnywhereLabel):
        if widget.isVisibleTo(top) and widget.text():
            need = widget.heightForWidth(widget.width())
            if need > widget.height() + 1:
                cut.append(f"{widget.text()[:60]!r}: {widget.height()} px high, needs {need}")
    for widget in top.findChildren(QLabel) + top.findChildren(QAbstractButton):
        if not widget.isVisibleTo(top) or not widget.text():
            continue
        parent, scrolled = widget.parentWidget(), False
        while parent is not None and parent is not top:
            if isinstance(parent, QAbstractScrollArea):
                scrolled = True
                break
            parent = parent.parentWidget()
        if scrolled or type(widget).__name__ == "ElidedLabel":
            continue
        if isinstance(widget, QLabel) and widget.wordWrap():
            need = widget.heightForWidth(widget.width())
            if need > widget.height() + 1:
                cut.append(f"{widget.text()[:60]!r}: {widget.height()} px high, needs {need}")
            plain = (widget.textFormat() == Qt.TextFormat.PlainText
                     or not Qt.mightBeRichText(widget.text()))
            room = widget.contentsRect().width()
            words = widget.text().split() if plain else []
            wide = max((widget.fontMetrics().horizontalAdvance(w) for w in words), default=0)
            if wide > room + 1:
                # QLabel wraps at blanks only: a word wider than the label is cut
                cut.append(f"{widget.text()[:60]!r}: a word {wide} px wide in {room} px")
        elif widget.width() + 1 < widget.minimumSizeHint().width():
            cut.append(f"{widget.text()[:60]!r}: {widget.width()} px wide, needs "
                       f"{widget.minimumSizeHint().width()}")
    return cut


class Watcher:
    """Records each window that opens while *run* runs, then closes it -
    also a modal one with an event loop of its own (QInputDialog.getText)."""

    def __init__(self, main) -> None:
        self.main = main
        self.seen: list[tuple[str, list[str]]] = []
        self._known = {id(w) for w in APP.topLevelWidgets() if w.isVisible()}
        self._timer = QTimer()
        self._timer.setInterval(60)
        self._timer.timeout.connect(self.check)

    def check(self) -> None:
        for widget in APP.topLevelWidgets():
            if (sip.isdeleted(widget) or widget is self.main or isinstance(widget, QMenu)
                    or not widget.isVisible() or widget.property("axSeen")):
                continue
            widget.setProperty("axSeen", True)
            problems = []
            for what, size in (("size", widget.size()), ("minimum", widget.minimumSize()),
                               ("minimum hint", widget.minimumSizeHint())):
                if not _fits(size):
                    problems.append(f"{what} {size.width()}x{size.height()}")
            frame = widget.frameGeometry()
            if frame.right() > SMALL_SCREEN.right() or frame.bottom() > SMALL_SCREEN.bottom():
                problems.append(f"off the screen at {frame.x()},{frame.y()} "
                                f"{frame.width()}x{frame.height()}")
            problems += _cut_texts(widget)
            self.seen.append((widget.windowTitle(), problems))
            if isinstance(widget, QDialog):
                widget.reject()
            widget.close()

    def run(self, call, settle: float = 0.4) -> list[tuple[str, list[str]]]:
        self._timer.start()
        try:
            call()
            end = time.monotonic() + settle
            while time.monotonic() < end:
                pump()
                self.check()
                time.sleep(0.02)
        finally:
            self._timer.stop()
        return self.seen


def _open(window, call, settle=0.4):
    seen = Watcher(window).run(call, settle)
    assert seen, "no window opened"
    bad = [f"{title}: {p}" for title, problems in seen for p in problems]
    assert not bad, "\n".join(bad)
    return [title for title, _p in seen]


@pytest.mark.timeout(120)
def test_happy_properties_of_one_and_of_several_fit(window):
    pane = window._panes[0]
    _select(pane, LONG)
    _open(window, pane._show_properties)
    _select(pane, LONG, "notes.txt", "sub")
    _open(window, pane._show_properties)


@pytest.mark.timeout(120)
def test_happy_permissions_fit(window):
    pane = window._panes[0]
    _select(pane, LONG)
    _open(window, pane._show_permissions)


@pytest.mark.timeout(120)
def test_happy_batch_rename_fits(window):
    pane = window._panes[0]
    _select(pane, LONG, "notes.txt")
    _open(window, pane._batch_rename)


@pytest.mark.timeout(120)
def test_happy_pack_with_options_fits(window):
    pane = window._panes[0]
    _select(pane, LONG, "notes.txt", "sub")
    _open(window, lambda: pane.pack_selection(None))


@pytest.mark.timeout(120)
def test_happy_checksum_fits(window):
    pane = window._panes[0]
    _select(pane, LONG)
    item = pane.selected_file_items()[0]
    _open(window, lambda: pane._show_checksum(item), settle=3.0)


@pytest.mark.timeout(120)
def test_happy_new_symlink_fits(window):
    pane = window._panes[0]
    _open(window, pane._create_symlink)


@pytest.mark.timeout(120)
def test_happy_extract_and_its_answer_fit(window):
    pane = window._panes[0]
    _select(pane, "bundle.zip")
    item = pane.selected_file_items()[0]

    def extract():
        pane._extract_archive(item)

    _open(window, extract, settle=3.0)


@pytest.mark.timeout(120)
def test_happy_compare_panes_fits(window, language):
    pane = window._panes[0]
    window._set_active_pane(pane)
    window._split_pane(Qt.Orientation.Horizontal)
    pump(0.3)
    assert len(window._panes) == 2
    right = window._panes[1]
    right.navigate(str(window.test_other))
    assert _wait(lambda: right.current_path == str(window.test_other))
    window._set_active_pane(pane)
    window._set_target_pane(right)
    titles = _open(window, window._open_compare_panes, settle=1.5)
    # the name of View > Compare Panes… (it read "Compare panes")
    assert titles == (["Compare Panes"] if language == "en" else ["Panes vergleichen"])


@pytest.mark.timeout(120)
@pytest.mark.parametrize("name", ["notes.txt", LONG, "a" * 250])
def test_sad_the_conflict_question_fits_also_for_a_long_name(window, name):
    from core.transfer_conflicts import TransferConflict
    from ui.transfer_conflict_dialog import TransferConflictDialog

    folder = "/srv/" + "/".join(["projects-and-archives"] * 8)
    conflict = TransferConflict(name=name, source_path="/tmp/" + name,
                                dest_path=folder + "/" + name, dest_dir=folder,
                                source_is_dir=False, dest_is_dir=False, source_size=10,
                                dest_size=20, source_mtime=1.7e9, dest_mtime=1.6e9)

    def ask():
        dialog = TransferConflictDialog(conflict, remaining=3, parent=window)
        dialog.show()

    _open(window, ask)


def test_sad_permissions_and_checksum_show_outside_text_as_the_pane_does(tmp_path):
    from core.local_fs import LocalFS
    from ui.checksum_dialog import ChecksumDialog
    from ui.elided_label import WrapAnywhereLabel
    from ui.permissions_dialog import PermissionsDialog

    name = "<b>inv\u202efdp.exe"
    path = tmp_path / name
    path.write_text("x")
    backend = LocalFS()
    item = next(i for i in backend.list_dir(str(tmp_path)) if i.name == name)
    import dataclasses

    item = dataclasses.replace(item, owner="<i>root\u202e</i>", group="wheel")
    dialog = PermissionsDialog(backend, str(path), item)
    texts = [w.text() for w in dialog.findChildren(WrapAnywhereLabel)]
    assert "<b>inv\ufffdfdp.exe" in texts          # plain, defused
    assert "<i>root\ufffd</i>:wheel" in texts
    assert "\u202e" not in dialog.windowTitle()
    dialog.deleteLater()
    box = ChecksumDialog(str(path), "sha256", "ab" * 32)
    [shown] = [w.text() for w in box.findChildren(WrapAnywhereLabel)]
    assert shown == str(tmp_path) + "/<b>inv\ufffdfdp.exe"
    assert not [w for w in box.findChildren(QLabel) if "inv" in w.text()]
    box.deleteLater()
