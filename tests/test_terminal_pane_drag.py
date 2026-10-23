"""Terminal panes drag and drop like file panes (operator: "ja
bitte machen").

Before: only a file pane's header started a pane drag and only a file pane
took one (ui/file_pane.py ``_DraggableHeader``, ``FilePaneWidget.dropEvent``);
``MainWindow._on_pane_drop`` looked the dragged pane up in ``_panes`` alone,
so a terminal pane moved only from Workspace > Move Pane to or its ⇄ button.
A background workspace was unreachable by drag: its tab did not open while
a pane hovered it.

Now the terminal header is a drag handle with the same payload, a terminal
pane shows the same drop zones, ``_on_pane_drop`` takes either kind as
source and target, and hovering a workspace tab with a pane opens it after
a short delay. A pane drag never reaches the shell as text.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6 import sip  # noqa: E402
from PyQt6.QtCore import QCoreApplication, QEvent, QMimeData, QPoint, QPointF, Qt  # noqa: E402
from PyQt6.QtGui import QDragEnterEvent, QDragLeaveEvent, QDragMoveEvent, QDropEvent  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication, QSplitter, QWidget  # noqa: E402

APP = QApplication.instance() or QApplication([])

PANE_MIME = "application/x-axross-pane-drag"
TRANSFER_MIME = "application/x-axross-transfer"
ACTIONS = Qt.DropAction.CopyAction | Qt.DropAction.MoveAction


def pump(seconds: float = 0.05) -> None:
    end = time.time() + seconds
    while time.time() < end:
        APP.processEvents()
        time.sleep(0.01)
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete.value)


def pane_mime(pane_or_id, *, text: str | None = None) -> QMimeData:
    mime = QMimeData()
    raw = pane_or_id if isinstance(pane_or_id, bytes) else str(
        pane_or_id if isinstance(pane_or_id, str) else id(pane_or_id)).encode()
    mime.setData(PANE_MIME, raw)
    if text is not None:
        mime.setText(text)
    return mime


def text_mime(text: str) -> QMimeData:
    mime = QMimeData()
    mime.setText(text)
    return mime


def drag_over(widget: QWidget, mime: QMimeData, at: QPoint | None = None):
    """DragEnter then DragMove sent to *widget* as Qt delivers them: through
    QApplication, which hands an ignored enter up the parent chain and a
    move to whoever accepted the enter. Returns (enter, move)."""
    at = at or widget.rect().center()
    enter = QDragEnterEvent(at, ACTIONS, mime, Qt.MouseButton.LeftButton,
                            Qt.KeyboardModifier.NoModifier)
    enter.setDropAction(Qt.DropAction.MoveAction)
    enter.ignore()
    QApplication.sendEvent(widget, enter)
    if not enter.isAccepted():
        return enter, None
    move = QDragMoveEvent(at, ACTIONS, mime, Qt.MouseButton.LeftButton,
                          Qt.KeyboardModifier.NoModifier)
    move.setDropAction(Qt.DropAction.MoveAction)
    move.ignore()
    QApplication.sendEvent(widget, move)
    return enter, move


def drop_on(widget: QWidget, mime: QMimeData, at: QPoint | None = None):
    """A whole drag ending in a drop on *widget*; the drop only when the
    enter was accepted. Returns (enter, drop or None)."""
    at = at or widget.rect().center()
    enter, _move = drag_over(widget, mime, at)
    if not enter.isAccepted():
        return enter, None
    drop = QDropEvent(QPointF(at), ACTIONS, mime, Qt.MouseButton.LeftButton,
                      Qt.KeyboardModifier.NoModifier)
    drop.setDropAction(Qt.DropAction.MoveAction)
    drop.ignore()
    QApplication.sendEvent(widget, drop)
    return enter, drop


class FakeDrag:
    """Stands in for QDrag: exec() would run the platform's drag loop."""

    started: list = []

    def __init__(self, source):
        self.source = source
        self.mime = None
        self.pixmap = None

    def setMimeData(self, mime):  # noqa: N802 - Qt name
        self.mime = mime

    def setPixmap(self, pixmap):  # noqa: N802 - Qt name
        self.pixmap = pixmap

    def setHotSpot(self, _point):  # noqa: N802 - Qt name
        pass

    def exec(self, *_args):
        FakeDrag.started.append(self)
        return Qt.DropAction.MoveAction


@pytest.fixture
def fake_drag(monkeypatch):
    import ui.pane_drag as pane_drag

    FakeDrag.started = []
    monkeypatch.setattr(pane_drag, "QDrag", FakeDrag)
    return FakeDrag


# -- a terminal pane on its own ----------------------------------------------------------


@pytest.fixture
def term(tmp_path):
    from ui.terminal_pane import TerminalPaneWidget

    t = TerminalPaneWidget(label="Local Shell", cwd=str(tmp_path))
    t.resize(700, 400)
    t.show()
    pump()
    t.sent = []
    t._terminal.data_ready.connect(t.sent.append)
    t.drops = []
    t.pane_drop_requested.connect(lambda *args: t.drops.append(args))
    yield t
    t.shutdown()
    t.close()
    t.deleteLater()
    pump()


def _header_drag(term, distance: int):
    header = term._title
    start = QPoint(5, header.height() // 2)
    QTest.mousePress(header, Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier, start)
    QTest.mouseMove(header, start + QPoint(distance, 0))
    QTest.mouseRelease(header, Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier,
                       start + QPoint(distance, 0))


def test_e2e_the_terminal_header_starts_a_pane_drag_past_the_threshold(term, fake_drag):
    from ui.pane_drag import PANE_DRAG_THRESHOLD, PANE_MIME_TYPE

    assert PANE_MIME_TYPE == PANE_MIME
    _header_drag(term, PANE_DRAG_THRESHOLD + 5)
    (drag,) = fake_drag.started
    assert bytes(drag.mime.data(PANE_MIME)).decode() == str(id(term))
    # Only the pane payload: no text a terminal or editor would take.
    assert drag.mime.formats() == [PANE_MIME]
    assert drag.pixmap is not None and not drag.pixmap.isNull()


def test_edge_a_short_move_on_the_header_is_no_drag(term, fake_drag):
    from ui.pane_drag import PANE_DRAG_THRESHOLD

    _header_drag(term, PANE_DRAG_THRESHOLD - 3)
    assert fake_drag.started == []


def test_e2e_the_header_buttons_still_click_and_drag_nothing(term, fake_drag):
    closed = []
    term.close_requested.connect(lambda: closed.append(True))
    close_button = next(b for b in term.findChildren(type(term._btn_pin))
                        if b.text() == "✕")
    QTest.mouseClick(close_button, Qt.MouseButton.LeftButton)
    assert closed == [True]
    QTest.mouseClick(term._btn_bookmark, Qt.MouseButton.LeftButton)
    assert fake_drag.started == []


def test_edge_the_file_pane_header_uses_the_same_drag(tmp_path, fake_drag):
    from core.local_fs import LocalFS
    from ui.file_pane import FilePaneWidget
    from ui.pane_drag import PANE_DRAG_THRESHOLD

    pane = FilePaneWidget(LocalFS())
    pane.resize(600, 400)
    pane.show()
    pump()
    try:
        header = pane._header_label
        start = QPoint(5, header.height() // 2)
        QTest.mousePress(header, Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier,
                         start)
        QTest.mouseMove(header, start + QPoint(PANE_DRAG_THRESHOLD + 5, 0))
        QTest.mouseRelease(header, Qt.MouseButton.LeftButton)
        (drag,) = fake_drag.started
        assert bytes(drag.mime.data(PANE_MIME)).decode() == str(id(pane))
    finally:
        pane.close()
        pane.deleteLater()
        pump()


def test_edge_a_drop_on_the_file_list_judges_the_zone_where_the_cursor_is(tmp_path):
    """Found while building this: the file pane judged a drop on its table
    in the table viewport's coordinates against the whole pane's size - the
    header and toolbars above the table shifted every zone. A drop near the
    pane's left edge, just under the toolbars, said "top"."""
    from core.local_fs import LocalFS
    from ui.file_pane import FilePaneWidget
    from ui.layout_utils import detect_drop_zone

    pane = FilePaneWidget(LocalFS())
    pane.resize(600, 600)
    pane.show()
    pump(0.2)
    drops = []
    pane.pane_drop_requested.connect(lambda *args: drops.append(args))
    try:
        view = pane._table.viewport()
        offset = view.mapTo(pane, QPoint(0, 0))
        # Just under the toolbars, nearer the pane's left edge than its top.
        x = (3 + offset.y()) * pane.width() // pane.height() // 2 - offset.x()
        at = QPoint(x, 3)
        mapped = view.mapTo(pane, at)
        right = detect_drop_zone(mapped.x(), mapped.y(), pane.width(), pane.height())
        wrong = detect_drop_zone(at.x(), at.y(), pane.width(), pane.height())
        assert (right, wrong) == ("left", "top")  # the case tells them apart
        drop_on(view, pane_mime(QWidget()), at)
        assert [zone for _id, _pane, zone in drops] == ["left"]
    finally:
        pane.close()
        pane.deleteLater()
        pump()


def test_happy_a_pane_dropped_on_the_terminal_asks_for_a_split(term):
    other = QWidget()
    view = term._terminal.viewport()
    # Right edge of the terminal: the "right" zone.
    at = QPoint(view.width() - 3, view.height() // 2)
    enter, drop = drop_on(view, pane_mime(other), at)
    assert enter.isAccepted() and drop is not None and drop.isAccepted()
    assert term.drops == [(str(id(other)), term, "right")]
    assert not term._drop_overlay.isVisible()


def test_happy_the_drop_zone_overlay_shows_while_a_pane_hovers(term):
    other = QWidget()
    view = term._terminal.viewport()
    enter, move = drag_over(view, pane_mime(other), QPoint(view.width() // 2, 2))
    assert enter.isAccepted() and move.isAccepted()
    assert term._drop_overlay.isVisible()
    assert term._drop_overlay._zone == "top"
    QApplication.sendEvent(term, QDragLeaveEvent())
    assert not term._drop_overlay.isVisible()


def test_security_a_pane_drop_never_reaches_the_shell(term):
    """The pane id is no command: nothing of a pane drag goes to the host,
    not even when the drag also carries text."""
    other = QWidget()
    view = term._terminal.viewport()
    drop_on(view, pane_mime(other))
    drop_on(view, pane_mime(other, text="rm -rf ~\n"))
    assert term.sent == []
    emulator = term._terminal
    sneaky = pane_mime(other, text="rm -rf ~\n")
    assert emulator.canInsertFromMimeData(sneaky) is False
    emulator.insertFromMimeData(sneaky)
    assert term.sent == []
    # Both drops were pane drops, asked of the window.
    assert len(term.drops) == 2


def test_regression_a_text_drop_on_the_terminal_pane_still_goes_to_the_shell(term):
    view = term._terminal.viewport()
    enter, drop = drop_on(view, text_mime("ls -l"))
    assert enter.isAccepted() and drop is not None
    assert term.sent == [b"ls -l"]
    assert term.drops == []


def test_sad_a_pane_dropped_on_itself_does_nothing(term):
    view = term._terminal.viewport()
    enter, drop = drop_on(view, pane_mime(term))
    assert not enter.isAccepted() and drop is None
    assert term.drops == [] and term.sent == []


def test_sad_a_file_transfer_drag_is_not_taken_by_the_terminal_pane(term):
    mime = QMimeData()
    mime.setData(TRANSFER_MIME, json.dumps({"paths": ["/x"], "source_pane_id": "1"}).encode())
    enter, drop = drop_on(term._terminal.viewport(), mime)
    assert not enter.isAccepted() and drop is None
    assert term.drops == [] and term.sent == []


def test_edge_a_garbled_pane_payload_is_ignored(term):
    for raw in (b"\xff\xfe\x00", b""):
        enter, drop = drop_on(term._terminal.viewport(), pane_mime(raw))
        assert not enter.isAccepted() and drop is None
    assert term.drops == [] and term.sent == []


# -- the main window ----------------------------------------------------------------------


@pytest.fixture
def home():
    path = Path(tempfile.mkdtemp())
    yield path
    shutil.rmtree(path, ignore_errors=True)


def _make_window(home: Path):
    from ui import main_window as MW

    with mock.patch("pathlib.Path.home", return_value=home):
        win = MW.MainWindow()
    win._reconnect_timer.stop()
    return win


def _destroy(win) -> None:
    if win is None or sip.isdeleted(win):
        return
    win.close()
    win.deleteLater()
    pump()


@pytest.fixture
def window(home, monkeypatch):
    from ui import main_window as MW

    monkeypatch.setattr(MW.MainWindow, "_SESSION_FILE", home / "session.json")
    win = _make_window(home)
    win.resize(1200, 800)
    win.show()
    pump()
    yield win
    _destroy(win)


def _shell(window, beside=None):
    """A local terminal pane made the way the window makes them (a terminal
    bookmark, a restored session), beside *beside* or the active pane."""
    term = window._preset_make_terminal_pane("local", cwd=str(Path.home()))
    window._place_terminal_pane(term, beside)
    pump()
    return term


def _files(window):
    """Another local file pane at the end of the current workspace."""
    from core.local_fs import LocalFS

    pane = window._add_pane_to_splitter(window._root_splitter, LocalFS())
    pump()
    return pane


def _siblings(widget) -> list:
    parent = widget.parent()
    return [parent.widget(i) for i in range(parent.count())]


def test_happy_a_terminal_dropped_on_a_file_pane_splits_beside_it(window):
    files = window._active_pane
    term = _shell(window, _files(window))
    window._on_pane_drop(str(id(term)), files, "right")
    pump()
    parent = term.parent()
    assert isinstance(parent, QSplitter)
    assert parent.orientation() == Qt.Orientation.Horizontal
    assert _siblings(term) == [files, term]
    assert term.isVisible() and files.isVisible()


def test_happy_a_file_pane_dropped_on_a_terminal_splits_beside_it(window):
    files = window._active_pane  # the terminal opens beside it
    term = _shell(window, files)
    mover = _files(window)
    window._on_pane_drop(str(id(mover)), term, "top")
    pump()
    assert mover.parent().orientation() == Qt.Orientation.Vertical
    assert _siblings(mover) == [mover, term]


def test_happy_a_terminal_dropped_on_a_terminal(window):
    first = _shell(window)
    second = _shell(window)
    window._on_pane_drop(str(id(second)), first, "bottom")
    pump()
    assert _siblings(second) == [first, second]
    assert second.parent().orientation() == Qt.Orientation.Vertical
    assert first in window._terminal_panes and second in window._terminal_panes


def test_happy_a_terminal_dragged_out_of_another_workspace_closes_it(window):
    home_ws = window.current_workspace()
    target = window._active_pane
    away = window.new_workspace("Shells", with_pane=False)
    term = window._preset_make_terminal_pane("local", cwd=str(Path.home()))
    window._root_splitter.addWidget(term)  # the empty workspace has no pane to sit beside
    pump()
    assert window.workspace_of(term) is away
    window.detach_workspace(away)
    window._on_pane_drop(str(id(term)), target, "left")
    pump()
    assert window.workspace_of(term) is home_ws
    assert [ws.name for ws in window.workspaces()] == [home_ws.name]
    assert away.window is None
    assert term.is_running


def test_sad_unknown_self_and_foreign_drops_change_nothing(window):
    files = window._active_pane
    term = _shell(window)
    before = window._serialize_workspaces()
    stray = QWidget()
    window._on_pane_drop("12345", files, "left")
    window._on_pane_drop(str(id(term)), term, "left")
    window._on_pane_drop(str(id(stray)), files, "left")
    window._on_pane_drop(str(id(term)), stray, "left")
    window._on_pane_drop(str(id(term)), files, "middle")
    pump()
    assert window._serialize_workspaces() == before
    assert term in window._terminal_panes


def test_e2e_dragging_a_terminal_onto_a_file_pane_moves_it(window):
    """The whole chain with real widgets: the drag events reach the file
    pane's table, its signal reaches the window, the terminal moves."""
    files = window._active_pane
    term = _shell(window, _files(window))
    view = files._table.viewport()
    at = QPoint(3, view.height() // 2)  # left edge
    enter, drop = drop_on(view, pane_mime(term), at)
    pump()
    assert enter.isAccepted() and drop is not None
    assert _siblings(term) == [term, files]


def test_e2e_dragging_a_file_pane_onto_a_terminal_moves_it(window):
    files = window._active_pane
    term = _shell(window)
    mover = _files(window)
    term.sent = []
    term._terminal.data_ready.connect(term.sent.append)
    view = term._terminal.viewport()
    at = QPoint(view.width() // 2, view.height() - 2)  # bottom edge
    enter, drop = drop_on(view, pane_mime(mover), at)
    pump()
    assert enter.isAccepted() and drop is not None
    assert _siblings(mover) == [term, mover]
    assert term.sent == []
    assert files in window._panes


# -- workspace tabs open while a pane hovers them ----------------------------------------


def _two_tabs(window):
    first = window.current_workspace()
    second = window.new_workspace("Second")
    window.switch_workspace(first)
    pump()
    bar = window._workspace_tabs.tabBar()
    assert bar.isVisible()
    return first, second, bar


def _tab_center(window, ws) -> QPoint:
    bar = window._workspace_tabs.tabBar()
    return bar.tabRect(window._workspace_tabs.indexOf(ws.root)).center()


def test_happy_hovering_a_tab_with_a_pane_opens_that_workspace(window):
    from ui.workspaces import TAB_DRAG_SWITCH_MS

    first, second, bar = _two_tabs(window)
    drag_over(bar, pane_mime(window._active_pane), _tab_center(window, second))
    pump(0.05)
    assert window.current_workspace() is first  # not at once
    pump(TAB_DRAG_SWITCH_MS / 1000 + 0.3)
    assert window.current_workspace() is second
    assert window._workspace_tabs.currentWidget() is second.root


def test_e2e_a_pane_reaches_a_background_workspace_by_dragging(window):
    """Drag a terminal over the tab of a background workspace, wait, drop it
    on that workspace's pane: it lands there."""
    from ui.workspaces import TAB_DRAG_SWITCH_MS

    first, second, bar = _two_tabs(window)
    term = _shell(window)
    assert window.workspace_of(term) is first
    drag_over(bar, pane_mime(term), _tab_center(window, second))
    pump(TAB_DRAG_SWITCH_MS / 1000 + 0.3)
    QApplication.sendEvent(bar, QDragLeaveEvent())
    pump()
    (target,) = [p for p in window._panes if window.workspace_of(p) is second]
    view = target._table.viewport()
    enter, drop = drop_on(view, pane_mime(term), QPoint(view.width() - 3, view.height() // 2))
    pump()
    assert drop is not None and window.workspace_of(term) is second
    assert _siblings(term) == [target, term]


def test_sad_a_file_transfer_drag_over_a_tab_switches_nothing(window):
    from ui.workspaces import TAB_DRAG_SWITCH_MS

    first, second, bar = _two_tabs(window)
    mime = QMimeData()
    mime.setData(TRANSFER_MIME, json.dumps({"paths": ["/x"], "source_pane_id": "1"}).encode())
    # Not taken by the tab bar, as before it watched for panes (measured:
    # neither the tab bar nor the window accepts these).
    enter, _move = drag_over(bar, mime, _tab_center(window, second))
    assert not enter.isAccepted()
    enter, _move = drag_over(bar, text_mime("hello"), _tab_center(window, second))
    assert not enter.isAccepted()
    pump(TAB_DRAG_SWITCH_MS / 1000 + 0.3)
    assert window.current_workspace() is first


def test_edge_leaving_the_tab_before_the_delay_switches_nothing(window):
    from ui.workspaces import TAB_DRAG_SWITCH_MS

    first, second, bar = _two_tabs(window)
    drag_over(bar, pane_mime(window._active_pane), _tab_center(window, second))
    pump(0.05)
    QApplication.sendEvent(bar, QDragLeaveEvent())
    pump(TAB_DRAG_SWITCH_MS / 1000 + 0.3)
    assert window.current_workspace() is first


def test_edge_hovering_the_current_tab_or_no_tab_starts_nothing(window):
    from ui.workspaces import TAB_DRAG_SWITCH_MS

    first, second, bar = _two_tabs(window)
    mime = pane_mime(window._active_pane)
    drag_over(bar, mime, _tab_center(window, first))
    drag_over(bar, mime, QPoint(bar.width() - 2, bar.height() // 2))
    pump(TAB_DRAG_SWITCH_MS / 1000 + 0.3)
    assert window.current_workspace() is first


def test_edge_moving_from_one_tab_to_another_restarts_the_delay(window):
    from ui.workspaces import TAB_DRAG_SWITCH_MS

    first, second, bar = _two_tabs(window)
    third = window.new_workspace("Third")
    window.switch_workspace(first)
    pump()
    mime = pane_mime(window._active_pane)
    drag_over(bar, mime, _tab_center(window, second))
    pump(TAB_DRAG_SWITCH_MS / 1000 * 0.6)
    move = QDragMoveEvent(_tab_center(window, third), ACTIONS, mime, Qt.MouseButton.LeftButton,
                          Qt.KeyboardModifier.NoModifier)
    QApplication.sendEvent(bar, move)
    pump(TAB_DRAG_SWITCH_MS / 1000 * 0.6)
    assert window.current_workspace() is first
    pump(TAB_DRAG_SWITCH_MS / 1000 * 0.4 + 0.3)
    assert window.current_workspace() is third


def test_sad_a_pane_dropped_on_a_tab_is_refused(window):
    first, second, bar = _two_tabs(window)
    enter, drop = drop_on(bar, pane_mime(window._active_pane), _tab_center(window, second))
    assert drop is None or not drop.isAccepted()


# -- session ------------------------------------------------------------------------------


def test_happy_a_dragged_terminal_is_saved_and_restored_in_its_new_workspace(home, monkeypatch):
    from ui import main_window as MW

    monkeypatch.setattr(MW.MainWindow, "_SESSION_FILE", home / "session.json")
    shell_dir = home / "shell"
    shell_dir.mkdir()
    win = _make_window(home)
    try:
        win.show()
        first = win.current_workspace()
        second = win.new_workspace("Second")
        target = win._active_pane
        win.switch_workspace(first)
        term = win._preset_make_terminal_pane("local", cwd=str(shell_dir))
        win._place_terminal_pane(term, None)
        pump()
        assert win.workspace_of(term) is first
        win._on_pane_drop(str(id(term)), target, "right")
        pump()
        assert win.workspace_of(term) is second
        win._save_session()
    finally:
        _destroy(win)
    data = json.loads((home / "session.json").read_text())
    by_name = {w["name"]: json.dumps(w["splitter"]) for w in data["workspaces"]}
    assert '"terminal"' in by_name["Second"] and '"terminal"' not in by_name["Workspace 1"]

    again = _make_window(home)
    try:
        assert again.restore_layout_on_start()
        again.show()
        pump()
        (restored,) = again._terminal_panes
        assert again.workspace_of(restored).name == "Second"
        assert restored.start_directory == str(shell_dir)
        # A restored terminal drags too: its drop signal reaches the window.
        (files,) = [p for p in again._panes if again.workspace_of(p).name == "Second"]
        restored.pane_drop_requested.emit(str(id(files)), restored, "left")
        pump()
        assert _siblings(files) == [files, restored]
    finally:
        _destroy(again)
