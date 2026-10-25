"""Cut and Paste of files between panes.

Operator: "eine wichtige funktion fehlt uns im rechte mausklick file
transfer menue ... cut n paste, also ausschneiden von einem file und dann
irgenwoanders wieder platzieren, aufpassen, dass wenn nicht platziert wird,
dass es dann auch nicht auf dem ursprung entfernt wird".

Before: the right-click menu had Copy Path, Copy to Target Pane and Move to
Target Pane, but no Cut and no Paste; Ctrl+X and Ctrl+V did nothing in a
pane. Cut only remembers the entries (app-wide); Paste moves them through
the transfer queue, which removes a source only after its copy completed
and was checked. A cut that is never pasted removes nothing.
"""

from __future__ import annotations

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

from PyQt6.QtCore import QEvent, QItemSelectionModel, Qt  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core.local_fs import LocalFS  # noqa: E402
from core.ram_fs import RamFsSession  # noqa: E402

APP = QApplication.instance() or QApplication([])
CTRL = Qt.KeyboardModifier.ControlModifier


def pump(seconds: float = 0.05) -> None:
    end = time.time() + seconds
    while time.time() < end:
        APP.processEvents()
        time.sleep(0.01)


def wait_for(predicate, timeout: float = 10.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        APP.processEvents()
        if predicate():
            return True
        time.sleep(0.01)
    return False


def row_of(pane, name: str):
    proxy = pane._table.model()
    for row in range(proxy.rowCount()):
        if proxy.index(row, 0).data() == name:
            return row
    return None


def select(pane, *names: str) -> None:
    proxy = pane._table.model()
    sel = pane._table.selectionModel()
    sel.clearSelection()
    for row in range(proxy.rowCount()):
        if proxy.index(row, 0).data() in names:
            sel.select(
                proxy.index(row, 0),
                QItemSelectionModel.SelectionFlag.Select | QItemSelectionModel.SelectionFlag.Rows,
            )


def press(widget, key, modifiers=Qt.KeyboardModifier.NoModifier) -> None:
    widget.setFocus()
    pump(0.02)
    QTest.keyClick(widget, key, modifiers)
    pump(0.02)


def by_command(menu) -> dict:
    return {str(a.property("axCommand")): a for a in menu.actions() if a.property("axCommand")}


@pytest.fixture(autouse=True)
def _no_pending_cut():
    from ui.cut_clipboard import cut_clipboard

    cut_clipboard().clear()
    yield
    cut_clipboard().clear()


# --- unit: the paste plan (core.cut_paste) ----------------------------------


def test_happy_plan_moves_entries_into_another_folder(tmp_path) -> None:
    from core.cut_paste import plan_paste

    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    (tmp_path / "a" / "f.txt").write_text("x")
    fs = LocalFS()
    plan = plan_paste(fs, [str(tmp_path / "a" / "f.txt")], fs, str(tmp_path / "b"))
    assert plan.paths == (str(tmp_path / "a" / "f.txt"),)
    assert plan.already_here == () and plan.refusal == ""


def test_edge_plan_into_the_folder_it_came_from_moves_nothing(tmp_path) -> None:
    from core.cut_paste import plan_paste

    (tmp_path / "f.txt").write_text("x")
    (tmp_path / "sub").mkdir()
    plan = plan_paste(
        LocalFS(), [str(tmp_path / "f.txt"), str(tmp_path / "sub")], LocalFS(), str(tmp_path)
    )
    assert plan.paths == ()
    assert plan.already_here == (str(tmp_path / "f.txt"), str(tmp_path / "sub"))
    assert plan.refusal == ""


def test_sad_plan_refuses_a_folder_into_itself_or_below_it(tmp_path) -> None:
    from core.cut_paste import plan_paste

    deep = tmp_path / "sub" / "deeper"
    deep.mkdir(parents=True)
    fs = LocalFS()
    for dest in (tmp_path / "sub", deep):
        plan = plan_paste(fs, [str(tmp_path / "sub")], fs, str(dest))
        assert plan.paths == ()
        assert "into itself" in plan.refusal, plan


def test_edge_plan_on_ramfs_and_across_backends() -> None:
    from core.cut_paste import plan_paste

    ram = RamFsSession()
    ram.mkdir("/a")
    ram.mkdir("/a/sub")
    with ram.open_write("/a/f.txt") as fh:
        fh.write(b"x")
    assert plan_paste(ram, ["/a/f.txt"], ram, "/a").already_here == ("/a/f.txt",)
    assert "into itself" in plan_paste(ram, ["/a/sub"], ram, "/a/sub").refusal
    # Another backend with the same path text is another place.
    other = RamFsSession()
    other.mkdir("/a")
    plan = plan_paste(ram, ["/a/f.txt", "/a/sub"], other, "/a")
    assert plan.paths == ("/a/f.txt", "/a/sub") and plan.refusal == ""


def test_sad_plan_with_nothing_cut_is_empty(tmp_path) -> None:
    from core.cut_paste import plan_paste

    plan = plan_paste(LocalFS(), [], LocalFS(), str(tmp_path))
    assert plan.paths == () and plan.already_here == () and plan.refusal == ""


# --- unit: the app-wide cut (ui.cut_clipboard) -------------------------------


class _Source:
    """Stands in for a pane: the clipboard only compares it by identity."""


def test_happy_a_cut_is_remembered_and_announced() -> None:
    from ui.cut_clipboard import cut_clipboard

    board = cut_clipboard()
    fired: list[int] = []
    board.changed.connect(lambda: fired.append(1))
    source, fs = _Source(), LocalFS()
    cut = board.cut(source, fs, "/data", ["/data/a.txt", "/data/sub"])
    assert board.pending is cut
    assert cut.paths == ("/data/a.txt", "/data/sub") and cut.backend is fs
    assert board.names_in(fs, "/data") == {"a.txt", "sub"}
    assert board.names_in(fs, "/other") == frozenset()
    assert board.names_in(LocalFS(), "/data") == frozenset()  # another connection
    assert fired


def test_sad_an_empty_cut_is_refused_and_keeps_the_pending_one() -> None:
    from ui.cut_clipboard import cut_clipboard

    board = cut_clipboard()
    source, fs = _Source(), LocalFS()
    cut = board.cut(source, fs, "/data", ["/data/a.txt"])
    with pytest.raises(ValueError):
        board.cut(source, fs, "/data", [])
    assert board.pending is cut


def test_edge_a_new_cut_replaces_and_clearing_is_per_cut_and_per_source() -> None:
    from ui.cut_clipboard import cut_clipboard

    board = cut_clipboard()
    first_source, second_source, fs = _Source(), _Source(), LocalFS()
    first = board.cut(first_source, fs, "/a", ["/a/x"])
    second = board.cut(second_source, fs, "/b", ["/b/y"])
    assert board.pending is second
    assert board.clear(first) is False and board.pending is second  # a stale paste
    assert board.drop_source(first_source) is False and board.pending is second
    assert board.drop_source(second_source) is True and board.pending is None
    board.cut(first_source, fs, "/a", ["/a/x"])
    assert board.clear() is True and board.pending is None
    assert board.clear() is False


def test_edge_a_clipboard_deleted_with_its_application_is_made_anew() -> None:
    """Destroying the QApplication deletes the Python-owned clipboard (seen in
    tests/test_pane_hover_activation.py, whose fixture lets the application
    go between tests): the next pane must get a fresh one, not a
    RuntimeError from the deleted wrapper."""
    from PyQt6 import sip

    from ui.cut_clipboard import cut_clipboard

    old = cut_clipboard()
    sip.delete(old)
    fresh = cut_clipboard()
    assert fresh is not old and not sip.isdeleted(fresh)
    cut = fresh.cut(_Source(), LocalFS(), "/data", ["/data/a.txt"])
    assert fresh.pending is cut and cut_clipboard() is fresh


# --- pane level: one pane, LocalFS ------------------------------------------


@pytest.fixture
def pane(tmp_path):
    from ui.file_pane import FilePaneWidget

    folder = tmp_path / "data"
    (folder / "sub").mkdir(parents=True)
    (folder / "notes.txt").write_text("keep me")
    (folder / "sub" / "inner.txt").write_text("inner")
    widget = FilePaneWidget(LocalFS())
    widget.resize(800, 500)
    widget.show()
    widget.navigate(str(folder))
    assert wait_for(lambda: row_of(widget, "notes.txt") is not None)
    yield widget
    widget.close()
    widget.deleteLater()
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    pump()


def test_happy_ctrl_x_remembers_the_selection_removes_nothing_and_dims_it(pane) -> None:
    from ui.cut_clipboard import cut_clipboard

    folder = Path(pane.current_path)
    plain = pane._table.model().index(row_of(pane, "notes.txt"), 0).data(
        Qt.ItemDataRole.ForegroundRole)
    select(pane, "notes.txt", "sub")
    press(pane._table, Qt.Key.Key_X, CTRL)
    cut = cut_clipboard().pending
    assert cut is not None and cut.source is pane and cut.backend is pane.backend
    assert sorted(cut.paths) == sorted([str(folder / "notes.txt"), str(folder / "sub")])
    assert (folder / "notes.txt").read_text() == "keep me"
    assert (folder / "sub" / "inner.txt").exists()
    model = pane._table.model()
    dimmed = model.index(row_of(pane, "notes.txt"), 0).data(Qt.ItemDataRole.ForegroundRole)
    assert dimmed is not None and dimmed != plain
    pane.refresh()  # the mark survives a new listing of the folder
    assert wait_for(lambda: row_of(pane, "notes.txt") is not None)
    again = pane._table.model().index(row_of(pane, "notes.txt"), 0)
    assert again.data(Qt.ItemDataRole.ForegroundRole) == dimmed


def test_sad_ctrl_x_with_nothing_selected_keeps_the_pending_cut(pane) -> None:
    from ui.cut_clipboard import cut_clipboard

    select(pane, "notes.txt")
    press(pane._table, Qt.Key.Key_X, CTRL)
    cut = cut_clipboard().pending
    pane._table.clearSelection()
    press(pane._table, Qt.Key.Key_X, CTRL)
    assert cut_clipboard().pending is cut


def test_edge_esc_clears_the_selection_first_then_drops_the_cut(pane) -> None:
    from ui.cut_clipboard import cut_clipboard

    folder = Path(pane.current_path)
    select(pane, "notes.txt")
    press(pane._table, Qt.Key.Key_X, CTRL)
    press(pane._table, Qt.Key.Key_Escape)
    assert not pane._table.selectionModel().hasSelection()
    assert cut_clipboard().pending is not None
    press(pane._table, Qt.Key.Key_Escape)
    assert cut_clipboard().pending is None
    assert (folder / "notes.txt").read_text() == "keep me"
    plain = pane._table.model().index(row_of(pane, "notes.txt"), 0)
    assert plain.data(Qt.ItemDataRole.ForegroundRole) is None  # the mark is gone


def test_edge_esc_in_another_pane_keeps_the_cut(pane) -> None:
    from ui.cut_clipboard import cut_clipboard
    from ui.file_pane import FilePaneWidget

    select(pane, "notes.txt")
    press(pane._table, Qt.Key.Key_X, CTRL)
    other = FilePaneWidget(LocalFS())
    other.show()
    try:
        other._table.clearSelection()
        press(other._table, Qt.Key.Key_Escape)
        assert cut_clipboard().pending is not None
    finally:
        other.close()
        other.deleteLater()
        APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)


def test_edge_closing_the_pane_or_changing_its_connection_drops_the_cut(pane) -> None:
    from ui.cut_clipboard import cut_clipboard

    folder = Path(pane.current_path)
    select(pane, "notes.txt")
    press(pane._table, Qt.Key.Key_X, CTRL)
    pane.set_backend(LocalFS(), str(folder))
    assert cut_clipboard().pending is None
    assert wait_for(lambda: row_of(pane, "notes.txt") is not None)
    select(pane, "notes.txt")
    press(pane._table, Qt.Key.Key_X, CTRL)
    assert cut_clipboard().pending is not None
    pane.shutdown()
    assert cut_clipboard().pending is None
    assert (folder / "notes.txt").read_text() == "keep me"


def test_edge_ctrl_c_x_v_still_edit_the_path_and_filter_lines(pane) -> None:
    from ui.cut_clipboard import cut_clipboard

    select(pane, "notes.txt")
    for edit in (pane._filter_edit, pane._path_edit):
        edit.setFocus()
        pump(0.02)
        edit.setText("")
        QTest.keyClicks(edit, "abc")
        edit.selectAll()
        QTest.keyClick(edit, Qt.Key.Key_X, CTRL)
        assert edit.text() == "", edit
        assert APP.clipboard().text() == "abc"
        QTest.keyClick(edit, Qt.Key.Key_V, CTRL)
        assert edit.text() == "abc"
        edit.selectAll()
        QTest.keyClick(edit, Qt.Key.Key_C, CTRL)
        assert APP.clipboard().text() == "abc"
        assert cut_clipboard().pending is None  # no file was cut
        edit.setText("")
    pane._path_edit.setText(pane.current_path)


def test_happy_the_menu_offers_cut_and_paste_only_when_it_can(pane) -> None:
    select(pane, "notes.txt")
    commands = by_command(pane._build_context_menu())
    assert "cut" in commands and "paste" not in commands
    commands["cut"].trigger()
    from ui.cut_clipboard import cut_clipboard

    assert cut_clipboard().pending is not None
    # A pane no window listens to cannot paste: no Paste entry.
    assert "paste" not in by_command(pane._build_context_menu())
    received: list[int] = []
    pane.paste_requested.connect(lambda: received.append(1))
    pane._table.clearSelection()
    commands = by_command(pane._build_context_menu())
    assert "cut" not in commands and "paste" in commands  # empty area too
    commands["paste"].trigger()
    assert received == [1]


def test_sad_a_hostile_single_name_offers_no_cut(pane) -> None:
    select(pane, "notes.txt")
    pane._safe_item_path = lambda item, warn=True: None
    assert "cut" not in by_command(pane._build_context_menu())


# --- e2e: two panes in the main window --------------------------------------


class _FailingWriteFS(LocalFS):
    """LocalFS whose writes break after the first chunk: a transfer that
    fails part-way through."""

    def open_write(self, path: str, append: bool = False):
        real = super().open_write(path, append=append)

        class _Writer:
            def __init__(self) -> None:
                self.calls = 0

            def write(self, data):
                self.calls += 1
                if self.calls > 1:
                    raise OSError("No space left on device (injected)")
                return real.write(data)

            def __getattr__(self, name):
                return getattr(real, name)

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                real.close()
                return False

        return _Writer()


@pytest.fixture
def win(tmp_path):
    from ui import column_prefs as CP
    from ui import main_window as MW

    root = Path(tempfile.mkdtemp(dir=tmp_path)).resolve()
    patches = [
        mock.patch.dict(os.environ, {"AXROSS_OPERATION_JOURNAL": str(root / "ops.jsonl")}),
        mock.patch.object(CP, "DEFAULT_PATH", root / "cols.json"),
    ]
    for p in patches:
        p.start()
    home = root / "home"
    home.mkdir()
    with mock.patch("pathlib.Path.home", return_value=home):
        window = MW.MainWindow()
    window._reconnect_timer.stop()
    window.resize(1200, 700)
    window.show()
    for extra in list(window._panes)[1:]:
        window._close_pane(extra)
    a, b = root / "a", root / "b"
    (a / "sub").mkdir(parents=True)
    b.mkdir()
    (a / "f.txt").write_text("payload")
    (a / "sub" / "inner.txt").write_text("inner")
    left = window._panes[0]
    left.navigate(str(a))
    right = window._add_pane_to_splitter(window._root_splitter, LocalFS())
    right.navigate(str(b))
    assert wait_for(lambda: row_of(left, "f.txt") is not None)
    asked: list[str] = []
    conflict = mock.patch.object(
        MW.MainWindow, "_ask_transfer_conflict",
        lambda _w, c, _remaining: asked.append(c.name), create=True,
    )
    conflict.start()
    patches.append(conflict)
    window.test_ctx = {"a": a, "b": b, "left": left, "right": right, "asked": asked, "MW": MW}
    yield window
    window.close()
    window.deleteLater()
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    pump()
    for p in reversed(patches):
        p.stop()
    shutil.rmtree(root, ignore_errors=True)


def settle(window) -> None:
    from core.transfer_worker import TransferStatus

    def idle() -> bool:
        if getattr(window, "_conflict_checks", None):
            return False
        return all(
            j.status not in (TransferStatus.PENDING, TransferStatus.ACTIVE)
            for j in window._transfer_manager._jobs.values()
        )

    assert wait_for(idle)
    pump(0.2)
    assert wait_for(idle)


def cut_in(pane, *names: str) -> None:
    select(pane, *names)
    press(pane._table, Qt.Key.Key_X, CTRL)


def test_happy_e2e_cut_then_ctrl_v_in_the_other_pane_moves(win) -> None:
    from ui.cut_clipboard import cut_clipboard

    ctx = win.test_ctx
    cut_in(ctx["left"], "f.txt", "sub")
    assert (ctx["a"] / "f.txt").exists()  # Cut removed nothing
    press(ctx["right"]._table, Qt.Key.Key_V, CTRL)
    settle(win)
    assert (ctx["b"] / "f.txt").read_text() == "payload"
    assert (ctx["b"] / "sub" / "inner.txt").read_text() == "inner"
    assert not (ctx["a"] / "f.txt").exists()
    assert not (ctx["a"] / "sub").exists()
    assert cut_clipboard().pending is None
    assert ctx["asked"] == []


def test_happy_e2e_paste_from_the_menu_of_the_empty_area(win) -> None:
    ctx = win.test_ctx
    cut_in(ctx["left"], "f.txt")
    ctx["right"]._table.clearSelection()
    by_command(ctx["right"]._build_context_menu())["paste"].trigger()
    settle(win)
    assert (ctx["b"] / "f.txt").read_text() == "payload"
    assert not (ctx["a"] / "f.txt").exists()


def test_happy_e2e_cut_and_paste_across_backends_into_ramfs(win) -> None:
    ctx = win.test_ctx
    ram = RamFsSession()
    ram.mkdir("/inbox")
    target = win._add_pane_to_splitter(win._root_splitter, ram)
    target.navigate("/inbox")
    pump()
    cut_in(ctx["left"], "f.txt")
    press(target._table, Qt.Key.Key_V, CTRL)
    settle(win)
    with ram.open_read("/inbox/f.txt") as fh:
        assert fh.read() == b"payload"
    assert not (ctx["a"] / "f.txt").exists()


def test_sad_e2e_a_cut_never_pasted_removes_nothing(win) -> None:
    from ui.cut_clipboard import cut_clipboard

    ctx = win.test_ctx
    cut_in(ctx["left"], "f.txt", "sub")
    cut_in(ctx["left"], "f.txt")  # a new cut replaces the first
    pump(0.3)
    win._close_pane(ctx["left"])
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    pump(0.3)
    assert cut_clipboard().pending is None
    assert (ctx["a"] / "f.txt").read_text() == "payload"
    assert (ctx["a"] / "sub" / "inner.txt").read_text() == "inner"
    assert not win._transfer_manager._jobs
    press(ctx["right"]._table, Qt.Key.Key_V, CTRL)  # nothing left to paste
    pump(0.3)
    assert not win._transfer_manager._jobs and list(ctx["b"].iterdir()) == []


def test_sad_e2e_a_paste_that_fails_part_way_keeps_the_source(win) -> None:
    from core.transfer_worker import TransferStatus

    ctx = win.test_ctx
    big = os.urandom(3 * 1024 * 1024)
    (ctx["a"] / "big.bin").write_bytes(big)
    ctx["left"].refresh()
    assert wait_for(lambda: row_of(ctx["left"], "big.bin") is not None)
    target = win._add_pane_to_splitter(win._root_splitter, _FailingWriteFS())
    target.navigate(str(ctx["b"]))
    pump()
    cut_in(ctx["left"], "big.bin")
    press(target._table, Qt.Key.Key_V, CTRL)
    settle(win)
    jobs = list(win._transfer_manager._jobs.values())
    assert jobs and all(j.status == TransferStatus.ERROR for j in jobs), [
        (j.status, j.error_message) for j in jobs]
    assert all("injected" in j.error_message for j in jobs)  # the write broke
    assert (ctx["a"] / "big.bin").read_bytes() == big
    assert not (ctx["b"] / "big.bin").exists()


def test_edge_e2e_paste_into_the_folder_it_came_from_is_a_no_op(win) -> None:
    from ui.cut_clipboard import cut_clipboard

    ctx = win.test_ctx
    cut_in(ctx["left"], "f.txt")
    ctx["right"].navigate(str(ctx["a"]))
    pump()
    press(ctx["right"]._table, Qt.Key.Key_V, CTRL)
    pump(0.3)
    settle(win)
    assert (ctx["a"] / "f.txt").read_text() == "payload"
    assert not win._transfer_manager._jobs
    assert cut_clipboard().pending is not None  # can still go elsewhere
    assert ctx["asked"] == []


def test_edge_e2e_a_folder_pasted_into_itself_is_refused(win) -> None:
    from ui.cut_clipboard import cut_clipboard

    ctx = win.test_ctx
    cut_in(ctx["left"], "sub")
    ctx["right"].navigate(str(ctx["a"] / "sub"))
    pump()
    warned: list[str] = []
    with mock.patch.object(ctx["MW"].QMessageBox, "warning",
                           lambda *a, **k: warned.append(str(a[2]))):
        press(ctx["right"]._table, Qt.Key.Key_V, CTRL)
        pump(0.3)
    assert warned and "into itself" in warned[0]
    assert not win._transfer_manager._jobs
    assert (ctx["a"] / "sub" / "inner.txt").read_text() == "inner"
    assert cut_clipboard().pending is not None


def test_edge_e2e_a_name_clash_goes_through_the_conflict_prompt(win) -> None:
    from ui.cut_clipboard import cut_clipboard

    ctx = win.test_ctx
    (ctx["b"] / "f.txt").write_text("older")
    ctx["right"].refresh()
    cut_in(ctx["left"], "f.txt")
    press(ctx["right"]._table, Qt.Key.Key_V, CTRL)
    settle(win)
    assert ctx["asked"] == ["f.txt"]  # the patched prompt answers Cancel
    assert (ctx["b"] / "f.txt").read_text() == "older"
    assert (ctx["a"] / "f.txt").read_text() == "payload"
    assert cut_clipboard().pending is not None  # nothing queued: still pending


def test_edge_e2e_the_production_gate_can_stop_a_paste(win) -> None:
    from ui.cut_clipboard import cut_clipboard

    ctx = win.test_ctx
    asked: list[str] = []

    def refuse(op: str) -> bool:
        asked.append(op)
        return False

    ctx["left"]._production_ok = refuse
    cut_in(ctx["left"], "f.txt")
    press(ctx["right"]._table, Qt.Key.Key_V, CTRL)
    pump(0.3)
    settle(win)
    assert asked and "move" in asked[0]
    assert not win._transfer_manager._jobs
    assert (ctx["a"] / "f.txt").read_text() == "payload"
    assert cut_clipboard().pending is not None
