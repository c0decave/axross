"""Terminal bookmarks: a sidebar entry that opens a shell on a host.

Operator punch list item 40: "wir brauchen nicht nur filesystem dir
bookmarks und file bookmarks, sondern auch terminal bookmarks, im
einfachsten fall terminal auf ip xyz bookmark klicken und hin verbinden,
erweitert auch mit arbeitsverzeichnis in das man will, soll ebenfalls links
in der bookmark liste vorhanden sein. so ähnlich wie quickconnect nur halt
eben ein bookmark zu dem host als terminal/shell."

A bookmark of kind ``terminal`` names a connection profile (or ``local``)
and an optional working folder - never a credential. Activating it opens a
terminal pane on that host, in that folder. It is made from a terminal pane
("Bookmark this Terminal") or from the sidebar ("New Terminal Bookmark…").
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QPoint, Qt  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication, QDialog, QTreeWidgetItemIterator  # noqa: E402

import core.bookmarks as BM  # noqa: E402
from core.bookmarks import KIND_TERMINAL, Bookmark, BookmarkManager  # noqa: E402

APP = QApplication.instance() or QApplication([])


def pump(seconds: float = 0.05) -> None:
    end = time.time() + seconds
    while time.time() < end:
        APP.processEvents()
        time.sleep(0.01)


def _bookmarks_file() -> Path:
    return BM._bookmarks_file()


def _stored() -> list:
    return json.loads(_bookmarks_file().read_text(encoding="utf-8"))


# --- core: the store ---------------------------------------------------------


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    return tmp_path


def test_happy_a_terminal_bookmark_is_stored_with_its_kind_and_no_secret(home) -> None:
    m = BookmarkManager()
    assert m.add(
        Bookmark("box", "/srv/app", backend_name="alpha", profile_name="alpha", kind=KIND_TERMINAL)
    )
    (entry,) = _stored()
    assert entry["kind"] == "terminal"
    assert entry["profile_name"] == "alpha" and entry["path"] == "/srv/app"
    assert set(entry) == {
        "name", "path", "backend_name", "profile_name", "icon_name", "color", "created", "kind",
        "search",  # a Smart Folder's saved search (empty here); never a secret
    }
    assert entry["search"] == {}
    assert BookmarkManager().all()[0].kind == KIND_TERMINAL


def test_edge_a_folder_and_a_terminal_bookmark_on_the_same_path_are_both_kept(home) -> None:
    m = BookmarkManager()
    assert m.add(Bookmark("dir", str(home)))
    assert m.add(Bookmark("sh", str(home), profile_name="local", kind=KIND_TERMINAL))
    assert not m.add(Bookmark("sh2", str(home), profile_name="local", kind=KIND_TERMINAL))
    assert [b.kind for b in BookmarkManager().all()] == ["folder", "terminal"]
    assert m.find(str(home), "Local").kind == "folder"
    assert m.find(str(home), "Local", KIND_TERMINAL).name == "sh"


def test_edge_a_second_writer_keeps_both_kinds_apart(home) -> None:
    first = BookmarkManager()
    first.add(Bookmark("dir", "/x"))
    second = BookmarkManager()
    second.add(Bookmark("sh", "/x", profile_name="local", kind=KIND_TERMINAL))
    first.add(Bookmark("other", "/y"))  # merges what the second writer added
    assert sorted((b.name, b.kind) for b in BookmarkManager().all()) == [
        ("dir", "folder"), ("other", "folder"), ("sh", "terminal")
    ]


def test_sad_an_unknown_kind_and_a_terminal_without_profile_load_safely(home) -> None:
    store = home / ".config" / "axross" / "bookmarks.json"
    store.parent.mkdir(parents=True)
    store.write_text(
        json.dumps(
            [
                {"name": "odd", "path": "/odd", "kind": "<script>"},
                {"name": "sh", "path": "", "kind": "terminal"},
            ]
        ),
        encoding="utf-8",
    )
    odd, sh = BookmarkManager().all()
    assert odd.kind == "folder"
    assert (sh.kind, sh.profile_name, sh.path) == ("terminal", "local", "")


# --- the terminal pane: a remote folder reaches the shell ---------------------


class _Channel:
    def __init__(self) -> None:
        self.sent: list[bytes] = []
        self.closed = False

    def get_pty(self, **_kw) -> None:
        pass

    def invoke_shell(self) -> None:
        pass

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)

    def recv_ready(self) -> bool:
        return False

    def resize_pty(self, **_kw) -> None:
        pass

    def close(self) -> None:
        self.closed = True


class _Transport:
    def __init__(self) -> None:
        self.channel = _Channel()

    def is_active(self) -> bool:
        return True

    def open_session(self) -> _Channel:
        return self.channel


def test_edge_a_remote_terminal_pane_cds_into_its_folder() -> None:
    from ui.terminal_pane import TerminalPaneWidget

    transport = _Transport()
    pane = TerminalPaneWidget(transport=transport, label="box", cwd="/srv/my app")
    try:
        assert b" cd -- '/srv/my app'\n" in transport.channel.sent
    finally:
        pane.shutdown()
        pane.deleteLater()


# --- the main window ----------------------------------------------------------


@pytest.fixture(scope="module")
def _window():
    from core.profiles import ConnectionProfile
    from ui.main_window import MainWindow

    win = MainWindow()
    win._reconnect_timer.stop()
    win._profile_manager.add(
        ConnectionProfile(name="alpha", protocol="sftp", host="alpha.lab", username="u")
    )
    win._profile_manager.add(
        ConnectionProfile(name="share", protocol="smb", host="nas.lab", username="u")
    )
    win.resize(1000, 650)
    win.show()
    win._bookmark_sidebar.show()
    pump()
    yield win
    for term in list(win._terminal_panes):
        win._close_terminal_pane(term)
    win.close()
    win.deleteLater()
    pump()


@pytest.fixture
def win(_window):
    mgr = _window._bookmark_manager
    mgr._root.clear()
    mgr.save()
    _window._bookmark_sidebar.rebuild()
    for term in list(_window._terminal_panes):
        _window._close_terminal_pane(term)
    pump()
    yield _window
    for term in list(_window._terminal_panes):
        _window._close_terminal_pane(term)
    pump()


def _sidebar_item(win, name):
    it = QTreeWidgetItemIterator(win._bookmark_sidebar._tree)
    while it.value():
        if it.value().text(0) == name:
            return it.value()
        it += 1
    raise AssertionError(f"no sidebar entry {name!r}")


def _click_sidebar(win, name) -> None:
    tree = win._bookmark_sidebar._tree
    rect = tree.visualItemRect(_sidebar_item(win, name))
    QTest.mouseClick(tree.viewport(), Qt.MouseButton.LeftButton, pos=rect.center() + QPoint(20, 0))
    pump()


def _wait_cwd(term, expected: str, timeout: float = 15.0) -> str | None:
    end = time.time() + timeout
    cwd = None
    while time.time() < end:
        pump(0.05)
        cwd = term.working_directory()
        if cwd and os.path.realpath(cwd) == os.path.realpath(expected) and term._session._pid:
            return cwd
    return cwd


def _add(win, bookmark: Bookmark) -> None:
    assert win._bookmark_manager.add(bookmark)
    win._rebuild_bookmarks_menu()
    pump()


def test_happy_e2e_clicking_a_local_terminal_bookmark_opens_a_shell_in_its_folder(
    win, tmp_path
) -> None:
    folder = tmp_path / "work dir"
    folder.mkdir()
    _add(win, Bookmark("Here", str(folder), profile_name="local", kind=KIND_TERMINAL,
                       icon_name="terminal"))
    before = list(win._terminal_panes)
    _click_sidebar(win, "Here")
    new = [t for t in win._terminal_panes if t not in before]
    assert len(new) == 1
    term = new[0]
    assert term.is_local and term.isVisible()
    # the shell process itself runs in the folder (its /proc cwd)
    assert os.path.realpath(_wait_cwd(term, str(folder)) or "") == os.path.realpath(folder)


def test_happy_e2e_the_bookmarks_menu_entry_opens_the_terminal_too(win, tmp_path) -> None:
    _add(win, Bookmark("Menu shell", str(tmp_path), profile_name="local", kind=KIND_TERMINAL))
    action = next(a for a in win._bookmarks_menu.actions() if a.text().startswith("Menu shell"))
    assert action.text() == "Menu shell  [Terminal: Local Shell]"
    before = len(win._terminal_panes)
    action.trigger()
    pump()
    assert len(win._terminal_panes) == before + 1


def test_happy_e2e_new_terminal_bookmark_from_the_sidebar_menu(win, monkeypatch) -> None:
    from ui.bookmark_edit_dialog import BookmarkEditDialog

    seen = {}

    def fill(dialog):
        combo = dialog._connection_combo
        seen["choices"] = [combo.itemText(i) for i in range(combo.count())]
        combo.setCurrentIndex(combo.findData("alpha"))
        dialog._name_edit.setText("alpha shell")
        dialog._path_edit.setText("/srv/app")
        return QDialog.DialogCode.Accepted

    monkeypatch.setattr(BookmarkEditDialog, "exec", fill)
    side = win._bookmark_sidebar
    menu = side._build_menu(None)
    label = "New Terminal Bookmark…"
    next(a for a in menu.actions() if a.text().replace("&", "") == label).trigger()
    pump()
    # Local Shell, a bare SSH host (test_terminal_host_bookmarks.py), plus the
    # shell-capable profiles only (no SMB share)
    assert seen["choices"] == ["Local Shell", "SSH Host (no profile)", "alpha"]
    (entry,) = _stored()
    assert (entry["kind"], entry["profile_name"], entry["path"], entry["name"]) == (
        "terminal", "alpha", "/srv/app", "alpha shell"
    )
    assert entry["icon_name"] == "terminal"
    assert "password" not in json.dumps(entry).lower()
    _sidebar_item(win, "alpha shell")  # shown in the sidebar


def test_happy_e2e_bookmark_this_terminal_from_the_terminal_pane(
    win, tmp_path, monkeypatch
) -> None:
    from ui.bookmark_edit_dialog import BookmarkEditDialog

    _add(win, Bookmark("Start", str(tmp_path), profile_name="local", kind=KIND_TERMINAL))
    _click_sidebar(win, "Start")
    term = win._terminal_panes[-1]
    assert _wait_cwd(term, str(tmp_path))
    win._bookmark_manager.remove_node(win._bookmark_manager.all()[0])
    monkeypatch.setattr(BookmarkEditDialog, "exec", lambda d: QDialog.DialogCode.Accepted)
    term._btn_bookmark.click()
    pump()
    (entry,) = _stored()
    assert (entry["kind"], entry["profile_name"]) == ("terminal", "local")
    assert os.path.realpath(entry["path"]) == os.path.realpath(tmp_path)


def test_edge_e2e_a_profile_terminal_bookmark_connects_and_enters_its_folder(
    win, monkeypatch
) -> None:
    transport = _Transport()
    cm = win._connection_manager
    monkeypatch.setattr(cm, "get_session", lambda p: SimpleNamespace(transport=transport))
    monkeypatch.setattr(cm, "acquire", lambda p: True)
    monkeypatch.setattr(cm, "release", lambda p: None)
    _add(win, Bookmark("alpha app", "/srv/app", backend_name="alpha", profile_name="alpha",
                       kind=KIND_TERMINAL))
    _click_sidebar(win, "alpha app")
    term = win._terminal_panes[-1]
    assert term.profile is not None and term.profile.name == "alpha"
    assert b" cd -- /srv/app\n" in transport.channel.sent


# --- sad -----------------------------------------------------------------------


def test_sad_a_missing_profile_says_so_and_opens_nothing(win) -> None:
    _add(win, Bookmark("gone", "/srv", backend_name="ghost", profile_name="ghost",
                       kind=KIND_TERMINAL))
    before = len(win._terminal_panes)
    with mock.patch("ui.main_window.QMessageBox.warning") as warn:
        _click_sidebar(win, "gone")
    assert warn.call_count == 1 and "ghost" in warn.call_args.args[2]
    assert len(win._terminal_panes) == before


def test_sad_a_profile_without_a_shell_says_so_and_opens_nothing(win) -> None:
    _add(win, Bookmark("nas", "", backend_name="share", profile_name="share", kind=KIND_TERMINAL))
    before = len(win._terminal_panes)
    with mock.patch("ui.main_window.QMessageBox.warning") as warn:
        _click_sidebar(win, "nas")
    assert warn.call_count == 1 and "share" in warn.call_args.args[2]
    assert len(win._terminal_panes) == before


def test_sad_a_missing_local_folder_says_so_and_opens_nothing(win, tmp_path) -> None:
    gone = tmp_path / "gone"
    _add(win, Bookmark("nowhere", str(gone), profile_name="local", kind=KIND_TERMINAL))
    before = len(win._terminal_panes)
    with mock.patch("ui.main_window.QMessageBox.warning") as warn:
        _click_sidebar(win, "nowhere")
    assert warn.call_count == 1 and str(gone) in warn.call_args.args[2]
    assert len(win._terminal_panes) == before


def test_sad_a_terminal_without_a_profile_cannot_be_bookmarked(win, monkeypatch) -> None:
    from ui.terminal_pane import TerminalPaneWidget

    term = TerminalPaneWidget(transport=_Transport(), label="SSH: adhoc")
    try:
        with mock.patch("ui.main_window.QMessageBox.information") as info:
            win._bookmark_terminal(term)
        assert info.call_count == 1
        assert _stored() == []
    finally:
        term.shutdown()
        term.deleteLater()


# --- edge ------------------------------------------------------------------------


def test_edge_files_dropped_onto_a_terminal_bookmark_are_not_transferred(win, tmp_path) -> None:
    from PyQt6.QtCore import QEvent, QMimeData
    from PyQt6.QtGui import QDragMoveEvent

    from ui.file_pane import TRANSFER_MIME_TYPE

    _add(win, Bookmark("sh", str(tmp_path), profile_name="local", kind=KIND_TERMINAL))
    tree = win._bookmark_sidebar._tree
    mime = QMimeData()
    payload = {"paths": [str(tmp_path / "f.txt")], "dirs": [], "source_pane_id": "1"}
    mime.setData(TRANSFER_MIME_TYPE, json.dumps(payload).encode())
    with mock.patch("ui.bookmark_sidebar.decode_transfer_payload", return_value=payload):
        event = QDragMoveEvent(
            tree.visualItemRect(_sidebar_item(win, "sh")).center(),
            Qt.DropAction.MoveAction,
            mime,
            Qt.MouseButton.LeftButton,
            Qt.KeyboardModifier.NoModifier,
            QEvent.Type.DragMove,
        )
        assert tree._external_drop(event) is None


def test_edge_the_sidebar_shows_a_terminal_entry_with_its_host_in_the_tooltip(win) -> None:
    _add(win, Bookmark("t", "/srv", backend_name="alpha", profile_name="alpha",
                       kind=KIND_TERMINAL, icon_name="terminal"))
    tip = _sidebar_item(win, "t").toolTip(0)
    assert "Terminal" in tip and "alpha" in tip and "/srv" in tip


def test_edge_the_main_window_refuses_a_transfer_onto_a_terminal_bookmark(win, monkeypatch) -> None:
    requested = []
    monkeypatch.setattr(win, "_request_transfer", lambda *a, **kw: requested.append(a))
    term_bm = Bookmark("sh", "/tmp", profile_name="local", kind=KIND_TERMINAL)
    pane_id = str(id(win._active_pane))
    win._on_bookmark_transfer_drop(["/etc/hostname"], pane_id, term_bm, True)
    pump()
    assert requested == []
    assert "terminal" in win.statusBar().currentMessage().lower()


# --- round-2 verification: terminal bookmarks beside Smart Folders ------------------


def _smart(name: str) -> Bookmark:
    from core import file_search as FS
    from core.search_federation import SearchQuery

    search = FS.saved_search_to_dict(
        SearchQuery(name="*.iso"),
        [{"backend_name": "Local", "profile_name": "", "path": "/home/u"}],
        use_index=False,
    )
    return BM.new_smart_folder(name, search)


def test_happy_e2e_folder_smart_folder_and_terminal_bookmarks_work_side_by_side(
    win, tmp_path, monkeypatch
) -> None:
    """The merge put the Smart Folder (``search``) and the terminal kind on
    one Bookmark: each click still reaches its own handler, and moving,
    sorting and reloading keep both."""
    folder = tmp_path / "plain"
    folder.mkdir()
    runs: list[str] = []
    monkeypatch.setattr(win, "_run_smart_folder", lambda b: runs.append(b.name))
    _add(win, Bookmark("C plain", str(folder)))
    _add(win, _smart("B smart"))
    _add(win, Bookmark("A shell", str(tmp_path), profile_name="local", kind=KIND_TERMINAL))

    before = list(win._terminal_panes)
    _click_sidebar(win, "B smart")
    assert runs == ["B smart"] and win._terminal_panes == before
    _click_sidebar(win, "A shell")
    assert len(win._terminal_panes) == len(before) + 1 and runs == ["B smart"]
    _click_sidebar(win, "C plain")
    assert runs == ["B smart"]
    assert _wait_for_path(win, folder)

    side = win._bookmark_sidebar
    group = win._bookmark_manager.add_group("G")
    side.rebuild()
    nodes = list(win._bookmark_manager.all())
    side._move_nodes(nodes, group)
    side._sort(group, "name", False)
    assert [b.name for b in group.children] == ["A shell", "B smart", "C plain"]

    again = BookmarkManager()
    by_name = {b.name: b for b in again.all()}
    assert by_name["A shell"].is_terminal and not by_name["A shell"].is_smart_folder
    assert by_name["B smart"].is_smart_folder and not by_name["B smart"].is_terminal
    assert by_name["B smart"].search == _smart("x").search
    assert not by_name["C plain"].is_terminal and not by_name["C plain"].is_smart_folder


def _wait_for_path(win, folder, timeout: float = 10.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        pump(0.05)
        if os.path.realpath(win._active_pane.current_path) == os.path.realpath(folder):
            return True
    return False


def test_edge_the_edit_dialog_keeps_each_kind_its_own_fields(home) -> None:
    """Editing a Smart Folder keeps its search and folder kind; editing a
    terminal bookmark keeps its kind and gets no search."""
    from ui.bookmark_edit_dialog import BookmarkEditDialog

    smart = _smart("S")
    dialog = BookmarkEditDialog(smart)
    try:
        dialog._name_edit.setText("S2")
        out = dialog.result_bookmark()
    finally:
        dialog.deleteLater()
    assert (out.name, out.kind, out.search, out.path) == ("S2", "folder", smart.search, smart.path)
    term = Bookmark("T", "/srv", profile_name="alpha", backend_name="alpha", kind=KIND_TERMINAL)
    dialog = BookmarkEditDialog(term, terminal_profiles=["alpha"])
    try:
        dialog._path_edit.setText("/srv/www")
        out = dialog.result_bookmark()
    finally:
        dialog.deleteLater()
    assert (out.kind, out.search, out.path, out.profile_name) == (
        KIND_TERMINAL, {}, "/srv/www", "alpha")


def test_sad_an_ssh_profile_named_like_the_local_shell_is_never_offered_as_local(
    win, monkeypatch
) -> None:
    """``local`` is the profile name a terminal bookmark keeps for a local
    shell. An SSH profile called "local" would be stored the same way and
    open a shell on this machine instead of the host - commands meant for
    the server would run here. It is not offered, and Bookmark this
    Terminal on it says why instead of storing a local shell."""
    from core.profiles import ConnectionProfile
    from ui.terminal_pane import TerminalPaneWidget

    win._profile_manager.add(
        ConnectionProfile(name="local", protocol="sftp", host="far.lab", username="u")
    )
    try:
        assert "local" not in win._terminal_profile_names()
        assert "alpha" in win._terminal_profile_names()
        term = TerminalPaneWidget(transport=_Transport(), label="local",
                                  profile=win._profile_manager.get("local"))
        try:
            with mock.patch("ui.main_window.QMessageBox.information") as info:
                win._bookmark_terminal(term)
            assert info.call_count == 1 and "local" in info.call_args.args[2]
            assert _stored() == []
        finally:
            term.shutdown()
            term.deleteLater()
    finally:
        win._profile_manager.remove("local")


def test_edge_e2e_a_local_working_folder_typed_with_a_tilde_opens_there(
    win, tmp_path, monkeypatch
) -> None:
    """``~/work`` is a folder in the home folder, not a missing folder."""
    home = tmp_path / "home"
    (home / "work").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    _add(win, Bookmark("Tilde", "~/work", profile_name="local", kind=KIND_TERMINAL))
    before = list(win._terminal_panes)
    with mock.patch("ui.main_window.QMessageBox.warning") as warn:
        _click_sidebar(win, "Tilde")
    assert warn.call_count == 0
    (term,) = [t for t in win._terminal_panes if t not in before]
    assert os.path.realpath(_wait_cwd(term, str(home / "work")) or "") == os.path.realpath(
        home / "work"
    )


def _renders_as_rich_text(text: str) -> bool:
    """What QMessageBox does with *text* (Qt.TextFormat.AutoText): compared
    by layout with the plain and the rich rendering."""
    from PyQt6.QtCore import Qt
    from PyQt6.QtWidgets import QLabel

    auto, plain, rich = QLabel(text), QLabel(text), QLabel(text)
    auto.setTextFormat(Qt.TextFormat.AutoText)
    plain.setTextFormat(Qt.TextFormat.PlainText)
    rich.setTextFormat(Qt.TextFormat.RichText)
    return auto.sizeHint() == rich.sizeHint() and auto.sizeHint() != plain.sizeHint()


def test_sad_markup_in_a_name_is_shown_literally(home) -> None:
    """Verification round: profile and bookmark names went into the first
    line of a message box, where Qt renders markup."""
    assert _renders_as_rich_text("Delete '<b>evil-name-here</b>'?")  # the control
    from ui.main_window import MainWindow

    with mock.patch("ui.main_window.QMessageBox.warning") as warn:
        MainWindow._open_terminal_bookmark(
            mock.MagicMock(_profile_manager=mock.MagicMock(get=lambda n: None)),
            Bookmark("<b>evil-name-here</b>", "", backend_name="x", profile_name="<i>p</i>",
                     kind=KIND_TERMINAL))
    text = warn.call_args.args[2]
    assert "<b>evil-name-here</b>" in text and not _renders_as_rich_text(text)


def test_edge_control_characters_in_the_folder_are_said(home) -> None:
    from core.bookmarks import LOCAL_SHELL
    from ui.main_window import MainWindow

    with mock.patch("ui.main_window.QMessageBox.warning") as warn:
        result = MainWindow._open_terminal_bookmark(
            mock.MagicMock(), Bookmark("b", "/srv/x\nrm -rf", backend_name="Local",
                                       profile_name=LOCAL_SHELL, kind=KIND_TERMINAL))
    assert result is None and "control characters" in warn.call_args.args[2]
