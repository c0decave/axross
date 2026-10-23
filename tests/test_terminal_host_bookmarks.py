"""Terminal bookmarks on a bare host: no saved connection profile needed.

Operator item 37: "im einfachsten fall terminal auf ip xyz bookmark klicken
und hin verbinden, erweitert auch mit arbeitsverzeichnis in das man will ...
so ähnlich wie quickconnect nur halt eben ein bookmark zu dem host als
terminal/shell."

Before, a terminal bookmark had to name a saved SSH profile
(ui/main_window.py _open_terminal_bookmark, the dialog's connection combo).
Now it can hold host, port, user, an optional key file and an optional
working folder - never a password. A click connects the way Quick Connect
does: the known_hosts question for an unknown host key, the password asked
when no key or agent gets in, the key's passphrase asked when the key is
encrypted - and opens a terminal pane that changes into the folder.
"""

from __future__ import annotations

import json
import os
import socket
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


def _stored() -> list:
    return json.loads(BM._bookmarks_file().read_text(encoding="utf-8"))


def _host_bm(name="box", path="/srv/app", host="10.0.0.5", port=22, username="alice",
             key_file="") -> Bookmark:
    return Bookmark(name, path, kind=KIND_TERMINAL, host=host, port=port, username=username,
                    key_file=key_file, icon_name="terminal")


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    return tmp_path


# --- core: the store -----------------------------------------------------------------


def test_happy_a_host_terminal_bookmark_is_stored_without_profile_or_secret(home) -> None:
    m = BookmarkManager()
    assert m.add(_host_bm(key_file="~/.ssh/id_ed25519"))
    (entry,) = _stored()
    assert (entry["kind"], entry["host"], entry["port"], entry["username"]) == (
        "terminal", "10.0.0.5", 22, "alice")
    assert entry["key_file"] == "~/.ssh/id_ed25519" and entry["path"] == "/srv/app"
    # The address, never "": an older axross turns an empty profile of a terminal
    # bookmark into a local shell, which would run the host's commands here.
    assert entry["profile_name"] == entry["backend_name"] == "alice@10.0.0.5:22"
    assert "password" not in json.dumps(entry).lower()
    (again,) = BookmarkManager().all()
    assert again.is_terminal and again.is_host_terminal
    assert (again.host, again.port, again.username) == ("10.0.0.5", 22, "alice")


def test_happy_bookmarks_of_older_versions_load_and_save_unchanged(home) -> None:
    """A file written before host bookmarks existed keeps its exact shape:
    the host fields are written only for a host bookmark."""
    old = [
        {"name": "dir", "path": "/x", "backend_name": "Local", "profile_name": "",
         "icon_name": "bookmark", "color": "", "search": {}, "created": 1.0, "kind": "folder"},
        {"name": "sh", "path": "/srv", "backend_name": "alpha", "profile_name": "alpha",
         "icon_name": "terminal", "color": "", "search": {}, "created": 2.0, "kind": "terminal"},
    ]
    store = BM._bookmarks_file()
    store.parent.mkdir(parents=True)
    store.write_text(json.dumps(old), encoding="utf-8")
    m = BookmarkManager()
    assert [b.is_host_terminal for b in m.all()] == [False, False]
    m.add(Bookmark("new", "/y"))
    assert _stored()[:2] == old


def test_happy_the_profile_a_click_connects_with(home) -> None:
    from core.bookmarks import host_bookmark_profile, is_host_profile

    bm = _host_bm(port=2222, key_file="~/.ssh/k")
    BM._normalise_kind(bm)
    profile = host_bookmark_profile(bm)
    assert (profile.protocol, profile.host, profile.port, profile.username) == (
        "sftp", "10.0.0.5", 2222, "alice")
    assert (profile.auth_type, profile.key_file) == ("key", "~/.ssh/k")
    assert profile.store_password is False and profile.get_password() is None
    assert profile.proxy_mode == "default"  # the application's proxy setting applies
    assert is_host_profile(profile)
    assert host_bookmark_profile(bm, auth_type="password").auth_type == "password"


def test_sad_damaged_host_fields_load_safely(home) -> None:
    store = BM._bookmarks_file()
    store.parent.mkdir(parents=True)
    store.write_text(json.dumps([
        {"name": "a", "path": "", "kind": "terminal", "host": "h1", "port": "22"},
        {"name": "b", "path": "", "kind": "terminal", "host": "h2", "port": True},
        {"name": "c", "path": "", "kind": "terminal", "host": "h3", "port": 70000},
        {"name": "d", "path": "", "kind": "terminal", "host": ["x"], "username": 5},
        {"name": "e", "path": "/f", "kind": "folder", "host": "h5"},
    ]), encoding="utf-8")
    a, b, c, d, e = BookmarkManager().all()
    assert [x.port for x in (a, b, c)] == [22, 22, 22]
    assert a.is_host_terminal and a.profile_name == a.backend_name == "h1:22"
    # no usable host: an ordinary local-shell terminal bookmark, as before
    assert not d.is_host_terminal and d.profile_name == "local" and d.username == ""
    # a folder bookmark never becomes a host terminal
    assert e.kind == "folder" and not e.is_host_terminal


@pytest.mark.parametrize("field,value,needle", [
    ("host", "bad host", "host"),
    ("host", "evil\nhost", "control"),
    ("host", "-oProxyCommand=x", "host"),
    ("port", 0, "port"),
    ("username", "a\x1bb", "control"),
    ("key_file", "/k\0", "control"),
])
def test_sad_a_host_bookmark_that_cannot_connect_is_named(field, value, needle) -> None:
    from core.bookmarks import host_bookmark_problem

    bm = _host_bm()
    setattr(bm, field, value)
    problem = host_bookmark_problem(bm)
    assert problem and needle in problem.lower()
    assert host_bookmark_problem(_host_bm()) is None


def test_edge_addresses_and_duplicates(home) -> None:
    from core.bookmarks import host_address

    assert host_address("::1", 2222, "root") == "root@[::1]:2222"
    assert host_address("box.lan", 22, "") == "box.lan:22"
    m = BookmarkManager()
    assert m.add(_host_bm(path="/srv"))
    assert not m.add(_host_bm(name="again", path="/srv"))  # same host, same folder
    assert m.add(_host_bm(name="other folder", path="/tmp"))
    assert m.add(_host_bm(name="other user", path="/srv", username="bob"))


def test_edge_a_second_writer_merges_host_bookmarks(home) -> None:
    first = BookmarkManager()
    first.add(Bookmark("dir", "/x"))
    second = BookmarkManager()
    second.add(_host_bm())
    first.add(Bookmark("other", "/y"))
    by_name = {b.name: b for b in BookmarkManager().all()}
    assert set(by_name) == {"dir", "box", "other"}
    assert by_name["box"].is_host_terminal and by_name["box"].username == "alice"


def test_edge_editing_a_host_bookmark_keeps_its_host(home) -> None:
    m = BookmarkManager()
    m.add(_host_bm())
    old = m.all()[0]
    import dataclasses

    m.update_bookmark(old, dataclasses.replace(old, name="renamed", port=2200))
    (entry,) = _stored()
    assert (entry["name"], entry["port"], entry["backend_name"]) == (
        "renamed", 2200, "alice@10.0.0.5:2200")


# --- the main window -------------------------------------------------------------------


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


class _FakeConnections:
    """Stands in for ConnectionManager.connect/get_session/acquire/release:
    records every connect, can raise per attempt and asks the host-key callback."""

    def __init__(self, cm, monkeypatch, *, failures=(), host_key_error=None) -> None:
        self.calls: list[dict] = []
        self.failures = list(failures)
        self.host_key_error = host_key_error
        self.transport = _Transport()
        self.live: dict = {}
        self.released = 0
        monkeypatch.setattr(cm, "connect", self.connect)
        monkeypatch.setattr(cm, "get_session", self.get_session)
        monkeypatch.setattr(cm, "acquire", lambda p: self._key(p) in self.live)
        monkeypatch.setattr(cm, "release", self.release)

    @staticmethod
    def _key(profile):
        return (profile.host, profile.port, profile.username)

    def connect(self, profile, password="", key_passphrase="", on_unknown_host=None):
        self.calls.append({"auth": profile.auth_type, "password": password,
                           "passphrase": key_passphrase, "profile": profile})
        if self.host_key_error is not None:
            if on_unknown_host is None or not on_unknown_host(self.host_key_error):
                raise self.host_key_error
        if self.failures:
            raise self.failures.pop(0)
        session = SimpleNamespace(transport=self.transport, name=profile.name)
        self.live[self._key(profile)] = session
        return session

    def get_session(self, profile):
        return self.live.get(self._key(profile))

    def release(self, profile):
        self.released += 1


@pytest.fixture(scope="module")
def _window():
    from ui.main_window import MainWindow

    win = MainWindow()
    win._reconnect_timer.stop()
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
def win(_window, monkeypatch):
    monkeypatch.delenv("SSH_AUTH_SOCK", raising=False)
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


def _add(win, bookmark: Bookmark) -> None:
    assert win._bookmark_manager.add(bookmark)
    win._rebuild_bookmarks_menu()
    pump()


def _wait(predicate, timeout: float = 10.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        pump(0.02)
        if predicate():
            return True
    return False


def _answers(monkeypatch, *texts):
    """QInputDialog.getText answers, in order; records the prompts."""
    asked: list[str] = []
    queue = list(texts)

    def get_text(_parent, _title, label, *_a, **_kw):
        asked.append(label)
        if not queue:
            return "", False
        value = queue.pop(0)
        return (value, value is not None)

    monkeypatch.setattr("PyQt6.QtWidgets.QInputDialog.getText", get_text)
    return asked


def test_happy_e2e_new_host_terminal_bookmark_from_the_sidebar_menu(win, monkeypatch) -> None:
    from ui.bookmark_edit_dialog import BookmarkEditDialog

    seen = {}

    def fill(dialog):
        combo = dialog._connection_combo
        seen["choices"] = [combo.itemText(i) for i in range(combo.count())]
        combo.setCurrentIndex(dialog.host_choice_index)
        seen["visible"] = not dialog._host_box.isHidden()
        dialog._host_edit.setText("10.0.0.5")
        dialog._port_spin.setValue(2222)
        dialog._user_edit.setText("alice")
        dialog._key_edit.setText("~/.ssh/id_ed25519")
        dialog._path_edit.setText("/srv/app")
        dialog._name_edit.setText("")
        dialog.accept()
        return dialog.result()

    monkeypatch.setattr(BookmarkEditDialog, "exec", fill)
    menu = win._bookmark_sidebar._build_menu(None)
    next(a for a in menu.actions() if a.text().replace("&", "") == "New Terminal Bookmark…").trigger()
    pump()
    assert seen["choices"][:2] == ["Local Shell", "SSH Host (no profile)"] and seen["visible"]
    (entry,) = _stored()
    assert (entry["kind"], entry["host"], entry["port"], entry["username"], entry["path"]) == (
        "terminal", "10.0.0.5", 2222, "alice", "/srv/app")
    assert entry["name"] == "alice@10.0.0.5:2222: /srv/app"
    assert "password" not in json.dumps(entry).lower()
    tip = _sidebar_item(win, entry["name"]).toolTip(0)
    assert "alice@10.0.0.5:2222" in tip and "/srv/app" in tip


def test_happy_e2e_click_asks_the_password_and_opens_a_shell_in_the_folder(
    win, monkeypatch
) -> None:
    fake = _FakeConnections(win._connection_manager, monkeypatch)
    asked = _answers(monkeypatch, "s3cret")
    _add(win, _host_bm("lab box", "/srv/my app"))
    before = list(win._terminal_panes)
    _click_sidebar(win, "lab box")
    assert _wait(lambda: len(win._terminal_panes) == len(before) + 1)
    term = win._terminal_panes[-1]
    assert term.isVisible() and term.session_label == "alice@10.0.0.5:22"
    assert b" cd -- '/srv/my app'\n" in fake.transport.channel.sent
    assert asked == ["Password for alice@10.0.0.5:"]
    (call,) = fake.calls
    assert (call["auth"], call["password"]) == ("password", "s3cret")
    # the window's own connect reference was handed to the pane
    assert fake.released == 1
    # nothing stored: not in the bookmark file, no keyring write
    assert "s3cret" not in BM._bookmarks_file().read_text(encoding="utf-8")
    assert call["profile"].store_password is False
    # the shell's pane is no saved layout entry (no profile to reopen it with)
    assert win._serialize_terminal(term) is None


def test_happy_e2e_the_bookmarks_menu_entry_names_the_host(win, monkeypatch) -> None:
    _add(win, _host_bm("menu box"))
    action = next(a for a in win._bookmarks_menu.actions() if a.text().startswith("menu box"))
    assert action.text() == "menu box  [Terminal: alice@10.0.0.5:22]"


def test_happy_e2e_with_an_agent_no_password_is_asked(win, monkeypatch) -> None:
    monkeypatch.setenv("SSH_AUTH_SOCK", "/run/user/1000/agent.sock")
    fake = _FakeConnections(win._connection_manager, monkeypatch)
    asked = _answers(monkeypatch)
    _add(win, _host_bm("agent box"))
    before = len(win._terminal_panes)
    _click_sidebar(win, "agent box")
    assert _wait(lambda: len(win._terminal_panes) == before + 1)
    assert [c["auth"] for c in fake.calls] == ["agent"] and asked == []


def test_sad_e2e_an_agent_that_is_refused_falls_back_to_the_password(win, monkeypatch) -> None:
    import paramiko

    monkeypatch.setenv("SSH_AUTH_SOCK", "/run/user/1000/agent.sock")
    refused = paramiko.AuthenticationException("All SSH agent keys rejected")
    fake = _FakeConnections(win._connection_manager, monkeypatch, failures=[refused])
    asked = _answers(monkeypatch, "pw")
    _add(win, _host_bm("fallback box"))
    before = len(win._terminal_panes)
    _click_sidebar(win, "fallback box")
    assert _wait(lambda: len(win._terminal_panes) == before + 1)
    assert [(c["auth"], c["password"]) for c in fake.calls] == [("agent", ""), ("password", "pw")]
    assert asked == ["Password for alice@10.0.0.5:"]


def test_sad_e2e_an_encrypted_key_asks_its_passphrase(win, monkeypatch) -> None:
    import paramiko

    fake = _FakeConnections(win._connection_manager, monkeypatch,
                            failures=[paramiko.PasswordRequiredException("encrypted")])
    asked = _answers(monkeypatch, "phrase")
    _add(win, _host_bm("key box", key_file="/keys/id"))
    before = len(win._terminal_panes)
    _click_sidebar(win, "key box")
    assert _wait(lambda: len(win._terminal_panes) == before + 1)
    assert [(c["auth"], c["passphrase"]) for c in fake.calls] == [("key", ""), ("key", "phrase")]
    assert asked == ["Passphrase for the key /keys/id:"]


def test_sad_e2e_an_unknown_host_key_is_asked_and_a_no_opens_nothing(win, monkeypatch) -> None:
    from core.ssh_client import UnknownHostKeyError

    fake = _FakeConnections(win._connection_manager, monkeypatch,
                            host_key_error=UnknownHostKeyError("10.0.0.5", "ssh-ed25519", "AAAA"))
    _answers(monkeypatch, "pw")
    questions: list = []
    monkeypatch.setattr(win, "_confirm_unknown_host", lambda err: questions.append(err) or False)
    _add(win, _host_bm("new host"))
    before = len(win._terminal_panes)
    with mock.patch("ui.main_window.QMessageBox.critical") as critical:
        _click_sidebar(win, "new host")
        assert _wait(lambda: critical.call_count == 1)
    assert len(questions) == 1 and questions[0].host == "10.0.0.5"
    assert len(win._terminal_panes) == before and fake.live == {}


def test_sad_e2e_a_cancelled_password_prompt_connects_nothing(win, monkeypatch) -> None:
    fake = _FakeConnections(win._connection_manager, monkeypatch)
    _answers(monkeypatch, None)
    _add(win, _host_bm("cancel box"))
    before = len(win._terminal_panes)
    _click_sidebar(win, "cancel box")
    pump(0.3)
    assert fake.calls == [] and len(win._terminal_panes) == before


def test_sad_e2e_a_broken_host_is_said_and_nothing_connects(win, monkeypatch) -> None:
    fake = _FakeConnections(win._connection_manager, monkeypatch)
    store = BM._bookmarks_file()
    store.write_text(json.dumps([{"name": "broken", "path": "", "kind": "terminal",
                                  "host": "two words"}]), encoding="utf-8")
    win._bookmark_manager.load()
    win._bookmark_sidebar.rebuild()
    pump()
    with mock.patch("ui.main_window.QMessageBox.warning") as warn:
        _click_sidebar(win, "broken")
    assert warn.call_count == 1 and "two words" in warn.call_args.args[2]
    assert fake.calls == []


def test_edge_e2e_bookmark_this_terminal_on_a_host_shell_makes_a_host_bookmark(
    win, monkeypatch
) -> None:
    from ui.bookmark_edit_dialog import BookmarkEditDialog

    _FakeConnections(win._connection_manager, monkeypatch)
    _answers(monkeypatch, "pw")
    _add(win, _host_bm("src", "/srv/www", port=2200))
    _click_sidebar(win, "src")
    assert _wait(lambda: bool(win._terminal_panes))
    term = win._terminal_panes[-1]
    win._bookmark_manager.remove_node(win._bookmark_manager.all()[0])
    monkeypatch.setattr(BookmarkEditDialog, "exec", lambda d: QDialog.DialogCode.Accepted)
    term._btn_bookmark.click()
    pump()
    (entry,) = _stored()
    assert (entry["host"], entry["port"], entry["username"], entry["path"]) == (
        "10.0.0.5", 2200, "alice", "/srv/www")
    assert entry["profile_name"] == "alice@10.0.0.5:2200"


def test_edge_the_edit_dialog_refuses_an_empty_host(home, monkeypatch) -> None:
    from ui.bookmark_edit_dialog import BookmarkEditDialog

    dialog = BookmarkEditDialog(Bookmark("", "", kind=KIND_TERMINAL, profile_name="local"),
                                new=True)
    try:
        dialog._connection_combo.setCurrentIndex(dialog.host_choice_index)
        dialog._host_edit.setText("")
        with mock.patch("ui.bookmark_edit_dialog.QMessageBox.warning") as warn:
            dialog.accept()
        assert warn.call_count == 1 and dialog.result() != QDialog.DialogCode.Accepted
        # switching back to the local shell hides the host fields again
        dialog._connection_combo.setCurrentIndex(0)
        assert dialog._host_box.isHidden()
        assert not dialog.result_bookmark().is_host_terminal
    finally:
        dialog.deleteLater()


def test_sad_a_host_bookmark_never_reads_as_a_local_shell_in_an_older_version(home) -> None:
    """The rule of the loader before host bookmarks (an empty profile of a
    terminal bookmark is the local shell): applied to what is stored now, it
    must not give "local" - commands meant for the host would run here."""
    m = BookmarkManager()
    m.add(_host_bm())
    (entry,) = _stored()
    old_rule = entry.get("profile_name") or "local"
    assert old_rule not in ("", "local")


def test_sad_e2e_a_refused_key_file_falls_back_to_the_password(win, monkeypatch) -> None:
    import paramiko

    fake = _FakeConnections(win._connection_manager, monkeypatch,
                            failures=[paramiko.AuthenticationException("Authentication failed.")])
    asked = _answers(monkeypatch, "pw")
    _add(win, _host_bm("refused key", key_file="/keys/id"))
    before = len(win._terminal_panes)
    _click_sidebar(win, "refused key")
    assert _wait(lambda: len(win._terminal_panes) == before + 1)
    assert [(c["auth"], c["password"]) for c in fake.calls] == [("key", ""), ("password", "pw")]
    assert asked == ["Password for alice@10.0.0.5:"]


def test_edge_e2e_a_shell_that_does_not_start_gives_the_connection_back(
    win, monkeypatch
) -> None:
    fake = _FakeConnections(win._connection_manager, monkeypatch)
    monkeypatch.setattr(win._connection_manager, "acquire", lambda p: False)

    def refuse():
        raise OSError("channel refused")

    monkeypatch.setattr(fake.transport, "open_session", refuse)
    _answers(monkeypatch, "pw")
    _add(win, _host_bm("no shell"))
    before = len(win._terminal_panes)
    _click_sidebar(win, "no shell")
    assert _wait(lambda: len(win._terminal_panes) == before + 1)
    term = win._terminal_panes[-1]
    assert not term.is_running and not term.holds_session
    assert fake.released == 1  # nothing uses the session: the connect's reference is back


def test_sad_markup_in_a_host_is_not_shown_as_rich_text(home) -> None:
    from ui.bookmark_edit_dialog import BookmarkEditDialog

    dialog = BookmarkEditDialog(Bookmark("", "", kind=KIND_TERMINAL, profile_name="local"),
                                new=True)
    try:
        dialog._connection_combo.setCurrentIndex(dialog.host_choice_index)
        dialog._host_edit.setText("<b>evil</b>")
        with mock.patch("ui.bookmark_edit_dialog.QMessageBox.warning") as warn:
            dialog.accept()
        text = warn.call_args.args[2]
        assert "<b>evil</b>" in text and "<" not in text.splitlines()[0]
    finally:
        dialog.deleteLater()


# --- live: the lab's sshd (tests/docker ssh-alpha, 10.99.0.10) ----------------------------

LAB = ("10.99.0.10", 22)


def _lab_up() -> bool:
    try:
        with socket.create_connection(LAB, timeout=2):
            return True
    except OSError:
        return False


@pytest.mark.skipif(not _lab_up(), reason="the lab's ssh-alpha (10.99.0.10) is not reachable")
def test_happy_e2e_live_a_host_bookmark_reaches_a_real_sshd(win, monkeypatch, tmp_path) -> None:
    """Real network, real paramiko, real known_hosts handling: the first
    click asks about the host key (accepted), the password is asked, the
    shell starts in /tmp; the second click asks no host-key question."""
    known = Path.home() / ".ssh" / "known_hosts"
    assert not known.exists() or "10.99.0.10" not in known.read_text()
    questions: list = []
    monkeypatch.setattr(win, "_confirm_unknown_host", lambda err: questions.append(err) or True)
    _answers(monkeypatch, "alpha123", "alpha123")
    _add(win, _host_bm("alpha", "/tmp", host=LAB[0], username="alpha"))
    _click_sidebar(win, "alpha")
    assert _wait(lambda: bool(win._terminal_panes), timeout=30)
    term = win._terminal_panes[-1]
    term._session.write(b"echo AX_PWD=$(pwd)\n")
    assert _wait(lambda: "AX_PWD=/tmp" in "\n".join(term._terminal.screen.screen_lines()),
                 timeout=15)
    assert len(questions) == 1 and "10.99.0.10" in known.read_text()
    win._close_terminal_pane(term)
    win._connection_manager.disconnect_all()
    _click_sidebar(win, "alpha")
    assert _wait(lambda: bool(win._terminal_panes), timeout=30)
    assert len(questions) == 1  # trusted now: not asked again
