"""The security badge (ui/security_badge.py) wherever a connection shows:
the file pane's header, the workspace tabs, the bookmarks (sidebar,
manager, Quick Connect) and the chat panel's accounts and conversations.
Every level has its own SVG icon; the tooltip says exactly what protects
the connection - never markup from the other side."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from bluez_testkit import wait_until  # noqa: E402
from fake_ircd import FakeIrcd, self_signed  # noqa: E402
from PyQt6.QtWidgets import QApplication, QSplitter, QTabWidget  # noqa: E402

from core import chat as C  # noqa: E402
from core import chat_irc as I  # noqa: E402
from core import conn_security as CS  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from core.profiles import ConnectionProfile  # noqa: E402


@pytest.fixture(autouse=True)
def _app():
    app = QApplication.instance() or QApplication([])
    C._SESSION_SECRETS.clear()
    yield app
    C._SESSION_SECRETS.clear()


def _painted(qicon) -> int:
    image = qicon.pixmap(32, 32).toImage()
    return sum(1 for x in range(32) for y in range(32) if image.pixelColor(x, y).alpha() > 100)


class RemoteFS(LocalFS):
    """A local folder dressed as a connection of *protocol* (no network)."""

    def __init__(self, protocol: str, label: str = "remote", **fields) -> None:
        super().__init__()
        self._axross_profile = ConnectionProfile(name=label, protocol=protocol, host="h.example", **fields)
        self._label = label

    @property
    def name(self) -> str:
        return self._label


# --- the icons and the tooltip ----------------------------------------------------------------

def test_happy_every_level_has_its_own_coloured_icon():
    from ui import icon_provider as IP
    from ui.security_badge import icon_name

    names = [icon_name(level) for level in CS.ORDER]
    assert len(set(names)) == len(CS.ORDER) and all(IP.has_icon(n) for n in names)
    assert len({IP.ICONS[n] for n in names}) == len(names)          # no two share a drawing
    for name in names:
        assert IP._ICON_COLORS.get(name) and _painted(IP.icon(name)) > 20, name
        assert name not in IP.bookmark_icon_names()                   # not a bookmark choice


def test_sad_text_from_the_other_side_is_escaped_in_the_tooltip():
    from ui.security_badge import SecurityBadge, tooltip_html

    hostile = CS.SecurityInfo(CS.LEVEL_ENCRYPTED, "SFTP over SSH, encrypted", True,
                              ("Server: SSH-2.0-<img src=http://evil/x>",))
    tip = tooltip_html(hostile)
    assert "<img" not in tip and "&lt;img" in tip
    assert "negotiated on the live connection" in tip
    badge = SecurityBadge()
    badge.set_info(hostile)
    assert badge.toolTip() == tip and badge.accessibleName() == "Encrypted"


def test_edge_no_info_shows_unknown_and_local_says_no_network():
    from ui.security_badge import SecurityBadge, tooltip_lines

    badge = SecurityBadge()
    badge.set_info(None)
    assert badge.info is CS.UNKNOWN and "configured" in badge.toolTip()
    assert not any("negotiated" in line or "configured" in line for line in tooltip_lines(CS.LOCAL))


def test_happy_a_badge_on_a_bookmark_icon_keeps_the_icon():
    from ui.icon_provider import icon
    from ui.security_badge import with_badge

    base = icon("bookmark")
    badged = with_badge(base, CS.SecurityInfo(CS.LEVEL_CLEARTEXT, "x"))
    assert badged.pixmap(32, 32).toImage() != base.pixmap(32, 32).toImage()
    assert _painted(badged) >= _painted(base)


# --- the file pane ------------------------------------------------------------------------------

def test_happy_the_pane_header_shows_how_its_connection_is_protected(tmp_path):
    from ui.file_pane import FilePaneWidget

    pane = FilePaneWidget(LocalFS())
    try:
        assert pane.security_info is CS.LOCAL
        changes = []
        pane.security_changed.connect(lambda: changes.append(pane.security_info))
        pane.set_backend(RemoteFS("ftp", "anon@ftp (FTP)"), str(tmp_path))
        assert changes and changes[-1].level == CS.LEVEL_CLEARTEXT
        assert "anyone on the network" in pane._security_badge.toolTip()
        pane.set_backend(RemoteFS("sftp", "me@host (SFTP)"), str(tmp_path))
        assert pane._security_badge.info.level == CS.LEVEL_ENCRYPTED
    finally:
        pane.deleteLater()


def test_happy_a_live_answer_replaces_the_configured_one():
    from ui.file_pane import FilePaneWidget

    backend = RemoteFS("smb", "\\\\srv\\data (SMB)")
    pane = FilePaneWidget(backend)
    try:
        assert pane.security_info.level == CS.LEVEL_SIGNED and not pane.security_info.negotiated
        backend.security_info = lambda: CS.SecurityInfo(CS.LEVEL_ENCRYPTED, "SMB 3.1.1 with encryption", True)
        pane.refresh_security()
        assert pane._security_badge.info.summary == "SMB 3.1.1 with encryption"
        assert "negotiated" in pane._security_badge.toolTip()
    finally:
        pane.deleteLater()


# --- the workspace tabs --------------------------------------------------------------------------

def test_happy_a_tab_shows_its_weakest_connection():
    from ui.security_badge import refresh_workspace_tabs

    tabs = QTabWidget()
    roots = [QSplitter(), QSplitter(), QSplitter()]
    for n, root in enumerate(roots):
        tabs.addTab(root, f"ws{n}")
    panes = {
        0: [SimpleNamespace(security_info=CS.LOCAL, backend=SimpleNamespace(name="Local")),
            SimpleNamespace(security_info=CS.SecurityInfo(CS.LEVEL_CLEARTEXT, "FTP - cleartext"),
                            backend=SimpleNamespace(name="<b>ftp</b>"))],
        1: [SimpleNamespace(security_info=CS.SecurityInfo(CS.LEVEL_ENCRYPTED, "SSH"),
                            backend=SimpleNamespace(name="ssh"))],
        2: [],
    }
    workspaces = [SimpleNamespace(root=r, n=n) for n, r in enumerate(roots)]
    window = SimpleNamespace(_workspace_tabs=tabs, _workspaces=workspaces,
                             _widgets_of=lambda ws: (panes[ws.n], [], []))
    refresh_workspace_tabs(window)
    assert "Cleartext" in tabs.tabToolTip(0) and "&lt;b&gt;ftp&lt;/b&gt;" in tabs.tabToolTip(0)
    assert not tabs.tabIcon(0).isNull() and "Encrypted" in tabs.tabToolTip(1)
    assert tabs.tabIcon(2).isNull() and tabs.tabToolTip(2) == ""


# --- bookmarks ----------------------------------------------------------------------------------

@pytest.fixture
def bookmarks(tmp_path, monkeypatch):
    import core.bookmarks as BM

    monkeypatch.setattr(BM, "BOOKMARKS_FILE", tmp_path / "bookmarks.json")
    manager = BM.BookmarkManager()
    manager.add(BM.Bookmark("ftp box", "/pub", backend_name="anon@ftp (FTP)", profile_name="ftpbox"))
    manager.add(BM.Bookmark("home", "/home"))
    manager.add(BM.Bookmark("gone", "/x", backend_name="old (SFTP)", profile_name="deleted"))
    profiles = {"ftpbox": ConnectionProfile(name="ftpbox", protocol="ftp", host="ftp.example")}
    return manager, profiles.get


def _items(tree):
    out = {}
    for i in range(tree.topLevelItemCount()):
        item = tree.topLevelItem(i)
        out[item.text(0)] = item
    return out


def test_happy_the_sidebar_badges_remote_bookmarks_and_says_why(bookmarks):
    from ui.bookmark_sidebar import BookmarkSidebar
    from ui.icon_provider import icon

    manager, lookup = bookmarks
    side = BookmarkSidebar(manager, profile_lookup=lookup)
    items = _items(side._tree)
    ftp = items["ftp box"]
    assert "Cleartext" in ftp.toolTip(0) and "configured" in ftp.toolTip(0)
    assert ftp.icon(0).pixmap(32, 32).toImage() != icon("bookmark").pixmap(32, 32).toImage()
    home = items["home"]
    assert "Local" in home.toolTip(0)
    assert home.icon(0).pixmap(32, 32).toImage() == icon("bookmark").pixmap(32, 32).toImage()
    assert "not known" in items["gone"].toolTip(0)


def test_happy_the_manager_shows_the_badge_in_the_connection_column(bookmarks):
    from ui.bookmark_manager_dialog import COL_CONNECTION, BookmarkManagerDialog

    manager, lookup = bookmarks
    dialog = BookmarkManagerDialog(manager, profile_lookup=lookup)
    try:
        ftp = _items(dialog._tree)["ftp box"]
        assert not ftp.icon(COL_CONNECTION).isNull()
        assert "Cleartext" in ftp.toolTip(COL_CONNECTION)
    finally:
        dialog.deleteLater()


def test_edge_without_a_profile_lookup_the_sidebar_still_builds(bookmarks):
    from ui.bookmark_sidebar import BookmarkSidebar

    manager, _lookup = bookmarks
    side = BookmarkSidebar(manager)
    assert "not known" in _items(side._tree)["ftp box"].toolTip(0)


def test_happy_quick_connect_entries_carry_their_badge():
    from ui.quick_connect_menu import QuickConnectMenu

    menu = QuickConnectMenu("Quick", on_connect=lambda p: None, on_background=lambda p: None,
                            on_edit=lambda p: None)
    action = menu.add_profile("box", ConnectionProfile(name="box", protocol="ftps", host="h"))
    assert not action.icon().isNull() and "certificate verified" in action.toolTip()


# --- chat -----------------------------------------------------------------------------------------

def test_happy_a_conversation_says_whether_it_is_end_to_end():
    account = C.Account(protocol="irc", name="t", settings={"server": "irc.example", "nick": "a"})
    client = C.ChatClient(account)
    try:
        client.e2e_scheme = "Olm/Megolm"
        client._add_conversation("!e2e", C.CONV_CHANNEL, "Secret", encryption=C.ENC_E2E)
        client._add_conversation("!half", C.CONV_CHANNEL, "Mixed", encryption=C.ENC_E2E_UNTRUSTED)
        client._add_conversation("!plain", C.CONV_CHANNEL, "Public", encryption=C.ENC_TRANSPORT)
        e2e = client.conversation_security("!e2e")
        assert e2e.level == CS.LEVEL_E2E and "(Olm/Megolm)" in e2e.summary
        assert client.conversation_security("!half").level == CS.LEVEL_E2E_UNVERIFIED
        plain = client.conversation_security("!plain")
        assert plain.level == CS.LEVEL_TLS and plain.summary.startswith("Not end-to-end encrypted")
    finally:
        client.shutdown()


def test_sad_an_irc_account_without_tls_is_cleartext_everywhere(tmp_path):
    from ui.chat_panel import ChatPanel

    path = tmp_path / "chat.json"
    account = C.Account(protocol="irc", name="plain", settings={
        "server": "irc.example", "port": 6667, "tls": I.TLS_OFF, "nick": "a", "proxy": "none"})
    C.save_accounts([account], path)
    panel = ChatPanel(I.PROTOCOL, accounts_path=path)
    try:
        item = panel._account_items[account.account_id]
        assert "Cleartext" in item.toolTip(0) and "password too" in item.toolTip(0)
    finally:
        panel.shutdown()
        panel.deleteLater()


def test_happy_a_tls_irc_link_shows_the_negotiated_version_and_the_pin(tmp_path):
    from ui.chat_panel import ChatPanel

    cert, key, der = self_signed(tmp_path)
    server = FakeIrcd(tls=(cert, key), caps=()).start()
    path = tmp_path / "chat.json"
    account = C.Account(protocol="irc", name="tls", settings={
        "server": "127.0.0.1", "port": server.port, "tls": I.TLS_PINNED,
        "fingerprint": I.fingerprint_of(der), "nick": "alice", "proxy": "none", "autojoin": ["#c"]})
    C.save_accounts([account], path)
    panel = ChatPanel(I.PROTOCOL, accounts_path=path)
    try:
        client = panel.clients[account.account_id]
        assert client.link_security().negotiated is False          # before: as configured
        client.connect_account()
        assert wait_until(lambda: client.state == C.STATE_ONLINE and client.conversation("#c"), 10)
        info = client.link_security()
        assert info.level == CS.LEVEL_TLS and info.negotiated
        assert info.summary.startswith("IRC: TLS 1.") and "pinned" in info.summary
        assert any(d.startswith("Certificate SHA-256") for d in info.details)
        QApplication.processEvents()
        assert "negotiated" in panel._account_items[account.account_id].toolTip(0)
        view = panel.show_conversation(account.account_id, "#c")
        assert "Not end-to-end encrypted" in view.security.toolTip()
        client.disconnect_account()
        assert client.link_security().negotiated is False          # after: as configured again
    finally:
        panel.shutdown()
        panel.deleteLater()
        server.stop()
