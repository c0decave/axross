"""The public channel / room list of the chat panel (ui/chat_rooms.py) and
where it comes from: IRC LIST against tests/fake_ircd.py, the Matrix room
directory and an XMPP server's group chat service against fakes of the
libraries' objects (no network, no matrix-nio or slixmpp needed)."""

from __future__ import annotations

import asyncio
import json
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
from fake_ircd import FakeIrcd  # noqa: E402
from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import chat as C  # noqa: E402
from core import chat_irc as I  # noqa: E402
from core import chat_matrix as M  # noqa: E402
from core import chat_xmpp as X  # noqa: E402
from ui.chat_rooms import COL_NAME, COL_USERS, RoomListPanel, RoomModel  # noqa: E402


@pytest.fixture(autouse=True)
def _app():
    app = QApplication.instance() or QApplication([])
    C._SESSION_SECRETS.clear()
    yield app
    C._SESSION_SECRETS.clear()


@pytest.fixture
def ircd():
    servers = []

    def start(**kw):
        server = FakeIrcd(**kw).start()
        servers.append(server)
        return server
    yield start
    for server in servers:
        server.stop()


@pytest.fixture
def panel_with(tmp_path):
    made = []

    def make(server):
        from ui.chat_panel import ChatPanel

        path = tmp_path / "chat.json"
        account = C.Account(protocol="irc", name="test", settings={
            "server": "127.0.0.1", "port": server.port, "tls": I.TLS_OFF, "nick": "alice", "proxy": "none"})
        C.save_accounts([account], path)
        panel = ChatPanel(I.PROTOCOL, accounts_path=path)
        made.append(panel)
        panel.show()
        return panel, panel.clients[account.account_id], account.account_id
    yield make
    for panel in made:
        panel.shutdown()
        panel.deleteLater()


def _collect(client):
    got = {"rooms": [], "done": []}
    client.room_list_batch.connect(lambda rid, rooms: got["rooms"].extend((rid, r) for r in rooms))
    client.room_list_done.connect(lambda rid, problem: got["done"].append((rid, problem)))
    return got


def _online(client):
    client.connect_account()
    return wait_until(lambda: client.state == C.STATE_ONLINE, 10)


# --- IRC LIST ------------------------------------------------------------------------------

def test_happy_irc_list_fills_the_panel_and_a_double_click_joins(ircd, panel_with):
    server = ircd(caps=())
    server.listed = [("#python", 1234, "The Python language <b>no markup</b>"), ("#rust", 900, "Rust")]
    panel, client, aid = panel_with(server)
    assert _online(client)
    panel.rooms_button.setChecked(True)          # shown: the list is asked for at once
    model = panel.rooms.models[aid]
    assert wait_until(lambda: not model.loading and len(model.rooms) == 2, 10)
    assert [model.room(r).name for r in range(2)] == ["#python", "#rust"]   # most users first
    index = model.index(0, 2)
    assert model.data(index) == "The Python language <b>no markup</b>"     # plain text cell
    assert "double-click joins" in panel.rooms.status.text()
    # the server log is not flooded with the list
    assert not any("#rust" in m.text for m in client.history(client.server_key))
    panel.rooms.table.doubleClicked.emit(model.index(1, COL_NAME))
    assert wait_until(lambda: client.conversation("#rust") is not None, 10)


def test_happy_a_big_list_arrives_in_batches_and_the_filter_narrows_it(ircd, panel_with):
    server = ircd(caps=())
    server.listed = [(f"#chan{i}", i % 500, f"topic {i}") for i in range(6000)]
    panel, client, aid = panel_with(server)
    assert _online(client)
    batches = []
    client.room_list_batch.connect(lambda rid, rooms: batches.append(len(rooms)))
    panel.rooms_button.setChecked(True)
    model = panel.rooms.models[aid]
    assert wait_until(lambda: not model.loading and len(model.rooms) == 6000, 20)
    assert len(batches) >= 6000 // C.ROOM_BATCH and max(batches) <= C.ROOM_BATCH
    panel.rooms.filter.setText("chan599")
    assert wait_until(lambda: model.rowCount() == 11, 5)   # #chan599, #chan5990..#chan5999
    assert "11 of 6000" in panel.rooms.status.text()


def test_happy_a_list_typed_by_hand_feeds_the_panel_too(ircd, panel_with):
    server = ircd(caps=())
    server.listed = [("#typed", 3, "")]
    panel, client, aid = panel_with(server)
    assert _online(client)
    panel.rooms_button.setChecked(True)
    model = panel.rooms.models[aid]
    assert wait_until(lambda: not model.loading and model.rooms, 10)
    first = model.request_id
    client.send(client.server_key, "/quote LIST")
    assert wait_until(lambda: model.request_id > first and not model.loading, 10)
    assert [r.name for r in model.rooms] == ["#typed"]


def test_sad_a_list_that_never_ends_is_reported(ircd, monkeypatch):
    monkeypatch.setattr(I, "LIST_TIMEOUT", 0.5)
    server = ircd(caps=())
    server.listed = [("#a", 1, "")]
    server.list_unfinished = True
    account = C.Account(protocol="irc", name="t", settings={
        "server": "127.0.0.1", "port": server.port, "tls": I.TLS_OFF, "nick": "alice", "proxy": "none"})
    client = I.IrcClient(account)
    try:
        got = _collect(client)
        assert _online(client)
        rid = client.request_room_list()
        assert wait_until(lambda: got["done"], 10)
        assert got["done"][0][0] == rid and "did not finish" in got["done"][0][1]
        assert [r.name for _rid, r in got["rooms"]] == ["#a"]   # what came is kept
    finally:
        client.shutdown()


def test_sad_listing_when_offline_is_an_error_not_a_hang():
    account = C.Account(protocol="irc", name="t", settings={"server": "irc.example", "nick": "a"})
    client = I.IrcClient(account)
    try:
        got = _collect(client)
        client.request_room_list()
        assert wait_until(lambda: got["done"], 5)
        assert got["done"][0][1] == "Not connected."
    finally:
        client.shutdown()


def test_edge_the_list_is_capped(ircd, monkeypatch):
    monkeypatch.setattr(C, "MAX_ROOM_LIST", 50)
    server = ircd(caps=())
    server.listed = [(f"#c{i}", 1, "") for i in range(120)]
    account = C.Account(protocol="irc", name="t", settings={
        "server": "127.0.0.1", "port": server.port, "tls": I.TLS_OFF, "nick": "alice", "proxy": "none"})
    client = I.IrcClient(account)
    try:
        got = _collect(client)
        assert _online(client)
        client.request_room_list()
        assert wait_until(lambda: got["done"], 10)
        assert len(got["rooms"]) == 50 and "first 50" in got["done"][0][1]
    finally:
        client.shutdown()


# --- Matrix: the public room directory -----------------------------------------------------------

def test_happy_matrix_public_rooms_join_by_alias_else_by_id():
    rooms, token = M.parse_public_rooms({"chunk": [
        {"room_id": "!abc:example.org", "canonical_alias": "#python:example.org", "name": "Python",
         "num_joined_members": 812, "topic": "Snakes"},
        {"room_id": "!def:example.org", "name": "No alias"},
        {"room_id": "not a room"},
        "junk",
    ], "next_batch": "t2"})
    assert [(r.name, r.title, r.users) for r in rooms] == [
        ("#python:example.org", "Python", 812), ("!def:example.org", "No alias", -1)]
    assert token == "t2"


def test_sad_matrix_directory_answers_that_are_not_lists():
    with pytest.raises(C.ChatError):
        M.parse_public_rooms(["x"])
    rooms, token = M.parse_public_rooms({"chunk": "x", "next_batch": 5})
    assert rooms == [] and token == ""


class _FakeContent:
    def __init__(self, body: bytes) -> None:
        self.body = body

    async def read(self, n: int) -> bytes:
        chunk, self.body = self.body[:n], self.body[n:]
        return chunk


class _FakeNio:
    """matrix-nio's AsyncClient as far as the directory uses it."""

    def __init__(self, pages):
        self.pages, self.requests = list(pages), []
        self.client_session, self.access_token = object(), "token"

    async def send(self, method, path, data=None, headers=None):
        self.requests.append((method, path, json.loads(data), headers["Authorization"]))
        page = self.pages.pop(0)
        return SimpleNamespace(status=200, content=_FakeContent(json.dumps(page).encode()),
                               release=lambda: None)


def _matrix_client(nio):
    account = C.Account(protocol="matrix", name="m", settings={"homeserver": "https://example.org",
                                                               "user": "@a:example.org"})
    client = M.MatrixClient(account)
    client.nio, client.state = nio, C.STATE_ONLINE
    return client


def test_happy_matrix_directory_pages_are_followed_with_the_search_term():
    nio = _FakeNio([
        {"chunk": [{"room_id": "!a:example.org", "canonical_alias": "#a:example.org"}], "next_batch": "p2"},
        {"chunk": [{"room_id": "!b:example.org", "canonical_alias": "#b:example.org"}]},
    ])
    client = _matrix_client(nio)
    try:
        got = _collect(client)
        rid = client.request_room_list("snake")
        assert wait_until(lambda: got["done"], 5)
        assert got["done"] == [(rid, "")]
        assert [r.name for _rid, r in got["rooms"]] == ["#a:example.org", "#b:example.org"]
        assert nio.requests[0][:2] == ("POST", "/_matrix/client/v3/publicRooms")
        assert nio.requests[0][2]["filter"] == {"generic_search_term": "snake"}
        assert nio.requests[1][2]["since"] == "p2" and nio.requests[0][3] == "Bearer token"
    finally:
        client.state = C.STATE_OFFLINE
        client.nio = None
        client.shutdown()


def test_sad_matrix_directory_that_fails_is_reported():
    nio = _FakeNio([])

    async def refuse(*args, **kwargs):
        return SimpleNamespace(status=403, content=_FakeContent(b""), release=lambda: None)
    nio.send = refuse
    client = _matrix_client(nio)
    try:
        got = _collect(client)
        client.request_room_list()
        assert wait_until(lambda: got["done"], 5)
        assert "HTTP 403" in got["done"][0][1]
    finally:
        client.state = C.STATE_OFFLINE
        client.nio = None
        client.shutdown()


def test_edge_matrix_directory_stops_at_the_page_limit(monkeypatch):
    monkeypatch.setattr(M, "ROOM_PAGES", 3)
    pages = [{"chunk": [{"room_id": f"!r{i}:example.org"}], "next_batch": f"p{i}"} for i in range(10)]
    nio = _FakeNio(pages)
    client = _matrix_client(nio)
    try:
        got = _collect(client)
        client.request_room_list()
        assert wait_until(lambda: got["done"], 5)
        assert len(got["rooms"]) == 3 and "first 3" in got["done"][0][1]
    finally:
        client.state = C.STATE_OFFLINE
        client.nio = None
        client.shutdown()


def test_sad_matrix_directory_page_that_is_too_large_is_refused(monkeypatch):
    monkeypatch.setattr(M, "MAX_DIRECTORY_PAGE", 1000)
    nio = _FakeNio([{"chunk": [{"room_id": f"!r{i}:example.org", "topic": "x" * 200} for i in range(20)]}])
    client = _matrix_client(nio)
    try:
        got = _collect(client)
        client.request_room_list()
        assert wait_until(lambda: got["done"], 5)
        assert "too large" in got["done"][0][1] and got["rooms"] == []
    finally:
        client.state = C.STATE_OFFLINE
        client.nio = None
        client.shutdown()


# --- XMPP: the group chat service ----------------------------------------------------------------

class _FakeDisco:
    def __init__(self, items, infos):
        self.items, self.infos = items, infos

    async def get_items(self, jid, timeout=None):
        return {"disco_items": {"items": self.items.get(jid, [])}}

    async def get_info(self, jid, timeout=None):
        if jid not in self.infos:
            raise asyncio.TimeoutError()
        return {"disco_info": {"identities": self.infos[jid]}}


def _xmpp_client(disco):
    account = C.Account(protocol="xmpp", name="x", settings={"jid": "bob@example.net"})
    client = X.XmppClient(account)
    client.xmpp = SimpleNamespace(plugin={"xep_0030": disco})
    client.state = C.STATE_ONLINE
    return client


def test_happy_xmpp_rooms_of_the_conference_service():
    disco = _FakeDisco(
        items={"example.net": [("upload.example.net", None, "Upload"), ("conference.example.net", None, "Chats")],
               "conference.example.net": [("lounge@conference.example.net", None, "Lounge (12)"),
                                          ("dev@conference.example.net", None, "Developers"),
                                          ("not a jid", None, "x")]},
        infos={"upload.example.net": [("store", "file", None, "")],
               "conference.example.net": [("conference", "text", None, "Chats")]})
    client = _xmpp_client(disco)
    try:
        got = _collect(client)
        client.request_room_list("dev")
        assert wait_until(lambda: got["done"], 5)
        assert [(r.name, r.title) for _rid, r in got["rooms"]] == [("dev@conference.example.net", "Developers")]
        assert got["done"][0][1] == ""
    finally:
        client.state = C.STATE_OFFLINE
        client.xmpp = None
        client.shutdown()


def test_sad_xmpp_server_without_a_group_chat_service():
    client = _xmpp_client(_FakeDisco(items={"example.net": [("pubsub.example.net", None, "")]}, infos={}))
    try:
        got = _collect(client)
        client.request_room_list()
        assert wait_until(lambda: got["done"], 5)
        assert "no group chat service" in got["done"][0][1]
    finally:
        client.state = C.STATE_OFFLINE
        client.xmpp = None
        client.shutdown()


# --- the model and the panel on their own ------------------------------------------------------------

def test_happy_the_model_sorts_by_users_when_complete_and_by_name_on_request():
    model = RoomModel()
    model.reset(1)
    model.add([C.RoomInfo("#b", users=5), C.RoomInfo("#a", users=50), C.RoomInfo("#c")])
    assert [model.room(r).name for r in range(3)] == ["#b", "#a", "#c"]   # as they arrive
    model.finish("")
    assert [model.room(r).name for r in range(3)] == ["#a", "#b", "#c"]
    model.sort(COL_NAME, Qt.SortOrder.AscendingOrder)
    assert [model.room(r).name for r in range(3)] == ["#a", "#b", "#c"]
    assert model.data(model.index(2, COL_USERS)) == ""


def test_edge_batches_of_an_older_request_are_dropped():
    panel = RoomListPanel("Channel List")
    model = panel.model_for("acc")
    model.reset(7)
    panel.add_batch("acc", 6, [C.RoomInfo("#old")])
    panel.add_batch("acc", 7, [C.RoomInfo("#new")])
    panel.list_done("acc", 6, "stale")
    assert [r.name for r in model.rooms] == ["#new"] and model.loading
    panel.list_done("acc", 7, "")
    assert not model.loading and model.problem == ""


def test_edge_hostile_room_fields_are_cleaned_by_the_client():
    account = C.Account(protocol="irc", name="t", settings={"server": "irc.example", "nick": "a"})
    client = I.IrcClient(account)
    try:
        got = _collect(client)
        client._emit_rooms(3, [C.RoomInfo("#x\u202e\x07", title="t" * 900, users="many",
                                          topic="line1\nline2 \x03" + "4red")])
        QApplication.processEvents()
        (_rid, room), = got["rooms"]
        assert room.name == "#x" and len(room.title) <= 210 and room.users == -1
        assert room.topic == "line1 line2 red"
    finally:
        client.shutdown()
