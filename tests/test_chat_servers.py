"""core.chat_servers - the lists of public IRC networks, Matrix homeservers
and XMPP providers - and the account editor's server drop-down
(ui/chat_server_box.py). Nothing here touches the network: the directories
are fake answers handed to refresh()."""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from bluez_testkit import wait_until  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import chat as C  # noqa: E402
from core import chat_irc as I  # noqa: E402
from core import chat_matrix as M  # noqa: E402
from core import chat_servers as S  # noqa: E402
from core import chat_xmpp as X  # noqa: E402

IRSSI = """servers = (
  { address = "irc.libera.chat";   chatnet = "liberachat";port = "6697"; use_tls = "yes"; tls_verify = "yes"; },
  { address = "open.ircnet.net";   chatnet = "IRCnet";    port = "6667"; },
  { address = "ssl.ircnet.ovh";    chatnet = "IRCnet";    port = "6697"; use_tls = "yes"; tls_verify = "yes"; },
  { address = "irc.dal.net";       chatnet = "DALnet";    port = "6667"; },
  { address = "silc.silcnet.org";  chatnet = "SILC";      port = "706";  }
);
chatnets = {
  liberachat = { type = "IRC"; max_kicks = "1"; };
  IRCnet = { type = "IRC"; };
  DALnet = { type = "IRC"; };
  SILC = { type = "SILC"; };
};
"""
JOINMATRIX = {"public_servers": [
    {"name": "example.org", "client_domain": "matrix.example.org", "reg_method": "In-house Element",
     "staff_jur": "Germany"},
    {"name": "plain.example", "client_domain": "plain.example:8448"},
    {"name": "<b>bad</b>", "client_domain": "not a host"},
], "private_servers": []}
PROVIDERS = [
    {"jid": "chat.example.net", "category": "A", "serverLocations": ["de", "at"], "inBandRegistration": True},
    {"jid": "paid.example.com", "category": "B", "freeOfCharge": False,
     "registrationWebPage": {"en": "https://paid.example.com/signup"}},
    {"jid": 42},
]


@pytest.fixture(autouse=True)
def _app():
    return QApplication.instance() or QApplication([])


# --- the directories' formats ------------------------------------------------------------

def test_happy_irssi_networks_prefer_their_tls_server_and_leave_silc_out():
    entries = S.parse_irssi(IRSSI, "https://example.org/irssi.conf")
    by_name = {e.name: e for e in entries}
    assert set(by_name) == {"liberachat", "IRCnet", "DALnet"}
    assert (by_name["IRCnet"].host, by_name["IRCnet"].port, by_name["IRCnet"].tls) == ("ssl.ircnet.ovh", 6697, True)
    assert by_name["DALnet"].tls is False and "plain text" in by_name["DALnet"].note
    assert by_name["liberachat"].source == "https://example.org/irssi.conf"


def test_happy_joinmatrix_entries_keep_the_server_name_apart_from_the_client_address():
    entries = S.parse_joinmatrix(JOINMATRIX, "https://servers.joinmatrix.org/servers.json")
    assert [(e.name, e.host, e.port, e.domain) for e in entries] == [
        ("example.org", "matrix.example.org", 443, "example.org"),
        ("plain.example", "plain.example", 8448, "plain.example")]
    assert entries[0].note == "In-house Element; Germany"


def test_happy_xmpp_providers_with_category_country_and_sign_up():
    entries = S.parse_xmpp_providers(PROVIDERS, "https://data.xmpp.net/providers/v2/providers-B.json")
    assert [e.host for e in entries] == ["chat.example.net", "paid.example.com"]
    assert entries[0].note == "category A; DE, AT; sign-up in the app"
    assert "paid" in entries[1].note and "website" in entries[1].note


def test_sad_hostile_entries_are_dropped_or_cleaned():
    raw = [
        {"name": "x", "host": "evil host; rm -rf", "port": 1},
        {"name": "x", "host": "a.example", "port": 70000},
        {"name": "x", "host": "a.example", "port": True},
        {"name": "x", "host": "b.example", "tls": "yes"},
        {"name": "\u202eevil\u0007" + "n" * 500, "host": "c.example", "port": 6697,
         "note": "<script>x</script>\nsecond line", "source": "javascript:alert(1)"},
        "not a dict",
    ]
    entries = S.entries_of(raw)
    assert [e.host for e in entries] == ["c.example"]
    entry = entries[0]
    assert "\u202e" not in entry.name and "\u0007" not in entry.name and len(entry.name) <= 90
    assert "\n" not in entry.note and entry.source == ""
    # shown as typed - the drop-down is plain text, markup stays text
    assert "<script>" in entry.note


def test_sad_answers_that_are_not_lists_give_nothing():
    assert S.parse_joinmatrix([1, 2]) == []
    assert S.parse_xmpp_providers({"jid": "a.example"}) == []
    assert S.parse_irssi("no servers here") == []
    with pytest.raises(S.ServerListError):
        S.PARSERS["joinmatrix"](b"{not json", "https://x.example")


def test_edge_repeats_are_dropped_and_the_list_is_capped(monkeypatch):
    monkeypatch.setattr(S, "MAX_ENTRIES", 5)
    raw = [{"host": f"h{i % 7}.example", "port": 1} for i in range(40)]
    entries = S.entries_of(raw, limit=S.MAX_ENTRIES)
    assert len(entries) == 5 and len({e.host for e in entries}) == 5


# --- the files ----------------------------------------------------------------------------

@pytest.mark.parametrize("protocol", S.PROTOCOLS)
def test_happy_the_bundled_snapshots_are_valid_and_dated(protocol):
    raw = json.loads(S.bundled_path(protocol).read_text(encoding="utf-8"))
    server_list = S.bundled(protocol)
    assert server_list.origin == "bundled" and len(server_list.entries) >= 5
    assert len(server_list.entries) == len(raw["servers"])  # nothing invalid was shipped
    assert time.strptime(server_list.date, "%Y-%m-%d")
    assert server_list.sources and all(u.startswith("https://") for u in server_list.sources)
    for entry in server_list.entries:
        assert S.valid_host(entry.host) and entry.source.startswith("https://")


def test_happy_the_snapshots_hold_the_well_known_servers():
    hosts = {p: {e.host for e in S.bundled(p).entries} for p in S.PROTOCOLS}
    assert {"irc.libera.chat", "irc.oftc.net"} <= hosts["irc"]
    assert "matrix-client.matrix.org" in hosts["matrix"]
    libera = next(e for e in S.bundled("irc").entries if e.host == "irc.libera.chat")
    assert (libera.port, libera.tls) == (6697, True)


def test_happy_load_prefers_a_refreshed_cache(tmp_path):
    fetched = S.ServerList("irc", [S.ServerEntry("Net", "irc.example.net", 6697)], "2026-11-06", "fetched",
                           ("https://example.org/list",))
    S.save_cache(fetched, tmp_path)
    loaded = S.load("irc", tmp_path)
    assert loaded.origin == "cache" and [e.host for e in loaded.entries] == ["irc.example.net"]
    assert loaded.date == "2026-11-06"


def test_sad_a_tampered_or_empty_cache_falls_back_to_the_snapshot(tmp_path):
    (tmp_path / "matrix.json").write_text("{broken", encoding="utf-8")
    assert S.load("matrix", tmp_path).origin == "bundled"
    (tmp_path / "xmpp.json").write_text(json.dumps({"format": 1, "protocol": "irc", "servers": []}),
                                        encoding="utf-8")
    assert S.load("xmpp", tmp_path).origin == "bundled"
    (tmp_path / "irc.json").write_text(json.dumps(
        {"format": 1, "protocol": "irc", "snapshot_date": "x", "servers": [{"host": "not valid"}]}),
        encoding="utf-8")
    assert S.load("irc", tmp_path).origin == "bundled"


def test_edge_an_unknown_protocol_has_an_empty_list():
    assert S.load("gopher").entries == []


# --- refreshing (fake directories) ------------------------------------------------------------

def test_happy_refresh_reads_the_directory_and_caches_it(tmp_path):
    asked = []

    def get(url):
        asked.append(url)
        return json.dumps(JOINMATRIX).encode()
    server_list = S.refresh("matrix", get=get, cache=tmp_path, today="2026-11-06")
    assert asked == [S.DIRECTORIES["matrix"][0][0]]
    assert server_list.origin == "fetched" and len(server_list.entries) == 2
    assert S.load("matrix", tmp_path).origin == "cache"


def test_happy_refresh_tries_the_second_place_when_the_first_fails(tmp_path):
    def get(url):
        if "data.xmpp.net" in url:
            raise S.ServerListError("cannot reach data.xmpp.net: blocked")
        return json.dumps(PROVIDERS).encode()
    server_list = S.refresh("xmpp", get=get, cache=tmp_path)
    assert [e.host for e in server_list.entries] == ["chat.example.net", "paid.example.com"]
    assert "kaidan" in server_list.sources[0].lower()


def test_sad_a_failed_refresh_says_why_and_keeps_the_cache(tmp_path):
    before = S.ServerList("irc", [S.ServerEntry("Net", "irc.example.net", 6697)], "2026-01-01", "fetched")
    S.save_cache(before, tmp_path)

    def get(url):
        return b"<html>not the list</html>"
    with pytest.raises(S.ServerListError, match="no usable server"):
        S.refresh("irc", get=get, cache=tmp_path)
    assert [e.host for e in S.load("irc", tmp_path).entries] == ["irc.example.net"]


def test_sad_a_crashing_parser_is_a_problem_not_a_crash(tmp_path):
    with pytest.raises(S.ServerListError, match="not JSON|unreadable"):
        S.refresh("matrix", get=lambda url: b"\xff\xfe", cache=tmp_path)


class _Response:
    def __init__(self, chunks):
        self._chunks = list(chunks)

    def read1(self, _n):
        return self._chunks.pop(0) if self._chunks else b""

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _Opener:
    def __init__(self, chunks):
        self.chunks, self.requests = chunks, []

    def open(self, request, timeout):
        self.requests.append((request.full_url, timeout))
        return _Response(self.chunks)


def test_happy_http_get_reads_the_answer_through_the_given_opener():
    opener = _Opener([b"abc", b"def"])
    assert S.http_get("https://example.org/list", opener=opener) == b"abcdef"
    assert opener.requests == [("https://example.org/list", S.FETCH_TIMEOUT)]


def test_sad_http_get_refuses_plain_http_and_oversized_answers():
    with pytest.raises(S.ServerListError, match="https"):
        S.http_get("http://example.org/list", opener=_Opener([b"x"]))
    with pytest.raises(S.ServerListError, match="larger"):
        S.http_get("https://example.org/list", opener=_Opener([b"x" * 600, b"y" * 600]), max_bytes=1000)


# --- applying a chosen server ----------------------------------------------------------------------

def test_happy_choosing_an_irc_network_fills_server_port_and_tls():
    entry = S.ServerEntry("OFTC", "irc.oftc.net", 6697, True)
    assert I.apply_server(entry, {}) == {"server": "irc.oftc.net", "port": 6697, "tls": I.TLS_VERIFY}
    plain = S.ServerEntry("DALnet", "irc.dal.net", 6667, False)
    assert I.apply_server(plain, {})["tls"] == I.TLS_OFF


def test_happy_choosing_a_homeserver_keeps_the_user_name_on_the_server_name():
    entry = S.ServerEntry("example.org", "matrix.example.org", 443, domain="example.org")
    assert M.apply_server(entry, {"user": "@alice:old.example"}) == {
        "homeserver": "https://matrix.example.org", "user": "@alice:example.org"}
    assert M.apply_server(S.ServerEntry("x.example", "x.example", 8448), {"user": ""}) == {
        "homeserver": "https://x.example:8448"}


def test_edge_choosing_a_provider_keeps_the_typed_name():
    entry = S.ServerEntry("chat.example.net", "chat.example.net")
    assert X.apply_server(entry, {"jid": "bob@old.example"}) == {"jid": "bob@chat.example.net"}
    assert X.apply_server(entry, {"jid": "bob"}) == {"jid": "bob@chat.example.net"}
    assert X.apply_server(entry, {"jid": ""}) == {"jid": "@chat.example.net"}


# --- the drop-down in the account editor --------------------------------------------------------

def _fake_list(protocol="irc"):
    return S.ServerList(protocol, [S.ServerEntry("Libera.Chat", "irc.libera.chat", 6697, True, "a note"),
                                   S.ServerEntry("<b>DALnet</b>", "irc.dal.net", 6667, False)],
                        "2026-11-06", "bundled", ("https://example.org",))


def test_happy_the_irc_editor_offers_the_servers_and_a_choice_fills_the_form(monkeypatch):
    from ui import chat_panel as P

    monkeypatch.setattr(S, "load", lambda protocol, cache=None: _fake_list(protocol))
    editor = P.AccountEditor(I.PROTOCOL, None)
    box = editor.server_box
    assert box.combo.isEditable() and box.combo.count() == 2
    assert box.combo.itemText(1).startswith("<b>DALnet</b>")  # plain text, never rendered
    assert "2026-11-06" in box.info.text()
    box.combo.activated.emit(1)
    assert box.text() == "irc.dal.net"
    assert editor.widgets["port"].value() == 6667
    assert editor.widgets["tls"].currentData() == I.TLS_OFF
    settings, _ = editor.values()
    assert settings["server"] == "irc.dal.net"


def test_happy_a_typed_server_is_kept_as_typed(monkeypatch):
    from ui import chat_panel as P

    monkeypatch.setattr(S, "load", lambda protocol, cache=None: _fake_list(protocol))
    editor = P.AccountEditor(I.PROTOCOL, C.Account(protocol="irc", name="x", settings={"server": "irc.mine.example"}))
    assert editor.server_box.text() == "irc.mine.example"
    editor.server_box.combo.lineEdit().setText("irc.other.example")
    assert editor.values()[0]["server"] == "irc.other.example"


def test_happy_the_xmpp_editor_puts_the_provider_into_the_jabber_id(monkeypatch):
    from ui import chat_panel as P

    monkeypatch.setattr(S, "load", lambda protocol, cache=None: S.ServerList(
        protocol, [S.ServerEntry("chat.example.net", "chat.example.net")], "2026-11-05"))
    editor = P.AccountEditor(X.PROTOCOL, None)
    editor.server_box.combo.lineEdit().setText("bob")
    editor.server_box.combo.lineEdit().textEdited.emit("bob")
    editor.server_box.combo.activated.emit(0)
    assert editor.values()[0]["jid"] == "bob@chat.example.net"


def test_happy_refresh_list_replaces_the_entries_off_the_gui_thread():
    import threading

    from ui.chat_server_box import ServerBox

    threads = []

    def refresh(protocol):
        threads.append(threading.current_thread())
        return S.ServerList(protocol, [S.ServerEntry("New", "irc.new.example", 6697)], "2026-11-06", "fetched")
    box = ServerBox("irc", "", load=lambda p: _fake_list(p), refresh=refresh)
    box.refresh()
    assert wait_until(lambda: box.combo.count() == 1, 5)
    assert threads and threads[0] is not threading.main_thread()
    assert "refreshed" in box.info.text() and box.refresh_button.isEnabled()


def test_sad_a_failed_refresh_keeps_the_snapshot_and_says_why():
    from ui.chat_server_box import ServerBox

    def refresh(protocol):
        raise S.ServerListError("cannot reach servers.joinmatrix.org: blocked")
    box = ServerBox("matrix", "", load=lambda p: _fake_list(p), refresh=refresh)
    box.refresh()
    assert wait_until(lambda: box.refresh_button.isEnabled(), 5)
    assert box.combo.count() == 2
    assert "blocked" in box.info.text() and "shipped with axross" in box.info.text()


def test_edge_an_empty_list_still_lets_the_user_type():
    from ui.chat_server_box import ServerBox

    box = ServerBox("irc", "irc.mine.example", load=lambda p: S.ServerList(p))
    assert box.combo.count() == 0 and box.text() == "irc.mine.example"
    assert "type the server" in box.info.text()
