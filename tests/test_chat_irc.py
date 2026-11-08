"""core.chat_irc against tests/fake_ircd.py, its parts on their own, and
the chat panel (ui/chat_panel.py) of the IRC extension."""

from __future__ import annotations

import base64
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from bluez_testkit import wait_until  # noqa: E402
from fake_ircd import FakeIrcd, self_signed  # noqa: E402
from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication, QToolButton  # noqa: E402

from core import chat as C  # noqa: E402
from core import chat_irc as I  # noqa: E402


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
def clients():
    made = []

    def make(server, **settings):
        base = {"server": "127.0.0.1", "port": server.port, "tls": I.TLS_OFF, "nick": "alice", "proxy": "none"}
        base.update(settings)
        account = C.Account(protocol="irc", name="test", settings=base)
        for name in ("password", "server_password"):
            if name in settings:
                C._SESSION_SECRETS[(account.keyring_profile, name)] = base.pop(name)
        client = I.IrcClient(account)
        made.append(client)
        return client
    yield make
    for client in made:
        client.shutdown()


def messages(client, key):
    return [m.text for m in client.history(key)]


def online(client, timeout=10):
    return wait_until(lambda: client.state == C.STATE_ONLINE, timeout)


# --- lines ---------------------------------------------------------------------------

def test_happy_a_line_with_tags_prefix_and_trailing():
    line = I.parse_line("@time=2026-11-04T10:00:00.000Z;msgid=a\\sb :nick!u@h PRIVMSG #c :hello there\r\n")
    assert line.command == "PRIVMSG" and line.params == ["#c", "hello there"]
    assert line.nick == "nick" and line.tags == {"time": "2026-11-04T10:00:00.000Z", "msgid": "a b"}


def test_sad_garbage_is_not_a_line():
    assert I.parse_line("") is None
    assert I.parse_line(":only.prefix") is None
    assert I.parse_line("PRIV\x00MSG x") is None
    assert I.parse_line("NOT-A-COMMAND x") is None


def test_sad_a_line_break_cannot_smuggle_a_second_command():
    with pytest.raises(I.LineError):
        I.format_line("PRIVMSG", "#c", "hi\r\nQUIT :bye")
    with pytest.raises(I.LineError):
        I.format_line("PRIVMSG", "#c x", "hi")
    assert I.format_line("PRIVMSG", "#c", "hi there") == "PRIVMSG #c :hi there"
    assert I.format_line("JOIN", "#c") == "JOIN #c"


def test_edge_split_text_never_cuts_a_character():
    text = "ä" * 300 + " " + "€" * 200
    pieces = I.split_text(text, 100)
    assert all(len(p.encode()) <= 100 for p in pieces)
    assert "".join(pieces).replace(" ", "") == text.replace(" ", "")


def test_happy_rfc1459_case_mapping():
    assert I.casefold("Nick[]\\~") == "nick{}|^"
    assert I.casefold("Nick[]", "ascii") == "nick[]"


def test_happy_scram_sha256_rfc7677_vector():
    scram = I.Scram("user", "pencil", nonce="rOprNGfwEbeRWgbNEkqO")
    assert scram.first() == b"n,,n=user,r=rOprNGfwEbeRWgbNEkqO"
    final = scram.final(b"r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,"
                        b"s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096")
    assert final == (b"c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,"
                     b"p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=")
    scram.verify(b"v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=")


def test_sad_scram_refuses_a_server_that_does_not_know_the_password():
    scram = I.Scram("user", "pencil", nonce="rOprNGfwEbeRWgbNEkqO")
    scram.final(b"r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096")
    with pytest.raises(I.ScramError):
        scram.verify(b"v=" + base64.b64encode(b"x" * 32))
    with pytest.raises(I.ScramError):
        I.Scram("u", "p", nonce="abc").final(b"r=other,s=AAAA,i=4096")
    with pytest.raises(I.ScramError):
        I.Scram("u", "p", nonce="abc").final(b"r=abcdef,s=AAAA,i=10")


def test_sad_text_from_the_network_loses_its_tricks():
    text = C.clean_text("a\u202eevil\u202c\x03" + "04red\x02bold\x0f \x07\x1b[2J end")
    assert text == "aevilredbold [2J end"
    assert len(C.clean_text("x" * 100_000)) < C.MAX_TEXT + 10


def test_happy_fingerprints_are_normalised():
    fp = "ab" * 32
    assert I.normalise_fingerprint(fp) == ":".join(["AB"] * 32)
    assert I.normalise_fingerprint("abc") == ""


# --- a session -------------------------------------------------------------------------

def test_happy_register_join_and_talk(ircd, clients):
    server = ircd(caps=("server-time", "multi-prefix"))
    client = clients(server, autojoin=["#axross"])
    client.connect_account()
    assert online(client)
    assert wait_until(lambda: client.conversation("#axross") is not None)
    conv = client.conversation("#axross")
    assert wait_until(lambda: "alice" in conv.members)
    assert conv.members["alice"].role == "@"
    server.add_member("#axross", "bob")
    assert wait_until(lambda: "bob" in client.conversation("#axross").members)
    server.say_as("bob", "#axross", "hi <b>alice</b>")
    assert wait_until(lambda: "hi <b>alice</b>" in messages(client, "#axross"))
    message = client.history("#axross")[-1]
    assert message.sender == "bob" and message.encryption == C.ENC_NONE and not message.outgoing
    assert client.conversation("#axross").highlight
    client.send("#axross", "hello bob")
    assert wait_until(lambda: "PRIVMSG #axross :hello bob" in server.lines_of("alice"))
    client.send("#axross", "/me waves")
    assert wait_until(lambda: "PRIVMSG #axross :\x01ACTION waves\x01" in server.lines_of("alice"))
    server.say_as("bob", "alice", "psst")
    assert wait_until(lambda: client.conversation("bob") is not None)
    assert messages(client, "bob") == ["psst"]


def test_happy_a_long_message_is_split_to_fit_the_line_limit(ircd, clients):
    server = ircd(caps=())
    client = clients(server, autojoin=["#c"])
    client.connect_account()
    assert online(client) and wait_until(lambda: client.conversation("#c") is not None)
    client.send("#c", "wort " * 300)
    assert wait_until(lambda: len([l for l in server.lines_of("alice") if l.startswith("PRIVMSG #c")]) >= 3, 15)
    for line in server.lines_of("alice"):
        assert len(line.encode()) + 2 <= 512


def test_sad_a_pasted_line_break_cannot_inject_a_command(ircd, clients):
    server = ircd(caps=())
    client = clients(server, autojoin=["#c"])
    client.connect_account()
    assert online(client) and wait_until(lambda: client.conversation("#c") is not None)
    client.send("#c", "one\r\nQUIT :gone")
    assert wait_until(lambda: "PRIVMSG #c :QUIT :gone" in server.lines_of("alice"))
    assert not any(l.startswith("QUIT") for l in server.lines_of("alice"))


def test_happy_nick_in_use_takes_the_alternative(ircd, clients):
    server = ircd(caps=())
    client = clients(server, nick="taken", alt_nick="alice2")
    client.connect_account()
    assert online(client)
    assert client.nick == "alice2"


def test_happy_sasl_scram_over_tls_with_a_pinned_certificate(ircd, clients, tmp_path):
    cert, key, der = self_signed(tmp_path)
    server = ircd(tls=(cert, key), accounts={"alice": "s3cret"})
    client = clients(server, tls=I.TLS_PINNED, fingerprint=I.fingerprint_of(der),
                     sasl=I.SASL_SCRAM, password="s3cret")
    client.connect_account()
    assert online(client)
    assert server.session("alice").account == "alice"
    assert client.conversation(client.server_key).encryption == C.ENC_TRANSPORT
    assert not any("s3cret" in l for l in server.lines_of("alice"))


def test_sad_an_untrusted_certificate_is_asked_and_pinned_on_yes(ircd, clients, tmp_path):
    cert, key, der = self_signed(tmp_path)
    server = ircd(tls=(cert, key), caps=())
    client = clients(server, tls=I.TLS_VERIFY)
    asked = []
    client.request.connect(asked.append)
    client.connect_account()
    assert wait_until(lambda: asked and client.state == C.STATE_ERROR)
    request = asked[0]
    assert isinstance(request, I.CertificateRequest) and request.fingerprint == I.fingerprint_of(der)
    client.answer(request, True)
    assert online(client)
    assert client.account.settings["fingerprint"] == request.fingerprint


def test_sad_a_different_certificate_than_the_pinned_one_is_refused(ircd, clients, tmp_path):
    cert, key, _der = self_signed(tmp_path)
    server = ircd(tls=(cert, key), caps=())
    client = clients(server, tls=I.TLS_PINNED, fingerprint="00" * 32)
    client.connect_account()
    assert wait_until(lambda: client.state == C.STATE_ERROR)
    assert server.session("alice") is None


def test_sad_a_wrong_password_ends_without_another_try(ircd, clients):
    server = ircd(accounts={"alice": "right"})
    client = clients(server, sasl=I.SASL_SCRAM, password="wrong")
    client.connect_account()
    assert wait_until(lambda: client.state == C.STATE_ERROR)
    assert any("SASL login failed" in t for t in messages(client, client.server_key))
    assert not client._want_online


def test_sad_a_server_that_cannot_prove_the_password_is_left(ircd, clients):
    server = ircd(accounts={"alice": "pw"})
    server.forge_scram_signature = True
    client = clients(server, sasl=I.SASL_SCRAM, password="pw")
    client.connect_account()
    assert wait_until(lambda: client.state == C.STATE_ERROR)
    assert any("could not prove" in t for t in messages(client, client.server_key))


def test_sad_required_sasl_missing_is_not_replaced_by_another_login(ircd, clients):
    server = ircd(caps=("server-time",))
    client = clients(server, sasl=I.SASL_SCRAM, password="pw", nickserv=True)
    client.connect_account()
    assert wait_until(lambda: client.state == C.STATE_ERROR)
    assert not any("IDENTIFY" in l for l in server.lines_of("alice") + server.lines_of(""))


def test_sad_plain_without_tls_is_refused():
    assert I.validate({"server": "x", "nick": "a", "sasl": I.SASL_PLAIN, "tls": I.TLS_OFF})
    assert I.validate({"server": "x", "nick": "a b"})
    assert I.validate({"server": "x", "nick": "a", "tls": I.TLS_PINNED, "fingerprint": "zz"})
    assert I.validate({"server": "x", "nick": "alice"}) is None


def test_happy_reconnect_rejoins_the_channels(ircd, clients, monkeypatch):
    monkeypatch.setattr(I, "RECONNECT_DELAYS", (0.2,))
    server = ircd(caps=())
    client = clients(server)
    client.connect_account()
    assert online(client)
    client.join("#later")
    assert wait_until(lambda: client.conversation("#later") is not None)
    server.kill_connections()
    assert wait_until(lambda: client.state == C.STATE_CONNECTING, 5)
    assert wait_until(lambda: client.state == C.STATE_ONLINE and server.session("alice") is not None, 10)
    assert wait_until(lambda: "alice" in server.channels["#later"]["members"], 5)


def test_sad_ctcp_requests_are_not_answered(ircd, clients):
    server = ircd(caps=())
    client = clients(server)
    client.connect_account()
    assert online(client)
    server.say_as("eve", "alice", "\x01VERSION\x01")
    assert wait_until(lambda: any("CTCP VERSION" in t for t in messages(client, client.server_key)))
    assert not any(l.startswith("NOTICE eve") for l in server.lines_of("alice"))


def test_sad_quote_refuses_secrets_and_line_breaks(ircd, clients):
    server = ircd(caps=())
    client = clients(server)
    client.connect_account()
    assert online(client)
    client.send(client.server_key, "/quote PASS hunter2")
    assert wait_until(lambda: any("not sent by hand" in t for t in messages(client, client.server_key)))
    client.send(client.server_key, "/quote PRIVMSG bob :hi there")
    assert wait_until(lambda: "PRIVMSG bob :hi there" in server.lines_of("alice"))


def test_edge_an_overlong_server_line_is_dropped_not_fatal(ircd, clients):
    server = ircd(caps=())
    client = clients(server)
    client.connect_account()
    assert online(client)
    server.inject("alice", ":x!y@z PRIVMSG alice :" + "A" * 20_000)
    server.say_as("bob", "alice", "after")
    assert wait_until(lambda: client.conversation("bob") is not None and messages(client, "bob") == ["after"])
    assert client.state == C.STATE_ONLINE


def test_happy_nick_change_and_kick(ircd, clients):
    server = ircd(caps=())
    client = clients(server, autojoin=["#c"])
    client.connect_account()
    assert online(client) and wait_until(lambda: client.conversation("#c") is not None)
    client.send("#c", "/nick alicia")
    assert wait_until(lambda: client.nick == "alicia")
    assert wait_until(lambda: "alicia" in client.conversation("#c").members)
    server.inject("alicia", ":op!o@h KICK #c alicia :bye")
    assert wait_until(lambda: not client.conversation("#c").joined)


# --- accounts ----------------------------------------------------------------------------

def test_happy_accounts_round_trip_without_secrets(tmp_path):
    path = tmp_path / "chat.json"
    account = C.Account(protocol="irc", name="Libera", settings={"server": "irc.libera.chat", "nick": "a"})
    C.save_accounts([account], path)
    assert oct(path.stat().st_mode & 0o777) == "0o600"
    (loaded,) = C.load_accounts(path)
    assert loaded.account_id == account.account_id and loaded.settings == account.settings


def test_sad_a_tampered_accounts_file_gives_the_good_entries(tmp_path):
    path = tmp_path / "chat.json"
    path.write_text('{"accounts": [{"protocol": "irc", "name": "ok", "account_id": "abcdef12", "settings": {}},'
                    '{"protocol": "../x", "name": "bad", "account_id": "abcdef13", "settings": {}},'
                    '{"protocol": "irc", "name": "dup", "account_id": "abcdef12", "settings": {}}, 5]}')
    assert [a.name for a in C.load_accounts(path)] == ["ok"]
    path.write_text("not json")
    assert C.load_accounts(path) == []


# --- the panel ---------------------------------------------------------------------------

def test_happy_the_panel_shows_messages_escaped_and_completes_nicks(ircd, tmp_path):
    from ui.chat_panel import ChatPanel

    server = ircd(caps=())
    path = tmp_path / "chat.json"
    account = C.Account(protocol="irc", name="test", settings={
        "server": "127.0.0.1", "port": server.port, "tls": I.TLS_OFF, "nick": "alice",
        "proxy": "none", "autojoin": ["#c"]})
    C.save_accounts([account], path)
    panel = ChatPanel(I.PROTOCOL, accounts_path=path)
    try:
        panel.show()
        client = panel.clients[account.account_id]
        client.connect_account()
        assert online(client) and wait_until(lambda: client.conversation("#c") is not None)
        server.add_member("#c", "bobby")
        assert wait_until(lambda: "bobby" in client.conversation("#c").members)
        view = panel.show_conversation(account.account_id, "#c")
        server.say_as("bobby", "#c", "<img src=http://evil/x> look https://example.org/a")
        assert wait_until(lambda: "evil" in view.view.toPlainText())
        assert "<img" in view.view.toPlainText()          # shown as text, not rendered
        assert 'href="https://example.org/a"' in view.view.toHtml()
        assert "<img" not in view.view.toHtml()            # nothing the sender wrote became markup
        view.input.setText("bo")
        view.input.complete()
        assert view.input.text() == "bobby: "
        panel.detach(account.account_id, "#c")
        assert (account.account_id, "#c") in panel.windows
        window = panel.windows[(account.account_id, "#c")]
        QApplication.processEvents()
        # the conversation is in the window, not an empty frame
        assert window.isVisible() and view.isVisible() and view.window() is window
        assert "evil" in view.view.toPlainText()
        window.findChild(QToolButton, "axCloseCorner").click()   # the window's own [x]
        assert wait_until(lambda: (account.account_id, "#c") not in panel.windows)
        assert panel.stack.indexOf(view) >= 0
        panel.detach(account.account_id, "#c")           # again, and Esc closes it
        window = panel.windows[(account.account_id, "#c")]
        QApplication.processEvents()
        assert view.isVisible()
        QTest.keyClick(window, Qt.Key.Key_Escape)
        assert wait_until(lambda: (account.account_id, "#c") not in panel.windows)
        assert panel.stack.indexOf(view) >= 0
    finally:
        panel.shutdown()
        panel.deleteLater()


def test_happy_the_extension_is_found_with_its_manifest():
    from core import extensions as EX

    infos = [e for e in EX.discover() if e.module_name == "irc" and e.source == "bundled"]
    assert infos and infos[0].name == "IRC"


def test_sad_a_client_reporting_after_its_panel_is_gone_does_not_raise(tmp_path):
    """A client lives on its own: once the panel (and its tree with the
    items) is destroyed, a late conversation_changed hit a deleted
    QTreeWidgetItem and an exception escaped into Qt."""
    from PyQt6 import sip

    from ui.chat_panel import ChatPanel

    path = tmp_path / "chat.json"
    account = C.Account(protocol="irc", name="test", settings={
        "server": "127.0.0.1", "port": 1, "tls": I.TLS_OFF, "nick": "alice", "proxy": "none"})
    C.save_accounts([account], path)
    panel = ChatPanel(I.PROTOCOL, accounts_path=path)
    client = panel.clients[account.account_id]
    sip.delete(panel)
    client.conversation_changed.emit(client.server_key)
    client.state_changed.emit("offline", "")
    QApplication.processEvents()


# --- the default proxy ----------------------------------------------------------------------

def _default_socks5(tmp_path, monkeypatch, routes):
    from proxy_testkit import FakeSocks5Server

    from core import proxy_settings as PS

    proxy = FakeSocks5Server(routes)
    path = tmp_path / "proxy.json"
    PS.save(PS.ProxyDefaults(proxy_type="socks5", host="127.0.0.1", port=proxy.port, bypass=[]), path)
    monkeypatch.setattr(PS, "SETTINGS_PATH", path)
    return proxy


def test_happy_the_default_proxy_carries_the_connection(ircd, clients, tmp_path, monkeypatch):
    """Round 3 checked every chat protocol for the XMPP bug (the default
    proxy ignored, a direct connection): IRC's connection and its
    certificate probe go through core.chat.open_stream - a recording SOCKS5
    listener sees them, and a refused tunnel is an error, not a direct
    connection."""
    from proxy_testkit import allow_loopback_proxy

    server = ircd()
    proxy = _default_socks5(tmp_path, monkeypatch, {("127.0.0.1", server.port): ("127.0.0.1", server.port)})
    try:
        with allow_loopback_proxy():
            client = clients(server, proxy="default")
            client.connect_account()
            assert online(client)
            assert proxy.connects == [("127.0.0.1", server.port)]
            client.disconnect_account()
            proxy.routes.clear()
            refused = clients(server, proxy="default", nick="bob")
            refused.connect_account()
            assert wait_until(lambda: refused.state == C.STATE_ERROR, 10)
            assert proxy.connects[-1] == ("127.0.0.1", server.port) and len(proxy.connects) >= 2
            assert not any("bob" in line for line in server.lines_of("bob"))
    finally:
        proxy.close()


def test_sad_member_nicks_from_the_server_are_shown_cleaned():
    """NAMES (353), JOIN and NICK put the server's nicks into the member
    list as they came: bidi and zero-width characters (``\\u202enimda``)
    reached the panel. Each member is shown by its nick made safe (as
    Matrix shows display names); the nick itself stays what commands
    address."""
    import asyncio

    account = C.Account(protocol="irc", name="t", settings={
        "server": "127.0.0.1", "port": 1, "tls": I.TLS_OFF, "nick": "alice", "proxy": "none"})
    client = I.IrcClient(account)
    try:
        client._add_conversation("#c", C.CONV_CHANNEL, "#c")

        async def feed():
            await client._on_353(I.parse_line(":srv 353 alice = #c :bob \u202enimda\u200b mallory\r\n"))
            await client._on_366(I.parse_line(":srv 366 alice #c :End\r\n"))
            await client._on_join(I.parse_line(":ev\u2066il!u@h JOIN #c\r\n"))
            await client._on_nick(I.parse_line(":bob!u@h NICK :\u202ebob2\r\n"))

        asyncio.run(feed())
        members = client.conversation("#c").members
        shown = sorted(m.display for m in members.values())
        assert shown == ["bob2", "evil", "mallory", "nimda"]
        assert "\u202enimda\u200b" in {m.name for m in members.values()}
    finally:
        client.shutdown()
