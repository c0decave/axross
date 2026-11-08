"""core.chat_xmpp against tests/fake_xmppd.py: TLS with a pinned
certificate, login, contacts, OMEMO 2 between two axross clients (the
server sees only the fallback text), trust (blind trust before
verification, manual), plain text on request, group chats; and its parts
on their own (SCE envelopes, the encrypted key store)."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("slixmpp")
pytest.importorskip("twomemo.etree")

from bluez_testkit import wait_until  # noqa: E402
from fake_ircd import self_signed  # noqa: E402
from fake_xmppd import FakeXmppd  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import chat as C  # noqa: E402
from core import chat_irc as I  # noqa: E402
from core import chat_xmpp as X  # noqa: E402


@pytest.fixture(autouse=True)
def _app():
    app = QApplication.instance() or QApplication([])
    C._SESSION_SECRETS.clear()
    yield app
    C._SESSION_SECRETS.clear()


@pytest.fixture
def server(tmp_path):
    cert, key, der = self_signed(tmp_path)
    srv = FakeXmppd((cert, key), {"alice": "pw-a", "bob": "pw-b", "carol": "pw-c"}).start()
    srv.fingerprint = I.fingerprint_of(der)
    yield srv
    srv.stop()


@pytest.fixture
def make(server):
    made = []

    def build(user: str, password: str | None = None, **settings):
        account = C.Account(protocol="xmpp", name=user, settings={
            "jid": f"{user}@localhost", "server": "127.0.0.1", "port": server.port, "proxy": "none",
            "fingerprint": server.fingerprint, "starttls_only": True, **settings})
        C._SESSION_SECRETS[(account.keyring_profile, "password")] = password or f"pw-{user[0]}"
        C._SESSION_SECRETS[(account.keyring_profile, "store_key")] = __import__("base64").b64encode(
            os.urandom(32)).decode()
        client = X.XmppClient(account)
        asked = []
        client.request.connect(asked.append)
        client.asked = asked
        made.append(client)
        return client
    yield build
    for client in made:
        client.shutdown()


def online(client, timeout=40):
    ok = wait_until(lambda: client.state == C.STATE_ONLINE, timeout)
    if not ok:
        print(client.state, client.detail, [m.text for m in client.history(client.server_key)])
    return ok


def omemo_ready(client, timeout=30):
    return wait_until(lambda: any("OMEMO ready" in m.text for m in client.history(client.server_key)), timeout)


def texts(client, key):
    return [m.text for m in client.history(key)]


# --- parts ----------------------------------------------------------------------------------

def test_happy_an_sce_envelope_round_trips():
    data = X.sce_envelope("hello <&> there", "alice@x", "bob@x")
    assert X.parse_envelope(data, "alice@x/phone") == "hello <&> there"


def test_sad_an_envelope_from_someone_else_is_refused():
    data = X.sce_envelope("I am alice", "mallory@x", "bob@x")
    with pytest.raises(ValueError):
        X.parse_envelope(data, "alice@x")


def test_sad_the_key_store_cannot_be_read_with_another_key(tmp_path):
    path = tmp_path / "omemo.bin"
    store = X.EncryptedJsonStore(path, os.urandom(32))
    store.data["k"] = 1
    store.save()
    assert oct(path.stat().st_mode & 0o777) == "0o600"
    assert b'"k"' not in path.read_bytes()
    with pytest.raises(C.ChatError):
        X.EncryptedJsonStore(path, os.urandom(32))


def test_sad_jids_and_fingerprints_are_checked():
    assert X.validate({"jid": "alice"})
    assert X.validate({"jid": "alice@x", "fingerprint": "zz"})
    assert X.validate({"jid": "alice@x"}) is None


# --- a session ------------------------------------------------------------------------------

def test_happy_login_contacts_and_an_omemo_chat(server, make):
    alice, bob = make("alice"), make("bob")
    alice.connect_account()
    bob.connect_account()
    assert online(alice) and online(bob)
    assert omemo_ready(alice) and omemo_ready(bob)
    assert wait_until(lambda: "bob@localhost" in alice.conversation(alice.server_key).members, 10)
    alice.open_direct("bob@localhost")
    assert wait_until(lambda: alice.conversation("bob@localhost") is not None)
    assert wait_until(lambda: alice.conversation("bob@localhost").encryption == C.ENC_E2E_UNTRUSTED, 20)
    alice.send("bob@localhost", "secret via omemo")
    assert wait_until(lambda: "secret via omemo" in texts(bob, "alice@localhost"), 30)
    got = [m for m in bob.history("alice@localhost") if m.text == "secret via omemo"][0]
    assert got.encryption == C.ENC_E2E_UNTRUSTED          # blind trust before verification
    sent = [s for s in server.sent_by("alice") if "urn:xmpp:omemo:2" in s and "<ns0:message" in s or
            ("message" in s and "urn:xmpp:omemo:2" in s)]
    assert sent and not any("secret via omemo" in s for s in server.sent_by("alice"))
    assert any(X.FALLBACK_BODY in s for s in sent)


def test_happy_a_verified_device_makes_the_chat_verified(server, make):
    alice, bob = make("alice"), make("bob")
    alice.connect_account()
    bob.connect_account()
    assert online(alice) and online(bob) and omemo_ready(alice) and omemo_ready(bob)
    alice.open_direct("bob@localhost")
    assert wait_until(lambda: alice.conversation("bob@localhost") is not None
                      and alice.conversation("bob@localhost").encryption == C.ENC_E2E_UNTRUSTED, 20)
    devices = alice.runner.submit(alice.devices_of("bob@localhost")).result(10)
    assert len(devices) == 1 and devices[0].trust == X.TRUST_BLIND or devices[0].trust == X.TRUST_UNDECIDED
    alice.set_trust("bob@localhost", devices[0].identity_key, X.TRUST_VERIFIED)
    assert wait_until(lambda: alice.conversation("bob@localhost").encryption == C.ENC_E2E, 20)
    alice.send("bob@localhost", "verified now")
    assert wait_until(lambda: [m for m in alice.history("bob@localhost") if m.text == "verified now"], 10)
    assert [m for m in alice.history("bob@localhost") if m.text == "verified now"][0].encryption == C.ENC_E2E


def test_sad_manual_trust_asks_and_sends_nothing_until_answered(server, make):
    carol, bob = make("carol", trust=X.POLICY_MANUAL), make("bob")
    carol.connect_account()
    bob.connect_account()
    assert online(carol) and online(bob) and omemo_ready(carol) and omemo_ready(bob)
    carol.open_direct("bob@localhost")
    assert wait_until(lambda: carol.conversation("bob@localhost") is not None)
    carol.send("bob@localhost", "first try")
    assert wait_until(lambda: any(isinstance(r, X.TrustRequest) for r in carol.asked), 20)
    assert wait_until(lambda: any("decide" in t for t in texts(carol, "bob@localhost")), 10)
    request = next(r for r in carol.asked if isinstance(r, X.TrustRequest))
    carol.answer(request, True)
    assert wait_until(lambda: carol.conversation("bob@localhost").encryption == C.ENC_E2E_UNTRUSTED, 20)
    carol.send("bob@localhost", "second try")
    assert wait_until(lambda: "second try" in texts(bob, "carol@localhost"), 30)
    assert "first try" not in texts(bob, "carol@localhost")


def test_happy_plain_text_only_on_request(server, make):
    alice, bob = make("alice"), make("bob")
    alice.connect_account()
    bob.connect_account()
    assert online(alice) and online(bob) and omemo_ready(alice) and omemo_ready(bob)
    alice.open_direct("bob@localhost")
    assert wait_until(lambda: alice.conversation("bob@localhost") is not None)
    alice.send("bob@localhost", "/plain")
    assert wait_until(lambda: alice.conversation("bob@localhost").encryption == C.ENC_TRANSPORT, 10)
    alice.send("bob@localhost", "readable by the server")
    assert wait_until(lambda: "readable by the server" in texts(bob, "alice@localhost"), 20)
    assert any("readable by the server" in s for s in server.sent_by("alice"))
    assert [m for m in bob.history("alice@localhost")
            if m.text == "readable by the server"][0].encryption == C.ENC_TRANSPORT


def test_sad_another_certificate_than_the_pinned_one_ends_before_the_login(server, make):
    mallory = make("alice", fingerprint="00" * 32)
    mallory.connect_account()
    assert wait_until(lambda: mallory.state == C.STATE_ERROR, 20)
    assert not any("auth" in s for s in server.sent_by("alice"))
    assert server.sent_by("alice") == []
    assert any(isinstance(r, I.CertificateRequest) for r in mallory.asked)


def test_sad_a_wrong_password_is_an_error(server, make):
    alice = make("alice", password="wrong")
    alice.connect_account()
    assert wait_until(lambda: alice.state == C.STATE_ERROR, 20)
    assert any("refused the login" in t for t in texts(alice, alice.server_key))


def test_happy_group_chat(server, make):
    alice, bob = make("alice"), make("bob")
    alice.connect_account()
    bob.connect_account()
    assert online(alice) and online(bob)
    room = "lobby@conference.localhost"
    alice.join(room)
    bob.join(f"{room} bobby")
    assert wait_until(lambda: alice.conversation(room) is not None and "bobby" in alice.conversation(room).members, 20)
    bob.send(room, "hello room")
    assert wait_until(lambda: "hello room" in texts(alice, room), 20)
    assert alice.conversation(room).encryption == C.ENC_TRANSPORT
    assert any("not end-to-end encrypted" in t for t in texts(alice, room))


# --- the default proxy ----------------------------------------------------------------------

@pytest.fixture
def default_socks5(tmp_path, monkeypatch, server):
    """axross's default proxy is a recording loopback SOCKS5 server that
    relays to the fake XMPP server (the SSRF guard lets the loopback proxy
    through for the test)."""
    from proxy_testkit import FakeSocks5Server, allow_loopback_proxy

    from core import proxy_settings as PS

    proxy = FakeSocks5Server({("127.0.0.1", server.port): ("127.0.0.1", server.port)})
    path = tmp_path / "proxy.json"
    PS.save(PS.ProxyDefaults(proxy_type="socks5", host="127.0.0.1", port=proxy.port, bypass=[]), path)
    monkeypatch.setattr(PS, "SETTINGS_PATH", path)
    with allow_loopback_proxy():
        yield proxy
    proxy.close()


def test_happy_the_default_proxy_carries_the_connection(server, make, default_socks5):
    """slixmpp 1.17 has no proxy support: the ``use_proxy`` / ``proxy_config``
    attributes axross set were ignored and the client logged in directly
    while the default SOCKS5 proxy applied."""
    alice = make("alice", proxy="default")
    alice.connect_account()
    assert online(alice)
    assert ("127.0.0.1", server.port) in default_socks5.connects


def test_sad_a_proxy_that_fails_fails_the_login_never_a_direct_one(server, make, default_socks5):
    """A proxy that refuses the tunnel ends in an error; the server sees no
    connection (no direct fallback, no retry around the proxy)."""
    default_socks5.routes.clear()
    alice = make("alice", proxy="default")
    alice.connect_account()
    assert wait_until(lambda: alice.state == C.STATE_ERROR, 20)
    assert default_socks5.connects and server.sessions == []
    assert any("through the proxy failed" in t for t in texts(alice, alice.server_key))


def test_sad_the_certificate_probe_goes_through_the_proxy_too(server, default_socks5):
    """probe_certificate opened a plain asyncio connection, around the proxy."""
    import asyncio

    der = asyncio.run(X.probe_certificate("127.0.0.1", server.port, "localhost"))
    assert der and I.fingerprint_of(der) == server.fingerprint
    assert default_socks5.connects == [("127.0.0.1", server.port)]
    default_socks5.routes.clear()
    # A refused tunnel gives nothing - a direct connection would get the certificate.
    assert asyncio.run(X.probe_certificate("127.0.0.1", server.port, "localhost")) == b""
    assert len(default_socks5.connects) == 2


def test_sad_group_chat_nicks_are_shown_cleaned():
    """A room's occupant nick (the resource of the presence's JID) went
    into the member list as it came - bidi and zero-width characters
    reached the panel. It is shown made safe, as Matrix shows names."""
    account = C.Account(protocol="xmpp", name="a", settings={"jid": "a@localhost", "proxy": "none"})
    client = X.XmppClient(account)

    class _From(str):
        resource = "\u202enimda\u200b"

    presence = {"from": _From("room@conference.localhost/x"), "type": "available",
                "muc": {"role": "participant"}}
    try:
        client._add_conversation("room@conference.localhost", C.CONV_CHANNEL, "room")
        client._on_groupchat_presence(presence)
        (member,) = client.conversation("room@conference.localhost").members.values()
        assert member.display == "nimda" and member.name == "\u202enimda\u200b"
    finally:
        client.shutdown()
