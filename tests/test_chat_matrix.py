"""core.chat_matrix: its parts on their own, and two axross clients
talking end-to-end encrypted through a real Synapse (tests/synapse_testkit.py,
only with AXROSS_TEST_SYNAPSE): an encrypted direct chat, interactive
verification with matching emoji, the "block" policy, the login kept
across a restart, room keys exported and imported."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from bluez_testkit import wait_until  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import chat as C  # noqa: E402
from core import chat_matrix as M  # noqa: E402

import synapse_testkit as ST  # noqa: E402


@pytest.fixture(autouse=True)
def _app():
    app = QApplication.instance() or QApplication([])
    C._SESSION_SECRETS.clear()
    yield app
    C._SESSION_SECRETS.clear()


# --- parts -----------------------------------------------------------------------------

def test_happy_user_ids_and_fingerprints():
    assert M.full_user_id("alice", "https://example.org") == "@alice:example.org"
    assert M.full_user_id("@bob:x.y", "https://example.org") == "@bob:x.y"
    assert M.fingerprint_text("abcdefgh") == "abcd efgh"


def test_sad_plain_http_only_to_this_machine():
    assert M.validate({"homeserver": "http://matrix.org", "user": "a"})
    assert M.validate({"homeserver": "http://127.0.0.1:8008", "user": "a"}) is None
    assert M.validate({"homeserver": "matrix.org", "user": "a"}) is None
    assert M.validate({"homeserver": "", "user": "a"})
    assert M.validate({"homeserver": "https://matrix.org", "user": "@a b:x"})
    assert M.loopback_http("http://localhost:1/") and not M.loopback_http("http://10.0.0.1/")


def test_happy_nio_with_encryption_is_there():
    assert M.nio_missing() is None


# --- over Synapse ------------------------------------------------------------------------

needs_synapse = pytest.mark.skipif(ST.synapse_python() is None, reason="AXROSS_TEST_SYNAPSE not set")


@pytest.fixture(scope="module")
def synapse(tmp_path_factory):
    server = ST.Synapse(ST.synapse_python(), tmp_path_factory.mktemp("synapse")).start()
    yield server
    server.stop()


@pytest.fixture
def make(synapse):
    made = []

    def build(user: str, **settings):
        # a user of its own per test: an earlier test's direct chat would be reused
        synapse.count = getattr(synapse, "count", 0) + 1
        user = f"{user}{synapse.count}"
        user_id = f"@{user}:localhost"
        if not getattr(synapse, "users", None):
            synapse.users = set()
        if user not in synapse.users:
            synapse.register(user, "pw-" + user)
            synapse.users.add(user)
        account = C.Account(protocol="matrix", name=user, settings={
            "homeserver": synapse.url, "user": user_id, "proxy": "none", **settings})
        C._SESSION_SECRETS[(account.keyring_profile, "password")] = "pw-" + user
        client = M.MatrixClient(account)
        asked = []
        client.request.connect(asked.append)
        client.asked = asked
        made.append(client)
        return client
    yield build
    for client in made:
        client.shutdown()


def online(client, timeout=60):
    ok = wait_until(lambda: client.state == C.STATE_ONLINE, timeout)
    if not ok:
        print(client.state, client.detail, texts(client, client.server_key))
    return ok


def texts(client, key):
    return [m.text for m in client.history(key)]


def direct_room(a, b):
    """a starts an encrypted direct chat with b; b accepts. The room id."""
    a.open_direct(b.user_id)
    assert wait_until(lambda: any(isinstance(r, M.InviteRequest) for r in b.asked), 60)
    invite = next(r for r in b.asked if isinstance(r, M.InviteRequest))
    b.answer(invite, True)
    assert wait_until(lambda: b.conversation(invite.room_id) is not None, 60)
    assert wait_until(lambda: a.conversation(invite.room_id) is not None
                      and b.user_id in a.conversation(invite.room_id).members, 60)
    return invite.room_id


@needs_synapse
def test_happy_an_encrypted_direct_chat(make):
    alice, bob = make("alice"), make("bob")
    alice.connect_account()
    bob.connect_account()
    assert online(alice) and online(bob)
    room = direct_room(alice, bob)
    assert wait_until(lambda: alice.conversation(room).encryption in (C.ENC_E2E_UNTRUSTED, C.ENC_E2E), 30)
    alice.send(room, "secret hello")
    assert wait_until(lambda: "secret hello" in texts(bob, room), 60)
    message = [m for m in bob.history(room) if m.text == "secret hello"][0]
    assert message.encryption == C.ENC_E2E_UNTRUSTED     # bob has not verified alice's device
    assert bob.conversation(room).encryption == C.ENC_E2E_UNTRUSTED


@needs_synapse
def test_happy_verification_with_matching_emoji(make):
    alice, bob = make("alice"), make("bob")
    alice.connect_account()
    bob.connect_account()
    assert online(alice) and online(bob)
    room = direct_room(alice, bob)
    alice.verify(bob.user_id, bob.account.settings["device_id"])
    assert wait_until(lambda: any(isinstance(r, M.VerificationRequest) for r in bob.asked), 60)
    bob.answer(next(r for r in bob.asked if isinstance(r, M.VerificationRequest)), True)
    assert wait_until(lambda: any(isinstance(r, M.SasRequest) for r in alice.asked)
                      and any(isinstance(r, M.SasRequest) for r in bob.asked), 60)
    sas_a = next(r for r in alice.asked if isinstance(r, M.SasRequest))
    sas_b = next(r for r in bob.asked if isinstance(r, M.SasRequest))
    assert sas_a.emoji == sas_b.emoji and len(sas_a.emoji) == 7
    alice.answer(sas_a, True)
    bob.answer(sas_b, True)
    assert wait_until(lambda: any(isinstance(r, M.VerificationResult) and r.ok for r in alice.asked)
                      and any(isinstance(r, M.VerificationResult) and r.ok for r in bob.asked), 60)
    assert [d.trust for d in alice.devices(bob.user_id)] == ["verified"]
    assert [d.trust for d in bob.devices(alice.user_id)] == ["verified"]
    alice.send(room, "now verified")
    assert wait_until(lambda: "now verified" in texts(bob, room), 60)
    assert [m for m in bob.history(room) if m.text == "now verified"][0].encryption == C.ENC_E2E


@needs_synapse
def test_sad_mismatching_emoji_verify_nothing(make):
    alice, bob = make("alice"), make("bob")
    alice.connect_account()
    bob.connect_account()
    assert online(alice) and online(bob)
    direct_room(alice, bob)
    alice.verify(bob.user_id)
    assert wait_until(lambda: any(isinstance(r, M.VerificationRequest) for r in bob.asked), 60)
    bob.answer(next(r for r in bob.asked if isinstance(r, M.VerificationRequest)), True)
    assert wait_until(lambda: any(isinstance(r, M.SasRequest) for r in bob.asked), 60)
    bob.answer(next(r for r in bob.asked if isinstance(r, M.SasRequest)), False)
    assert wait_until(lambda: any(isinstance(r, M.VerificationResult) and not r.ok for r in alice.asked), 60)
    assert [d.trust for d in alice.devices(bob.user_id)] == ["unset"]


@needs_synapse
def test_sad_block_sends_nothing_to_unverified_devices(make):
    carol, dave = make("carol", unverified=M.UNVERIFIED_BLOCK), make("dave")
    carol.connect_account()
    dave.connect_account()
    assert online(carol) and online(dave)
    room = direct_room(carol, dave)
    carol.send(room, "should not go")
    assert wait_until(lambda: any("nobody verified" in t for t in texts(carol, room)), 30)
    dave_device = dave.account.settings["device_id"]
    carol.set_trust(dave.user_id, dave_device, "ignored")
    assert wait_until(lambda: [d.trust for d in carol.devices(dave.user_id)] == ["ignored"], 10)
    carol.send(room, "now it goes")
    assert wait_until(lambda: "now it goes" in texts(dave, room), 60)
    assert "should not go" not in texts(dave, room)


@needs_synapse
def test_happy_the_login_and_keys_survive_a_restart(make, tmp_path):
    erin, frank = make("erin"), make("frank")
    erin.connect_account()
    frank.connect_account()
    assert online(erin) and online(frank)
    room = direct_room(erin, frank)
    device = erin.account.settings["device_id"]
    erin.shutdown()
    C._SESSION_SECRETS.pop((erin.account.keyring_profile, "password"))   # the token must do
    again = M.MatrixClient(erin.account)
    again.connect_account()
    try:
        assert online(again)
        assert again.account.settings["device_id"] == device
        frank.send(room, "after the restart")
        assert wait_until(lambda: "after the restart" in texts(again, room), 60)
        assert [m for m in again.history(room) if m.text == "after the restart"][0].encryption != C.ENC_FAILED
        path = str(tmp_path / "keys.txt")
        again.export_keys(path, "long passphrase")
        assert wait_until(lambda: os.path.exists(path) and os.path.getsize(path) > 0, 30)
        assert oct(os.stat(path).st_mode & 0o777) == "0o600"
        again.import_keys(path, "wrong passphrase")
        assert wait_until(lambda: any("Could not import" in t for t in texts(again, again.server_key)), 30)
        again.import_keys(path, "long passphrase")
        assert wait_until(lambda: any("imported" in t for t in texts(again, again.server_key)), 30)
    finally:
        again.shutdown()


# --- the default proxy ----------------------------------------------------------------------

def test_happy_the_default_proxy_carries_the_connection(tmp_path, monkeypatch):
    """Round 3 checked every chat protocol for the XMPP bug (the default
    proxy ignored, a direct connection): nio's HTTP session for the
    homeserver goes through the default SOCKS5 proxy - a recording
    listener sees the request - and a refused tunnel never ends in a
    direct request."""
    import asyncio
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    from proxy_testkit import FakeSocks5Server

    from core import proxy_settings as PS

    if M.nio_missing():
        pytest.skip("matrix-nio is not installed")
    hits = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            hits.append(self.path)
            body = b'{"versions": ["v1.1"]}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    port = httpd.server_address[1]
    proxy = FakeSocks5Server({("127.0.0.1", port): ("127.0.0.1", port)})
    path = tmp_path / "proxy.json"
    PS.save(PS.ProxyDefaults(proxy_type="socks5", host="127.0.0.1", port=proxy.port, bypass=[]), path)
    monkeypatch.setattr(PS, "SETTINGS_PATH", path)
    account = C.Account(protocol="matrix", name="a", settings={
        "homeserver": f"http://127.0.0.1:{port}", "user": "alice", "proxy": "default"})
    client = M.MatrixClient(account)

    async def versions():
        nio = client._make_nio("")
        try:
            return await nio.send("GET", "/_matrix/client/versions")
        finally:
            await nio.close()

    try:
        response = asyncio.run(versions())
        assert response.status == 200
        assert proxy.connects == [("127.0.0.1", port)] and hits == ["/_matrix/client/versions"]
        proxy.routes.clear()
        with pytest.raises(Exception):  # noqa: B017 - aiohttp_socks' own error type
            asyncio.run(versions())
        assert len(proxy.connects) == 2 and len(hits) == 1
    finally:
        client.shutdown()
        proxy.close()
        httpd.shutdown()
