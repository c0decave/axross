"""XMPP (Jabber) for the chat panel (resources/extensions/xmpp.py), on
slixmpp, with OMEMO end-to-end encryption.

* TLS always (STARTTLS or direct TLS), the certificate checked; a server
  with a self-signed certificate is trusted only by its pinned SHA-256
  fingerprint - checked right after the handshake, before the login.
  SASL (SCRAM preferred by slixmpp); never a plain-text connection.
* Contacts (roster) with presence, one-to-one chats, group chats (MUC,
  XEP-0045), message carbons (XEP-0280: what you send from another client
  shows here too), ping.
* OMEMO (XEP-0384) for one-to-one chats: OMEMO 2 (``urn:xmpp:omemo:2``,
  python-omemo + twomemo, MIT) with Stanza Content Encryption (XEP-0420);
  the old OMEMO (``eu.siacs.conversations.axolotl``) as well when the user
  installed the ``oldmemo`` package (AGPL-3.0, so never bundled). The glue
  to slixmpp - bundles and device lists over PEP, sending, trust - is
  axross's own. The keys are kept encrypted (AES-GCM, the key in the
  keyring) under ``~/.local/state/axross/chat/xmpp-<id>/``.
* Trust: "blind trust before verification" (as Conversations and Dino):
  new devices of a contact are used until one of its devices is verified;
  from then on a new device is undecided and asked. Or "manual": every new
  device is asked. A device is verified by comparing its fingerprint.
  Group chats are not OMEMO-encrypted here (TLS to the server only) - the
  panel says so.

Message bodies are plain text; XHTML-IM is not rendered.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import re
import secrets
import ssl
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

from core import chat as C
from core.chat_irc import CertificateRequest, fingerprint_of, normalise_fingerprint

log = logging.getLogger(__name__)

NS_OMEMO2 = "urn:xmpp:omemo:2"
NS_OLDMEMO = "eu.siacs.conversations.axolotl"
NS_SCE = "urn:xmpp:sce:1"
NS_EME = "urn:xmpp:eme:0"
NS_HINTS = "urn:xmpp:hints"
NS_CLIENT = "jabber:client"
FALLBACK_BODY = "[This message is OMEMO encrypted - your client cannot show it]"
TRUST_VERIFIED = "verified"
TRUST_BLIND = "blindly_trusted"
TRUST_DISTRUSTED = "distrusted"
TRUST_UNDECIDED = "undecided"
POLICY_BTBV = "btbv"
POLICY_MANUAL = "manual"
_BARE_JID = re.compile(r"[^@/\s]{1,1023}@[^@/\s]{1,1023}")
_SASL_NS = "urn:ietf:params:xml:ns:xmpp-sasl"


class _SaslLogFilter(logging.Filter):
    """slixmpp logs every stanza it sends and receives at DEBUG - the SASL
    <auth> / <response> too, whose base64 holds the password (PLAIN) or
    its proof. Those records keep their direction, not their content."""

    def filter(self, record: logging.LogRecord) -> bool:
        if any(_SASL_NS in str(arg) for arg in (record.args or ())) or _SASL_NS in str(record.msg):
            record.msg, record.args = "%s", ("(an XMPP SASL login stanza - not logged)",)
        return True


def install_log_redaction() -> None:
    """Keep the SASL stanzas out of slixmpp's DEBUG log (once)."""
    target = logging.getLogger("slixmpp.xmlstream.xmlstream")
    if not any(isinstance(f, _SaslLogFilter) for f in target.filters):
        target.addFilter(_SaslLogFilter())


#: The SASL mechanisms an account may log in with: each refuses a stream
#: that is not encrypted (slixmpp's LOGIN and X-* would send the password).
SAFE_SASL_MECHANISMS = ("SCRAM-SHA-512-PLUS", "SCRAM-SHA-256-PLUS", "SCRAM-SHA-1-PLUS",
                        "SCRAM-SHA-512", "SCRAM-SHA-256", "SCRAM-SHA-1", "PLAIN")
_ROOM_JID = _BARE_JID


def libraries_missing(*, load: bool = True) -> str | None:
    """Why the XMPP client cannot run here, or None. *load* False only
    looks whether the packages are installed, without importing them (the
    OMEMO libraries take a third of a second; the connect imports them)."""
    if not load:
        return None if C.modules_installed("omemo", "slixmpp", "twomemo") else _LIBRARIES_MISSING
    try:
        import omemo  # noqa: F401
        import slixmpp  # noqa: F401
        import twomemo  # noqa: F401
    except ImportError:
        return _LIBRARIES_MISSING
    return None


# Help > Features… installs it, as for every other extra.
_LIBRARIES_MISSING = "XMPP needs slixmpp and OMEMO: install them in Help → Features… (Matrix and XMPP chat)"


def oldmemo_available() -> bool:
    try:
        import oldmemo  # noqa: F401
        import oldmemo.etree  # noqa: F401
    except ImportError:
        return False
    return True


def bare(jid: str) -> str:
    return str(jid).split("/", 1)[0].lower()


def fingerprint_text(identity_key: bytes) -> str:
    hexed = identity_key.hex()
    return " ".join(hexed[i:i + 8] for i in range(0, len(hexed), 8))


# --- requests to the user -------------------------------------------------------------------

@dataclass
class TrustRequest:
    """New devices of *jid* that nobody decided on: trust them?"""
    jid: str
    devices: list = field(default_factory=list)   # [DeviceInfo]
    kind: str = "omemo-trust"


@dataclass
class SubscriptionRequest:
    jid: str
    kind: str = "subscription"


@dataclass
class DeviceInfo:
    user_id: str          # bare JID
    device_id: str
    name: str
    fingerprint: str
    trust: str
    identity_key: bytes = b""
    namespaces: tuple = ()


# --- the key store ---------------------------------------------------------------------------

class EncryptedJsonStore:
    """python-omemo's storage as one JSON document, AES-GCM encrypted with a
    key from the keyring, written atomically 0600."""

    def __init__(self, path, key: bytes) -> None:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        self.path = path
        self._aead = AESGCM(key)
        self.data: dict = {}
        try:
            raw = path.read_bytes()
        except FileNotFoundError:
            return
        if len(raw) < 13:
            raise C.ChatError("The OMEMO key store is damaged.")
        try:
            self.data = json.loads(self._aead.decrypt(raw[:12], raw[12:], b"axross-omemo"))
        except Exception as exc:  # noqa: BLE001 - wrong key or tampered
            raise C.ChatError("The OMEMO key store cannot be opened (another keyring, or tampered with).") from exc

    def save(self) -> None:
        nonce = secrets.token_bytes(12)
        blob = nonce + self._aead.encrypt(nonce, json.dumps(self.data).encode(), b"axross-omemo")
        tmp = self.path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(blob)
        os.replace(tmp, self.path)


def make_storage(store: EncryptedJsonStore):
    import omemo

    class Storage(omemo.Storage):
        def __init__(self) -> None:
            super().__init__()

        async def _load(self, key: str):
            if key in store.data:
                return omemo.Just(store.data[key])
            return omemo.Nothing()

        async def _store(self, key: str, value) -> None:
            store.data[key] = value
            store.save()

        async def _delete(self, key: str) -> None:
            store.data.pop(key, None)
            store.save()

    return Storage()


# --- XEP-0420 stanza content encryption ------------------------------------------------------

def sce_envelope(body: str, sender: str, recipient: str) -> bytes:
    env = ET.Element(f"{{{NS_SCE}}}envelope")
    content = ET.SubElement(env, f"{{{NS_SCE}}}content")
    ET.SubElement(content, f"{{{NS_CLIENT}}}body").text = body
    ET.SubElement(env, f"{{{NS_SCE}}}rpad").text = base64.b64encode(
        secrets.token_bytes(secrets.randbelow(40) + 1)).decode()[:secrets.randbelow(200) + 1]
    ET.SubElement(env, f"{{{NS_SCE}}}time", stamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    ET.SubElement(env, f"{{{NS_SCE}}}to", jid=recipient)
    ET.SubElement(env, f"{{{NS_SCE}}}from", jid=sender)
    return ET.tostring(env)


def parse_envelope(data: bytes, sender: str) -> str:
    """The body of an SCE envelope; refused when the envelope names another
    sender than the stanza (a message replayed from someone else)."""
    if len(data) > 1_000_000:
        raise ValueError("envelope too large")
    env = ET.fromstring(data)  # small, no DTD: ElementTree does not resolve external entities
    if env.tag != f"{{{NS_SCE}}}envelope":
        raise ValueError("not an SCE envelope")
    frm = env.find(f"{{{NS_SCE}}}from")
    if frm is None or bare(frm.get("jid", "")) != bare(sender):
        raise ValueError("the envelope names another sender")
    body = env.find(f"{{{NS_SCE}}}content/{{{NS_CLIENT}}}body")
    return body.text or "" if body is not None else ""


# --- the client --------------------------------------------------------------------------------

class XmppClient(C.ChatClient):
    protocol = "xmpp"
    supports_room_list = True
    e2e_scheme = "OMEMO"
    commands = ("join", "leave", "msg", "me", "topic", "nick", "add", "remove", "devices", "trust",
                "distrust", "plain", "omemo", "help")
    extra_secrets = ("store_key",)

    def __init__(self, account: C.Account, parent=None) -> None:
        super().__init__(account, parent)
        s = account.settings
        self.jid = bare(str(s.get("jid", "")).strip())
        self.resource = re.sub(r"[^\w.-]", "", str(s.get("resource", "") or "axross"))[:40] or "axross"
        self.host = str(s.get("server", "")).strip()
        try:
            self.port = int(s.get("port") or 0)
        except (TypeError, ValueError):
            self.port = 0
        self.policy = s.get("trust") if s.get("trust") in (POLICY_BTBV, POLICY_MANUAL) else POLICY_BTBV
        self.xmpp = None
        self.omemo = None
        self._plain: set[str] = set()       # conversations the user switched to plain text
        self._rooms: dict[str, str] = {}    # room jid -> our nick
        self._want_online = False
        self._session_ready: asyncio.Event | None = None
        self._update_conversation(self.server_key, title=account.name or self.jid or "XMPP")

    # -- connect -----------------------------------------------------------------------------------
    def _ssl_context(self, pinned: str) -> ssl.SSLContext:
        if pinned:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE        # the fingerprint below is the check
        else:
            from core.tls_context import client_tls_context

            ctx = client_tls_context(True, label="XMPP")
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        return ctx

    async def _connect(self) -> None:
        missing = libraries_missing()
        if missing:
            raise C.ChatError(missing)
        if not _BARE_JID.fullmatch(self.jid):
            raise C.ChatError(f"{self.jid!r} is not a Jabber ID (name@server).")
        password = C.account_secret(self.account, "password")
        if not password:
            raise C.ChatError("The account has no password stored.")
        install_log_redaction()
        self._want_online = True
        pinned = normalise_fingerprint(str(self.account.settings.get("fingerprint", "")))
        xmpp = _client_class()(f"{self.jid}/{self.resource}", password)
        xmpp.ssl_context = self._ssl_context(pinned)
        xmpp.enable_plaintext = False
        # enable_plaintext only picks the ports: a stream whose STARTTLS an
        # attacker stripped goes on in cleartext, and slixmpp's LOGIN (or
        # X-*) mechanisms send the password without asking whether the
        # stream is encrypted. SCRAM and PLAIN refuse an unencrypted one
        # (unencrypted_scram / unencrypted_plain are off): with only those,
        # a stream without TLS ends in "no login method", never the password.
        xmpp.plugin["feature_mechanisms"].use_mechs = set(SAFE_SASL_MECHANISMS)
        xmpp.enable_direct_tls = not self.account.settings.get("starttls_only", False)
        self._proxy = None
        if self.account.settings.get("proxy") != "none":
            self._proxy = self._apply_proxy(xmpp)
        for plugin in ("xep_0030", "xep_0004", "xep_0060", "xep_0163", "xep_0199", "xep_0203", "xep_0280",
                       "xep_0045", "xep_0334", "xep_0380"):
            xmpp.register_plugin(plugin)
        xmpp.plugin["xep_0199"].enable_keepalive(interval=120, timeout=60)
        self.xmpp = xmpp
        self._session_ready = asyncio.Event()
        self._pinned = pinned
        xmpp.add_event_handler("ssl_cert", self._on_cert)
        xmpp.add_event_handler("ssl_invalid_chain", self._on_invalid_chain)
        xmpp.add_event_handler("session_start", self._on_session_start)
        xmpp.add_event_handler("failed_auth", self._on_failed_auth)
        xmpp.add_event_handler("no_auth", self._on_no_auth)
        xmpp.add_event_handler("disconnected", self._on_disconnected)
        xmpp.add_event_handler("message", self._on_message)
        xmpp.add_event_handler("carbon_received", self._on_carbon)
        xmpp.add_event_handler("carbon_sent", self._on_carbon)
        xmpp.add_event_handler("groupchat_message", self._on_groupchat)
        xmpp.add_event_handler("groupchat_presence", self._on_groupchat_presence)
        xmpp.add_event_handler("changed_status", self._on_presence)
        xmpp.add_event_handler("roster_update", self._on_roster)
        xmpp.add_event_handler("presence_subscribe", self._on_subscribe)
        xmpp.add_event_handler("pubsub_publish", self._on_pep)
        xmpp.add_event_handler(PROXY_FAILED_EVENT, self._on_proxy_failed)
        self._set_state(C.STATE_CONNECTING, self.host or self.jid.split("@", 1)[1])
        xmpp.connect(*self._connect_address())
        try:
            await asyncio.wait_for(self._session_ready.wait(), 60)
        except asyncio.TimeoutError:
            xmpp.disconnect()
            if self.state != C.STATE_ERROR:
                raise C.ChatError("The server did not finish the login within 60 s.")

    def configured_link_security(self):
        from core import conn_security as CS

        how = "certificate pinned by its fingerprint" if self.account.settings.get("fingerprint") \
            else "certificate verified"
        return CS.SecurityInfo(CS.LEVEL_TLS, f"XMPP over TLS (never without), {how}")

    def _read_link_info(self):
        """The negotiated TLS of the stream (slixmpp's asyncio transport),
        None when it cannot be read."""
        from core import conn_security as CS

        transport = getattr(self.xmpp, "transport", None)
        ssl_object = transport.get_extra_info("ssl_object") if transport is not None else None
        if transport is not None and ssl_object is None and not transport.is_closing():
            # Connected, and not over TLS: say so, never the configured claim.
            return CS.SecurityInfo(CS.LEVEL_CLEARTEXT, "XMPP without TLS - " + CS._CLEAR, True)
        extra = (f"Certificate SHA-256: {self._last_fingerprint}",) \
            if getattr(self, "_last_fingerprint", "") else ()
        info = CS.tls_socket(ssl_object, verified=True, what="XMPP", extra=extra)
        if info is not None and getattr(self, "_pinned", "") and info.level == CS.LEVEL_TLS:
            info = CS.SecurityInfo(info.level, info.summary.replace(
                "certificate verified", "certificate pinned by its fingerprint"), True, info.details)
        return info

    async def _room_list(self, rid: int, search: str) -> None:
        """The rooms of the server's group chat service (XEP-0030 disco#items
        of the item whose identity is conference/text)."""
        xmpp = self._require_online()
        disco = xmpp.plugin["xep_0030"]
        domain = self.jid.split("@", 1)[1]
        service = await self._conference_service(disco, domain)
        if not service:
            raise C.ChatError(f"{domain} names no group chat service.")
        iq = await disco.get_items(jid=service, timeout=30)
        items = list(iq["disco_items"]["items"])[:C.MAX_ROOM_LIST]
        lowered = search.lower()
        rooms = []
        for jid, _node, name in items:
            jid = str(jid or "")
            if not _ROOM_JID.fullmatch(jid):
                continue
            if lowered and lowered not in jid.lower() and lowered not in str(name or "").lower():
                continue
            rooms.append(C.RoomInfo(name=jid, title=str(name or "")))
            if len(rooms) >= C.ROOM_BATCH:
                self._emit_rooms(rid, rooms)
                rooms = []
        self._emit_rooms(rid, rooms)
        self.room_list_done.emit(rid, "")

    async def _conference_service(self, disco, domain: str) -> str:
        iq = await disco.get_items(jid=domain, timeout=30)
        for jid, _node, _name in list(iq["disco_items"]["items"])[:50]:
            try:
                info = await disco.get_info(jid=jid, timeout=15)
            except Exception:  # noqa: BLE001 - an item that does not answer is not the one
                continue
            for identity in info["disco_info"]["identities"]:
                if identity[0] == "conference" and identity[1] == "text":
                    return str(jid)
        return ""

    def _apply_proxy(self, xmpp):
        """The default proxy for this account (None: it connects directly).
        slixmpp has no proxy support of its own (``use_proxy`` /
        ``proxy_config`` are gone since 1.8): the client class of
        :func:`_client_class` makes every TCP connection through it."""
        from core import proxy_settings

        domain = self.host or self.jid.split("@", 1)[1]
        config = proxy_settings.resolve("default", None, domain, self.port or 5222, "xmpp").config
        xmpp.axross_proxy = config
        return config

    def _connect_address(self) -> tuple[str | None, int | None]:
        """The (host, port) for slixmpp's connect(). Behind a proxy always an
        explicit address (the server field or the JID's domain, port 5222):
        slixmpp then makes no SRV or address lookup of its own here - the
        proxy resolves the name."""
        if getattr(self, "_proxy", None) is not None:
            return self.host or self.jid.split("@", 1)[1], self.port or 5222
        return self.host or None, self.port or None

    def _on_proxy_failed(self, exc) -> None:
        """The proxy did not give a connection: the login fails - never a
        direct connection instead."""
        self._want_online = False
        self._set_state(C.STATE_ERROR, "the proxy refused the connection")
        self._note(self.server_key, f"The connection through the proxy failed: {exc}", C.KIND_ERROR)
        self._session_ready.set()

    def _on_cert(self, pem: str) -> None:
        der = ssl.PEM_cert_to_DER_cert(pem)
        got = fingerprint_of(der)
        self._last_fingerprint = got
        if self._pinned and got != self._pinned:
            self._note(self.server_key, f"The server's certificate ({got}) is not the pinned one - "
                       "disconnecting before the login.", C.KIND_ERROR)
            self._want_online = False
            self.xmpp.abort()
            self._set_state(C.STATE_ERROR, "certificate does not match the pin")
            self.request.emit(CertificateRequest(self.host or self.jid.split("@", 1)[1], self.port or 5222, got,
                                                 "The certificate is not the pinned one."))
            self._session_ready.set()

    def _on_invalid_chain(self, exc) -> None:
        self._want_online = False
        self._set_state(C.STATE_ERROR, "untrusted certificate")
        self._note(self.server_key, f"The server's certificate is not trusted: {exc}", C.KIND_ERROR)
        asyncio.get_running_loop().create_task(self._offer_certificate(str(exc)))
        self._session_ready.set()

    async def _offer_certificate(self, reason: str) -> None:
        der = await probe_certificate(self.host or self.jid.split("@", 1)[1], self.port or 5222,
                                      self.jid.split("@", 1)[1],
                                      proxy_mode="none" if self.account.settings.get("proxy") == "none"
                                      else "default")
        if der:
            self.request.emit(CertificateRequest(self.host or self.jid.split("@", 1)[1], self.port or 5222,
                                                 fingerprint_of(der), reason))

    def _on_failed_auth(self, _event) -> None:
        self._want_online = False
        self._set_state(C.STATE_ERROR, "login failed")
        self._note(self.server_key, "The server refused the login (wrong password?).", C.KIND_ERROR)
        self.xmpp.disconnect()
        self._session_ready.set()

    def _on_no_auth(self, _event) -> None:
        """No login method both sides accept - on a stream without TLS
        (STARTTLS missing or stripped) every one is refused."""
        self._want_online = False
        transport = getattr(self.xmpp, "transport", None)
        secure = transport is not None and transport.get_extra_info("ssl_object") is not None
        reason = ("no shared login method" if secure
                  else "the server offered no TLS - the password was not sent")
        self._set_state(C.STATE_ERROR, reason)
        self._note(self.server_key, f"Login refused: {reason}.", C.KIND_ERROR)
        self.xmpp.disconnect()
        self._session_ready.set()

    def _on_disconnected(self, _event) -> None:
        if self.state == C.STATE_ONLINE:
            self._set_state(C.STATE_CONNECTING if self._want_online else C.STATE_OFFLINE, "")
            self._note(self.server_key, "Disconnected.")
            for conv in self.conversations():
                if conv.kind == C.CONV_CHANNEL:
                    self._update_conversation(conv.key, joined=False, members={})
            if self._want_online:
                self._cancel_reconnect()
                self._reconnect_handle = asyncio.get_running_loop().call_later(10, self._reconnect)

    def _cancel_reconnect(self) -> None:
        handle = getattr(self, "_reconnect_handle", None)
        if handle is not None:
            handle.cancel()
        self._reconnect_handle = None

    def _reconnect(self) -> None:
        self._reconnect_handle = None
        if self._want_online and self.xmpp is not None:
            self._note(self.server_key, "Reconnecting…")
            self.xmpp.connect(*self._connect_address())

    async def _on_session_start(self, _event) -> None:
        xmpp = self.xmpp
        if xmpp is None or not self._want_online:
            return  # a client disconnected while it was still connecting
        xmpp.send_presence()
        try:
            await xmpp.get_roster()
        except Exception as exc:  # noqa: BLE001 - a roster is optional for a session
            self._note(self.server_key, f"No contact list: {C.error_text(exc)}", C.KIND_ERROR)
        try:
            await xmpp.plugin["xep_0280"].enable()
        except Exception:  # noqa: BLE001 - carbons are optional
            pass
        self._note(self.server_key, f"Signed in as {self.jid}" + (
            f" (certificate {self._last_fingerprint})" if getattr(self, "_last_fingerprint", "") else ""))
        try:
            await self._start_omemo()
        except Exception as exc:  # noqa: BLE001 - chats work without; say why
            log.warning("OMEMO start failed", exc_info=True)
            self._note(self.server_key, f"OMEMO could not start: {C.error_text(exc)} - messages are not "
                       "end-to-end encrypted.", C.KIND_ERROR)
        self._on_roster(None)
        for room, nick in list(self._rooms.items()):
            xmpp.plugin["xep_0045"].join_muc(room, nick)
        for line in self.account.settings.get("autojoin", []) or []:
            parts = str(line).split()
            if parts and _ROOM_JID.fullmatch(parts[0]):
                await self._join(" ".join(parts))
        try:
            self._link_info = self._read_link_info()
        except Exception:  # noqa: BLE001 - the badge falls back to the settings
            log.debug("XMPP: TLS state not readable", exc_info=True)
        self._set_state(C.STATE_ONLINE, self.jid)
        self._session_ready.set()

    async def _disconnect(self) -> None:
        self._want_online = False
        self._cancel_reconnect()
        if self.xmpp is not None:
            # slixmpp's disconnect() stops a connection attempt only once a
            # transport exists: against an unreachable server it would go on
            # retrying, and log in later on its own.
            try:
                self.xmpp.cancel_connection_attempt()
            except Exception:  # noqa: BLE001 - nothing to cancel
                pass
        if self.omemo is not None:
            try:
                await self.omemo.shutdown()
            except Exception:  # noqa: BLE001
                pass
            self.omemo = None
        if self.xmpp is not None:
            try:
                await asyncio.wait_for(self.xmpp.disconnect(wait=1.0), 5)
            except Exception:  # noqa: BLE001
                pass
            try:
                self.xmpp.abort()  # whatever is left: no reconnect of its own
            except Exception:  # noqa: BLE001
                pass
            self.xmpp = None

    # -- OMEMO ------------------------------------------------------------------------------------
    def _store_key(self) -> bytes:
        key = C.account_secret(self.account, "store_key")
        if not key:
            key = base64.b64encode(secrets.token_bytes(32)).decode()
            if not C.store_account_secret(self.account, "store_key", key):
                self._note(self.server_key, "The keyring cannot keep the key of the OMEMO store: this device's "
                           "keys are lost when axross closes.", C.KIND_ERROR)
        return base64.b64decode(key)

    async def _start_omemo(self) -> None:
        import twomemo

        store = EncryptedJsonStore(C.state_dir(self.account) / "omemo.bin", self._store_key())
        storage = make_storage(store)
        backends = [twomemo.Twomemo(storage)]
        if oldmemo_available() and self.account.settings.get("oldmemo", True) is not False:
            try:   # installed by the user (AGPL, never bundled): optional
                import oldmemo
            except ImportError:
                oldmemo = None
            if oldmemo is not None:
                backends.append(oldmemo.Oldmemo(storage))
        manager_class = make_session_manager(self)
        self.omemo = await manager_class.create(
            backends, storage, self.jid, "axross", TRUST_UNDECIDED,
            signed_pre_key_rotation_period=7 * 24 * 3600)
        for ns in self.omemo_namespaces():
            self.xmpp.plugin["xep_0163"].add_interest(device_node(ns))
        own, _others = await self.omemo.get_own_device_information()
        self._note(self.server_key, f"OMEMO ready ({', '.join(self.omemo_namespaces())}): this device "
                   f"{own.device_id}, fingerprint {fingerprint_text(own.identity_key)}")

    def omemo_namespaces(self) -> list[str]:
        out = [NS_OMEMO2]
        if oldmemo_available() and self.account.settings.get("oldmemo", True) is not False:
            out.append(NS_OLDMEMO)
        return out

    async def _on_pep(self, msg) -> None:
        if self.omemo is None:
            return
        items = msg["pubsub_event"]["items"]
        node = items["node"]
        sender = bare(msg["from"])
        for ns in self.omemo_namespaces():
            if node != device_node(ns):
                continue
            for item in items:
                payload = item.xml.find(f"{{{ns}}}{'devices' if ns == NS_OMEMO2 else 'list'}")
                if payload is None:
                    continue
                try:
                    device_list = parse_device_list(ns, payload)
                    await self.omemo.update_device_list(ns, sender, device_list)
                except Exception:  # noqa: BLE001 - one bad list must not stop the session
                    log.warning("OMEMO: device list of %s not read", sender, exc_info=True)
        self._refresh_encryption(sender)

    def _refresh_encryption(self, jid: str) -> None:
        conv = self.conversation(jid)
        if conv is None or conv.kind != C.CONV_DIRECT:
            return
        self.runner.loop.create_task(self._update_direct_encryption(jid))

    async def _update_direct_encryption(self, jid: str) -> None:
        if self.omemo is None or jid in self._plain or "/" in jid:
            self._update_conversation(jid, encryption=C.ENC_TRANSPORT)
            return
        try:
            devices = await self.omemo.get_device_information(jid)
        except Exception:  # noqa: BLE001
            devices = frozenset()
        active = [d for d in devices if any(on for _ns, on in d.active)]
        if not active:
            self._update_conversation(jid, encryption=C.ENC_TRANSPORT)
            return
        verified = all(d.trust_level_name in (TRUST_VERIFIED, TRUST_DISTRUSTED) for d in active)
        self._update_conversation(jid, encryption=C.ENC_E2E if verified else C.ENC_E2E_UNTRUSTED)

    async def devices_of(self, jid: str) -> list[DeviceInfo]:
        if self.omemo is None:
            return []
        out = []
        for d in await self.omemo.get_device_information(bare(jid)):
            if not any(on for _ns, on in d.active):
                continue
            out.append(DeviceInfo(d.bare_jid, str(d.device_id), C.clean_name(d.label or ""),
                                  fingerprint_text(d.identity_key), d.trust_level_name or TRUST_UNDECIDED,
                                  d.identity_key, tuple(sorted(d.namespaces))))
        return out

    async def own_device(self) -> DeviceInfo | None:
        if self.omemo is None:
            return None
        own, _ = await self.omemo.get_own_device_information()
        return DeviceInfo(self.jid, str(own.device_id), "this device", fingerprint_text(own.identity_key),
                          TRUST_VERIFIED, own.identity_key)

    def set_trust(self, jid: str, identity_key: bytes, trust: str) -> None:
        self.runner.submit(self._set_trust(jid, identity_key, trust),
                           on_error=lambda e: self._error_in(self.server_key, e))

    async def _set_trust(self, jid: str, identity_key: bytes, trust: str) -> None:
        if self.omemo is None:
            raise C.ChatError("OMEMO is not running.")
        if trust not in (TRUST_VERIFIED, TRUST_BLIND, TRUST_DISTRUSTED, TRUST_UNDECIDED):
            raise C.ChatError(f"Unknown trust {trust!r}.")
        await self.omemo.set_trust(bare(jid), identity_key, trust)
        self._note(self.server_key, f"{jid} {fingerprint_text(identity_key)[:26]}…: {trust}.")
        await self._update_direct_encryption(bare(jid))

    # -- receiving -----------------------------------------------------------------------------------
    def _encrypted_element(self, msg):
        for ns, tag in ((NS_OMEMO2, "encrypted"), (NS_OLDMEMO, "encrypted")):
            elem = msg.xml.find(f"{{{ns}}}{tag}")
            if elem is not None:
                return ns, elem
        return None, None

    async def _on_message(self, msg) -> None:
        if msg["type"] not in ("chat", "normal"):
            return
        if msg.xml.find("{http://jabber.org/protocol/pubsub#event}event") is not None:
            return
        if msg.xml.find("{urn:xmpp:carbons:2}received") is not None or \
                msg.xml.find("{urn:xmpp:carbons:2}sent") is not None:
            return  # the carbon handlers do these
        await self._incoming(msg, outgoing=False)

    async def _on_carbon(self, msg) -> None:
        if bare(msg["from"]) != self.jid:
            return  # only our own server may send us carbons (XEP-0280 security)
        sent = msg.xml.find("{urn:xmpp:carbons:2}sent") is not None
        inner = msg["carbon_sent"] if sent else msg["carbon_received"]
        await self._incoming(inner, outgoing=sent)

    async def _incoming(self, msg, *, outgoing: bool) -> None:
        sender = bare(msg["from"])
        peer = bare(msg["to"]) if outgoing else sender
        if not peer or "@" not in peer and peer != self.jid.split("@", 1)[1]:
            return
        label = peer
        if peer in self._rooms:
            # A private message of a group chat occupant (room@service/nick):
            # its bare JID is the room's. Keyed by the full JID, it gets a
            # conversation of its own instead of posing as a room message.
            full = str(msg["to"] if outgoing else msg["from"])
            nick = full.split("/", 1)[1] if "/" in full else ""
            if not nick:
                return  # from the room itself, not an occupant: not a chat
            peer, label = full, f"{C.clean_name(nick)} ({peer})"
        ns, elem = self._encrypted_element(msg)
        text, encryption, note = msg["body"] or "", C.ENC_TRANSPORT, ""
        if elem is not None:
            if self.omemo is None:
                text, encryption = "(an OMEMO message - OMEMO is not running here)", C.ENC_FAILED
            else:
                try:
                    text, encryption = await self._decrypt(ns, elem, sender)
                except Exception as exc:  # noqa: BLE001 - say it, do not stop the session
                    log.info("OMEMO decrypt failed", exc_info=True)
                    text, encryption = f"(could not be decrypted: {C.error_text(exc)})", C.ENC_FAILED
                if text is None:
                    return  # an empty OMEMO message (key exchange / heartbeat)
        elif not text:
            return
        if self.conversation(peer) is None:
            self._add_conversation(peer, C.CONV_DIRECT, label, encryption=C.ENC_TRANSPORT)
            self._refresh_encryption(peer)
        kind = C.KIND_MESSAGE
        if text.startswith("/me "):
            kind, text = C.KIND_ACTION, text[4:]
        stamp = msg["delay"]["stamp"].timestamp() if msg["delay"]["stamp"] else time.time()
        self._add_message(C.ChatMessage(conversation=peer, sender=self.jid.split("@", 1)[0] if outgoing else
                                        self._name_of(sender), text=text, kind=kind, timestamp=stamp,
                                        outgoing=outgoing, encryption=encryption, note=note,
                                        message_id=str(msg["id"] or "")),
                          highlight_words=[self.jid.split("@", 1)[0]])

    async def _decrypt(self, ns: str, elem, sender: str) -> tuple[str | None, str]:
        message = parse_message(ns, elem, sender)
        plaintext, device, _ = await self.omemo.decrypt(message)
        if plaintext is None:
            return None, C.ENC_E2E
        if ns == NS_OMEMO2:
            text = parse_envelope(plaintext, sender)
        else:
            text = plaintext.decode("utf-8", "replace")
        level = C.ENC_E2E if device.trust_level_name == TRUST_VERIFIED else C.ENC_E2E_UNTRUSTED
        return text, level

    def _name_of(self, jid: str) -> str:
        if self.xmpp is not None:
            item = self.xmpp.client_roster[jid]
            if item["name"]:
                return C.clean_name(item["name"])
        return jid.split("@", 1)[0]

    # -- group chats ---------------------------------------------------------------------------------
    def _on_groupchat(self, msg) -> None:
        room = bare(msg["from"])
        if self.conversation(room) is None:
            return
        nick = msg["mucnick"] or ""
        if msg["subject"] and not msg["body"]:
            self._update_conversation(room, topic=msg["subject"])
            return
        text = msg["body"] or ""
        if not text:
            return
        kind = C.KIND_ACTION if text.startswith("/me ") else C.KIND_MESSAGE
        if kind == C.KIND_ACTION:
            text = text[4:]
        own = nick == self._rooms.get(room)
        stamp = msg["delay"]["stamp"].timestamp() if msg["delay"]["stamp"] else time.time()
        self._add_message(C.ChatMessage(conversation=room, sender=nick, text=text, kind=kind, timestamp=stamp,
                                        outgoing=own, encryption=C.ENC_TRANSPORT, message_id=str(msg["id"] or "")),
                          highlight_words=[self._rooms.get(room, "")])

    def _on_groupchat_presence(self, presence) -> None:
        room = bare(presence["from"])
        conv = self.conversation(room)
        if conv is None:
            return
        nick = presence["from"].resource
        members = dict(conv.members)
        if presence["type"] == "unavailable":
            members.pop(nick, None)
        else:
            role = presence["muc"]["role"] or ""
            members[nick] = C.Member(name=nick, display=C.clean_name(nick),
                                     role={"moderator": "@", "participant": ""}.get(role, ""),
                                     away=presence["type"] in ("away", "xa", "dnd"))
        self._set_members(room, members)

    # -- contacts --------------------------------------------------------------------------------------
    def _on_roster(self, _event) -> None:
        if self.xmpp is None:
            return
        contacts = {}
        for jid in list(self.xmpp.client_roster.keys())[:5000]:
            if jid == self.jid:
                continue
            item = self.xmpp.client_roster[jid]
            online = bool(item.resources)
            contacts[jid] = C.Member(name=jid, display=C.clean_name(item["name"] or jid), away=not online)
        self._set_members(self.server_key, contacts)

    def _on_presence(self, _presence) -> None:
        self._on_roster(None)

    def _on_subscribe(self, presence) -> None:
        jid = bare(presence["from"])
        self.request.emit(SubscriptionRequest(jid))

    # -- sending -----------------------------------------------------------------------------------------
    def _require_online(self):
        if self.xmpp is None or self.state != C.STATE_ONLINE:
            raise C.ChatError("Not connected.")
        return self.xmpp

    async def _send_text(self, key: str, text: str) -> None:
        conv = self.conversation(key)
        if conv is None or conv.kind == C.CONV_SERVER:
            raise C.ChatError("This is the account's window - choose a contact or a room.")
        xmpp = self._require_online()
        if conv.kind == C.CONV_CHANNEL:
            xmpp.send_message(mto=key, mbody=text, mtype="groupchat")
            return
        if key in self._plain or self.omemo is None or "/" in key:
            # ("/": a group chat occupant's private chat - OMEMO is per account)
            xmpp.send_message(mto=key, mbody=text, mtype="chat")
            self._add_message(C.ChatMessage(conversation=key, sender=self.jid.split("@", 1)[0], text=text,
                                            outgoing=True, encryption=C.ENC_TRANSPORT))
            return
        await self._send_encrypted(key, text)

    async def _send_encrypted(self, jid: str, text: str) -> None:
        import omemo

        plaintext = {NS_OMEMO2: sce_envelope(text, self.jid, jid)}
        if NS_OLDMEMO in self.omemo_namespaces():
            plaintext[NS_OLDMEMO] = text.encode("utf-8")
        try:
            try:
                messages, errors = await self.omemo.encrypt(frozenset([jid]), plaintext, identifier=jid)
            except omemo.NoEligibleDevices:
                # the contact's device list may not be here yet (a chat opened just now)
                await self.omemo.refresh_device_lists(jid)
                messages, errors = await self.omemo.encrypt(frozenset([jid]), plaintext, identifier=jid)
        except omemo.NoEligibleDevices:
            raise C.ChatError(f"{jid} has no OMEMO device this client may encrypt for. Not sent; /plain "
                              "switches this chat to unencrypted.")
        except (omemo.TrustDecisionFailed, omemo.StillUndecided):
            raise C.ChatError(f"Not sent: {jid} has devices nobody decided on - decide in Encryption….")
        for err in errors:
            log.info("OMEMO encrypt: %s", err)
        message, _key = next(((m, k) for m, k in messages.items() if m.namespace == NS_OMEMO2),
                             next(iter(messages.items())))
        stanza = self.xmpp.make_message(mto=jid, mtype="chat", mbody=FALLBACK_BODY)
        stanza.xml.append(serialize_message(message))
        stanza.xml.append(ET.Element(f"{{{NS_EME}}}encryption", namespace=message.namespace,
                                     name="OMEMO"))
        stanza.xml.append(ET.Element(f"{{{NS_HINTS}}}store"))
        stanza.send()
        level = C.ENC_E2E
        for d in await self.omemo.get_device_information(jid):
            if any(on for _ns, on in d.active) and d.trust_level_name != TRUST_VERIFIED:
                level = C.ENC_E2E_UNTRUSTED
        self._add_message(C.ChatMessage(conversation=jid, sender=self.jid.split("@", 1)[0], text=text,
                                        outgoing=True, encryption=level))

    async def _join(self, target: str) -> None:
        xmpp = self._require_online()
        parts = target.split()
        room = bare(parts[0]) if parts else ""
        if not _ROOM_JID.fullmatch(room):
            raise C.ChatError(f"{room!r} is not a room address (room@conference.server).")
        nick = parts[1] if len(parts) > 1 else self.jid.split("@", 1)[0]
        self._rooms[room] = nick
        self._add_conversation(room, C.CONV_CHANNEL, room, encryption=C.ENC_TRANSPORT, members={})
        self._note(room, "Group chats are not end-to-end encrypted here: the room's server reads them.")
        xmpp.plugin["xep_0045"].join_muc(room, nick)

    async def _open_direct(self, target: str) -> None:
        jid = bare(target.split()[0]) if target.split() else ""
        if not _BARE_JID.fullmatch(jid):
            raise C.ChatError(f"{jid!r} is not a Jabber ID (name@server).")
        self._add_conversation(jid, C.CONV_DIRECT, jid, encryption=C.ENC_TRANSPORT)
        if self.omemo is not None:
            try:
                await self.omemo.refresh_device_lists(jid)
            except Exception:  # noqa: BLE001 - no OMEMO for this contact, maybe
                pass
            await self._update_direct_encryption(jid)

    async def _leave(self, key: str) -> None:
        conv = self.conversation(key)
        if conv is not None and conv.kind == C.CONV_CHANNEL and self.xmpp is not None:
            self.xmpp.plugin["xep_0045"].leave_muc(key, self._rooms.pop(key, ""))
        self._remove_conversation(key)

    async def _answer(self, request, answer) -> None:
        if isinstance(request, CertificateRequest) and answer is True:
            self.account.settings["fingerprint"] = request.fingerprint
            callback = getattr(self, "on_account_changed", None)
            if callback is not None:
                callback(self.account)
            self._note(self.server_key, f"Trusting the certificate {request.fingerprint}; connect again.")
            return
        if isinstance(request, SubscriptionRequest) and self.xmpp is not None:
            self.xmpp.send_presence(pto=request.jid, ptype="subscribed" if answer else "unsubscribed")
            if answer:
                self.xmpp.send_presence(pto=request.jid, ptype="subscribe")
            return
        if isinstance(request, TrustRequest) and self.omemo is not None:
            trust = TRUST_VERIFIED if answer == "verified" else (TRUST_BLIND if answer else TRUST_DISTRUSTED)
            for d in request.devices:
                await self.omemo.set_trust(d.user_id, d.identity_key, trust)
            await self._update_direct_encryption(request.jid)

    HELP = (
        "/join room@conference.server [nick] - join a group chat",
        "/leave - leave this group chat",
        "/msg name@server text - a message",
        "/me text, /topic text, /nick name (in a group chat)",
        "/add name@server, /remove name@server - the contact list",
        "/devices - OMEMO devices of this chat with their fingerprints and trust",
        "/trust FINGERPRINT-START, /distrust FINGERPRINT-START - after comparing it",
        "/plain - this chat unencrypted (until /omemo)",
    )

    async def _command(self, key: str, name: str, args: str) -> None:
        if name == "help":
            for line in self.HELP:
                self._note(key, line)
            return
        xmpp = self._require_online()
        conv = self.conversation(key)
        parts = args.split()
        if name == "join":
            await self._join(args)
        elif name == "leave":
            await self._leave(key)
        elif name == "msg":
            target, _, text = args.partition(" ")
            await self._open_direct(target)
            if text:
                await self._send_text(bare(target), text)
        elif name == "me":
            await self._send_text(key, "/me " + args)
        elif name == "topic":
            if conv is None or conv.kind != C.CONV_CHANNEL:
                raise C.ChatError("/topic works in a group chat.")
            xmpp.send_message(mto=key, mbody="", msubject=args, mtype="groupchat")
        elif name == "nick":
            if conv is None or conv.kind != C.CONV_CHANNEL or not parts:
                raise C.ChatError("/nick name, in a group chat.")
            self._rooms[key] = parts[0]
            xmpp.send_presence(pto=f"{key}/{parts[0]}")
        elif name in ("add", "remove"):
            if not parts or not _BARE_JID.fullmatch(bare(parts[0])):
                raise C.ChatError(f"/{name} name@server")
            if name == "add":
                xmpp.send_presence(pto=bare(parts[0]), ptype="subscribe")
                await xmpp.update_roster(bare(parts[0]), subscription="none")
            else:
                await xmpp.del_roster_item(bare(parts[0]))
        elif name == "devices":
            jid = key if conv is not None and conv.kind == C.CONV_DIRECT else self.jid
            own = await self.own_device()
            if own is not None:
                self._note(key, f"This device {own.device_id}: {own.fingerprint}")
            for d in await self.devices_of(jid):
                self._note(key, f"{d.user_id} {d.device_id}: {d.trust} - {d.fingerprint}")
        elif name in ("trust", "distrust"):
            jid = key if conv is not None and conv.kind == C.CONV_DIRECT else ""
            start = args.replace(" ", "").lower()
            if not jid or len(start) < 8:
                raise C.ChatError(f"/{name} FINGERPRINT-START (at least 8 hex digits), in a chat.")
            hits = [d for d in await self.devices_of(jid) if d.identity_key.hex().startswith(start)]
            if len(hits) != 1:
                raise C.ChatError(f"{len(hits)} devices start with that fingerprint.")
            await self._set_trust(jid, hits[0].identity_key, TRUST_VERIFIED if name == "trust" else TRUST_DISTRUSTED)
        elif name == "plain":
            self._plain.add(key)
            await self._update_direct_encryption(key)
            self._note(key, "This chat is NOT end-to-end encrypted now (/omemo turns it back on).", C.KIND_ERROR)
        elif name == "omemo":
            self._plain.discard(key)
            await self._update_direct_encryption(key)
        else:
            self._note(key, f"Unknown command: /{name} (/help lists them)", C.KIND_ERROR)


# --- PEP and stanza helpers per OMEMO version ----------------------------------------------------

def device_node(ns: str) -> str:
    return f"{NS_OMEMO2}:devices" if ns == NS_OMEMO2 else f"{NS_OLDMEMO}.devicelist"


def bundle_node(ns: str, device_id: int) -> tuple[str, str | None]:
    """(node, item id) of a device's bundle."""
    if ns == NS_OMEMO2:
        return f"{NS_OMEMO2}:bundles", str(device_id)
    return f"{NS_OLDMEMO}.bundles:{device_id}", None


def _etree(ns: str):
    if ns == NS_OMEMO2:
        import twomemo.etree as mod
    else:
        try:   # the user's own oldmemo install (AGPL, never bundled)
            import oldmemo.etree as mod
        except ImportError as exc:
            raise ValueError("the old OMEMO needs the oldmemo package") from exc
    return mod


def parse_device_list(ns: str, element):
    return _etree(ns).parse_device_list(element)


def parse_message(ns: str, element, sender: str):
    return _etree(ns).parse_message(element, sender)


def serialize_message(message):
    return _etree(message.namespace).serialize_message(message)


def _publish_options(max_items: str = "max"):
    from slixmpp.plugins.xep_0004 import Form

    form = Form()
    form["type"] = "submit"
    form.add_field("FORM_TYPE", ftype="hidden", value="http://jabber.org/protocol/pubsub#publish-options")
    form.add_field("pubsub#access_model", value="open")
    form.add_field("pubsub#max_items", value=max_items)
    return form


def make_session_manager(client: XmppClient):
    """python-omemo's SessionManager with its I/O over *client*'s slixmpp
    (PEP for bundles and device lists) and its trust rules."""
    import omemo
    from omemo.types import TrustLevel

    class SessionManager(omemo.SessionManager):
        @staticmethod
        async def _upload_bundle(bundle) -> None:
            ns = bundle.namespace
            node, item = bundle_node(ns, bundle.device_id)
            payload = _etree(ns).serialize_bundle(bundle)
            await client.xmpp.plugin["xep_0060"].publish(client.jid, node, id=item, payload=payload,
                                                  options=_publish_options())

        @staticmethod
        async def _download_bundle(namespace: str, bare_jid: str, device_id: int):
            node, item = bundle_node(namespace, device_id)
            try:
                if item is not None:
                    result = await client.xmpp.plugin["xep_0060"].get_item(bare_jid, node, item)
                else:
                    result = await client.xmpp.plugin["xep_0060"].get_items(bare_jid, node, max_items=1)
            except Exception as exc:  # noqa: BLE001 - becomes the library's error
                raise omemo.BundleDownloadFailed(f"{bare_jid}/{device_id}: {exc}") from exc
            items = list(result["pubsub"]["items"])
            if not items:
                raise omemo.BundleNotFound(f"{bare_jid}/{device_id}")
            tag = "bundle"
            payload = items[0].xml.find(f"{{{namespace}}}{tag}")
            if payload is None:
                raise omemo.BundleDownloadFailed(f"{bare_jid}/{device_id}: no bundle in the item")
            return _etree(namespace).parse_bundle(payload, bare_jid, device_id)

        @staticmethod
        async def _delete_bundle(namespace: str, device_id: int) -> None:
            node, item = bundle_node(namespace, device_id)
            try:
                if item is not None:
                    await client.xmpp.plugin["xep_0060"].retract(client.jid, node, item)
                else:
                    await client.xmpp.plugin["xep_0060"].delete_node(client.jid, node)
            except Exception as exc:  # noqa: BLE001
                raise omemo.BundleDeletionFailed(str(exc)) from exc

        @staticmethod
        async def _upload_device_list(namespace: str, device_list) -> None:
            payload = _etree(namespace).serialize_device_list(device_list)
            await client.xmpp.plugin["xep_0060"].publish(client.jid, device_node(namespace), id="current",
                                                  payload=payload, options=_publish_options("1"))

        @staticmethod
        async def _download_device_list(namespace: str, bare_jid: str):
            try:
                result = await client.xmpp.plugin["xep_0060"].get_items(bare_jid, device_node(namespace), max_items=1)
            except Exception:  # noqa: BLE001 - no list published: no devices
                return {}
            items = list(result["pubsub"]["items"])
            if not items:
                return {}
            tag = "devices" if namespace == NS_OMEMO2 else "list"
            payload = items[0].xml.find(f"{{{namespace}}}{tag}")
            return _etree(namespace).parse_device_list(payload) if payload is not None else {}

        async def _evaluate_custom_trust_level(self, device):
            name = device.trust_level_name
            if name in (TRUST_VERIFIED, TRUST_BLIND):
                return TrustLevel.TRUSTED
            if name == TRUST_DISTRUSTED:
                return TrustLevel.DISTRUSTED
            return TrustLevel.UNDECIDED

        async def _make_trust_decision(self, undecided, identifier) -> None:
            by_jid: dict[str, list] = {}
            for device in undecided:
                by_jid.setdefault(device.bare_jid, []).append(device)
            ask = []
            for jid, devices in by_jid.items():
                verified = [d for d in await self.get_device_information(jid)
                            if d.trust_level_name == TRUST_VERIFIED]
                if client.policy == POLICY_BTBV and not verified:
                    for d in devices:   # blind trust before verification
                        await self.set_trust(jid, d.identity_key, TRUST_BLIND)
                else:
                    ask.append((jid, devices))
            for jid, devices in ask:
                client.request.emit(TrustRequest(jid, [
                    DeviceInfo(jid, str(d.device_id), C.clean_name(d.label or ""), fingerprint_text(d.identity_key),
                               TRUST_UNDECIDED, d.identity_key) for d in devices]))
            if ask:
                raise omemo.TrustDecisionFailed("new devices wait for the user's decision")

        @staticmethod
        async def _send_message(message, bare_jid: str) -> None:
            stanza = client.xmpp.make_message(mto=bare_jid, mtype="chat")
            stanza.xml.append(serialize_message(message))
            stanza.xml.append(ET.Element(f"{{{NS_HINTS}}}store"))
            stanza.send()

    return SessionManager


# --- the connection (through the proxy) ----------------------------------------------------------------

#: the slixmpp event :func:`_client_class`'s client fires when the proxy gives no connection
PROXY_FAILED_EVENT = "axross_proxy_failed"
_CLIENT_CLASS = None


def _client_class():
    """slixmpp's ClientXMPP whose TCP connections axross makes: through
    ``axross_proxy`` (a core.proxy.ProxyConfig) when it is set. slixmpp 1.17
    has no proxy support: its own connection step would connect directly
    and resolve SRV and address records locally. A proxy that fails ends
    the connection attempt (no retry, no direct connection) and fires
    :data:`PROXY_FAILED_EVENT`."""
    global _CLIENT_CLASS
    if _CLIENT_CLASS is not None:
        return _CLIENT_CLASS
    import slixmpp

    class ProxiedClientXMPP(slixmpp.ClientXMPP):
        axross_proxy = None

        async def get_dns_records(self, domain, port=None):
            if self.axross_proxy is not None:
                return []   # no local SRV / address lookup behind a proxy
            return await super().get_dns_records(domain, port)

        async def _attempt_connection(self, host, port, tls, server_hostname):
            proxy = self.axross_proxy
            if proxy is None:
                return await super()._attempt_connection(host, port, tls, server_hostname)
            from core.proxy import create_proxy_socket

            self.event_when_connected = "connected"
            self._connect_loop_wait += 1
            if self._current_connection_attempt is None:
                return False
            ssl_context = self.get_ssl_context() if tls else None
            try:
                sock = await asyncio.to_thread(create_proxy_socket, proxy, host, int(port), 20.0)
            except Exception as exc:  # noqa: BLE001 - any proxy failure ends the attempt
                # slixmpp checks this attribute: no further attempt, no rescheduling.
                self._current_connection_attempt = None
                self.event("connection_failed", exc)
                self.event(PROXY_FAILED_EVENT, exc)
                return False
            try:
                sock.setblocking(False)
                await self.loop.create_connection(lambda: self, sock=sock, ssl=ssl_context,
                                                  server_hostname=(server_hostname or self.default_domain)
                                                  if ssl_context is not None else None)
            except OSError as exc:
                sock.close()
                self.event("connection_failed", exc)
                return False
            self._connect_loop_wait = 0
            return True

    _CLIENT_CLASS = ProxiedClientXMPP
    return _CLIENT_CLASS


# --- probing an untrusted certificate ----------------------------------------------------------------

async def probe_certificate(host: str, port: int, domain: str, timeout: float = 15.0,
                            proxy_mode: str = "default") -> bytes:
    """The DER certificate a server shows after STARTTLS (or direct TLS), not
    verified - to show its fingerprint to the user. b"" if none. Through the
    default proxy when one applies (*proxy_mode* "default"); a proxy that
    fails gives b"", never a direct connection."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        reader, writer = await C.open_stream(host, port, proxy_mode=proxy_mode, protocol="xmpp",
                                             timeout=timeout)
        writer.write(f"<?xml version='1.0'?><stream:stream to='{domain}' version='1.0' "
                     "xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>".encode())
        writer.write(b"<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
        await writer.drain()
        data = b""
        while b"<proceed" not in data and len(data) < 65536:
            chunk = await asyncio.wait_for(reader.read(4096), timeout)
            if not chunk:
                return b""
            data += chunk
        await writer.start_tls(ctx, server_hostname=domain)
        der = writer.get_extra_info("ssl_object").getpeercert(binary_form=True) or b""
        writer.close()
        return der
    except (OSError, asyncio.TimeoutError, ssl.SSLError, ValueError, C.ChatError):
        return b""


# --- the account form ---------------------------------------------------------------------------------

FIELDS = (
    C.FieldSpec("jid", "Jabber ID", required=True, help="name@server"),
    C.FieldSpec("password", "Password", "password", secret=True, help="Kept in the keyring"),
    C.FieldSpec("resource", "Resource", default="axross"),
    C.FieldSpec("server", "Server (optional)", help="Only when it differs from the JID's domain (no SRV)"),
    C.FieldSpec("port", "Port (optional)", "int", 0),
    C.FieldSpec("fingerprint", "Pinned SHA-256", help="Only for a self-signed server certificate"),
    C.FieldSpec("trust", "New OMEMO devices", "choice", POLICY_BTBV,
                ((POLICY_BTBV, "Blind trust until a device is verified (as Conversations)"),
                 (POLICY_MANUAL, "Ask for every new device"))),
    C.FieldSpec("autojoin", "Join at start", "lines", "", help="One room@conference.server [nick] per line"),
    C.FieldSpec("proxy", "Proxy", "choice", "default", C.PROXY_CHOICES),
)


def validate(settings: dict) -> str | None:
    jid = bare(str(settings.get("jid", "")).strip())
    if not _BARE_JID.fullmatch(jid):
        return "The Jabber ID is missing or not name@server."
    if settings.get("fingerprint") and not normalise_fingerprint(str(settings.get("fingerprint"))):
        return "A pinned certificate needs its SHA-256 fingerprint (64 hex digits)."
    return None


def apply_server(entry, values: dict) -> dict:
    """What choosing a public provider (core.chat_servers.ServerEntry) fills
    in: the Jabber ID on its domain, keeping a name already typed."""
    jid = str(values.get("jid", "") or "").strip()
    local = jid.split("@", 1)[0].strip()
    return {"jid": f"{local}@{entry.host}"}


PROTOCOL = C.Protocol(
    name="xmpp", title="XMPP", fields=FIELDS, make_client=XmppClient,
    join_label="Join Group Chat…", join_prompt="Room (room@conference.server) and nick:",
    direct_label="Chat With…", direct_prompt="Jabber ID (name@server):", validate=validate,
    server_field="jid", apply_server=apply_server, room_list_label="Group Chats",
)
