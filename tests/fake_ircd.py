"""A small IRC server for the tests of core.chat_irc: registration with CAP
negotiation, SASL PLAIN and SCRAM-SHA-256 (the server side of RFC 7677),
optional TLS with a self-signed certificate, channels with topic, NAMES,
JOIN/PART/KICK/MODE/TOPIC/NICK/QUIT, PRIVMSG/NOTICE routing, PING/PONG.

Runs on an asyncio loop of its own thread; ``lines`` records what each
client sent, ``inject(nick, raw)`` sends a raw line to a connected client.
"""

from __future__ import annotations

import asyncio
import base64
import datetime
import hashlib
import hmac
import os
import secrets
import ssl
import threading
import time
from dataclasses import dataclass, field


def self_signed(tmp_dir, host: str = "localhost"):
    """(cert path, key path, DER) of a fresh self-signed certificate."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
            .sign(key, hashes.SHA256()))
    cert_path = os.path.join(str(tmp_dir), "ircd.crt")
    key_path = os.path.join(str(tmp_dir), "ircd.key")
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    return cert_path, key_path, cert.public_bytes(serialization.Encoding.DER)


@dataclass
class Session:
    writer: asyncio.StreamWriter
    nick: str = ""
    user: str = ""
    registered: bool = False
    caps: set = field(default_factory=set)
    cap_negotiating: bool = False
    account: str = ""
    sasl_mech: str = ""
    scram: dict = field(default_factory=dict)
    lines: list = field(default_factory=list)

    @property
    def mask(self) -> str:
        return f"{self.nick}!{self.user or 'u'}@test.host"


class FakeIrcd:
    NAME = "irc.test"

    def __init__(self, *, tls: tuple[str, str] | None = None, caps=("sasl", "server-time", "multi-prefix",
                 "away-notify"), sasl_mechs=("PLAIN", "SCRAM-SHA-256"), accounts: dict | None = None,
                 isupport=("CASEMAPPING=rfc1459", "CHANTYPES=#&", "PREFIX=(ov)@+",
                           "CHANMODES=beI,k,l,imnpst")) -> None:
        self.tls = tls
        self.caps = tuple(caps)
        self.sasl_mechs = tuple(sasl_mechs)
        self.accounts = dict(accounts or {})
        self.isupport = isupport
        self.sessions: list[Session] = []
        self.channels: dict[str, dict] = {}
        self.all_lines: list[tuple[str, str]] = []
        self.loop = asyncio.new_event_loop()
        self.server = None
        self.port = 0
        self.thread = threading.Thread(target=self.loop.run_forever, daemon=True)
        self.drop_next_registration = False
        self.forge_scram_signature = False
        #: extra channels LIST names: (name, users, topic)
        self.listed: list[tuple[str, int, str]] = []
        #: LIST never sends its end (RPL_LISTEND)
        self.list_unfinished = False

    # -- life cycle ---------------------------------------------------------------------
    def start(self) -> "FakeIrcd":
        self.thread.start()
        ctx = None
        if self.tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(*self.tls)
        async def serve():
            self.server = await asyncio.start_server(self._client, "127.0.0.1", 0, ssl=ctx)
            self.port = self.server.sockets[0].getsockname()[1]
        asyncio.run_coroutine_threadsafe(serve(), self.loop).result(5)
        return self

    def stop(self) -> None:
        async def close():
            if self.server is not None:
                self.server.close()
            for s in list(self.sessions):
                s.writer.close()
        try:
            asyncio.run_coroutine_threadsafe(close(), self.loop).result(5)
        except Exception:
            pass
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(5)

    def call(self, fn, *args):
        async def run():
            return fn(*args)
        return asyncio.run_coroutine_threadsafe(run(), self.loop).result(5)

    def inject(self, nick: str, raw: str) -> None:
        def go():
            for s in self.sessions:
                if s.nick.lower() == nick.lower():
                    self._send(s, raw)
        self.call(go)

    def kill_connections(self) -> None:
        def go():
            for s in list(self.sessions):
                s.writer.close()
        self.call(go)

    def session(self, nick: str) -> Session | None:
        for s in self.sessions:
            if s.nick.lower() == nick.lower():
                return s
        return None

    def lines_of(self, nick: str) -> list[str]:
        return [line for who, line in list(self.all_lines) if who.lower() == nick.lower()]

    # -- a fake second user ---------------------------------------------------------------
    def say_as(self, sender: str, target: str, text: str, command: str = "PRIVMSG") -> None:
        def go():
            prefix = f"{sender}!bot@other.host"
            if target.startswith("#"):
                chan = self.channels.get(target.lower())
                for s in self.sessions:
                    if chan and s.nick.lower() in chan["members"]:
                        self._send(s, f":{prefix} {command} {target} :{text}")
            else:
                s = self.session(target)
                if s:
                    self._send(s, f":{prefix} {command} {target} :{text}")
        self.call(go)

    def add_member(self, channel: str, nick: str) -> None:
        def go():
            chan = self.channels.setdefault(channel.lower(), {"name": channel, "topic": "", "members": {}})
            chan["members"][nick.lower()] = ""
            for s in self.sessions:
                if s.nick.lower() in chan["members"] and s.nick.lower() != nick.lower():
                    self._send(s, f":{nick}!bot@other.host JOIN {channel}")
        self.call(go)

    # -- the protocol -------------------------------------------------------------------
    def _send(self, s: Session, raw: str) -> None:
        if "server-time" in s.caps and not raw.startswith("@"):
            stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
            raw = f"@time={stamp} {raw}"
        try:
            s.writer.write(raw.encode("utf-8") + b"\r\n")
        except Exception:
            pass

    def _num(self, s: Session, code: str, *params: str) -> None:
        params = list(params)
        last = params.pop() if params else ""
        middle = (" " + " ".join(params)) if params else ""
        self._send(s, f":{self.NAME} {code} {s.nick or '*'}{middle} :{last}")

    async def _client(self, reader, writer) -> None:
        s = Session(writer=writer)
        self.sessions.append(s)
        try:
            while True:
                data = await reader.readline()
                if not data:
                    break
                line = data.decode("utf-8", errors="replace").rstrip("\r\n")
                s.lines.append(line)
                self.all_lines.append((s.nick, line))
                await self._handle(s, line)
                await writer.drain()
        except (ConnectionError, ssl.SSLError):
            pass
        finally:
            if s in self.sessions:
                self.sessions.remove(s)
            for chan in self.channels.values():
                chan["members"].pop(s.nick.lower(), None)
            writer.close()

    def _try_register(self, s: Session) -> None:
        if s.registered or s.cap_negotiating or not s.nick or not s.user:
            return
        if self.drop_next_registration:
            self.drop_next_registration = False
            s.writer.close()
            return
        s.registered = True
        self._num(s, "001", f"Welcome to the test network, {s.nick}")
        self._num(s, "005", *self.isupport, "are supported by this server")
        self._num(s, "375", "- irc.test message of the day -")
        self._num(s, "372", "- be nice")
        self._num(s, "376", "End of MOTD")

    async def _handle(self, s: Session, line: str) -> None:
        from core.chat_irc import parse_line

        msg = parse_line(line)
        if msg is None:
            return
        cmd, p = msg.command, msg.params
        if cmd == "CAP":
            sub = p[0].upper() if p else ""
            if sub == "LS":
                s.cap_negotiating = True
                offered = []
                for c in self.caps:
                    offered.append(f"sasl={','.join(self.sasl_mechs)}" if c == "sasl" else c)
                self._send(s, f":{self.NAME} CAP * LS :{' '.join(offered)}")
            elif sub == "REQ":
                wanted = p[-1].split()
                if all(w in self.caps for w in wanted):
                    s.caps.update(wanted)
                    self._send(s, f":{self.NAME} CAP * ACK :{' '.join(wanted)}")
                else:
                    self._send(s, f":{self.NAME} CAP * NAK :{' '.join(wanted)}")
            elif sub == "END":
                s.cap_negotiating = False
                self._try_register(s)
        elif cmd == "AUTHENTICATE":
            await self._sasl(s, p[0] if p else "")
        elif cmd == "NICK":
            new = p[0]
            if any(o is not s and o.nick.lower() == new.lower() for o in self.sessions) or new.lower() == "taken":
                self._num(s, "433", new, "Nickname is already in use")
                return
            old_mask = s.mask
            if s.registered:
                self._send(s, f":{old_mask} NICK {new}")
            for chan in self.channels.values():
                if s.nick.lower() in chan["members"]:
                    chan["members"][new.lower()] = chan["members"].pop(s.nick.lower())
            s.nick = new
            self._try_register(s)
        elif cmd == "USER":
            s.user = p[0]
            self._try_register(s)
        elif cmd == "PING":
            self._send(s, f":{self.NAME} PONG {self.NAME} :{p[0] if p else ''}")
        elif cmd == "JOIN":
            name = p[0]
            chan = self.channels.setdefault(name.lower(), {"name": name, "topic": "", "members": {}})
            if chan.get("key") and (len(p) < 2 or p[1] != chan["key"]):
                self._num(s, "475", name, "Cannot join channel (+k)")
                return
            role = "@" if not chan["members"] else ""
            chan["members"][s.nick.lower()] = role
            for o in self.sessions:
                if o.nick.lower() in chan["members"]:
                    self._send(o, f":{s.mask} JOIN {name}")
            if chan["topic"]:
                self._num(s, "332", name, chan["topic"])
            names = " ".join(f"{r}{n}" for n, r in chan["members"].items())
            self._num(s, "353", "=", name, names)
            self._num(s, "366", name, "End of /NAMES list.")
        elif cmd == "PART":
            chan = self.channels.get(p[0].lower())
            if chan and s.nick.lower() in chan["members"]:
                for o in self.sessions:
                    if o.nick.lower() in chan["members"]:
                        self._send(o, f":{s.mask} PART {chan['name']} :{p[1] if len(p) > 1 else ''}")
                chan["members"].pop(s.nick.lower(), None)
        elif cmd == "TOPIC":
            chan = self.channels.get(p[0].lower())
            if chan and len(p) > 1:
                chan["topic"] = p[1]
                for o in self.sessions:
                    if o.nick.lower() in chan["members"]:
                        self._send(o, f":{s.mask} TOPIC {chan['name']} :{p[1]}")
        elif cmd in ("PRIVMSG", "NOTICE"):
            target, text = p[0], p[1] if len(p) > 1 else ""
            if target.startswith("#"):
                chan = self.channels.get(target.lower())
                if not chan:
                    self._num(s, "403", target, "No such channel")
                    return
                for o in self.sessions:
                    if o is not s and o.nick.lower() in chan["members"]:
                        self._send(o, f":{s.mask} {cmd} {target} :{text}")
            else:
                o = self.session(target)
                if o is None:
                    if cmd == "PRIVMSG" and target.lower() != "nickserv":
                        self._num(s, "401", target, "No such nick/channel")
                    return
                self._send(o, f":{s.mask} {cmd} {target} :{text}")
        elif cmd == "LIST":
            # RPL_LISTSTART, one RPL_LIST per channel (the real ones, then
            # self.listed: (name, users, topic) - a big network's list),
            # RPL_LISTEND; a mask "*text*" filters as ELIST does
            mask = p[0].strip("*").lower() if p else ""
            self._num(s, "321", "Channel", "Users  Name")
            rows = [(c["name"], len(c["members"]), c["topic"]) for c in self.channels.values()]
            for n, row in enumerate(rows + list(self.listed)):
                if mask and mask not in row[0].lower():
                    continue
                self._num(s, "322", row[0], str(row[1]), row[2])
                if n % 200 == 0:
                    await s.writer.drain()
            if not self.list_unfinished:
                self._num(s, "323", "End of /LIST")
        elif cmd == "QUIT":
            s.writer.close()

    async def _sasl(self, s: Session, data: str) -> None:
        if not s.sasl_mech:
            if data not in self.sasl_mechs:
                self._num(s, "908", ",".join(self.sasl_mechs), "are available SASL mechanisms")
                self._num(s, "904", "SASL authentication failed")
                return
            s.sasl_mech = data
            self._send(s, "AUTHENTICATE +")
            return
        payload = base64.b64decode(data) if data != "+" else b""
        if s.sasl_mech == "PLAIN":
            _authz, user, password = payload.split(b"\x00")
            self._sasl_result(s, self.accounts.get(user.decode()) == password.decode(), user.decode())
            return
        # SCRAM-SHA-256
        st = s.scram
        if not st:
            text = payload.decode()
            assert text.startswith("n,,")
            bare = text[3:]
            attrs = dict(x.split("=", 1) for x in bare.split(","))
            user = attrs["n"]
            password = self.accounts.get(user)
            if password is None:
                self._num(s, "904", "SASL authentication failed")
                s.sasl_mech = ""
                return
            salt = secrets.token_bytes(16)
            nonce = attrs["r"] + base64.b64encode(secrets.token_bytes(12)).decode()
            server_first = f"r={nonce},s={base64.b64encode(salt).decode()},i=4096"
            st.update(user=user, password=password, salt=salt, bare=bare, server_first=server_first, nonce=nonce)
            self._send(s, "AUTHENTICATE " + base64.b64encode(server_first.encode()).decode())
            return
        if "server_final" not in st:
            text = payload.decode()
            without_proof, _, proof = text.rpartition(",p=")
            salted = hashlib.pbkdf2_hmac("sha256", st["password"].encode(), st["salt"], 4096)
            client_key = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
            stored = hashlib.sha256(client_key).digest()
            auth = f"{st['bare']},{st['server_first']},{without_proof}".encode()
            sig = hmac.new(stored, auth, hashlib.sha256).digest()
            expected = base64.b64encode(bytes(a ^ b for a, b in zip(client_key, sig))).decode()
            if proof != expected or f"r={st['nonce']}" not in without_proof:
                self._num(s, "904", "SASL authentication failed")
                s.sasl_mech, s.scram = "", {}
                return
            server_key = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
            server_sig = base64.b64encode(hmac.new(server_key, auth, hashlib.sha256).digest()).decode()
            if self.forge_scram_signature:
                server_sig = base64.b64encode(b"x" * 32).decode()
            st["server_final"] = f"v={server_sig}"
            self._send(s, "AUTHENTICATE " + base64.b64encode(st["server_final"].encode()).decode())
            return
        self._sasl_result(s, True, st["user"])

    def _sasl_result(self, s: Session, ok: bool, user: str) -> None:
        if ok:
            s.account = user
            self._num(s, "900", s.mask, user, f"You are now logged in as {user}")
            self._num(s, "903", "SASL authentication successful")
        else:
            self._num(s, "904", "SASL authentication failed")
        s.sasl_mech, s.scram = "", {}
