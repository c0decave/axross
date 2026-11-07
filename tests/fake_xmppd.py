"""A small XMPP server for the tests of core.chat_xmpp: STARTTLS with a
self-signed certificate, SASL PLAIN, resource binding, a roster where
every account sees every other, presence, message routing, carbons, PEP
(publish, items, retract, +notify to every other account) for OMEMO, and
simple group chats (XEP-0045: join, presence, groupchat messages, subject).

Runs on an asyncio loop of its own thread. ``stanzas`` records what each
account sent (as text), for the tests' assertions.
"""

from __future__ import annotations

import asyncio
import base64
import itertools
import ssl
import threading
import xml.etree.ElementTree as ET

NS_STREAM = "http://etherx.jabber.org/streams"
NS_CLIENT = "jabber:client"
NS_TLS = "urn:ietf:params:xml:ns:xmpp-tls"
NS_SASL = "urn:ietf:params:xml:ns:xmpp-sasl"
NS_BIND = "urn:ietf:params:xml:ns:xmpp-bind"
NS_SESSION = "urn:ietf:params:xml:ns:xmpp-session"
NS_ROSTER = "jabber:iq:roster"
NS_DISCO_INFO = "http://jabber.org/protocol/disco#info"
NS_PUBSUB = "http://jabber.org/protocol/pubsub"
NS_PUBSUB_EVENT = "http://jabber.org/protocol/pubsub#event"
NS_CARBONS = "urn:xmpp:carbons:2"
NS_FORWARD = "urn:xmpp:forward:0"
NS_PING = "urn:xmpp:ping"
NS_MUC = "http://jabber.org/protocol/muc"
NS_MUC_USER = "http://jabber.org/protocol/muc#user"
ET.register_namespace("stream", NS_STREAM)


class Session:
    def __init__(self, server: "FakeXmppd", reader, writer) -> None:
        self.server, self.reader, self.writer = server, reader, writer
        self.user = ""
        self.resource = ""
        self.tls = False
        self.authenticated = False
        self.carbons = False
        self.available = False

    @property
    def bare(self) -> str:
        return f"{self.user}@{self.server.domain}"

    @property
    def full(self) -> str:
        return f"{self.bare}/{self.resource}"

    def send(self, xml) -> None:
        data = xml if isinstance(xml, (bytes, str)) else ET.tostring(xml, encoding="unicode",
                                                                       default_namespace=None)
        if isinstance(data, str):
            data = data.encode()
        try:
            self.writer.write(data)
        except Exception:
            pass


class FakeXmppd:
    def __init__(self, cert: tuple[str, str], accounts: dict[str, str], domain: str = "localhost") -> None:
        self.cert = cert
        self.accounts = dict(accounts)          # user -> password
        self.domain = domain
        self.muc_domain = f"conference.{domain}"
        self.sessions: list[Session] = []
        self.pep: dict[tuple[str, str], dict[str, ET.Element]] = {}
        self.rooms: dict[str, dict[str, Session]] = {}
        self.subjects: dict[str, str] = {}
        self.stanzas: list[tuple[str, str]] = []
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self.loop.run_forever, daemon=True)
        self.port = 0
        self._ids = itertools.count(1)

    # -- life cycle ----------------------------------------------------------------------------
    def start(self) -> "FakeXmppd":
        self.thread.start()

        async def serve():
            self.server = await asyncio.start_server(self._client, "127.0.0.1", 0)
            self.port = self.server.sockets[0].getsockname()[1]
        asyncio.run_coroutine_threadsafe(serve(), self.loop).result(5)
        return self

    def stop(self) -> None:
        async def close():
            self.server.close()
            for s in list(self.sessions):
                s.writer.close()
        try:
            asyncio.run_coroutine_threadsafe(close(), self.loop).result(5)
        except Exception:
            pass
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(5)

    def sent_by(self, user: str) -> list[str]:
        return [text for who, text in list(self.stanzas) if who == user]

    # -- the stream ------------------------------------------------------------------------------
    async def _client(self, reader, writer) -> None:
        session = Session(self, reader, writer)
        self.sessions.append(session)
        try:
            await self._stream(session)
        except (ConnectionError, ssl.SSLError, asyncio.IncompleteReadError, ET.ParseError):
            pass
        finally:
            if session in self.sessions:
                self.sessions.remove(session)
            for occupants in self.rooms.values():
                for nick, s in list(occupants.items()):
                    if s is session:
                        occupants.pop(nick)
            try:
                writer.close()
            except Exception:
                pass

    async def _stream(self, session: Session) -> None:
        while True:
            parser = ET.XMLPullParser(events=("start", "end"))
            depth = 0
            restart = False
            while not restart:
                data = await session.reader.read(65536)
                if not data:
                    return
                parser.feed(data)
                for event, elem in parser.read_events():
                    if event == "start":
                        depth += 1
                        if depth == 1:
                            self._stream_header(session)
                        continue
                    depth -= 1
                    if depth == 0:
                        return
                    if depth == 1:
                        restart = await self._stanza(session, elem)
                        if restart:
                            break

    def _stream_header(self, session: Session) -> None:
        session.send(f"<?xml version='1.0'?><stream:stream xmlns='{NS_CLIENT}' xmlns:stream='{NS_STREAM}' "
                     f"from='{self.domain}' id='s{next(self._ids)}' version='1.0'>")
        if not session.tls:
            features = (f"<stream:features><starttls xmlns='{NS_TLS}'><required/></starttls></stream:features>")
        elif not session.authenticated:
            features = (f"<stream:features><mechanisms xmlns='{NS_SASL}'><mechanism>PLAIN</mechanism>"
                        "</mechanisms></stream:features>")
        else:
            features = (f"<stream:features><bind xmlns='{NS_BIND}'/><session xmlns='{NS_SESSION}'>"
                        "<optional/></session></stream:features>")
        session.send(features)

    async def _stanza(self, session: Session, elem) -> bool:
        tag = elem.tag
        if tag == f"{{{NS_TLS}}}starttls":
            session.send(f"<proceed xmlns='{NS_TLS}'/>")
            await session.writer.drain()
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(*self.cert)
            await session.writer.start_tls(ctx)
            session.tls = True
            return True
        if tag == f"{{{NS_SASL}}}auth":
            raw = base64.b64decode(elem.text or "")
            _authz, user, password = raw.split(b"\x00")
            user = user.decode().split("@", 1)[0]
            if self.accounts.get(user) == password.decode():
                session.user = user
                session.authenticated = True
                session.send(f"<success xmlns='{NS_SASL}'/>")
                return True
            session.send(f"<failure xmlns='{NS_SASL}'><not-authorized/></failure>")
            return False
        if not session.authenticated:
            return False
        self.stanzas.append((session.user, ET.tostring(elem, encoding="unicode")))
        local = tag.rsplit("}", 1)[-1]
        if local == "iq":
            self._iq(session, elem)
        elif local == "presence":
            self._presence(session, elem)
        elif local == "message":
            self._message(session, elem)
        return False

    # -- iq ------------------------------------------------------------------------------------------
    def _reply(self, session: Session, iq, child=None, error: str = "") -> None:
        out = ET.Element(f"{{{NS_CLIENT}}}iq", {"type": "error" if error else "result", "id": iq.get("id", ""),
                                                 "to": session.full if session.resource else session.bare})
        if iq.get("to"):
            out.set("from", iq.get("to"))
        if child is not None:
            out.append(child)
        if error:
            err = ET.SubElement(out, f"{{{NS_CLIENT}}}error", type="cancel")
            ET.SubElement(err, f"{{urn:ietf:params:xml:ns:xmpp-stanzas}}{error}")
        session.send(out)

    def _iq(self, session: Session, iq) -> None:
        kind = iq.get("type")
        child = next(iter(iq), None)
        ns = child.tag.split("}", 1)[0][1:] if child is not None and "}" in child.tag else ""
        to = iq.get("to", "")
        if ns == NS_BIND:
            res = child.find(f"{{{NS_BIND}}}resource")
            session.resource = (res.text if res is not None and res.text else "res") + ""
            bound = ET.Element(f"{{{NS_BIND}}}bind")
            ET.SubElement(bound, f"{{{NS_BIND}}}jid").text = session.full
            self._reply(session, iq, bound)
        elif ns in (NS_SESSION, NS_PING, NS_CARBONS):
            if ns == NS_CARBONS:
                session.carbons = child.tag.endswith("enable")
            self._reply(session, iq)
        elif ns == NS_ROSTER and kind == "get":
            query = ET.Element(f"{{{NS_ROSTER}}}query")
            for user in self.accounts:
                if user != session.user:
                    ET.SubElement(query, f"{{{NS_ROSTER}}}item", jid=f"{user}@{self.domain}", subscription="both",
                                  name=user.capitalize())
            self._reply(session, iq, query)
        elif ns == NS_ROSTER:
            self._reply(session, iq)
        elif ns == NS_DISCO_INFO:
            query = ET.Element(f"{{{NS_DISCO_INFO}}}query")
            ET.SubElement(query, f"{{{NS_DISCO_INFO}}}identity", category="pubsub", type="pep")
            for feature in (NS_PUBSUB, f"{NS_PUBSUB}#publish", f"{NS_PUBSUB}#publish-options", NS_CARBONS):
                ET.SubElement(query, f"{{{NS_DISCO_INFO}}}feature", var=feature)
            self._reply(session, iq, query)
        elif ns == NS_PUBSUB:
            self._pubsub(session, iq, child, to or session.bare)
        else:
            self._reply(session, iq, error="service-unavailable")

    def _pubsub(self, session: Session, iq, pubsub, owner: str) -> None:
        owner = owner.split("/", 1)[0]
        publish = pubsub.find(f"{{{NS_PUBSUB}}}publish")
        items = pubsub.find(f"{{{NS_PUBSUB}}}items")
        retract = pubsub.find(f"{{{NS_PUBSUB}}}retract")
        if publish is not None:
            node = publish.get("node")
            item = publish.find(f"{{{NS_PUBSUB}}}item")
            item_id = item.get("id") or f"i{next(self._ids)}"
            payload = next(iter(item), None)
            self.pep.setdefault((session.bare, node), {})[item_id] = payload
            self._reply(session, iq)
            for other in list(self.sessions):     # +notify: every account (and our other resources)
                if other.authenticated and other.resource:
                    msg = ET.Element(f"{{{NS_CLIENT}}}message", {"from": session.bare, "to": other.full,
                                                                  "type": "headline"})
                    event = ET.SubElement(msg, f"{{{NS_PUBSUB_EVENT}}}event")
                    ev_items = ET.SubElement(event, f"{{{NS_PUBSUB_EVENT}}}items", node=node)
                    ev_item = ET.SubElement(ev_items, f"{{{NS_PUBSUB_EVENT}}}item", id=item_id)
                    if payload is not None:
                        ev_item.append(payload)
                    other.send(msg)
            return
        if items is not None:
            node = items.get("node")
            stored = self.pep.get((owner, node))
            if stored is None:
                self._reply(session, iq, error="item-not-found")
                return
            wanted = [i.get("id") for i in items.findall(f"{{{NS_PUBSUB}}}item")]
            out = ET.Element(f"{{{NS_PUBSUB}}}pubsub")
            out_items = ET.SubElement(out, f"{{{NS_PUBSUB}}}items", node=node)
            for item_id, payload in stored.items():
                if wanted and item_id not in wanted:
                    continue
                item = ET.SubElement(out_items, f"{{{NS_PUBSUB}}}item", id=item_id)
                if payload is not None:
                    item.append(payload)
            self._reply(session, iq, out)
            return
        if retract is not None:
            node = retract.get("node")
            for item in retract.findall(f"{{{NS_PUBSUB}}}item"):
                self.pep.get((session.bare, node), {}).pop(item.get("id"), None)
            self._reply(session, iq)
            return
        self._reply(session, iq, error="feature-not-implemented")

    # -- presence ------------------------------------------------------------------------------------
    def _presence(self, session: Session, pres) -> None:
        to = pres.get("to", "")
        if to.split("/", 1)[0].endswith("@" + self.muc_domain):
            self._muc_presence(session, pres, to)
            return
        if pres.get("type") in ("subscribe", "subscribed", "unsubscribe", "unsubscribed"):
            target = self._by_bare(to.split("/", 1)[0])
            for other in target:
                fwd = ET.Element(f"{{{NS_CLIENT}}}presence", {"from": session.bare, "to": other.full,
                                                               "type": pres.get("type")})
                other.send(fwd)
            return
        session.available = pres.get("type") != "unavailable"
        for other in list(self.sessions):
            if other is session or not other.resource:
                continue
            out = ET.Element(f"{{{NS_CLIENT}}}presence", {"from": session.full, "to": other.full})
            if pres.get("type"):
                out.set("type", pres.get("type"))
            other.send(out)
            if other.available and pres.get("type") != "unavailable":
                session.send(ET.Element(f"{{{NS_CLIENT}}}presence", {"from": other.full, "to": session.full}))

    def _muc_presence(self, session: Session, pres, to: str) -> None:
        room, _, nick = to.partition("/")
        occupants = self.rooms.setdefault(room, {})
        if pres.get("type") == "unavailable":
            occupants.pop(nick, None)
            for s in [session] + list(occupants.values()):
                out = ET.Element(f"{{{NS_CLIENT}}}presence", {"from": f"{room}/{nick}", "to": s.full,
                                                               "type": "unavailable"})
                s.send(out)
            return
        occupants[nick] = session
        for other_nick, other in occupants.items():
            for target, who in ((session, other_nick), (other, nick)):
                if target is session and who == nick and other is not session:
                    continue
                out = ET.Element(f"{{{NS_CLIENT}}}presence", {"from": f"{room}/{who}", "to": target.full})
                x = ET.SubElement(out, f"{{{NS_MUC_USER}}}x")
                ET.SubElement(x, f"{{{NS_MUC_USER}}}item", affiliation="member", role="participant")
                if target is session and who == nick:
                    ET.SubElement(x, f"{{{NS_MUC_USER}}}status", code="110")
                target.send(out)
        subject = ET.Element(f"{{{NS_CLIENT}}}message", {"from": room, "to": session.full, "type": "groupchat"})
        ET.SubElement(subject, f"{{{NS_CLIENT}}}subject").text = self.subjects.get(room, "")
        session.send(subject)

    # -- messages ------------------------------------------------------------------------------------
    def _by_bare(self, bare: str) -> list[Session]:
        return [s for s in self.sessions if s.resource and s.bare == bare.lower()]

    def _message(self, session: Session, msg) -> None:
        to = msg.get("to", "")
        bare_to = to.split("/", 1)[0].lower()
        if msg.get("type") == "groupchat":
            occupants = self.rooms.get(bare_to, {})
            nick = next((n for n, s in occupants.items() if s is session), None)
            if nick is None:
                return
            subject = msg.find(f"{{{NS_CLIENT}}}subject")
            if subject is not None:
                self.subjects[bare_to] = subject.text or ""
            for other in occupants.values():
                out = ET.fromstring(ET.tostring(msg))
                out.set("from", f"{bare_to}/{nick}")
                out.set("to", other.full)
                other.send(out)
            return
        for target in self._by_bare(bare_to):
            out = ET.fromstring(ET.tostring(msg))
            out.set("from", session.full)
            out.set("to", target.full)
            target.send(out)
        if msg.get("type") == "chat":
            for other in self._by_bare(session.bare):     # carbons of what we sent
                if other is session or not other.carbons:
                    continue
                carbon = ET.Element(f"{{{NS_CLIENT}}}message", {"from": session.bare, "to": other.full,
                                                                 "type": "chat"})
                sent = ET.SubElement(carbon, f"{{{NS_CARBONS}}}sent")
                fwd = ET.SubElement(sent, f"{{{NS_FORWARD}}}forwarded")
                inner = ET.fromstring(ET.tostring(msg))
                inner.set("from", session.full)
                fwd.append(inner)
                other.send(carbon)
