"""An in-memory IMAP server behind imaplib's client API, for data-safety tests.

Only what core/imap_client.py sends, with the semantics that decide over
mail: CLOSE of a mailbox selected read-write expunges every \\Deleted
message (RFC 3501 6.4.2), EXPUNGE does the same, UID EXPUNGE only the
given UIDs (UIDPLUS), UNSELECT (RFC 3691) and SELECT / EXAMINE / LOGOUT
leave without an expunge, COPY to a missing mailbox is NO [TRYCREATE],
UID COPY / MOVE / FETCH of a UID that is not there answer OK with nothing.

``Server(caps=..., auth_caps=...)``: ``caps`` is what the greeting
announces, ``auth_caps`` (default: the same) what CAPABILITY answers
after login - Dovecot names UIDPLUS, MOVE and UNSELECT only there.
"""

from __future__ import annotations

import imaplib
import re


class Server:
    def __init__(self, sep="/", caps=("IMAP4REV1",), auth_caps=None):
        self.sep = sep
        self.caps = tuple(caps)
        self.auth_caps = tuple(auth_caps if auth_caps is not None else caps)
        self.boxes: dict[str, dict] = {}
        self.log: list[str] = []
        #: Called with (uid,) before an EXPUNGE / UID EXPUNGE is carried out:
        #: lets a test flag a message "from another client" in between.
        self.before_expunge = None

    def add_box(self, name):
        self.boxes.setdefault(name, {"uidnext": 1, "msgs": {}})

    def add_msg(self, box, subj, flags=(), raw=None):
        b = self.boxes[box]
        uid = b["uidnext"]
        b["uidnext"] += 1
        raw = raw or f"Subject: {subj}\r\n\r\nbody of {subj}\r\n".encode()
        b["msgs"][uid] = {"flags": set(flags), "raw": raw, "subj": subj}
        return uid

    def subjects(self, box):
        return sorted(m["subj"] for m in self.boxes[box]["msgs"].values())

    def flag(self, box, subj, flag="\\Deleted"):
        for m in self.boxes[box]["msgs"].values():
            if m["subj"] == subj:
                m["flags"].add(flag)


def _unq(arg: str) -> str:
    if arg.startswith('"') and arg.endswith('"'):
        return arg[1:-1].replace('\\"', '"').replace("\\\\", "\\")
    return arg


class FakeIMAP:
    """Stand-in for imaplib.IMAP4 bound to a Server."""

    abort = imaplib.IMAP4.abort
    error = imaplib.IMAP4.error

    server: Server | None = None  # set by install()

    def __init__(self, *a, **kw):
        self.srv = type(self).server
        self.capabilities = self.srv.caps
        self.selected = None
        self.readonly = True
        self.state = "AUTH"
        self.sock = None
        self._authed = False

    def login(self, u, p):
        self._authed = True
        return "OK", [b"logged in"]

    def noop(self):
        return "OK", [b""]

    def logout(self):
        self.srv.log.append("LOGOUT")
        self.selected = None
        return "BYE", [b""]

    def capability(self):
        caps = self.srv.auth_caps if self._authed else self.srv.caps
        return "OK", [" ".join(caps).encode()]

    def list(self, ref='""', pat="*"):
        if pat == '""':
            return "OK", [f'(\\Noselect) "{self.srv.sep}" ""'.encode()]
        return "OK", [f'(\\HasNoChildren) "{self.srv.sep}" "{n}"'.encode() for n in self.srv.boxes]

    def select(self, mailbox, readonly=False):
        name = _unq(mailbox)
        self.srv.log.append(("EXAMINE " if readonly else "SELECT ") + name)
        self.selected = None
        if name not in self.srv.boxes:
            return "NO", [b"no such mailbox"]
        self.selected, self.readonly = name, readonly
        return "OK", [str(len(self.srv.boxes[name]["msgs"])).encode()]

    def close(self):
        self.srv.log.append(f"CLOSE {self.selected} ro={self.readonly}")
        if self.selected and not self.readonly:
            self._expunge(None)
        self.selected = None
        return "OK", [b""]

    def unselect(self):
        if "UNSELECT" not in self.srv.auth_caps:
            raise self.error("UNSELECT not supported")
        self.srv.log.append(f"UNSELECT {self.selected}")
        self.selected = None
        return "OK", [b""]

    def expunge(self):
        self.srv.log.append("EXPUNGE")
        self._expunge(None)
        return "OK", [b""]

    def _expunge(self, uids):
        if self.srv.before_expunge is not None:
            self.srv.before_expunge(uids)
        msgs = self.srv.boxes[self.selected]["msgs"]
        for uid in [u for u, m in msgs.items() if "\\Deleted" in m["flags"]]:
            if uids is None or uid in uids:
                del msgs[uid]

    def create(self, mailbox):
        name = _unq(mailbox)
        if name in self.srv.boxes:
            return "NO", [b"[ALREADYEXISTS] Mailbox exists"]
        self.srv.add_box(name)
        return "OK", [b""]

    def delete(self, mailbox):
        name = _unq(mailbox)
        if name not in self.srv.boxes:
            return "NO", [b"[NONEXISTENT] no such mailbox"]
        del self.srv.boxes[name]
        return "OK", [b""]

    def rename(self, old, new):
        o, n = _unq(old), _unq(new)
        self.srv.log.append(f"RENAME {o} {n}")
        if o not in self.srv.boxes:
            return "NO", [b"[NONEXISTENT]"]
        if n in self.srv.boxes:
            return "NO", [b"[ALREADYEXISTS]"]
        self.srv.boxes[n] = self.srv.boxes.pop(o)
        return "OK", [b""]

    def status(self, mailbox, what):
        name = _unq(mailbox)
        if name not in self.srv.boxes:
            return "NO", [b"no such"]
        return "OK", [f'"{name}" (MESSAGES {len(self.srv.boxes[name]["msgs"])})'.encode()]

    def append(self, mailbox, flags, date, message):
        name = _unq(mailbox)
        if name not in self.srv.boxes:
            return "NO", [b"[TRYCREATE] no such mailbox"]
        m = re.search(rb"^Subject: (.*)$", message, re.M)
        self.srv.add_msg(name, m.group(1).decode().strip() if m else "appended", raw=message)
        return "OK", [b""]

    def getquotaroot(self, box):
        return "NO", [b""]

    def uid(self, cmd, *args):
        cmd = cmd.upper()
        self.srv.log.append("UID " + cmd + " " + " ".join(str(a) for a in args))
        if self.selected is None:
            raise self.error("command UID illegal in state AUTH")
        msgs = self.srv.boxes[self.selected]["msgs"]
        if cmd == "SEARCH":
            crit = " ".join(a for a in args if a)
            if crit == "DELETED":
                uids = [u for u, m in msgs.items() if "\\Deleted" in m["flags"]]
            else:
                uids = list(msgs)
            return "OK", [" ".join(map(str, sorted(uids))).encode()]
        if cmd == "FETCH":
            uidset, what = args
            out = []
            for u in self._uidset(uidset, msgs):
                m = msgs[u]
                seq = sorted(msgs).index(u) + 1
                if what == "(UID)":
                    out.append(f"{seq} (UID {u})".encode())
                elif "FLAGS" in what and "ENVELOPE" not in what:
                    out.append(f"{seq} (UID {u} FLAGS ({' '.join(sorted(m['flags']))}))".encode())
                elif "RFC822)" in what and "SIZE" not in what:
                    out.append((f"{seq} (UID {u} RFC822 {{{len(m['raw'])}}}".encode(), m["raw"]))
                    out.append(b")")
                else:
                    out.append(
                        f'{seq} (UID {u} RFC822.SIZE {len(m["raw"])} '
                        f'INTERNALDATE "01-Jan-2026 10:00:00 +0000" '
                        f'ENVELOPE (NIL "{m["subj"]}" NIL NIL NIL NIL NIL NIL NIL NIL))'.encode()
                    )
            return "OK", out or [None]
        if cmd == "STORE":
            uidset, verb, flags = args
            if self.readonly:
                return "NO", [b"mailbox is read-only"]
            fl = set(flags.strip("()").split())
            for u in self._uidset(uidset, msgs):
                if verb.startswith("+"):
                    msgs[u]["flags"] |= fl
                elif verb.startswith("-"):
                    msgs[u]["flags"] -= fl
                else:
                    msgs[u]["flags"] = fl
            return "OK", [b""]
        if cmd in ("COPY", "MOVE"):
            if cmd == "MOVE" and "MOVE" not in self.srv.auth_caps:
                return "BAD", [b"unknown command"]
            uidset, dst = args
            d = _unq(dst)
            if d not in self.srv.boxes:
                return "NO", [b"[TRYCREATE] no such mailbox"]
            for u in self._uidset(uidset, msgs):
                m = msgs[u]
                self.srv.add_msg(d, m["subj"], flags=m["flags"] - {"\\Deleted"}, raw=m["raw"])
                if cmd == "MOVE":
                    del msgs[u]
            return "OK", [b""]
        if cmd == "EXPUNGE":
            if "UIDPLUS" not in self.srv.auth_caps:
                return "BAD", [b"unknown command"]
            (uidset,) = args
            self._expunge(set(self._uidset(uidset, msgs)))
            return "OK", [b""]
        raise self.error(f"unknown UID {cmd}")

    @staticmethod
    def _uidset(s, msgs):
        return [int(p) for p in str(s).split(",") if p.isdigit() and int(p) in msgs]


def session(monkeypatch, server: Server):
    """An ImapSession talking to *server*; imaplib's classes patched for
    the test's duration."""
    from core import imap_client as IC

    FakeIMAP.server = server
    monkeypatch.setattr(IC, "_IMAP4", FakeIMAP)
    monkeypatch.setattr(IC, "_IMAP4_SSL", FakeIMAP)
    return IC.ImapSession("fake", 143, "u", "p", use_ssl=False)
