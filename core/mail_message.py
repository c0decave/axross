"""One e-mail message, whatever it came from: an .eml file (RFC 5322 /
MIME), an Outlook .msg (MS-OXMSG in a compound file, core.cfb), a message
of an mbox or a Maildir, or a message an IMAP/POP3 backend lists as .eml.

parse_eml / parse_msg give a :class:`MailMessage`: the header fields as
sent (every Received line, Authentication-Results, DKIM-Signature ...),
the text and HTML bodies, and the attachments with name, declared type,
size and SHA-256. Bounded: a message larger than MAX_MESSAGE, more than
MAX_PARTS MIME parts or MAX_HEADERS header fields is cut off and says so
(``truncated``); nothing is fetched, nothing is run, HTML is not rendered.
"""

from __future__ import annotations

import email
import email.policy
import hashlib
import re
import struct
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from email.utils import getaddresses, parsedate_to_datetime

from core import cfb

MAX_MESSAGE = 64 * 1024 * 1024
MAX_PARTS = 2000
MAX_HEADERS = 2000
MAX_BODY_CHARS = 4 * 1024 * 1024


@dataclass
class Attachment:
    name: str
    content_type: str
    size: int
    sha256: str
    data: bytes = field(repr=False, default=b"")
    inline: bool = False


@dataclass
class MailMessage:
    source: str = ""                       # where it came from (path, mbox#n, imap:/INBOX/...)
    kind: str = "eml"                      # eml | msg
    headers: list[tuple[str, str]] = field(default_factory=list)
    subject: str = ""
    from_: str = ""
    to: list[str] = field(default_factory=list)
    cc: list[str] = field(default_factory=list)
    bcc: list[str] = field(default_factory=list)
    reply_to: list[str] = field(default_factory=list)
    message_id: str = ""
    date: datetime | None = None
    text: str = ""
    html: str = ""
    attachments: list[Attachment] = field(default_factory=list)
    sha256: str = ""                       # of the raw message
    size: int = 0
    truncated: list[str] = field(default_factory=list)
    raw: bytes = field(repr=False, default=b"")
    #: "pst" when *raw* is not the message as it was sent but rebuilt by
    #: axross (core.pst.to_eml): its DKIM signatures cannot be verified
    rebuilt: str = ""

    def header(self, name: str) -> str:
        """The first value of header *name* ('' when absent)."""
        low = name.lower()
        return next((v for k, v in self.headers if k.lower() == low), "")

    def header_all(self, name: str) -> list[str]:
        low = name.lower()
        return [v for k, v in self.headers if k.lower() == low]

    def summary(self) -> dict:
        return {"source": self.source, "kind": self.kind, "subject": self.subject, "from": self.from_,
                "to": self.to, "cc": self.cc, "bcc": self.bcc, "date": self.date.isoformat() if self.date else "",
                "message_id": self.message_id, "size": self.size, "sha256": self.sha256,
                "attachments": [{"name": a.name, "type": a.content_type, "size": a.size, "sha256": a.sha256}
                                for a in self.attachments],
                "truncated": self.truncated}


def _addresses(values: list[str]) -> list[str]:
    out = []
    for name, addr in getaddresses(values):
        out.append(f"{name} <{addr}>" if name and addr else addr or name)
    return [a for a in out if a]


def _date(value: str) -> datetime | None:
    if not value:
        return None
    try:
        d = parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError):
        return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def _clean(value) -> str:
    text = str(value) if value is not None else ""
    return "".join(c if c >= " " or c == "\t" else " " for c in text)[:8192]


# --- .eml ----------------------------------------------------------------------------

#: The source label core.mail_project gives a message of an Outlook data
#: file: "<path>.pst#<folder>/<node>" - set by axross, not by the message.
_PST_SOURCE = re.compile(r"\.(?:pst|ost)#", re.I)


def parse_eml(data: bytes, source: str = "") -> MailMessage:
    msg = MailMessage(source=source, kind="eml", size=len(data), sha256=hashlib.sha256(data).hexdigest())
    if _PST_SOURCE.search(source):
        msg.rebuilt = "pst"
    if len(data) > MAX_MESSAGE:
        msg.truncated.append(f"message larger than {MAX_MESSAGE} bytes - only its start was read")
        data = data[:MAX_MESSAGE]
    msg.raw = data
    parsed = email.message_from_bytes(data, policy=email.policy.default)
    headers = []
    for key, value in parsed.raw_items():
        if len(headers) >= MAX_HEADERS:
            msg.truncated.append(f"more than {MAX_HEADERS} header fields")
            break
        try:
            text = str(value)
        except Exception:  # noqa: BLE001 - a header the parser cannot decode stays raw
            text = repr(value)
        headers.append((key, _clean(text)))
    msg.headers = headers
    msg.subject = msg.header("Subject")
    msg.from_ = ", ".join(_addresses(msg.header_all("From")))
    msg.to = _addresses(msg.header_all("To"))
    msg.cc = _addresses(msg.header_all("Cc"))
    msg.bcc = _addresses(msg.header_all("Bcc"))
    msg.reply_to = _addresses(msg.header_all("Reply-To"))
    msg.message_id = msg.header("Message-ID").strip()
    msg.date = _date(msg.header("Date"))
    parts = 0
    for part in parsed.walk():
        parts += 1
        if parts > MAX_PARTS:
            msg.truncated.append(f"more than {MAX_PARTS} MIME parts")
            break
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        disposition = (part.get_content_disposition() or "").lower()
        filename = part.get_filename()
        if filename or disposition == "attachment" or (not ctype.startswith("text/") and disposition != "inline"):
            try:
                payload = part.get_payload(decode=True) or b""
            except Exception:  # noqa: BLE001 - a broken transfer encoding
                payload = b""
            msg.attachments.append(Attachment(
                name=_clean(filename or ""), content_type=ctype, size=len(payload),
                sha256=hashlib.sha256(payload).hexdigest(), data=payload, inline=disposition == "inline"))
            continue
        try:
            content = part.get_content()
        except Exception:  # noqa: BLE001 - unknown charset: bytes as latin-1
            content = (part.get_payload(decode=True) or b"").decode("latin-1")
        if not isinstance(content, str):
            continue
        if ctype == "text/html":
            msg.html = (msg.html + content)[:MAX_BODY_CHARS]
        else:
            msg.text = (msg.text + content)[:MAX_BODY_CHARS]
    return msg


# --- .msg (MS-OXMSG) -------------------------------------------------------------------

_PT_UNICODE, _PT_STRING8, _PT_BINARY, _PT_SYSTIME, _PT_LONG = 0x001F, 0x001E, 0x0102, 0x0040, 0x0003


def _props_stream(cf: cfb.CompoundFile, storage: cfb.Entry, header: int) -> dict[int, bytes]:
    """The fixed-length properties (__properties_version1.0): tag -> 8 bytes."""
    entry = storage.children.get("__properties_version1.0")
    if entry is None:
        return {}
    raw = cf.read(entry, 1024 * 1024)
    out = {}
    for off in range(header, len(raw) - 15, 16):
        tag, _flags = struct.unpack_from("<II", raw, off)
        out[tag] = raw[off + 8:off + 16]
    return out


def _prop(cf: cfb.CompoundFile, storage: cfb.Entry, prop_id: int, limit: int = MAX_BODY_CHARS * 2) -> str | bytes | None:
    for ptype in (_PT_UNICODE, _PT_STRING8, _PT_BINARY):
        entry = storage.children.get(f"__substg1.0_{prop_id:04X}{ptype:04X}")
        if entry is None:
            continue
        data = cf.read(entry, limit)
        if ptype == _PT_UNICODE:
            return data.decode("utf-16-le", "replace").rstrip("\0")
        if ptype == _PT_STRING8:
            return data.decode("cp1252", "replace").rstrip("\0")
        return data
    return None


def _text(cf, storage, prop_id) -> str:
    v = _prop(cf, storage, prop_id)
    return _clean(v) if isinstance(v, str) else ""


_CODEPAGES = {65001: "utf-8", 65000: "utf-7", 1200: "utf-16-le", 1201: "utf-16-be", 20127: "ascii",
              20866: "koi8-r", 21866: "koi8-u", 50220: "iso2022-jp", 50221: "iso2022-jp",
              50222: "iso2022-jp", 51932: "euc-jp", 51949: "euc-kr", 52936: "hz", 54936: "gb18030",
              936: "gbk", 10000: "mac-roman"}


def codepage_codec(codepage) -> str:
    """Python's codec for a Windows code page number (PR_INTERNET_CPID,
    PR_MESSAGE_CODEPAGE): 1252 is cp1252, 28592 iso-8859-2, 65001 utf-8;
    '' when it names none Python has."""
    import codecs

    if not isinstance(codepage, int) or codepage <= 0:
        return ""
    name = _CODEPAGES.get(codepage) or (
        f"iso-8859-{codepage - 28590}" if 28591 <= codepage <= 28606 else f"cp{codepage}")
    try:
        return codecs.lookup(name).name
    except LookupError:
        return ""


def decode_html_body(raw: bytes, *codepages) -> str:
    """An Outlook HTML body (PR_HTML, bytes) in the first of *codepages* that
    names a codec (PR_INTERNET_CPID, then PR_MESSAGE_CODEPAGE), else UTF-8:
    a cp1252 body read as UTF-8 showed every umlaut as a replacement mark."""
    codec = next((c for c in map(codepage_codec, codepages) if c), "") or "utf-8"
    return raw.decode(codec, "replace")


def _filetime(raw: bytes | None) -> datetime | None:
    if not raw:
        return None
    (ticks,) = struct.unpack("<Q", raw[:8])
    if not ticks:
        return None
    try:
        return datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=ticks // 10)
    except OverflowError:
        return None


def parse_msg(data: bytes, source: str = "") -> MailMessage:
    """An Outlook .msg. Its transport headers (PR_TRANSPORT_MESSAGE_HEADERS)
    are the message's real header fields when it was received over SMTP."""
    msg = MailMessage(source=source, kind="msg", size=len(data), sha256=hashlib.sha256(data).hexdigest())
    if len(data) > MAX_MESSAGE:
        raise ValueError(f".msg larger than {MAX_MESSAGE} bytes")
    msg.raw = data
    cf = cfb.CompoundFile(data)
    root = cf.root
    transport = _prop(cf, root, 0x007D)   # raw: its line breaks separate the fields
    transport = transport if isinstance(transport, str) else ""
    if transport:
        parsed = email.message_from_string(transport + "\n\n", policy=email.policy.default)
        msg.headers = [(k, _clean(str(v))) for k, v in list(parsed.raw_items())[:MAX_HEADERS]]
    msg.subject = _text(cf, root, 0x0037) or msg.header("Subject")
    sender_name, sender_addr = _text(cf, root, 0x0C1A), _text(cf, root, 0x5D01) or _text(cf, root, 0x0C1F)
    msg.from_ = (f"{sender_name} <{sender_addr}>" if sender_name and sender_addr else sender_addr or sender_name
                 ) or ", ".join(_addresses(msg.header_all("From")))
    msg.message_id = _text(cf, root, 0x1035) or msg.header("Message-ID")
    props = _props_stream(cf, root, 32)
    msg.date = _filetime(props.get((0x0039 << 16) | _PT_SYSTIME)) or _date(msg.header("Date"))
    body = _prop(cf, root, 0x1000)
    msg.text = body[:MAX_BODY_CHARS] if isinstance(body, str) else ""
    html = _prop(cf, root, 0x1013)
    if isinstance(html, bytes):
        codepages = [struct.unpack("<I", raw[:4])[0] for raw in
                     (props.get((tag << 16) | _PT_LONG) for tag in (0x3FDE, 0x3FFD)) if raw]
        msg.html = decode_html_body(html, *codepages)[:MAX_BODY_CHARS]
    elif isinstance(html, str):
        msg.html = html[:MAX_BODY_CHARS]
    for name, entry in sorted(root.children.items()):
        if name.startswith("__recip_version1.0_#") and entry.kind == cfb.STORAGE:
            addr = _text(cf, entry, 0x39FE) or _text(cf, entry, 0x3003)
            disp = _text(cf, entry, 0x3001)
            rprops = _props_stream(cf, entry, 8)
            rtype_raw = rprops.get((0x0C15 << 16) | _PT_LONG)
            # PR_RECIPIENT_TYPE: 1 To, 2 Cc, 3 Bcc (high bits are flags)
            rtype = (struct.unpack("<I", rtype_raw[:4])[0] if rtype_raw else 1) & 0x0FFFFFFF
            text = f"{disp} <{addr}>" if disp and addr and disp != addr else addr or disp
            {2: msg.cc, 3: msg.bcc}.get(rtype, msg.to).append(text)
        elif name.startswith("__attach_version1.0_#") and entry.kind == cfb.STORAGE:
            if len(msg.attachments) >= MAX_PARTS:
                msg.truncated.append(f"more than {MAX_PARTS} attachments")
                break
            payload = _prop(cf, entry, 0x3701, MAX_MESSAGE)
            payload = payload if isinstance(payload, bytes) else b""
            fname = _text(cf, entry, 0x3707) or _text(cf, entry, 0x3704)
            ctype = _text(cf, entry, 0x370E) or "application/octet-stream"
            msg.attachments.append(Attachment(name=fname, content_type=ctype, size=len(payload),
                                              sha256=hashlib.sha256(payload).hexdigest(), data=payload))
    if not msg.to:
        msg.to = _addresses(msg.header_all("To"))
    if not msg.cc:
        msg.cc = _addresses(msg.header_all("Cc"))
    if not msg.bcc:
        msg.bcc = _addresses(msg.header_all("Bcc"))
    msg.reply_to = _addresses(msg.header_all("Reply-To"))
    return msg


def parse_any(data: bytes, name: str = "", source: str = "") -> MailMessage:
    """.msg by its compound-file signature, everything else as RFC 5322."""
    if data[:8] == cfb.MAGIC:
        return parse_msg(data, source or name)
    return parse_eml(data, source or name)
