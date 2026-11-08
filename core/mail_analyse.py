"""What a message tells about itself, offline: the Received chain, what the
receiving servers recorded about SPF / DKIM / DMARC, whether sender
addresses agree, the links (and whether their text names another place
than they lead to) and the attachments (real type against the claimed
one, executables, macros, double extensions).

No DNS lookup, no download, no rendering: only what is in the message.
Each finding is (severity, area, text); severity is ``info``, ``warn`` or
``high``. :func:`analyse` returns a :class:`Report` that serialises to
JSON for a mail project, a script or the Agent.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import asdict, dataclass, field
from email.utils import parseaddr, parsedate_to_datetime
from core.mail_html import hidden_chars, links, split_url, strip_hidden
from core.mail_message import MailMessage

MAX_LINKS = 2000

_EXECUTABLE = {".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf",
               ".wsh", ".hta", ".msi", ".msp", ".ps1", ".psm1", ".jar", ".lnk", ".cpl", ".dll", ".reg",
               ".sh", ".app", ".appx", ".msix", ".xll", ".iqy", ".one", ".url", ".chm"}
_CONTAINER = {".iso", ".img", ".vhd", ".vhdx", ".zip", ".rar", ".7z", ".ace", ".cab", ".arj", ".gz", ".tar"}
_MACRO = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".xlam", ".ppam", ".potm", ".sldm", ".xlsb"}
_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
               "cutt.ly", "shorturl.at", "rb.gy", "t.ly", "tiny.cc", "s.id"}
_URL = re.compile(r"""\bhttps?://[^\s<>"'\]\)]+""", re.I)
_RECEIVED_FROM = re.compile(r"\bfrom\s+(\S+)(?:\s+\(([^)]*)\))?", re.I)
_RECEIVED_BY = re.compile(r"\bby\s+(\S+)", re.I)
# an address literal: "[192.0.2.1]", "[IPv6:2001:db8::1]" (RFC 5321 4.1.3; Postfix and Exim
# write it so in Received), "[2001:db8::1]", or a bare one ("192.0.2.1", "IPv6:2001:db8::1")
_IP = re.compile(r"\[(?:IPv6:)?([0-9a-f:.]+)\]|(?<![0-9a-z:.])(?:IPv6:)?([0-9a-f:.]{2,})", re.I)
_AUTH = re.compile(r"\b(spf|dkim|dmarc|arc)\s*=\s*([a-z]+)", re.I)


@dataclass
class Finding:
    severity: str
    area: str
    text: str


@dataclass
class Hop:
    from_host: str
    from_ip: str
    by_host: str
    date: str
    delay_s: float | None = None


@dataclass
class Link:
    url: str
    host: str
    text: str = ""
    notes: list[str] = field(default_factory=list)


@dataclass
class Report:
    summary: dict
    findings: list[Finding] = field(default_factory=list)
    hops: list[Hop] = field(default_factory=list)
    auth: dict[str, list[str]] = field(default_factory=dict)
    links: list[Link] = field(default_factory=list)
    attachments: list[dict] = field(default_factory=list)

    @property
    def score(self) -> int:
        """0 (nothing noticed) ... 100: a rough sum, for sorting."""
        weight = {"info": 0, "warn": 10, "high": 30}
        return min(100, sum(weight.get(f.severity, 0) for f in self.findings))

    def to_dict(self) -> dict:
        d = asdict(self)
        d["score"] = self.score
        return d


def _domain(addr: str) -> str:
    _name, email_addr = parseaddr(addr or "")
    return email_addr.rsplit("@", 1)[-1].lower().strip(">") if "@" in email_addr else ""


def _org(domain: str) -> str:
    """'mail.eu.example.co.uk' -> 'example.co.uk' (a rough registrable part,
    good enough to compare two domains of one message)."""
    parts = [p for p in domain.lower().split(".") if p]
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in {"co", "com", "org", "net", "ac", "gov", "edu", "ne", "or"}:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def ip_literals(text: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """The IP addresses written in *text* (a Received line's "from" comment),
    in their order; the "IPv6:" tag of an address literal is not part of it."""
    out = []
    for m in _IP.finditer(text or ""):
        try:
            out.append(ipaddress.ip_address((m.group(1) or m.group(2)).rstrip(".")))
        except ValueError:
            continue
    return out


def _received(msg: MailMessage, report: Report) -> None:
    previous = None
    hops = []
    for value in reversed(msg.header_all("Received")):   # oldest first
        flat = " ".join(value.split())
        body, _, date_part = flat.rpartition(";")
        m_from, m_by = _RECEIVED_FROM.search(body), _RECEIVED_BY.search(body)
        ip = ""
        if m_from and m_from.group(2):
            found = ip_literals(m_from.group(2))
            ip = str(found[0]) if found else ""
        hop = Hop(m_from.group(1) if m_from else "", ip, m_by.group(1) if m_by else "", date_part.strip())
        try:
            when = parsedate_to_datetime(date_part.strip()) if date_part.strip() else None
        except (TypeError, ValueError, IndexError):
            when = None
        if when is not None and previous is not None and when.tzinfo and previous.tzinfo:
            hop.delay_s = (when - previous).total_seconds()
            if hop.delay_s < -300:
                report.findings.append(Finding("warn", "received", f"hop to {hop.by_host or '?'} is dated "
                                               f"{-hop.delay_s:.0f} s before the one before it"))
        if when is not None:
            previous = when
        hops.append(hop)
    report.hops = hops
    if not hops:
        report.findings.append(Finding("info", "received", "no Received lines (never went through a mail server, "
                                       "or they were removed)"))
    for hop in hops[:1]:
        if hop.from_ip:
            try:
                addr = ipaddress.ip_address(hop.from_ip)
                if not (addr.is_private or addr.is_loopback):
                    report.findings.append(Finding("info", "received", f"first server saw it come from {hop.from_ip}"))
            except ValueError:
                pass


def _auth(msg: MailMessage, report: Report) -> None:
    results: dict[str, list[str]] = {}
    for value in msg.header_all("Authentication-Results") + msg.header_all("ARC-Authentication-Results"):
        for method, result in _AUTH.findall(value):
            results.setdefault(method.lower(), []).append(result.lower())
    report.auth = results
    for method in ("spf", "dkim", "dmarc"):
        got = results.get(method, [])
        if any(r in ("fail", "softfail", "permerror") for r in got):
            sev = "high" if method in ("dmarc", "dkim") or "fail" in got else "warn"
            report.findings.append(Finding(sev, "auth", f"{method.upper()} {', '.join(sorted(set(got)))} "
                                           "(as the receiving server recorded it)"))
        elif not got and msg.header_all("Authentication-Results"):
            report.findings.append(Finding("info", "auth", f"no {method.upper()} result recorded"))
    if not msg.header_all("Authentication-Results"):
        report.findings.append(Finding("info", "auth", "no Authentication-Results header - nothing recorded "
                                       "about SPF / DKIM / DMARC"))
    from_dom = _domain(msg.header("From") or msg.from_)
    for sig in msg.header_all("DKIM-Signature"):
        m = re.search(r"\bd\s*=\s*([^;\s]+)", sig)
        if m and from_dom and _org(m.group(1)) != _org(from_dom):
            report.findings.append(Finding("warn", "auth", f"DKIM signed by {m.group(1)}, not by the From domain "
                                           f"{from_dom}"))


def _addresses(msg: MailMessage, report: Report) -> None:
    raw_from = msg.header("From") or msg.from_   # as sent: a quoted display name stays one
    from_dom = _domain(raw_from)
    name, addr = parseaddr(raw_from)
    if not addr:
        report.findings.append(Finding("warn", "sender", "no usable From address"))
    if name and "@" in name:
        shown = _domain(name.replace(" ", ""))
        if shown and _org(shown) != _org(from_dom):
            report.findings.append(Finding("high", "sender", f"the From name shows an address at {shown}, "
                                           f"the message is from {from_dom}"))
    for reply in msg.reply_to:
        rd = _domain(reply)
        if rd and from_dom and _org(rd) != _org(from_dom):
            report.findings.append(Finding("warn", "sender", f"replies go to {rd}, not to {from_dom}"))
    for label in ("Return-Path", "Sender"):
        v = msg.header(label)
        d = _domain(v)
        if d and from_dom and _org(d) != _org(from_dom):
            report.findings.append(Finding("info", "sender", f"{label} domain {d} differs from From {from_dom}"))
    if any(ord(c) > 127 for c in from_dom) or "xn--" in from_dom:
        report.findings.append(Finding("warn", "sender", f"the From domain {from_dom} uses non-ASCII letters "
                                       "(could imitate another one)"))


#: Notes of :func:`_link_notes` that make a high-severity finding.
_MALFORMED = "a malformed address (it cannot be read as a link; browsers differ on where it leads)"
_HIDDEN = "hidden characters in the address (bidi overrides or zero-width marks change what it shows)"


def _link_notes(url: str, host: str, text: str) -> list[str]:
    notes = []
    if hidden_chars(url):
        notes.append(_HIDDEN)
        url = strip_hidden(url)
    parts = split_url(url)
    if parts is None:
        return [*notes, _MALFORMED]
    try:
        ipaddress.ip_address(host.strip("[]"))
        notes.append("an IP address instead of a name")
    except ValueError:
        pass
    if "xn--" in host or any(ord(c) > 127 for c in host):
        notes.append("non-ASCII letters in the name")
    if host in _SHORTENERS:
        notes.append("a URL shortener - the real target is hidden")
    if "@" in (parts.netloc or ""):
        notes.append("a user name in the address (the part before @ is not the host)")
    shown = _URL.search(strip_hidden(text or ""))
    if shown:
        shown_parts = split_url(shown.group(0))
        shown_host = ((shown_parts.hostname if shown_parts else "") or "").lower()
        if shown_host and _org(shown_host) != _org(host):
            notes.append(f"the text shows {shown_host}, the link leads to {host}")
    if parts.scheme.lower() == "http":
        notes.append("not encrypted (http)")
    return notes


def _host(url: str) -> str:
    """The host *url* leads to (format characters left out), "" for none
    or a malformed address."""
    parts = split_url(strip_hidden(url))
    return ((parts.hostname if parts else "") or "").lower()


def _links(msg: MailMessage, report: Report) -> None:
    seen = set()
    # the parser unescapes both; at most this many <a> are looked at (each one
    # that is no web address or was seen before costs little, but not nothing)
    for href, inner in links(msg.html or "", limit=20 * MAX_LINKS):
        url, text = href.strip(), inner.strip()
        if not url.lower().startswith(("http://", "https://")) or (url, text) in seen:
            continue
        seen.add((url, text))
        host = _host(url)
        report.links.append(Link(url[:2048], host, text[:200], _link_notes(url, host, text)))
        if len(report.links) >= MAX_LINKS:
            break
    for m in _URL.finditer(msg.text or ""):
        url = m.group(0).rstrip(".,;:!?")
        if any(link.url == url for link in report.links) or len(report.links) >= MAX_LINKS:
            continue
        host = _host(url)
        report.links.append(Link(url[:2048], host, "", _link_notes(url, host, "")))
    for link in report.links:
        for note in link.notes:
            sev = ("high" if note.startswith("the text shows") or "user name" in note
                   or note in (_MALFORMED, _HIDDEN) else "warn")
            if note.startswith("not encrypted"):
                sev = "info"
            report.findings.append(Finding(sev, "link", f"{link.host}: {note}"))


def _attachments(msg: MailMessage, report: Report) -> None:
    from core.file_type import identify_bytes

    for att in msg.attachments:
        name = att.name or "(no name)"
        low = name.lower()
        exts = re.findall(r"\.[a-z0-9]{1,5}", low)
        last = exts[-1] if exts else ""
        info = identify_bytes(att.data[:65536], name, size=att.size) if att.data else None
        row = {"name": name, "declared": att.content_type, "size": att.size, "sha256": att.sha256,
               "detected": info.mime if info else "", "description": info.description if info else "",
               "notes": []}
        if last in _EXECUTABLE:
            row["notes"].append("a program or script")
            report.findings.append(Finding("high", "attachment", f"{name}: a program or script ({last})"))
        elif last in _MACRO:
            row["notes"].append("an Office file with macros")
            report.findings.append(Finding("high", "attachment", f"{name}: an Office file with macros"))
        elif last in _CONTAINER:
            row["notes"].append("a container - what is inside is not checked here")
            report.findings.append(Finding("warn", "attachment", f"{name}: a container ({last})"))
        if len(exts) >= 2 and last in _EXECUTABLE | _MACRO and exts[-2] in {".pdf", ".doc", ".docx", ".xls",
                                                                             ".xlsx", ".jpg", ".png", ".txt"}:
            row["notes"].append("a double extension")
            report.findings.append(Finding("high", "attachment", f"{name}: a double extension "
                                           f"({exts[-2]}{last}) - looks like one thing, is another"))
        if "\u202e" in name:
            row["notes"].append("a right-to-left override in the name")
            report.findings.append(Finding("high", "attachment", f"{name!r}: a right-to-left override "
                                           "hides the real extension"))
        if info is not None and info.mismatch:
            row["notes"].append(f"the content is {info.mime}, the name claims {info.extension_mime}")
            report.findings.append(Finding("warn", "attachment", f"{name}: content is {info.mime}, "
                                           f"the name claims {info.extension_mime}"))
        if info is not None and info.mime in ("application/x-dosexec", "application/x-executable",
                                              "application/x-msdownload", "application/x-elf"):
            if "a program or script" not in row["notes"]:
                report.findings.append(Finding("high", "attachment", f"{name}: the content is a program"))
        report.attachments.append(row)


def analyse(msg: MailMessage) -> Report:
    report = Report(summary=msg.summary())
    for note in msg.truncated:
        report.findings.append(Finding("warn", "message", note))
    _received(msg, report)
    _auth(msg, report)
    _addresses(msg, report)
    _links(msg, report)
    _attachments(msg, report)
    if msg.html and not msg.text:
        report.findings.append(Finding("info", "message", "HTML only, no plain text part"))
    return report
