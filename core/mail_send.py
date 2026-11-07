"""Writing mail: build a message, keep it as a draft (IMAP APPEND with
\\Draft), send it over SMTP (and keep a copy in Sent).

SMTP: implicit TLS (465) or STARTTLS (587) with the certificate checked;
plain SMTP only to this machine. Through axross's proxy when one is set.
Every header value is checked for CR/LF before a message is built - no
header can be smuggled in through an address or a subject the Agent wrote.
"""

from __future__ import annotations

import smtplib
import ssl
from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import formataddr, formatdate, getaddresses, make_msgid, parseaddr

MAX_RECIPIENTS = 100
MAX_BODY = 2 * 1024 * 1024


@dataclass
class Outgoing:
    """A built message and its Bcc recipients (envelope only, never a header)."""

    message: EmailMessage
    bcc: list[str]

    def as_bytes(self) -> bytes:
        return self.message.as_bytes()


@dataclass
class SmtpSettings:
    host: str
    port: int = 587
    security: str = "starttls"        # ssl | starttls | plain (only to this machine)
    username: str = ""
    password: str = ""
    from_address: str = ""
    timeout: float = 30.0
    proxy: object | None = None       # core.proxy.ProxyConfig


def _one_line(label: str, value: str) -> str:
    if any(c in value for c in "\r\n\0"):
        raise ValueError(f"{label} must not contain line breaks")
    return value.strip()


def _addresses(label: str, values) -> list[str]:
    if isinstance(values, str):
        values = [values]
    out = []
    for name, addr in getaddresses([_one_line(label, v) for v in values or []]):
        if not addr or "@" not in addr or any(c in addr for c in " <>,;\"\\"):
            raise ValueError(f"{label}: {addr or name!r} is no e-mail address")
        out.append(formataddr((name, addr)) if name else addr)
    return out


def build_message(*, from_addr: str, to, subject: str, body: str, cc=(), bcc=(),
                  in_reply_to: str = "", references: str = "") -> Outgoing:
    """A plain-text message; raises ValueError for anything that could
    inject a header or is no address."""
    msg = EmailMessage()
    sender = _addresses("From", [from_addr])
    if len(sender) != 1:
        raise ValueError("exactly one From address")
    rcpt_to, rcpt_cc, rcpt_bcc = _addresses("To", to), _addresses("Cc", cc), _addresses("Bcc", bcc)
    if not rcpt_to + rcpt_cc + rcpt_bcc:
        raise ValueError("no recipient")
    if len(rcpt_to + rcpt_cc + rcpt_bcc) > MAX_RECIPIENTS:
        raise ValueError(f"more than {MAX_RECIPIENTS} recipients")
    if len(body) > MAX_BODY:
        raise ValueError(f"the text is longer than {MAX_BODY} characters")
    msg["From"] = sender[0]
    if rcpt_to:
        msg["To"] = ", ".join(rcpt_to)
    if rcpt_cc:
        msg["Cc"] = ", ".join(rcpt_cc)
    msg["Subject"] = _one_line("Subject", subject)
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain=parseaddr(sender[0])[1].rsplit("@", 1)[-1])
    if in_reply_to:
        msg["In-Reply-To"] = _one_line("In-Reply-To", in_reply_to)
        msg["References"] = _one_line("References", (references + " " + in_reply_to).strip())
    msg["X-Mailer"] = "axross"
    msg.set_content(body)
    return Outgoing(msg, rcpt_bcc)


def _is_local(host: str) -> bool:
    return host in ("localhost", "127.0.0.1", "::1")


def send(settings: SmtpSettings, out: Outgoing) -> list[str]:
    """Send *out*; the envelope recipients it was accepted for."""
    msg = out.message
    host = settings.host
    if settings.security not in ("ssl", "starttls", "plain"):
        raise ValueError(f"unknown SMTP security {settings.security!r}")
    if settings.security == "plain" and not _is_local(host):
        raise ValueError("plain SMTP (no TLS) only to this machine")
    context = ssl.create_default_context()

    def connect_socket(h, p, timeout):
        if settings.proxy is not None:
            from core.proxy import create_proxy_socket

            return create_proxy_socket(settings.proxy, h, p, timeout=timeout)
        from core.proxy import create_direct_socket

        return create_direct_socket(h, p, timeout=timeout)

    class _SMTP(smtplib.SMTP):
        def _get_socket(self, h, p, timeout):
            return connect_socket(h, p, timeout)

    class _SMTPS(smtplib.SMTP_SSL):
        def _get_socket(self, h, p, timeout):
            return context.wrap_socket(connect_socket(h, p, timeout), server_hostname=h)

    recipients = [addr for _n, addr in getaddresses([msg.get("To", ""), msg.get("Cc", ""), *out.bcc]) if addr]
    if settings.security == "ssl":
        client = _SMTPS(host, settings.port or 465, timeout=settings.timeout, context=context)
    else:
        client = _SMTP(host, settings.port or 587, timeout=settings.timeout)
    with client:
        if settings.security == "starttls":
            client.ehlo()
            if not client.has_extn("starttls"):
                raise OSError(f"{host} offers no STARTTLS - refusing to send in the clear")
            client.starttls(context=context)
            client.ehlo()
        if settings.username:
            client.login(settings.username, settings.password)
        refused = client.send_message(msg, from_addr=parseaddr(msg["From"])[1], to_addrs=recipients)
    return [r for r in recipients if r not in refused]


def save_draft(imap_session, msg: Outgoing, mailbox: str = "") -> str:
    """APPEND *msg* to the Drafts mailbox with \\Draft; the mailbox used."""
    box = mailbox or imap_session.special_mailbox("drafts") or "Drafts"
    imap_session.append_message(box, msg.as_bytes(), ("\\Draft", "\\Seen"))
    return box


def save_sent(imap_session, msg: Outgoing, mailbox: str = "") -> str:
    box = mailbox or imap_session.special_mailbox("sent")
    if box:
        imap_session.append_message(box, msg.as_bytes(), ("\\Seen",))
    return box
