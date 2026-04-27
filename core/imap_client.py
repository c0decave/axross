"""IMAP4 backend implementing the FileBackend protocol.

Maps email mailboxes and messages to a filesystem-like interface:

    /                       — root, lists all mailboxes
    /INBOX/                 — lists emails in INBOX as files
    /INBOX/1234_subject.eml — raw email (RFC 822) for message UID 1234
    /INBOX/1234/            — list attachments of message UID 1234
    /INBOX/1234/report.pdf  — download attachment from message 1234

Uses only Python stdlib (imaplib, email).
"""
from __future__ import annotations

import email
import email.header
import email.policy
import email.utils
import imaplib
import io
import logging
import posixpath
import re
import tempfile
from datetime import datetime
from typing import IO

from models.file_item import FileItem

log = logging.getLogger(__name__)

# Characters not allowed in filenames — replaced with underscore
_FILENAME_BAD_CHARS = re.compile(r'[/\\:*?"<>|\x00-\x1f]')

# Matches IMAP LIST response:  (\HasChildren) "/" "INBOX"
_LIST_RE = re.compile(
    rb'\((?P<flags>[^)]*)\)\s+"?(?P<sep>[^"]*)"?\s+"?(?P<name>[^"]*)"?'
)

# Matches quota response values like (STORAGE 1234 5678)
_QUOTA_RE = re.compile(r'\(STORAGE\s+(\d+)\s+(\d+)\)', re.IGNORECASE)


def _sanitize_filename(name: str, max_len: int = 120) -> str:
    """Sanitize a string for use as a filename component."""
    name = _FILENAME_BAD_CHARS.sub("_", name)
    name = name.strip(". ")
    if not name:
        name = "untitled"
    if len(name) > max_len:
        name = name[:max_len]
    return name


class _ProxyIMAP4(imaplib.IMAP4):
    """IMAP4 subclass that builds its TCP socket through a SOCKS /
    HTTP proxy via :func:`core.proxy.create_proxy_socket`.

    ``imaplib`` itself has no proxy hook, but it cleanly delegates
    socket creation to ``_create_socket(self, timeout)``. Overriding
    that one method routes every byte of the IMAP session through
    the proxy without touching the rest of imaplib's state machine.
    """

    def __init__(self, host: str, port: int, proxy_config):
        self._axross_proxy = proxy_config
        super().__init__(host, port)

    def _create_socket(self, timeout=None):
        from core.proxy import create_proxy_socket
        timeout = float(timeout) if timeout is not None else 30.0
        return create_proxy_socket(
            self._axross_proxy, self.host, int(self.port), timeout=timeout,
        )


class _ProxyIMAP4_SSL(imaplib.IMAP4_SSL):
    """IMAP4_SSL counterpart. Re-uses the proxy socket-builder, then
    wraps the result in TLS via the SSL context imaplib already
    constructs internally."""

    def __init__(self, host: str, port: int, proxy_config, ssl_context=None):
        self._axross_proxy = proxy_config
        super().__init__(host, port, ssl_context=ssl_context)

    def _create_socket(self, timeout=None):
        from core.proxy import create_proxy_socket
        timeout = float(timeout) if timeout is not None else 30.0
        raw = create_proxy_socket(
            self._axross_proxy, self.host, int(self.port), timeout=timeout,
        )
        # ssl_context is populated by IMAP4_SSL.__init__ (defaults to
        # ssl._create_stdlib_context() when None was passed in).
        return self.ssl_context.wrap_socket(raw, server_hostname=self.host)


def _decode_header(raw: str | bytes | None) -> str:
    """Decode an RFC 2047 encoded header value into a plain string."""
    if raw is None:
        return ""
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")
    parts = email.header.decode_header(raw)
    decoded: list[str] = []
    for fragment, charset in parts:
        if isinstance(fragment, bytes):
            decoded.append(fragment.decode(charset or "utf-8", errors="replace"))
        else:
            decoded.append(fragment)
    return " ".join(decoded)


def _imap_utf7_encode(text: str) -> bytes:
    """Encode a mailbox name using modified UTF-7 (IMAP convention).

    ASCII printable characters (0x20-0x7E) except '&' pass through unchanged.
    Non-ASCII characters are encoded as modified BASE64 wrapped in & ... -.
    Literal '&' is encoded as '&-'.
    """
    result = bytearray()
    buf = ""
    for ch in text:
        if 0x20 <= ord(ch) <= 0x7E:
            if buf:
                import base64
                encoded = base64.b64encode(buf.encode("utf-16-be")).rstrip(b"=")
                result.extend(b"&" + encoded.replace(b"/", b",") + b"-")
                buf = ""
            if ch == "&":
                result.extend(b"&-")
            else:
                result.append(ord(ch))
        else:
            buf += ch
    if buf:
        import base64
        encoded = base64.b64encode(buf.encode("utf-16-be")).rstrip(b"=")
        result.extend(b"&" + encoded.replace(b"/", b",") + b"-")
    return bytes(result)


def _imap_utf7_decode(data: bytes) -> str:
    """Decode a modified UTF-7 (IMAP) mailbox name to a Python string."""
    import base64
    result: list[str] = []
    i = 0
    while i < len(data):
        if data[i:i + 1] == b"&":
            # Find the closing '-'
            j = data.find(b"-", i + 1)
            if j == -1:
                # Malformed: no closing '-', treat '&' as literal
                result.append("&")
                i += 1
                continue
            if j == i + 1:
                # "&-" is a literal "&"
                result.append("&")
            else:
                encoded = data[i + 1:j].replace(b",", b"/")
                # Add padding
                pad = 4 - len(encoded) % 4
                if pad < 4:
                    encoded += b"=" * pad
                decoded_bytes = base64.b64decode(encoded)
                result.append(decoded_bytes.decode("utf-16-be"))
            i = j + 1
        else:
            result.append(chr(data[i]))
            i += 1
    return "".join(result)


class _SpooledWriter:
    """Write to a temp buffer, then IMAP APPEND on close.

    If ``filename`` is set, the written bytes are wrapped in a minimal
    RFC 822 message with the data as an attachment before appending.
    If ``filename`` is None, the bytes are assumed to be a complete
    RFC 822 message already (e.g. when copying .eml files).
    """

    def __init__(
        self,
        imap: imaplib.IMAP4 | imaplib.IMAP4_SSL,
        mailbox: str,
        filename: str | None = None,
    ):
        self._imap = imap
        self._mailbox = mailbox
        self._filename = filename
        self._buf = tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024)

    def write(self, data: bytes) -> int:
        return self._buf.write(data)

    def read(self, n: int = -1) -> bytes:
        return self._buf.read(n)

    def seek(self, pos: int, whence: int = 0) -> int:
        return self._buf.seek(pos, whence)

    def tell(self) -> int:
        return self._buf.tell()

    def close(self) -> None:
        self._buf.seek(0)
        raw_bytes = self._buf.read()
        self._buf.close()

        if self._filename and not self._filename.lower().endswith(".eml"):
            # Wrap arbitrary file data in a minimal RFC 822 message
            message_bytes = self._wrap_as_email(raw_bytes, self._filename)
        else:
            message_bytes = raw_bytes

        mailbox_encoded = _imap_utf7_encode(self._mailbox).decode("ascii")
        typ, data = self._imap.append(
            mailbox_encoded, None, None, message_bytes
        )
        if typ != "OK":
            raise OSError(
                f"IMAP APPEND to {self._mailbox} failed: {data}"
            )
        log.info("Appended %d bytes to mailbox %s", len(message_bytes), self._mailbox)

    def discard(self) -> None:
        """Drop buffered bytes without APPENDing to the mailbox
        (transfer cancel path)."""
        try:
            self._buf.close()
        except Exception:  # noqa: BLE001
            pass

    @staticmethod
    def _wrap_as_email(data: bytes, filename: str) -> bytes:
        """Wrap raw file data in an RFC 822 message with the file as attachment."""
        import email.mime.base
        import email.mime.multipart
        import email.mime.text
        from email.utils import formatdate

        msg = email.mime.multipart.MIMEMultipart()
        msg["Subject"] = f"File: {filename}"
        msg["From"] = "axross@localhost"
        msg["Date"] = formatdate(localtime=True)
        msg.attach(email.mime.text.MIMEText(
            f"File '{filename}' uploaded via axross.", "plain"
        ))

        attachment = email.mime.base.MIMEBase("application", "octet-stream")
        attachment.set_payload(data)
        import email.encoders
        email.encoders.encode_base64(attachment)
        attachment.add_header(
            "Content-Disposition", "attachment", filename=filename,
        )
        msg.attach(attachment)
        return msg.as_bytes()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class ImapSession:
    """IMAP4 backend implementing the FileBackend protocol.

    Maps IMAP mailboxes to directories and email messages to files,
    providing a filesystem-like view of an IMAP account.
    """

    def __init__(
        self,
        host: str,
        port: int = 993,
        username: str = "",
        password: str = "",
        use_ssl: bool = True,
        proxy_type: str = "none",
        proxy_host: str = "",
        proxy_port: int = 0,
        proxy_username: str = "",
        proxy_password: str = "",
    ):
        self._host = host
        self._port = port
        self._username = username
        self._password = password
        self._use_ssl = use_ssl
        from core.proxy import ProxyConfig
        self._proxy = ProxyConfig(
            proxy_type=proxy_type or "none",
            host=proxy_host,
            port=int(proxy_port or 0),
            username=proxy_username,
            password=proxy_password,
        )
        self._imap: imaplib.IMAP4 | imaplib.IMAP4_SSL | None = None
        self._hierarchy_sep: str = "/"
        self._selected_mailbox: str | None = None
        self._mailbox_cache: set[str] | None = None

        self._connect()

    def _connect(self) -> None:
        """Establish IMAP connection and authenticate."""
        # ``_proxy`` is set by ``__init__``; defensively tolerate the
        # __new__-bypass pattern some unit tests use.
        proxy = getattr(self, "_proxy", None)
        proxy_active = proxy is not None and proxy.enabled
        try:
            if self._use_ssl:
                if proxy_active:
                    self._imap = _ProxyIMAP4_SSL(self._host, self._port, proxy)
                else:
                    self._imap = imaplib.IMAP4_SSL(self._host, self._port)
            else:
                # Credentials will traverse the wire in plaintext — this is
                # occasionally legitimate (localhost, overlay VPN), but it
                # is almost always a misconfiguration the user wants to know
                # about.
                log.warning(
                    "IMAP connecting to %s:%d WITHOUT TLS — credentials "
                    "will be sent in plaintext",
                    self._host, self._port,
                )
                if proxy_active:
                    self._imap = _ProxyIMAP4(self._host, self._port, proxy)
                else:
                    self._imap = imaplib.IMAP4(self._host, self._port)

            typ, data = self._imap.login(self._username, self._password)
            if typ != "OK":
                raise ConnectionError(
                    f"IMAP LOGIN failed: {data}"
                )

            # Detect hierarchy separator from LIST
            try:
                typ, data = self._imap.list('""', '""')
                if typ == "OK" and data and data[0]:
                    raw = data[0] if isinstance(data[0], bytes) else data[0].encode()
                    m = _LIST_RE.match(raw)
                    if m:
                        sep = m.group("sep").decode("ascii", errors="replace").strip()
                        if sep:
                            self._hierarchy_sep = sep
            except Exception as exc:
                log.debug("Could not detect hierarchy separator: %s", exc)

            log.info(
                "IMAP%s connected: %s@%s:%d (sep=%r)",
                "S" if self._use_ssl else "",
                self._username, self._host, self._port,
                self._hierarchy_sep,
            )
        except Exception:
            self._imap = None
            raise

    def _ensure_connected(self) -> imaplib.IMAP4 | imaplib.IMAP4_SSL:
        """Return the IMAP connection, reconnecting if needed."""
        if self._imap is None:
            self._connect()
        assert self._imap is not None
        try:
            self._imap.noop()
        except Exception:
            self._connect()
        assert self._imap is not None
        return self._imap

    def _select_mailbox(self, mailbox: str, readonly: bool = True) -> None:
        """Select a mailbox if not already selected.

        Tracks the writable/read-only mode in the cache so that a
        subsequent call asking for write access re-selects when
        the previous selection was read-only (otherwise STOREs
        would silently no-op against an EXAMINE'd mailbox).
        """
        imap = self._ensure_connected()
        encoded = _imap_utf7_encode(mailbox).decode("ascii")
        if (
            self._selected_mailbox == mailbox
            and getattr(self, "_selected_readonly", True) == readonly
        ):
            return
        typ, data = imap.select(encoded, readonly=readonly)
        if typ != "OK":
            raise OSError(f"Cannot select mailbox {mailbox!r}: {data}")
        self._selected_mailbox = mailbox
        self._selected_readonly = readonly

    def _mailbox_names(self) -> set[str]:
        """Return known mailbox names, refreshing from IMAP when needed."""
        if self._mailbox_cache is not None:
            return set(self._mailbox_cache)

        imap = self._ensure_connected()
        typ, data = imap.list()
        if typ != "OK":
            raise OSError(f"IMAP LIST failed: {data}")

        names: set[str] = set()
        for entry in data:
            if entry is None:
                continue
            raw = entry if isinstance(entry, bytes) else entry.encode()
            match = _LIST_RE.match(raw)
            if not match:
                log.debug("Unparseable LIST entry: %r", entry)
                continue
            names.add(_imap_utf7_decode(match.group("name")))

        self._mailbox_cache = names
        return set(names)

    def _virtual_path_to_mailbox(self, path: str) -> str:
        """Map a virtual path like ``/Inbox/Sub`` to an IMAP mailbox name."""
        normalized = self.normalize(path)
        parts = [p for p in normalized.split("/") if p]
        if not parts:
            raise OSError("Root is not a mailbox")
        return self._hierarchy_sep.join(parts)

    @staticmethod
    def _attachment_name(part) -> str | None:
        filename = part.get_filename()
        if filename:
            return _sanitize_filename(filename)

        content_disp = part.get("Content-Disposition", "")
        if "attachment" not in content_disp.lower():
            return None

        content_type = part.get_content_type()
        ext = content_type.split("/")[-1] if "/" in content_type else "bin"
        return f"attachment.{ext}"

    # ------------------------------------------------------------------
    # Path parsing
    # ------------------------------------------------------------------

    def _parse_path(self, path: str) -> tuple:
        """Parse a virtual path into components.

        Returns:
            (None,)                         — root (list mailboxes)
            (mailbox,)                      — list messages in mailbox
            (mailbox, uid)                  — specific message (.eml)
            (mailbox, uid, attachment_name) — specific attachment
        """
        path = self.normalize(path)
        parts = [p for p in path.split("/") if p]

        if not parts:
            return (None,)

        mailbox_names = self._mailbox_names()
        mailbox: str | None = None
        remainder: list[str] = []
        for index in range(len(parts), 0, -1):
            candidate = self._hierarchy_sep.join(parts[:index])
            if candidate in mailbox_names:
                mailbox = candidate
                remainder = parts[index:]
                break

        if mailbox is None:
            mailbox = parts[0]
            remainder = parts[1:]

        if not remainder:
            return (mailbox,)

        # Second part is either "uid.eml" or "uid" (directory for attachments)
        name_part = remainder[0]
        uid_str = name_part
        # Strip .eml extension if present
        if uid_str.lower().endswith(".eml"):
            uid_str = uid_str[:-4]
        # Extract UID: it's the part before the first underscore
        uid_match = re.match(r"^(\d+)", uid_str)
        if not uid_match:
            # Non-UID filename (e.g. transfer temp file ".readme.txt.part-xxx"
            # or an arbitrary file being written).  Return mailbox + raw name
            # so callers can handle it gracefully.
            if len(remainder) == 1:
                return (mailbox, None)
            raise OSError(f"Invalid message identifier in path: {name_part!r}")
        uid = uid_match.group(1)

        if len(remainder) == 1:
            if name_part.lower().endswith(".eml"):
                # Explicit .eml reference — this is the raw message
                return (mailbox, uid)
            # Could be a directory (listing attachments) or a message file
            # Treat as message if it looks like "uid_subject.eml", directory otherwise
            return (mailbox, uid)

        if len(remainder) == 2:
            attachment_name = remainder[1]
            return (mailbox, uid, attachment_name)

        raise OSError(f"Path too deep: {path!r}")

    # ------------------------------------------------------------------
    # FileBackend interface
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        proto = "IMAPS" if self._use_ssl else "IMAP"
        return f"{self._username}@{self._host} ({proto})"

    @property
    def connected(self) -> bool:
        if self._imap is None:
            return False
        try:
            self._imap.noop()
            return True
        except Exception:
            return False

    def close(self) -> None:
        self.disconnect()

    def disconnect(self) -> None:
        """Close the IMAP connection."""
        if self._imap is not None:
            try:
                if self._selected_mailbox is not None:
                    self._imap.close()
            except Exception:
                pass
            try:
                self._imap.logout()
            except Exception:
                pass
            self._imap = None
            self._selected_mailbox = None
            self._mailbox_cache = None
        log.info("Disconnected from %s", self._host)

    def list_dir(self, path: str) -> list[FileItem]:
        """List directory contents at the given virtual path."""
        parsed = self._parse_path(path)

        if parsed == (None,):
            return self._list_mailboxes()
        if len(parsed) == 1:
            return self._list_messages(parsed[0])
        if len(parsed) == 2:
            mailbox, uid = parsed
            if uid is None:
                raise FileNotFoundError(f"Path not found: {path}")
            return self._list_attachments(mailbox, uid)

        raise OSError(f"Cannot list: {path!r} is a file, not a directory")

    def _list_mailboxes(self) -> list[FileItem]:
        """List all mailboxes as directory entries."""
        imap = self._ensure_connected()
        typ, data = imap.list()
        if typ != "OK":
            raise OSError(f"IMAP LIST failed: {data}")

        items: list[FileItem] = []
        mailbox_names: set[str] = set()
        for entry in data:
            if entry is None:
                continue
            raw = entry if isinstance(entry, bytes) else entry.encode()
            m = _LIST_RE.match(raw)
            if not m:
                log.debug("Unparseable LIST entry: %r", entry)
                continue

            flags = m.group("flags").decode("ascii", errors="replace")
            name_bytes = m.group("name")
            name = _imap_utf7_decode(name_bytes)
            mailbox_names.add(name)

            # Skip \Noselect mailboxes
            if "\\Noselect" in flags:
                continue

            items.append(FileItem(
                name=name,
                is_dir=True,
            ))

        self._mailbox_cache = mailbox_names
        return items

    def _list_messages(self, mailbox: str) -> list[FileItem]:
        """List messages in a mailbox as file entries."""
        self._select_mailbox(mailbox, readonly=True)
        imap = self._ensure_connected()

        typ, data = imap.uid("SEARCH", None, "ALL")
        if typ != "OK":
            raise OSError(f"IMAP UID SEARCH failed in {mailbox!r}: {data}")

        uids_raw = data[0]
        if not uids_raw or not uids_raw.strip():
            return []

        uid_list = uids_raw.split()
        items: list[FileItem] = []

        # Fetch envelopes in batches to avoid overly long commands
        batch_size = 100
        for i in range(0, len(uid_list), batch_size):
            batch = b",".join(uid_list[i:i + batch_size])
            typ, fetch_data = imap.uid(
                "FETCH", batch.decode("ascii"),
                "(ENVELOPE RFC822.SIZE INTERNALDATE)"
            )
            if typ != "OK":
                log.warning("FETCH failed for UIDs %s: %s", batch, fetch_data)
                continue

            for response_part in fetch_data:
                if isinstance(response_part, tuple):
                    header_line = response_part[0]
                elif isinstance(response_part, bytes):
                    header_line = response_part
                else:
                    continue
                if isinstance(header_line, bytes):
                    header_line = header_line.decode("ascii", errors="replace")

                # Extract UID
                uid_match = re.search(r"UID\s+(\d+)", header_line)
                if not uid_match:
                    continue
                uid = uid_match.group(1)

                # Extract RFC822.SIZE
                size = 0
                size_match = re.search(r"RFC822\.SIZE\s+(\d+)", header_line)
                if size_match:
                    size = int(size_match.group(1))

                # Extract INTERNALDATE
                modified = datetime.fromtimestamp(0)
                date_match = re.search(
                    r'INTERNALDATE\s+"([^"]+)"', header_line
                )
                if date_match:
                    try:
                        modified = datetime(
                            *email.utils.parsedate(date_match.group(1))[:6]
                        )
                    except Exception:
                        pass

                # Extract subject from ENVELOPE
                subject = "no_subject"
                env_match = re.search(r"ENVELOPE\s+\(", header_line)
                if env_match:
                    subject = self._extract_envelope_subject(
                        header_line[env_match.start():]
                    )

                sanitized_subject = _sanitize_filename(subject, max_len=80)
                eml_name = f"{uid}_{sanitized_subject}.eml"

                # Add the message as a file
                items.append(FileItem(
                    name=eml_name,
                    size=size,
                    modified=modified,
                ))

        return items

    def _extract_envelope_subject(self, envelope_str: str) -> str:
        """Extract the subject field from an IMAP ENVELOPE response.

        The ENVELOPE is structured as:
            (date subject from sender reply-to to cc bcc in-reply-to message-id)
        where subject is the second field (index 1), a quoted string or NIL.
        """
        # Find opening paren of ENVELOPE
        depth = 0
        start = envelope_str.index("(")
        # Skip the date field (first element)
        i = start + 1

        # Skip whitespace
        while i < len(envelope_str) and envelope_str[i] == " ":
            i += 1

        # Skip the date field (a quoted string or NIL)
        i = self._skip_envelope_field(envelope_str, i)

        # Skip whitespace
        while i < len(envelope_str) and envelope_str[i] == " ":
            i += 1

        # Now we're at the subject field
        if i >= len(envelope_str):
            return "no_subject"

        if envelope_str[i:i + 3].upper() == "NIL":
            return "no_subject"

        if envelope_str[i] == '"':
            # Quoted string — find the closing quote (handle escapes)
            j = i + 1
            while j < len(envelope_str):
                if envelope_str[j] == "\\":
                    j += 2
                    continue
                if envelope_str[j] == '"':
                    break
                j += 1
            raw_subject = envelope_str[i + 1:j]
            # Unescape
            raw_subject = raw_subject.replace('\\"', '"').replace("\\\\", "\\")
            return _decode_header(raw_subject) or "no_subject"

        if envelope_str[i] == "{":
            # Literal string — this is uncommon in ENVELOPE, but handle it
            return "no_subject"

        return "no_subject"

    @staticmethod
    def _skip_envelope_field(s: str, i: int) -> int:
        """Skip one ENVELOPE field (quoted string, NIL, or parenthesized list)."""
        if i >= len(s):
            return i

        if s[i:i + 3].upper() == "NIL":
            return i + 3

        if s[i] == '"':
            j = i + 1
            while j < len(s):
                if s[j] == "\\":
                    j += 2
                    continue
                if s[j] == '"':
                    return j + 1
                j += 1
            return j

        if s[i] == "(":
            depth = 1
            j = i + 1
            while j < len(s) and depth > 0:
                if s[j] == "(":
                    depth += 1
                elif s[j] == ")":
                    depth -= 1
                elif s[j] == '"':
                    # Skip quoted string inside parens
                    j += 1
                    while j < len(s):
                        if s[j] == "\\":
                            j += 2
                            continue
                        if s[j] == '"':
                            break
                        j += 1
                j += 1
            return j

        # Unknown token — skip to whitespace
        j = i
        while j < len(s) and s[j] not in (" ", ")"):
            j += 1
        return j

    def _list_attachments(self, mailbox: str, uid: str) -> list[FileItem]:
        """List MIME attachments of a specific message as file entries."""
        raw = self._fetch_raw_message(mailbox, uid)
        msg = email.message_from_bytes(raw, policy=email.policy.default)
        items: list[FileItem] = []

        for part in msg.walk():
            attachment_name = self._attachment_name(part)
            if attachment_name is None:
                continue
            payload = part.get_payload(decode=True)
            size = len(payload) if payload else 0
            items.append(FileItem(
                name=attachment_name,
                size=size,
            ))

        return items

    def _fetch_raw_message(self, mailbox: str, uid: str) -> bytes:
        """Fetch the full RFC822 body of a message by UID."""
        self._select_mailbox(mailbox, readonly=True)
        imap = self._ensure_connected()
        typ, data = imap.uid("FETCH", uid, "(RFC822)")
        if typ != "OK":
            raise OSError(f"Cannot fetch message UID {uid} from {mailbox!r}: {data}")
        for response_part in data:
            if isinstance(response_part, tuple):
                return response_part[1]
        raise OSError(f"No RFC822 body returned for UID {uid} in {mailbox!r}")

    def stat(self, path: str) -> FileItem:
        """Return a FileItem for the given virtual path."""
        parsed = self._parse_path(path)

        if parsed == (None,):
            return FileItem(name="/", is_dir=True)

        if len(parsed) == 1:
            # Mailbox
            mailbox = parsed[0]
            if mailbox not in self._mailbox_names():
                raise FileNotFoundError(f"Mailbox not found: {mailbox}")
            return FileItem(name=mailbox, is_dir=True)

        if len(parsed) == 2:
            mailbox, uid = parsed
            if uid is None:
                raise FileNotFoundError(f"Path not found: {path}")
            # Check if path ends with .eml
            normalized = self.normalize(path)
            parts = [p for p in normalized.split("/") if p]
            leaf_name = parts[-1] if parts else path
            if leaf_name.lower().endswith(".eml"):
                # It's a message file
                self._select_mailbox(mailbox, readonly=True)
                imap = self._ensure_connected()
                typ, data = imap.uid("FETCH", uid, "(RFC822.SIZE INTERNALDATE)")
                if typ != "OK":
                    raise OSError(f"Cannot stat message UID {uid}: {data}")
                size = 0
                modified = datetime.fromtimestamp(0)
                for response_part in data:
                    if isinstance(response_part, tuple):
                        line = response_part[0]
                        if isinstance(line, bytes):
                            line = line.decode("ascii", errors="replace")
                        sm = re.search(r"RFC822\.SIZE\s+(\d+)", line)
                        if sm:
                            size = int(sm.group(1))
                        dm = re.search(r'INTERNALDATE\s+"([^"]+)"', line)
                        if dm:
                            try:
                                modified = datetime(
                                    *email.utils.parsedate(dm.group(1))[:6]
                                )
                            except Exception:
                                pass
                return FileItem(name=leaf_name, size=size, modified=modified)
            else:
                # It's the attachment directory for this UID
                return FileItem(name=uid, is_dir=True)

        if len(parsed) == 3:
            mailbox, uid, att_name = parsed
            # Stat an attachment
            raw = self._fetch_raw_message(mailbox, uid)
            msg = email.message_from_bytes(raw, policy=email.policy.default)
            for part in msg.walk():
                if self._attachment_name(part) == att_name:
                    payload = part.get_payload(decode=True)
                    size = len(payload) if payload else 0
                    return FileItem(name=att_name, size=size)
            raise OSError(f"Attachment {att_name!r} not found in UID {uid}")

        raise OSError(f"Invalid path: {path!r}")

    def is_dir(self, path: str) -> bool:
        """Check if the path refers to a directory-like entity."""
        parsed = self._parse_path(path)
        if parsed == (None,):
            return True
        if len(parsed) == 1:
            return parsed[0] in self._mailbox_names()
        if len(parsed) == 2:
            mailbox, uid = parsed
            if uid is None:
                return False  # Non-UID filename — treat as file
            # Check if it's a .eml file reference or attachment dir
            normalized = self.normalize(path)
            parts = [p for p in normalized.split("/") if p]
            if parts and parts[-1].lower().endswith(".eml"):
                return False
            return True  # Attachment listing directory
        return False  # Attachment file

    def exists(self, path: str) -> bool:
        """Check if the given path exists."""
        try:
            self.stat(path)
            return True
        except OSError:
            return False

    def mkdir(self, path: str) -> None:
        """Create a new mailbox."""
        mailbox = self._virtual_path_to_mailbox(path)
        imap = self._ensure_connected()
        encoded = _imap_utf7_encode(mailbox).decode("ascii")
        typ, data = imap.create(encoded)
        if typ != "OK":
            raise OSError(f"Cannot create mailbox {mailbox!r}: {data}")
        self._mailbox_cache = None
        log.info("Created mailbox: %s", mailbox)

    def remove(self, path: str, recursive: bool = False) -> None:
        """Delete a message or mailbox.

        For messages: mark \\Deleted and expunge.
        For mailboxes: delete the mailbox via IMAP DELETE.
        """
        parsed = self._parse_path(path)

        if parsed == (None,):
            raise OSError("Cannot remove root")

        if len(parsed) == 1:
            # Delete mailbox
            mailbox = parsed[0]
            imap = self._ensure_connected()
            # Unselect current mailbox if it's the one being deleted
            if self._selected_mailbox == mailbox:
                try:
                    imap.close()
                except Exception:
                    pass
                self._selected_mailbox = None
            encoded = _imap_utf7_encode(mailbox).decode("ascii")
            typ, data = imap.delete(encoded)
            if typ != "OK":
                raise OSError(f"Cannot delete mailbox {mailbox!r}: {data}")
            self._mailbox_cache = None
            log.info("Deleted mailbox: %s", mailbox)
            return

        if len(parsed) >= 2:
            mailbox, uid = parsed[0], parsed[1]
            if uid is None:
                log.debug("Ignoring remove for non-UID path: %s", path)
                return  # Non-UID path (temp file etc.) — nothing to delete
            self._select_mailbox(mailbox, readonly=False)
            imap = self._ensure_connected()
            typ, data = imap.uid("STORE", uid, "+FLAGS", "(\\Deleted)")
            if typ != "OK":
                raise OSError(
                    f"Cannot mark UID {uid} as deleted in {mailbox!r}: {data}"
                )
            typ, data = imap.expunge()
            if typ != "OK":
                log.warning("Expunge failed in %s: %s", mailbox, data)
            self._selected_mailbox = None  # State may have changed
            log.info("Deleted message UID %s from %s", uid, mailbox)
            return

        raise OSError(f"Cannot remove: {path!r}")

    def rename(self, src: str, dst: str) -> None:
        """Rename a mailbox or move a message.

        For mailboxes: IMAP RENAME.
        For messages: COPY to new mailbox + DELETE from old.
        """
        src_parsed = self._parse_path(src)
        dst_parsed = self._parse_path(dst)

        # Rename mailbox
        if len(src_parsed) == 1 and src_parsed[0] is not None and src_parsed[0] in self._mailbox_names():
            old_name = src_parsed[0]
            new_name = self._virtual_path_to_mailbox(dst)
            imap = self._ensure_connected()
            if self._selected_mailbox == old_name:
                try:
                    imap.close()
                except Exception:
                    pass
                self._selected_mailbox = None
            old_enc = _imap_utf7_encode(old_name).decode("ascii")
            new_enc = _imap_utf7_encode(new_name).decode("ascii")
            typ, data = imap.rename(old_enc, new_enc)
            if typ != "OK":
                raise OSError(
                    f"Cannot rename mailbox {old_name!r} to {new_name!r}: {data}"
                )
            self._mailbox_cache = None
            log.info("Renamed mailbox %s -> %s", old_name, new_name)
            return

        # Move message: copy to new mailbox, then delete from old
        if len(src_parsed) >= 2 and len(dst_parsed) >= 1:
            src_mailbox, src_uid = src_parsed[0], src_parsed[1]
            if src_uid is None:
                raise OSError(f"Cannot rename non-message path: {src!r}")
            dst_mailbox = dst_parsed[0]
            if dst_mailbox is None:
                raise OSError("Cannot move message to root")

            self._select_mailbox(src_mailbox, readonly=False)
            imap = self._ensure_connected()

            dst_enc = _imap_utf7_encode(dst_mailbox).decode("ascii")
            typ, data = imap.uid("COPY", src_uid, dst_enc)
            if typ != "OK":
                raise OSError(
                    f"Cannot copy UID {src_uid} to {dst_mailbox!r}: {data}"
                )

            # Delete from source
            typ, data = imap.uid("STORE", src_uid, "+FLAGS", "(\\Deleted)")
            if typ != "OK":
                log.warning(
                    "Could not mark UID %s as deleted after copy: %s",
                    src_uid, data,
                )
            imap.expunge()
            self._selected_mailbox = None
            log.info(
                "Moved message UID %s from %s to %s",
                src_uid, src_mailbox, dst_mailbox,
            )
            return

        raise OSError(f"Cannot rename {src!r} to {dst!r}")

    def open_read(self, path: str) -> IO[bytes]:
        """Download an email (.eml) or an attachment."""
        parsed = self._parse_path(path)

        if len(parsed) == 2:
            mailbox, uid = parsed
            if uid is None:
                raise OSError(f"Cannot read non-message path: {path!r}")
            raw = self._fetch_raw_message(mailbox, uid)
            return io.BytesIO(raw)

        if len(parsed) == 3:
            # Specific attachment
            mailbox, uid, att_name = parsed
            raw = self._fetch_raw_message(mailbox, uid)
            msg = email.message_from_bytes(raw, policy=email.policy.default)
            for part in msg.walk():
                if self._attachment_name(part) == att_name:
                    payload = part.get_payload(decode=True)
                    if payload is None:
                        payload = b""
                    return io.BytesIO(payload)
            raise OSError(
                f"Attachment {att_name!r} not found in UID {uid} of {mailbox!r}"
            )

        raise OSError(f"Cannot read: {path!r} is a directory")

    def open_write(self, path: str, append: bool = False) -> IO[bytes]:
        """Upload / append a message to a mailbox (IMAP APPEND).

        Accepts paths like:
            /INBOX              — write raw RFC 822 bytes directly
            /INBOX/readme.txt   — wrap arbitrary file in an RFC 822 email
            /INBOX/5_sub.eml    — write raw RFC 822 bytes directly

        The transfer worker may create temp paths like
        ``/INBOX/.readme.txt.part-<id>`` which are not valid UID references.
        We handle those by parsing the path manually instead of relying on
        ``_parse_path()`` (which expects a numeric UID prefix).
        """
        normalized = self.normalize(path)
        parts = [p for p in normalized.split("/") if p]

        if not parts:
            raise OSError(f"Cannot write to root: {path!r}")

        mailbox = parts[0]
        imap = self._ensure_connected()

        if len(parts) == 1:
            # Single component — could be a write to root like "/bigfile.bin"
            # or a legitimate mailbox name like "INBOX" or "Sent.Items".
            # Check if a mailbox with this name actually exists; if not,
            # treat it as a filename and write to INBOX.
            try:
                imap_enc = _imap_utf7_encode(mailbox).decode("ascii")
                typ, _ = imap.select(imap_enc, readonly=True)
                if typ == "OK":
                    self._selected_mailbox = mailbox
                    return _SpooledWriter(imap, mailbox)
            except Exception:
                pass
            # Mailbox doesn't exist — treat as filename, write to INBOX
            filename = mailbox
            mailbox = "INBOX"
            log.info("IMAP write to root-level file %r — using mailbox INBOX", filename)
            return _SpooledWriter(imap, mailbox, filename=filename)

        if len(parts) == 2:
            filename = parts[1]
            # Pass filename so _SpooledWriter can wrap non-.eml data
            return _SpooledWriter(imap, mailbox, filename=filename)

        raise OSError(
            f"Cannot write to {path!r}: only message-level writes are supported"
        )

    def normalize(self, path: str) -> str:
        """Normalize a virtual path."""
        path = (path or "/").replace("\\", "/")
        result = posixpath.normpath(path)
        if result == ".":
            return "/"
        if not result.startswith("/"):
            return f"/{result}"
        return result

    def separator(self) -> str:
        return "/"

    def join(self, *parts: str) -> str:
        return posixpath.join(*parts)

    def parent(self, path: str) -> str:
        return posixpath.dirname(self.normalize(path)) or "/"

    def home(self) -> str:
        return "/"

    def chmod(self, path: str, mode: int) -> None:
        raise OSError("IMAP does not support Unix permissions")

    def readlink(self, path: str) -> str:
        raise OSError("IMAP does not support symlinks")

    def list_versions(self, path: str) -> list:
        return []

    def open_version_read(self, path: str, version_id: str):
        raise OSError(
            f"{type(self).__name__} does not expose file version history"
        )

    def copy(self, src: str, dst: str) -> None:
        """IMAP has COPY for messages between mailboxes but the
        FileBackend abstraction doesn't map cleanly to that; raise
        for fallback so callers stay protocol-agnostic."""
        raise OSError("IMAP copy between mailboxes not exposed as FS primitive")

    def checksum(self, path: str, algorithm: str = "sha256") -> str:
        """IMAP doesn't checksum messages — FETCH BODY[] returns the
        full RFC822 which callers can stream-hash themselves."""
        return ""

    # ------------------------------------------------------------------
    # IMAP-specific verbs (slice 4 of API_GAPS)
    # ------------------------------------------------------------------

    def search(self, criteria: str = "ALL", *,
               mailbox: str = "INBOX") -> list[int]:
        """Run an IMAP SEARCH against ``mailbox`` and return the
        matching UIDs (NOT the message-sequence numbers — UIDs are
        stable across sessions; sequence numbers shift after expunge).

        ``criteria`` is the raw IMAP search string (RFC 3501 §6.4.4),
        e.g.::

            sess.search('FROM "boss@x.com" SINCE 1-Jan-2026')
            sess.search('UNSEEN SUBJECT "invoice"')
            sess.search('LARGER 1048576')   # > 1 MiB

        F32: refuse CR/LF in ``criteria`` and ``mailbox``. imaplib
        sends each command as ``<tag> <verb> <args>\\r\\n`` without
        re-escaping embedded CR/LF in the args, so a tainted
        criterion would smuggle a second IMAP command on the same
        connection. We block this BEFORE the wire frame is built.

        Caller is still responsible for escaping ``"`` characters
        inside quoted-string criteria — that's an IMAP-syntax issue
        rather than a smuggling one.
        """
        if "\r" in criteria or "\n" in criteria:
            raise ValueError(
                "IMAP search: criteria must not contain CR/LF (would "
                "smuggle a second IMAP command). F32."
            )
        if "\r" in mailbox or "\n" in mailbox:
            raise ValueError(
                "IMAP search: mailbox must not contain CR/LF. F32."
            )
        imap = self._ensure_connected()
        self._select_mailbox(mailbox, readonly=True)
        typ, data = imap.uid("SEARCH", None, criteria)
        if typ != "OK":
            raise OSError(f"IMAP SEARCH failed: {data}")
        if not data or data[0] is None:
            return []
        raw = data[0].decode() if isinstance(data[0], bytes) else data[0]
        return [int(u) for u in raw.split() if u.strip()]

    def fetch_flags(self, uid: int, *, mailbox: str = "INBOX") -> list[str]:
        """Return the flags currently set on a message (e.g.
        ``["\\Seen", "\\Answered"]``)."""
        imap = self._ensure_connected()
        self._select_mailbox(mailbox, readonly=True)
        typ, data = imap.uid("FETCH", str(int(uid)), "(FLAGS)")
        if typ != "OK" or not data:
            raise OSError(f"IMAP FETCH FLAGS failed: {data}")
        raw = data[0].decode() if isinstance(data[0], bytes) else str(data[0])
        m = re.search(r"FLAGS\s*\(([^)]*)\)", raw)
        if not m:
            return []
        return [f for f in m.group(1).split() if f]

    def set_flags(self, uid: int, flags: list[str] | tuple[str, ...], *,
                  mailbox: str = "INBOX",
                  mode: str = "set") -> None:
        """STORE flags on a message. ``mode`` is ``"set"`` (replace),
        ``"add"`` (``+FLAGS``), or ``"remove"`` (``-FLAGS``).

        ``flags`` are raw IMAP flag strings like ``"\\Seen"``,
        ``"\\Flagged"``, ``"\\Deleted"``, or any custom keyword the
        server allows.
        """
        if mode == "set":
            verb = "FLAGS"
        elif mode == "add":
            verb = "+FLAGS"
        elif mode == "remove":
            verb = "-FLAGS"
        else:
            raise ValueError(f"set_flags mode must be set/add/remove, got {mode!r}")
        # Validate flags shape — imaplib will happily smuggle a CR/LF
        # into the wire if we don't.
        for f in flags:
            if "\r" in f or "\n" in f or " " in f:
                raise ValueError(
                    f"set_flags flag {f!r} must not contain CR/LF/space"
                )
        imap = self._ensure_connected()
        self._select_mailbox(mailbox, readonly=False)
        typ, data = imap.uid(
            "STORE", str(int(uid)),
            verb, "(" + " ".join(flags) + ")",
        )
        if typ != "OK":
            raise OSError(f"IMAP STORE {verb} failed: {data}")

    def move(self, uid: int, src_mailbox: str, dst_mailbox: str) -> None:
        """Move a message from ``src_mailbox`` to ``dst_mailbox`` by
        UID. Uses the IMAP MOVE extension (RFC 6851) when the server
        announces it; falls back to COPY + STORE \\Deleted + EXPUNGE
        for pre-MOVE servers.

        F32: mailbox names with CR/LF are refused before any wire
        byte is sent."""
        for label, val in (("src_mailbox", src_mailbox),
                           ("dst_mailbox", dst_mailbox)):
            if "\r" in val or "\n" in val:
                raise ValueError(
                    f"IMAP move: {label} must not contain CR/LF. F32."
                )
        imap = self._ensure_connected()
        self._select_mailbox(src_mailbox, readonly=False)
        # capability() ASKs the server; cache locally to avoid spam.
        try:
            typ, caps = imap.capability()
            cap_str = b" ".join(caps).decode("ascii", errors="replace") \
                if isinstance(caps, list) else str(caps)
        except Exception:  # noqa: BLE001
            cap_str = ""
        dst_enc = _imap_utf7_encode(dst_mailbox).decode("ascii")
        if "MOVE" in cap_str.upper():
            typ, data = imap.uid("MOVE", str(int(uid)), dst_enc)
            if typ != "OK":
                raise OSError(f"IMAP MOVE failed: {data}")
            return
        # Fallback: COPY then STORE \\Deleted + EXPUNGE.
        typ, data = imap.uid("COPY", str(int(uid)), dst_enc)
        if typ != "OK":
            raise OSError(f"IMAP COPY (move-fallback) failed: {data}")
        self.set_flags(uid, ["\\Deleted"], mailbox=src_mailbox, mode="add")
        imap.expunge()

    def disk_usage(self, path: str) -> tuple[int, int, int]:
        """Return quota usage if the server supports IMAP QUOTA.

        Returns (total_bytes, used_bytes, free_bytes).
        """
        imap = self._ensure_connected()
        try:
            typ, data = imap.getquotaroot("INBOX")
            if typ != "OK":
                raise OSError("QUOTA not supported by server")

            # data is a list; the quota response may span multiple entries
            for entry in data:
                if entry is None:
                    continue
                text = entry.decode("ascii", errors="replace") if isinstance(entry, bytes) else str(entry)
                m = _QUOTA_RE.search(text)
                if m:
                    used_kb = int(m.group(1))
                    total_kb = int(m.group(2))
                    used = used_kb * 1024
                    total = total_kb * 1024
                    free = max(0, total - used)
                    return (total, used, free)

            raise OSError("No STORAGE quota found in server response")
        except (imaplib.IMAP4.error, AttributeError) as exc:
            raise OSError(f"IMAP QUOTA not supported: {exc}") from exc
