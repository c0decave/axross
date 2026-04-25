"""Exchange / EWS backend implementing FileBackend.

Exposes an Exchange (or Office 365) mailbox as a filesystem, the
same way :mod:`core.imap_client` does for IMAP. Folder = directory;
message = ``<id>_<subject>.eml`` raw RFC 822 file; attachments live
in a ``<id>/`` sub-directory.

Path layout
-----------
    /                          — list of top-level mailbox folders
    /Inbox/                    — messages in Inbox
    /Inbox/123_subject.eml     — raw RFC 822 of message id 123
    /Inbox/123/                — attachments of message 123
    /Inbox/123/report.pdf      — attachment bytes

Why a separate backend (vs. just IMAP)
--------------------------------------
* On-prem Exchange and Office 365 expose richer metadata via EWS
  (calendar, contacts, search, free/busy) that IMAP doesn't.
* Modern AzureAD-only mailboxes don't always allow IMAP at all.
* exchangelib handles autodiscover + auth (NTLM / Basic / OAuth)
  centrally so we don't have to thread three transport modes.

Scope
-----
Email-as-file only. Calendar / Contacts / Tasks intentionally
deferred — they don't fit the FileBackend protocol cleanly.

* V1: read + message delete.
* V2 (this module): mkdir (create folder), rename (same-parent
  folder rename), copy (message move between folders) and
  open_write (upload a new RFC 822 message into a folder). V2
  writes are header-level — Subject / To / Cc / text body are
  pulled from the supplied MIME stream; attachments + HTML parts
  are preserved best-effort but not guaranteed round-trip. The
  transport-layer quirk we rely on: exchangelib's ``Message.save()``
  handles folder routing through the ``folder=`` kwarg so we don't
  have to walk the store to place the new item.
"""
from __future__ import annotations

import email
import email.message
import email.utils
import io
import logging
import re
from datetime import datetime
from typing import IO

from models.file_item import FileItem

log = logging.getLogger(__name__)


try:  # pragma: no cover — optional dep
    import exchangelib  # type: ignore[import-not-found]
    from exchangelib import (  # type: ignore[import-not-found]
        Account, Configuration, Credentials, DELEGATE,
        Folder, Mailbox, Message,
    )
    # Override exchangelib's module-level default User-Agent before
    # any Account is constructed. exchangelib's session pool reads
    # this constant when it creates the underlying requests.Sessions,
    # so patching the module attribute covers all subsequent SOAP
    # calls. See docs/OPSEC.md #4.
    from core.client_identity import HTTP_USER_AGENT as _AXROSS_UA
    try:
        exchangelib.USER_AGENT = _AXROSS_UA  # type: ignore[attr-defined]
    except AttributeError:
        pass
    EXCHANGELIB_AVAILABLE = True
except ImportError:  # pragma: no cover — optional dep
    exchangelib = None  # type: ignore[assignment]
    Account = None  # type: ignore[assignment]
    Configuration = None  # type: ignore[assignment]
    Credentials = None  # type: ignore[assignment]
    DELEGATE = None  # type: ignore[assignment]
    Folder = None  # type: ignore[assignment]
    Mailbox = None  # type: ignore[assignment]
    Message = None  # type: ignore[assignment]
    EXCHANGELIB_AVAILABLE = False


# Cap on a single message read — mailbox attachments can hit hundreds
# of MiB and we'd rather refuse than OOM on a one-line "show me that
# file" click.
MAX_MESSAGE_BYTES = 64 * 1024 * 1024


# --------------------------------------------------------------------------
# Path helpers
# --------------------------------------------------------------------------

_FILENAME_BAD_CHARS = re.compile(r'[/\\:*?"<>|\x00-\x1f]')


# Substrings (case-insensitive) that mark a "not found" failure as
# distinct from a transient transport error. Conservative: anything
# we don't recognise is treated as transient and re-raised so the
# caller sees the real problem.
_NOT_FOUND_MARKERS = (
    "not found",
    "does not exist",
    "no folder", "no such",
    "errornonexistentmailbox",
)


def _is_not_found(exc: BaseException) -> bool:
    msg = str(exc).lower()
    return any(marker in msg for marker in _NOT_FOUND_MARKERS)


def _sanitize(name: str, max_len: int = 120) -> str:
    cleaned = _FILENAME_BAD_CHARS.sub("_", name or "")
    cleaned = cleaned.strip(". ")
    if not cleaned:
        cleaned = "untitled"
    return cleaned[:max_len]


def _split_path(path: str) -> list[str]:
    """Normalise to forward-slash, drop empties, drop leading/trailing
    slashes. Returns the path component list. Empty for root.

    Doubled separators (``"a//b"``) collapse — the empty segment is
    dropped — so callers don't need to pre-clean their inputs."""
    norm = (path or "/").replace("\\", "/").strip("/")
    if not norm:
        return []
    return [seg for seg in norm.split("/") if seg]


def _parse_msg_segment(segment: str) -> tuple[str, str]:
    """Pull (id, subject) out of a message-file or message-dir name.

    The on-disk shape is ``<id>_<subject>.eml`` for the raw message
    file and ``<id>`` for the attachments directory. Returns (id, "")
    when no subject is present.
    """
    name = segment
    if name.endswith(".eml"):
        name = name[:-4]
    head, _, tail = name.partition("_")
    if not _ and not tail:
        return head, ""
    return head, tail


def _extract_text_body(parsed: email.message.Message) -> str:
    """Pull a text/plain body out of the parsed RFC 822 message.

    Falls back to the first non-multipart part when text/plain is
    absent. The charset defaults to utf-8; decode errors become
    replacement characters so the write always succeeds — we're
    round-tripping what the user sent, not policing it.
    """
    if parsed.is_multipart():
        for part in parsed.walk():
            if part.get_content_type() == "text/plain":
                raw = part.get_payload(decode=True) or b""
                charset = part.get_content_charset() or "utf-8"
                return raw.decode(charset, errors="replace")
        for part in parsed.walk():
            if part.is_multipart():
                continue
            raw = part.get_payload(decode=True) or b""
            charset = part.get_content_charset() or "utf-8"
            return raw.decode(charset, errors="replace")
        return ""
    raw = parsed.get_payload(decode=True) or b""
    charset = parsed.get_content_charset() or "utf-8"
    return raw.decode(charset, errors="replace")


def _split_addresses(headers: list[str] | None) -> list[str]:
    """Split one or more ``To`` / ``Cc`` header values into a flat
    list of bare email addresses.

    Delegates to :func:`email.utils.getaddresses` so quoted display
    names with embedded commas — ``"Last, First" <a@example.com>``
    — don't fracture into ``"Last``, ``First" <a@example.com>``
    (three malformed entries). Entries with no address part are
    dropped silently; we surface only what exchangelib can use.
    """
    if not headers:
        return []
    parsed = email.utils.getaddresses(headers)
    out: list[str] = []
    for _display, addr in parsed:
        cleaned = (addr or "").strip()
        if cleaned:
            out.append(cleaned)
    return out


class _ExchangeMessageWriter:
    """Buffer-then-commit writer for Exchange message uploads.

    The bytes land in a BytesIO until ``close()``; at that point they
    are parsed as RFC 822 and a new ``Message`` is created in the
    target folder with subject / recipients / body lifted from the
    supplied MIME.

    Not seekable — the transfer worker doesn't need to read back, and
    seekable=False lets us cleanly reject half-written reuse.
    """

    def __init__(self, session: "ExchangeSession", folder, filename: str):
        self._session = session
        self._folder = folder
        self._filename = filename
        self._buf = io.BytesIO()
        self._closed = False

    def write(self, data: bytes) -> int:
        if self._closed:
            raise ValueError("Exchange writer already closed")
        return self._buf.write(data)

    def tell(self) -> int:
        return self._buf.tell()

    def flush(self) -> None:
        return None

    def writable(self) -> bool:
        return True

    def readable(self) -> bool:
        return False

    def seekable(self) -> bool:
        return False

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        payload = self._buf.getvalue()
        self._buf.close()
        self._session._commit_message(self._folder, self._filename, payload)

    def discard(self) -> None:
        """Drop buffered bytes without committing a new message
        (transfer cancel path)."""
        if self._closed:
            return
        self._closed = True
        try:
            self._buf.close()
        except Exception:  # noqa: BLE001
            pass

    def __enter__(self) -> "_ExchangeMessageWriter":
        return self

    def __exit__(self, *exc_info) -> bool:
        self.close()
        return False


# --------------------------------------------------------------------------
# Session
# --------------------------------------------------------------------------

class ExchangeSession:
    """EWS-backed FileBackend.

    Construct one per (smtp address, credentials). Folder / message
    fetches go through exchangelib. Each method translates the
    library's exceptions into ``OSError`` so transfer_worker etc.
    don't have to care about EWS specifics.
    """

    def __init__(
        self,
        smtp_address: str,
        username: str = "",
        password: str = "",
        *,
        server: str = "",          # "outlook.office365.com" etc.
        autodiscover: bool = True,
    ):
        if not EXCHANGELIB_AVAILABLE:
            raise ImportError(
                "Exchange support requires exchangelib. "
                "Install with: pip install axross[exchange]"
            )
        self._smtp = smtp_address
        self._username = username or smtp_address
        self._password = password
        # Bind early so the cleanup branch below can introspect even
        # if the failure happened before assignment.
        self._account = None
        try:
            creds = Credentials(self._username, password)  # type: ignore[misc]
            if autodiscover:
                self._account = Account(  # type: ignore[misc]
                    primary_smtp_address=smtp_address,
                    credentials=creds, autodiscover=True,
                    access_type=DELEGATE,
                )
            else:
                if not server:
                    raise ValueError(
                        "ExchangeSession: server is required when "
                        "autodiscover=False"
                    )
                config = Configuration(  # type: ignore[misc]
                    server=server, credentials=creds,
                )
                self._account = Account(  # type: ignore[misc]
                    primary_smtp_address=smtp_address,
                    config=config, autodiscover=False,
                    access_type=DELEGATE,
                )
        except Exception as exc:  # noqa: BLE001 — surface to user
            # If autodiscover or the second Account ctor raised AFTER
            # we'd already established the protocol object, drop it
            # cleanly so the underlying TLS/HTTP connection isn't held
            # for the GC. ``Account`` may not have a ``close()`` on
            # every exchangelib version; use getattr + best-effort.
            self._safely_close_account()
            self._account = None
            raise OSError(
                f"Exchange connect to {smtp_address}: {exc}",
            ) from exc
        log.info("ExchangeSession opened for %s", smtp_address)

    def _safely_close_account(self) -> None:
        """Best-effort close of the underlying exchangelib Account /
        protocol so a partially-constructed session doesn't strand
        TLS connections in the protocol pool."""
        if self._account is None:
            return
        for closer in (
            getattr(self._account, "close", None),
            getattr(getattr(self._account, "protocol", None),
                    "close_pools", None),
            getattr(getattr(self._account, "protocol", None), "close", None),
        ):
            if closer is None:
                continue
            try:
                closer()
            except Exception as exc:  # noqa: BLE001
                log.debug("ExchangeSession close: %s raised %s",
                          closer, exc)

    def close(self) -> None:
        """Public teardown: drop the underlying exchangelib resources.
        Idempotent."""
        self._safely_close_account()
        self._account = None

    # ------------------------------------------------------------------
    # FileBackend protocol — surface
    # ------------------------------------------------------------------
    @property
    def name(self) -> str:
        return f"{self._smtp} (Exchange)"

    def separator(self) -> str:
        return "/"

    def join(self, *parts: str) -> str:
        cleaned = [str(p).strip("/") for p in parts if p is not None]
        cleaned = [p for p in cleaned if p]
        if not cleaned:
            return "/"
        return "/" + "/".join(cleaned)

    def normalize(self, path: str) -> str:
        return self.join(*_split_path(path))

    def parent(self, path: str) -> str:
        parts = _split_path(path)
        if not parts:
            return "/"
        return self.join(*parts[:-1])

    def home(self) -> str:
        return "/"

    # ------------------------------------------------------------------
    # Listing / stat
    # ------------------------------------------------------------------
    def list_dir(self, path: str) -> list[FileItem]:
        parts = _split_path(path)
        if not parts:
            return self._list_root_folders()
        # Last segment may be a message id (= attachments dir) or a
        # folder name. Try folder first; if it fails, treat as message.
        try:
            folder = self._resolve_folder(parts)
        except OSError:
            # Attachments listing: parts == [<folder>..., <msg_id>]
            *folder_parts, msg_seg = parts
            folder = self._resolve_folder(folder_parts)
            return self._list_attachments(folder, msg_seg)
        return self._list_messages(folder)

    def stat(self, path: str) -> FileItem:
        parts = _split_path(path)
        if not parts:
            return FileItem(name="", is_dir=True)
        # The last segment can be either a folder, a message file
        # (.eml), or an attachment basename. Check in that order —
        # but only fall through to the next interpretation when the
        # error was a clean "not found", NOT a transient network
        # blip (otherwise a TLS reset during folder traversal looks
        # like "attachment not found" to the user).
        head, *_ = _parse_msg_segment(parts[-1])
        try:
            folder = self._resolve_folder(parts)
            return FileItem(name=parts[-1], is_dir=True)
        except OSError as exc:
            if not _is_not_found(exc):
                raise
        # Attachments dir lookup: last segment is a bare msg id.
        if not parts[-1].endswith(".eml"):
            try:
                folder = self._resolve_folder(parts[:-1])
                self._fetch_message(folder, parts[-1])
                return FileItem(name=parts[-1], is_dir=True)
            except OSError as exc:
                if not _is_not_found(exc):
                    raise
        # Message file (.eml) lookup.
        if parts[-1].endswith(".eml"):
            folder = self._resolve_folder(parts[:-1])
            msg = self._fetch_message(folder, head)
            return FileItem(
                name=parts[-1],
                size=self._estimate_size(msg),
                modified=self._msg_mtime(msg),
                is_dir=False,
            )
        # Attachment within a message.
        if len(parts) >= 3:
            folder = self._resolve_folder(parts[:-2])
            msg = self._fetch_message(folder, parts[-2])
            for att in getattr(msg, "attachments", None) or []:
                if _sanitize(getattr(att, "name", "")) == parts[-1]:
                    return FileItem(
                        name=parts[-1],
                        size=int(getattr(att, "size", 0) or 0),
                        modified=self._msg_mtime(msg),
                        is_dir=False,
                    )
        raise OSError(f"Exchange stat({path}): not found")

    def is_dir(self, path: str) -> bool:
        try:
            return self.stat(path).is_dir
        except OSError:
            return False

    def exists(self, path: str) -> bool:
        try:
            self.stat(path)
            return True
        except OSError:
            return False

    # ------------------------------------------------------------------
    # IO
    # ------------------------------------------------------------------
    def open_read(self, path: str) -> IO[bytes]:
        parts = _split_path(path)
        if not parts:
            raise OSError("Exchange open_read: cannot read root")
        # Message .eml: <folder>/<id>_<subject>.eml
        if parts[-1].endswith(".eml") and len(parts) >= 2:
            folder = self._resolve_folder(parts[:-1])
            msg_id, _ = _parse_msg_segment(parts[-1])
            msg = self._fetch_message(folder, msg_id)
            payload = bytes(getattr(msg, "mime_content", b"") or b"")
            self._enforce_size_cap(payload, path)
            return io.BytesIO(payload)
        # Attachment: <folder>/<id>/<filename>
        if len(parts) >= 3:
            folder = self._resolve_folder(parts[:-2])
            msg = self._fetch_message(folder, parts[-2])
            atts = list(getattr(msg, "attachments", None) or [])
            wanted = parts[-1]
            matches = [
                att for att in atts
                if self._unique_attachment_name(atts, att) == wanted
            ]
            if not matches:
                raise OSError(
                    f"Exchange open_read({path}): attachment not found"
                )
            if len(matches) > 1:
                # _unique_attachment_name disambiguates by appending
                # ``.1``, ``.2``, … so a true collision after that is
                # an exchangelib invariant violation we'd rather surface
                # than silently pick one and corrupt the user's data.
                raise OSError(
                    f"Exchange open_read({path}): multiple attachments "
                    f"resolve to the same on-disk name "
                    f"({len(matches)} matches) — refusing to guess"
                )
            payload = bytes(getattr(matches[0], "content", b"") or b"")
            self._enforce_size_cap(payload, path)
            return io.BytesIO(payload)
        raise OSError(f"Exchange open_read({path}): not a message or attachment")

    @staticmethod
    def _enforce_size_cap(payload: bytes, path: str) -> None:
        if len(payload) > MAX_MESSAGE_BYTES:
            raise OSError(
                f"Exchange open_read({path}): "
                f"{len(payload)} bytes exceeds {MAX_MESSAGE_BYTES} cap"
            )

    def open_write(self, path: str, append: bool = False) -> IO[bytes]:
        """Upload a new RFC 822 message into the folder named by
        ``path``'s parent. Only ``<folder>/<name>.eml`` paths are
        accepted — writing to the attachments sub-dir would require
        mutating an existing message, which EWS doesn't expose."""
        if append:
            raise OSError("Exchange open_write: append unsupported (EWS messages are immutable)")
        parts = _split_path(path)
        if len(parts) < 2:
            raise OSError(
                f"Exchange open_write({path}): expected /<folder>/<name>.eml",
            )
        leaf = parts[-1]
        if not leaf.endswith(".eml"):
            raise OSError(
                f"Exchange open_write({path}): only .eml uploads are supported — "
                "attachments cannot be added to an existing message",
            )
        folder = self._resolve_folder(parts[:-1])
        return _ExchangeMessageWriter(self, folder, leaf)

    def _commit_message(self, folder, filename: str, raw: bytes) -> None:
        """Parse ``raw`` as RFC 822 and save a new Message into
        ``folder``. Size capped like ``open_read`` — a 200 MiB write
        is a mistake, not a workflow."""
        self._enforce_size_cap(raw, filename)
        try:
            parsed = email.message_from_bytes(raw)
        except Exception as exc:  # noqa: BLE001
            raise OSError(
                f"Exchange commit({filename}): RFC 822 parse failed: {exc}",
            ) from exc
        # ``filename`` includes the trailing ``.eml``; strip it so the
        # fallback subject is readable.
        fallback_subject = filename[:-4] if filename.endswith(".eml") else filename
        subject = (parsed.get("Subject") or "").strip() or fallback_subject
        body = _extract_text_body(parsed)
        to_addrs = _split_addresses(parsed.get_all("To"))
        cc_addrs = _split_addresses(parsed.get_all("Cc"))
        bcc_addrs = _split_addresses(parsed.get_all("Bcc"))
        try:
            msg = Message(  # type: ignore[misc]
                account=self._account,
                folder=folder,
                subject=subject,
                body=body,
                to_recipients=[Mailbox(email_address=a) for a in to_addrs] or None,  # type: ignore[misc]
                cc_recipients=[Mailbox(email_address=a) for a in cc_addrs] or None,  # type: ignore[misc]
                bcc_recipients=[Mailbox(email_address=a) for a in bcc_addrs] or None,  # type: ignore[misc]
            )
            msg.save()
        except Exception as exc:  # noqa: BLE001
            raise OSError(
                f"Exchange commit({filename}): save failed: {exc}",
            ) from exc
        log.info("Exchange committed %d bytes as %r in %s",
                 len(raw), subject, getattr(folder, "name", "?"))

    # ------------------------------------------------------------------
    # Mutation
    # ------------------------------------------------------------------
    def remove(self, path: str, recursive: bool = False) -> None:
        parts = _split_path(path)
        if not parts:
            raise OSError("Exchange remove: cannot remove root")
        if parts[-1].endswith(".eml") and len(parts) >= 2:
            folder = self._resolve_folder(parts[:-1])
            msg_id, _ = _parse_msg_segment(parts[-1])
            msg = self._fetch_message(folder, msg_id)
            try:
                msg.delete()
            except Exception as exc:  # noqa: BLE001
                raise OSError(f"Exchange delete: {exc}") from exc
            return
        raise OSError("Exchange remove: only message files can be deleted")

    def mkdir(self, path: str) -> None:
        """Create a mail folder at ``path``. Parent must exist; leaf
        must be unique within the parent — EWS allows duplicates by
        display name but our flat-name path scheme cannot distinguish
        them, so we refuse upfront rather than create a shadow."""
        parts = _split_path(path)
        if not parts:
            raise OSError("Exchange mkdir: cannot create root")
        leaf = parts[-1]
        parent_parts = parts[:-1]
        try:
            parent = (self._resolve_folder(parent_parts)
                      if parent_parts else self._account.root)
        except OSError as exc:
            raise OSError(
                f"Exchange mkdir({path}): parent missing: {exc}",
            ) from exc
        # Probe for duplicate — a failed lookup means clear to create.
        # A broad ``except Exception`` here would swallow genuine
        # network / TLS / auth errors and mis-report them as
        # "folder doesn't exist"; narrow to the canonical "not found"
        # shape and let anything else propagate as OSError so the
        # user sees the real problem (cf. ``_is_not_found`` — same
        # substring heuristic EWS uses elsewhere in this module).
        exists = False
        try:
            probe = parent / leaf
            _ = probe.name
            exists = True
        except Exception as probe_exc:  # noqa: BLE001
            if not _is_not_found(probe_exc):
                raise OSError(
                    f"Exchange mkdir({path}): duplicate probe failed "
                    f"with a non-not-found error (likely network or "
                    f"auth): {probe_exc}",
                ) from probe_exc
        if exists:
            raise OSError(f"Exchange mkdir({path}): already exists")
        try:
            Folder(parent=parent, name=leaf).save()  # type: ignore[misc]
        except Exception as exc:  # noqa: BLE001
            raise OSError(f"Exchange mkdir({path}): {exc}") from exc
        log.info("Exchange mkdir %s", path)

    def rename(self, src: str, dst: str) -> None:
        """Same-parent rename of a folder. Cross-parent moves and
        message renames are rejected — the former needs ``move()``
        support we haven't validated against Outlook's archive
        policies, the latter would break the ``<id>_<subject>.eml``
        scheme (id is server-assigned and immutable)."""
        src_parts = _split_path(src)
        dst_parts = _split_path(dst)
        if not src_parts or not dst_parts:
            raise OSError("Exchange rename: cannot rename root")
        if src_parts[-1].endswith(".eml") or dst_parts[-1].endswith(".eml"):
            raise OSError(
                "Exchange rename: messages cannot be renamed "
                "(the server-assigned id is part of the filename)",
            )
        if src_parts[:-1] != dst_parts[:-1]:
            raise OSError(
                "Exchange rename: cross-folder moves are unsupported — "
                "use copy + delete if you really need to relocate",
            )
        try:
            folder = self._resolve_folder(src_parts)
            folder.name = dst_parts[-1]
            folder.save()
        except Exception as exc:  # noqa: BLE001
            raise OSError(f"Exchange rename({src}→{dst}): {exc}") from exc
        log.info("Exchange rename %s → %s", src, dst)

    def chmod(self, path: str, mode: int) -> None:
        raise OSError("Exchange has no POSIX permissions")

    def readlink(self, path: str) -> str:
        raise OSError("Exchange has no symlinks")

    def copy(self, src: str, dst: str) -> None:
        """Copy a message between folders. Only message-level copy is
        supported — duplicating a folder would require recursively
        fanning out messages and loses server-side storage savings."""
        src_parts = _split_path(src)
        dst_parts = _split_path(dst)
        if len(src_parts) < 2 or not src_parts[-1].endswith(".eml"):
            raise OSError(
                "Exchange copy: source must be a message path "
                "(/<folder>/<id>_<subject>.eml)",
            )
        if len(dst_parts) < 1:
            raise OSError("Exchange copy: destination must name a folder")
        # Dst may be a folder path or a folder/newname.eml path; in
        # either case the target folder is the leading components (we
        # cannot rename on copy — the copy keeps the original subject).
        dst_folder_parts = (dst_parts[:-1] if dst_parts[-1].endswith(".eml")
                            else dst_parts)
        try:
            src_folder = self._resolve_folder(src_parts[:-1])
            dst_folder = (self._resolve_folder(dst_folder_parts)
                          if dst_folder_parts else self._account.root)
            msg_id, _ = _parse_msg_segment(src_parts[-1])
            msg = self._fetch_message(src_folder, msg_id)
            msg.copy(to_folder=dst_folder)
        except OSError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise OSError(f"Exchange copy({src}→{dst}): {exc}") from exc
        log.info("Exchange copy %s → %s", src, dst)

    def disk_usage(self, path: str) -> tuple[int, int, int]:
        # Mailbox quota would be the right answer; exchangelib exposes
        # it but support varies per-tenant. Returning zeros keeps the
        # contract instead of probing every time.
        return (0, 0, 0)

    def checksum(self, path: str, algorithm: str = "sha256") -> str:
        return ""

    def list_versions(self, path: str) -> list:
        return []

    def open_version_read(self, path: str, version_id: str):
        raise OSError("Exchange backend has no version history")

    # ------------------------------------------------------------------
    # exchangelib helpers — kept narrow so tests can patch them
    # ------------------------------------------------------------------
    def _list_root_folders(self) -> list[FileItem]:
        try:
            roots = list(self._account.root.children)
        except Exception as exc:  # noqa: BLE001
            raise OSError(f"Exchange list root folders: {exc}") from exc
        out: list[FileItem] = []
        for folder in roots:
            name = _sanitize(getattr(folder, "name", "") or "")
            if not name:
                continue
            out.append(FileItem(name=name, is_dir=True))
        return out

    def _resolve_folder(self, parts: list[str]):
        try:
            cursor = self._account.root
            for segment in parts:
                # exchangelib supports folder lookup by name with /
                cursor = cursor / segment
                # Touch the folder to force an EWS round-trip — if it
                # doesn't exist we get a clear exception instead of a
                # lazy failure later.
                _ = cursor.name  # noqa: F841
            return cursor
        except Exception as exc:  # noqa: BLE001
            raise OSError(
                f"Exchange folder lookup {'/'.join(parts)}: {exc}",
            ) from exc

    def _list_messages(self, folder) -> list[FileItem]:
        try:
            messages = list(folder.all())
        except Exception as exc:  # noqa: BLE001
            raise OSError(f"Exchange list messages: {exc}") from exc
        out: list[FileItem] = []
        for msg in messages:
            mid = self._msg_id(msg)
            subj = _sanitize(getattr(msg, "subject", "") or "no_subject")
            file_name = f"{mid}_{subj}.eml"
            out.append(FileItem(
                name=file_name,
                size=self._estimate_size(msg),
                modified=self._msg_mtime(msg),
                is_dir=False,
            ))
            # Add the attachments-directory entry only when the message
            # actually has attachments — otherwise we'd lie.
            if getattr(msg, "has_attachments", False):
                out.append(FileItem(name=mid, is_dir=True))
        return out

    def _list_attachments(self, folder, msg_seg: str) -> list[FileItem]:
        msg = self._fetch_message(folder, msg_seg)
        atts = list(getattr(msg, "attachments", None) or [])
        out: list[FileItem] = []
        for att in atts:
            out.append(FileItem(
                name=self._unique_attachment_name(atts, att),
                size=int(getattr(att, "size", 0) or 0),
                modified=self._msg_mtime(msg),
                is_dir=False,
            ))
        return out

    @staticmethod
    def _unique_attachment_name(all_atts, target) -> str:
        """Translate an attachment to its on-disk name, disambiguating
        when two attachments sanitise to the same string. Appends
        ``.1``, ``.2``, … to later occurrences in iteration order.

        Without this, a message with two attachments both named
        ``report (1).pdf`` would surface as a single visible file in
        list_dir + open_read would silently return the first one's
        content even when the user clicked the second — a textbook
        silent-data-corruption bug for anyone saving multiple
        attachments with similar names.
        """
        seen: dict[str, int] = {}
        for att in all_atts:
            base = _sanitize(getattr(att, "name", "")) or "attachment"
            if base not in seen:
                seen[base] = 0
                resolved = base
            else:
                seen[base] += 1
                root, _, ext = base.rpartition(".")
                if root:
                    resolved = f"{root}.{seen[base]}.{ext}"
                else:
                    resolved = f"{base}.{seen[base]}"
            if att is target:
                return resolved
        # target wasn't in all_atts — fall back to the sanitised name.
        return _sanitize(getattr(target, "name", "")) or "attachment"

    def _fetch_message(self, folder, msg_seg: str):
        msg_id, _ = _parse_msg_segment(msg_seg)
        try:
            for msg in folder.filter(id=msg_id):
                return msg
        except Exception as exc:  # noqa: BLE001
            raise OSError(f"Exchange fetch_message({msg_id}): {exc}") from exc
        raise OSError(f"Exchange message {msg_id} not found")

    @staticmethod
    def _msg_id(msg) -> str:
        return str(getattr(msg, "id", "") or getattr(msg, "item_id", ""))

    @staticmethod
    def _msg_mtime(msg) -> datetime:
        for attr in ("datetime_received", "datetime_sent", "last_modified_time"):
            value = getattr(msg, attr, None)
            if isinstance(value, datetime):
                return value
        return datetime.fromtimestamp(0)

    @staticmethod
    def _estimate_size(msg) -> int:
        # exchangelib exposes ``size`` on Message objects; fall back to
        # 0 when the property isn't populated (Outlook draft messages
        # sometimes ship without it).
        try:
            return int(getattr(msg, "size", 0) or 0)
        except (TypeError, ValueError):
            return 0


__all__ = [
    "EXCHANGELIB_AVAILABLE",
    "ExchangeSession",
    "MAX_MESSAGE_BYTES",
    "_ExchangeMessageWriter",
    "_extract_text_body",
    "_parse_msg_segment",
    "_sanitize",
    "_split_addresses",
    "_split_path",
]
