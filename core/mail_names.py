"""File names of mail messages and attachments, capped in UTF-8 bytes.

The mail backends (IMAP, POP3, Exchange) show a message as
``<id>_<subject>.eml``. The subject used to be cut at a number of
*characters* (IMAP 80, POP3 and Exchange 120): a CJK or emoji subject is
three or four bytes a character, and an Exchange ItemId alone is about
150 - names over NAME_MAX (255 bytes on Linux and macOS file systems), so
copying such a message to a local folder failed with ENAMETOOLONG
(errno 36).

Now the whole name is at most :data:`MAX_NAME_BYTES` UTF-8 bytes: the id
and the extension are kept whole, the subject is cut at a character
boundary. A name that fitted before is unchanged - the name is the
message's identity in paths (bookmarks, a mail dock's seen-state) - and
where a backend checks a name against the message, it still accepts the
longer name it gave such a message before (IMAP, POP3; Exchange finds a
message by its id alone).
"""

from __future__ import annotations

#: The most UTF-8 bytes of a mail file name: under NAME_MAX (255) with
#: room for a copy's " (2)" or a transfer's ".part-xxxx" temp suffix.
MAX_NAME_BYTES = 200
#: An extension longer than this is not kept whole by cap_file_name.
_MAX_EXT_BYTES = 16


def cap_bytes(text: str, max_bytes: int) -> str:
    """*text* cut to at most *max_bytes* UTF-8 bytes, at a character
    boundary (never half a character)."""
    raw = text.encode("utf-8", "surrogatepass")
    if len(raw) <= max_bytes:
        return text
    return raw[: max(max_bytes, 0)].decode("utf-8", "ignore")


def cap_file_name(name: str, max_bytes: int = MAX_NAME_BYTES) -> str:
    """*name* in at most *max_bytes* UTF-8 bytes, its extension kept: an
    attachment ``<long CJK name>.pdf`` stays a ``.pdf``."""
    if len(name.encode("utf-8", "surrogatepass")) <= max_bytes:
        return name
    stem, dot, ext = name.rpartition(".")
    ext_bytes = len(ext.encode("utf-8", "surrogatepass"))
    if dot and stem and 0 < ext_bytes <= _MAX_EXT_BYTES:
        return f"{cap_bytes(stem, max_bytes - ext_bytes - 1)}.{ext}"
    return cap_bytes(name, max_bytes)


def message_subject_part(ident: str, subject: str, ext: str = ".eml",
                         max_bytes: int = MAX_NAME_BYTES) -> str:
    """The part of *subject* that :func:`message_file_name` keeps."""
    budget = max_bytes - len(ident.encode("utf-8")) - 1 - len(ext.encode("utf-8"))
    return cap_bytes(subject, budget) if budget > 0 else ""


def message_file_name(ident: str, subject: str, ext: str = ".eml",
                      max_bytes: int = MAX_NAME_BYTES) -> str:
    """``<ident>_<subject><ext>`` in at most *max_bytes* UTF-8 bytes: the
    id (the part that tells messages apart) and the extension whole, the
    subject cut. An id that leaves no room gives ``<ident><ext>``."""
    part = message_subject_part(ident, subject, ext, max_bytes)
    return f"{ident}_{part}{ext}" if part else f"{ident}{ext}"


def cap_component(full: str, max_chars: int) -> str:
    """A sanitised name *full* as one path component: its first
    *max_chars* characters, as before, when they fit in MAX_NAME_BYTES
    bytes (the name stays what it was); otherwise *full* capped in bytes
    with its extension kept."""
    short = full[:max_chars]
    if len(short.encode("utf-8", "surrogatepass")) <= MAX_NAME_BYTES:
        return short
    return cap_file_name(full)
