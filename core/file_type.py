"""Identify a file's real type from its content, not from its name.

Used by the pane's *Identify File Type…* entry and by
``axross.file_type``. A bounded prefix (64 KiB by default) is read through
the backend's own ``open_read``, so every protocol works the same way, and
the bytes are classified by several engines in turn:

1. Qt's ``QMimeDatabase.mimeTypeForData`` - the freedesktop
   shared-mime-info magic rules, in-process (``core.previews.guess_mime``
   uses the same database, but by file name and for local files only).
2. ``puremagic`` through :func:`core.net_helpers.magic_type`, when Qt is
   not importable (a headless install).
3. :data:`SIGNATURES`, a small built-in magic-byte table. The pane's
   binary sniff (``FilePaneWidget._BINARY_MAGIC``) is derived from it.
4. A text heuristic (no NUL bytes, few control characters).

What the extension claims comes from the same database by name. The two
are compared with MIME inheritance, so ``.docx`` holding a ZIP or
``.json`` holding plain text is a match, while a PNG called ``.txt`` is a
mismatch. ``file(1)`` may add its description for local files - with a
timeout, an argument list and ``--`` before the path - but no field
depends on it.

The read runs on a daemon helper thread with a deadline and a cancel
check, so a remote that stops answering yields a "timed out" row instead
of blocking the caller. A read that never returns keeps its helper thread
until it does: a blocking socket read cannot be interrupted from outside.
"""

from __future__ import annotations

import codecs
import logging
import os
import shutil
import stat as stat_module
import subprocess
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

log = logging.getLogger(__name__)

#: Bytes read from the start of a file. Every engine decides on far less;
#: 64 KiB also gives the text statistics something to count.
DEFAULT_MAX_BYTES = 64 * 1024
#: Seconds a stat + read may take before the row says "timed out".
DEFAULT_TIMEOUT = 15.0
#: Seconds ``file(1)`` may run.
FILE_COMMAND_TIMEOUT = 3.0
#: Longest ``file(1)`` description kept.
FILE_COMMAND_MAX_CHARS = 300
#: Identify Files in This Folder: files looked at, at most.
FOLDER_MAX_FILES = 2000
#: Seconds listing that folder may take.
FOLDER_LIST_TIMEOUT = 60.0
#: Bytes the partition note of one disk image may read (core.disk_image
#: probes the head, the tail, a GPT and each partition's first sectors).
IMAGE_NOTE_MAX_BYTES = 4 * 1024 * 1024

KIND_FILE = "file"
KIND_DIRECTORY = "directory"
KIND_SPECIAL = "special"
KIND_ERROR = "error"
KIND_TIMEOUT = "timeout"
KIND_CANCELLED = "cancelled"

MATCH = "match"
MISMATCH = "mismatch"
UNKNOWN = "unknown"

OCTET_STREAM = "application/octet-stream"
ZEROSIZE = "application/x-zerosize"
DIRECTORY_MIME = "inode/directory"
TEXT_PLAIN = "text/plain"


@dataclass(frozen=True)
class Signature:
    """A magic-byte signature: ``magic`` at ``offset`` means ``mime``."""

    offset: int
    magic: bytes
    mime: str
    description: str


#: Built-in signatures, most specific first. Every entry is binary content;
#: ``FilePaneWidget._BINARY_MAGIC`` is derived from this table.
SIGNATURES: tuple[Signature, ...] = (
    Signature(0, b"\x89PNG", "image/png", "PNG image"),
    Signature(0, b"\xff\xd8\xff", "image/jpeg", "JPEG image"),
    Signature(0, b"GIF8", "image/gif", "GIF image"),
    Signature(0, b"PK\x03\x04", "application/zip", "ZIP archive"),
    Signature(0, b"\x1f\x8b", "application/gzip", "gzip archive"),
    Signature(0, b"BZ", "application/x-bzip2", "bzip2 archive"),
    Signature(0, b"\xfd7zXZ", "application/x-xz", "xz archive"),
    Signature(0, b"7z\xbc\xaf\x27\x1c", "application/x-7z-compressed", "7-Zip archive"),
    Signature(0, b"Rar!\x1a\x07", "application/vnd.rar", "RAR archive"),
    Signature(0, b"\x28\xb5\x2f\xfd", "application/zstd", "Zstandard archive"),
    Signature(257, b"ustar", "application/x-tar", "tar archive"),
    Signature(0, b"\x7fELF", "application/x-executable", "ELF executable"),
    Signature(0, b"MZ", "application/x-msdownload", "DOS/Windows executable"),
    Signature(0, b"\xca\xfe\xba\xbe", "application/x-java", "Java class or Mach-O fat binary"),
    Signature(0, b"%PDF", "application/pdf", "PDF document"),
    Signature(0, b"SQLite", "application/vnd.sqlite3", "SQLite database"),
    Signature(0, b"\x00asm", "application/wasm", "WebAssembly module"),
    Signature(0, b"RIFF", "application/x-riff", "RIFF container (WAV / AVI / WebP)"),
    Signature(0, b"\xff\xfb", "audio/mpeg", "MP3 audio"),
    Signature(0, b"ID3", "audio/mpeg", "MP3 audio (ID3 tag)"),
    Signature(0, b"fLaC", "audio/flac", "FLAC audio"),
    Signature(0, b"OggS", "audio/ogg", "Ogg container"),
    Signature(0, b"\x1a\x45\xdf\xa3", "video/x-matroska", "Matroska / WebM video"),
    Signature(4, b"ftyp", "video/mp4", "MP4 / QuickTime media"),
    Signature(0, b"II*\x00", "image/tiff", "TIFF image"),
    Signature(0, b"MM\x00*", "image/tiff", "TIFF image"),
)

#: ``(offset, magic)`` pairs for callers that only need "is it binary?".
BINARY_SIGNATURES: tuple[tuple[int, bytes], ...] = tuple((s.offset, s.magic) for s in SIGNATURES)

# Byte-order marks, longest first: the UTF-32 LE mark starts with the
# UTF-16 LE one.
_BOMS: tuple[tuple[bytes, str, str], ...] = (
    (codecs.BOM_UTF32_LE, "UTF-32 LE (BOM)", "utf-32"),
    (codecs.BOM_UTF32_BE, "UTF-32 BE (BOM)", "utf-32"),
    (codecs.BOM_UTF8, "UTF-8 (BOM)", "utf-8-sig"),
    (codecs.BOM_UTF16_LE, "UTF-16 LE (BOM)", "utf-16"),
    (codecs.BOM_UTF16_BE, "UTF-16 BE (BOM)", "utf-16"),
)

# Without Qt's inheritance data: claims that a detected type satisfies.
_TEXTUAL_APPLICATION = frozenset(
    {
        "application/json",
        "application/xml",
        "application/javascript",
        "application/x-sh",
        "application/x-shellscript",
        "application/x-python",
        "application/x-perl",
        "application/x-ruby",
        "application/sql",
        "application/x-yaml",
        "application/toml",
    }
)
_ZIP_FAMILY_PREFIXES = (
    "application/vnd.openxmlformats-officedocument.",
    "application/vnd.oasis.opendocument.",
    "application/vnd.ms-",
)
_ZIP_FAMILY = frozenset(
    {
        "application/java-archive",
        "application/x-java-archive",
        "application/vnd.android.package-archive",
        "application/epub+zip",
        "application/x-zip-compressed",
    }
)
_ENCODING_MIME = {
    "gzip": "application/gzip",
    "bzip2": "application/x-bzip2",
    "xz": "application/x-xz",
}


@dataclass(frozen=True)
class FileTypeInfo:
    """What one file really is.

    ``kind`` is ``file``, ``directory``, ``special`` (FIFO, device,
    socket), ``error``, ``timeout`` or ``cancelled``. ``mime`` and
    ``description`` come from the content; ``extension`` (``".png"``,
    ``""`` for none) and ``extension_mime`` (``""`` when the extension is
    unknown) from the name. ``verdict`` is ``match``, ``mismatch`` or
    ``unknown`` (nothing claimed, or the content cannot tell). ``encoding``
    and ``line_endings`` are set for text only. ``engine`` names the
    detector that decided, ``file_command`` holds ``file(1)``'s description
    for local files (``""`` when unavailable) and ``error`` the reason a
    row has no type.
    """

    path: str
    name: str
    kind: str
    description: str = ""
    mime: str = ""
    extension: str = ""
    extension_mime: str = ""
    verdict: str = UNKNOWN
    size: int | None = None
    encoding: str = ""
    line_endings: str = ""
    engine: str = ""
    file_command: str = ""
    bytes_read: int = 0
    error: str = ""

    @property
    def mismatch(self) -> bool:
        """True when the content contradicts what the extension claims."""
        return self.verdict == MISMATCH

    def summary(self) -> str:
        """One line for a log or a script's output."""
        label = self.path or self.name
        if self.error:
            return f"{label}: {self.kind} - {self.error}"
        text = f"{label}: {self.description or self.kind}"
        if self.mime:
            text += f" ({self.mime})"
        if self.mismatch:
            text += f" - MISMATCH: {self.extension} claims {self.extension_mime}"
        if self.encoding:
            text += f", {self.encoding}, {self.line_endings} line endings"
        return text


# ---------------------------------------------------------------------------
# Engines
# ---------------------------------------------------------------------------

_DB_LOCK = threading.Lock()
_CLASSIFY_LOCK = threading.Lock()
_DB: Any = None
_DB_MISSING = False


def _mime_db():
    """The process-wide ``QMimeDatabase``, or None when PyQt6 is missing.

    The database is shared data inside Qt; one instance is created lazily
    and reused from any thread.
    """
    global _DB, _DB_MISSING
    if _DB is not None or _DB_MISSING:
        return _DB
    with _DB_LOCK:
        if _DB is None and not _DB_MISSING:
            try:
                from PyQt6.QtCore import QMimeDatabase
            except ImportError:
                _DB_MISSING = True
                return None
            _DB = QMimeDatabase()
    return _DB


def _puremagic_mime(data: bytes) -> str:
    """MIME from ``puremagic`` (optional extra), ``""`` when unknown."""
    from core.net_helpers import magic_type

    try:
        return magic_type(data, default="")
    except OSError:  # puremagic not installed
        return ""


def _signature(data: bytes) -> Signature | None:
    for sig in SIGNATURES:
        if data[sig.offset : sig.offset + len(sig.magic)] == sig.magic:
            return sig
    return None


def _looks_like_text(data: bytes) -> bool:
    """No NUL bytes and almost no control characters (a BOM counts as text)."""
    if any(data.startswith(bom) for bom, _n, _c in _BOMS):
        return True
    if b"\x00" in data:
        return False
    allowed = {0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x1B}
    control = sum(1 for b in data if (b < 0x20 and b not in allowed) or b == 0x7F)
    return control <= len(data) * 0.05


def _detect(data: bytes) -> tuple[str, str, str]:
    """``(mime, description, engine)`` for non-empty *data*."""
    from core.disk_image import detect_container

    disk_mime, disk = detect_container(data)
    if disk:
        # Virtual disks and GPT disks: core.disk_image names the container
        # and its size, which the generic databases do not; the MIME type is
        # the container's own, so a correctly named one is no mismatch.
        return disk_mime, disk, "disk image"
    db = _mime_db()
    if db is not None:
        found = db.mimeTypeForData(data)
        name = found.name()
        if name and name != OCTET_STREAM:
            return name, found.comment() or name, "Qt"
    mime = _puremagic_mime(data)
    if mime and mime != OCTET_STREAM:
        sig = _signature(data)
        description = sig.description if sig is not None and sig.mime == mime else mime
        return mime, description, "puremagic"
    sig = _signature(data)
    if sig is not None:
        return sig.mime, sig.description, "signature table"
    if _looks_like_text(data):
        return TEXT_PLAIN, "Plain text", "text heuristic"
    return OCTET_STREAM, "Unknown binary data", "text heuristic"


def _canonical(mime: str) -> str:
    db = _mime_db()
    if db is not None and mime:
        found = db.mimeTypeForName(mime)
        if found.isValid():
            return found.name()
    return mime


def _is_textual(mime: str) -> bool:
    if not mime:
        return False
    if mime.startswith("text/"):
        return True
    db = _mime_db()
    if db is not None:
        found = db.mimeTypeForName(mime)
        if found.isValid():
            return found.inherits(TEXT_PLAIN)
    return mime in _TEXTUAL_APPLICATION or mime.endswith(("+xml", "+json"))


def _inherits(child: str, parent: str) -> bool:
    db = _mime_db()
    if db is not None:
        found = db.mimeTypeForName(child)
        return found.isValid() and found.inherits(parent)
    if parent == "application/zip":
        return child in _ZIP_FAMILY or child.startswith(_ZIP_FAMILY_PREFIXES) or child.endswith(
            "+zip"
        )
    return False


def _extension(name: str) -> str:
    """The suffix a name claims (``".tar.gz"``, ``""`` for none)."""
    db = _mime_db()
    if db is not None:
        suffix = db.suffixForFileName(name)
        if suffix:
            return "." + suffix
    stem, ext = os.path.splitext(name)
    return ext if stem and len(ext) > 1 else ""


def _claimed_mime(name: str) -> str:
    """The MIME type the name's extension stands for, ``""`` if none."""
    if not name or not _extension(name):
        return ""
    db = _mime_db()
    if db is not None:
        from PyQt6.QtCore import QMimeDatabase

        found = db.mimeTypeForFile(name, QMimeDatabase.MatchMode.MatchExtension)
        return "" if found.isDefault() else found.name()
    import mimetypes

    guessed, encoding = mimetypes.guess_type(name, strict=False)
    if encoding in _ENCODING_MIME:
        return _ENCODING_MIME[encoding]
    return guessed or ""


def _verdict(detected: str, claimed: str) -> str:
    if not claimed or claimed == OCTET_STREAM or not detected or detected == ZEROSIZE:
        return UNKNOWN
    if detected == OCTET_STREAM:
        # Unknown binary content cannot contradict a binary claim, but it
        # does contradict a text one.
        return MISMATCH if _is_textual(claimed) else UNKNOWN
    detected, claimed = _canonical(detected), _canonical(claimed)
    if detected == claimed:
        return MATCH
    if _inherits(claimed, detected) or _inherits(detected, claimed):
        return MATCH
    if _is_textual(detected) and _is_textual(claimed):
        return MATCH
    return MISMATCH


def _line_endings(text: str) -> str:
    crlf = text.count("\r\n")
    lf = text.count("\n") - crlf
    cr = text.count("\r") - crlf
    present = [(label, n) for label, n in (("LF", lf), ("CRLF", crlf), ("CR", cr)) if n]
    if not present:
        return "none"
    if len(present) == 1:
        return present[0][0]
    return "mixed (" + ", ".join(f"{label} {n}" for label, n in present) + ")"


def _text_properties(data: bytes, truncated: bool) -> tuple[str, str]:
    """``(encoding, line_endings)`` of a text prefix."""
    for bom, label, codec in _BOMS:
        if data.startswith(bom):
            return label, _line_endings(data.decode(codec, errors="replace"))
    decoder = codecs.getincrementaldecoder("utf-8")()
    try:
        # final=False when the prefix was cut: a character split at the
        # cut is not an encoding error.
        text = decoder.decode(data, final=not truncated)
    except UnicodeDecodeError:
        text = None
    if text is not None:
        return ("ASCII" if data.isascii() else "UTF-8"), _line_endings(text)
    label = "8-bit (code page unknown)"
    codec = "latin-1"
    try:
        from core.net_helpers import text_encoding

        guess = text_encoding(data)
        if guess.get("encoding"):
            label = f"{guess['encoding']} (guessed, {guess['confidence']:.0%})"
            codecs.lookup(guess["encoding"])
            codec = guess["encoding"]
    except (OSError, LookupError):  # chardet missing, or a name Python lacks
        pass
    return label, _line_endings(data.decode(codec, errors="replace"))


def identify_bytes(
    data: bytes,
    name: str = "",
    *,
    size: int | None = None,
    path: str = "",
    truncated: bool | None = None,
) -> FileTypeInfo:
    """Classify *data* (a file's first bytes) for a file called *name*.

    Pure: no I/O. *size* is the whole file's size (defaults to
    ``len(data)``); *truncated* says *data* is only a prefix and defaults
    to ``size > len(data)``.
    """
    data = bytes(data)
    if size is None:
        size = len(data)
    if truncated is None:
        truncated = size > len(data)
    name = name or os.path.basename(path)
    # One classification at a time: the Qt database is shared between the
    # dialog's worker thread and scripts, and the lookups are cheap.
    with _CLASSIFY_LOCK:
        extension = _extension(name)
        claimed = _claimed_mime(name)
        if not data:
            mime, description, engine = ZEROSIZE, "Empty file", "size"
        else:
            mime, description, engine = _detect(data)
        textual = bool(data) and (
            _is_textual(mime) or (mime == OCTET_STREAM and _looks_like_text(data))
        )
        verdict = _verdict(mime, claimed)
    encoding = line_endings = ""
    if textual:
        encoding, line_endings = _text_properties(data, truncated)
    return FileTypeInfo(
        path=path or name,
        name=name,
        kind=KIND_FILE,
        description=description,
        mime=mime,
        extension=extension,
        extension_mime=claimed,
        verdict=verdict,
        size=size,
        encoding=encoding,
        line_endings=line_endings,
        engine=engine,
        bytes_read=len(data),
    )


# ---------------------------------------------------------------------------
# Reading with a deadline
# ---------------------------------------------------------------------------


def _cancel_check(cancel) -> Callable[[], bool]:
    if cancel is None:
        return lambda: False
    if hasattr(cancel, "is_set"):
        return cancel.is_set
    if callable(cancel):
        return cancel
    raise TypeError("cancel must be None, a threading.Event or a callable")


def _run_with_deadline(fn: Callable[[], Any], timeout: float, cancelled: Callable[[], bool]):
    """Run *fn* on a daemon thread; raise TimeoutError / InterruptedError.

    On timeout or cancel the thread is left behind: it ends whenever the
    blocked call returns, and as a daemon it never holds up an exit.
    """
    box: dict[str, Any] = {}
    done = threading.Event()

    def run() -> None:
        try:
            box["value"] = fn()
        except BaseException as exc:  # noqa: BLE001 - re-raised in the caller
            box["error"] = exc
        finally:
            done.set()

    worker = threading.Thread(target=run, name="file-type-probe", daemon=True)
    worker.start()
    deadline = time.monotonic() + timeout
    while not done.wait(0.05):
        if cancelled():
            raise InterruptedError("cancelled")
        if time.monotonic() >= deadline:
            raise TimeoutError(f"no answer within {timeout:g} s")
    if "error" in box:
        raise box["error"]
    return box.get("value")


def _read_bounded(backend, path: str, max_bytes: int) -> bytes:
    chunks: list[bytes] = []
    got = 0
    with backend.open_read(path) as fh:
        while got < max_bytes:
            chunk = fh.read(max_bytes - got)
            if not chunk:
                break
            chunks.append(bytes(chunk))
            got += len(chunk)
    return b"".join(chunks)[:max_bytes]


def _check_limits(max_bytes: int, timeout: float) -> None:
    if int(max_bytes) <= 0:
        raise ValueError(f"max_bytes must be positive, not {max_bytes!r}")
    if not timeout or timeout <= 0:
        raise ValueError(f"timeout must be positive, not {timeout!r}")


def read_prefix(
    backend,
    path: str,
    max_bytes: int = DEFAULT_MAX_BYTES,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    cancel=None,
) -> bytes:
    """Up to *max_bytes* from the start of *path*, read off the calling thread.

    Raises ``TimeoutError`` after *timeout* seconds, ``InterruptedError``
    once *cancel* (an Event or a callable) is set, and whatever the
    backend raised otherwise.
    """
    _check_limits(max_bytes, timeout)
    return _run_with_deadline(
        lambda: _read_bounded(backend, path, int(max_bytes)), timeout, _cancel_check(cancel)
    )


def _is_local(backend) -> bool:
    try:
        from core.local_fs import LocalFS
    except ImportError:  # pragma: no cover - always present
        return False
    return isinstance(backend, LocalFS)


def _special_description(mode: int) -> str:
    if stat_module.S_ISFIFO(mode):
        return "FIFO (named pipe)"
    if stat_module.S_ISCHR(mode):
        return "character device"
    if stat_module.S_ISBLK(mode):
        return "block device"
    if stat_module.S_ISSOCK(mode):
        return "socket"
    return "special file"


def file_command_description(path: str, *, timeout: float = FILE_COMMAND_TIMEOUT) -> str:
    """``file(1)``'s description of a local *path*, ``""`` when unavailable.

    Argument list, no shell, ``--`` before the path, a timeout; any failure
    is an empty string rather than an error.
    """
    binary = shutil.which("file")
    if not binary:
        return ""
    try:
        from core.subprocess_env import clean_child_env

        result = subprocess.run(
            [binary, "--brief", "--dereference", "--", path],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=timeout,
            check=False,
            env=clean_child_env(LC_ALL="C"),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        log.debug("file(1) on %s failed: %s", path, exc)
        return ""
    if result.returncode != 0:
        return ""
    text = (result.stdout or b"").decode("utf-8", errors="replace").strip()
    return text[:FILE_COMMAND_MAX_CHARS]


def name_of(path: str) -> str:
    """The last component of *path* (either separator), for display."""
    trimmed = path.rstrip("/\\")
    return trimmed.replace("\\", "/").rsplit("/", 1)[-1] if trimmed else path


def _probe(backend, path: str, max_bytes: int) -> tuple[str, Any, bytes]:
    """``(kind, size_or_description, data)`` - the part that may block."""
    if _is_local(backend):
        st = os.stat(path)
        if stat_module.S_ISDIR(st.st_mode):
            return KIND_DIRECTORY, None, b""
        if not stat_module.S_ISREG(st.st_mode):
            # Never open a FIFO or a device: the read would block or never end.
            return KIND_SPECIAL, _special_description(st.st_mode), b""
        return KIND_FILE, st.st_size, _read_bounded(backend, path, max_bytes)
    item = backend.stat(path)
    if getattr(item, "is_dir", False):
        return KIND_DIRECTORY, None, b""
    return KIND_FILE, getattr(item, "size", None), _read_bounded(backend, path, max_bytes)


def identify(
    backend,
    path: str,
    *,
    max_bytes: int = DEFAULT_MAX_BYTES,
    timeout: float = DEFAULT_TIMEOUT,
    cancel=None,
    use_file_command: bool = True,
) -> FileTypeInfo:
    """Identify *path* on *backend*; never raises for an unreadable file.

    Stats the path and reads at most *max_bytes* on a helper thread. A
    folder, a FIFO / device, a missing or unreadable file, a read that
    takes longer than *timeout* seconds and a set *cancel* each give a row
    with ``kind`` and ``error`` saying so. ``file(1)`` is consulted only
    for regular local files and only when *use_file_command* is true.
    Raises ``ValueError`` for a non-positive *max_bytes* or *timeout*.
    """
    _check_limits(max_bytes, timeout)
    cancelled = _cancel_check(cancel)
    name = name_of(path)
    if cancelled():
        return FileTypeInfo(path=path, name=name, kind=KIND_CANCELLED, error="cancelled")
    try:
        kind, extra, data = _run_with_deadline(
            lambda: _probe(backend, path, int(max_bytes)), timeout, cancelled
        )
    except InterruptedError:
        return FileTypeInfo(path=path, name=name, kind=KIND_CANCELLED, error="cancelled")
    except TimeoutError as exc:
        return FileTypeInfo(
            path=path, name=name, kind=KIND_TIMEOUT, description="timed out", error=str(exc)
        )
    except Exception as exc:  # noqa: BLE001 - any backend failure becomes a row
        return FileTypeInfo(
            path=path,
            name=name,
            kind=KIND_ERROR,
            description="cannot read",
            error=str(exc) or type(exc).__name__,
        )
    if kind == KIND_DIRECTORY:
        return FileTypeInfo(
            path=path, name=name, kind=KIND_DIRECTORY, description="Folder", mime=DIRECTORY_MIME
        )
    if kind == KIND_SPECIAL:
        return FileTypeInfo(path=path, name=name, kind=KIND_SPECIAL, description=extra)
    size = extra if isinstance(extra, int) else None
    truncated = len(data) >= int(max_bytes) if size is None else size > len(data)
    info = identify_bytes(data, name, size=size, path=path, truncated=truncated)
    if use_file_command and _is_local(backend):
        from dataclasses import replace

        info = replace(info, file_command=file_command_description(path))
    return info


# -- a whole folder -------------------------------------------------------------------------


@dataclass(frozen=True)
class FolderListing:
    """The files Identify Files in This Folder looks at: ``files`` as
    ``(path, item)`` sorted by name; ``folders`` subfolders (not entered),
    ``skipped`` entries whose name is no single safe path component (a
    hostile remote's ``../x``), ``truncated`` when there were more than
    the cap."""

    files: list
    folders: int = 0
    skipped: int = 0
    truncated: bool = False


def list_folder(
    backend,
    folder: str,
    *,
    max_files: int = FOLDER_MAX_FILES,
    timeout: float = FOLDER_LIST_TIMEOUT,
    cancel=None,
) -> FolderListing:
    """The files directly in *folder* (any backend, through ``list_dir``),
    at most *max_files*. Raises what the listing raises (``OSError``,
    ``TimeoutError``, ``InterruptedError`` on cancel) and ``ValueError``
    for a non-positive *max_files*."""
    from core.path_policy import safe_join

    if int(max_files) <= 0:
        raise ValueError(f"max_files must be positive, not {max_files!r}")
    _check_limits(1, timeout)
    items = _run_with_deadline(lambda: list(backend.list_dir(folder)), timeout,
                               _cancel_check(cancel))
    files, folders, skipped = [], 0, 0
    for item in sorted(items, key=lambda i: (str(getattr(i, "name", "")).casefold(),
                                             str(getattr(i, "name", "")))):
        name = getattr(item, "name", "")
        if not name or name in (".", ".."):
            continue
        if getattr(item, "is_dir", False):
            folders += 1
            continue
        try:
            path = safe_join(backend, folder, name)
        except ValueError:
            skipped += 1
            continue
        files.append((path, item))
    truncated = len(files) > int(max_files)
    return FolderListing(files=files[: int(max_files)], folders=folders, skipped=skipped,
                         truncated=truncated)


def is_disk_image(info: FileTypeInfo) -> bool:
    """A file whose content (or, failing that, name) says disk image - the
    rows that get *Disk Image…*."""
    if info.kind != KIND_FILE:
        return False
    from core import disk_image as DI

    return DI.type_says_image(info.mime, info.engine) or DI.looks_like_image(info.name)


class _Budget:
    """A read-only view of a binary file that hands out at most *budget*
    bytes in total; then every read is empty, as at the end of the file."""

    def __init__(self, fh, budget: int) -> None:
        self._fh = fh
        self.left = int(budget)

    def read(self, size: int = -1) -> bytes:
        if self.left <= 0:
            return b""
        size = self.left if size is None or size < 0 else min(size, self.left)
        data = self._fh.read(size)
        self.left -= len(data)
        return data

    def seekable(self) -> bool:
        try:
            return bool(self._fh.seekable())
        except (AttributeError, OSError, ValueError):
            return False

    def seek(self, offset: int, whence: int = 0) -> int:
        return self._fh.seek(offset, whence)

    def tell(self) -> int:
        return self._fh.tell()


def disk_image_note(
    backend,
    path: str,
    *,
    size: int | None = None,
    max_bytes: int = IMAGE_NOTE_MAX_BYTES,
    timeout: float = DEFAULT_TIMEOUT,
    cancel=None,
) -> str:
    """What :mod:`core.disk_image` reads from the image at *path* in one line
    (container, partition table, ``N partitions``, size), reading at most
    *max_bytes* within *timeout*; ``""`` when it cannot tell or fails."""
    from core import disk_image as DI

    _check_limits(max_bytes, timeout)

    def probe() -> str:
        length = size
        if length is None:
            length = int(getattr(backend.stat(path), "size", 0) or 0)
        with backend.open_read(path) as fh:
            info = DI.inspect(_Budget(fh, max_bytes), int(length))
        return info.summary() if info.kind != "unknown" else ""

    try:
        return _run_with_deadline(probe, timeout, _cancel_check(cancel)) or ""
    except Exception as exc:  # noqa: BLE001 - a note is optional, never an error
        log.debug("disk image note for %s: %s", path, exc)
        return ""


__all__ = [
    "BINARY_SIGNATURES",
    "DEFAULT_MAX_BYTES",
    "DEFAULT_TIMEOUT",
    "FOLDER_LIST_TIMEOUT",
    "FOLDER_MAX_FILES",
    "FileTypeInfo",
    "FolderListing",
    "IMAGE_NOTE_MAX_BYTES",
    "KIND_CANCELLED",
    "KIND_DIRECTORY",
    "KIND_ERROR",
    "KIND_FILE",
    "KIND_SPECIAL",
    "KIND_TIMEOUT",
    "MATCH",
    "MISMATCH",
    "SIGNATURES",
    "Signature",
    "UNKNOWN",
    "disk_image_note",
    "file_command_description",
    "identify",
    "identify_bytes",
    "is_disk_image",
    "list_folder",
    "name_of",
    "read_prefix",
]
