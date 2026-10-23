"""One text file, read and written through any backend, byte-faithful.

The editor widgets (ui/editor_window.py tabs, ui/text_editor.py dialog) keep
the text; this keeps what the widget loses: QPlainTextEdit folds every line
ending into a block break and ``toPlainText()`` rewrites no-break spaces and
U+2028, so a save is built from the blocks, each line gets back the ending
it had (a new line gets the file's most common one), a UTF-8 BOM the file
started with is put back, and the file is written atomically - after a
check that nobody changed it since it was read.
"""

from __future__ import annotations

import codecs
import difflib
import logging
import re

from core import open_limits

log = logging.getLogger(__name__)


class EditorReadLimitError(OSError):
    """Raised when a backend returns more data than the editor cap."""


_UTF8_BOM = b"\xef\xbb\xbf"
_UTF16_BOMS = (b"\xff\xfe", b"\xfe\xff")

#: Everything QPlainTextEdit turns into a block break (QTextCursor::insertText
#: also splits at the frame marks U+FDD0 and U+FDD1). The widget keeps none
#: of them, so the save has to put back the one each line had.
_LINE_BREAK = re.compile("(\r\n|\r|\n| |\ufdd0|\ufdd1)")
NEWLINE_NAMES = {"\n": "LF", "\r\n": "CRLF", "\r": "CR"}


def _split_lines(text: str) -> tuple[list[str], list[str]]:
    """*text* as the editor's blocks and the break that ended each one
    (``""`` after the last block)."""
    parts = _LINE_BREAK.split(text)
    return parts[0::2], parts[1::2] + [""]


def _common_newline(endings: list[str]) -> str:
    """The line ending most lines use (first seen wins a tie), else LF.
    New lines get it."""
    counts: dict[str, int] = {}
    for ending in endings:
        if ending in ("\r\n", "\r", "\n"):
            counts[ending] = counts.get(ending, 0) + 1
    return max(counts, key=counts.get) if counts else "\n"


def _line_endings(old_lines, old_endings, new_lines, default: str) -> list[str]:
    """The ending for each of *new_lines*: a line that is still there, or
    was edited in place, keeps the one it had; a new line gets *default*.

    Joining every line with one ending rewrote the untouched lines of a
    file that mixes LF and CRLF."""
    endings = [default] * len(new_lines)
    # Common head and tail first: an edit is local, and the matcher then
    # only sees the changed middle of a large file.
    head = 0
    limit = min(len(old_lines), len(new_lines))
    while head < limit and old_lines[head] == new_lines[head]:
        endings[head] = old_endings[head]
        head += 1
    tail = 0
    while (
        tail < limit - head
        and old_lines[len(old_lines) - 1 - tail] == new_lines[len(new_lines) - 1 - tail]
    ):
        endings[len(new_lines) - 1 - tail] = old_endings[len(old_lines) - 1 - tail]
        tail += 1
    old_mid = old_lines[head : len(old_lines) - tail]
    new_mid = new_lines[head : len(new_lines) - tail]
    matcher = difflib.SequenceMatcher(None, old_mid, new_mid, autojunk=False)
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag not in ("equal", "replace"):
            continue
        for k in range(min(i2 - i1, j2 - j1)):
            endings[head + j1 + k] = old_endings[head + i1 + k]
    for k in range(len(endings) - 1):
        if not endings[k]:
            endings[k] = default
    if endings:
        endings[-1] = ""
    return endings


def _read_capped(handle, cap: int | None = None) -> bytes:
    if cap is None:
        cap = open_limits.max_open_bytes()
    data = handle.read(cap + 1)
    if isinstance(data, str):
        data = data.encode("utf-8", errors="replace")
    if len(data) > cap:
        raise EditorReadLimitError(f"file exceeds {cap} byte editor cap")
    return bytes(data)


def decode(raw: bytes) -> tuple[str, str, bool]:
    """``(text, encoding, bom)`` of file bytes: UTF-16 by its BOM, UTF-8
    (with or without BOM), else Latin-1, which reads any byte - also a file
    that starts with a UTF-16 BOM but is not valid UTF-16 (odd length, lone
    surrogate), so it still opens and saves byte for byte."""
    if raw.startswith(_UTF16_BOMS):
        try:
            return raw.decode("utf-16"), "utf-16", True
        except UnicodeDecodeError:
            return raw.decode("latin-1"), "latin-1", False
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1"), "latin-1", False
    if raw.startswith(_UTF8_BOM):
        return text[1:], "utf-8", True
    return text, "utf-8", False


class TextDocument:
    """The file behind one editor: load, encode, save."""

    def __init__(self, backend, path: str) -> None:
        self.backend = backend
        self.path = path
        self.original = b""
        self.encoding = "utf-8"
        self.bom = False
        #: Byte order of a UTF-16 file: the one it was read with, else
        #: little endian (what Windows writes).
        self.utf16_codec = "utf-16-le"
        self.newline = "\n"
        self._lines: list[str] = [""]
        self._endings: list[str] = [""]
        self._force_newline = False
        self.loaded = False

    @classmethod
    def untitled(cls) -> "TextDocument":
        """A document no file is behind yet (the editor's New): UTF-8, LF.
        It is written by save_as() only - save() has no file to write."""
        return cls(None, "")

    # -- reading ---------------------------------------------------------------------------

    def read_bytes(self) -> bytes:
        stat = self.backend.stat(self.path)
        if stat.size > open_limits.max_open_bytes():
            raise EditorReadLimitError(
                f"{self.path} is {stat.size_human}; the open size limit is smaller "
                "(Edit → Settings… → Files & Panes → Open Size Limit)"
            )
        with self.backend.open_read(self.path) as fh:
            return _read_capped(fh)

    def load(self) -> str:
        """Read the file; returns its text. Raises OSError."""
        raw = self.read_bytes()
        text, self.encoding, self.bom = decode(raw)
        if self.encoding == "utf-16":
            self.utf16_codec = "utf-16-be" if raw.startswith(b"\xfe\xff") else "utf-16-le"
        self.original = raw
        self._remember(text)
        self._force_newline = False
        self.loaded = True
        return text

    def _remember(self, text: str) -> None:
        self._lines, self._endings = _split_lines(text)
        self.newline = _common_newline(self._endings)

    @staticmethod
    def blocks_of(text: str) -> list[str]:
        """*text* as the widget's blocks would hold it."""
        return _split_lines(text)[0]

    # -- settings --------------------------------------------------------------------------

    @property
    def newline_name(self) -> str:
        return NEWLINE_NAMES.get(self.newline, "LF")

    def set_newline(self, newline: str) -> None:
        """Every line ending becomes *newline* on the next save."""
        if newline not in NEWLINE_NAMES:
            raise ValueError(f"not a line ending: {newline!r}")
        self.newline = newline
        self._force_newline = True

    def set_encoding(self, encoding: str, *, bom: bool | None = None) -> None:
        """Write with *encoding* from the next save on (LookupError for an
        unknown codec). UTF-16 always carries its BOM."""
        name = codecs.lookup(encoding).name
        self.encoding = name if name not in ("utf-16", "utf-16-le", "utf-16-be") else "utf-16"
        if self.encoding == "utf-16":
            self.bom = True
        elif bom is not None:
            self.bom = bool(bom) and self.encoding == "utf-8"
        elif self.encoding != "utf-8":
            self.bom = False

    @property
    def encoding_name(self) -> str:
        label = {"utf-8": "UTF-8", "latin-1": "Latin-1", "iso8859-1": "Latin-1",
                 "utf-16": "UTF-16"}.get(self.encoding, self.encoding.upper())
        return label + (" BOM" if self.bom and self.encoding == "utf-8" else "")

    # -- writing ---------------------------------------------------------------------------

    def encode(self, blocks: list[str]) -> bytes:
        """The bytes the file should hold for the widget's *blocks*."""
        if self._force_newline:
            endings = [self.newline] * (len(blocks) - 1) + [""]
        else:
            endings = _line_endings(self._lines, self._endings, blocks, self.newline)
        text = "".join(line + ending for line, ending in zip(blocks, endings))
        if self.encoding == "utf-16":
            # The codec "utf-16" writes the host's byte order: a big-endian
            # file would come back little endian. Keep the file's own.
            content = ("\ufeff" + text).encode(self.utf16_codec)
        else:
            content = text.encode(self.encoding)
        if self.bom and self.encoding == "utf-8":
            content = _UTF8_BOM + content
        self._pending_text = text
        return content

    def changed_on_disk(self) -> bool:
        """Whether the file differs from what was read or last saved.
        Raises OSError when it cannot be read back."""
        return self.read_bytes() != self.original

    def save(self, blocks: list[str], *, force: bool = False) -> str:
        """Write *blocks*: ``"saved"``, or ``"conflict"`` when the file
        changed since it was read (nothing written; *force* writes anyway).
        Raises PermissionError for a document that was never read,
        UnicodeEncodeError (nothing written), OSError."""
        if self.backend is None:
            raise PermissionError("An untitled document has no file yet; save it with save_as().")
        if not self.loaded:
            raise PermissionError(
                "The file was never read, so saving would replace content nobody has seen."
            )
        content = self.encode(blocks)
        if not force:
            try:
                if self.changed_on_disk():
                    return "conflict"
            except EditorReadLimitError:
                raise  # cannot check: refuse rather than overwrite blind
            except OSError as exc:
                log.warning("Could not check %s for changes, saving: %s", self.path, exc)
        from core.atomic_io import atomic_write

        atomic_write(self.backend, self.path, content)
        self._after_write(content)
        log.info("Saved file: %s (%d bytes)", self.path, len(content))
        return "saved"

    def save_as(self, backend, path: str, blocks: list[str]) -> None:
        """Write *blocks* to *path* on *backend* (any file there is
        replaced - the caller asked first) with this document's encoding,
        BOM and line endings; from then on the document is that file.
        Raises UnicodeEncodeError (nothing written), OSError (the document
        stays the file it was)."""
        if self.backend is not None and not self.loaded:
            raise PermissionError(
                "The file was never read, so its encoding and line endings are unknown."
            )
        content = self.encode(blocks)
        from core.atomic_io import atomic_write

        atomic_write(backend, path, content)
        self.backend, self.path = backend, path
        self.loaded = True
        self._after_write(content)
        log.info("Saved file as: %s (%d bytes)", path, len(content))

    def _after_write(self, content: bytes) -> None:
        self.original = content
        self._remember(self._pending_text)
        self._force_newline = False
