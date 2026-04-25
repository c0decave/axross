"""Read-only viewer for files fetched via :mod:`core.elevated_io`.

Companion UI for the file-pane "Open as root…" entry. The bytes have
already come back from ``elevated_read`` (which handled the polkit
prompt and the size cap), so this dialog is a pure renderer — no
backend, no further IO. Auto-detects text vs binary and shows either
decoded UTF-8 or a hex dump.

Read-only on purpose: writing back through ``elevated_write`` would
need a second polkit prompt and a confirmation flow that this small
first-cut viewer doesn't try to handle. Use a normal editor (with
sudo) when you need to modify ``/etc/*`` content.
"""
from __future__ import annotations

from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QLabel,
    QPlainTextEdit,
    QVBoxLayout,
)


MAX_TEXT_RENDER = 4 * 1024 * 1024  # 4 MiB — beyond this we hex-dump


def _looks_like_text(data: bytes, sample: int = 4096) -> bool:
    """Heuristic: treat the blob as text iff the first ``sample`` bytes
    decode as UTF-8 and contain no NUL. Matches what ``file(1)`` does
    for the common case (config files, /etc/passwd, log lines)."""
    head = data[:sample]
    if b"\x00" in head:
        return False
    try:
        head.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def _is_text_renderable(data: bytes) -> bool:
    """Stricter than ``_looks_like_text``: a blob is renderable as
    text only if (a) it sniffs as text in the first 4 KiB and
    (b) it's small enough to safely paste into QPlainTextEdit. A
    256-MiB log without a NUL byte should still go to the hex
    dump rather than spawn millions of replacement chars."""
    return _looks_like_text(data) and len(data) <= MAX_TEXT_RENDER


def _hex_dump(data: bytes, max_bytes: int = 256 * 1024) -> str:
    """Render a classic ``offset | hex | ascii`` dump. Capped at
    ``max_bytes`` so a 256-MiB elevated_read doesn't try to format
    tens of millions of lines into the QPlainTextEdit."""
    blob = data[:max_bytes]
    lines: list[str] = []
    for off in range(0, len(blob), 16):
        chunk = blob[off:off + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(
            chr(b) if 32 <= b < 127 else "." for b in chunk
        )
        lines.append(f"{off:08x}  {hex_part:<47}  {ascii_part}")
    if len(data) > max_bytes:
        lines.append(
            f"--- truncated: {len(data) - max_bytes} more bytes "
            f"({len(data)} total) ---"
        )
    return "\n".join(lines)


class ElevatedViewerDialog(QDialog):
    """Read-only viewer for bytes returned by ``elevated_read``."""

    def __init__(self, path: str, data: bytes, parent=None) -> None:
        super().__init__(parent)
        self._path = path
        self._data = data
        # Text rendering is gated on size too — see _is_text_renderable.
        # A multi-MiB binary file that happens to lack NULs in the
        # first 4 KiB shouldn't dump its decoded form into the editor.
        self._is_text = _is_text_renderable(data)
        self.setWindowTitle(f"Open as root: {path}")
        self.resize(820, 560)
        self._build_ui()

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)

        kind = "text" if self._is_text else "binary"
        info = QLabel(
            f"{self._path}  —  {len(self._data)} bytes  ({kind}, "
            f"read via pkexec, read-only)"
        )
        info.setStyleSheet("color: #666;")
        root.addWidget(info)

        self._editor = QPlainTextEdit()
        self._editor.setReadOnly(True)
        self._editor.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        font = QFont("Monospace", 10)
        font.setStyleHint(QFont.StyleHint.Monospace)
        self._editor.setFont(font)
        if self._is_text:
            self._editor.setPlainText(self._data.decode("utf-8", errors="replace"))
        else:
            self._editor.setPlainText(_hex_dump(self._data))
        root.addWidget(self._editor, stretch=1)

        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Close, self)
        btns.rejected.connect(self.reject)
        btns.accepted.connect(self.accept)
        root.addWidget(btns)
