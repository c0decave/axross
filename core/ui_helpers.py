"""User-facing dialog + toast helpers exposed via :mod:`core.scripting`.

Available as ``axross.message``, ``axross.confirm``, ``axross.toast``
in the REPL, ``--script`` mode, and the MCP server. Each helper tries
the running Qt application first; when there isn't one (headless
script mode) it falls back to plain stdout / readline so scripts
keep working in CI / cron contexts.

State icons live as inline SVG strings (rendered through Qt's
QSvgRenderer when Qt is available, dumped to a tempfile otherwise).
The bundled axross logo is loaded from
``resources/logo/axross-glyph.svg`` when present.

Examples (REPL or --script)::

    axross.message("Backup finished", level="success")
    if axross.confirm("Delete 47 files? This is irreversible."):
        for p in doomed:
            backend.remove(p)

    axross.toast("Connection lost", level="error", timeout=5)
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Literal

log = logging.getLogger(__name__)

# Status levels we render. Each maps to a colour + a glyph the SVG
# embeds. The user passes these as ``level=`` strings.
LEVELS = ("info", "success", "warning", "error")
Level = Literal["info", "success", "warning", "error"]

# Path to the bundled axross glyph (used by message + toast for the
# branded look). Resolved at import time; falls back to None when
# the resource isn't shipped (headless / incomplete install).
_GLYPH_PATH: Path | None
try:
    _candidate = Path(__file__).resolve().parent.parent / "resources" / "logo" / "axross-glyph.svg"
    _GLYPH_PATH = _candidate if _candidate.exists() else None
except Exception:  # noqa: BLE001 — never let resource resolution break import
    _GLYPH_PATH = None


# ---------------------------------------------------------------------------
# State icon SVG payloads (small, self-contained, no external deps)
# ---------------------------------------------------------------------------
#
# Each payload is a 64×64 SVG with a coloured circle background and a
# white glyph (i / ✓ / ! / ✕). Tuned to render crisply at the typical
# Qt MessageBox icon size (32–64 px) and at toast-strip sizes (24 px).

_LEVEL_SVG: dict[str, str] = {
    "info": (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">'
        '<circle cx="32" cy="32" r="30" fill="#2b87d1"/>'
        '<rect x="29" y="20" width="6" height="6" fill="#fff" rx="1"/>'
        '<rect x="29" y="30" width="6" height="20" fill="#fff" rx="1"/>'
        "</svg>"
    ),
    "success": (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">'
        '<circle cx="32" cy="32" r="30" fill="#2ea44f"/>'
        '<path d="M18 33 L28 43 L48 23" stroke="#fff" stroke-width="6" '
        'fill="none" stroke-linecap="round" stroke-linejoin="round"/>'
        "</svg>"
    ),
    "warning": (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">'
        '<polygon points="32,4 60,56 4,56" fill="#e0a800"/>'
        '<rect x="29" y="22" width="6" height="20" fill="#fff" rx="1"/>'
        '<rect x="29" y="46" width="6" height="6" fill="#fff" rx="1"/>'
        "</svg>"
    ),
    "error": (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">'
        '<circle cx="32" cy="32" r="30" fill="#cb2431"/>'
        '<path d="M20 20 L44 44 M44 20 L20 44" stroke="#fff" '
        'stroke-width="6" stroke-linecap="round"/>'
        "</svg>"
    ),
}


def _qt_is_running() -> bool:
    """True iff a QApplication exists and has an event loop. Determines
    whether we render via Qt widgets or fall back to stdout."""
    try:
        from PyQt6.QtWidgets import QApplication
    except ImportError:
        return False
    return QApplication.instance() is not None


def _level_pixmap(level: str, size: int = 48):
    """Build a QPixmap from the level's SVG payload. Returns ``None``
    when Qt isn't available (headless callers should fall back)."""
    try:
        from PyQt6.QtCore import QByteArray, Qt
        from PyQt6.QtGui import QPainter, QPixmap
        from PyQt6.QtSvg import QSvgRenderer
    except ImportError:
        return None
    svg = _LEVEL_SVG.get(level, _LEVEL_SVG["info"])
    renderer = QSvgRenderer(QByteArray(svg.encode("utf-8")))
    pm = QPixmap(size, size)
    pm.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pm)
    try:
        renderer.render(painter)
    finally:
        painter.end()
    return pm


# ---------------------------------------------------------------------------
# Public surface
# ---------------------------------------------------------------------------


def message(text: str, *, title: str = "axross", level: Level = "info") -> None:
    """Show a modal informational dialog.

    With a running Qt app: a :class:`QMessageBox` with a coloured
    state-icon (info/success/warning/error) and the bundled axross
    glyph as the window icon.

    Without Qt: prints ``"[axross] LEVEL: TITLE — TEXT"`` to stdout
    so the same code works in --script / cron / CI contexts.

    ``level`` accepts ``"info"`` / ``"success"`` / ``"warning"`` /
    ``"error"``. Other values fall back to "info".
    """
    if level not in LEVELS:
        level = "info"
    if not _qt_is_running():
        print(f"[axross] {level.upper()}: {title} — {text}", flush=True)
        return
    from PyQt6.QtWidgets import QMessageBox

    box = QMessageBox()
    box.setWindowTitle(title)
    box.setText(text)
    pm = _level_pixmap(level, 48)
    if pm is not None:
        box.setIconPixmap(pm)
    _apply_app_glyph(box)
    box.exec()


def confirm(text: str, *, title: str = "axross", default_yes: bool = False) -> bool:
    """Show a Yes/No dialog. Returns True on Yes, False on No / closed.

    Headless fallback (no Qt event loop): reads a single y/n from
    stdin so ``--script`` and REPL-without-GUI both work. The default
    answer is shown in upper-case in the prompt.
    """
    if not _qt_is_running():
        prompt = "Y/n" if default_yes else "y/N"
        try:
            answer = input(f"[axross] {title}: {text} [{prompt}] ").strip().lower()
        except (EOFError, OSError):
            return default_yes
        if not answer:
            return default_yes
        return answer in ("y", "yes", "j", "ja", "s", "si", "sí")
    from PyQt6.QtWidgets import QMessageBox

    box = QMessageBox()
    box.setWindowTitle(title)
    box.setText(text)
    pm = _level_pixmap("warning", 48)
    if pm is not None:
        box.setIconPixmap(pm)
    box.setStandardButtons(
        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
    )
    box.setDefaultButton(
        QMessageBox.StandardButton.Yes if default_yes else QMessageBox.StandardButton.No,
    )
    _apply_app_glyph(box)
    return box.exec() == QMessageBox.StandardButton.Yes


def toast(text: str, *, level: Level = "info", timeout: float = 4.0) -> None:
    """Show a non-modal toast in the bottom-right corner of the
    main window. Auto-dismisses after ``timeout`` seconds.

    With a running Qt app: a small frameless widget with the level
    SVG icon and the message text. Multiple toasts stack vertically.

    Headless fallback: prints ``"[axross] LEVEL: TEXT"`` and returns
    immediately.
    """
    if level not in LEVELS:
        level = "info"
    if not _qt_is_running():
        print(f"[axross] {level.upper()}: {text}", flush=True)
        return
    _show_toast(text, level=level, timeout=timeout)


def _apply_app_glyph(box) -> None:
    """Set the QMessageBox window icon to the bundled axross glyph
    (renders alongside the title, not inside the body — that's what
    setIconPixmap is for)."""
    if _GLYPH_PATH is None:
        return
    try:
        from PyQt6.QtGui import QIcon

        box.setWindowIcon(QIcon(str(_GLYPH_PATH)))
    except Exception:  # noqa: BLE001 — cosmetic
        pass


# ---------------------------------------------------------------------------
# Toast widget — minimal, self-stacking
# ---------------------------------------------------------------------------

# Active toasts so we can stack them vertically. Newest at the bottom.
# Protected by ``_toasts_lock`` because QTimer-driven dismissals can
# fire from re-entered event-loop iterations and a bare list mutation
# would corrupt the stack.
_toasts_lock = threading.Lock()
_active_toasts: list = []
# Cap stacked toasts so users can't be locked out of the bottom-right
# corner of the window by a runaway log loop.
_TOAST_MAX_STACK = 6


def _show_toast(text: str, *, level: str, timeout: float) -> None:
    from PyQt6.QtCore import Qt, QTimer
    from PyQt6.QtGui import QFont
    from PyQt6.QtWidgets import (
        QApplication,
        QFrame,
        QHBoxLayout,
        QLabel,
        QWidget,
    )

    app = QApplication.instance()
    if not isinstance(app, QApplication):
        # QApplication.instance() returns QCoreApplication | None; our
        # callers have already verified Qt is up via _qt_is_running(),
        # but if someone calls _show_toast() directly with a bare
        # QCoreApplication we have nothing to render against.
        return

    parent: QWidget | None = None
    for w in app.topLevelWidgets():
        if w.isVisible():
            parent = w
            break

    bg = {
        "info": "#2b87d1",
        "success": "#2ea44f",
        "warning": "#e0a800",
        "error": "#cb2431",
    }[level]

    toast_widget = QFrame(parent, Qt.WindowType.ToolTip)
    toast_widget.setStyleSheet(
        f"QFrame {{ background-color: {bg}; color: white; "
        f"border-radius: 8px; padding: 8px; }}"
        f"QLabel {{ color: white; }}"
    )
    layout = QHBoxLayout(toast_widget)
    layout.setContentsMargins(10, 8, 14, 8)
    layout.setSpacing(10)

    icon_label = QLabel()
    pm = _level_pixmap(level, 24)
    if pm is not None:
        icon_label.setPixmap(pm)
    layout.addWidget(icon_label)

    text_label = QLabel(text)
    text_label.setWordWrap(True)
    text_label.setMinimumWidth(180)
    text_label.setMaximumWidth(380)
    text_label.setFont(QFont("Sans", 10))
    layout.addWidget(text_label, stretch=1)

    toast_widget.adjustSize()
    with _toasts_lock:
        # Refuse to grow the stack past _TOAST_MAX_STACK — drop the
        # oldest so a runaway loop can't blanket the screen.
        while len(_active_toasts) >= _TOAST_MAX_STACK:
            old = _active_toasts.pop(0)
            try:
                old.close()
                old.deleteLater()
            except Exception:  # noqa: BLE001 — Qt object may be already gone
                pass
        _active_toasts.append(toast_widget)
        slot_index = len(_active_toasts) - 1
    _position_toast(toast_widget, parent, slot=slot_index)
    toast_widget.show()

    def _dismiss() -> None:
        with _toasts_lock:
            try:
                _active_toasts.remove(toast_widget)
            except ValueError:
                pass
            survivors = list(_active_toasts)
        toast_widget.close()
        toast_widget.deleteLater()
        # Re-layout the remaining toasts so the gaps close up.
        for i, w in enumerate(survivors):
            _position_toast(w, parent, slot=i)

    QTimer.singleShot(int(max(0.5, timeout) * 1000), _dismiss)


def _position_toast(widget, parent, slot: int | None = None) -> None:
    """Bottom-right corner of the parent window (or screen if no
    parent). Stacks vertically with 8 px gaps. Y is clamped to the
    visible region so a deep stack can't push toasts above the
    parent window."""
    from PyQt6.QtWidgets import QApplication

    if slot is None:
        with _toasts_lock:
            slot = len(_active_toasts)
    if parent is not None and parent.isVisible():
        rect = parent.geometry()
    else:
        screen = QApplication.primaryScreen()
        if screen is None:
            return
        rect = screen.availableGeometry()
    x = rect.right() - widget.width() - 16
    y = rect.bottom() - widget.height() - 16 - slot * (widget.height() + 8)
    # Don't allow the y to climb above the window's top-edge; clamp
    # so a flood of toasts collapses on top of each other instead
    # of disappearing off-screen.
    y = max(rect.top() + 8, y)
    widget.move(int(x), int(y))
