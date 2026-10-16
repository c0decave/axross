"""Window handling shared by the image viewer and the media viewer.

* A Maximize button in the title bar (a QDialog has none by default).
* Ctrl+M toggles maximized <-> normal; F11 toggles fullscreen and comes
  back to the state it left (maximized or normal), which Qt itself does
  not do: ``showFullScreen`` drops the maximized bit.
* The last normal geometry and whether the window was maximized are kept
  per viewer in ``session.json`` under ``window.viewers.<name>`` — the
  file the main window already keeps its own size and visual settings in
  (``core.i18n.SETTINGS_FILE``). It is written when a viewer closes,
  never on a resize, and merged so every other key in the file stays.
* A remembered geometry is clamped to the available screen on restore, so
  a window saved on a larger or detached monitor never opens off-screen.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from PyQt6.QtCore import QRect, QSize, Qt
from PyQt6.QtGui import QGuiApplication, QKeySequence, QShortcut
from PyQt6.QtWidgets import QWidget

from core import i18n

log = logging.getLogger("ui.viewer_window")

MAXIMIZE_KEY = "Ctrl+M"
FULLSCREEN_KEY = "F11"

#: Key under ``window`` in session.json that holds one entry per viewer.
VIEWERS_KEY = "viewers"

#: Size a viewer opens at when nothing (valid) is remembered.
DEFAULT_SIZES: dict[str, tuple[int, int]] = {
    "image": (900, 680),
    "media": (1000, 720),
}

#: Dynamic property: was the window maximized when it went fullscreen?
_MAXIMIZED_BEFORE_FULLSCREEN = "axrossMaximizedBeforeFullScreen"


# -- window state --------------------------------------------------------------


def allow_maximize(window: QWidget) -> None:
    """Give *window* a Maximize button in its title bar."""
    window.setWindowFlag(Qt.WindowType.WindowMaximizeButtonHint, True)


def toggle_maximized(window: QWidget) -> None:
    """Maximized -> normal, normal -> maximized. In fullscreen, Ctrl+M asks
    for a maximized window, so it leaves fullscreen into maximized."""
    if window.isFullScreen() or not window.isMaximized():
        window.showMaximized()
    else:
        window.showNormal()


def toggle_fullscreen(window: QWidget) -> None:
    """Enter fullscreen, or leave it to the state it was entered from."""
    if window.isFullScreen():
        leave_fullscreen(window)
        return
    window.setProperty(_MAXIMIZED_BEFORE_FULLSCREEN, window.isMaximized())
    window.showFullScreen()


def leave_fullscreen(window: QWidget) -> None:
    """Back to maximized or normal, whichever fullscreen was entered from."""
    if not window.isFullScreen():
        return
    if _was_maximized_before_fullscreen(window):
        window.showMaximized()
    else:
        window.showNormal()


def _was_maximized_before_fullscreen(window: QWidget) -> bool:
    return bool(window.property(_MAXIMIZED_BEFORE_FULLSCREEN))


def install_window_keys(window: QWidget, *, fullscreen: bool) -> list[QShortcut]:
    """Ctrl+M (and F11 when *fullscreen*) as window-wide shortcuts, so they
    work whichever child has the focus."""
    shortcuts = [QShortcut(QKeySequence(MAXIMIZE_KEY), window)]
    shortcuts[0].activated.connect(lambda: toggle_maximized(window))
    if fullscreen:
        sc = QShortcut(QKeySequence(FULLSCREEN_KEY), window)
        sc.activated.connect(lambda: toggle_fullscreen(window))
        shortcuts.append(sc)
    return shortcuts


# -- persistence ---------------------------------------------------------------


def _settings_path() -> Path:
    # Looked up per call: tests and the window patch the module attribute.
    return Path(i18n.SETTINGS_FILE)


def _read_settings():
    from ui.main_window import _read_json_file

    return _read_json_file(_settings_path())


def _valid_entry(entry) -> dict | None:
    if not isinstance(entry, dict):
        return None
    values = {}
    for key in ("x", "y", "width", "height"):
        value = entry.get(key)
        if isinstance(value, bool) or not isinstance(value, int):
            return None
        values[key] = value
    if values["width"] <= 0 or values["height"] <= 0:
        return None
    values["maximized"] = entry.get("maximized") is True
    return values


def load_state(name: str) -> dict | None:
    """The remembered state of viewer *name*, or ``None`` when there is
    none or it is unusable (any failure costs the size, not the viewer)."""
    try:
        data = _read_settings()
    except (OSError, ValueError):
        return None
    window = data.get("window") if isinstance(data, dict) else None
    viewers = window.get(VIEWERS_KEY) if isinstance(window, dict) else None
    if not isinstance(viewers, dict):
        return None
    return _valid_entry(viewers.get(name))


def clamp_to_screen(rect: QRect, window: QWidget | None = None) -> QRect:
    """*rect* shrunk to fit the available area of the screen it is on and
    moved fully inside it. A rect on no screen goes to the window's screen,
    else the primary one."""
    screen = QGuiApplication.screenAt(rect.center())
    if screen is None and window is not None:
        screen = window.screen()
    if screen is None:
        screen = QGuiApplication.primaryScreen()
    if screen is None:
        return QRect(rect)
    avail = screen.availableGeometry()
    width = max(1, min(rect.width(), avail.width()))
    height = max(1, min(rect.height(), avail.height()))
    x = min(max(rect.x(), avail.left()), avail.left() + avail.width() - width)
    y = min(max(rect.y(), avail.top()), avail.top() + avail.height() - height)
    return QRect(x, y, width, height)


def restore_window_state(window: QWidget, name: str) -> None:
    """Size and place *window* as viewer *name* was last closed; call it
    before the window is shown. Without a usable entry it gets the default
    size and opens normal."""
    state = load_state(name)
    if state is None:
        window.resize(QSize(*DEFAULT_SIZES[name]))
        return
    rect = QRect(state["x"], state["y"], state["width"], state["height"])
    window.setGeometry(clamp_to_screen(rect, window))
    if state["maximized"]:
        window.setWindowState(window.windowState() | Qt.WindowState.WindowMaximized)


def save_window_state(window: QWidget, name: str) -> None:
    """Remember *window*'s normal geometry and maximized state as viewer
    *name*. Only a window that is on screen is saved: a viewer that closed
    before it was shown (a failed load) must not overwrite what is kept."""
    if not window.isVisible():
        return
    full = window.isFullScreen()
    maximized = window.isMaximized() or (full and _was_maximized_before_fullscreen(window))
    rect = window.normalGeometry() if (full or window.isMaximized()) else window.geometry()
    if not rect.isValid():
        rect = window.geometry()
    entry = {
        "x": rect.x(),
        "y": rect.y(),
        "width": rect.width(),
        "height": rect.height(),
        "maximized": maximized,
    }
    from ui.main_window import _write_private_text

    # Same merge as MainWindow._save_session and i18n.store_language: keep
    # whatever this function does not write itself.
    try:
        data = _read_settings()
    except (OSError, ValueError):
        data = None
    if not isinstance(data, dict):
        data = {}
    win = data.get("window")
    if not isinstance(win, dict):
        win = {}
    viewers = win.get(VIEWERS_KEY)
    if not isinstance(viewers, dict):
        viewers = {}
    viewers[name] = entry
    win[VIEWERS_KEY] = viewers
    data["window"] = win
    try:
        _write_private_text(_settings_path(), json.dumps(data, indent=2))
    except OSError as exc:
        log.warning("Could not save the %s viewer window state: %s", name, exc)


__all__ = [
    "DEFAULT_SIZES",
    "FULLSCREEN_KEY",
    "MAXIMIZE_KEY",
    "VIEWERS_KEY",
    "allow_maximize",
    "clamp_to_screen",
    "install_window_keys",
    "leave_fullscreen",
    "load_state",
    "restore_window_state",
    "save_window_state",
    "toggle_fullscreen",
    "toggle_maximized",
]
