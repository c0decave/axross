"""The Markdown reader's theme in the window: View > Theme, kept, and every open page told.

One :class:`ThemeHub` a process holds the chosen theme (core.markdown_themes: an id, or "auto" - the
page follows the window: axross's theme in axross, the desktop's light or dark scheme in
axross-markdown) and says when it changes (``changed``); each ui.markdown_view.MarkdownView makes its page
anew in the new colours and shows it in one change - the old page stays, in its colours, until the new
one is there (no flash of a page half in one theme and half in the other, no blank page between).

Rapid switching is rate-limited: a choice applies at once when the last one is at least
:data:`MIN_INTERVAL_MS` old, else the latest of them a moment later - never more than one change of the
page's colours in that time, whatever chose (a click, the keyboard, a script).

The choice is kept in axross's settings (``markdown_theme``) in axross, in
``~/.config/axross-markdown/settings.json`` (``page_theme``) in axross-markdown.
"""

from __future__ import annotations

import logging
import sys
import time

from PyQt6.QtCore import QObject, QTimer, pyqtSignal

from core import markdown_themes as MT

log = logging.getLogger(__name__)

#: The least time between two changes of the page's colours.
MIN_INTERVAL_MS = 400
#: The setting in axross's settings.json.
AXROSS_SETTING = "markdown_theme"


def standalone() -> bool:
    """Whether this is axross-markdown (its own package) - not axross's built-in viewer."""
    return "axross_markdown" in sys.modules


def stored_theme() -> str:
    """The theme kept ("auto" when none is)."""
    try:
        if standalone():
            from core.markdown_settings import read_setting

            return MT.normalize(read_setting(MT.SETTING_PAGE, MT.AUTO))
        try:
            from core import open_limits
        except ImportError:  # (an export without axross's settings)
            return MT.AUTO
        return MT.normalize(open_limits.read_setting(AXROSS_SETTING, MT.AUTO))
    except Exception:  # noqa: BLE001 - unreadable settings: the window's
        return MT.AUTO


def store_theme(theme_id: str) -> None:
    try:
        if standalone():
            from core.markdown_settings import write_setting

            write_setting(MT.SETTING_PAGE, theme_id)
            return
        try:
            from core import open_limits
        except ImportError:
            return
        open_limits.write_setting(AXROSS_SETTING, theme_id)
    except Exception:  # noqa: BLE001 - not kept: said in the log, the choice still applies
        log.warning("The Markdown theme could not be kept", exc_info=True)


class ThemeHub(QObject):
    """The chosen theme of the process; ``changed(theme_id)`` once a change applies."""

    changed = pyqtSignal(str)

    def __init__(self, parent=None, *, clock=time.monotonic) -> None:
        super().__init__(parent)
        self._theme = stored_theme()
        self._pending: str | None = None
        self._applied = float("-inf")
        self.clock = clock
        self.applied_count = 0
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self._apply_pending)

    def theme_id(self) -> str:
        """The theme in use: an id, or "auto"."""
        return self._theme

    def theme(self) -> MT.Theme | None:
        """The chosen Theme - None for "auto"."""
        return MT.get(self._theme)

    def choose(self, theme_id: str, *, keep: bool = True) -> None:
        """*theme_id* chosen (kept with *keep*): applied now, or - another change less than
        MIN_INTERVAL_MS ago - the latest choice once that time is over."""
        theme_id = MT.normalize(theme_id)
        if keep:
            store_theme(theme_id)
        self._pending = theme_id
        wait = MIN_INTERVAL_MS - (self.clock() - self._applied) * 1000
        if wait <= 0 and not self._timer.isActive():
            self._apply_pending()
        elif not self._timer.isActive():
            self._timer.start(max(1, int(wait)))

    def _apply_pending(self) -> None:
        theme_id, self._pending = self._pending, None
        if theme_id is None or theme_id == self._theme:
            return
        self._theme = theme_id
        self._applied = self.clock()
        self.applied_count += 1
        self.changed.emit(theme_id)


_HUB: list[ThemeHub] = []


def hub() -> ThemeHub:
    """The process's ThemeHub (made at first use, owned by the application)."""
    from PyQt6 import sip
    from PyQt6.QtCore import QCoreApplication

    if _HUB and not sip.isdeleted(_HUB[0]):
        return _HUB[0]
    _HUB[:] = [ThemeHub(QCoreApplication.instance())]
    return _HUB[0]


def auto_label() -> str:
    from core.i18n import tr

    return tr("Automatic (as the window)") if standalone() else tr("Automatic (as axross)")


def fill_theme_menu(menu) -> None:
    """*menu*: "Automatic" and every theme, the one in use checked - a choice applied to every open page
    and kept."""
    from PyQt6.QtGui import QActionGroup

    from core.i18n import tr

    group = QActionGroup(menu)
    group.setExclusive(True)
    current = hub().theme_id()
    for theme_id in MT.CHOICES:
        label = auto_label() if theme_id == MT.AUTO else tr(MT.THEMES[theme_id].label)
        action = menu.addAction(label)
        action.setCheckable(True)
        action.setChecked(theme_id == current)
        action.setData(theme_id)
        group.addAction(action)
    group.triggered.connect(lambda action: hub().choose(action.data()))

    def checked() -> None:  # (another window may have chosen one)
        now = hub().theme_id()
        for action in group.actions():
            action.setChecked(action.data() == now)

    menu.aboutToShow.connect(checked)


def page_palette(theme: MT.Theme, base):
    """*base* (a QPalette) with the page roles of *theme*: its ground, text, links and selection."""
    from PyQt6.QtGui import QColor, QPalette

    palette = QPalette(base)
    page = theme.page
    roles = ((QPalette.ColorRole.Base, page["page_bg"]), (QPalette.ColorRole.Window, page["page_bg"]),
             (QPalette.ColorRole.Text, page["text"]), (QPalette.ColorRole.WindowText, page["text"]),
             (QPalette.ColorRole.Highlight, page["selection_bg"]),
             (QPalette.ColorRole.HighlightedText, page["selection_fg"]),
             (QPalette.ColorRole.Link, page["link"]), (QPalette.ColorRole.LinkVisited, page["link"]),
             (QPalette.ColorRole.PlaceholderText, page["muted"]))
    for group in (QPalette.ColorGroup.Active, QPalette.ColorGroup.Inactive):
        for role, colour in roles:
            palette.setColor(group, role, QColor(colour))
    return palette


def add_theme_menu(menu):
    """A "Theme" submenu of *menu* (View): :func:`fill_theme_menu`. The submenu."""
    from core.i18n import tr

    themes = menu.addMenu(tr("Theme"))
    themes.setObjectName("markdown_page_theme")
    fill_theme_menu(themes)
    return themes


__all__ = ["MIN_INTERVAL_MS", "ThemeHub", "add_theme_menu", "auto_label", "fill_theme_menu", "hub",
           "page_palette", "standalone", "store_theme", "stored_theme"]
