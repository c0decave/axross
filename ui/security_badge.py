"""The security badge: how a connection is protected, always in sight - the
file pane's header, the workspace tabs, the bookmarks, the chat accounts and
conversations. Each level of core.conn_security has an SVG icon of its own
(ui/icon_provider.py, ``sec-*``); the tooltip says exactly what protects the
connection and whether that was read from the live connection ("negotiated")
or follows from the settings ("configured").

Parts of the text come from the other side (an SSH server's version, a
cipher name): the tooltip is built as escaped rich text, never interpreted.
"""

from __future__ import annotations

import html
import logging

from PyQt6.QtCore import QSize, Qt, QTimer
from PyQt6.QtGui import QIcon
from PyQt6.QtWidgets import QToolButton, QToolTip

from core import conn_security as CS
from core.i18n import tr
from ui.icon_provider import has_icon, icon

log = logging.getLogger(__name__)


def icon_name(level: str) -> str:
    name = f"sec-{level}"
    return name if has_icon(name) else "sec-unknown"


def security_icon(info: CS.SecurityInfo | None, size: int = 32) -> QIcon:
    return icon(icon_name(info.level if info is not None else CS.LEVEL_UNKNOWN), size)


def with_badge(base: QIcon, info: CS.SecurityInfo | None, size: int = 32) -> QIcon:
    """*base* with the security badge in its lower right corner (a
    bookmark's own icon keeps its place, the badge is added)."""
    from PyQt6.QtGui import QPainter, QPixmap

    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    try:
        base.paint(painter, 0, 0, size, size)
        badge = size * 9 // 16
        painter.drawPixmap(size - badge, size - badge, security_icon(info, badge).pixmap(badge, badge))
    finally:
        painter.end()
    return QIcon(pixmap)


def tooltip_lines(info: CS.SecurityInfo) -> list[str]:
    """The tooltip as plain lines: what kind of protection, exactly what,
    the details, and where the answer comes from."""
    lines = [tr(info.title), tr(info.summary)]
    lines += [tr(d) for d in info.details]
    if info.level != CS.LEVEL_LOCAL:
        lines.append(tr("(negotiated on the live connection)") if info.negotiated
                     else tr("(configured – not read from a live connection)"))
    return lines


def tooltip_html(info: CS.SecurityInfo | None, heading: str = "") -> str:
    """Escaped rich text of :func:`tooltip_lines` (the first line bold)."""
    info = info or CS.UNKNOWN
    lines = ([heading] if heading else []) + tooltip_lines(info)
    escaped = [html.escape(line) for line in lines]
    first = 1 if heading else 0
    escaped[first] = f"<b>{escaped[first]}</b>"
    return "<qt>" + "<br>".join(escaped) + "</qt>"


class SecurityBadge(QToolButton):
    """A small icon button showing a SecurityInfo; hovering or clicking it
    shows the details."""

    def __init__(self, parent=None, size: int = 16) -> None:
        super().__init__(parent)
        self.setAutoRaise(True)
        self.setIconSize(QSize(size, size))
        self.setFocusPolicy(Qt.FocusPolicy.TabFocus)
        self.setCursor(Qt.CursorShape.WhatsThisCursor)
        self.setStyleSheet("QToolButton { border: none; padding: 0px; }")
        self.info: CS.SecurityInfo | None = None
        self.clicked.connect(self._show_details)
        self.set_info(None)

    def set_info(self, info: CS.SecurityInfo | None, heading: str = "") -> None:
        self.info = info or CS.UNKNOWN
        self.setIcon(security_icon(self.info))
        tip = tooltip_html(self.info, heading)
        self.setToolTip(tip)
        self.setAccessibleName(tr(self.info.title))
        self.setAccessibleDescription(" ".join(tooltip_lines(self.info)))

    def _show_details(self) -> None:
        QToolTip.showText(self.mapToGlobal(self.rect().bottomLeft()), self.toolTip(), self)


# --- workspace tabs -----------------------------------------------------------------------

def tab_security(infos: list[tuple[str, CS.SecurityInfo]]) -> tuple[QIcon, str] | None:
    """The icon (the weakest connection's) and the tooltip (every
    connection) of a workspace tab; None for a tab without file panes."""
    if not infos:
        return None
    weakest = CS.weakest([info for _name, info in infos])
    lines = [html.escape(tr("Weakest connection: {title}").format(title=tr(weakest.title)))]
    for name, info in infos[:20]:
        lines.append(html.escape(f"{name}: {tr(info.summary)}"))
    if len(infos) > 20:
        lines.append(html.escape(tr("… and {n} more").format(n=len(infos) - 20)))
    lines[0] = f"<b>{lines[0]}</b>"
    return security_icon(weakest), "<qt>" + "<br>".join(lines) + "</qt>"


def refresh_workspace_tabs(window) -> None:
    """Give every workspace tab of *window* (ui.workspaces.WorkspaceMixin)
    the badge of its weakest file connection."""
    tabs = getattr(window, "_workspace_tabs", None)
    if tabs is None:
        return
    from PyQt6 import sip

    if sip.isdeleted(tabs):
        return
    for ws in list(getattr(window, "_workspaces", [])):
        index = tabs.indexOf(ws.root)
        if index < 0:
            continue
        try:
            panes = window._widgets_of(ws)[0]
        except Exception:  # noqa: BLE001 - a workspace being torn down
            log.debug("workspace panes not readable", exc_info=True)
            continue
        infos = []
        for pane in panes:
            if isinstance(pane, sip.simplewrapper) and sip.isdeleted(pane):
                continue
            info = getattr(pane, "security_info", None)
            backend = getattr(pane, "backend", None)
            infos.append((getattr(backend, "name", "?"), info if info is not None else CS.of_backend(backend)))
        shown = tab_security(infos)
        tabs.setTabIcon(index, shown[0] if shown else QIcon())
        tabs.setTabToolTip(index, shown[1] if shown else "")


def schedule_workspace_tabs(window) -> None:
    """:func:`refresh_workspace_tabs` once the event loop is free again -
    many panes changing at once (a session restore) refresh the tabs once."""
    from PyQt6 import sip

    if window is None or sip.isdeleted(window):
        return
    timer = getattr(window, "_security_tab_timer", None)
    if timer is None:
        timer = QTimer(window)
        timer.setSingleShot(True)
        timer.setInterval(0)
        timer.timeout.connect(lambda: refresh_workspace_tabs(window))
        window._security_tab_timer = timer
    timer.start()
