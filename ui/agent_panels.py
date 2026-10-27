"""Agent conversations as panels of their own.

A tab of the Agent dock (ui.agent_dock) is *detached* into an
:class:`AgentPanel` - from the tab's right-click menu (Detach as Panel, or
Send to Workspace, which lays the panel out on the picked workspace or a
new one in the same step) or by dragging the tab out of the tab bar - and
*attached* back from the panel's title bar (Attach to Agent Dock). Tools >
New Agent Window opens a fresh conversation directly as such a panel.

The panel carries the tab itself: the same AgentTab widget with its
session, its running task, its open questions and its transcript moves
from the dock into the panel and back - nothing is rebuilt or restarted.
The tab keeps working through the Agent dock it belongs to (voice, MCP
servers, settings, agent events), so every integration of the dock covers
a detached conversation as well.

An AgentPanel is an extension panel (ui.extension_panels.ExtensionDock):
it is on All Workspaces (the window's dock area) or laid out on a
workspace like a pane, moved from its title bar (Send to Workspace) or the
Add Extension Panel menu, dragged by its title bar and takes dragged
panes. Unlike an extension's panel, its [x] closes the conversation - asking first when
there is anything to lose, as closing a tab does - and a closed workspace
leaves it on screen on All Workspaces instead of hiding it.

Session: the panel's object name is ``agent-conversation-<session id>``;
the session file says the conversation is detached (core.agent_session:
``detached``) and the main window's layout says on which workspace.
"""

from __future__ import annotations

import weakref

from PyQt6 import sip
from PyQt6.QtCore import QEvent, QPoint, QSize, Qt, pyqtSignal
from PyQt6.QtGui import QMouseEvent
from PyQt6.QtWidgets import QMenu, QSplitter, QTabBar, QToolButton, QWidget

from core.i18n import tr
from ui.extension_panels import ExtensionDock, ExtensionPanelTitleBar

#: The object name of a detached conversation: this, then its session id.
AGENT_PANEL_PREFIX = "agent-conversation-"
#: What a session layout entry of a detached conversation names as its
#: "extension" (no extension has it: theirs carry a "user:"/"bundled:" id).
AGENT_PANEL_EXT_ID = "axross:agent"
#: How far (pixels) beyond the tab bar a dragged tab must go to detach.
DETACH_DISTANCE = 30


def alive(widget) -> bool:
    """*widget* is there and its Qt object not deleted."""
    return widget is not None and not sip.isdeleted(widget)


def weak_call(obj, method: str):
    """A slot calling *obj.method* while *obj* lives: a connection to a
    long-lived sender (the application's focusChanged, a panel) that
    neither keeps *obj* alive nor calls into it once it is gone."""
    ref = weakref.ref(obj)

    def call(*args, **kwargs):
        target = ref()
        if target is not None and not sip.isdeleted(target):
            return getattr(target, method)(*args, **kwargs)
        return None

    return call


def panel_title(title: str) -> str:
    """The window title of a detached conversation (menus list it)."""
    return tr("Agent: {title}").format(title=title)


class AgentPanelTitleBar(ExtensionPanelTitleBar):
    """An extension panel's title bar with the Agent's icon, the link lamp
    of the conversation and an Attach to Agent Dock button (also in the
    right-click menu)."""

    attach_requested = pyqtSignal()

    def __init__(self, title: str, dock: AgentPanel) -> None:
        super().__init__(title, dock, icon_name="bot")
        self._close_btn.setToolTip(tr("Close this conversation"))
        self.attach_button = QToolButton(self)
        self.attach_button.setText("⇲")  # ⇲: back into the dock
        self.attach_button.setToolTip(tr("Attach to Agent Dock"))
        self.attach_button.setAccessibleName(tr("Attach to Agent Dock"))
        self.attach_button.setAutoRaise(True)
        self.attach_button.setFixedSize(QSize(22, 22))
        self.attach_button.clicked.connect(lambda _checked=False: self.attach_requested.emit())
        layout = self.layout()
        layout.insertWidget(layout.indexOf(self.move_button), self.attach_button)

    def context_menu(self) -> QMenu:
        menu = super().context_menu()
        menu.addAction(tr("Attach to Agent Dock")).triggered.connect(
            lambda _checked=False: self.attach_requested.emit())
        return menu


class AgentPanel(ExtensionDock):
    """A detached Agent conversation: the AgentTab *tab* in a panel."""

    parks_visible = True
    #: This panel's place changed (into a workspace or the dock area).
    place_changed = pyqtSignal(object)
    #: Its [x] was pressed: the Agent dock decides (it asks, then closes).
    close_requested = pyqtSignal(object)
    #: Close all of its dock area: back into the Agent dock, unasked.
    park_requested = pyqtSignal(object)

    def __init__(self, tab: QWidget, owner: QWidget) -> None:
        title = tab.session.title
        super().__init__(panel_title(title), owner, AGENT_PANEL_EXT_ID)
        self.setObjectName(f"{AGENT_PANEL_PREFIX}{tab.session.id}")
        self.tab = tab
        #: Set by the Agent dock once the conversation is to go: the
        #: next close is not asked about again.
        self.closing = False
        bar = AgentPanelTitleBar(title, self)
        self.setTitleBarWidget(bar)
        from ui.agent_link_lamp import LinkLamp

        #: Whether this conversation's LLM is reachable (as the dock's lamp).
        self.lamp = LinkLamp(bar)
        bar.add_indicator(self.lamp)
        self.setWidget(tab)
        tab.show()

    def set_title(self, title: str) -> None:
        self.setWindowTitle(panel_title(title))
        bar = self.titleBarWidget()
        if bar is not None:
            bar.set_title(title)

    def in_layout(self) -> bool:
        """Laid out on a workspace (else on All Workspaces)."""
        return isinstance(self.parentWidget(), QSplitter)

    def close_in_area(self) -> None:
        """Close all panels in this area (ui.dock_titlebar): the
        conversation goes back into the Agent dock - reopened with it from
        View > Panels - instead of being deleted."""
        self.park_requested.emit(self)

    def closeEvent(self, event) -> None:  # noqa: N802 - Qt override
        # Not ExtensionDock's: [x] does not park a conversation, it ends it
        # - after the same question as closing its tab.
        if self.closing:
            event.accept()
            return
        event.ignore()
        self.close_requested.emit(self)

    def event(self, event) -> bool:  # noqa: D401 - Qt override
        if event.type() == QEvent.Type.ParentChange and self.parentWidget() is not None:
            self.place_changed.emit(self)
        return super().event(event)


class DetachTabBar(QTabBar):
    """A movable tab bar whose tab, dragged well away from the bar,
    detaches: ``detach_requested(index)``. A drag along the bar moves the
    tab as before."""

    detach_requested = pyqtSignal(int)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._pressed: QPoint | None = None

    def mousePressEvent(self, event: QMouseEvent) -> None:  # noqa: N802 - Qt override
        if event.button() == Qt.MouseButton.LeftButton and self.tabAt(event.pos()) >= 0:
            self._pressed = event.pos()
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event: QMouseEvent) -> None:  # noqa: N802 - Qt override
        if self._pressed is not None and event.buttons() & Qt.MouseButton.LeftButton:
            margin = DETACH_DISTANCE
            if not self.rect().adjusted(-margin, -margin, margin, margin).contains(event.pos()):
                self._pressed = None
                # Qt's own tab move ends first (the tab settles in its slot),
                # then the tab - the current one, which the press selected -
                # leaves the bar.
                release = QMouseEvent(
                    QEvent.Type.MouseButtonRelease, event.position(), event.globalPosition(),
                    Qt.MouseButton.LeftButton, Qt.MouseButton.NoButton, event.modifiers())
                super().mouseReleaseEvent(release)
                index = self.currentIndex()
                if index >= 0:
                    self.detach_requested.emit(index)
                event.accept()
                return
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event: QMouseEvent) -> None:  # noqa: N802 - Qt override
        self._pressed = None
        super().mouseReleaseEvent(event)


__all__ = [
    "AGENT_PANEL_EXT_ID",
    "AGENT_PANEL_PREFIX",
    "DETACH_DISTANCE",
    "AgentPanel",
    "AgentPanelTitleBar",
    "DetachTabBar",
    "alive",
    "panel_title",
    "weak_call",
]
