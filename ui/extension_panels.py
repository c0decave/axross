"""Extension panels on workspaces: the panel an extension adds with
``api.add_dock`` belongs either to all workspaces - the main window's dock
area, as it always did and still does by default - or to one workspace,
where it is laid out like a pane.

* **Moving** a panel: its title bar's Send to Workspace button (or a right
  click on the title bar) offers every workspace (numbered as the tabs
  stand), New Workspace and All Workspaces; a workspace's Add Extension
  Panel menu (Workspace menu, tab menu) brings any loaded panel there.
* **On a workspace** the panel sits in the workspace's splitters: it shows
  with its workspace and hides with it, goes along with a detached one,
  is dragged by its title bar onto another pane, takes a dragged pane on
  itself, is resized by the splitter handles and evened out by Equalize
  Pane Sizes. It does not float there (no float button, no double-click
  float): a pane does not either.
* **Closing** it with [x] takes it out of the workspace like a pane - the
  workspace closes when nothing else is in it. The extension keeps running
  and the panel keeps its state; showing it again from the Extensions menu
  or its toolbar button puts it back at its place.
* **Closing the workspace** (or replacing its layout with a preset) parks
  its panels on All Workspaces, hidden, with their state.
* **Switching the extension off** takes its panels out of their workspaces
  and remembers where they were; switched on again (Reload too) they come
  back there. A workspace that held only such a panel stays while its
  extension is off. The places of a switched-off extension's panels are
  saved with the session too.
* **Size**: a panel's content sits in a scroll area (ui.dock_frame), so
  the panel takes the space the dock area or the workspace gives it and its
  content scrolls when that is less than it needs - its content's smallest
  size no longer adds up with the other panels' into a window larger than
  the screen. ``widget()`` and ``setWidget()`` still give and take the
  content itself.

Session: a panel on a workspace is a ``{"type": "extension", "panel":
<the dock's object name>}`` entry of that workspace's layout. The object
name (``extension-dock-<ext id>-<n>``, n counting the extension's panels)
is what finds the panel again after a restart.

The Agent's detached conversations (ui.agent_panels) are panels of this
kind too - ExtensionDock subclasses the window lists in ``_own_panels`` -
with three differences: their [x] closes the conversation (it asks like
closing an Agent tab), a closed workspace leaves them on screen on All
Workspaces (``parks_visible``), and a session entry naming one that is
gone keeps no place (only an extension that is switched off comes back).
"""

from __future__ import annotations

import logging
import weakref
from dataclasses import dataclass

from PyQt6 import sip
from PyQt6.QtCore import QPoint, QSize, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QMouseEvent
from PyQt6.QtWidgets import QDockWidget, QMenu, QSplitter, QToolButton, QWidget

from core.i18n import tr
from ui.dock_frame import PanelFrame
from ui.dock_titlebar import DockTitleBar
from ui.pane_drag import PANE_DRAG_THRESHOLD, PaneDropZones, start_pane_drag

log = logging.getLogger(__name__)

#: The session node type of an extension panel.
PANEL_NODE = "extension"
#: The object name of every panel ``api.add_dock`` makes starts so.
EXTENSION_DOCK_PREFIX = "extension-dock-"
#: Longest panel name a session entry may carry (``extension-dock-`` +
#: ``user:`` + a module name + a counter: well below).
MAX_PANEL_NAME = 256
#: Smallest share of its splitter a returning panel is given, in pixels.
_MIN_RETURN_PX = 80


def panel_node_problem(node: dict) -> str:
    """Why a session's extension panel entry is unusable ("" when it is fine)."""
    name = node.get("panel")
    if not isinstance(name, str) or not name or len(name) > MAX_PANEL_NAME:
        return ("An extension panel entry has no usable panel name "
                f"(1 to {MAX_PANEL_NAME} characters).")
    return ""


class ExtensionDock(QDockWidget):
    """The dock ``api.add_dock`` makes. In the dock area it is a plain
    panel; on a workspace (*pane mode*) it is a pane: it takes a dragged
    pane (``pane_drop_requested``, as the file and terminal panes), does
    not float, and its [x] takes it out of the workspace. Its content sits
    in a :class:`PanelFrame`; ``widget()`` is the content."""

    #: (dragged pane's id, this panel, zone) - as FilePaneWidget's.
    pane_drop_requested = pyqtSignal(str, object, str)
    #: A closed workspace leaves the panel on screen on All Workspaces
    #: (True) or hidden, for its menu entry to show it again (False).
    parks_visible = False

    def __init__(self, title: str, owner: QWidget, ext_id: str) -> None:
        super().__init__(title, owner)
        self.ext_id = ext_id
        self._owner = weakref.ref(owner)
        self._pane_mode = False
        self._pane_drop = PaneDropZones(self)
        self.setAcceptDrops(True)
        self._frame = PanelFrame(self)
        super().setWidget(self._frame)

    # -- the content, in its scroll area ------------------------------------------------------

    def widget(self) -> QWidget | None:
        """The panel's content (not the scroll area around it)."""
        frame = self._frame
        return None if sip.isdeleted(frame) else frame.content()

    def setWidget(self, widget: QWidget | None) -> None:  # noqa: N802 - Qt API
        """*widget* becomes the content; one it replaces stays alive, a
        hidden child of the panel, as QDockWidget.setWidget leaves it."""
        frame = self._frame
        if sip.isdeleted(frame) or widget is frame.content():
            return
        old = frame.take_content()
        if old is not None:
            old.setParent(self)
            old.hide()
        if widget is not None:
            frame.set_content(widget)

    def takeWidget(self) -> QWidget | None:  # noqa: N802 - Qt naming
        """Out of the panel: the content without a parent. Whoever moves
        the content elsewhere takes it first (the Agent dock attaching a
        conversation)."""
        frame = self._frame
        return None if sip.isdeleted(frame) else frame.take_content()

    def owner(self):
        """The main window this panel belongs to (None once it is gone)."""
        owner = self._owner()
        return None if owner is None or sip.isdeleted(owner) else owner

    @property
    def pane_mode(self) -> bool:
        return self._pane_mode

    def set_pane_mode(self, on: bool) -> None:
        on = bool(on)
        self._pane_mode = on
        features = self.features()
        if on:
            features &= ~QDockWidget.DockWidgetFeature.DockWidgetFloatable
            features &= ~QDockWidget.DockWidgetFeature.DockWidgetMovable
        else:
            features |= (QDockWidget.DockWidgetFeature.DockWidgetFloatable
                         | QDockWidget.DockWidgetFeature.DockWidgetMovable)
        self.setFeatures(features)
        bar = self.titleBarWidget()
        if hasattr(bar, "set_pane_mode"):
            bar.set_pane_mode(on)

    # -- a dragged pane dropped here (pane mode only) ---------------------------------------

    def dragEnterEvent(self, event) -> None:  # noqa: N802 - Qt override
        if not (self._pane_mode and self._pane_drop.enter(event)):
            event.ignore()

    def dragMoveEvent(self, event) -> None:  # noqa: N802 - Qt override
        if not (self._pane_mode and self._pane_drop.move(event)):
            event.ignore()

    def dragLeaveEvent(self, event) -> None:  # noqa: N802 - Qt override
        self._pane_drop.leave()
        super().dragLeaveEvent(event)

    def dropEvent(self, event) -> None:  # noqa: N802 - Qt override
        pane_drop = self._pane_drop.drop(event) if self._pane_mode else None
        if pane_drop is None:
            event.ignore()
            return
        source_id, zone = pane_drop
        self.pane_drop_requested.emit(source_id, self, zone)

    # -- [x] on a workspace -------------------------------------------------------------------

    def closeEvent(self, event) -> None:  # noqa: N802 - Qt override
        super().closeEvent(event)
        if not (event.isAccepted() and self._pane_mode):
            return
        # Once Qt has hidden it: the window takes it out of the workspace.
        ref = weakref.ref(self)

        def take_out() -> None:
            dock = ref()
            if dock is None or sip.isdeleted(dock) or not dock.isHidden() or not dock.pane_mode:
                return  # shown again meanwhile, or gone
            owner = dock.owner()
            if owner is not None and hasattr(owner, "close_extension_panel"):
                owner.close_extension_panel(dock)

        QTimer.singleShot(0, take_out)


class ExtensionPanelTitleBar(DockTitleBar):
    """The title bar of an extension panel: the built-in panels' one plus a
    Send to Workspace button (and the same menu on a right click). On a
    workspace the float and close-all buttons go - a pane has neither -
    and a drag on the bar drags the panel like a pane's header."""

    def __init__(self, title: str, dock: ExtensionDock, *, icon_name: str = "extensions",
                 reopen_hint: str = "the Extensions menu") -> None:
        super().__init__(title, icon_name, dock, reopen_hint=reopen_hint)
        self._pane_mode = False
        self._pane_drag_start: QPoint | None = None
        self.move_menu = QMenu(tr("Send to Workspace"), self)
        self.move_menu.aboutToShow.connect(self._fill_move_menu)
        self.move_button = QToolButton(self)
        self.move_button.setText("⇄")  # ⇄, as a terminal pane's button
        self.move_button.setToolTip(tr("Send to Workspace"))
        self.move_button.setAccessibleName(tr("Send to Workspace"))
        self.move_button.setAutoRaise(True)
        self.move_button.setFixedSize(QSize(22, 22))
        self.move_button.clicked.connect(self._pop_move_menu)
        layout = self.layout()
        layout.insertWidget(layout.indexOf(self._float_btn), self.move_button)

    @property
    def pane_mode(self) -> bool:
        return self._pane_mode

    def set_pane_mode(self, on: bool) -> None:
        self._pane_mode = bool(on)
        self._float_btn.setVisible(not on)
        self._close_all_btn.setVisible(not on)
        self.setCursor(Qt.CursorShape.OpenHandCursor if on else Qt.CursorShape.ArrowCursor)
        self.setToolTip(tr("Drag to move the panel") if on else "")

    # -- the menu ----------------------------------------------------------------------------

    def _fill_move_menu(self) -> None:
        self.move_menu.clear()
        owner = self._dock.owner() if isinstance(self._dock, ExtensionDock) else None
        filler = getattr(owner, "fill_move_menu_for", None)
        if filler is None:
            self.move_menu.addAction(tr("No workspaces here")).setEnabled(False)
            return
        filler(self._dock, self.move_menu)

    def _pop_move_menu(self, _checked: bool = False) -> None:
        self.move_menu.exec(self.move_button.mapToGlobal(QPoint(0, self.move_button.height())))

    def context_menu(self) -> QMenu:
        """The right-click menu of the bar (a new one each time)."""
        menu = QMenu(self)
        menu.addMenu(self.move_menu)
        return menu

    def show_context_menu(self, pos: QPoint) -> None:
        menu = self.context_menu()
        menu.exec(self.mapToGlobal(pos))
        menu.deleteLater()

    def contextMenuEvent(self, event) -> None:  # noqa: N802 - Qt override
        self.show_context_menu(event.pos())
        event.accept()

    # -- dragging the panel like a pane (on a workspace) --------------------------------------

    def mousePressEvent(self, event: QMouseEvent) -> None:  # noqa: N802 - Qt override
        if self._pane_mode and event.button() == Qt.MouseButton.LeftButton:
            self._pane_drag_start = event.pos()
            event.accept()
            return
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event: QMouseEvent) -> None:  # noqa: N802 - Qt override
        start = self._pane_drag_start
        if self._pane_mode and start is not None:
            if (event.pos() - start).manhattanLength() >= PANE_DRAG_THRESHOLD:
                self._pane_drag_start = None
                start_pane_drag(self, self._dock)
            event.accept()
            return
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event: QMouseEvent) -> None:  # noqa: N802 - Qt override
        if self._pane_drag_start is not None:
            self._pane_drag_start = None
            event.accept()
            return
        super().mouseReleaseEvent(event)


@dataclass
class PanelHome:
    """Where a panel that left a workspace belongs: the splitter that held
    it and its index there, the neighbour it sat before or after (for when
    that splitter went with it), its size, and whether the session keeps
    it (the extension was switched off) or only this run (closed with [x])."""

    name: str
    ext_id: str
    ws: object
    holder: QSplitter | None
    index: int
    orientation: Qt.Orientation
    neighbour: QWidget | None
    before: bool
    size: int
    keep: bool


def _alive(widget) -> bool:
    return widget is not None and not sip.isdeleted(widget)


class ExtensionPanelsMixin:
    """The extension panel half of MainWindow (with WorkspaceMixin)."""

    # -- lookup ---------------------------------------------------------------------------------

    @property
    def _panel_homes(self) -> dict[str, PanelHome]:
        homes = self.__dict__.get("_ax_panel_homes")
        if homes is None:
            homes = self.__dict__["_ax_panel_homes"] = {}
        return homes

    def extension_panels(self) -> list[ExtensionDock]:
        """Every panel of the loaded extensions, in load order, then the
        window's own panels of this kind (``_own_panels``: the Agent's
        detached conversations)."""
        host = getattr(self, "extension_host", None)
        docks = [] if host is None else [
            d for ext_id in host.loaded_ids() for d in host.docks(ext_id)
            if isinstance(d, ExtensionDock) and _alive(d)]
        return docks + [d for d in self._own_panels() if isinstance(d, ExtensionDock)
                        and _alive(d) and d not in docks]

    def _own_panels(self) -> list:
        """Panels of the window itself laid out like extension panels."""
        return []

    def _extension_panel_named(self, name: str) -> ExtensionDock | None:
        return next((d for d in self.extension_panels() if d.objectName() == name), None)

    def _layout_panels(self) -> list[ExtensionDock]:
        """The panels laid out on a workspace."""
        return [d for d in self.extension_panels() if self._in_layout(d)]

    @staticmethod
    def _in_layout(dock) -> bool:
        return _alive(dock) and isinstance(dock.parentWidget(), QSplitter)

    def extension_panel_workspace(self, dock):
        """The workspace *dock* is laid out on; None for All Workspaces."""
        return self.workspace_of(dock) if self._in_layout(dock) else None

    def _keeps_panel_home(self, ws) -> bool:
        """*ws* remembers the panel of a switched-off extension."""
        return any(h.ws is ws and h.keep for h in self._panel_homes.values())

    # -- moving -------------------------------------------------------------------------------

    def move_extension_panel(self, dock, ws) -> bool:
        """Lay *dock* out on workspace *ws* (at the end of its root, shown:
        that workspace comes to the front), or with *ws* None put it back
        on All Workspaces (the dock area). False for anything that is no
        panel of this window, a workspace it does not hold, or where the
        panel already is."""
        if not isinstance(dock, ExtensionDock) or not _alive(dock) \
                or dock not in self.extension_panels():
            return False
        if ws is not None and ws not in self._workspaces:
            return False
        here = self.extension_panel_workspace(dock)
        if ws is here:
            return False
        self._panel_homes.pop(dock.objectName(), None)
        self._lift_panel(dock)
        if ws is None:
            self._dock_panel(dock, visible=True)
            dock.raise_()
        else:
            dock.set_pane_mode(True)
            ws.root.addWidget(dock)
            dock.show()
            self._equalize_later(ws.root)
        self._prune_empty_workspaces()
        if ws is not None:
            self._show_workspace(ws)
        log.info("Extension panel %s moved to %s", dock.objectName(),
                 ws.name if ws is not None else "all workspaces")
        return True

    def move_extension_panel_to_new_workspace(self, dock):
        """A new, empty workspace with *dock* in it; None when none can be made."""
        if not isinstance(dock, ExtensionDock) or dock not in self.extension_panels():
            return None
        ws = self.new_workspace(with_pane=False, activate=False)
        if ws is not None:
            self.move_extension_panel(dock, ws)
        return ws

    def _lift_panel(self, dock: ExtensionDock) -> None:
        """Out of wherever it is: a workspace's splitters or the dock area."""
        if self._in_layout(dock):
            self._take_out_of_layout(dock)
        else:
            if dock.isFloating():
                dock.setFloating(False)
            self.removeDockWidget(dock)

    def _dock_panel(self, dock: ExtensionDock, *, visible: bool) -> None:
        """Into the dock area (All Workspaces), as add_dock put it."""
        dock.set_pane_mode(False)
        self.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, dock)
        dock.setVisible(visible)

    def _equalize_later(self, root: QSplitter) -> None:
        # Once the layout has its size; a hidden root has none yet.
        QTimer.singleShot(
            0, lambda r=root: None if sip.isdeleted(r) else self._equalize_splitter(r))

    def reveal_extension_panel(self, dock) -> None:
        """The Extensions menu entry or the toolbar button showed *dock*: on
        a workspace, that workspace comes to the front; closed from one,
        it goes back there."""
        if not isinstance(dock, ExtensionDock) or not _alive(dock):
            return
        if self._in_layout(dock):
            self._show_workspace(self.workspace_of(dock))
            return
        home = self._panel_homes.pop(dock.objectName(), None)
        if home is not None and home.ws in self._workspaces:
            self._lift_panel(dock)
            self._return_home(dock, home)
            self._show_workspace(home.ws)

    # -- leaving and returning ----------------------------------------------------------------

    def _remember_home(self, dock: ExtensionDock, *, keep: bool) -> PanelHome | None:
        holder = dock.parentWidget()
        ws = self.workspace_of(dock)
        if not isinstance(holder, QSplitter) or ws is None:
            return None
        index = holder.indexOf(dock)
        sizes = holder.sizes()
        if index + 1 < holder.count():
            neighbour, before = holder.widget(index + 1), True
        elif index > 0:
            neighbour, before = holder.widget(index - 1), False
        else:
            neighbour, before = None, True
        home = PanelHome(
            name=dock.objectName(), ext_id=dock.ext_id, ws=ws, holder=holder, index=index,
            orientation=holder.orientation(), neighbour=neighbour, before=before,
            size=sizes[index] if index < len(sizes) else 0, keep=keep)
        self._panel_homes[home.name] = home
        return home

    def _return_home(self, dock: ExtensionDock, home: PanelHome) -> None:
        """Lay *dock* out where *home* says: in the splitter that held it,
        else beside its old neighbour, else at the end of the workspace."""
        dock.set_pane_mode(True)
        ws = home.ws
        holder = home.holder
        neighbour = home.neighbour
        if _alive(holder) and self.workspace_of(holder) is ws:
            holder.insertWidget(min(home.index, holder.count()), dock)
        elif _alive(neighbour) and self.workspace_of(neighbour) is ws \
                and isinstance(neighbour.parentWidget(), QSplitter):
            holder = self._put_beside(dock, neighbour, home.orientation, home.before)
        else:
            holder = ws.root
            holder.addWidget(dock)
        dock.show()
        if home.size > 0:
            size = home.size
            QTimer.singleShot(0, lambda h=holder, d=dock, s=size: self._give_size(h, d, s))
        else:
            self._equalize_later(ws.root)

    def _put_beside(self, widget, neighbour, orientation, before: bool) -> QSplitter:
        """*widget* before or after *neighbour* along *orientation*: in its
        splitter when that runs the same way, else in a new one in its place."""
        parent = neighbour.parentWidget()
        index = parent.indexOf(neighbour)
        if parent.orientation() == orientation:
            parent.insertWidget(index if before else index + 1, widget)
            return parent
        split = QSplitter(orientation)
        parent.replaceWidget(index, split)
        if before:
            split.addWidget(widget)
            split.addWidget(neighbour)
        else:
            split.addWidget(neighbour)
            split.addWidget(widget)
        split.show()
        neighbour.show()
        return split

    @staticmethod
    def _give_size(holder: QSplitter, widget, size: int) -> None:
        """Size *widget* in *holder* as it was; the others share the rest."""
        if not (_alive(holder) and _alive(widget)) or holder.indexOf(widget) < 0:
            return
        sizes = holder.sizes()
        total = sum(sizes)
        count = len(sizes)
        if count < 2 or total <= 0:
            return
        index = holder.indexOf(widget)
        size = max(_MIN_RETURN_PX, min(size, total - _MIN_RETURN_PX * (count - 1)))
        rest = total - sizes[index]
        others = [s for i, s in enumerate(sizes) if i != index]
        if rest <= 0:
            share = [(total - size) // (count - 1)] * (count - 1)
        else:
            share = [s * (total - size) // rest for s in others]
        share.insert(index, size)
        holder.setSizes(share)

    # -- the window's and the host's hooks ----------------------------------------------------

    def close_extension_panel(self, dock) -> None:
        """[x] on a workspace panel (it is hidden already): out of the
        workspace like a pane, parked on All Workspaces; showing it again
        puts it back (reveal_extension_panel)."""
        if not self._in_layout(dock):
            return
        self._remember_home(dock, keep=False)
        self._take_out_of_layout(dock)
        self._dock_panel(dock, visible=False)
        self._prune_empty_workspaces()

    def extension_panel_removed(self, dock) -> None:
        """The extension is switched off (unloaded, reloaded): a panel on a
        workspace leaves it and its place is kept for when it comes back."""
        if not self._in_layout(dock):
            return
        self._remember_home(dock, keep=True)
        self._take_out_of_layout(dock)

    def extension_panel_added(self, dock) -> None:
        """A panel was just made: back on the workspace it left, if any."""
        if not isinstance(dock, ExtensionDock):
            return
        home = self._panel_homes.pop(dock.objectName(), None)
        if home is None or home.ws not in self._workspaces:
            return
        self._lift_panel(dock)
        self._return_home(dock, home)

    def _park_extension_panels(self, root: QSplitter) -> None:
        """*root* goes (its workspace closes, a preset replaces it): its
        panels go back to All Workspaces, hidden, with their state."""
        if not _alive(root):
            return
        for dock in root.findChildren(ExtensionDock):
            if _alive(dock) and dock.pane_mode:
                dock.setParent(None)
                self._dock_panel(dock, visible=dock.parks_visible)

    def _forget_panel_homes(self, ws) -> None:
        for name in [n for n, h in self._panel_homes.items() if h.ws is ws]:
            del self._panel_homes[name]

    # -- menus ----------------------------------------------------------------------------

    def _fill_panel_move_menu(self, dock: ExtensionDock, menu: QMenu) -> None:
        """Every workspace, numbered (the one holding *dock* ticked), New
        Workspace and All Workspaces (ticked while it is in the dock area)."""
        here = self.extension_panel_workspace(dock)

        def send(ws, d=dock):
            if ws is None:
                self.move_extension_panel_to_new_workspace(d)
            else:
                self._move_or_show_panel(d, ws)

        self.fill_workspace_targets(menu, send, here=here, tick_here=True)
        everywhere = menu.addAction(tr("All Workspaces"))
        everywhere.setCheckable(True)
        everywhere.setChecked(here is None)
        everywhere.triggered.connect(lambda _c=False, d=dock: self._move_or_show_panel(d, None))

    def _move_or_show_panel(self, dock, ws) -> None:
        if not self.move_extension_panel(dock, ws):
            if ws is not None and self.extension_panel_workspace(dock) is ws:
                self._show_workspace(ws)
            elif ws is None and _alive(dock):
                dock.show()

    def fill_add_extension_panel_menu(self, menu: QMenu, ws) -> None:
        """Add Extension Panel ▸ for workspace *ws*: every loaded panel (the
        ones already there ticked)."""
        menu.clear()
        panels = self.extension_panels()
        if not panels:
            menu.addAction(tr("No extension panel is switched on")).setEnabled(False)
            return
        for dock in panels:
            action = menu.addAction(dock.windowTitle().replace("&", "&&"))
            action.setCheckable(True)
            action.setChecked(self.extension_panel_workspace(dock) is ws)
            action.triggered.connect(
                lambda _c=False, d=dock, w=ws: self._move_or_show_panel(d, w))

    def _add_extension_panel_menu(self, parent: QMenu, ws) -> QMenu:
        """Add Extension Panel ▸ for *ws* in a menu built once (a tab's)."""
        menu = parent.addMenu(tr("Add Extension Panel"))
        menu.aboutToShow.connect(lambda m=menu, w=ws: self.fill_add_extension_panel_menu(m, w))
        self.fill_add_extension_panel_menu(menu, ws)
        return menu

    def _workspace_panel_menu(self) -> QMenu:
        """Add Extension Panel ▸ of the Workspace menu, for the workspace
        on screen; made once (the Workspace menu is rebuilt on each open)."""
        menu = self.__dict__.get("_ax_workspace_panel_menu")
        if menu is None:
            menu = QMenu(tr("Add Extension Panel"), self)
            menu.aboutToShow.connect(
                lambda m=menu: self.fill_add_extension_panel_menu(m, self._current_ws))
            self.__dict__["_ax_workspace_panel_menu"] = menu
        self.fill_add_extension_panel_menu(menu, self._current_ws)
        return menu

    # -- session --------------------------------------------------------------------------

    @staticmethod
    def _serialize_extension_panel(dock: ExtensionDock) -> dict:
        return {"type": PANEL_NODE, "panel": dock.objectName(), "ext_id": dock.ext_id}

    def _home_anchor(self, home: PanelHome):
        """Where the session writes a kept home: ("holder", splitter),
        ("neighbour", the neighbour) or ("root", the workspace root)."""
        if _alive(home.holder) and self.workspace_of(home.holder) is home.ws:
            return "holder", home.holder
        nb = home.neighbour
        if _alive(nb) and self.workspace_of(nb) is home.ws \
                and isinstance(nb.parentWidget(), QSplitter):
            return "neighbour", nb
        return "root", home.ws.root

    def _kept_homes_at(self, splitter: QSplitter) -> tuple[list, dict, list]:
        """The kept homes the session writes in *splitter*: (by index in it,
        by neighbour widget id, at its end)."""
        at_index: list[PanelHome] = []
        by_neighbour: dict[int, list[PanelHome]] = {}
        at_end: list[PanelHome] = []
        for home in self._panel_homes.values():
            if not home.keep or home.ws not in self._workspaces:
                continue
            kind, anchor = self._home_anchor(home)
            if kind == "holder" and anchor is splitter:
                at_index.append(home)
            elif kind == "neighbour" and anchor.parentWidget() is splitter:
                by_neighbour.setdefault(id(anchor), []).append(home)
            elif kind == "root" and anchor is splitter:
                at_end.append(home)
        return at_index, by_neighbour, at_end

    @staticmethod
    def _home_node(home: PanelHome) -> dict:
        return {"type": PANEL_NODE, "panel": home.name, "ext_id": home.ext_id}

    def _place_kept_homes(self, splitter: QSplitter, items: list) -> list:
        """*items*: (widget index, widget, entry, size) of *splitter*'s
        written children; the kept homes of switched-off extensions'
        panels go in between, at their places. (entry, size) pairs."""
        at_index, by_neighbour, at_end = self._kept_homes_at(splitter)
        if not (at_index or by_neighbour or at_end):
            return [(entry, size) for _i, _w, entry, size in items]
        keyed = []
        for index, widget, entry, size in items:
            homes = by_neighbour.get(id(widget), ())
            wrap = [h for h in homes if h.orientation != splitter.orientation()]
            if wrap:
                home = wrap[0]
                pair = [(self._home_node(home), home.size or size), (entry, size)]
                if not home.before:
                    pair.reverse()
                entry = {
                    "type": "splitter",
                    "orientation": "horizontal"
                    if home.orientation == Qt.Orientation.Horizontal else "vertical",
                    "sizes": [s for _e, s in pair],
                    "children": [e for e, _s in pair],
                }
            keyed.append(((index, 1), entry, size))
            for home in homes:
                if home.orientation == splitter.orientation():
                    keyed.append(((index, 0 if home.before else 2), self._home_node(home),
                                  home.size or size))
        for home in at_index:
            keyed.append(((home.index, 0), self._home_node(home), home.size))
        for home in at_end:
            keyed.append(((1 << 30, 0), self._home_node(home), home.size))
        keyed.sort(key=lambda item: item[0])
        return [(entry, size) for _k, entry, size in keyed]

    def _restore_extension_panel(self, splitter: QSplitter, data: dict, size) -> bool:
        """A session's panel entry: the loaded panel laid out here (True),
        or for a panel whose extension is off, its place kept (False: no
        widget was added)."""
        name = data.get("panel")
        if not isinstance(name, str):
            return False
        dock = self._extension_panel_named(name)
        if dock is not None:
            if self._in_layout(dock):
                return False  # named twice: the first entry has it
            self._panel_homes.pop(name, None)
            self._lift_panel(dock)
            dock.set_pane_mode(True)
            splitter.addWidget(dock)
            dock.show()
            return True
        ws = self.workspace_of(splitter)
        if ws is None or name in self._panel_homes or not name.startswith(EXTENSION_DOCK_PREFIX):
            return False  # only a switched-off extension's panel comes back later
        ext_id = data.get("ext_id")
        self._panel_homes[name] = PanelHome(
            name=name, ext_id=ext_id if isinstance(ext_id, str) else "", ws=ws, holder=splitter,
            index=splitter.count(), orientation=splitter.orientation(), neighbour=None,
            before=True, size=size if isinstance(size, int) and size > 0 else 0, keep=True)
        return False

    def _settle_restored_homes(self, splitter: QSplitter) -> None:
        """After *splitter*'s entries are restored: each kept home in it
        learns its neighbour, for when the splitter goes."""
        for home in self._panel_homes.values():
            if home.holder is not splitter or home.neighbour is not None:
                continue
            if home.index < splitter.count():
                home.neighbour, home.before = splitter.widget(home.index), True
            elif splitter.count():
                home.neighbour, home.before = splitter.widget(splitter.count() - 1), False


__all__ = [
    "EXTENSION_DOCK_PREFIX",
    "MAX_PANEL_NAME",
    "PANEL_NODE",
    "ExtensionDock",
    "ExtensionPanelTitleBar",
    "ExtensionPanelsMixin",
    "PanelHome",
    "panel_node_problem",
]
