"""Docks shown only on one workspace.

A dock - the Agent, Log, Transfers, Terminal, Console, Scripts,
Bookmarks, Analysis docks, and every extension panel in the dock area
(the Media Player, Bluetooth ...) - is on all workspaces until it is
bound to one: from the pin button of its title bar, or a right click on
it, *Show Only on Workspace ▸*. A bound dock keeps its place in the dock
area but shows only while its workspace is the one in the main window
(or, for a workspace detached to a window of its own, while that one is
current); on the other workspaces it is out of the way. Opening it
there (View > Panels, its toolbar button, a tab of its dock area) brings
its workspace to the front. Closing the workspace frees the dock again.

This is not *Send to Workspace* (ui.extension_panels), which lays a panel
out inside a workspace like a pane; a bound dock stays a dock.

Session: ``window["dock_workspaces"]`` maps a dock's object name to
``{"ws": <index in the workspaces list>, "open": <shown on its
workspace>}``, read after the workspaces and the dock state.
"""

from __future__ import annotations

import logging
import weakref

from PyQt6 import sip
from PyQt6.QtCore import QEvent, QObject, QTimer
from PyQt6.QtWidgets import QDockWidget, QMenu, QSplitter

from core.i18n import tr

log = logging.getLogger(__name__)

SESSION_KEY = "dock_workspaces"


def _alive(obj) -> bool:
    return obj is not None and not sip.isdeleted(obj)


class _ShowWatcher(QObject):
    """Tells the window when a bound dock is shown. visibilityChanged is no
    help here: for a dock tabified with others Qt reports False while it
    is being shown."""

    def __init__(self, owner, dock: QDockWidget) -> None:
        super().__init__(dock)
        self._owner = weakref.ref(owner)
        self._dock = weakref.ref(dock)

    def eventFilter(self, obj, event) -> bool:  # noqa: N802 - Qt override
        if event.type() == QEvent.Type.Show:
            owner, dock = self._owner(), self._dock()
            if owner is not None and dock is not None and _alive(owner):
                owner._dock_shown(dock)
        return False


class DockBindingMixin:
    """For MainWindow (with WorkspaceMixin): bind docks to workspaces."""

    # -- state (made on first use: the mixin has no __init__) -----------------------------

    @property
    def _dock_bindings(self) -> dict:
        """dock object name -> Workspace."""
        return self.__dict__.setdefault("_ax_dock_bindings", {})

    @property
    def _dock_wanted(self) -> dict:
        """dock object name -> the user had it open on its workspace."""
        return self.__dict__.setdefault("_ax_dock_wanted", {})

    @property
    def _dock_hidden_by_binding(self) -> set:
        """dock object names hidden because their workspace is not on
        screen (their open/closed state is in _dock_wanted)."""
        return self.__dict__.setdefault("_ax_dock_hidden", set())

    def _dock_hooked(self) -> dict:
        """dock object name -> the dock (weakly) whose show is watched. By
        object, not by name: an extension switched off and on again makes
        a new dock under the old name, which needs a watcher of its own."""
        return self.__dict__.setdefault("_ax_dock_hooked", {})

    # -- reading ------------------------------------------------------------------------------

    def bindable_docks(self) -> list[QDockWidget]:
        """The docks of the window's dock area (not panels laid out on a
        workspace) that have a name to be remembered by."""
        return [d for d in self.findChildren(QDockWidget)
                if _alive(d) and d.objectName() and d.parentWidget() is self
                and not isinstance(d.parentWidget(), QSplitter)]

    def _dock_named(self, name: str) -> QDockWidget | None:
        return next((d for d in self.bindable_docks() if d.objectName() == name), None)

    def dock_workspace(self, dock) -> object | None:
        """The workspace *dock* is shown only on, or None (all)."""
        if not _alive(dock):
            return None
        ws = self._dock_bindings.get(dock.objectName())
        return ws if ws in self._workspaces else None

    def _shown_workspace(self, ws) -> bool:
        """Whether *ws* is the one a bound dock shows for now."""
        if ws is None:
            return True
        if ws.window is not None:  # detached: while it is the current one
            return ws is self._current_ws
        return ws is self._tab_workspace()

    # -- binding ------------------------------------------------------------------------------

    def bind_dock_to_workspace(self, dock, ws) -> bool:
        """Show *dock* only on workspace *ws*; None shows it on all again.
        False for what is no dock of this window's dock area or a
        workspace it does not hold."""
        if not _alive(dock) or dock not in self.bindable_docks():
            return False
        if ws is not None and ws not in self._workspaces:
            return False
        name = dock.objectName()
        old = self._dock_bindings.get(name)
        if old is ws:
            return False
        if ws is None:
            self._release(name, dock)
        else:
            self._dock_bindings[name] = ws
            self._hook_dock(dock)
        self.apply_dock_bindings()
        self._refresh_pin(dock)
        log.info("Dock %s shown on %s", name, ws.name if ws is not None else "all workspaces")
        return True

    @staticmethod
    def _refresh_pin(dock) -> None:
        bar = dock.titleBarWidget() if _alive(dock) else None
        if bar is not None and hasattr(bar, "update_pin"):
            bar.update_pin()

    def _hook_dock(self, dock: QDockWidget) -> bool:
        """Opening a bound dock elsewhere brings its workspace (once per
        dock). True when *dock* was not hooked before."""
        name = dock.objectName()
        ref = self._dock_hooked().get(name)
        if ref is not None and ref() is dock:
            return False
        self._dock_hooked()[name] = weakref.ref(dock)
        dock.installEventFilter(_ShowWatcher(self, dock))
        return True

    def _dock_shown(self, dock: QDockWidget) -> None:
        """A bound dock was shown (View > Panels, its toolbar button, code
        that wants it seen) on another workspace: its own comes to the front
        - after the show, outside Qt's event handling."""
        if self.__dict__.get("_ax_applying_bindings") or not _alive(dock):
            return
        ws = self.dock_workspace(dock)
        if ws is None or self._shown_workspace(ws):
            return
        self._dock_wanted[dock.objectName()] = True
        self._dock_hidden_by_binding.discard(dock.objectName())
        ref = weakref.ref(dock)

        def bring() -> None:
            d = ref()
            if d is None or not _alive(d) or not _alive(self) or ws not in self._workspaces:
                return
            self._show_workspace(ws)
            self.apply_dock_bindings()

        QTimer.singleShot(0, bring)

    def _show_dock_quietly(self, dock: QDockWidget) -> None:
        self.__dict__["_ax_applying_bindings"] = True
        try:
            dock.show()
        finally:
            self.__dict__["_ax_applying_bindings"] = False

    def _release(self, name: str, dock) -> None:
        """*name* is on all workspaces again: shown when it was open."""
        self._dock_bindings.pop(name, None)
        hidden = name in self._dock_hidden_by_binding
        self._dock_hidden_by_binding.discard(name)
        wanted = self._dock_wanted.pop(name, False)
        if hidden and wanted and dock is not None:
            self._show_dock_quietly(dock)
        if dock is not None:
            self._refresh_pin(dock)

    def apply_dock_bindings(self) -> None:
        """Each bound dock shown or hidden for the workspace on screen. A
        dock leaving the screen remembers whether the user had it open;
        coming back it is shown again only then."""
        bindings = self._dock_bindings
        if not bindings:
            return
        hidden = self._dock_hidden_by_binding
        self.__dict__["_ax_applying_bindings"] = True
        try:
            for name, ws in list(bindings.items()):
                dock = self._dock_named(name)
                if dock is None:
                    continue  # an extension's panel, switched off: the binding waits
                if ws not in self._workspaces:
                    self._release(name, dock)
                    continue
                if self._shown_workspace(ws):
                    if name in hidden:
                        hidden.discard(name)
                        if self._dock_wanted.get(name):
                            dock.show()
                            dock.raise_()
                elif name not in hidden:
                    self._dock_wanted[name] = not dock.isHidden()
                    hidden.add(name)
                    if not dock.isHidden():
                        dock.hide()
        finally:
            self.__dict__["_ax_applying_bindings"] = False

    def _forget_dock_bindings(self, ws) -> None:
        """Workspace *ws* goes: its docks are on all workspaces again."""
        for name in [n for n, w in self._dock_bindings.items() if w is ws]:
            self._release(name, self._dock_named(name))

    # -- the menu -------------------------------------------------------------------------------

    def fill_dock_workspace_menu(self, menu: QMenu, dock) -> None:
        """Show Only on Workspace ▸: All Workspaces, every workspace
        (numbered, the bound one ticked) and New Workspace."""
        menu.clear()
        here = self.dock_workspace(dock)
        everywhere = menu.addAction(tr("All Workspaces"))
        everywhere.setCheckable(True)
        everywhere.setChecked(here is None)
        everywhere.triggered.connect(
            lambda _c=False, d=dock: self.bind_dock_to_workspace(d, None))
        menu.addSeparator()
        for number, ws in enumerate(self.numbered_workspaces(), start=1):
            action = menu.addAction(self.workspace_label(ws, number))
            action.setCheckable(True)
            action.setChecked(ws is here)
            action.triggered.connect(
                lambda _c=False, d=dock, w=ws: self._bind_and_show(d, w))
        new = menu.addAction(tr("New Workspace"))
        new.setEnabled(self.can_add_workspace())
        new.triggered.connect(lambda _c=False, d=dock: self._bind_to_new_workspace(d))

    def _bind_and_show(self, dock, ws) -> None:
        """Bind from the menu: the dock was in use, so its workspace comes
        to the front with it open."""
        self.bind_dock_to_workspace(dock, ws)
        if _alive(dock) and ws in self._workspaces and not self._shown_workspace(ws):
            self._dock_wanted[dock.objectName()] = True
            self._show_workspace(ws)
            self.apply_dock_bindings()

    def _bind_to_new_workspace(self, dock) -> None:
        ws = self.new_workspace(activate=False)
        if ws is not None:
            self._bind_and_show(dock, ws)

    # -- session ------------------------------------------------------------------------------

    def _session_order(self) -> list:
        """The workspaces in the order of the session file's list
        (WorkspaceMixin._serialize_workspaces): the tabs as they stand -
        the user can drag them - then the detached ones. The window's own
        list keeps the order they were made in."""
        return list(self.numbered_workspaces())

    def dock_bindings_session(self) -> dict:
        """``{name: {"ws": index, "open": bool}}`` for the session file."""
        out = {}
        order = self._session_order()
        for name, ws in self._dock_bindings.items():
            if ws in order:
                dock = self._dock_named(name)
                shown = self._shown_workspace(ws)
                open_ = (dock is not None and dock.isVisible()) if shown else \
                    bool(self._dock_wanted.get(name))
                out[name] = {"ws": order.index(ws), "open": bool(open_)}
        return out

    def restore_dock_bindings(self, data) -> None:
        """The bindings of a session (after its workspaces and dock state);
        entries that do not fit - a bad shape, a workspace that is not
        there - are left out."""
        self._dock_bindings.clear()
        self._dock_wanted.clear()
        self._dock_hidden_by_binding.clear()
        if not isinstance(data, dict):
            return
        order = self._session_order()
        for name, entry in list(data.items())[:256]:
            if not isinstance(name, str) or not isinstance(entry, dict):
                continue
            index = entry.get("ws")
            if isinstance(index, bool) or not isinstance(index, int) or \
                    not 0 <= index < len(order):
                continue
            self._dock_bindings[name] = order[index]
            self._dock_wanted[name] = bool(entry.get("open", True))
            if not self._shown_workspace(order[index]):
                # saved hidden by its binding: the session says whether it was open
                self._dock_hidden_by_binding.add(name)
            dock = self._dock_named(name)
            if dock is not None:
                self._hook_dock(dock)
        self.apply_dock_bindings()
        for dock in self.bindable_docks():
            self._refresh_pin(dock)

    def hook_bound_dock(self, dock) -> None:
        """A dock made after the session was read (an extension switched on
        later): its binding takes effect."""
        if _alive(dock) and dock.objectName() in self._dock_bindings:
            name = dock.objectName()
            ws = self._dock_bindings[name]
            if self._hook_dock(dock) and ws in self._workspaces \
                    and not self._shown_workspace(ws):
                # A new dock under a bound name (its extension switched on
                # again) while its workspace is not on screen. Qt shows a
                # dock it just added a moment later, unless it is hidden
                # explicitly: hidden now, it neither shows on this
                # workspace nor brings its own; it opens there as the
                # panel it replaces was, or open if that was not known.
                hidden = self._dock_hidden_by_binding
                if name not in hidden:
                    self._dock_wanted[name] = True
                    hidden.add(name)
                self.__dict__["_ax_applying_bindings"] = True
                try:
                    dock.hide()
                finally:
                    self.__dict__["_ax_applying_bindings"] = False
            self.apply_dock_bindings()
        self._refresh_pin(dock)


def dock_owner(dock):
    """The window that binds *dock* (its dock area's main window), or None."""
    widget = dock.parentWidget() if _alive(dock) else None
    while widget is not None:
        if hasattr(widget, "fill_dock_workspace_menu"):
            return widget
        widget = widget.parentWidget()
    return None


__all__ = ["DockBindingMixin", "SESSION_KEY", "dock_owner"]
