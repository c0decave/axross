"""Workspaces: named pane layouts as tabs, each detachable to a window of
its own (punch-list item 49).

The main window's central widget is a tab widget of workspaces. A workspace
is a root ``QSplitter`` with its panes; ``MainWindow._root_splitter`` is the
root of the *current* workspace, so every path that adds a pane (connects,
splits, restored sessions, layout presets) lands there unchanged.

* A workspace detaches to a :class:`WorkspaceWindow` - another screen, or
  side by side - and comes back as a tab when that window is closed.
* Panes - file and terminal panes alike - move between workspaces from
  Workspace > Move Pane to, or by dragging a pane onto a pane of another
  workspace. Held over a workspace tab, a dragged pane opens that tab after
  TAB_DRAG_SWITCH_MS, so a background workspace is reachable too.
* A new workspace starts with a file list or a local terminal
  (Workspace > New Workspace); Add Terminal Pane puts another local shell
  into the workspace on screen, side by side - several shells in one
  workspace.
* The tab bar hides while there is only one workspace, so the default
  window looks as it always did.
* All panes stay in ``MainWindow._panes`` whichever workspace holds them:
  transfers, the source/target pair and the shutdown work across workspaces.

Session: ``workspaces`` holds every workspace (name, layout with its file
panes and terminals, detached and its window geometry, current) in tab
order; ``splitter`` still holds the first one, so an older axross restores
at least that.
"""

from __future__ import annotations

import logging

from PyQt6 import sip
from PyQt6.QtCore import QByteArray, QEvent, QObject, Qt, QTimer
from PyQt6.QtGui import QAction, QKeySequence
from PyQt6.QtWidgets import (
    QInputDialog,
    QMainWindow,
    QMenu,
    QMessageBox,
    QSplitter,
    QTabWidget,
    QToolBar,
)

from core.i18n import tr
from ui.pane_drag import PANE_MIME_TYPE

log = logging.getLogger(__name__)

#: Workspaces one window keeps; a session file cannot ask for more.
MAX_WORKSPACES = 32
MAX_NAME = 64
DEFAULT_PREFIX = "Workspace"
#: How long a dragged pane is held over a workspace tab before it opens.
TAB_DRAG_SWITCH_MS = 500
#: What a new workspace starts with: a file list or a local terminal.
START_FILES = "files"
START_TERMINAL = "terminal"
START_KINDS = (START_FILES, START_TERMINAL)


def clean_name(name: object) -> str:
    """*name* stripped, or ValueError: 1 to MAX_NAME characters, no
    control characters (a tab title is one line)."""
    if not isinstance(name, str):
        raise ValueError("a workspace name is text")
    name = name.strip()
    if not name or len(name) > MAX_NAME:
        raise ValueError(f"a workspace name is 1 to {MAX_NAME} characters")
    if any(ord(c) < 32 or c == "\x7f" for c in name):
        raise ValueError("a workspace name may not hold control characters")
    return name


def tab_label(name: str) -> str:
    """*name* for a tab or a menu entry, where "&" marks a mnemonic: shown
    as typed ("R&D" showed as "RD" with an underlined D)."""
    return name.replace("&", "&&")


def session_problem(workspaces) -> tuple[str, list]:
    """Why a session's ``workspaces`` entry cannot be restored ("" when it
    can), and the layout trees it holds for the caller's tree check."""
    if workspaces is None:
        return "", []
    if not isinstance(workspaces, list):
        return "The workspaces are not a list.", []
    if len(workspaces) > MAX_WORKSPACES:
        return f"The session holds more than {MAX_WORKSPACES} workspaces.", []
    trees = []
    for entry in workspaces:
        if not isinstance(entry, dict):
            return "A workspace is not an object.", []
        try:
            clean_name(entry.get("name"))
        except ValueError as exc:
            return f"A workspace name is unusable: {exc}.", []
        tree = entry.get("splitter", {})
        if not isinstance(tree, dict):
            return "A workspace layout is not an object.", []
        if not isinstance(entry.get("geometry", ""), str):
            return "A workspace window geometry is not text.", []
        trees.append(tree)
    return "", trees


def window_shortcut_actions(owner) -> list[QAction]:
    """The main window's own actions with a window-wide shortcut: those
    added to the window, its menus (submenus included) and its toolbars -
    not the actions inside panes, which a detached window has itself."""
    found: list[QAction] = []
    seen: set[int] = set()
    stack = list(owner.actions())
    menubar = owner.menuWidget()
    if menubar is not None:
        stack += menubar.actions()
    # The window's own toolbars only: a dock's toolbar keys belong to it.
    for toolbar in owner.findChildren(QToolBar, options=Qt.FindChildOption.FindDirectChildrenOnly):
        stack += toolbar.actions()
    while stack:
        action = stack.pop()
        if id(action) in seen or sip.isdeleted(action):
            continue
        seen.add(id(action))
        menu = action.menu()
        if menu is not None:
            stack += menu.actions()
        if action.shortcuts() and action.shortcutContext() == Qt.ShortcutContext.WindowShortcut:
            found.append(action)
    return found


class TabDragSwitcher(QObject):
    """Opens the workspace tab a dragged pane is held over, after
    TAB_DRAG_SWITCH_MS - so a pane reaches a workspace in the background.
    Pane drags only: any other drag (files, text) passes the tab bar as
    before. The tab bar itself takes no drop."""

    def __init__(self, tabs: QTabWidget) -> None:
        super().__init__(tabs)
        self._tabs = tabs
        self._pending = None  # the tab page (workspace root) waited for
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.setInterval(TAB_DRAG_SWITCH_MS)
        self._timer.timeout.connect(self._switch)
        bar = tabs.tabBar()
        bar.setAcceptDrops(True)
        bar.installEventFilter(self)

    def eventFilter(self, obj, event) -> bool:  # noqa: N802 - Qt override
        kind = event.type()
        if kind in (QEvent.Type.DragEnter, QEvent.Type.DragMove):
            if not event.mimeData().hasFormat(PANE_MIME_TYPE):
                return False  # the tab bar ignores it, as it always did
            if kind == QEvent.Type.DragEnter:
                event.accept()  # keeps the moves coming
            else:
                event.ignore()  # no drop on a tab: the cursor says so
            self._hover(event.position().toPoint())
            return True
        if kind == QEvent.Type.DragLeave:
            self._cancel()
            return False
        if kind == QEvent.Type.Drop and event.mimeData().hasFormat(PANE_MIME_TYPE):
            self._cancel()
            event.ignore()
            return True
        return False

    def _hover(self, pos) -> None:
        tabs = self._tabs
        index = tabs.tabBar().tabAt(pos)
        page = tabs.widget(index) if index >= 0 else None
        if page is None or page is tabs.currentWidget():
            self._cancel()
            return
        if page is not self._pending:
            self._pending = page
            self._timer.start()

    def _cancel(self) -> None:
        self._timer.stop()
        self._pending = None

    def _switch(self) -> None:
        page, self._pending = self._pending, None
        if page is not None and not sip.isdeleted(page) and self._tabs.indexOf(page) >= 0:
            self._tabs.setCurrentWidget(page)  # currentChanged switches the workspace


class Workspace:
    """One named pane layout: its root splitter, the window it is detached
    to (None while it is a tab), and the source/target pair it had."""

    def __init__(self, name: str, root: QSplitter) -> None:
        self.name = name
        self.root = root
        self.window: WorkspaceWindow | None = None
        self.last_active = None
        self.last_target = None

    def __repr__(self) -> str:
        return f"<Workspace {self.name!r}{' detached' if self.window else ''}>"


class WorkspaceWindow(QMainWindow):
    """A detached workspace. Closing it brings the workspace back as a tab;
    the main window closing closes it for good (``shutting_down``).

    Panes reach the main window through ``self.window()`` (the editor, the
    tagged-files list, the status bar); here that is this window, so every
    attribute it lacks is looked up on the main window."""

    def __init__(self, owner, workspace: Workspace) -> None:
        super().__init__(owner, Qt.WindowType.Window)
        self._owner = owner
        self.workspace = workspace
        self.shutting_down = False
        self.setCentralWidget(workspace.root)
        # The main window's keys work here too: a window-wide shortcut
        # fires in every window its action is added to.
        self.addActions(window_shortcut_actions(owner))
        self.retitle()

    def __getattr__(self, name: str):
        owner = self.__dict__.get("_owner")
        if owner is None or name.startswith("__"):
            raise AttributeError(name)
        return getattr(owner, name)

    def retitle(self) -> None:
        self.setWindowTitle(f"{self.workspace.name} — axross")

    def activated(self) -> None:
        if not self.shutting_down:
            self._owner.switch_workspace(self.workspace)

    def changeEvent(self, event) -> None:
        if event.type() == QEvent.Type.ActivationChange and self.isActiveWindow():
            self.activated()
        super().changeEvent(event)

    def closeEvent(self, event) -> None:
        if not self.shutting_down:
            self._owner.attach_workspace(self.workspace)
        super().closeEvent(event)


class WorkspaceMixin:
    """The workspace half of MainWindow. Expects the MainWindow attributes
    ``_panes``, ``_terminal_panes``, ``_pane_placeholders``, ``_active_pane``,
    ``_target_pane`` and its pane methods."""

    # -- lookup ----------------------------------------------------------------------

    @property
    def _root_splitter(self) -> QSplitter:
        return self._current_ws.root

    @_root_splitter.setter
    def _root_splitter(self, root: QSplitter) -> None:
        self._install_root_splitter(root)

    def workspaces(self) -> list[Workspace]:
        return list(self._workspaces)

    def current_workspace(self) -> Workspace:
        return self._current_ws

    def _is_workspace_root(self, widget) -> bool:
        return any(ws.root is widget for ws in self._workspaces)

    def workspace_of(self, widget) -> Workspace | None:
        """The workspace whose layout holds *widget*, or None."""
        roots = {id(ws.root): ws for ws in self._workspaces}
        while widget is not None and not sip.isdeleted(widget):
            ws = roots.get(id(widget))
            if ws is not None and ws.root is widget:
                return ws
            widget = widget.parentWidget()
        return None

    def _widgets_of(self, ws: Workspace) -> tuple[list, list, list]:
        """The file panes, terminal panes and placeholders in *ws*."""
        return (
            [p for p in self._panes if self.workspace_of(p) is ws],
            [t for t in self._terminal_panes if self.workspace_of(t) is ws],
            [h for h in self._pane_placeholders if self.workspace_of(h) is ws],
        )

    def _next_workspace_name(self) -> str:
        taken = {ws.name for ws in self._workspaces}
        n = 1
        while f"{DEFAULT_PREFIX} {n}" in taken:
            n += 1
        return f"{DEFAULT_PREFIX} {n}"

    # -- setup -----------------------------------------------------------------------

    def _setup_workspaces(self) -> None:
        """The tab widget and one empty workspace; any earlier ones go."""
        if getattr(self, "_workspace_tabs", None) is None:
            tabs = QTabWidget()
            tabs.setObjectName("workspaceTabs")
            tabs.setDocumentMode(True)
            tabs.setMovable(True)
            tabs.setTabBarAutoHide(True)
            tabs.currentChanged.connect(self._on_workspace_tab_changed)
            tabs.tabBarDoubleClicked.connect(self._rename_workspace_at)
            bar = tabs.tabBar()
            bar.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
            bar.customContextMenuRequested.connect(self._show_workspace_tab_menu)
            self._tab_drag_switcher = TabDragSwitcher(tabs)
            self._workspace_tabs = tabs
            self._workspaces: list[Workspace] = []
            self._current_ws: Workspace | None = None
            self.setCentralWidget(tabs)
        self._drop_all_workspaces()
        self._add_workspace(self._next_workspace_name())

    def _add_workspace(self, name: str) -> Workspace:
        root = QSplitter(Qt.Orientation.Horizontal)
        ws = Workspace(name, root)
        self._workspaces.append(ws)
        tabs = self._workspace_tabs
        tabs.blockSignals(True)
        try:
            tabs.addTab(root, tab_label(name))
        finally:
            tabs.blockSignals(False)
        if self._current_ws is None:
            self._current_ws = ws
            tabs.setCurrentWidget(root)
        return ws

    def _drop_workspace(self, ws: Workspace) -> None:
        """Take *ws* away - its panes are already torn down."""
        if ws in self._workspaces:
            self._workspaces.remove(ws)
        if ws.window is not None:
            window, ws.window = ws.window, None
            window.shutting_down = True
            window.takeCentralWidget()
            window.close()
            window.deleteLater()
        tabs = self._workspace_tabs
        index = tabs.indexOf(ws.root)
        if index >= 0:
            tabs.blockSignals(True)
            try:
                tabs.removeTab(index)
            finally:
                tabs.blockSignals(False)
        ws.root.setParent(None)
        ws.root.deleteLater()
        if self._current_ws is ws:
            self._current_ws = None
            if self._workspaces:
                self.switch_workspace(self._tab_workspace() or self._workspaces[0])

    def _drop_all_workspaces(self) -> None:
        for ws in list(self._workspaces):
            self._drop_workspace(ws)
        self._current_ws = None

    def _tab_workspace(self) -> Workspace | None:
        root = self._workspace_tabs.currentWidget()
        return next((ws for ws in self._workspaces if ws.root is root), None)

    def _install_root_splitter(self, root: QSplitter) -> None:
        """A layout preset built a new root for the current workspace."""
        ws = self._current_ws
        old = ws.root
        ws.root = root
        if ws.window is not None:
            ws.window.takeCentralWidget()
            ws.window.setCentralWidget(root)
        else:
            tabs = self._workspace_tabs
            index = tabs.indexOf(old)
            tabs.blockSignals(True)
            try:
                tabs.removeTab(index)
                tabs.insertTab(index, root, tab_label(ws.name))
                tabs.setCurrentIndex(index)
            finally:
                tabs.blockSignals(False)
        if old is not root:
            old.setParent(None)
            old.deleteLater()

    # -- switching -------------------------------------------------------------------

    def switch_workspace(self, ws: Workspace) -> None:
        """Make *ws* current: its tab shows (or its window is raised by the
        caller) and its own source/target pair comes back."""
        if ws not in self._workspaces:
            return
        old = self._current_ws
        if old is not None and old is not ws:
            old.last_active, old.last_target = self._active_pane, self._target_pane
        self._current_ws = ws
        if ws.window is None and self._workspace_tabs.currentWidget() is not ws.root:
            self._workspace_tabs.blockSignals(True)
            try:
                self._workspace_tabs.setCurrentWidget(ws.root)
            finally:
                self._workspace_tabs.blockSignals(False)
        if old is ws and self.workspace_of(self._active_pane) is ws:
            return
        files = self._widgets_of(ws)[0]
        if not files:
            return
        active = ws.last_active if ws.last_active in files else files[0]
        self._set_active_pane(active)
        target = ws.last_target if ws.last_target in files else None
        if target is None and len(files) > 1:
            target = next(p for p in files if p is not active)
        if target is not None and target is not active:
            self._target_pane = target
            self._refresh_pane_styles()

    def _on_workspace_tab_changed(self, index: int) -> None:
        ws = self._tab_workspace()
        if ws is not None:
            self.switch_workspace(ws)

    def _note_active_workspace(self, pane) -> None:
        """A pane became active: its workspace is the current one."""
        ws = self.workspace_of(pane)
        if ws is not None and ws is not self._current_ws:
            old = self._current_ws
            # _set_active_pane made the old source the target: that is the
            # pane the old workspace had active.
            if old is not None and self.workspace_of(self._target_pane) is old:
                old.last_active = self._target_pane
            self._current_ws = ws
            if ws.window is None and self._workspace_tabs.currentWidget() is not ws.root:
                self._workspace_tabs.blockSignals(True)
                try:
                    self._workspace_tabs.setCurrentWidget(ws.root)
                finally:
                    self._workspace_tabs.blockSignals(False)

    def next_workspace(self, *, forward: bool = True) -> None:
        tabs = self._workspace_tabs
        if tabs.count() < 2:
            return
        step = 1 if forward else -1
        tabs.setCurrentIndex((tabs.currentIndex() + step) % tabs.count())

    # -- create, rename, close -------------------------------------------------------

    def new_workspace(self, name: str | None = None, *, with_pane: bool = True,
                      activate: bool = True, start: str = START_FILES) -> Workspace | None:
        """A new workspace tab - with one local file pane, or with *start*
        START_TERMINAL one local terminal; nothing when *with_pane* is
        False. None at the MAX_WORKSPACES ceiling or for a bad name;
        ValueError for an unknown *start*."""
        if start not in START_KINDS:
            raise ValueError(f"a workspace starts with one of {START_KINDS}, not {start!r}")
        if len(self._workspaces) >= MAX_WORKSPACES:
            self.statusBar().showMessage(
                tr("No more than {n} workspaces.").format(n=MAX_WORKSPACES), 5000)
            return None
        try:
            name = clean_name(name) if name is not None else self._next_workspace_name()
        except ValueError as exc:
            log.warning("New workspace refused: %s", exc)
            return None
        # Before the new workspace exists: the folder the active pane shows.
        folder = self._terminal_start_folder() if with_pane and start == START_TERMINAL else None
        ws = self._add_workspace(name)
        if with_pane and start == START_TERMINAL:
            self.add_terminal_pane(ws, cwd=folder)
        elif with_pane:
            from core.local_fs import LocalFS

            self._add_pane_to_splitter(ws.root, LocalFS())
        if activate:
            self.switch_workspace(ws)
        return ws

    def _terminal_start_folder(self) -> str:
        """Where a new local shell starts: the folder the active file pane
        shows when it is a local one, else home (the shell falls back to
        home itself when the folder is gone - see _local_folder_or_home)."""
        from core.local_fs import LocalFS

        pane = self._active_pane
        path = pane.current_path if pane is not None and type(pane.backend) is LocalFS else None
        return self._local_folder_or_home(path)

    def add_terminal_pane(self, ws: Workspace | None = None, *, cwd: str | None = None):
        """A local shell as a pane of its own in *ws* (default: the current
        workspace), beside the panes already there; the panes of the
        workspace's root share its width evenly. Starts in *cwd*, else in
        the active local pane's folder or home. None for a workspace this
        window does not hold."""
        ws = ws if ws is not None else self._current_ws
        if ws not in self._workspaces:
            return None
        folder = self._local_folder_or_home(cwd) if cwd else self._terminal_start_folder()
        term = self._preset_make_terminal_pane("local", cwd=folder)
        root = ws.root
        root.addWidget(term)
        term.show()
        # Once the layout has its size; a hidden root has none yet.
        QTimer.singleShot(
            0, lambda r=root: None if sip.isdeleted(r) else self._equalize_splitter(r))
        term.setFocus()
        return term

    def _add_terminal_pane_and_show(self, ws: Workspace):
        """Add Terminal Pane on a tab: the shell lands there and that
        workspace comes to the front, where the user can type in it."""
        term = self.add_terminal_pane(ws)
        if term is not None:
            self._show_workspace(ws)
            term.setFocus()
        return term

    def rename_workspace(self, ws: Workspace, name) -> bool:
        try:
            name = clean_name(name)
        except ValueError as exc:
            log.info("Rename refused: %s", exc)
            return False
        ws.name = name
        index = self._workspace_tabs.indexOf(ws.root)
        if index >= 0:
            self._workspace_tabs.setTabText(index, tab_label(name))
        if ws.window is not None:
            ws.window.retitle()
        return True

    def _rename_workspace_at(self, index: int) -> None:
        root = self._workspace_tabs.widget(index)
        ws = next((w for w in self._workspaces if w.root is root), None)
        if ws is not None:
            self._ask_rename_workspace(ws)

    def _ask_rename_workspace(self, ws: Workspace | None = None) -> None:
        ws = ws or self._current_ws
        name, ok = QInputDialog.getText(self, tr("Rename Workspace"), tr("Name:"), text=ws.name)
        if ok and not self.rename_workspace(ws, name):
            QMessageBox.information(
                self, tr("Rename Workspace"),
                tr("A workspace name is 1 to {n} characters on one line.").format(n=MAX_NAME))

    def close_workspace(self, ws: Workspace, *, ask: bool = True) -> bool:
        """Close *ws* and every pane in it - never the last workspace. With
        *ask*, a workspace that holds panes asks first."""
        if ws not in self._workspaces or len(self._workspaces) <= 1:
            return False
        if ws.window is None and sum(w.window is None for w in self._workspaces) <= 1:
            self.statusBar().showMessage(
                tr("The main window keeps at least one workspace."), 5000)
            return False
        files, terms, holders = self._widgets_of(ws)
        count = len(files) + len(terms) + len(holders)
        if ask and count:
            reply = QMessageBox.question(
                self, tr("Close Workspace"),
                # Fixed first line: a message box renders markup found there.
                tr("Close this workspace and its {n} panes?\n\n{name}").format(
                    name=ws.name, n=count),
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if reply != QMessageBox.StandardButton.Yes:
                return False
        self._tear_down_panes(files, terms, holders)
        self._drop_workspace(ws)
        self._settle_source_and_target()
        return True

    def _settle_source_and_target(self) -> None:
        """After panes went away: a source and target from what is left,
        preferring the current workspace."""
        if self._active_pane not in self._panes:
            self._active_pane = None
        if self._target_pane not in self._panes:
            self._target_pane = None
        if self._active_pane is None and self._panes:
            mine = self._widgets_of(self._current_ws)[0] if self._current_ws else []
            self._set_active_pane((mine or self._panes)[0])
        if self._target_pane is None and len(self._panes) > 1:
            self._target_pane = next(p for p in self._panes if p is not self._active_pane)
        self._refresh_pane_styles()

    def _prune_empty_workspaces(self) -> None:
        """A workspace whose last pane left (closed, moved, dragged away)
        goes - as a tab closes with its last page. One always stays, and
        the main window keeps one tab (empty) while others are detached."""
        for ws in list(self._workspaces):
            if len(self._workspaces) <= 1:
                break
            if ws.window is None and sum(w.window is None for w in self._workspaces) <= 1:
                continue
            if ws.root.count() == 0 and not any(self._widgets_of(ws)):
                self._drop_workspace(ws)

    # -- detach / attach -------------------------------------------------------------

    def detach_workspace(self, ws: Workspace | None = None, *, geometry: bytes | None = None,
                         activate: bool = True):
        """Put *ws* on a window of its own; the window, or None when it is
        already detached or the only tab left. A restored session passes
        *activate* False: its windows show without taking the focus, which
        made the last detached one the current workspace."""
        ws = ws or self._current_ws
        if ws not in self._workspaces or ws.window is not None:
            return None
        tabs = self._workspace_tabs
        attached = [w for w in self._workspaces if w.window is None]
        if len(attached) <= 1:
            self.statusBar().showMessage(
                tr("The main window keeps at least one workspace."), 5000)
            return None
        index = tabs.indexOf(ws.root)
        tabs.blockSignals(True)
        try:
            tabs.removeTab(index)
        finally:
            tabs.blockSignals(False)
        window = WorkspaceWindow(self, ws)
        ws.window = window
        if not activate:
            window.setAttribute(Qt.WidgetAttribute.WA_ShowWithoutActivating)
        if not (geometry and window.restoreGeometry(QByteArray(geometry))):
            window.resize(max(480, self.width() * 2 // 3), max(360, self.height() * 2 // 3))
        ws.root.show()
        for child in ws.root.findChildren(QSplitter):
            child.show()
        window.show()
        if activate:
            self.switch_workspace(ws)
        return window

    def attach_workspace(self, ws: Workspace) -> None:
        """Back from its window into the tabs (the window is closing)."""
        window = ws.window
        if window is None:
            return
        ws.window = None
        window.takeCentralWidget()
        window.deleteLater()
        self._workspace_tabs.blockSignals(True)
        try:
            self._workspace_tabs.addTab(ws.root, tab_label(ws.name))
        finally:
            self._workspace_tabs.blockSignals(False)
        ws.root.show()
        self.switch_workspace(ws)

    def changeEvent(self, event) -> None:
        """The main window gets the focus: its shown tab is current again,
        not a detached workspace worked in last."""
        super().changeEvent(event)
        if (event.type() == QEvent.Type.ActivationChange and self.isActiveWindow()
                and getattr(self, "_workspace_tabs", None) is not None):
            ws = self._tab_workspace()
            if ws is not None and self._current_ws is not None and self._current_ws.window:
                self.switch_workspace(ws)

    def _close_detached_windows(self) -> None:
        """The application closes: detached windows close with it and stay
        detached in the saved session."""
        for ws in self._workspaces:
            if ws.window is not None:
                ws.window.shutting_down = True
                ws.window.close()

    # -- moving panes ----------------------------------------------------------------

    def _take_out_of_layout(self, widget) -> None:
        """Lift *widget* out of its splitter; a nested splitter left with
        one child is replaced by it, an empty one goes."""
        parent = widget.parent()
        widget.setParent(None)
        if not isinstance(parent, QSplitter) or self._is_workspace_root(parent):
            return
        if parent.count() == 1:
            grandparent = parent.parent()
            if isinstance(grandparent, QSplitter):
                remaining = parent.widget(0)
                grandparent.replaceWidget(grandparent.indexOf(parent), remaining)
                remaining.show()
                parent.deleteLater()
        elif parent.count() == 0:
            parent.setParent(None)
            parent.deleteLater()

    def move_pane_to_workspace(self, pane, ws: Workspace) -> bool:
        """Move *pane* - a file pane or a terminal pane - into *ws* (at the
        end of its root); the source workspace closes if that was its last
        pane."""
        if ws not in self._workspaces or not (pane in self._panes or pane in self._terminal_panes):
            return False
        if self.workspace_of(pane) is ws:
            return False
        self._take_out_of_layout(pane)
        ws.root.addWidget(pane)
        pane.show()
        self._prune_empty_workspaces()
        self.switch_workspace(ws)
        if pane in self._panes:
            self._set_active_pane(pane)
        return True

    def _pane_to_move(self):
        """What Move Pane to Workspace moves: the terminal pane that has the
        keyboard focus, else the active file pane."""
        from PyQt6.QtWidgets import QApplication

        widget = QApplication.focusWidget()
        while widget is not None:
            if widget in self._terminal_panes:
                return widget
            widget = widget.parentWidget()
        return self._active_pane

    def move_active_pane_to_new_workspace(self, pane=None) -> Workspace | None:
        pane = pane if pane is not None else self._pane_to_move()
        if pane is None:
            return None
        ws = self.new_workspace(with_pane=False, activate=False)
        if ws is not None:
            self.move_pane_to_workspace(pane, ws)
        return ws

    # -- menus -----------------------------------------------------------------------

    def _build_workspace_menu(self, menubar) -> QMenu:
        menu = menubar.addMenu(tr("&Workspace"))
        self._workspace_menu = menu
        menu.aboutToShow.connect(self._fill_workspace_menu)
        # New Workspace > With File List / With Terminal; the submenu stays,
        # the Workspace menu itself is rebuilt each time it opens.
        self._new_workspace_menu = QMenu(tr("New Workspace"), self)
        self._new_workspace_action = self._new_workspace_menu.addAction(tr("With File List"))
        self._new_workspace_action.setShortcut(QKeySequence("Ctrl+Alt+N"))
        self._new_workspace_action.triggered.connect(lambda _c=False: self.new_workspace())
        self._new_terminal_workspace_action = self._new_workspace_menu.addAction(
            tr("With Terminal"))
        self._new_terminal_workspace_action.setShortcut(QKeySequence("Ctrl+Alt+Shift+N"))
        self._new_terminal_workspace_action.triggered.connect(
            lambda _c=False: self.new_workspace(start=START_TERMINAL))
        self._add_terminal_pane_action = QAction(tr("Add Terminal Pane"), self)
        self._add_terminal_pane_action.setToolTip(
            tr("A local shell beside the panes of this workspace"))
        self._add_terminal_pane_action.triggered.connect(lambda _c=False: self.add_terminal_pane())
        self._next_workspace_action = menu.addAction(tr("Next Workspace"))
        self._next_workspace_action.setShortcut(QKeySequence("Ctrl+Alt+PgDown"))
        self._next_workspace_action.triggered.connect(lambda _c=False: self.next_workspace())
        self._prev_workspace_action = menu.addAction(tr("Previous Workspace"))
        self._prev_workspace_action.setShortcut(QKeySequence("Ctrl+Alt+PgUp"))
        self._prev_workspace_action.triggered.connect(
            lambda _c=False: self.next_workspace(forward=False))
        # Window-wide: the menu is rebuilt each time it opens.
        for action in (self._new_workspace_action, self._new_terminal_workspace_action,
                       self._next_workspace_action, self._prev_workspace_action):
            self.addAction(action)
        return menu

    def _fill_workspace_menu(self) -> None:
        menu = self._workspace_menu
        menu.clear()
        menu.addMenu(self._new_workspace_menu)
        menu.addAction(self._add_terminal_pane_action)
        menu.addAction(tr("Rename Workspace…")).triggered.connect(
            lambda _c=False: self._ask_rename_workspace())
        ws = self._current_ws
        detach = menu.addAction(tr("Detach to Window"))
        detach.setEnabled(ws.window is None
                          and sum(w.window is None for w in self._workspaces) > 1)
        detach.triggered.connect(lambda _c=False, w=ws: self.detach_workspace(w))
        close = menu.addAction(tr("Close Workspace"))
        close.setEnabled(len(self._workspaces) > 1)
        close.triggered.connect(lambda _c=False, w=ws: self.close_workspace(w))
        menu.addSeparator()
        move = menu.addMenu(tr("Move Pane to Workspace"))
        move.setEnabled(self._pane_to_move() is not None)
        move.aboutToShow.connect(lambda m=move: self._fill_move_menu(m))
        self._fill_move_menu(move)
        menu.addSeparator()
        menu.addAction(self._next_workspace_action)
        menu.addAction(self._prev_workspace_action)
        menu.addSeparator()
        for other in self._workspaces:
            text = tab_label(other.name) + (tr(" (window)") if other.window else "")
            action = menu.addAction(text)
            action.setCheckable(True)
            action.setChecked(other is ws)
            action.triggered.connect(lambda _c=False, w=other: self._show_workspace(w))

    def _fill_move_menu(self, menu: QMenu) -> None:
        self.fill_move_menu_for(self._pane_to_move(), menu)

    def fill_move_menu_for(self, pane, menu: QMenu) -> None:
        """The other workspaces and New Workspace, each moving *pane* (a
        file or terminal pane) - for the Workspace menu and a terminal
        pane's header button."""
        menu.clear()
        if pane is None:
            return
        here = self.workspace_of(pane)
        for ws in self._workspaces:
            if ws is here:
                continue
            menu.addAction(tab_label(ws.name)).triggered.connect(
                lambda _c=False, w=ws, p=pane: self.move_pane_to_workspace(p, w))
        menu.addSeparator()
        menu.addAction(tr("New Workspace")).triggered.connect(
            lambda _c=False, p=pane: self.move_active_pane_to_new_workspace(p))

    def _show_workspace(self, ws: Workspace) -> None:
        if ws.window is not None:
            ws.window.raise_()
            ws.window.activateWindow()
        self.switch_workspace(ws)

    def _show_workspace_tab_menu(self, pos) -> None:
        bar = self._workspace_tabs.tabBar()
        index = bar.tabAt(pos)
        root = self._workspace_tabs.widget(index) if index >= 0 else None
        ws = next((w for w in self._workspaces if w.root is root), None)
        if ws is None:
            return
        menu = QMenu(self)
        menu.addAction(tr("Rename…")).triggered.connect(
            lambda _c=False: self._ask_rename_workspace(ws))
        menu.addAction(tr("Detach to Window")).triggered.connect(
            lambda _c=False: self.detach_workspace(ws))
        menu.addAction(tr("Close Workspace")).triggered.connect(
            lambda _c=False: self.close_workspace(ws))
        menu.addSeparator()
        menu.addAction(tr("Add Terminal Pane")).triggered.connect(
            lambda _c=False: self._add_terminal_pane_and_show(ws))
        menu.addMenu(self._new_workspace_menu)
        menu.exec(bar.mapToGlobal(pos))
        menu.deleteLater()

    # -- session ---------------------------------------------------------------------

    def _serialize_workspaces(self) -> list[dict]:
        tabs = self._workspace_tabs
        ordered = sorted(
            self._workspaces,
            key=lambda w: (w.window is not None,
                           tabs.indexOf(w.root) if w.window is None else self._workspaces.index(w)),
        )
        entries = []
        for ws in ordered:
            entry = {"name": ws.name, "splitter": self._serialize_splitter(ws.root)}
            if ws.window is not None:
                entry["detached"] = True
                entry["geometry"] = bytes(ws.window.saveGeometry().toBase64()).decode("ascii")
            if ws is self._current_ws:
                entry["current"] = True
            entries.append(entry)
        return entries
