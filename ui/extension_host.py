"""Loading extensions into the main window and the API they get.

See :mod:`core.extensions` for what an extension is and where it lives.
The host imports an extension only when it is switched on and the
security mode allows scripts, calls its ``activate(api)`` and keeps track
of everything that ``api`` registered, so switching it off (or a failing
``activate``) removes all of it again.

Every call into extension code - ``activate``, ``deactivate``, menu and
context callbacks, event handlers, background results - goes through one
guard: an exception is logged, shown in the status bar and recorded as the
extension's error (Extensions > Manage Extensions… shows it); it never
reaches Qt, which would abort the application.
"""

from __future__ import annotations

import logging
import re
import sys
import threading
import time
import traceback
import types
import weakref
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from PyQt6.QtCore import QObject, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QAction, QKeySequence
from PyQt6.QtWidgets import QDockWidget, QMenu, QWidget

from core import extensions as EX

log = logging.getLogger(__name__)

#: Events an extension can subscribe to with ``api.on``.
EVENTS = ("selection_changed", "path_changed", "pane_activated")
#: The order a resumed extension gets the events it missed: the pane,
#: then its folder, then the selection in that folder.
_CATCH_UP_ORDER = ("pane_activated", "path_changed", "selection_changed")
#: What a context action can apply to (``applies_to``).
APPLIES_TO = ("any", "folder", "selection", "files", "folders", "single_file", "single_folder")
#: An agent tool's own name (the agent sees ``ext_<module>__<name>``).
_AGENT_TOOL_NAME = re.compile(r"^[a-z][a-z0-9_]{0,31}$")

_ACTIVE_HOST: weakref.ReferenceType | None = None


@dataclass(frozen=True)
class ExtensionContext:
    """What a context action or an event handler is about: the active
    pane's backend, its folder and the selected paths."""

    backend: Any
    folder: str
    paths: tuple[str, ...]
    items: tuple = ()
    pane: Any = None

    @property
    def is_local(self) -> bool:
        from core.local_fs import LocalFS

        return isinstance(self.backend, LocalFS)


def context_of(pane) -> ExtensionContext:
    items = tuple(pane.selected_file_items())
    return ExtensionContext(
        backend=pane.backend,
        folder=pane.current_path,
        paths=tuple(pane.selected_items()),
        items=items,
        pane=pane,
    )


@dataclass
class _Registered:
    actions: list[QAction] = field(default_factory=list)
    context: list[tuple[str, Callable, str, tuple[str, ...]]] = field(default_factory=list)
    docks: list[QDockWidget] = field(default_factory=list)
    handlers: dict[str, list[Callable]] = field(default_factory=dict)
    agent_tools: list = field(default_factory=list)
    agent_topics: list = field(default_factory=list)
    agent_handlers: list[Callable] = field(default_factory=list)


class ExtensionAPI:
    """The object an extension's ``activate(api)`` receives."""

    def __init__(self, host: ExtensionHost, info: EX.ExtensionInfo) -> None:
        from core import scripting

        self._host = host
        self.info = info
        #: The whole scripting API (``axross.*`` in scripts).
        self.axross = scripting
        self.log = logging.getLogger(f"axross.ext.{info.module_name}")
        self._reg = _Registered()
        self._pause_action: QAction | None = None

    @property
    def window(self):
        """The main window - an escape hatch; prefer the calls below."""
        return self._host.window

    # -- registering --------------------------------------------------------
    def add_menu_action(
        self, label: str, callback: Callable[[], Any], *, shortcut: str | None = None
    ) -> QAction:
        """An entry in the Extensions menu."""
        action = QAction(str(label), self._host.window)
        if shortcut:
            action.setShortcut(QKeySequence(shortcut))
        action.triggered.connect(lambda _checked=False: self._host.call(self, callback))
        self._host.menu_section().addAction(action)
        self._reg.actions.append(action)
        return action

    def add_context_action(
        self,
        label: str,
        callback: Callable[[ExtensionContext], Any],
        *,
        applies_to: str = "any",
        extensions: tuple[str, ...] | list[str] = (),
    ) -> None:
        """An entry in the file pane's right-click menu.

        *applies_to*: ``any`` (always), ``folder`` (nothing selected: the
        folder itself), ``selection`` (anything selected), ``files`` /
        ``folders`` (only files / only folders selected), ``single_file`` /
        ``single_folder`` (exactly one file / one folder selected).
        *extensions* (``(".md", ".txt")``) limits file entries by name.
        """
        if applies_to not in APPLIES_TO:
            raise ValueError(f"applies_to must be one of {APPLIES_TO}, not {applies_to!r}")
        suffixes = tuple(str(e).lower() for e in extensions)
        self._reg.context.append((str(label), callback, applies_to, suffixes))

    def add_dock(self, title: str, widget: QWidget) -> QDockWidget:
        """A panel docked on the right, with the title bar of the built-in
        panels (float, [x], close all in this area) and a Move to Workspace
        button; its show/hide entry goes into the Extensions menu, which
        also reopens it after [x].

        The panel is on all workspaces (the dock area) until the user
        moves it to one, where it is laid out like a pane
        (ui.extension_panels); a panel that was on a workspace when the
        extension was switched off goes back there. The returned dock and
        *widget* stay the same objects wherever the panel is."""
        from ui.extension_panels import (
            EXTENSION_DOCK_PREFIX,
            ExtensionDock,
            ExtensionPanelTitleBar,
        )

        window = self._host.window
        ext_id = self.info.ext_id
        dock = ExtensionDock(str(title), window, ext_id)
        dock.setObjectName(f"{EXTENSION_DOCK_PREFIX}{ext_id}-{len(self._reg.docks)}")
        bar = ExtensionPanelTitleBar(str(title), dock)
        bar.enable_pause(
            lambda paused: self._host.set_paused(ext_id, paused),
            paused=self._host.is_paused(ext_id),
        )
        dock.setTitleBarWidget(bar)
        dock.setWidget(widget)
        window.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, dock)
        toggle = dock.toggleViewAction()
        self._host.menu_section().addAction(toggle)
        self._reg.actions.append(toggle)
        self._reg.docks.append(dock)
        reveal = getattr(window, "reveal_extension_panel", None)
        if callable(reveal):
            # Shown from the menu: on a workspace, that one comes to the front.
            toggle.triggered.connect(lambda checked, d=dock: reveal(d) if checked else None)
        drop = getattr(window, "_on_pane_drop", None)
        if callable(drop):
            dock.pane_drop_requested.connect(drop)
        added = getattr(window, "extension_panel_added", None)
        if callable(added):
            added(dock)
        return dock

    def on(self, event: str, callback: Callable[[ExtensionContext], Any]) -> None:
        """Call *callback(context)* on ``selection_changed``, ``path_changed``
        or ``pane_activated`` of the active pane."""
        if event not in EVENTS:
            raise ValueError(f"unknown event {event!r}; known: {', '.join(EVENTS)}")
        self._reg.handlers.setdefault(event, []).append(callback)

    # -- the agent ------------------------------------------------------------
    def add_agent_tool(
        self,
        name: str,
        description: str,
        handler: Callable[[dict], Any],
        *,
        parameters: dict | None = None,
        required: tuple[str, ...] | list[str] = (),
        writes: bool = False,
    ) -> str:
        """A tool for the agent, named ``ext_<module>__<name>`` there.

        *parameters* are the JSON-schema properties of its arguments,
        *required* the names that must be given. *handler(args)* runs on
        the agent's thread (not the GUI's) and returns a string or anything
        JSON can hold; an exception becomes an error the model reads. With
        *writes* every call asks the user first (as in Ask mode). A tab
        offers the tool when "ext:<this extension>" is ticked in its Tools
        list - tabs started with :meth:`run_agent` tick it.
        """
        from core.agent import FunctionTool

        if not isinstance(name, str) or not _AGENT_TOOL_NAME.match(name):
            raise ValueError(
                f"an agent tool name is 1-32 of a-z, 0-9 and _, starting with a letter: {name!r}"
            )
        props = parameters if parameters is not None else {}
        if not isinstance(props, dict) or not all(isinstance(v, dict) for v in props.values()):
            raise ValueError("parameters must map argument names to JSON schemas")
        missing = [r for r in required if r not in props]
        if missing:
            raise ValueError(f"required names no parameter: {missing}")
        full = f"ext_{self.info.module_name}__{name}"[:64]
        tool = FunctionTool(
            name=full, description=f"[{self.info.name}] {description}"[:2000],
            schema={"type": "object", "properties": dict(props), "required": list(required)},
            handler=handler, write=bool(writes), always_ask=bool(writes),
            alive=lambda: self._host._loaded.get(self.info.ext_id, (None, None))[1] is self,
        )
        self._reg.agent_tools = [t for t in self._reg.agent_tools if t.name != full] + [tool]
        self._host.agent_tools_changed.emit()
        return full

    def add_agent_topic(self, title: str, task: str, *, description: str = "",
                        mode: str | None = None, needs: tuple[str, ...] = ()) -> None:
        """A prepared task in every Agent tab's Topics menu (core.agent_topics:
        ``{folder}`` and ``{backend}`` are filled in)."""
        from core.agent_topics import Topic

        self._reg.agent_topics.append(Topic(str(title)[:80], str(task), str(description)[:200],
                                            mode, tuple(needs), source=self.info.ext_id))
        self._host.agent_tools_changed.emit()

    def on_agent_event(self, callback: Callable[[str, dict], Any]) -> None:
        """Call *callback(session id, event)* on the GUI thread for every
        event of every Agent tab: run_started, reasoning (the model's
        thinking), assistant, tool_call, tool_result, confirmation, usage,
        connection (a request to the LLM: trying, connected, failed,
        cancelled), run_finished, ..."""
        self._reg.agent_handlers.append(callback)

    def _agent_dock(self):
        dock = getattr(self._host.window, "_agent_dock", None)
        if dock is None:
            raise RuntimeError("this window has no Agent panel")
        return dock

    def run_agent(self, task: str, *, folder: str | None = None, mode: str | None = None,
                  on_done: Callable[[str, str], Any] | None = None) -> str:
        """Start *task* in a new Agent tab (with this extension's tools) and
        return the tab's session id. *on_done(answer, error)* runs on the GUI
        thread when the task ends ("" for the one that is not there)."""
        done = None
        if on_done is not None:
            def done(answer, error, _cb=on_done):
                self._host.call(self, _cb, answer, error)
        tab = self._agent_dock().start_task(str(task), folder=folder, mode=mode,
                                            groups=(f"ext:{self.info.ext_id}",), on_done=done)
        return tab.session.id

    def open_agent_tab(self, task: str = "", *, folder: str | None = None) -> str:
        """A new Agent tab with *task* typed in but not sent; its session id."""
        dock = self._agent_dock()
        dock.show()
        tab = dock.new_tab(task=str(task) or None, folder=folder)
        return tab.session.id

    # -- helpers --------------------------------------------------------------
    def current(self) -> ExtensionContext | None:
        """The active pane's context, or None without a file pane."""
        pane = getattr(self._host.window, "_active_pane", None)
        return context_of(pane) if pane is not None else None

    def drop_context(self, mime) -> ExtensionContext | None:
        """What a drag & drop of *mime* onto an extension's widget is about:
        for a file pane drag the source pane's backend and the dragged paths
        (a local pane that has closed meanwhile still means the local disk;
        a remote one's connection is gone: None), for ``file://`` URLs from
        another program the local disk. None for anything else. Parsing
        only - no filesystem call, safe in drop handlers."""
        import os

        from core.local_fs import LocalFS
        from ui.file_pane import decode_transfer_payload

        if mime is None:
            return None
        payload = decode_transfer_payload(mime)
        if payload is not None:
            paths = tuple(payload["paths"])
            if not paths:
                return None
            find = getattr(self._host.window, "_pane_by_id", None)
            pane = find(payload["source_pane_id"]) if callable(find) else None
            if pane is not None:
                return ExtensionContext(backend=pane.backend, folder=pane.current_path,
                                        paths=paths, pane=pane)
            if payload.get("filesystem") == "Local":
                return ExtensionContext(backend=LocalFS(), folder=os.path.dirname(paths[0]),
                                        paths=paths)
            return None
        if mime.hasUrls():
            paths = tuple(u.toLocalFile() for u in mime.urls() if u.isLocalFile())
            if paths:
                return ExtensionContext(backend=LocalFS(), folder=os.path.dirname(paths[0]),
                                        paths=paths)
        return None

    def notify(self, text: str, timeout_ms: int = 5000) -> None:
        bar = self._host.window.statusBar()
        if bar is not None:
            bar.showMessage(f"{self.info.name}: {text}", timeout_ms)

    def run_in_background(
        self,
        work: Callable[[], Any],
        *,
        on_done: Callable[[Any], Any] | None = None,
        on_error: Callable[[BaseException], Any] | None = None,
    ) -> None:
        """Run *work()* on a worker thread; *on_done(result)* or
        *on_error(exc)* then run on the GUI thread. Without *on_error* a
        failure is reported like any other extension error. Results that
        arrive after the extension was switched off are dropped."""
        self._host.run_in_background(self, work, on_done, on_error)

    # -- host side ------------------------------------------------------------
    def _remove_all(self) -> None:
        had_agent = bool(self._reg.agent_tools or self._reg.agent_topics)
        for action in self._reg.actions:
            for widget in action.associatedObjects():
                if isinstance(widget, QMenu):
                    widget.removeAction(action)
        removed = getattr(self._host.window, "extension_panel_removed", None)
        for dock in self._reg.docks:
            if callable(removed):
                removed(dock)  # out of its workspace, its place kept
            self._host.window.removeDockWidget(dock)
            dock.deleteLater()
        self._reg = _Registered()
        self._pause_action = None
        if had_agent:
            self._host.agent_tools_changed.emit()


class ExtensionHost(QObject):
    """Loads the switched-on extensions into *window*."""

    _result = pyqtSignal(object, object, object, object)  # api, callback, value, is_error
    #: An extension added or lost agent tools or topics.
    agent_tools_changed = pyqtSignal()

    def __init__(self, window, menu: QMenu) -> None:
        super().__init__(window)
        global _ACTIVE_HOST
        self.window = window
        self.menu = menu
        self._fixed = list(menu.actions())  # Manage / Open folder / Reload
        self._separator = menu.addSeparator()
        self._loaded: dict[str, tuple[Any, ExtensionAPI]] = {}
        self._errors: dict[str, str] = {}
        #: Paused extensions (persisted in extensions.json) and the events
        #: each one missed while paused, for the catch-up on resume.
        self._paused: set[str] = EX.paused_ids()
        self._missed: dict[str, set[str]] = {}
        #: Extensions skipped at this start, for the notice once the window
        #: is up; suspensions that could not be saved (still honoured now).
        self._pending_notices: list[EX.ExtensionInfo] = []
        self._unsaved_suspended: set[str] = set()
        self._result.connect(self._deliver)
        _ACTIVE_HOST = weakref.ref(self)

    # -- state ----------------------------------------------------------------
    def menu_section(self) -> QMenu:
        return self.menu

    def module(self, ext_id: str):
        entry = self._loaded.get(ext_id)
        return entry[0] if entry else None

    def error(self, ext_id: str) -> str:
        return self._errors.get(ext_id, "")

    def docks(self, ext_id: str) -> list[QDockWidget]:
        entry = self._loaded.get(ext_id)
        return list(entry[1]._reg.docks) if entry else []

    def loaded_ids(self) -> list[str]:
        return list(self._loaded)

    # -- pause ------------------------------------------------------------------
    def is_paused(self, ext_id: str) -> bool:
        return ext_id in self._paused

    def set_paused(self, ext_id: str, paused: bool) -> bool:
        """Hold back (or deliver again) the pane events of a loaded
        extension, so its panel stops reloading on every folder or
        selection change. Resuming sends each event it missed once, with
        the active pane's current state. The state is kept in
        extensions.json; False if *ext_id* is not loaded."""
        from core.i18n import tr

        if ext_id not in self._loaded:
            return False
        paused = bool(paused)
        if paused != (ext_id in self._paused):
            if paused:
                self._paused.add(ext_id)
            else:
                self._paused.discard(ext_id)
            try:
                EX.set_paused(ext_id, paused)
            except OSError as exc:
                log.warning("Pause state of %s not saved: %s", ext_id, exc)
                bar = self.window.statusBar()
                if bar is not None:
                    bar.showMessage(
                        tr("Pause state not saved: {error}").format(error=exc), 10000
                    )
        self._show_paused(ext_id)
        if not paused:
            self._catch_up(ext_id)
        return True

    def _show_paused(self, ext_id: str) -> None:
        entry = self._loaded.get(ext_id)
        if entry is None:
            return
        api = entry[1]
        paused = ext_id in self._paused
        for dock in api._reg.docks:
            bar = dock.titleBarWidget()
            if hasattr(bar, "set_paused"):
                bar.set_paused(paused)
        if api._pause_action is not None:
            api._pause_action.setChecked(paused)

    def _catch_up(self, ext_id: str) -> None:
        missed = self._missed.pop(ext_id, set())
        pane = getattr(self.window, "_active_pane", None)
        entry = self._loaded.get(ext_id)
        if not missed or pane is None or entry is None:
            return
        api = entry[1]
        context = context_of(pane)
        for event in _CATCH_UP_ORDER:
            if event in missed:
                for handler in list(api._reg.handlers.get(event, ())):
                    self.call(api, handler, context)

    def _add_pause_action(self, api: ExtensionAPI) -> None:
        """A checkable "Pause <name>" in the Extensions menu, for an
        extension with panels or event handlers - pausing anything else
        would change nothing."""
        from core.i18n import tr

        if not (api._reg.docks or api._reg.handlers):
            return
        ext_id = api.info.ext_id
        action = QAction(tr("Pause {name}").format(name=api.info.name), self.window)
        action.setCheckable(True)
        action.setChecked(ext_id in self._paused)
        action.setProperty("axPauseExtension", ext_id)
        action.setToolTip(tr("No folder and selection changes reach it while paused"))
        action.triggered.connect(lambda checked: self.set_paused(ext_id, bool(checked)))
        self.menu_section().addAction(action)
        api._reg.actions.append(action)
        api._pause_action = action

    # -- load / unload ----------------------------------------------------------
    def load_enabled(self, *, user_request: bool = False) -> None:
        """Load the switched-on extensions. At the start (the default) an
        extension an earlier start stopped in (core.extensions' startup
        guard) is skipped with a notice once the window is up, and safe
        mode loads none. *user_request* (Reload) loads them all, a
        suspended one included: that is the user's new try."""
        enabled = EX.enabled_ids()
        if not user_request:
            self._suspend_stale(enabled)
        suspended = EX.suspended_ids() | self._unsaved_suspended
        skipped: list[EX.ExtensionInfo] = []
        safe = EX.safe_mode() and not user_request
        for info in EX.discover():
            if info.ext_id not in enabled or info.ext_id in self._loaded:
                continue
            if safe:
                self._errors[info.ext_id] = "not loaded: safe mode (--safe-mode)"
                continue
            if info.ext_id in suspended and not user_request:
                self._errors[info.ext_id] = (
                    "not loaded: an earlier start stopped while activating it "
                    "(it hung or crashed); Try Again in the notice, or Reload, loads it"
                )
                skipped.append(info)
                continue
            if info.ext_id in suspended:
                self._unsuspend(info.ext_id)
            self.load(info)
        if safe and enabled:
            from core.i18n import tr

            log.info("Safe mode: no extension loaded (%d switched on)", len(enabled))
            self._status(tr("Safe mode: no extension was loaded."), 10000)
        if skipped:
            self._pending_notices.extend(skipped)
            # Once the event loop runs: the window is shown by then.
            QTimer.singleShot(0, self._show_start_notices)

    def _suspend_stale(self, enabled: set[str]) -> None:
        """Turn the markers of earlier processes into suspensions."""
        for entry in EX.collect_stale_activations():
            ext_id = entry["ext_id"]
            if ext_id not in enabled:
                log.info("Startup guard: %s was switched off since process %s stopped in it",
                         ext_id, entry["pid"])
                continue
            what = ("ended (hung and was killed, or crashed) while activating"
                    if entry["reason"] == "ended" else
                    f"still runs, but has been activating for more than "
                    f"{EX.HUNG_ACTIVATION_SECONDS:g} s")
            log.warning(
                "Startup guard: process %s %s the extension %s (%s), activation started "
                "%s; it stays switched on but is not loaded at the start until tried again",
                entry["pid"], what, entry["name"], ext_id,
                time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(entry["started"])),
            )
            try:
                EX.set_suspended(ext_id, True)
            except OSError as exc:
                log.warning("Suspension of %s not saved: %s", ext_id, exc)
                self._unsaved_suspended.add(ext_id)

    def _unsuspend(self, ext_id: str) -> None:
        self._unsaved_suspended.discard(ext_id)
        try:
            EX.set_suspended(ext_id, False)
        except OSError as exc:
            log.warning("Suspension of %s not cleared: %s", ext_id, exc)

    def _status(self, text: str, timeout_ms: int) -> None:
        bar = self.window.statusBar()
        if bar is not None:
            bar.showMessage(text, timeout_ms)

    def _show_start_notices(self) -> None:
        """One non-modal notice per extension skipped at this start."""
        from PyQt6.QtWidgets import QMessageBox

        from core.i18n import tr

        pending, self._pending_notices = self._pending_notices, []
        for info in pending:
            box = QMessageBox(self.window)
            box.setObjectName("axExtensionStartNotice")
            box.setIcon(QMessageBox.Icon.Warning)
            box.setWindowTitle(tr("Extension not loaded"))
            box.setText(
                tr("{name} was not loaded on this start: an earlier start of axross stopped "
                   "while activating it (it hung or crashed). It stays switched on.").format(
                       name=info.name)
            )
            box.setInformativeText(
                tr("Try Again loads it now - if it hangs again, the next start skips it again. "
                   "Keep Off switches it off; Extensions > Manage Extensions… switches it on "
                   "again. Details are in the log.")
            )
            retry = box.addButton(tr("Try Again"), QMessageBox.ButtonRole.AcceptRole)
            keep_off = box.addButton(tr("Keep Off"), QMessageBox.ButtonRole.DestructiveRole)
            box.addButton(tr("Later"), QMessageBox.ButtonRole.RejectRole)
            box.setWindowModality(Qt.WindowModality.NonModal)
            box.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose, True)

            def answered(button, ext_id=info.ext_id, retry=retry, keep_off=keep_off):
                if button is retry:
                    self.retry(ext_id)
                elif button is keep_off:
                    self.set_enabled(ext_id, False)

            box.buttonClicked.connect(answered)
            box.show()

    def retry(self, ext_id: str) -> bool:
        """Try Again for an extension skipped at the start: load it now
        (with its marker, so a new hang is caught by the next start)."""
        info = next((e for e in EX.discover() if e.ext_id == ext_id), None)
        if info is None or ext_id in self._loaded:
            return ext_id in self._loaded
        self._unsuspend(ext_id)
        self._errors.pop(ext_id, None)
        return self.load(info)

    def reload(self) -> None:
        """Unload everything and load the switched-on extensions anew, from
        their current source."""
        self.unload_all()
        self._errors.clear()
        self.load_enabled(user_request=True)

    def set_enabled(self, ext_id: str, on: bool) -> None:
        EX.set_enabled(ext_id, on)  # clears a suspension too
        self._unsaved_suspended.discard(ext_id)
        if on:
            info = next((e for e in EX.discover() if e.ext_id == ext_id), None)
            if info is not None and ext_id not in self._loaded:
                self._errors.pop(ext_id, None)
                self.load(info)
        else:
            self.unload(ext_id)
            self._errors.pop(ext_id, None)

    def load(self, info: EX.ExtensionInfo) -> bool:
        if info.error:
            self._errors[info.ext_id] = info.error
            return False
        if not EX.extensions_allowed():
            self._errors[info.ext_id] = "blocked by the paranoid security mode"
            return False
        api = ExtensionAPI(self, info)
        module_name = f"axross_extension_{info.source}_{info.module_name}"
        # The startup guard: a marker while the extension's code runs, so
        # a hang or crash in it is found by the next start.
        marker = EX.begin_activation(info)
        started = time.monotonic()
        try:
            module = _exec_source(module_name, info.path)
            module.activate(api)
        except Exception as exc:  # noqa: BLE001 - extension code
            sys.modules.pop(module_name, None)
            api._remove_all()
            self._record(api, exc)
            return False
        finally:
            EX.end_activation(marker)
            took = time.monotonic() - started
            if took > EX.SLOW_ACTIVATE_SECONDS:
                log.warning("Extension %s took %.2f s to activate (more than %g s)",
                            info.ext_id, took, EX.SLOW_ACTIVATE_SECONDS)
        self._loaded[info.ext_id] = (module, api)
        self._add_pause_action(api)
        self._show_paused(info.ext_id)
        log.info("Extension loaded: %s (%s) in %.3f s", info.name, info.ext_id, took)
        if api._reg.agent_tools or api._reg.agent_topics:
            # What activate() registered counts only now that it is loaded.
            self.agent_tools_changed.emit()
        return True

    def unload(self, ext_id: str) -> None:
        entry = self._loaded.pop(ext_id, None)
        if entry is None:
            return
        module, api = entry
        self._missed.pop(ext_id, None)
        deactivate = getattr(module, "deactivate", None)
        if callable(deactivate):
            self.call(api, deactivate, api)
        api._remove_all()
        sys.modules.pop(f"axross_extension_{api.info.source}_{api.info.module_name}", None)
        log.info("Extension unloaded: %s", ext_id)

    def unload_all(self) -> None:
        for ext_id in list(self._loaded):
            self.unload(ext_id)

    # -- calling extension code ------------------------------------------------
    def call(self, api: ExtensionAPI, fn: Callable, *args) -> Any:
        try:
            return fn(*args)
        except Exception as exc:  # noqa: BLE001 - extension code
            self._record(api, exc)
            return None

    def _record(self, api: ExtensionAPI, exc: BaseException) -> None:
        text = f"{type(exc).__name__}: {exc}"
        self._errors[api.info.ext_id] = text
        log.error(
            "Extension %s failed: %s\n%s",
            api.info.ext_id,
            text,
            "".join(traceback.format_exception(exc)).rstrip(),
        )
        bar = self.window.statusBar()
        if bar is not None:
            bar.showMessage(f"Extension {api.info.name} failed: {text}", 10000)

    def emit(self, event: str, pane) -> None:
        """Tell every subscribed extension about *event* on *pane*."""
        if not self._loaded or pane is None:
            return
        context = None
        for ext_id, (_module, api) in list(self._loaded.items()):
            handlers = api._reg.handlers.get(event, ())
            if handlers and ext_id in self._paused:
                self._missed.setdefault(ext_id, set()).add(event)
                continue
            for handler in handlers:
                if context is None:
                    context = context_of(pane)
                self.call(api, handler, context)

    # -- the agent ------------------------------------------------------------------
    def emit_agent_event(self, session_id: str, event: dict) -> None:
        for _module, api in list(self._loaded.values()):
            for handler in list(api._reg.agent_handlers):
                self.call(api, handler, session_id, dict(event))

    def agent_tool_owners(self) -> list[tuple[str, str]]:
        """``(ext_id, name)`` of the loaded extensions with agent tools."""
        return [
            (ext_id, api.info.name)
            for ext_id, (_m, api) in self._loaded.items()
            if api._reg.agent_tools
        ]

    def agent_tools(self, ext_ids) -> list:
        wanted = set(ext_ids)
        return [t for ext_id, (_m, api) in self._loaded.items() if ext_id in wanted
                for t in api._reg.agent_tools]

    def agent_topics(self) -> list:
        return [t for _m, api in self._loaded.values() for t in api._reg.agent_topics]

    def run_in_background(self, api, work, on_done, on_error) -> None:
        def runner():
            try:
                value, failed = work(), False
            except Exception as exc:  # noqa: BLE001 - extension code
                value, failed = exc, True
            try:
                self._result.emit(api, (on_done, on_error), value, failed)
            except RuntimeError:  # the host is gone
                pass

        threading.Thread(target=runner, name=f"ext-{api.info.module_name}", daemon=True).start()

    def _deliver(self, api, callbacks, value, failed) -> None:
        if self._loaded.get(api.info.ext_id, (None, None))[1] is not api:
            return  # switched off (or reloaded) meanwhile
        on_done, on_error = callbacks
        if failed:
            if on_error is not None:
                self.call(api, on_error, value)
            else:
                self._record(api, value)
        elif on_done is not None:
            self.call(api, on_done, value)

    # -- the pane's right-click menu ----------------------------------------------
    def add_context_actions(self, pane, menu: QMenu) -> None:
        entries = []
        context = None
        for _module, api in self._loaded.values():
            for label, callback, applies_to, suffixes in api._reg.context:
                if context is None:
                    context = context_of(pane)
                if _applies(context, applies_to, suffixes):
                    entries.append((api, label, callback))
        if not entries:
            return
        menu.addSeparator()
        for api, label, callback in entries:
            action = menu.addAction(label)
            action.triggered.connect(
                lambda _checked=False, a=api, cb=callback, c=context: self.call(a, cb, c)
            )


def _exec_source(module_name: str, path: str) -> types.ModuleType:
    """Run the extension's current source as a module.

    Compiled straight from the file, never from ``__pycache__``: a source
    rewritten within the same second at the same size kept its old byte
    code, so Reload ran the previous version. No byte code is written
    into the user's extension folder either.
    """
    source = Path(path).read_bytes()
    module = types.ModuleType(module_name)
    module.__file__ = path
    if path.endswith("__init__.py"):
        module.__path__ = [str(Path(path).parent)]  # its own submodules import
        module.__package__ = module_name
    sys.modules[module_name] = module
    exec(compile(source, path, "exec", dont_inherit=True), module.__dict__)  # noqa: S102
    return module


def _applies(ctx: ExtensionContext, applies_to: str, suffixes: tuple[str, ...]) -> bool:
    items = [i for i in ctx.items if getattr(i, "name", "") != ".."]
    files = [i for i in items if not i.is_dir]
    folders = [i for i in items if i.is_dir]
    if suffixes and files and not all(i.name.lower().endswith(suffixes) for i in files):
        return False
    if applies_to == "any":
        return True
    if applies_to == "folder":
        return not items
    if applies_to == "selection":
        return bool(items)
    if applies_to == "files":
        return bool(files) and not folders
    if applies_to == "folders":
        return bool(folders) and not files
    if applies_to == "single_file":
        return len(files) == 1 and not folders
    if applies_to == "single_folder":
        return len(folders) == 1 and not files
    return False


def add_context_actions(pane, menu: QMenu) -> None:
    """Called by the file pane at the end of its right-click menu."""
    host = _ACTIVE_HOST() if _ACTIVE_HOST is not None else None
    if host is not None:
        try:
            host.add_context_actions(pane, menu)
        except Exception:  # noqa: BLE001 - the menu must open regardless
            log.warning("Extension context actions failed", exc_info=True)


__all__ = [
    "APPLIES_TO",
    "EVENTS",
    "ExtensionAPI",
    "ExtensionContext",
    "ExtensionHost",
    "add_context_actions",
    "context_of",
]
