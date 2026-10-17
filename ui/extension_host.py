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
import traceback
import types
import weakref
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from PyQt6.QtCore import QObject, Qt, pyqtSignal
from PyQt6.QtGui import QAction, QKeySequence
from PyQt6.QtWidgets import QDockWidget, QMenu, QWidget

from core import extensions as EX

log = logging.getLogger(__name__)

#: Events an extension can subscribe to with ``api.on``.
EVENTS = ("selection_changed", "path_changed", "pane_activated")
#: What a context action can apply to (``applies_to``).
APPLIES_TO = ("any", "folder", "selection", "files", "folders", "single_file")
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
        ``folders`` (only files / only folders selected), ``single_file``.
        *extensions* (``(".md", ".txt")``) limits file entries by name.
        """
        if applies_to not in APPLIES_TO:
            raise ValueError(f"applies_to must be one of {APPLIES_TO}, not {applies_to!r}")
        suffixes = tuple(str(e).lower() for e in extensions)
        self._reg.context.append((str(label), callback, applies_to, suffixes))

    def add_dock(self, title: str, widget: QWidget) -> QDockWidget:
        """A panel docked on the right; its show/hide entry goes into the
        Extensions menu."""
        window = self._host.window
        dock = QDockWidget(str(title), window)
        dock.setObjectName(f"extension-dock-{self.info.ext_id}-{len(self._reg.docks)}")
        dock.setWidget(widget)
        window.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, dock)
        toggle = dock.toggleViewAction()
        self._host.menu_section().addAction(toggle)
        self._reg.actions.append(toggle)
        self._reg.docks.append(dock)
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
        event of every Agent tab: run_started, assistant, tool_call,
        tool_result, confirmation, usage, run_finished, ..."""
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
        for dock in self._reg.docks:
            self._host.window.removeDockWidget(dock)
            dock.deleteLater()
        self._reg = _Registered()
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

    # -- load / unload ----------------------------------------------------------
    def load_enabled(self) -> None:
        enabled = EX.enabled_ids()
        for info in EX.discover():
            if info.ext_id in enabled and info.ext_id not in self._loaded:
                self.load(info)

    def reload(self) -> None:
        """Unload everything and load the switched-on extensions anew, from
        their current source."""
        self.unload_all()
        self._errors.clear()
        self.load_enabled()

    def set_enabled(self, ext_id: str, on: bool) -> None:
        EX.set_enabled(ext_id, on)
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
        try:
            module = _exec_source(module_name, info.path)
            module.activate(api)
        except Exception as exc:  # noqa: BLE001 - extension code
            sys.modules.pop(module_name, None)
            api._remove_all()
            self._record(api, exc)
            return False
        self._loaded[info.ext_id] = (module, api)
        log.info("Extension loaded: %s (%s)", info.name, info.ext_id)
        if api._reg.agent_tools or api._reg.agent_topics:
            # What activate() registered counts only now that it is loaded.
            self.agent_tools_changed.emit()
        return True

    def unload(self, ext_id: str) -> None:
        entry = self._loaded.pop(ext_id, None)
        if entry is None:
            return
        module, api = entry
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
        for _module, api in list(self._loaded.values()):
            for handler in api._reg.handlers.get(event, ()):
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
