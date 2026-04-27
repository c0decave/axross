"""Embedded Python REPL widget — a Console tab in the bottom dock.

Drives a stdlib :class:`code.InteractiveConsole` from a Qt widget so
the user can script axross interactively. The REPL globals are
pre-populated with the curated :mod:`core.scripting` surface re-exported
as ``axross``, so a fresh prompt looks like::

    >>> axross.help()
    >>> b = axross.localfs()
    >>> b.list_dir("/etc")[:5]

Features:

* Multi-line input (``...`` continuation) via InteractiveConsole.
* Up / Down history nav, persisted to
  ``~/.config/axross/repl_history`` between runs.
* Tab completion via stdlib :mod:`rlcompleter` over the live
  globals (no external dep).
* stdout / stderr captured per statement and rendered in the
  console buffer so prints land in the REPL, not in the parent
  terminal.

Why no external `jedi` dep: rlcompleter is good enough for the
"name → attributes" + "module.attribute" path and ships with Python.
A ``jedi``-powered upgrade is a clean follow-up.
"""
from __future__ import annotations

import code
import contextlib
import io
import logging
import os
import sys
import traceback
from pathlib import Path

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont, QKeyEvent, QTextCursor
from PyQt6.QtWidgets import (
    QDockWidget,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPlainTextEdit,
    QSplitter,
    QTabWidget,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

log = logging.getLogger(__name__)

PROMPT = ">>> "
PROMPT_CONT = "... "

# Where REPL history lives across runs. ~/.config/axross/repl_history.
HISTORY_PATH = Path.home() / ".config" / "axross" / "repl_history"

# Cap on persisted history lines (so a chatty user doesn't grow this
# unbounded). Newest entries are kept.
HISTORY_LIMIT = 1000
# Compact (rewrite the file truncated to HISTORY_LIMIT) every N
# appends so it can't grow without bound between sessions.
COMPACT_EVERY_N = 200

# Maximum console buffer size before we trim the head. A loop like
# ``for _ in range(10**8): print('x')`` would otherwise lock the Qt
# widget while we keep appending. Mirrors the terminal widget's
# TERMINAL_BUFFER_CAP_BYTES so the two docks behave consistently.
CONSOLE_BUFFER_CAP_CHARS = 4 * 1024 * 1024
# When trimming, keep this much of the tail (= the recent stuff a
# user actually cares about).
CONSOLE_BUFFER_TAIL_CHARS = 2 * 1024 * 1024


def _build_globals() -> dict:
    """Build the namespace handed to the InteractiveConsole. Includes
    the curated :mod:`core.scripting` surface re-exported as ``axross``
    plus a few common stdlib aliases the user almost always wants."""
    import core.scripting as _scripting
    return {
        "__name__": "__axross_repl__",
        "__doc__": "Axross embedded REPL — see axross.help()",
        "axross": _scripting,
    }


class _RlCompleter:
    """Side-effect-free completer.

    Stdlib :class:`rlcompleter.Completer` walks attributes via
    :func:`getattr`, which fires ``@property`` descriptors as a side
    effect. Tab is a *passive* keypress — the user expects no code
    execution from it. We avoid getattr entirely by inspecting each
    object's :attr:`__dict__` / :attr:`__slots__` and class MRO,
    which yields the same list of completable names without invoking
    any descriptors.
    """

    def __init__(self, namespace: dict):
        self._namespace = namespace

    def matches(self, prefix: str) -> list[str]:
        if "." in prefix:
            head, _, tail = prefix.rpartition(".")
            obj = self._safe_lookup(head)
            if obj is None:
                return []
            attrs = self._collect_attrs(obj)
            hits = sorted({n for n in attrs if n.startswith(tail)})
            return [f"{head}.{n}" for n in hits]
        # Bare-name completion: union of namespace + builtins.
        import builtins
        candidates = set(self._namespace) | set(dir(builtins))
        candidates = {c for c in candidates if not c.startswith("__")}
        return sorted(c for c in candidates if c.startswith(prefix))

    def _safe_lookup(self, dotted: str):
        """Walk ``a.b.c`` through the namespace using ``__dict__``
        only. Returns the resolved object or None if any step is
        missing."""
        parts = dotted.split(".")
        obj = self._namespace.get(parts[0])
        if obj is None:
            return None
        for name in parts[1:]:
            obj = self._dict_lookup(obj, name)
            if obj is None:
                return None
        return obj

    @staticmethod
    def _dict_lookup(obj, name: str):
        # Try the instance __dict__ first.
        d = getattr(type(obj), "__dict__", {})
        if name in d:
            return d[name]
        inst_dict = getattr(obj, "__dict__", None)
        if isinstance(inst_dict, dict) and name in inst_dict:
            return inst_dict[name]
        # Walk the class MRO via __dict__ only — never via getattr.
        for klass in getattr(type(obj), "__mro__", ()):
            kd = getattr(klass, "__dict__", {})
            if name in kd:
                return kd[name]
        return None

    @staticmethod
    def _collect_attrs(obj) -> set[str]:
        out: set[str] = set()
        # Module-style objects have a __dict__ that's the source of truth.
        d = getattr(obj, "__dict__", None)
        if isinstance(d, dict):
            out.update(d.keys())
        # Class-bound names via the MRO — descriptors stay un-fired.
        for klass in getattr(type(obj), "__mro__", ()):
            kd = getattr(klass, "__dict__", {})
            out.update(kd.keys())
            for slot in getattr(klass, "__slots__", ()) or ():
                if isinstance(slot, str):
                    out.add(slot)
        # Strip dunders and private — REPL users rarely want those by Tab.
        return {n for n in out if not n.startswith("_")}


class ReplWidget(QPlainTextEdit):
    """Qt-embedded Python REPL.

    Append-only output area + an editable trailing input line. The
    input line starts after ``self._input_start`` — every key event
    that would touch text before that position is rejected so the
    user can't garble the scrollback.
    """

    statement_executed = pyqtSignal(str)

    def __init__(self, parent: QWidget | None = None,
                 startup_path: Path | None = None):
        super().__init__(parent)
        font = QFont("Monospace", 10)
        font.setStyleHint(QFont.StyleHint.Monospace)
        self.setFont(font)
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
        self.setUndoRedoEnabled(False)
        self.setStyleSheet(
            "QPlainTextEdit { background-color: #1a1d24; color: #d4d4d4; "
            "selection-background-color: #264f78; }"
        )

        self._globals = _build_globals()
        self._console = code.InteractiveConsole(locals=self._globals)
        self._completer = _RlCompleter(self._globals)
        self._buffer: list[str] = []  # multi-line accumulator
        self._history: list[str] = []
        self._history_idx: int | None = None
        self._history_appends_since_compact = 0
        self._input_start = 0  # cursor position where editable input begins

        self._load_history()
        self._print_banner()
        self._maybe_run_startup(startup_path)
        self._write_prompt(PROMPT)

    # ------------------------------------------------------------------
    # Banner / startup script
    # ------------------------------------------------------------------

    def _print_banner(self) -> None:
        py = sys.version.split()[0]
        self._append(
            f"Axross embedded REPL · Python {py}\n"
            "Type axross.help() for the cheat-sheet · Tab completes names · "
            "Ctrl-D / exit() to close.\n",
        )

    def _maybe_run_startup(self, startup_path: Path | None) -> None:
        path = startup_path or Path.home() / ".config" / "axross" / "startup.py"
        if not path.exists():
            return
        try:
            src = path.read_text(encoding="utf-8")
        except OSError as exc:
            self._append(f"[startup script {path} unreadable: {exc}]\n")
            return
        self._append(f"[loading startup script {path}]\n")
        self._run_source(src)

    # ------------------------------------------------------------------
    # Output helpers
    # ------------------------------------------------------------------

    def _append(self, text: str) -> None:
        cursor = self.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        cursor.insertText(text)
        self.setTextCursor(cursor)
        self._input_start = cursor.position()
        self._maybe_trim_buffer()

    def _maybe_trim_buffer(self) -> None:
        """Drop head bytes when the console buffer crosses the cap.
        We slice off the front so the most-recent output stays
        readable (matches how the terminal dock handles flooding)."""
        full = self.toPlainText()
        if len(full) <= CONSOLE_BUFFER_CAP_CHARS:
            return
        keep = full[-CONSOLE_BUFFER_TAIL_CHARS:]
        self.setPlainText(keep)
        cursor = self.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        self.setTextCursor(cursor)
        self._input_start = cursor.position()

    def _write_prompt(self, prompt: str) -> None:
        self._append(prompt)

    def _current_input(self) -> str:
        return self.toPlainText()[self._input_start:]

    def _replace_input(self, new_text: str) -> None:
        cursor = self.textCursor()
        cursor.setPosition(self._input_start)
        cursor.movePosition(
            QTextCursor.MoveOperation.End,
            QTextCursor.MoveMode.KeepAnchor,
        )
        cursor.removeSelectedText()
        cursor.insertText(new_text)
        self.setTextCursor(cursor)

    # ------------------------------------------------------------------
    # Statement execution
    # ------------------------------------------------------------------

    def _run_source(self, source: str) -> bool:
        """Feed ``source`` to the InteractiveConsole. Returns True
        when the source needs more input (open block / unclosed string)."""
        out_buf = io.StringIO()
        err_buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(out_buf), contextlib.redirect_stderr(err_buf):
                more = self._console.runsource(source, "<repl>")
        except SystemExit:
            self._append("\n[REPL: exit() requested]\n")
            return False
        except BaseException:  # noqa: BLE001 — show the exception inline
            err_buf.write(traceback.format_exc())
            more = False
        out_text = out_buf.getvalue()
        err_text = err_buf.getvalue()
        if out_text:
            self._append(out_text)
            if not out_text.endswith("\n"):
                self._append("\n")
        if err_text:
            # Tee REPL exceptions to the logger so they survive a
            # buffer trim and land in axross.log alongside everything
            # else. Inline rendering remains the primary surface.
            log.warning("REPL exception:\n%s", err_text.rstrip())
            self._append(err_text)
            if not err_text.endswith("\n"):
                self._append("\n")
        return bool(more)

    def _submit_current(self) -> None:
        line = self._current_input()
        # End the current input line in the buffer first.
        self._append("\n")
        self._buffer.append(line)
        if line.strip():
            # Keep history dedup-friendly (don't store consecutive dupes).
            if not self._history or self._history[-1] != line:
                self._history.append(line)
                self._append_history(line)
        self._history_idx = None

        # Slash commands run BEFORE the InteractiveConsole gets the
        # source so users get a tight, side-effect-free shortcut
        # vocabulary that doesn't pollute the Python namespace.
        # The dispatcher returns True if it handled the line; we then
        # short-circuit the normal exec path.
        if self._maybe_dispatch_slash(line.strip()):
            self._buffer = []
            self._write_prompt(PROMPT)
            self.statement_executed.emit(line)
            return

        source = "\n".join(self._buffer)
        more = self._run_source(source)
        if not more:
            self._buffer = []
            self._write_prompt(PROMPT)
        else:
            self._write_prompt(PROMPT_CONT)
        self.statement_executed.emit(line)

    # ------------------------------------------------------------------
    # Slash commands — REPL-only shortcuts, no Python namespace impact
    # ------------------------------------------------------------------

    _SLASH_HELP = """\
REPL slash commands (typed at the prompt; not Python):
  .help                       this list
  .scripts                    list saved scripts
  .save <name>                save the last submitted statement(s)
  .load <name>                paste a saved script into the prompt
  .run <name>                 execute a saved script in the live namespace
  .delete <name>              remove a saved script
  .open                       open the script directory in your file mgr
"""

    def _maybe_dispatch_slash(self, text: str) -> bool:
        if not text.startswith("."):
            return False
        cmd, _, arg = text[1:].partition(" ")
        cmd = cmd.strip().lower()
        arg = arg.strip()
        if cmd == "help":
            self._append(self._SLASH_HELP)
            return True
        if cmd == "scripts":
            from core import scripting as _s
            names = _s.list_scripts()
            self._append("(no saved scripts)\n" if not names
                         else "  " + "\n  ".join(names) + "\n")
            return True
        if cmd == "save":
            if not arg:
                self._append("usage: .save <name>\n")
                return True
            # Save every line we've submitted in this session, joined
            # with newlines. Strips any leading slash command lines
            # so the saved script is pure Python.
            source = "\n".join(
                h for h in self._history if not h.lstrip().startswith(".")
            ) + "\n"
            from core import scripting as _s
            try:
                path = _s.save_script(arg, source)
                self._append(f"saved → {path}\n")
            except (OSError, ValueError) as exc:
                self._append(f"save failed: {exc}\n")
            return True
        if cmd == "load":
            if not arg:
                self._append("usage: .load <name>\n")
                return True
            from core import scripting as _s
            try:
                src = _s.load_script(arg)
            except OSError as exc:
                self._append(f"load failed: {exc}\n")
                return True
            self._append(f"--- {arg} ---\n{src}\n")
            return True
        if cmd == "run":
            if not arg:
                self._append("usage: .run <name>\n")
                return True
            from core import scripting as _s
            try:
                # Run inside the LIVE InteractiveConsole namespace so
                # variables it sets become visible to subsequent prompts.
                src = _s.load_script(arg)
            except OSError as exc:
                self._append(f"run failed: {exc}\n")
                return True
            # Feed via the same _run_source path so stdout / errors
            # render in the console buffer.
            self._run_source(src)
            return True
        if cmd == "delete":
            if not arg:
                self._append("usage: .delete <name>\n")
                return True
            from core import scripting as _s
            try:
                _s.delete_script(arg)
                self._append(f"deleted {arg}\n")
            except (OSError, ValueError) as exc:
                self._append(f"delete failed: {exc}\n")
            return True
        if cmd == "open":
            from core import scripting as _s
            self._append(f"script dir: {_s.script_dir()}\n")
            return True
        # Unknown slash command — fall through to Python so a typo
        # like ``.5`` (float literal) still gets parsed normally.
        return False

    # ------------------------------------------------------------------
    # History persistence
    # ------------------------------------------------------------------

    def _load_history(self) -> None:
        if not HISTORY_PATH.exists():
            return
        try:
            text = HISTORY_PATH.read_text(encoding="utf-8")
        except OSError as exc:
            log.debug("cannot read REPL history: %s", exc)
            return
        self._history = [
            line for line in text.splitlines() if line.strip()
        ][-HISTORY_LIMIT:]

    def _append_history(self, line: str) -> None:
        """Append-only single-line write. Cheap (one O_APPEND write per
        submitted statement) compared to rewriting the entire history.
        Compaction runs every COMPACT_EVERY_N submits to keep the on-
        disk file from growing past HISTORY_LIMIT × line-length."""
        try:
            HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
            payload = (line.replace("\n", " ") + "\n").encode("utf-8")
            fd = os.open(
                HISTORY_PATH,
                os.O_WRONLY | os.O_CREAT | os.O_APPEND,
                0o600,
            )
            try:
                os.write(fd, payload)
            finally:
                os.close(fd)
            self._history_appends_since_compact += 1
            if self._history_appends_since_compact >= COMPACT_EVERY_N:
                self._compact_history_file()
                self._history_appends_since_compact = 0
        except OSError as exc:
            log.debug("cannot append REPL history: %s", exc)

    def _compact_history_file(self) -> None:
        """Rewrite the history file with only the last HISTORY_LIMIT
        entries. Atomic via rename so a crash mid-compact can't corrupt
        the file. Mode is 0o600 from the start (created with that mode,
        re-applied on the rename target)."""
        try:
            tail = self._history[-HISTORY_LIMIT:]
            payload = ("\n".join(tail) + "\n").encode("utf-8") if tail else b""
            tmp_path = HISTORY_PATH.with_suffix(HISTORY_PATH.suffix + ".tmp")
            fd = os.open(
                tmp_path,
                os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                0o600,
            )
            try:
                os.write(fd, payload)
            finally:
                os.close(fd)
            os.replace(tmp_path, HISTORY_PATH)
            try:
                os.chmod(HISTORY_PATH, 0o600)
            except OSError:
                pass
        except OSError as exc:
            log.debug("cannot compact REPL history: %s", exc)

    # ------------------------------------------------------------------
    # Tab completion
    # ------------------------------------------------------------------

    def _tab_complete(self) -> None:
        line = self._current_input()
        # Find the completion prefix: walk backwards from end while
        # the char is part of an identifier or a dot.
        i = len(line)
        while i > 0 and (line[i - 1].isalnum() or line[i - 1] in "._"):
            i -= 1
        prefix = line[i:]
        if not prefix:
            # Insert four spaces — matches the typical "Tab to indent"
            # behaviour inside continuation lines.
            self._replace_input(line + "    ")
            return
        matches = self._completer.matches(prefix)
        if not matches:
            return
        if len(matches) == 1:
            # Single match → replace the prefix in-place.
            new_line = line[:i] + matches[0]
            self._replace_input(new_line)
            return
        # Multiple matches → write them, then re-prompt with what the
        # user had typed.
        self._append("\n" + "  ".join(matches) + "\n")
        prompt = PROMPT_CONT if self._buffer else PROMPT
        self._write_prompt(prompt)
        self._append(line)

    # ------------------------------------------------------------------
    # Key handling — the core widget contract
    # ------------------------------------------------------------------

    def keyPressEvent(self, event: QKeyEvent) -> None:  # noqa: N802 — Qt
        cursor_pos = self.textCursor().position()
        # Reject any edit before the input start.
        if cursor_pos < self._input_start and event.key() not in (
            Qt.Key.Key_Right, Qt.Key.Key_Left,
            Qt.Key.Key_Up, Qt.Key.Key_Down,
            Qt.Key.Key_Home, Qt.Key.Key_End,
        ):
            cursor = self.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.End)
            self.setTextCursor(cursor)

        key = event.key()
        if key in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
            self._submit_current()
            return
        if key == Qt.Key.Key_Tab:
            self._tab_complete()
            return
        if key == Qt.Key.Key_Up:
            self._history_prev()
            return
        if key == Qt.Key.Key_Down:
            self._history_next()
            return
        if key == Qt.Key.Key_Home:
            cursor = self.textCursor()
            cursor.setPosition(self._input_start)
            self.setTextCursor(cursor)
            return
        if key == Qt.Key.Key_Backspace:
            # Don't let the user backspace into the prompt.
            if self.textCursor().position() <= self._input_start:
                return
        if key == Qt.Key.Key_D and event.modifiers() & Qt.KeyboardModifier.ControlModifier:
            # Ctrl-D on an empty line clears the multi-line buffer or
            # signals a graceful "exit()" if the prompt is fresh.
            if not self._current_input().strip():
                if self._buffer:
                    self._buffer = []
                    self._append("\n")
                    self._write_prompt(PROMPT)
                else:
                    self._append("\n[REPL: Ctrl-D]\n")
            return
        super().keyPressEvent(event)

    # ------------------------------------------------------------------
    # History navigation
    # ------------------------------------------------------------------

    def _history_prev(self) -> None:
        if not self._history:
            return
        if self._history_idx is None:
            self._history_idx = len(self._history) - 1
        else:
            self._history_idx = max(0, self._history_idx - 1)
        self._replace_input(self._history[self._history_idx])

    def _history_next(self) -> None:
        if not self._history or self._history_idx is None:
            return
        self._history_idx += 1
        if self._history_idx >= len(self._history):
            self._history_idx = None
            self._replace_input("")
            return
        self._replace_input(self._history[self._history_idx])


class _ApiTab(QWidget):
    """Tab that shows every ``axross.*`` function — search box on
    top, grouped list in the middle, full docstring at the bottom.
    Same single source of truth as :func:`axross.help` and
    :func:`axross.docs`."""

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(2, 2, 2, 2)
        layout.setSpacing(2)

        self._filter = QLineEdit()
        self._filter.setPlaceholderText("Search axross.* …")
        self._filter.textChanged.connect(self._on_filter_changed)
        layout.addWidget(self._filter)

        self._list = QListWidget()
        self._list.itemSelectionChanged.connect(self._on_selection_changed)
        layout.addWidget(self._list, stretch=2)

        self._viewer = QTextBrowser()
        self._viewer.setOpenExternalLinks(False)
        layout.addWidget(self._viewer, stretch=3)

        self._populate()

    def _populate(self) -> None:
        from core.scripting import _help_entries
        self._list.clear()
        for group, items in _help_entries():
            header = QListWidgetItem(f"── {group} ──")
            header.setFlags(Qt.ItemFlag.NoItemFlags)
            self._list.addItem(header)
            for sig, summary in items:
                # ``axross.<name>`` — shown so the user can type the
                # exact identifier into the REPL.
                item = QListWidgetItem(f"  {sig}")
                item.setData(Qt.ItemDataRole.UserRole, sig)
                item.setToolTip(summary)
                self._list.addItem(item)

    def _on_filter_changed(self, text: str) -> None:
        needle = text.lower().strip()
        for i in range(self._list.count()):
            it = self._list.item(i)
            sig = it.data(Qt.ItemDataRole.UserRole)
            if sig is None:
                # Group header — show whenever its label contains the
                # filter, otherwise hide so the list stays compact.
                it.setHidden(needle not in it.text().lower() and bool(needle))
            else:
                it.setHidden(bool(needle) and needle not in sig.lower())

    def _on_selection_changed(self) -> None:
        items = self._list.selectedItems()
        if not items:
            return
        sig = items[0].data(Qt.ItemDataRole.UserRole)
        if not sig:
            return
        # sig is like "axross.open_url" — strip prefix to find the function.
        _, _, name = sig.partition(".")
        from core import scripting as _scripting
        fn = getattr(_scripting, name, None)
        if fn is None:
            self._viewer.setPlainText(f"(no function named {name})")
            return
        import inspect
        try:
            signature = str(inspect.signature(fn))
        except (TypeError, ValueError):
            signature = "(...)"
        doc = (fn.__doc__ or "(no docstring)").strip()
        # Render as plain text so the docstring's ReST-y backticks
        # don't get interpreted (we don't ship a Sphinx-style renderer).
        body = (
            f"<h3 style='margin:2px 0;'>axross.{name}{signature}</h3>"
            f"<pre style='white-space:pre-wrap;font-family:monospace;"
            f"font-size:10pt;'>{_html_escape(doc)}</pre>"
        )
        self._viewer.setHtml(body)


class _MarkdownTab(QWidget):
    """Trivial Markdown viewer for the Slash / Scripts / Backend-
    protocol tabs. We keep it minimal — Qt's QTextBrowser renders a
    sensible subset of CommonMark via :meth:`setMarkdown`, which is
    plenty for our reference docs.

    Re-renders on every ``showEvent`` so a freshly-saved REPL script
    appears in the Scripts tab without a restart, and so editing
    `~/.config/axross/scripts/` from outside refreshes when the user
    flips back to the tab."""

    def __init__(self, markdown_callable, parent: QWidget | None = None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(2, 2, 2, 2)
        self._viewer = QTextBrowser()
        self._viewer.setOpenExternalLinks(False)
        layout.addWidget(self._viewer)
        self._render_callable = markdown_callable
        self._render()

    def _render(self) -> None:
        try:
            self._viewer.setMarkdown(self._render_callable())
        except Exception as exc:  # noqa: BLE001 — never crash the dock
            # Log the traceback once so CI / stderr surfaces genuine
            # bugs in the reference renderer; the plaintext fallback
            # would otherwise hide an AttributeError forever.
            log.exception("Doc-pane Markdown render failed")
            self._viewer.setPlainText(
                f"(failed to render reference: {exc})"
            )

    def showEvent(self, event):  # noqa: N802 — Qt
        # Re-render every time the tab is brought into view. Cheap
        # (a few ms) and keeps the Scripts tab fresh after the user
        # runs ``.save foo`` from the REPL.
        self._render()
        super().showEvent(event)


class _ApiDocPane(QWidget):
    """Tabbed reference panel rendered alongside the REPL.

    Tabs:

    * **API** — every public ``axross.*`` function, searchable, with
      full docstring on click.
    * **Slash** — REPL slash-commands (``.save / .load / .run / …``).
    * **Scripts** — bundled example scripts under
      ``resources/scripts/`` with one-line summaries.
    * **Protocol** — the ``FileBackend`` interface every backend
      implements.

    All four tabs pull from :mod:`core.scripting` so adding a new
    function / script / slash-command shows up here automatically.
    """

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        self._tabs = QTabWidget()
        self._tabs.setDocumentMode(True)
        outer.addWidget(self._tabs)

        # API tab — the function-by-function reference (interactive).
        self._tabs.addTab(_ApiTab(), "API")

        # Slash / Scripts / Protocol tabs — Markdown-rendered, pulled
        # straight from axross.docs() so the source of truth is shared
        # with the headless reference and the SCRIPTING_REFERENCE.md
        # generator.
        from core import scripting as _s
        self._tabs.addTab(_MarkdownTab(lambda: _s.docs("slash")), "Slash")
        self._tabs.addTab(_MarkdownTab(lambda: _s.docs("scripts")), "Scripts")
        self._tabs.addTab(
            _MarkdownTab(lambda: _s.docs("backend")),
            "Protocol",
        )

    # The previous incarnation exposed ``self._list``; some tests poke
    # at it. Forward to the API tab's list so existing call sites
    # don't break.
    @property
    def _list(self):
        return self._tabs.widget(0)._list  # noqa: SLF001 — test bridge


def _html_escape(text: str) -> str:
    return (
        text
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


class ConsoleDock(QDockWidget):
    """Dockable container around :class:`ReplWidget` plus an API
    documentation panel rendered side-by-side via QSplitter. Mirrors
    the interface (``activity`` signal, allowed-areas) used by
    :class:`TerminalDock` / :class:`LogDock` so the MainWindow's
    tab-highlight plumbing works without special-casing."""

    activity = pyqtSignal()

    def __init__(self, parent: QWidget | None = None):
        super().__init__("Console", parent)
        self.setAllowedAreas(
            Qt.DockWidgetArea.BottomDockWidgetArea
            | Qt.DockWidgetArea.TopDockWidgetArea
        )
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(4, 4, 4, 4)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        self.repl = ReplWidget()
        splitter.addWidget(self.repl)
        self.docs = _ApiDocPane()
        splitter.addWidget(self.docs)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        # Initial sizes: REPL gets the bulk; docs ~280 px is enough
        # for the list + a paragraph of docstring without crowding.
        splitter.setSizes([700, 280])
        layout.addWidget(splitter)
        self.setWidget(container)

        # Forward each executed statement as an activity ping so the
        # tab-highlighter notices REPL work that happens in the
        # background.
        self.repl.statement_executed.connect(lambda _line: self.activity.emit())
