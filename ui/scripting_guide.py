"""Help > Scripting Guide: the scripting docs inside the app.

Two tabs: the guide (``docs/SCRIPTING.md``, or the variant for the
interface language, ``SCRIPTING_<lang>.md``) and the API reference
(:func:`core.scripting.docs`, the same text ``axross.docs()`` returns).

A wheel and the frozen bundle carry no ``docs/`` directory — MANIFEST.in
ships it in the sdist only, and neither pyproject's package data nor
build/axross.spec collects it. There the guide falls back to
:data:`BUILT_IN_GUIDE` plus the slash-command and bundled-script
references from core.scripting, which every install has.
"""

from __future__ import annotations

import os

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QTabWidget,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from core.i18n import tr

#: Largest guide file read from docs/ (the real ones are ~10 KB).
MAX_GUIDE_BYTES = 1024 * 1024
#: ``source`` value when the guide comes from :data:`BUILT_IN_GUIDE`.
BUILT_IN_SOURCE = "built-in"

BUILT_IN_GUIDE = """\
# Scripting

axross has a Python scripting surface: every function is reachable as
`axross.*` (see the **API Reference** tab, or `axross.help()`).

## Where scripts run

* **Scripts panel** (View > Panels > Scripts): write, save and manage
  scripts; **Run** starts one in its own process.
* **Console** (View > Panels > Console): the interactive REPL;
  `.run <name>` runs a saved script in the live namespace.
* **Command line**: `axross --script FILE` (or `-` for stdin), headless.
* **Schedule** (View > Scheduled Jobs): runs a saved script on an interval.

Saved scripts live in `~/.config/axross/scripts/` (mode 0700), one
`<name>.py` per script. Names use letters, digits, `_` and `-`.

## The Scripts panel

* **New** creates a script from a short template; **Save** (Ctrl+S),
  **Save As…**, **Rename…** and **Delete** manage the file. An edited
  script shows `*`; switching away asks to save, discard or cancel.
* **Run** (Ctrl+Return) saves unsaved edits, then starts the script in
  a separate Python process, with the same `axross` namespace as
  `axross --script`. Output streams into the pane below; the status line
  shows the exit status and the duration. **Stop** terminates the script
  and kills it if it does not end within a few seconds. Closing the
  window stops a running script.
* A traceback line that points into the script is a link: click it to
  jump to that line.
* **Run in Console** runs the script in the Console's live namespace
  instead: variables it sets stay available at the prompt, but the
  window waits until the script finishes.
* The **Examples** section lists the bundled example scripts. They are
  read-only; **Copy to My Scripts** makes an editable copy.
* Scripts that a scheduled job runs are marked `[scheduled]`; renaming
  or deleting one warns first.
* In **paranoid** security mode (Tools > Paranoid Security Mode) no
  saved script runs; Run says so in its tooltip.

In a separate process there is no terminal to ask: `axross.confirm()`
raises `axross.NonInteractiveError` instead of answering for you (pass
`assume_yes=True` to answer yes without asking), and `axross.message()`
prints instead of showing a dialog. Use Run in Console for scripts that
need dialogs. A write to a *production* profile still counts down in the
output first; Stop during the countdown and the write does not happen.
"""


def _project_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read_guide(path: str) -> str | None:
    try:
        if not os.path.isfile(path) or os.path.getsize(path) > MAX_GUIDE_BYTES:
            return None
        with open(path, encoding="utf-8") as fh:
            return fh.read(MAX_GUIDE_BYTES + 1)
    except (OSError, UnicodeDecodeError):
        return None


def guide_markdown(language: str | None = None, *, root: str | None = None) -> tuple[str, str]:
    """``(markdown, source)``: the docs file for ``language`` (default: the
    interface language), English next, else the built-in guide."""
    if language is None:
        from core.i18n import active

        language = active().language
    docs = os.path.join(root or _project_root(), "docs")
    names = ["SCRIPTING.md"]
    if language and language != "en":
        names.insert(0, f"SCRIPTING_{language}.md")
    for name in names:
        path = os.path.join(docs, name)
        text = _read_guide(path)
        if text is not None:
            return text, path
    from core import scripting

    parts = [BUILT_IN_GUIDE]
    for topic in ("slash", "scripts"):
        try:
            parts.append(scripting.docs(topic))
        except Exception:  # noqa: BLE001 — the guide must open regardless
            continue
    return "\n\n".join(parts), BUILT_IN_SOURCE


def _browser() -> QTextBrowser:
    view = QTextBrowser()
    view.setOpenExternalLinks(True)
    return view


class ScriptingGuideDialog(QDialog):
    """Guide + API reference, with a find field (Return: next match)."""

    def __init__(self, parent: QWidget | None = None, *, language: str | None = None):
        super().__init__(parent)
        self.setWindowTitle(tr("Scripting Guide") + " — axross")
        self.resize(820, 680)

        text, self.source = guide_markdown(language)
        self.guide = _browser()
        if self.source != BUILT_IN_SOURCE:
            # Relative links (SCRIPTING_REFERENCE.md, …) open beside it.
            self.guide.setSearchPaths([os.path.dirname(self.source)])
        self.guide.setMarkdown(text)

        from core import scripting

        self.api = _browser()
        try:
            self.api.setMarkdown(scripting.docs())
        except Exception as exc:  # noqa: BLE001 — never fail the help window
            self.api.setPlainText(tr("The API reference could not be built: {e}").format(e=exc))

        self.tabs = QTabWidget()
        self.tabs.addTab(self.guide, tr("Guide"))
        self.tabs.addTab(self.api, tr("API Reference"))

        self.search = QLineEdit()
        self.search.setPlaceholderText(tr("Find (Return: next match)"))
        self.search.setClearButtonEnabled(True)
        self.search.returnPressed.connect(self.find_next)
        self.search_hint = QLabel()
        find_row = QHBoxLayout()
        find_row.addWidget(self.search, 1)
        find_row.addWidget(self.search_hint)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        for button in buttons.buttons():  # Return in the find field must not close
            button.setAutoDefault(False)
            button.setDefault(False)

        layout = QVBoxLayout(self)
        layout.addLayout(find_row)
        layout.addWidget(self.tabs, 1)
        layout.addWidget(buttons)

    def _current_view(self) -> QTextBrowser:
        return self.api if self.tabs.currentIndex() == 1 else self.guide

    def find_next(self) -> bool:
        """Select the next match in the visible tab, wrapping at the end."""
        needle = self.search.text()
        view = self._current_view()
        self.search_hint.clear()
        if not needle:
            return False
        if view.find(needle):
            return True
        cursor = view.textCursor()
        cursor.movePosition(cursor.MoveOperation.Start)
        view.setTextCursor(cursor)
        if view.find(needle):
            return True
        self.search_hint.setText(tr("Not found"))
        return False

    def keyPressEvent(self, event) -> None:  # noqa: N802 — Qt
        if event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
            return  # no default button: Return never closes the guide
        super().keyPressEvent(event)


__all__ = [
    "BUILT_IN_GUIDE",
    "BUILT_IN_SOURCE",
    "MAX_GUIDE_BYTES",
    "ScriptingGuideDialog",
    "guide_markdown",
]
