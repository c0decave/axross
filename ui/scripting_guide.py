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
import re
import unicodedata
from urllib.parse import quote, unquote

from PyQt6.QtCore import Qt, QUrl
from PyQt6.QtGui import QTextCursor
from PyQt6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QSplitter,
    QTabWidget,
    QTextBrowser,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core.i18n import tr
from ui.close_corner import add_close_corner

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
* In **paranoid** security mode (Edit > Settings > Security) no
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


# -- structure: headings, slugs, links -------------------------------------------------

_FENCE = re.compile(r"^\s*(```|~~~)")
_HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")
_REF_FUNCTION = re.compile(r"^`axross\.([A-Za-z_][A-Za-z0-9_]*)\(")
_INLINE_API = re.compile(r"`axross\.([A-Za-z_][A-Za-z0-9_]*)(\([^`]*\))?`")
#: The guide's section about the API (every language writes `axross.*` in it).
_API_SECTION = "`axross.*`"


def _plain(heading: str) -> str:
    """A heading as the rendered document shows it: without the backticks."""
    return heading.replace("`", "").strip()


def github_slug(heading: str) -> str:
    """GitHub's anchor for a Markdown heading: lower case, punctuation
    dropped (letters, digits, "-", "_" and spaces stay), spaces to "-"."""
    text = heading.strip().lower()
    out = []
    for ch in text:
        if ch in " -_" or unicodedata.category(ch)[0] in "LN":
            out.append(ch)
    return "".join(out).replace(" ", "-")


def headings(markdown: str) -> list[tuple[int, str]]:
    """``(level, text)`` of every ATX heading outside fenced code."""
    out: list[tuple[int, str]] = []
    in_fence = False
    for line in markdown.splitlines():
        if _FENCE.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        match = _HEADING.match(line)
        if match:
            out.append((len(match.group(1)), match.group(2)))
    return out


def reference_topics(reference_md: str) -> dict[str, list[str]]:
    """The API reference's topics (its "##" headings) and the function
    names under each (its "### `axross.name(...)`" headings)."""
    topics: dict[str, list[str]] = {}
    current = None
    for level, text in headings(reference_md):
        if level == 2:
            current = _plain(text)
            topics[current] = []
        elif level == 3 and current is not None:
            match = _REF_FUNCTION.match(text)
            if match:
                topics[current].append(match.group(1))
    return {topic: names for topic, names in topics.items() if names}


def link_guide(markdown: str, topics: dict[str, list[str]]) -> str:
    """The guide with links for the app: `axross.name(...)` in prose links to
    that function (``api:name``) when it exists, and the section about the
    API gets a line of links to the reference topics (``apitopic:``), and a
    "###" section named like a reference topic a line of links to its
    functions. Fenced code is left alone."""
    known = {name for names in topics.values() for name in names}

    def link(match: re.Match) -> str:
        if match.group(1) not in known:
            return match.group(0)
        return f"[{match.group(0)}](api:{match.group(1)})"

    topic_line = " · ".join(f"[{t}](apitopic:{quote(t)})" for t in topics)
    out: list[str] = []
    in_fence = False
    for line in markdown.splitlines():
        if _FENCE.match(line):
            in_fence = not in_fence
            out.append(line)
            continue
        if in_fence:
            out.append(line)
            continue
        heading = _HEADING.match(line)
        if heading:
            out.append(line)
            if heading.group(1) == "##" and _API_SECTION in heading.group(2) and topic_line:
                out.extend(["", "**API reference:** " + topic_line])
            names = topics.get(_plain(heading.group(2))) if heading.group(1) == "###" else None
            if names:
                out.extend(["", "**API:** " + " · ".join(f"[`{n}`](api:{n})" for n in names)])
            continue
        out.append(_INLINE_API.sub(link, line))
    return "\n".join(out)


def _heading_block(view: QTextBrowser, match) -> "QTextCursor | None":
    """A cursor at the first heading block of *view* for which *match(text)*
    holds, or None."""
    block = view.document().begin()
    while block.isValid():
        if block.blockFormat().headingLevel() > 0 and match(block.text()):
            return QTextCursor(block)
        block = block.next()
    return None


def _scroll_to(view: QTextBrowser, cursor: QTextCursor) -> None:
    """Put the heading of *cursor* at the top of *view*."""
    view.setTextCursor(cursor)
    rect = view.document().documentLayout().blockBoundingRect(cursor.block())
    view.verticalScrollBar().setValue(int(rect.top()))


def _browser() -> QTextBrowser:
    view = QTextBrowser()
    # Every link goes through ScriptingGuideDialog.on_link: api:, apitopic:,
    # #section and the language files stay in the dialog, the rest opens
    # in the browser.
    view.setOpenLinks(False)
    return view


class ScriptingGuideDialog(QDialog):
    """Guide + API reference, with a find field (Return: next match)."""

    def __init__(self, parent: QWidget | None = None, *, language: str | None = None):
        super().__init__(parent)
        self.setWindowTitle(tr("Scripting Guide") + " — axross")
        self.resize(820, 680)

        from core import scripting

        self.api = _browser()
        try:
            reference = scripting.docs()
            self.api.setMarkdown(reference)
        except Exception as exc:  # noqa: BLE001 — never fail the help window
            reference = ""
            self.api.setPlainText(tr("The API reference could not be built: {e}").format(e=exc))
        self._api_markdown = reference
        self._topics = reference_topics(reference)

        self.guide = _browser()
        self.source = ""
        self._guide_markdown = ""
        self._load_guide(*guide_markdown(language))

        self.tabs = QTabWidget()
        self.tabs.addTab(self.guide, tr("Guide"))
        self.tabs.addTab(self.api, tr("API Reference"))
        self.guide.anchorClicked.connect(self.on_link)
        self.api.anchorClicked.connect(self.on_link)

        # Contents of the visible tab: sections, and the reference's topics
        # with their functions.
        self.contents = QTreeWidget()
        self.contents.setHeaderHidden(True)
        self.contents.itemActivated.connect(self._go_to_item)
        self.contents.itemClicked.connect(self._go_to_item)
        self.tabs.currentChanged.connect(lambda _index: self._fill_contents())
        split = QSplitter()
        split.addWidget(self.contents)
        split.addWidget(self.tabs)
        split.setStretchFactor(1, 1)
        split.setSizes([230, 590])

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
        layout.addWidget(split, 1)
        layout.addWidget(buttons)
        add_close_corner(self)
        self.resize(1060, 700)
        self._fill_contents()

    # -- contents and links ----------------------------------------------------------------

    def _load_guide(self, text: str, source: str) -> None:
        self.source = source
        self._guide_markdown = text
        if source != BUILT_IN_SOURCE:
            self.guide.setSearchPaths([os.path.dirname(source)])
        self.guide.setMarkdown(link_guide(text, self._topics))

    def _fill_contents(self) -> None:
        tree = self.contents
        tree.clear()
        if self.tabs.currentIndex() == 1:
            for topic, names in self._topics.items():
                item = QTreeWidgetItem([topic])
                item.setData(0, Qt.ItemDataRole.UserRole, ("topic", topic))
                for name in names:
                    child = QTreeWidgetItem([name])
                    child.setData(0, Qt.ItemDataRole.UserRole, ("api", name))
                    item.addChild(child)
                tree.addTopLevelItem(item)
            return
        parent = None
        for level, text in headings(self._guide_markdown):
            if level < 2:
                continue
            item = QTreeWidgetItem([_plain(text)])
            item.setData(0, Qt.ItemDataRole.UserRole, ("heading", _plain(text)))
            if level == 2 or parent is None:
                tree.addTopLevelItem(item)
                parent = item
            else:
                parent.addChild(item)

    def _go_to_item(self, item: QTreeWidgetItem, _column: int = 0) -> None:
        kind, value = item.data(0, Qt.ItemDataRole.UserRole)
        if kind == "heading":
            self._go(self.guide, lambda text: text == value)
        elif kind == "topic":
            self._go(self.api, lambda text: text == value)
        else:
            self._go(self.api, lambda text: text.startswith(f"axross.{value}("))

    def _go(self, view: QTextBrowser, match) -> bool:
        cursor = _heading_block(view, match)
        if cursor is None:
            self.search_hint.setText(tr("Not found"))
            return False
        self.search_hint.clear()
        self.tabs.setCurrentWidget(view)  # a tab change refills the contents
        _scroll_to(view, cursor)
        return True

    def on_link(self, url: QUrl) -> None:
        """Every link of both tabs: api:name and apitopic:topic open the
        reference, #section scrolls the guide, a SCRIPTING*.md file switches
        the guide (language) or opens the reference, the rest goes to the
        browser."""
        scheme = url.scheme()
        if scheme == "api":
            name = url.path()
            self._go(self.api, lambda text: text.startswith(f"axross.{name}("))
            return
        if scheme == "apitopic":
            topic = unquote(url.path())
            self._go(self.api, lambda text: text == topic)
            return
        if scheme in ("", "file") and not url.host():
            path = os.path.basename(url.path())
            fragment = url.fragment()
            if path.startswith("SCRIPTING") and path.endswith(".md") and path != "SCRIPTING_REFERENCE.md":
                if self.source != BUILT_IN_SOURCE:
                    text = _read_guide(os.path.join(os.path.dirname(self.source), path))
                    if text is not None:
                        self._load_guide(text, os.path.join(os.path.dirname(self.source), path))
                        self.tabs.setCurrentWidget(self.guide)
                        self._fill_contents()
                return
            if path == "SCRIPTING_REFERENCE.md":
                self.tabs.setCurrentWidget(self.api)
                return
            if not path and fragment:
                self._go(self.guide, lambda text: github_slug(text) == fragment)
                return
        from core import desktop_open

        desktop_open.open_url(url)  # the frozen build too (core.desktop_open)

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
