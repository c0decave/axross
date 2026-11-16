"""The Markdown viewer window: a ``.md`` file of any connection rendered
(:mod:`ui.markdown_view`) with its outline, find, zoom, Reload and Edit.

Opened by F3 and a double-click on a Markdown file (F4 still edits it), and
for a Markdown member of an archive. The text is read on a worker thread
(at most :data:`ui.markdown_view.TEXT_LIMIT` bytes; a cut is said), so a
slow server holds up no window.

Links (the view hands every link that is not an anchor of the text here):

* a relative link to another Markdown file opens it in a viewer of its own,
  on the same connection, relative to this file's folder;
* an ``http(s)`` link opens in the web browser only when the security mode
  allows external viewers and after the user said yes to a question that
  shows the real address (:func:`ui.update_ui.ask_open_link`);
* anything else (``file:``, ``mailto:``, a relative link to a file that is
  not Markdown) is named in the status line, not opened.
"""

from __future__ import annotations

import logging
import posixpath

from PyQt6 import sip
from PyQt6.QtCore import QUrl
from PyQt6.QtGui import QKeySequence, QShortcut
from PyQt6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
)

from core.i18n import tr
from ui import markdown_view as MV
from ui import viewer_window as VW
from ui.close_corner import add_close_corner
from ui.icon_provider import set_window_icon

log = logging.getLogger(__name__)

#: The name the window's size and place are saved under.
STATE_NAME = "markdown"


#: What a viewer without a file shows (the program axross-markdown started
#: without one).
WELCOME = """# Markdown Viewer

Open a Markdown file with **Open…** (Ctrl+O), or name files on the command line.

- the headings beside the text, a click goes there
- tables, task lists, strike-through, footnotes, highlighted code
- images beside the file; nothing is loaded from the network
- find (Ctrl+F), zoom (Ctrl + / - / 0), Reload (F5), Edit (F4)
"""


class MarkdownViewerDialog(QDialog):
    """The Markdown file *path* of *backend*, rendered. *source_pane*: the
    pane it was opened from (Edit opens the editor of its window).

    For a program of its own (ui.markdown_app): *opener(viewer)* adds Open…
    (Ctrl+O); *editor(backend, path)* is what Edit does; an empty *path*
    shows :data:`WELCOME` until a file is opened."""

    def __init__(self, backend, path: str, parent=None, *, source_pane=None,
                 opener=None, editor=None) -> None:
        super().__init__(parent)
        set_window_icon(self, "markdown")
        self.backend, self.path, self.source_pane = backend, path, source_pane
        self._opener, self._editor = opener, editor
        self.cut = False
        self.loaded_once = False
        self._generation = 0
        VW.allow_maximize(self)
        self._build_ui()
        self._update_title()
        VW.restore_window_state(self, STATE_NAME)
        self.reload()

    # -- the window --

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        add_close_corner(self)
        bar = QHBoxLayout()
        self.outline_button = QPushButton(tr("Outline"))
        self.outline_button.setCheckable(True)
        self.outline_button.setChecked(True)
        self.outline_button.setToolTip(tr("Show or hide the headings beside the text"))
        self.outline_button.toggled.connect(lambda on: self.view.outline.setVisible(on))
        self.reload_button = QPushButton(tr("Reload"))
        self.reload_button.setToolTip(tr("Read the file and its images again (F5)"))
        self.reload_button.clicked.connect(self.reload)
        self.edit_button = QPushButton(tr("Edit"))
        self.edit_button.setToolTip(tr("Open the file in the editor (F4)"))
        self.edit_button.clicked.connect(self.edit)
        self.edit_button.setEnabled(bool(self.path))
        self.reload_button.setEnabled(bool(self.path))
        self.open_button = None
        if self._opener is not None:
            self.open_button = QPushButton(tr("Open…"))
            self.open_button.setToolTip(tr("Open Markdown files (Ctrl+O)"))
            self.open_button.clicked.connect(lambda: self._opener(self))
            bar.addWidget(self.open_button)
        zoom_out = QPushButton("−")
        zoom_out.setToolTip(tr("Smaller (Ctrl+-)"))
        zoom_out.clicked.connect(lambda: self.view.zoom_by(-1))
        zoom_reset = QPushButton("100%")
        zoom_reset.setToolTip(tr("Original size (Ctrl+0)"))
        zoom_reset.clicked.connect(lambda: self.view.zoom_by(0))
        zoom_in = QPushButton("+")
        zoom_in.setToolTip(tr("Larger (Ctrl++)"))
        zoom_in.clicked.connect(lambda: self.view.zoom_by(1))
        self.find_field = QLineEdit()
        self.find_field.setPlaceholderText(tr("Find (Ctrl+F, Enter: next)"))
        self.find_field.setClearButtonEnabled(True)
        self.find_field.returnPressed.connect(self.find_next)
        for widget in (self.outline_button, self.reload_button, self.edit_button,
                       zoom_out, zoom_reset, zoom_in):
            bar.addWidget(widget)
        bar.addStretch(1)
        bar.addWidget(self.find_field, 1)
        root.addLayout(bar)
        self.view = MV.MarkdownView(MV.ImageSource(self.backend, self.path), parent=self)
        self.view.link.connect(self.follow)
        root.addWidget(self.view, 1)
        for keys, slot in (
            (QKeySequence.StandardKey.Find, lambda: self.find_field.setFocus()),
            (QKeySequence.StandardKey.ZoomIn, lambda: self.view.zoom_by(1)),
            (QKeySequence.StandardKey.ZoomOut, lambda: self.view.zoom_by(-1)),
            (QKeySequence("Ctrl+0"), lambda: self.view.zoom_by(0)),
            (QKeySequence("F5"), self.reload),
            (QKeySequence("F4"), self.edit),
            (QKeySequence("F3"), self.find_next),
        ):
            shortcut = QShortcut(QKeySequence(keys), self)
            shortcut.activated.connect(slot)
        if self._opener is not None:
            QShortcut(QKeySequence.StandardKey.Open, self).activated.connect(lambda: self._opener(self))
        VW.install_window_keys(self, fullscreen=False)

    def _update_title(self) -> None:
        if not self.path:
            self.setWindowTitle(tr("Markdown Viewer"))
            return
        name = posixpath.basename(self.path) or self.path
        self.setWindowTitle(tr("{name} – Markdown Viewer").format(name=MV.printable(name)))

    def done(self, result: int) -> None:  # noqa: D401 - Qt override
        VW.save_window_state(self, STATE_NAME)
        super().done(result)

    # -- the text --

    def reload(self) -> None:
        """Read the file (and, at the next rendering, its images) again, on
        a worker thread."""
        self._generation += 1
        generation = self._generation
        self.view.forget_images()
        if not self.path:
            self.view.render(tr(WELCOME))
            self.loaded_once = True
            self.view.status.setText("")
            return
        self.view.status.setText(tr("Reading…"))
        backend, path = self.backend, self.path

        def work():
            if MV._is_local(backend):
                import os
                import stat

                if not stat.S_ISREG(os.stat(path).st_mode):  # a FIFO, a device: never opened
                    raise OSError(tr("not a regular file"))
            return MV.read_text(backend, path)

        MV.in_background(work, lambda result, error: self._read(generation, result, error), owner=self)

    def _read(self, generation: int, result, error) -> None:
        if generation != self._generation or sip.isdeleted(self):
            return  # a newer Reload is on its way
        if error is not None:
            self.view.status.setText(tr("Cannot read {path}: {error}").format(
                path=MV.printable(self.path), error=MV.printable(error)))
            return
        text, self.cut = result
        self.view.render(text)
        self.loaded_once = True
        self.view.status.setText(
            tr("Only the first {mib} MiB of the file are shown.").format(mib=MV.TEXT_LIMIT >> 20)
            if self.cut else "")

    def find_next(self) -> bool:
        from ui.guide_view import find_next

        needle = self.find_field.text()
        found = find_next(self.view.browser, needle)
        if needle and not found:
            self.view.status.setText(tr("Not found: {text}").format(text=MV.printable(needle)))
        return found

    def edit(self) -> None:
        """The file in the editor of the window it was opened from."""
        if not self.path:
            return
        if self._editor is not None:
            self._editor(self.backend, self.path)
            return
        owner = VW.owner_window(self.source_pane or self.parentWidget())
        opener = getattr(owner, "open_in_editor", None)
        if callable(opener):
            opener(self.backend, self.path)
            return
        from ui.text_editor import TextEditorDialog

        dialog = TextEditorDialog(self.backend, self.path, parent=owner)
        if dialog.loaded:
            VW.show_independent(dialog)
        else:
            dialog.deleteLater()

    # -- links --

    def target_of(self, url: QUrl) -> tuple[str, str]:
        """What a click on *url* does: ``("markdown", path)``, ``("web",
        url)`` or ``("refused", why)``."""
        scheme = url.scheme().lower()
        if scheme in ("http", "https") and url.host():
            return "web", url.toString(QUrl.ComponentFormattingOption.FullyEncoded)
        if scheme or url.toString().startswith("//"):
            return "refused", tr("Not opened: {target}").format(target=MV.printable(url.toString()))
        relative = url.path()
        if not relative or relative.startswith("/") or "\0" in relative:
            return "refused", tr("Not opened: {target}").format(target=MV.printable(url.toString()))
        path = posixpath.normpath(posixpath.join(posixpath.dirname(self.path) or "/", relative))
        if not MV.is_markdown(path):
            return "refused", tr("Not opened (not a Markdown file): {target}").format(
                target=MV.printable(url.toString()))
        return "markdown", path

    def follow(self, url: QUrl) -> None:
        kind, where = self.target_of(url)
        if kind == "refused":
            self.view.status.setText(where)
            return
        if kind == "markdown":
            open_markdown_viewer(self.backend, where, self.parentWidget(), source_pane=self.source_pane,
                                 opener=self._opener, editor=self._editor)
            return
        from core.security_mode import current_policy

        if not current_policy().allow_external_viewer:
            self.view.status.setText(tr("The security mode opens no web browser: {target}").format(
                target=MV.printable(where)))
            return
        from ui.markdown_safe import ask_open_link

        if ask_open_link(self, where, ""):
            from core.desktop_open import open_url

            open_url(QUrl(where))


def open_markdown_viewer(backend, path: str, parent=None, *, source_pane=None, opener=None,
                         editor=None) -> MarkdownViewerDialog:
    """Show the Markdown file *path* of *backend* in a viewer window of its
    own (non-modal)."""
    dialog = MarkdownViewerDialog(backend, path, VW.owner_window(parent), source_pane=source_pane,
                                  opener=opener, editor=editor)
    VW.show_independent(dialog)
    return dialog


__all__ = ["MarkdownViewerDialog", "open_markdown_viewer"]
