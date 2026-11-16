"""axross-markdown: axross's Markdown viewer as a program of its own -
``axross-markdown [FILE.md ...]``; ``axross-markdown --term FILE.md`` (or
``axross-mdcat``) shows them in the terminal instead (core.markdown_cli).

Each file opens rendered in a window of its own (ui.markdown_viewer: the
outline, footnotes, highlighted code, images beside the file, find, zoom);
without a file a window explains itself and offers Open… (Ctrl+O). Edit
(F4) opens axross's editor with the Markdown preview beside the text
(ui.editor_window, View > Markdown Preview). What a file holds is shown,
never run: no raw HTML, nothing from the network (ui.markdown_view).
"""

from __future__ import annotations

import os
import sys

from ui.standalone_app import run, smoke_ms_from_env

NAME = "axross-markdown"
TITLE = "Markdown Viewer"
#: What Open… offers first.
FILTER = "Markdown (*.md *.markdown *.mdown *.mkd);;All files (*)"


class MarkdownApp:
    """The program's windows: viewers, and one editor window (made when
    Edit is first used)."""

    def __init__(self) -> None:
        from core.local_fs import LocalFS

        self.backend = LocalFS()
        self.editor_window = None
        self.viewers: list = []

    def open_paths(self, paths: list[str], parent=None) -> list:
        """A viewer for each of *paths* (made absolute); a viewer without a
        file when there are none."""
        from ui.markdown_viewer import open_markdown_viewer

        opened = []
        for path in paths or [""]:
            full = os.path.abspath(os.path.expanduser(path)) if path else ""
            viewer = open_markdown_viewer(self.backend, full, parent, opener=self.ask_open,
                                          editor=self.edit)
            self.viewers.append(viewer)
            opened.append(viewer)
        return opened

    def ask_open(self, viewer) -> list:
        """Open…: the files chosen, each in a viewer; a viewer that showed no
        file yet is replaced by the first of them."""
        from PyQt6.QtWidgets import QFileDialog

        from core.i18n import tr

        start = os.path.dirname(viewer.path) if viewer.path else os.path.expanduser("~")
        paths, _chosen = QFileDialog.getOpenFileNames(viewer, tr("Open Markdown files"), start, FILTER)
        if not paths:
            return []
        opened = self.open_paths(paths)
        if not viewer.path:
            viewer.close()
        return opened

    def edit(self, backend, path: str):
        """Edit: the file in the editor window, the preview beside it."""
        from PyQt6 import sip

        from ui.editor_window import EditorWindow

        if self.editor_window is None or sip.isdeleted(self.editor_window):
            self.editor_window = EditorWindow()
        window = self.editor_window
        window.preview_new_tabs = True
        window.open_file(backend, path)
        window.show()
        window.raise_()
        window.activateWindow()
        return window


def build(app, args: list[str]):
    """The windows for *args* (files; none: a viewer without one)."""
    program = MarkdownApp()
    program.open_paths([a for a in args if not a.startswith("-")])
    app._ax_markdown = program  # noqa: SLF001 - kept with the application
    return None


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv if argv is None else argv)
    if any(a in ("--term", "-t", "--cat") for a in args[1:]):
        # The terminal view (core.markdown_cli, axross-mdcat): no Qt is started.
        from core.markdown_cli import main as terminal

        return terminal([a for a in args[1:] if a not in ("--term", "-t", "--cat")])
    return run(NAME, TITLE, "markdown", build, argv, smoke_ms=smoke_ms_from_env())


if __name__ == "__main__":
    sys.exit(main())
