"""axross-markdown: axross's Markdown viewer as a program of its own -
``axross-markdown [FILE.md ...]``; ``axross-markdown --term FILE.md`` (or
``axross-mdcat``) shows them in the terminal instead (core.markdown_cli);
``axross-markdown --html FILE.md > page.html`` writes the page for a web
browser (ui.markdown_html.export_html: the images beside the file in it,
nothing it may load from elsewhere) - no window either.

Each file opens rendered in a window of its own (ui.markdown_viewer: the
outline, footnotes, highlighted code, images beside the file, find, zoom);
without a file a window explains itself and offers Open… (Ctrl+O). Edit
(F4) opens axross's editor with the Markdown preview beside the text
(ui.editor_window, View > Markdown Preview). What a file holds is shown,
never run: raw HTML kept to a safe subset (no scripts, styles, frames,
forms or event handlers), nothing from the network (ui.markdown_view).
``--help`` says all of it; ``--term``, ``--html``, ``--help`` and
``--version`` never start Qt (nor import it).
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
                                          editor=self.edit, view_menu=self.view_menu)
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

    def view_menu(self, menu) -> None:
        """View > Theme: axross's themes ("Modern (follow system)" the
        first), the choice kept in the program's own settings
        (ui.standalone_app.settings_file)."""
        from PyQt6.QtGui import QActionGroup
        from PyQt6.QtWidgets import QApplication

        from core.i18n import tr
        from ui.standalone_app import fill_theme_menu

        themes = menu.addMenu(tr("Theme"))

        def refill() -> None:  # (the one in use checked - another window may have chosen one)
            for group in themes.findChildren(QActionGroup):
                group.deleteLater()
            themes.clear()
            fill_theme_menu(themes, QApplication.instance(), NAME)

        themes.aboutToShow.connect(refill)
        refill()

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
    program.open_paths(list(args))
    app._ax_markdown = program  # noqa: SLF001 - kept with the application
    return None


def export_html_main(args: list[str]) -> int:
    """``--html FILE``: the page of *FILE* ("-": standard input) for a web
    browser on standard output - its images (beside the file, as the
    terminal reads them: core.markdown_term.read_picture) in it."""
    from core import markdown_doc as MD

    if len(args) != 1:
        print("axross-markdown: --html takes one file (- for standard input)", file=sys.stderr)
        return 2
    if not MD.available():
        print("axross-markdown needs markdown-it-py and mdit-py-plugins", file=sys.stderr)
        return 2
    from core.markdown_cli import _read

    name = args[0]
    text, why = _read(name)
    if why:
        print(f"axross-markdown: {MD.clean(name)}: {why}", file=sys.stderr)
        return 1
    from ui.markdown_html import export_html

    doc = MD.parse(MD.clean(text))
    folder = os.path.dirname(os.path.abspath(name)) if name != "-" else os.getcwd()
    title = os.path.basename(name) if name != "-" else ""
    page = export_html(doc, title=title, images=_images_of(doc, folder))
    from core.markdown_cli import OutputGone, _write

    try:
        _write(page, NAME)  # (piped into head: it ends quietly - a BrokenPipeError's traceback was printed)
    except OutputGone as gone:  # (... "> /dev/full": said, exit 1)
        return gone.status
    return 0


def _images_of(doc, folder: str) -> dict[str, str]:
    """``{src: "data:image/png;base64,…"}`` of the images of *doc* beside
    the file and held in it (read as the terminal reads them: bounded, never
    a secret, never above *folder*) - the only ones the page shows."""
    import base64
    import io

    from core import markdown_doc as MD
    from core import markdown_term as T

    names = []
    for token in doc.tokens:
        for child in [token, *(token.children or ())]:
            if child.type == "image":
                names.append(str(child.attrGet("src") or ""))
            elif child.type in ("safe_html_block", "safe_html_inline"):
                names += [event[2].get("src", "") for event in MD.html_events(child)
                          if event[0] == "start" and event[1] == "img"]
    found, left = {}, T.IMAGES_PIXELS
    for name in dict.fromkeys(names):
        if len(found) >= T.IMAGES:
            break
        if name[:5].lower() == "data:":  # (held in the file: decoded and checked as the terminal's)
            data, _why = T.data_image(name)
            image = T.decode_picture(data, left) if data is not None else "not an image"
        else:
            path, why = T.locate(name, folder)
            if why or not path:
                continue
            image = T.read_picture(path, left, folder)
        if isinstance(image, str):
            continue
        left -= image.width * image.height
        out = io.BytesIO()
        image.save(out, format="PNG")
        found[name] = "data:image/png;base64," + base64.b64encode(out.getvalue()).decode("ascii")
    return found


TERMINAL = ("--term", "-t", "--cat")


def _parser():
    """The window's command line (``--term`` and ``--html`` have their own:
    main)."""
    import argparse

    from core.markdown_cli import program_version

    parser = argparse.ArgumentParser(
        prog=NAME, description="Show Markdown files rendered in a window: an outline, footnotes, "
        "highlighted code, images beside the file - shown, never run.",
        epilog="--term FILE ... shows them in the terminal instead (the options of axross-mdcat: "
        f"{NAME} --term --help); --html FILE writes the page for a web browser to standard output "
        "(- for standard input). Neither starts Qt.")
    parser.add_argument("files", nargs="*", metavar="FILE", help="Markdown files, each in a window of its own")
    parser.add_argument("-t", "--term", "--cat", action="store_true",
                        help="show the files in the terminal (axross-mdcat)")
    parser.add_argument("--html", metavar="FILE", help="write FILE's page for a web browser to standard output")
    parser.add_argument("--version", action="version", version=f"{NAME} {program_version()}")
    return parser


def main(argv: list[str] | None = None) -> int:
    """The program: windows for the files - or (``--term``) the terminal,
    (``--html``) a page on standard output, ``--help``, ``--version``: none
    of those starts Qt or imports it. An option it does not know is an
    error (exit 2), not a file."""
    args = list(sys.argv if argv is None else argv)
    rest = args[1:]
    if rest[:1] == ["--svg-worker"]:
        # A document's SVG drawn in a child process (core.svg_worker): a
        # frozen build has no python -c, the program itself answers.
        from core.svg_worker import _child_main

        return _child_main()
    if rest[:1] == ["--lex-worker"]:  # (the editor's highlighting lexed in a child: core.lex_worker - as main.py)
        from core.lex_worker import _child_main as lex_main

        return lex_main()
    if rest[:1] == ["--image-worker"]:  # (a picture decoded in a child: core.image_worker - as main.py)
        from core.image_worker import _child_main as image_main

        return image_main()
    if any(a in TERMINAL for a in rest):
        # The terminal view (core.markdown_cli, axross-mdcat): no Qt is started.
        from core.markdown_cli import main as terminal

        return terminal([a for a in rest if a not in TERMINAL])
    if rest[:1] == ["--script"]:  # (a build's check: ui.standalone_app.bundle_check)
        return run(NAME, TITLE, "markdown", build, argv, smoke_ms=smoke_ms_from_env())
    try:
        options = _parser().parse_args(rest)
    except SystemExit as stop:  # (--help, --version: said; an unknown option: said, exit 2)
        return int(stop.code or 0)
    if options.html is not None:
        if options.files:
            print(f"{NAME}: --html takes one file (- for standard input)", file=sys.stderr)
            return 2
        return export_html_main([options.html])
    try:
        return run(NAME, TITLE, "markdown", build, [args[0] if args else NAME, *options.files],
                   smoke_ms=smoke_ms_from_env())
    except ImportError as exc:  # (a system library Qt needs is missing: said, not a traceback)
        said = missing_library(exc)
        if said is None:
            raise
        print(f"{NAME}: {said}", file=sys.stderr)
        return 1


#: The packages that bring a system library Qt's window needs (Debian and
#: Ubuntu / Fedora and RHEL / Arch).
_PACKAGES = {
    "libEGL.so.1": "libegl1 / mesa-libEGL / libglvnd",
    "libGL.so.1": "libgl1 / mesa-libGL / libglvnd",
    "libOpenGL.so.0": "libopengl0 / libglvnd-opengl / libglvnd",
    "libxkbcommon.so.0": "libxkbcommon0 / libxkbcommon / libxkbcommon",
    "libxkbcommon-x11.so.0": "libxkbcommon-x11-0 / libxkbcommon-x11 / libxkbcommon-x11",
    "libfontconfig.so.1": "libfontconfig1 / fontconfig / fontconfig",
    "libfreetype.so.6": "libfreetype6 / freetype / freetype2",
    "libdbus-1.so.3": "libdbus-1-3 / dbus-libs / dbus",
    "libxcb-cursor.so.0": "libxcb-cursor0 / xcb-util-cursor / xcb-util-cursor",
}


def missing_library(error: ImportError) -> str | None:
    """What to say when *error* is a system library that is not there (the
    window cannot start: which library, which package brings it, what works
    without it) - None for any other ImportError."""
    import re

    found = re.search(r"([\w.+-]+\.so(?:\.\d+)*): cannot open shared object file", str(error))
    if found is None:
        return None
    library = found.group(1)
    package = _PACKAGES.get(library)
    where = (f" - install the package {package} (Debian or Ubuntu / Fedora or RHEL / Arch)" if package
             else " - install the package of your system that has it")
    return (f"the window needs the system library {library}, which is not installed{where}. "
            f"Without it, {NAME} --term FILE shows the file in the terminal and "
            f"{NAME} --html FILE writes it as a web page.")


if __name__ == "__main__":
    sys.exit(main())
