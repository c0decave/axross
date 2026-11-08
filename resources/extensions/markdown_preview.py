"""A panel that renders the selected Markdown file."""

from __future__ import annotations

EXTENSION = {
    "name": "Markdown Preview",
    "version": "1.0",
    "description": "A panel that shows the selected .md file rendered - local or remote, "
    "read in the background, at most 1 MiB.",
    "author": "axross",
}

SUFFIXES = (".md", ".markdown", ".mdown")
MAX_BYTES = 1024 * 1024

#: What the GUI thread may be given to lay out, in rough units of one
#: short paragraph (about 0.03 ms each, measured on Qt 6.11): about 0.4 s
#: at most. A table cell costs far more than a paragraph, and a run of
#: formatted text (``*a*a``) within one paragraph grows with the square of
#: its length - a 320 KB table or a 160 KB ``*a*a...`` line froze the
#: window for 13-28 s in ``setMarkdown``.
RENDER_BUDGET = 12000
BLOCK_COST = 1
TABLE_CELL_COST = 7
FRAGMENT_COST = 0.5
#: Per character, and per level a list or quote is indented.
CHAR_COST = 1 / 40
INDENT_COST = 0.1
#: Format runs one paragraph may have before it is cut.
MAX_FRAGMENTS_PER_BLOCK = 1000
#: The first part of the text parsed; doubled while it stays in budget.
#: Parsing a table is itself quadratic, so the whole 1 MiB is parsed only
#: when it is cheap (plain text, code).
FIRST_PARSE_CHARS = 16 * 1024


def read_markdown(backend, path: str, limit: int = MAX_BYTES) -> tuple[str, bool]:
    """The file's text (UTF-8, damaged bytes replaced) and whether it was
    cut at *limit*."""
    with backend.open_read(path) as fh:
        data = fh.read(limit + 1)
    cut = len(data) > limit
    return data[:limit].decode("utf-8", "replace"), cut


def _blank_resource(kind):
    """What the preview gives for a resource: never the file named."""
    from PyQt6.QtCore import QByteArray
    from PyQt6.QtGui import QImage, QTextDocument

    if kind == QTextDocument.ResourceType.ImageResource.value:
        blank = QImage(1, 1, QImage.Format.Format_ARGB32)
        blank.fill(0)
        return blank
    return QByteArray(b" ")


def _cut_position(doc, budget: float = RENDER_BUDGET):
    """The position from which *doc* is beyond the render budget, or
    ``None`` when all of it fits. A cut inside a table removes its later
    rows first, so the position lands just after the table."""
    from PyQt6.QtGui import QTextCursor

    spent = 0.0
    block = doc.begin()
    while block.isValid():
        table = QTextCursor(block).currentTable()
        spent += TABLE_CELL_COST if table is not None else BLOCK_COST
        listed = block.textList()
        indent = listed.format().indent() if listed is not None else 0
        spent += (indent + block.blockFormat().indent()) * INDENT_COST
        fragments = 0
        it = block.begin()
        while not it.atEnd() and spent <= budget:
            fragment = it.fragment()
            fragments += 1
            cost = FRAGMENT_COST + fragment.length() * CHAR_COST
            if spent + cost > budget or fragments > MAX_FRAGMENTS_PER_BLOCK:
                if table is not None:
                    spent = budget + 1  # a cell is not cut in its middle
                    break
                room = max(budget - spent - FRAGMENT_COST, 0) / CHAR_COST
                if fragments > MAX_FRAGMENTS_PER_BLOCK:
                    room = 0
                return fragment.position() + min(int(room), fragment.length())
            spent += cost
            it += 1
        if spent > budget:
            if table is None:
                return block.position()
            row = table.cellAt(block.position()).row()
            if row == 0:
                return max(table.firstPosition() - 1, 0)
            table.removeRows(row, table.rows() - row)
            return table.lastPosition() + 1
        block = block.next()
    return None


def render_html(text: str, font=None) -> tuple[str, bool]:
    """*text* converted to HTML on the calling (worker) thread, and whether
    only its beginning is kept. The result stays within the render budget,
    so laying it out on the GUI thread is quick."""
    from PyQt6.QtGui import QTextCursor, QTextDocument

    class Doc(QTextDocument):
        def loadResource(self, kind, _name):  # noqa: N802 - Qt
            return _blank_resource(kind)

    size = min(len(text), FIRST_PARSE_CHARS)
    while True:
        part = text[:size]
        if size < len(text):
            line_end = part.rfind("\n")
            if line_end > 0:
                part = part[:line_end + 1]
        doc = Doc()
        if font is not None:
            doc.setDefaultFont(font)
        doc.setMarkdown(part)
        cut_at = _cut_position(doc)
        if cut_at is not None or size >= len(text):
            break
        size *= 2
    if cut_at is not None and cut_at < doc.characterCount() - 1:
        cursor = QTextCursor(doc)
        cursor.setPosition(cut_at)
        cursor.movePosition(QTextCursor.MoveOperation.End, QTextCursor.MoveMode.KeepAnchor)
        cursor.removeSelectedText()
    return doc.toHtml(), cut_at is not None


def activate(api):
    from html import escape

    from PyQt6.QtWidgets import QTextBrowser

    from core.i18n import tr

    class Preview(QTextBrowser):
        """Loads no resource: the file is not axross's. QTextBrowser read
        an image (``![x](/dev/zero)``, a FIFO, a file on a hung mount)
        with QFile.readAll on the GUI thread, so a crafted .md froze the
        window or filled the memory; it is shown without its images.

        The answer must be a valid, non-empty one: for an empty answer
        QTextDocument reads the local file itself, and for an image that
        is no image QTextImageHandler loads the name directly."""

        def loadResource(self, kind, _name):  # noqa: N802 - Qt
            return _blank_resource(kind)

    view = Preview()
    view.setOpenExternalLinks(False)  # a click never leaves axross unasked
    view.setOpenLinks(False)
    view.setPlaceholderText(tr("Select a Markdown file (.md) to preview it here."))
    api.add_dock("Markdown Preview", view, icon="markdown")
    #: Counts the reads started: only the last one's result or error is shown.
    state = {"generation": 0}

    def show(ctx):
        files = [i for i in ctx.items if not i.is_dir]
        if len(files) != 1 or not files[0].name.lower().endswith(SUFFIXES):
            return
        path = ctx.backend.join(ctx.folder, files[0].name)
        state["generation"] += 1
        generation = state["generation"]
        font = view.document().defaultFont()

        def work():
            """Read and convert in the background: ``setMarkdown`` on the
            GUI thread froze the window for a large or crafted file."""
            text, read_cut = read_markdown(ctx.backend, path)
            html, render_cut = render_html(text, font)
            return html, read_cut or render_cut

        def done(result):
            if state["generation"] != generation:
                return  # the selection moved on meanwhile
            html, cut = result
            if cut:
                note = tr("Preview cut: only the beginning of the file is shown "
                          "(at most {kib} KiB, and less for long tables or "
                          "heavily formatted text).").format(kib=MAX_BYTES // 1024)
                head, tag, tail = html.rpartition("</body>")
                if tag:
                    html = f"{head}<hr /><p><i>{escape(note)}</i></p>{tag}{tail}"
            view.setHtml(html)

        def failed(exc):
            if state["generation"] != generation:
                return  # a late error must not replace the newer preview
            view.setPlainText(tr("Cannot read {path}: {error}").format(path=path, error=exc))

        api.run_in_background(
            work,
            on_done=done,
            on_error=failed,
        )

    api.on("selection_changed", show)
