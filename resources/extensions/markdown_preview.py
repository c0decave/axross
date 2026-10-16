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


def read_markdown(backend, path: str, limit: int = MAX_BYTES) -> tuple[str, bool]:
    """The file's text (UTF-8, damaged bytes replaced) and whether it was
    cut at *limit*."""
    with backend.open_read(path) as fh:
        data = fh.read(limit + 1)
    cut = len(data) > limit
    return data[:limit].decode("utf-8", "replace"), cut


def activate(api):
    from PyQt6.QtWidgets import QTextBrowser

    view = QTextBrowser()
    view.setOpenExternalLinks(False)  # a click never leaves axross unasked
    view.setOpenLinks(False)
    view.setPlaceholderText("Select a Markdown file (.md) to preview it here.")
    api.add_dock("Markdown Preview", view)
    state = {"wanted": None}

    def show(ctx):
        files = [i for i in ctx.items if not i.is_dir]
        if len(files) != 1 or not files[0].name.lower().endswith(SUFFIXES):
            return
        path = ctx.backend.join(ctx.folder, files[0].name)
        state["wanted"] = path

        def done(result, p=path):
            if state["wanted"] != p:
                return  # the selection moved on meanwhile
            text, cut = result
            if cut:
                text += f"\n\n---\n*Preview cut at {MAX_BYTES // 1024} KiB.*"
            view.setMarkdown(text)

        api.run_in_background(
            lambda: read_markdown(ctx.backend, path),
            on_done=done,
            on_error=lambda exc: view.setPlainText(f"Cannot read {path}: {exc}"),
        )

    api.on("selection_changed", show)
