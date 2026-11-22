"""Help > About axross-markdown…: the program's name, version and licence, and the licences of what its
one-file programs contain - read-only.

The texts are THIRD_PARTY_LICENSES.txt, which axross's scripts/export_standalone.py writes into the
program's package (scripts/standalone_licences.py: the licence texts of every package of its lock, the
notices, where the source code is); the one-file programs carry it (packaging/axross-markdown.spec).
Run from axross's own tree, it is axross's THIRD_PARTY_LICENSES.md.
"""

from __future__ import annotations

from pathlib import Path

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFontDatabase
from PyQt6.QtWidgets import QDialog, QDialogButtonBox, QLabel, QPlainTextEdit, QVBoxLayout

from core.i18n import tr

NAME = "axross-markdown"
LICENCES = "THIRD_PARTY_LICENSES.txt"
#: Largest licence file read (the real one is ~150 KB).
MAX_BYTES = 4 * 1024 * 1024


def licences_path() -> Path | None:
    """The licence file: the package's (…/axross_markdown/THIRD_PARTY_LICENSES.txt beside _ax/) - or,
    in axross's tree, axross's THIRD_PARTY_LICENSES.md; None when neither is there."""
    here = Path(__file__).resolve().parent  # (…/axross_markdown/_ax/ui, or axross's ui/)
    candidate = here.parent.parent / LICENCES if here.parent.name == "_ax" else here.parent / "THIRD_PARTY_LICENSES.md"
    return candidate if candidate.is_file() else None


def licences_text() -> str:
    """The licence file's text (bounded); what is missing, said, when there is none."""
    path = licences_path()
    if path is None:
        return tr("The licences of the third-party software are not in this copy of the program "
                  "({name}).").format(name=LICENCES)
    try:
        with open(path, "rb") as fh:
            data = fh.read(MAX_BYTES + 1)
    except OSError as exc:
        return tr("The licences of the third-party software could not be read: {error}").format(error=exc)
    text = data[:MAX_BYTES].decode("utf-8", errors="replace")
    return text + ("\n…\n" if len(data) > MAX_BYTES else "")


def statement() -> str:
    """The program's licence, in a few lines."""
    return tr("{name} is licensed under the Apache License 2.0. Its one-file programs contain PyQt6 "
              "(GPL-3.0) and Qt (LGPL-3.0): each is a combined work, distributed under the GPL-3.0. "
              "What they contain, the licence texts and where the source code is:").format(name=NAME)


class AboutDialog(QDialog):
    """The name and version, the licence statement and the licence texts (read-only)."""

    def __init__(self, version: str, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle(tr("About {name}").format(name=NAME))
        layout = QVBoxLayout(self)
        from ui.close_corner import add_close_corner
        from ui.icon_provider import set_window_icon

        set_window_icon(self, "markdown")  # (the program's own icon, as its viewer's)
        add_close_corner(self)  # (the [x] in the corner, as every window with a Close button has)
        self.title = QLabel(f"{NAME} {version}")
        self.title.setTextFormat(Qt.TextFormat.PlainText)
        font = self.title.font()
        font.setBold(True)
        font.setPointSizeF(font.pointSizeF() * 1.3)
        self.title.setFont(font)
        layout.addWidget(self.title)
        self.statement = QLabel(statement())
        self.statement.setTextFormat(Qt.TextFormat.PlainText)
        self.statement.setWordWrap(True)
        layout.addWidget(self.statement)
        self.licences = QPlainTextEdit()
        self.licences.setObjectName("licences")
        self.licences.setReadOnly(True)
        self.licences.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.licences.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))
        self.licences.setPlainText(licences_text())
        layout.addWidget(self.licences, 1)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        metrics = self.licences.fontMetrics()
        self.resize(metrics.horizontalAdvance("M") * 86, metrics.height() * 36)


def show_about(parent=None) -> AboutDialog:
    """The About window (non-modal, closed: deleted)."""
    from core.markdown_cli import program_version

    dialog = AboutDialog(program_version(), parent)
    dialog.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
    dialog.show()
    return dialog


__all__ = ["AboutDialog", "licences_path", "licences_text", "show_about", "statement"]
