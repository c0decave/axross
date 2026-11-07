"""Help > About axross: the text scrolls, the window fits the screen.

QMessageBox.about sized itself to the whole text: 967 px high (1009 px
in German), so OK was below a 768 or 800 px screen. Here the text sits
in a QTextBrowser that scrolls once the screen is too short for it.
"""

from __future__ import annotations

from PyQt6.QtCore import QSize, Qt
from PyQt6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from ui.screen_fit import fit_size
from ui.close_corner import add_close_corner

#: Width the text is laid out at; its height decides the window's.
TEXT_WIDTH_PX = 560


class AboutDialog(QDialog):
    def __init__(self, title: str, html: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setObjectName("axAboutDialog")
        self._html = html

        icon = QLabel()
        app_icon = self.windowIcon()
        if not app_icon.isNull():
            icon.setPixmap(app_icon.pixmap(64, 64))
        icon.setAlignment(Qt.AlignmentFlag.AlignTop)

        self._text = QTextBrowser()
        self._text.setObjectName("axAboutText")
        self._text.setFrameShape(QFrame.Shape.NoFrame)
        self._text.setOpenExternalLinks(True)
        self._text.setHtml(html)

        row = QHBoxLayout()
        row.addWidget(icon)
        row.addWidget(self._text, 1)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok)
        buttons.accepted.connect(self.accept)

        layout = QVBoxLayout(self)
        layout.addLayout(row, 1)
        layout.addWidget(buttons)

        # The whole text without a scroll bar while the screen has room.
        doc = self._text.document()
        doc.setTextWidth(TEXT_WIDTH_PX)
        text_height = int(doc.size().height()) + 8
        extra = buttons.sizeHint().height() + 3 * layout.spacing() + 2 * 12
        width = TEXT_WIDTH_PX + 64 + 3 * 12 + self._text.verticalScrollBar().sizeHint().width()
        self.resize(fit_size(QSize(width, text_height + extra), self))
        add_close_corner(self)

    @property
    def html(self) -> str:
        return self._html

    @property
    def text_browser(self) -> QTextBrowser:
        return self._text
