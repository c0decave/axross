"""Application themes.

Two families live here:

* **modern** (the default): token-driven light and dark stylesheets.
  ``modern`` itself follows the operating system's colour scheme;
  ``modern-light`` / ``modern-dark`` pin one variant.
* **classic**: the stylesheets the application shipped before the
  modern family existed (``classic`` is the old dark theme, plus the
  light, hacker and amber themes), kept byte-for-byte so nothing a
  user relied on moves.

Everything in this module is Qt-free except :func:`system_scheme` and the
helpers that take or build a QPalette (:func:`qpalette_for`,
:func:`hidden_entry_color`, which import Qt lazily), so the palette and the
resolution rules are unit-testable headless.
"""
from __future__ import annotations

import contextlib
import gc
import os
import re
from collections.abc import Iterator

DEFAULT_THEME = "modern"

#: (theme id, menu label). ``classic`` is the former dark theme; the
#: legacy id ``dark`` stays valid for old session files but is not
#: listed twice.
THEME_CHOICES: list[tuple[str, str]] = [
    ("modern", "Modern (follow system)"),
    ("modern-light", "Modern Light"),
    ("modern-dark", "Modern Dark"),
    ("classic", "Classic"),
    ("default", "Light Mode"),
    ("hacker", "Hacker Mode"),
    ("amber", "Amber Mode"),
]

_VALID = {theme_id for theme_id, _ in THEME_CHOICES} | {"dark"}



@contextlib.contextmanager
def collection_paused() -> Iterator[None]:
    """No cyclic garbage collection while Qt restyles every widget.

    QApplication.setStyleSheet / setStyle / setPalette / setFont walk a
    copied list of widgets and send each an event. A Python handler on one
    of them (the script editor re-highlights on a palette change) allocates
    and can start the collector, which deletes widgets only Python owned
    while Qt still walks its list: a segfault. The collector waits until
    the walk is over; garbage from before it is collected after it. (No
    collection first: it cost 11-20 ms per restyle, and the paused
    collector alone keeps tests/test_restyle_gc_pause.py's reproduction
    alive.)
    """
    was_enabled = gc.isenabled()
    gc.disable()
    try:
        yield
    finally:
        if was_enabled:
            gc.enable()


# --- classic stylesheets (unchanged) -------------------------------------

DARK_THEME = """
QMainWindow, QWidget {
    background-color: #1e1e2e;
    color: #cdd6f4;
}
QMenuBar {
    background-color: #181825;
    color: #cdd6f4;
}
QMenuBar::item:selected {
    background-color: #45475a;
}
QMenu {
    background-color: #1e1e2e;
    color: #cdd6f4;
    border: 1px solid #45475a;
}
QMenu::item:selected {
    background-color: #45475a;
}
QToolBar {
    background-color: #181825;
    border: none;
    spacing: 4px;
}
QTableView {
    background-color: #1e1e2e;
    alternate-background-color: #181825;
    color: #cdd6f4;
    gridline-color: #313244;
    selection-background-color: #45475a;
    selection-color: #cdd6f4;
}
QHeaderView::section {
    background-color: #181825;
    color: #cdd6f4;
    border: 1px solid #313244;
    padding: 4px;
}
QLineEdit {
    background-color: #313244;
    color: #cdd6f4;
    border: 1px solid #45475a;
    border-radius: 3px;
    padding: 2px 4px;
}
QPushButton {
    background-color: #313244;
    color: #cdd6f4;
    border: 1px solid #45475a;
    border-radius: 3px;
    padding: 4px 8px;
}
QPushButton:hover {
    background-color: #45475a;
}
QProgressBar {
    background-color: #313244;
    border: 1px solid #45475a;
    border-radius: 3px;
    text-align: center;
    color: #cdd6f4;
}
QProgressBar::chunk {
    background-color: #89b4fa;
}
QDockWidget {
    color: #cdd6f4;
}
QDockWidget::title {
    background-color: #181825;
    padding: 4px;
}
QLabel {
    color: #cdd6f4;
}
QSplitter::handle {
    background-color: #45475a;
}
QScrollBar:vertical, QScrollBar:horizontal {
    background-color: #1e1e2e;
}
QScrollBar::handle:vertical, QScrollBar::handle:horizontal {
    background-color: #45475a;
    border-radius: 3px;
}
QTabBar::tab {
    background-color: #181825;
    color: #cdd6f4;
    padding: 4px 8px;
    border: 1px solid #313244;
}
QTabBar::tab:selected {
    background-color: #313244;
}
QPlainTextEdit {
    background-color: #1e1e2e;
    color: #cdd6f4;
    selection-background-color: #45475a;
}
QListWidget {
    background-color: #1e1e2e;
    color: #cdd6f4;
}
QComboBox {
    background-color: #313244;
    color: #cdd6f4;
    border: 1px solid #45475a;
}
QDialog {
    background-color: #1e1e2e;
    color: #cdd6f4;
}
"""

HACKER_THEME = """
QMainWindow, QWidget {
    background-color: #0a0a0a;
    color: #00ff41;
    font-family: "Fira Code", "Cascadia Code", "Consolas", monospace;
}
QMenuBar {
    background-color: #0d0d0d;
    color: #00ff41;
}
QMenuBar::item:selected {
    background-color: #003300;
}
QMenu {
    background-color: #0a0a0a;
    color: #00ff41;
    border: 1px solid #004400;
}
QMenu::item:selected {
    background-color: #003300;
}
QToolBar {
    background-color: #0d0d0d;
    border-bottom: 1px solid #004400;
    spacing: 4px;
}
QTableView {
    background-color: #0a0a0a;
    alternate-background-color: #0d0d0d;
    color: #00ff41;
    gridline-color: #003300;
    selection-background-color: #004400;
    selection-color: #00ff41;
}
QHeaderView::section {
    background-color: #0d0d0d;
    color: #00cc33;
    border: 1px solid #003300;
    padding: 4px;
}
QLineEdit {
    background-color: #111111;
    color: #00ff41;
    border: 1px solid #004400;
    border-radius: 0px;
    padding: 2px 4px;
}
QPushButton {
    background-color: #111111;
    color: #00ff41;
    border: 1px solid #004400;
    border-radius: 0px;
    padding: 4px 8px;
}
QPushButton:hover {
    background-color: #003300;
    border-color: #00ff41;
}
QProgressBar {
    background-color: #111111;
    border: 1px solid #004400;
    border-radius: 0px;
    text-align: center;
    color: #00ff41;
}
QProgressBar::chunk {
    background-color: #00cc33;
}
QDockWidget {
    color: #00ff41;
}
QDockWidget::title {
    background-color: #0d0d0d;
    padding: 4px;
}
QLabel {
    color: #00ff41;
}
QSplitter::handle {
    background-color: #004400;
}
QScrollBar:vertical, QScrollBar:horizontal {
    background-color: #0a0a0a;
}
QScrollBar::handle:vertical, QScrollBar::handle:horizontal {
    background-color: #003300;
}
QTabBar::tab {
    background-color: #0d0d0d;
    color: #00ff41;
    padding: 4px 8px;
    border: 1px solid #003300;
}
QTabBar::tab:selected {
    background-color: #003300;
    border-bottom: 2px solid #00ff41;
}
QPlainTextEdit {
    background-color: #0a0a0a;
    color: #00ff41;
    selection-background-color: #003300;
    font-family: "Fira Code", "Cascadia Code", "Consolas", monospace;
}
QListWidget {
    background-color: #0a0a0a;
    color: #00ff41;
}
QComboBox {
    background-color: #111111;
    color: #00ff41;
    border: 1px solid #004400;
}
QDialog {
    background-color: #0a0a0a;
    color: #00ff41;
}
"""

AMBER_THEME = """
QMainWindow, QWidget {
    background-color: #0a0a0a;
    color: #ff8c00;
    font-family: "Fira Code", "Cascadia Code", "Consolas", monospace;
}
QMenuBar {
    background-color: #0d0d0d;
    color: #ff8c00;
}
QMenuBar::item:selected {
    background-color: #331a00;
}
QMenu {
    background-color: #0a0a0a;
    color: #ff8c00;
    border: 1px solid #442200;
}
QMenu::item:selected {
    background-color: #331a00;
}
QToolBar {
    background-color: #0d0d0d;
    border-bottom: 1px solid #442200;
    spacing: 4px;
}
QTableView {
    background-color: #0a0a0a;
    alternate-background-color: #0d0d0d;
    color: #ff8c00;
    gridline-color: #331a00;
    selection-background-color: #442200;
    selection-color: #ffaa00;
}
QHeaderView::section {
    background-color: #0d0d0d;
    color: #cc7000;
    border: 1px solid #331a00;
    padding: 4px;
}
QLineEdit {
    background-color: #111111;
    color: #ff8c00;
    border: 1px solid #442200;
    border-radius: 0px;
    padding: 2px 4px;
}
QPushButton {
    background-color: #111111;
    color: #ff8c00;
    border: 1px solid #442200;
    border-radius: 0px;
    padding: 4px 8px;
}
QPushButton:hover {
    background-color: #331a00;
    border-color: #ff8c00;
}
QProgressBar {
    background-color: #111111;
    border: 1px solid #442200;
    border-radius: 0px;
    text-align: center;
    color: #ff8c00;
}
QProgressBar::chunk {
    background-color: #cc7000;
}
QDockWidget {
    color: #ff8c00;
}
QDockWidget::title {
    background-color: #0d0d0d;
    padding: 4px;
}
QLabel {
    color: #ff8c00;
}
QSplitter::handle {
    background-color: #442200;
}
QScrollBar:vertical, QScrollBar:horizontal {
    background-color: #0a0a0a;
}
QScrollBar::handle:vertical, QScrollBar::handle:horizontal {
    background-color: #331a00;
}
QTabBar::tab {
    background-color: #0d0d0d;
    color: #ff8c00;
    padding: 4px 8px;
    border: 1px solid #331a00;
}
QTabBar::tab:selected {
    background-color: #331a00;
    border-bottom: 2px solid #ff8c00;
}
QPlainTextEdit {
    background-color: #0a0a0a;
    color: #ff8c00;
    selection-background-color: #331a00;
    font-family: "Fira Code", "Cascadia Code", "Consolas", monospace;
}
QListWidget {
    background-color: #0a0a0a;
    color: #ff8c00;
}
QComboBox {
    background-color: #111111;
    color: #ff8c00;
    border: 1px solid #442200;
}
QDialog {
    background-color: #0a0a0a;
    color: #ff8c00;
}
"""


COMPACT_CSS = """
QSplitter::handle {
    width: 1px;
    height: 1px;
}
QHeaderView::section {
    padding: 1px 3px;
}
QDockWidget::title {
    padding: 1px;
}
QTabBar::tab {
    padding: 2px 6px;
}
QToolBar {
    spacing: 1px;
    padding: 0px;
}
QPushButton {
    padding: 2px 4px;
}
QTableView {
    gridline-color: transparent;
}
"""


# --- modern family -------------------------------------------------------

MODERN_DARK: dict[str, str] = {
    "bg": "#14161b",
    "surface": "#1b1e25",
    "surface_alt": "#232731",
    "border": "#2e3340",
    "text": "#e6e8ee",
    "text_muted": "#9aa1b2",
    "accent": "#6c8cff",
    "accent_hover": "#869fff",
    "accent_fg": "#0b0e17",
    "accent_text_on_surface": "#8fa8ff",
    "selection": "#2b3558",
    "selection_text": "#ffffff",
    "danger": "#ff6b6b",
    "radius": "6px",
    # The line between two header sections - where a column is dragged:
    # 3.1:1 against the header (surface), WCAG 1.4.11 for a control edge.
    "header_divider": "#646b7e",
}

MODERN_LIGHT: dict[str, str] = {
    "bg": "#f4f5f8",
    "surface": "#ffffff",
    "surface_alt": "#eceef4",
    "border": "#d9dce6",
    "text": "#1a1d26",
    "text_muted": "#566074",
    "accent": "#3b5bdb",
    "accent_hover": "#4c6ae6",
    "accent_fg": "#ffffff",
    "accent_text_on_surface": "#2f4ac2",
    "selection": "#dbe3ff",
    "selection_text": "#12172b",
    "danger": "#c92a2a",
    "radius": "6px",
    "header_divider": "#8a91a3",  # 3.2:1 against the header (surface)
}

_MODERN_TEMPLATE = """
QMainWindow, QDialog {{
    background-color: {bg};
}}
QWidget {{
    color: {text};
    selection-background-color: {selection};
    selection-color: {selection_text};
}}
QMenuBar {{
    background-color: {bg};
    border-bottom: 1px solid {border};
    padding: 2px 4px;
}}
QMenuBar::item {{
    background: transparent;
    padding: 5px 10px;
    border-radius: {radius};
}}
QMenuBar::item:selected {{
    background-color: {surface_alt};
}}
QMenu {{
    background-color: {surface};
    border: 1px solid {border};
    border-radius: {radius};
    padding: 6px;
}}
QMenu::item {{
    padding: 6px 24px 6px 12px;
    border-radius: 4px;
}}
QMenu::item:selected {{
    background-color: {selection};
    color: {selection_text};
}}
QMenu::separator {{
    height: 1px;
    background: {border};
    margin: 5px 8px;
}}
QToolBar {{
    background-color: {bg};
    border: none;
    border-bottom: 1px solid {border};
    spacing: 4px;
    padding: 4px;
}}
QToolButton {{
    background: transparent;
    border: 1px solid transparent;
    border-radius: {radius};
    padding: 4px;
}}
QToolButton:hover {{
    background-color: {surface_alt};
    border-color: {border};
}}
QToolButton:pressed, QToolButton:checked {{
    background-color: {selection};
}}
QTableView, QTreeView, QListView, QListWidget {{
    background-color: {surface};
    alternate-background-color: {surface_alt};
    border: 1px solid {border};
    border-radius: {radius};
    gridline-color: transparent;
    outline: 0;
}}
QTableView::item, QTreeView::item, QListView::item {{
    padding: 3px 6px;
}}
QTableView::item:selected, QTreeView::item:selected, QListView::item:selected {{
    background-color: {selection};
    color: {selection_text};
}}
QHeaderView::section {{
    background-color: {surface};
    color: {text_muted};
    border: none;
    border-bottom: 1px solid {border};
    padding: 6px 8px;
    font-weight: 600;
}}
QHeaderView::section:horizontal {{
    border-right: 1px solid {header_divider};
}}
QLineEdit, QSpinBox, QDoubleSpinBox, QComboBox, QPlainTextEdit, QTextEdit {{
    background-color: {surface};
    border: 1px solid {border};
    border-radius: {radius};
    padding: 5px 8px;
}}
QLineEdit:focus, QSpinBox:focus, QDoubleSpinBox:focus, QComboBox:focus,
QPlainTextEdit:focus, QTextEdit:focus {{
    border: 1px solid {accent};
}}
QComboBox::drop-down {{
    border: none;
    width: 22px;
}}
QComboBox QAbstractItemView {{
    background-color: {surface};
    border: 1px solid {border};
    selection-background-color: {selection};
    selection-color: {selection_text};
}}
QPushButton {{
    background-color: {surface_alt};
    border: 1px solid {border};
    border-radius: {radius};
    padding: 5px 8px;
}}
QDialogButtonBox QPushButton {{
    padding: 6px 16px;
    min-width: 72px;
}}
QPushButton:hover {{
    border-color: {accent};
}}
QPushButton:pressed {{
    background-color: {selection};
}}
QPushButton:checked {{
    background-color: {selection};
    color: {selection_text};
    border-color: {accent};
}}
QPushButton:default {{
    background-color: {accent};
    border-color: {accent};
    color: {accent_fg};
}}
QPushButton:default:hover {{
    background-color: {accent_hover};
}}
QPushButton:disabled {{
    color: {text_muted};
}}
QCheckBox, QRadioButton {{
    spacing: 8px;
}}
QGroupBox {{
    border: 1px solid {border};
    border-radius: {radius};
    margin-top: 10px;
    padding-top: 8px;
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 4px;
    color: {text_muted};
}}
QTabWidget::pane {{
    border: 1px solid {border};
    border-radius: {radius};
}}
QTabBar::tab {{
    background: transparent;
    color: {text_muted};
    padding: 6px 12px;
    border: none;
    border-bottom: 2px solid transparent;
}}
QTabBar::tab:selected {{
    color: {text};
    border-bottom: 2px solid {accent};
}}
QTabBar::tab:hover:!selected {{
    color: {text};
    background-color: {surface_alt};
}}
QDockWidget {{
    titlebar-close-icon: none;
}}
QDockWidget::title {{
    background-color: {surface};
    border-bottom: 1px solid {border};
    padding: 6px 8px;
}}
QSplitter::handle {{
    background-color: {border};
}}
QSplitter::handle:hover {{
    background-color: {accent};
}}
QScrollBar:vertical {{
    background: transparent;
    width: 10px;
    margin: 0;
}}
QScrollBar:horizontal {{
    background: transparent;
    height: 10px;
    margin: 0;
}}
QScrollBar::handle:vertical, QScrollBar::handle:horizontal {{
    background-color: {border};
    border-radius: 5px;
    min-height: 28px;
    min-width: 28px;
}}
QScrollBar::handle:hover {{
    background-color: {text_muted};
}}
QScrollBar::add-line, QScrollBar::sub-line {{
    width: 0;
    height: 0;
}}
QScrollBar::add-page, QScrollBar::sub-page {{
    background: transparent;
}}
QProgressBar {{
    background-color: {surface_alt};
    border: none;
    border-radius: 4px;
    text-align: center;
    min-height: 14px;
}}
QProgressBar::chunk {{
    background-color: {accent};
    border-radius: 4px;
}}
QStatusBar {{
    background-color: {bg};
    border-top: 1px solid {border};
}}
QToolTip {{
    background-color: {surface_alt};
    color: {text};
    border: 1px solid {border};
    padding: 4px 6px;
}}
QLabel[role="muted"] {{
    color: {text_muted};
}}
QAbstractScrollArea::corner {{
    background: transparent;
    border: none;
}}
QScrollArea {{
    background: transparent;
    border: none;
}}
QScrollArea > QWidget > QWidget {{
    background: transparent;
}}
"""


def build_modern_qss(tokens: dict[str, str]) -> str:
    """Render the modern template with *tokens*.

    A missing token raises ``KeyError`` instead of silently producing a
    half-styled application.
    """
    return _MODERN_TEMPLATE.format_map(tokens)


# Secondary text. Classic themes get the same ``role="muted"`` hook so
# widgets can say "this is secondary" without hard-coding a grey that
# is unreadable on one of the backgrounds.
_CLASSIC_MUTED_DARK = '\nQLabel[role="muted"] {\n    color: #a6adc8;\n}\n'
_CLASSIC_MUTED_LIGHT = '\nQLabel[role="muted"] {\n    color: #666666;\n}\n'

_MODERN_VARIANTS = {"modern-light": MODERN_LIGHT, "modern-dark": MODERN_DARK}

# Added to the classic stylesheets above (which stay as they were):
# a line at the right edge of every horizontal header section - where a
# column is dragged - at 3:1 or more against the header background (WCAG
# 1.4.11; their own 1px border reached 1.2-1.4:1), and a checked button
# that looks checked (Auto-Scroll in the Log dock looked the same on and
# off). Values: (header divider, checked background, checked border,
# checked text).
_CLASSIC_EXTRA_COLOURS: dict[str, tuple[str, str, str, str]] = {
    "classic": ("#6c7086", "#45475a", "#89b4fa", "#cdd6f4"),  # 3.6:1 on #181825
    "hacker": ("#00802b", "#004400", "#00ff41", "#00ff41"),  # 3.8:1 on #0d0d0d
    "amber": ("#995200", "#442200", "#ff8c00", "#ffaa00"),  # 3.3:1 on #0d0d0d
}


def _classic_extra_css(resolved: str) -> str:
    divider, checked_bg, checked_border, checked_text = _CLASSIC_EXTRA_COLOURS[resolved]
    return (
        "\nQHeaderView::section:horizontal {\n"
        f"    border-right: 1px solid {divider};\n"
        "}\n"
        "QPushButton:checked {\n"
        f"    background-color: {checked_bg};\n"
        f"    color: {checked_text};\n"
        f"    border-color: {checked_border};\n"
        "}\n"
    )


# The native light theme keeps the desktop's look and palette; its header
# divider comes from that palette (Fusion's own line reached 2.0:1, Breeze
# draws a short one). ``shadow`` is the palette's darkest edge colour.
_NATIVE_HEADER_CSS = """
QHeaderView::section:horizontal {
    background-color: palette(button);
    color: palette(button-text);
    border: none;
    border-bottom: 1px solid palette(mid);
    border-right: 1px solid palette(shadow);
    padding: 4px;
}
"""


# Check boxes and radio buttons: Fusion drew an unchecked indicator at
# 1.0-1.6:1 against the background in every theme - in Hacker and Amber
# Mode not at all (WCAG 1.4.11 asks 3:1 for a control's edge). Values per
# theme: (edge, background, checked fill, check mark).
_INDICATOR_COLOURS: dict[str, tuple[str, str, str, str]] = {
    "modern-dark": (MODERN_DARK["text_muted"], MODERN_DARK["surface"],
                    MODERN_DARK["accent"], MODERN_DARK["accent_fg"]),
    "modern-light": (MODERN_LIGHT["text_muted"], MODERN_LIGHT["surface"],
                     MODERN_LIGHT["accent"], MODERN_LIGHT["accent_fg"]),
    "classic": ("#a6adc8", "#1e1e2e", "#89b4fa", "#1e1e2e"),
    "hacker": ("#00b33c", "#0a0a0a", "#00ff41", "#0a0a0a"),
    "amber": ("#cc7000", "#0a0a0a", "#ff8c00", "#0a0a0a"),
    # The native theme keeps the desktop palette; the mark is drawn white
    # on the highlight colour (an image cannot follow the palette).
    "native": ("palette(text)", "palette(base)", "palette(highlight)", "#ffffff"),
}

_CHECK_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 14 14">'
    '<path d="M3 7.2 L5.8 10 L11 4" fill="none" stroke="{colour}" stroke-width="2"'
    ' stroke-linecap="round" stroke-linejoin="round"/></svg>'
)
_DASH_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 14 14">'
    '<path d="M3.5 7 H10.5" stroke="{colour}" stroke-width="2" stroke-linecap="round"/></svg>'
)


def _indicator_dir():
    from pathlib import Path

    base = os.environ.get("XDG_CACHE_HOME", "").strip()
    root = Path(base) if base and os.path.isabs(base) else Path.home() / ".cache"
    return root / "axross" / "qss"


def _mark_file(template: str, kind: str, colour: str) -> str | None:
    """A check mark image in *colour* for a stylesheet ``url()``; None when
    it cannot be written (the box is then filled without a mark)."""
    folder = _indicator_dir()
    path = folder / f"{kind}-{colour.lstrip('#').lower()}.svg"
    text = template.format(colour=colour)
    try:
        if not path.is_file() or path.read_text(encoding="utf-8") != text:
            folder.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(f".{os.getpid()}.tmp")
            tmp.write_text(text, encoding="utf-8")
            os.replace(tmp, path)
    except OSError:
        return None
    return path.as_posix()


def _indicator_css(key: str) -> str:
    edge, base, fill, mark = _INDICATOR_COLOURS[key]
    check = _mark_file(_CHECK_SVG, "check", mark)
    dash = _mark_file(_DASH_SVG, "dash", mark)
    check_image = f'    image: url("{check}");\n' if check else ""
    dash_image = f'    image: url("{dash}");\n' if dash else ""
    return (
        "\nQCheckBox::indicator, QRadioButton::indicator, QGroupBox::indicator {\n"
        "    width: 14px;\n    height: 14px;\n"
        f"    border: 1px solid {edge};\n"
        f"    background-color: {base};\n"
        "}\n"
        "QCheckBox::indicator, QGroupBox::indicator {\n    border-radius: 3px;\n}\n"
        "QRadioButton::indicator {\n    border-radius: 8px;\n}\n"
        "QCheckBox::indicator:checked, QGroupBox::indicator:checked {\n"
        f"    background-color: {fill};\n    border-color: {fill};\n{check_image}"
        "}\n"
        "QCheckBox::indicator:indeterminate {\n"
        f"    background-color: {fill};\n    border-color: {fill};\n{dash_image}"
        "}\n"
        "QRadioButton::indicator:checked {\n"
        f"    border-color: {fill};\n"
        "    background-color: qradialgradient(cx:0.5, cy:0.5, radius:0.5, fx:0.5, fy:0.5,"
        f" stop:0 {fill}, stop:0.45 {fill}, stop:0.55 {base}, stop:1 {base});\n"
        "}\n"
        "QCheckBox::indicator:disabled, QRadioButton::indicator:disabled,"
        " QGroupBox::indicator:disabled {\n    border-style: dotted;\n}\n"
    )


def _version_css(key: str) -> str:
    """The version bottom right (ui.main_window): secondary text without a
    button frame; with an update notice in the theme's accent, so it is
    seen and reads as something to click."""
    muted, _base, accent, _mark = _INDICATOR_COLOURS[key]
    return (
        "\nQPushButton#axVersion {\n"
        f"    border: none;\n    background: transparent;\n    color: {muted};\n"
        "    padding: 0 6px;\n"
        "}\n"
        'QPushButton#axVersion[notice="true"] {\n'
        f"    color: {accent};\n    font-weight: bold;\n"
        "}\n"
        'QPushButton#axVersion[notice="true"]:hover {\n    text-decoration: underline;\n}\n'
    )


def normalize(theme: object) -> str:
    """Return a valid theme id; anything unknown becomes the default."""
    if isinstance(theme, str) and (theme in _VALID or theme == DEFAULT_THEME):
        return theme
    return DEFAULT_THEME


def resolve(theme: object, system_scheme: str | None) -> str:
    """Resolve ``modern`` against the OS colour scheme.

    Returns a concrete id: ``modern-light`` / ``modern-dark`` or one of
    the classic ids. An unknown or undetectable scheme resolves dark.
    """
    theme_id = normalize(theme)
    if theme_id != "modern":
        return theme_id
    return "modern-light" if system_scheme == "light" else "modern-dark"


def pane_family(resolved: str) -> str:
    """Key into the file pane's header colour table."""
    if resolved == "classic":
        return "dark"
    return resolved


def stylesheet_for(theme: object, system_scheme: str | None, compact: bool = False) -> str:
    """Complete application stylesheet for *theme*."""
    resolved = resolve(theme, system_scheme)
    if resolved in _MODERN_VARIANTS:
        css = build_modern_qss(_MODERN_VARIANTS[resolved]) + _indicator_css(resolved)
    elif resolved in ("classic", "dark"):
        css = DARK_THEME + _CLASSIC_MUTED_DARK + _classic_extra_css("classic")
        css += _indicator_css("classic")
    elif resolved == "hacker":
        css = HACKER_THEME + _CLASSIC_MUTED_DARK + _classic_extra_css("hacker")
        css += _indicator_css("hacker")
    elif resolved == "amber":
        css = AMBER_THEME + _CLASSIC_MUTED_DARK + _classic_extra_css("amber")
        css += _indicator_css("amber")
    else:
        css = _CLASSIC_MUTED_LIGHT + _NATIVE_HEADER_CSS + _indicator_css("native")
    css += _version_css("classic" if resolved == "dark" else
                        resolved if resolved in _INDICATOR_COLOURS else "native")
    if compact:
        css += COMPACT_CSS
    return css


_TOOLBAR_BACKGROUND = re.compile(r"QToolBar\s*\{[^}]*?background-color:\s*(#[0-9a-fA-F]{6})")


def toolbar_background(resolved: str) -> str | None:
    """The toolbar's background colour in the resolved theme, read from its
    stylesheet (``QToolBar { background-color: ... }``); ``None`` when the
    stylesheet leaves it to the palette (the native light theme)."""
    match = _TOOLBAR_BACKGROUND.search(stylesheet_for(resolved, None))
    return match.group(1).lower() if match else None


# Icon colour of the tinted themes — the foreground colour of the
# matching stylesheet above (HACKER_THEME / AMBER_THEME).
_ICON_TINTS = {"hacker": "#00ff41", "amber": "#ff8c00"}


def icon_tint_for(resolved: str) -> str | None:
    """Single icon colour for a resolved theme id, ``None`` when the
    theme keeps the regular per-icon palette."""
    return _ICON_TINTS.get(resolved)


def tokens_for(resolved: str) -> dict[str, str] | None:
    """Palette tokens of a resolved modern id, ``None`` for classic ids."""
    return _MODERN_VARIANTS.get(resolved)


# Palette tokens of the classic dark-family themes. Their stylesheets name
# only some widgets (QTableView, QLineEdit, ...); everything else (tree and
# list views with alternating rows, spin boxes, check boxes, tab widgets)
# falls back to the PALETTE, which on a light desktop is white - green text
# on a white alternate row in Hacker mode. Giving these themes a matching
# palette makes the unnamed widgets follow the theme too.
_CLASSIC_PALETTE_TOKENS: dict[str, dict[str, str]] = {
    "classic": {
        "bg": "#1e1e2e",
        "text": "#cdd6f4",
        "surface": "#1e1e2e",
        "surface_alt": "#181825",
        "selection": "#45475a",
        "selection_text": "#cdd6f4",
        "accent_text_on_surface": "#89b4fa",
        "text_muted": "#a6adc8",
    },
    "hacker": {
        "bg": "#0a0a0a",
        "text": "#00ff41",
        "surface": "#0a0a0a",
        "surface_alt": "#0d0d0d",
        "selection": "#004400",
        "selection_text": "#00ff41",
        "accent_text_on_surface": "#00ff41",
        "text_muted": "#00aa2c",
    },
    "amber": {
        "bg": "#0a0a0a",
        "text": "#ff8c00",
        "surface": "#0a0a0a",
        "surface_alt": "#0d0d0d",
        "selection": "#442200",
        "selection_text": "#ffaa00",
        "accent_text_on_surface": "#ffaa00",
        "text_muted": "#cc7000",
    },
}
_CLASSIC_PALETTE_TOKENS["dark"] = _CLASSIC_PALETTE_TOKENS["classic"]


def palette_tokens_for(resolved: str) -> dict[str, str] | None:
    """Tokens for the application QPalette of a resolved theme id: the
    modern tokens, the dark-family tokens above, ``None`` for the
    light / native theme (it keeps the desktop palette)."""
    return _MODERN_VARIANTS.get(resolved) or _CLASSIC_PALETTE_TOKENS.get(resolved)


def qpalette_for(tokens: dict[str, str]):
    """QPalette matching *tokens*, so widgets the stylesheet does not
    name (message boxes, calendars, native-looking dialogs) follow the
    theme instead of the desktop's scheme."""
    from PyQt6.QtGui import QColor, QPalette

    role = QPalette.ColorRole
    mapping = {
        role.Window: "bg",
        role.WindowText: "text",
        role.Base: "surface",
        role.AlternateBase: "surface_alt",
        role.Text: "text",
        role.Button: "surface_alt",
        role.ButtonText: "text",
        role.ToolTipBase: "surface_alt",
        role.ToolTipText: "text",
        role.Highlight: "selection",
        role.HighlightedText: "selection_text",
        role.Link: "accent_text_on_surface",
        role.PlaceholderText: "text_muted",
    }
    palette = QPalette()
    for qt_role, token in mapping.items():
        palette.setColor(qt_role, QColor(tokens[token]))
    disabled = QPalette.ColorGroup.Disabled
    for qt_role in (role.WindowText, role.Text, role.ButtonText):
        palette.setColor(disabled, qt_role, QColor(tokens["text_muted"]))
    return palette


#: WCAG AA for normal text: the least contrast a text colour may have.
MIN_TEXT_CONTRAST = 4.5


def is_hex_colour(value: object) -> bool:
    """``#rrggbb`` and nothing else - the one colour form the session file
    and the colour settings store."""
    return (
        isinstance(value, str)
        and len(value) == 7
        and value[0] == "#"
        and all(c in "0123456789abcdefABCDEF" for c in value[1:])
    )


def _relative_luminance(hex_colour: str) -> float:
    value = hex_colour.lstrip("#")
    channels = [int(value[i:i + 2], 16) / 255.0 for i in (0, 2, 4)]
    linear = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def contrast_ratio(a: str, b: str) -> float:
    """WCAG contrast ratio of two ``#rrggbb`` colours (1.0 to 21.0)."""
    la, lb = _relative_luminance(a), _relative_luminance(b)
    hi, lo = max(la, lb), min(la, lb)
    return (hi + 0.05) / (lo + 0.05)


def hidden_entry_color(palette):
    """Text colour for hidden entries in a file listing: the palette's
    muted text colour (``PlaceholderText``; the themes map ``text_muted``
    there), or ``None`` when it is not readable on both row backgrounds
    (``Base`` and ``AlternateBase``) - then hidden entries are only set in
    italics. A desktop palette is not ours to trust: a light grey on white
    would make hidden files hard to read."""
    from PyQt6.QtGui import QPalette

    role = QPalette.ColorRole
    muted = palette.color(role.PlaceholderText)
    worst = min(
        contrast_ratio(muted.name(), palette.color(role.Base).name()),
        contrast_ratio(muted.name(), palette.color(role.AlternateBase).name()),
    )
    return muted if worst >= MIN_TEXT_CONTRAST else None


def system_scheme() -> str | None:
    """``"dark"``, ``"light"`` or ``None`` when Qt cannot tell."""
    try:
        from PyQt6.QtCore import Qt
        from PyQt6.QtGui import QGuiApplication

        hints = QGuiApplication.styleHints()
        if hints is None:
            return None
        scheme = hints.colorScheme()
    except Exception:  # noqa: BLE001 - no Qt / old Qt: caller falls back to dark
        return None
    if scheme == Qt.ColorScheme.Dark:
        return "dark"
    if scheme == Qt.ColorScheme.Light:
        return "light"
    return None
