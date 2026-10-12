"""Application themes.

Two families live here:

* **modern** (the default): token-driven light and dark stylesheets.
  ``modern`` itself follows the operating system's colour scheme;
  ``modern-light`` / ``modern-dark`` pin one variant.
* **classic**: the stylesheets the application shipped before the
  modern family existed (``classic`` is the old dark theme, plus the
  light, hacker and amber themes), kept byte-for-byte so nothing a
  user relied on moves.

Everything in this module is Qt-free except :func:`system_scheme`, so
the palette and the resolution rules are unit-testable headless.
"""
from __future__ import annotations

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
        css = build_modern_qss(_MODERN_VARIANTS[resolved])
    elif resolved in ("classic", "dark"):
        css = DARK_THEME + _CLASSIC_MUTED_DARK
    elif resolved == "hacker":
        css = HACKER_THEME + _CLASSIC_MUTED_DARK
    elif resolved == "amber":
        css = AMBER_THEME + _CLASSIC_MUTED_DARK
    else:
        css = _CLASSIC_MUTED_LIGHT
    if compact:
        css += COMPACT_CSS
    return css


def tokens_for(resolved: str) -> dict[str, str] | None:
    """Palette tokens of a resolved modern id, ``None`` for classic ids."""
    return _MODERN_VARIANTS.get(resolved)


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
