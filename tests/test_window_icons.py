"""Every window, dialog and panel shows the icon of what it stands for - in
its title bar, the task bar, the docked-windows bar and as a floating or
tabbed panel. The axross icon only where a window has none of its own."""

from __future__ import annotations

import ast
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

ROOT = Path(__file__).resolve().parent.parent
SOURCES = sorted((ROOT / "ui").glob("*.py")) + sorted((ROOT / "resources" / "extensions").rglob("*.py"))
WINDOW_BASES = {"QDialog", "QMainWindow", "QDockWidget", "QWizard"}
#: Windows that show the axross icon on purpose (file::class -> why).
APP_ICON = {
    "ui/main_window.py::MainWindow": "the application window itself",
    "ui/about_dialog.py::AboutDialog": "About axross: its logo is the app icon",
}
#: The calls that give a window or panel its icon, and where the name is.
ICON_CALLS = {"set_window_icon": 1, "_install_dock_titlebar": 2, "_menu_icon": 1}


def _rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def _name(func: ast.expr) -> str:
    return func.id if isinstance(func, ast.Name) else getattr(func, "attr", "")


def _calls(node: ast.AST) -> list[ast.Call]:
    return [c for c in ast.walk(node) if isinstance(c, ast.Call)]


def _trees() -> dict[str, ast.Module]:
    return {_rel(p): ast.parse(p.read_text(encoding="utf-8")) for p in SOURCES}


def _window_classes(trees: dict[str, ast.Module]) -> list[tuple[str, ast.ClassDef]]:
    """Classes that are windows: (transitively) a QDialog / QMainWindow /
    QDockWidget, or a QWidget made with Qt.WindowType.Window."""
    bases: dict[str, set[str]] = {}
    for tree in trees.values():
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                bases.setdefault(node.name, set()).update(_name(b) for b in node.bases)

    def is_window(name: str, seen: frozenset = frozenset()) -> bool:
        if name in WINDOW_BASES:
            return True
        if name in seen or name not in bases:
            return False
        return any(is_window(b, seen | {name}) for b in bases[name])

    found = []
    for rel, tree in trees.items():
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            own_window = any(
                _name(c.func) == "__init__" and "WindowType.Window" in ast.unparse(c)
                for c in _calls(node)
            )
            if own_window or any(is_window(_name(b)) for b in node.bases):
                found.append((rel, node))
    return found


def test_happy_the_scan_finds_the_windows():
    names = {f"{rel}::{cls.name}" for rel, cls in _window_classes(_trees())}
    for expected in ("ui/bluetooth_details.py::DeviceDialog", "ui/arcade_window.py::ArcadeWindow",
                     "ui/log_dock.py::LogDock", "ui/chat_panel.py::ChatWindow",
                     "resources/extensions/agent_stats.py::StatsWindow"):
        assert expected in names
    assert len(names) > 80


def test_sad_no_window_class_is_left_with_the_axross_icon():
    missing = []
    for rel, cls in _window_classes(_trees()):
        key = f"{rel}::{cls.name}"
        if key in APP_ICON:
            continue
        if not any(_name(c.func) == "set_window_icon" for c in _calls(cls)):
            missing.append(key)
    assert missing == [], "give these their own icon: ui.icon_provider.set_window_icon(self, NAME)"


def test_sad_no_function_builds_a_window_without_its_icon():
    """A QDialog / QDockWidget / Qt.WindowType.Window QWidget made inline (not
    a class of its own) gets its icon in the same function."""
    missing = []
    for rel, tree in _trees().items():
        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            calls = _calls(fn)
            builds = [c for c in calls if _name(c.func) in ("QDialog", "QDockWidget")
                      or (_name(c.func) == "QWidget" and "WindowType.Window" in ast.unparse(c))
                      or (_name(c.func) == "ExtensionDock")]
            if not builds:
                continue
            named = {_name(c.func) for c in calls}
            if not ({"set_window_icon", "_install_dock_titlebar", "DockTitleBar",
                     "ExtensionPanelTitleBar"} & named):
                missing.append(f"{rel}::{fn.name}")
    assert missing == []


def test_sad_every_icon_named_for_a_window_exists():
    from ui.icon_provider import has_icon

    named, unknown = [], []
    for rel, tree in _trees().items():
        for call in _calls(tree):
            fn = _name(call.func)
            values = []
            if fn in ICON_CALLS and len(call.args) > ICON_CALLS[fn]:
                values.append(call.args[ICON_CALLS[fn]])
            if fn in ("add_dock", "add_menu_action", "ExtensionPanelTitleBar", "DockTitleBar"):
                values += [k.value for k in call.keywords if k.arg in ("icon", "icon_name")]
                if fn == "DockTitleBar" and len(call.args) > 1:
                    values.append(call.args[1])
            for v in values:
                if isinstance(v, ast.Constant) and isinstance(v.value, str):
                    named.append(v.value)
                    if not has_icon(v.value):
                        unknown.append(f"{rel}:{call.lineno} {v.value}")
    assert len(named) > 90
    assert unknown == []


def test_sad_every_bundled_panel_and_menu_entry_brings_its_icon():
    missing = []
    for path in sorted((ROOT / "resources" / "extensions").rglob("*.py")):
        for call in _calls(ast.parse(path.read_text(encoding="utf-8"))):
            if _name(call.func) in ("add_dock", "add_menu_action") and \
                    not any(k.arg == "icon" for k in call.keywords):
                missing.append(f"{_rel(path)}:{call.lineno}")
    assert missing == []


def test_happy_the_feature_icons_are_their_own_and_read_on_both_themes():
    from ui import icon_provider as IP
    from ui.themes import contrast_ratio

    own = ("bluetooth", "chat", "mail", "mail-project", "log", "system-info", "stats", "history",
           "clock", "heatmap", "forensics", "markdown", "workspace", "hex", "keyboard", "mixer")
    svgs = [IP.ICONS[name] for name in own]
    assert len(set(svgs)) == len(own)  # no two share a drawing
    assert IP.ICONS["mixer"] != IP.ICONS["audio-settings"]
    assert IP.ICONS["mail"] != IP.ICONS["inbox"]
    for name, svg in zip(own, svgs):
        assert 'viewBox="0 0 24 24"' in svg and 'stroke="currentColor"' in svg
        colour = IP._ICON_COLORS[name]
        assert contrast_ratio(colour, "#1e1e2e") >= 3.0, (name, colour)
        assert contrast_ratio(colour, "#ffffff") >= 1.8, (name, colour)


@pytest.fixture(scope="module")
def app():
    pytest.importorskip("PyQt6.QtWidgets")
    from PyQt6.QtWidgets import QApplication

    return QApplication.instance() or QApplication([])


def _painted(qicon) -> int:
    image = qicon.pixmap(32, 32).toImage()
    return sum(image.pixelColor(x, y).alpha() > 0 for x in range(32) for y in range(32))


def test_happy_a_window_shows_its_own_icon_not_the_apps(app):
    from PyQt6.QtWidgets import QDialog

    from ui.icon_provider import WINDOW_ICON_PROPERTY, icon, set_window_icon

    app.setWindowIcon(icon("unknown", 64))
    dialog = QDialog()
    assert dialog.windowIcon().cacheKey() == app.windowIcon().cacheKey()  # Qt's default
    set_window_icon(dialog, "bluetooth")
    assert dialog.property(WINDOW_ICON_PROPERTY) == "bluetooth"
    assert dialog.windowIcon().cacheKey() != app.windowIcon().cacheKey()
    assert _painted(dialog.windowIcon()) > 20
    dialog.deleteLater()


def test_happy_a_theme_switch_draws_the_window_icons_again(app):
    from PyQt6.QtWidgets import QDialog

    from ui import icon_provider as IP

    dialog = QDialog()
    IP.set_window_icon(dialog, "chat")
    before = dialog.windowIcon().pixmap(32, 32).toImage()
    try:
        IP.set_monochrome(True)
        assert IP.refresh_window_icons() >= 1
        after = dialog.windowIcon().pixmap(32, 32).toImage()
        assert after != before  # black strokes now, not the teal
    finally:
        IP.set_monochrome(False)
        IP.refresh_window_icons()
        dialog.deleteLater()


def test_happy_a_panel_title_bar_gives_the_dock_its_icon(app):
    from PyQt6.QtWidgets import QDockWidget

    from ui.dock_titlebar import DockTitleBar
    from ui.icon_provider import WINDOW_ICON_PROPERTY

    dock = QDockWidget("Mail: work")
    bar = DockTitleBar("Mail: work", "mail", dock)
    dock.setTitleBarWidget(bar)
    assert dock.property(WINDOW_ICON_PROPERTY) == "mail"
    assert bar.icon_name == "mail"
    bar.refresh_icon()
    assert _painted(dock.windowIcon()) > 20
    dock.deleteLater()


def test_edge_an_unknown_name_is_a_visible_placeholder_not_a_blank(app):
    from PyQt6.QtWidgets import QDialog

    from ui.icon_provider import set_window_icon

    dialog = QDialog()
    set_window_icon(dialog, "no-such-icon")
    assert _painted(dialog.windowIcon()) > 20
    dialog.deleteLater()
