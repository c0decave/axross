"""Every window with the [x] corner can be maximized and restored.

Only the image and media viewer could (0.8.64: title-bar button, Ctrl+M).
Reported: many newer windows lacked the maximize / restore
function, its icon left of the [x], and the viewers' hotkey. The corner
now brings all three: a maximize / restore button left of the [x], the
Maximize hint in the title bar and Ctrl+M - one shortcut per window, also
where a viewer installs its own keys (two would make Ctrl+M ambiguous and
dead).
"""

from __future__ import annotations

import ast
import os
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

ROOT = Path(__file__).resolve().parent.parent

QtWidgets = pytest.importorskip("PyQt6.QtWidgets")
from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtGui import QKeySequence, QShortcut  # noqa: E402
from PyQt6.QtWidgets import QApplication, QDialog, QHBoxLayout, QLabel, QToolButton, QVBoxLayout  # noqa: E402


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


def _dialog(layout=QVBoxLayout):
    dlg = QDialog()
    layout(dlg).addWidget(QLabel("content"))
    return dlg


def _max_button(dlg):
    return dlg.findChildren(QToolButton, "axMaximizeCorner")


def _ctrl_m(dlg):
    want = QKeySequence("Ctrl+M")
    return [s for s in dlg.findChildren(QShortcut) if s.key() == want]


def _pump(app, n=5):
    for _ in range(n):
        app.processEvents()


# -- happy ---------------------------------------------------------------------


def test_happy_the_button_sits_left_of_the_close_corner(app):
    from ui.close_corner import add_close_corner

    dlg = _dialog()
    close = add_close_corner(dlg)
    dlg.resize(500, 300)
    dlg.show()
    _pump(app)
    [maxi] = _max_button(dlg)
    m = maxi.mapTo(dlg, maxi.rect().topLeft())
    c = close.mapTo(dlg, close.rect().topLeft())
    assert m.x() < c.x() and c.x() - m.x() < 60
    assert abs(m.y() - c.y()) < 6
    assert not maxi.icon().isNull()
    assert dlg.windowFlags() & Qt.WindowType.WindowMaximizeButtonHint
    dlg.close()


def test_happy_click_maximizes_and_click_again_restores(app):
    from ui.close_corner import add_close_corner

    dlg = _dialog()
    add_close_corner(dlg)
    dlg.show()
    _pump(app)
    [maxi] = _max_button(dlg)
    assert "Maximize" in maxi.toolTip() and "Ctrl+M" in maxi.toolTip()
    maxi.click()
    _pump(app)
    assert dlg.isMaximized()
    assert "Restore" in maxi.toolTip()
    maxi.click()
    _pump(app)
    assert not dlg.isMaximized()
    assert "Maximize" in maxi.toolTip()
    dlg.close()


def test_happy_ctrl_m_toggles_the_window(app):
    from ui.close_corner import add_close_corner

    dlg = _dialog()
    add_close_corner(dlg)
    dlg.show()
    _pump(app)
    [sc] = _ctrl_m(dlg)
    sc.activated.emit()
    _pump(app)
    assert dlg.isMaximized()
    sc.activated.emit()
    _pump(app)
    assert not dlg.isMaximized()
    dlg.close()


# -- sad -----------------------------------------------------------------------


def test_sad_a_viewer_installing_its_own_keys_keeps_one_ctrl_m(app):
    # The image viewer adds the corner first and its keys later, the media
    # viewer the other way round: both must end with one Ctrl+M.
    from ui import viewer_window as VW
    from ui.close_corner import add_close_corner

    first = _dialog()
    add_close_corner(first)
    VW.install_window_keys(first, fullscreen=True)
    second = _dialog()
    VW.install_window_keys(second, fullscreen=False)
    add_close_corner(second)
    for dlg in (first, second):
        assert len(_ctrl_m(dlg)) == 1
        assert len(_max_button(dlg)) == 1


def test_sad_installing_twice_adds_one_button_and_one_shortcut(app):
    from ui.close_corner import add_close_corner

    dlg = _dialog()
    add_close_corner(dlg)
    add_close_corner(dlg)
    assert len(_max_button(dlg)) == 1
    assert len(_ctrl_m(dlg)) == 1


def test_sad_every_module_with_a_bare_close_corner_also_has_the_maximize_corner():
    missing = []
    for path in sorted((ROOT / "ui").glob("*.py")):
        if path.name == "close_corner.py":
            continue
        calls = {ast.unparse(n.func).split(".")[-1] for n in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
                 if isinstance(n, ast.Call)}
        if "make_close_corner" in calls and "make_maximize_corner" not in calls:
            missing.append(path.name)
    assert missing == []


# -- edge ----------------------------------------------------------------------


def test_edge_a_dialog_without_a_vertical_layout_keeps_it_left_of_the_x(app):
    from ui.close_corner import add_close_corner

    dlg = _dialog(QHBoxLayout)
    close = add_close_corner(dlg)
    for width in (480, 900):
        dlg.resize(width, 300)
        dlg.show()
        _pump(app)
        [maxi] = _max_button(dlg)
        m = maxi.mapTo(dlg, maxi.rect().topLeft())
        c = close.mapTo(dlg, close.rect().topLeft())
        assert m.x() + maxi.width() <= c.x() and m.x() > width * 0.7, width
        assert m.y() < 40
    dlg.close()


def test_edge_a_dialog_already_on_screen_stays_on_screen(app):
    # Setting a window flag hides a visible window; the corner shows it again.
    from ui.close_corner import add_close_corner

    dlg = _dialog()
    dlg.show()
    _pump(app)
    add_close_corner(dlg)
    _pump(app)
    assert dlg.isVisible()
    assert dlg.windowFlags() & Qt.WindowType.WindowMaximizeButtonHint
    dlg.close()


def test_edge_the_text_and_hex_editor_have_it(app, tmp_path):
    from core.local_fs import LocalFS
    from ui.hex_editor import HexEditorDialog
    from ui.text_editor import TextEditorDialog

    f = tmp_path / "a.txt"
    f.write_text("hello\n")
    for cls in (TextEditorDialog, HexEditorDialog):
        dlg = cls(LocalFS(), str(f))
        assert len(_max_button(dlg)) == 1, cls.__name__
        assert len(_ctrl_m(dlg)) == 1, cls.__name__
        assert dlg.windowFlags() & Qt.WindowType.WindowMaximizeButtonHint
        dlg.deleteLater()


def test_edge_the_icon_follows_a_maximize_from_the_title_bar(app):
    # The window manager's own button (or a double click on the title)
    # changes the state without the corner button: its icon follows.
    from ui.close_corner import add_close_corner

    dlg = _dialog()
    add_close_corner(dlg)
    dlg.show()
    _pump(app)
    [maxi] = _max_button(dlg)
    dlg.showMaximized()
    _pump(app)
    assert "Restore" in maxi.toolTip()
    dlg.showNormal()
    _pump(app)
    assert "Maximize" in maxi.toolTip()
    dlg.close()
