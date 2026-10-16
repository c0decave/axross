"""Release keyboard modifiers a test left held.

QApplication remembers the modifier state of the last key event it saw.
A test whose QTest.keyClick(..., Ctrl+Shift+D) opened a window before the
modifier releases arrived left Shift held for the rest of the process, and
every later selectRow() became a Shift-range selection that selected
nothing (a flaky drag test, red only in long runs).
"""

from __future__ import annotations

_KEYS = ("Key_Shift", "Key_Control", "Key_Alt", "Key_Meta")


def release_held_modifiers(app):
    """Release whatever modifier *app* still holds; return what was held
    (``NoModifier`` when nothing was)."""
    from PyQt6.QtCore import Qt
    from PyQt6.QtTest import QTest

    held = app.keyboardModifiers()
    if held == Qt.KeyboardModifier.NoModifier:
        return held
    target = app.activeWindow() or app.focusWidget()
    if target is None:
        target = next((w for w in app.topLevelWidgets() if not w.isHidden()), None)
    if target is None:
        from PyQt6.QtWidgets import QWidget

        target = QWidget()  # any widget makes QApplication see the release
    for name in _KEYS:
        QTest.keyRelease(target, getattr(Qt.Key, name))
    return held
