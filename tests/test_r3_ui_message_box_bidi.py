"""Round 3: a message box showed a name with a bidi override as it is.
"Could not extract {name}:" (an archive's name), Batch Rename's
"Refusing unsafe rename '{old_name}' -> '{new_name}'" - whose names are
refused *because* they hold such characters - and others read reversed
from the override on. Round 2 escaped some of them one by one (as_written);
ui.markup_guard now shows every message box text as the pane shows a name
(a bidi override, control or invisible character as U+FFFD; line breaks
and tabs stay)."""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _run(code: str) -> None:
    env = dict(os.environ, QT_QPA_PLATFORM="offscreen")
    out = subprocess.run([sys.executable, "-c", textwrap.dedent(code)], cwd=str(ROOT), env=env,
                         capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stderr[-2000:]
    assert out.stdout.strip().endswith("ok"), out.stdout


def test_sad_a_message_box_text_with_a_bidi_override_is_defused():
    _run("""
        import ui
        from PyQt6.QtCore import QTimer
        from PyQt6.QtWidgets import QApplication, QMessageBox
        app = QApplication([])
        text = "Could not extract inv\\u202efdp.zip:\\n\\tdamaged"
        box = QMessageBox(QMessageBox.Icon.Warning, "Extract", text)
        assert box.text() == "Could not extract inv\\ufffdfdp.zip:\\n\\tdamaged", repr(box.text())
        box.setText(text)
        assert "\\u202e" not in box.text()
        box.setInformativeText(text)
        assert "\\u202e" not in box.informativeText()
        seen = []
        def grab():
            w = app.activeModalWidget()
            if w is None:
                QTimer.singleShot(20, grab)
                return
            seen.append(w.text())
            w.close()
        QTimer.singleShot(20, grab)
        QMessageBox.warning(None, "Invalid Name", "Refusing unsafe rename 'a\\u202eb' -> 'c'")
        assert seen and "\\u202e" not in seen[0] and "a\\ufffdb" in seen[0], seen
        print("ok")
    """)


def test_happy_ordinary_and_written_texts_are_unchanged():
    _run("""
        import ui
        from PyQt6.QtWidgets import QApplication, QMessageBox
        from ui.plain_text import as_written
        app = QApplication([])
        for text in ("Delete 3 items?", "Größe: 4\\u00a0MB\\n\\nweiter?",
                     as_written("x <b>y</b>\\n z")):
            box = QMessageBox(QMessageBox.Icon.Question, "t", text)
            assert box.text() == text, (box.text(), text)
        print("ok")
    """)
