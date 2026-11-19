"""Round 3: a window title showed a name from outside as it is - "Bluetooth
Device – {name}" with the name a device sends over the air, "Versions –
{path}" and "Open as root: {path}" with a file's path. A bidi override in
it read the title reversed (``inv\\u202efdp.exe`` as "invexe.pdf") and a
line break split it, in the title bar and the task bar. Round 2 defused
titles one by one; ui.markup_guard now does it for every window: a title
is shown as a one-line status is (ui.plain_text.one_line)."""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_sad_every_window_title_is_shown_as_the_pane_shows_a_name():
    code = textwrap.dedent("""
        import ui
        from PyQt6.QtWidgets import QApplication, QDialog, QWidget
        app = QApplication([])
        for cls in (QWidget, QDialog):
            w = cls()
            w.setWindowTitle("Bluetooth Device \\u2013 inv\\u202efdp.exe\\nsecond")
            title = w.windowTitle()
            assert "\\u202e" not in title and "\\n" not in title, repr(title)
            assert title == "Bluetooth Device \\u2013 inv\\ufffdfdp.exe second", repr(title)
            w.setWindowTitle("Properties: report.pdf")
            assert w.windowTitle() == "Properties: report.pdf"
        print("ok")
    """)
    env = dict(os.environ, QT_QPA_PLATFORM="offscreen")
    out = subprocess.run([sys.executable, "-c", code], cwd=str(ROOT), env=env,
                         capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stderr[-2000:]
    assert out.stdout.strip() == "ok"
