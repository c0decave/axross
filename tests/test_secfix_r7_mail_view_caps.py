"""Round-7 finding M3: a long plain-text mail froze the mail viewer.

core/mail_html.py wrapped a plain-text body in ``<pre>`` with no cap, and
the viewer's QTextBrowser lays out all it holds at once: a 4 MB mail of
newlines kept the GUI thread 24.6 s (509 MB), 6 MB of alternating Hebrew
and Latin 20.7 s. Now a plain-text mail goes to a plain view (a
QPlainTextEdit, which lays out only the lines on screen; lines broken after
PLAIN_LINE characters, at most MAX_PLAIN characters / MAX_PLAIN_LINES
lines), and the formatted view gets at most MAX_SHOWN characters of
sanitised HTML - "Show All as Plain Text" shows the rest in the plain view.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import mail_html as M  # noqa: E402
from core.mail_message import MailMessage  # noqa: E402


def _msg(text: str = "", html: str = "") -> MailMessage:
    msg = MailMessage()
    msg.text, msg.html = text, html
    return msg


def test_sad_a_long_plain_text_mail_is_not_given_whole_to_the_formatted_view():
    body = "x\n" * 1_000_000
    view = M.message_view(_msg(body))
    assert view.html is None                      # the plain view shows it
    assert view.plain.count("\n") < M.MAX_PLAIN_LINES and view.plain_cut
    shown = M.message_html(_msg(body))
    assert len(shown) <= M.MAX_SHOWN + 64


def test_sad_a_long_html_mail_is_cut_for_the_formatted_view():
    body = "<p>" + "אa" * 1_000_000 + "</p>"
    view = M.message_view(_msg(html=body))
    assert view.cut and len(view.html) <= M.MAX_SHOWN + 64
    assert view.html.endswith("</p>")             # still balanced
    assert view.plain.startswith("אa") and not view.plain_cut
    assert max(len(line) for line in view.plain.split("\n")) <= M.PLAIN_LINE


def test_happy_a_short_mail_is_shown_whole():
    view = M.message_view(_msg("hello\nworld", "<p>Hi <b>there</b></p>"))
    assert not view.cut and "<b>there</b>" in view.html
    assert view.plain == "hello\nworld" and not view.plain_cut
    view = M.message_view(_msg(html="<p>one</p><p>two<br>three</p><script>x()</script>"))
    assert view.plain == "one\n\ntwo\nthree"
    assert M.message_html(_msg("a < b")) == "<pre>a &lt; b</pre>"


def test_edge_plain_lines_breaks_long_lines_and_counts_lines():
    text, cut = M.plain_lines("y" * (M.PLAIN_LINE * 3 + 5))
    assert [len(line) for line in text.split("\n")] == [M.PLAIN_LINE] * 3 + [5] and not cut
    text, cut = M.plain_lines("\n" * (M.MAX_PLAIN_LINES + 10))
    assert text.count("\n") == M.MAX_PLAIN_LINES - 1 and cut
    assert M.plain_lines("") == ("", False)


def test_e2e_the_viewer_shows_a_4_mb_plain_mail_at_once_and_a_long_html_mail_offers_show_all(tmp_path):
    """In a child (a regression would freeze the run): the 4 MB mail of the
    report in the plain view in well under a second (24.6 s before), and a
    long HTML mail cut, with Show All switching to the plain view."""
    code = textwrap.dedent(f"""
        import sys, time
        sys.path.insert(0, {str(ROOT)!r})
        import ui
        from PyQt6.QtWidgets import QApplication
        from core import mail_html
        from core.mail_message import MailMessage
        from ui.mail_project import MailProjectDialog
        app = QApplication([])
        dlg = MailProjectDialog(folder={str(tmp_path / "proj")!r})
        dlg.show(); dlg.detail_tabs.setCurrentIndex(1); app.processEvents()
        msg = MailMessage(); msg.text = "x\\n" * 2_000_000
        view = mail_html.message_view(msg)
        dlg._showing = 1
        started = time.monotonic()
        dlg._shown(1, view, ""); app.processEvents()
        plain_s = time.monotonic() - started
        print("plain", round(plain_s, 2), dlg.message_pages.currentIndex(),
              dlg.message_view.toPlainText() == "")
        msg = MailMessage(); msg.html = "<p>" + "\\u05d0a" * 1_000_000 + "</p>"
        view = mail_html.message_view(msg)
        dlg._showing = 2
        started = time.monotonic()
        dlg._shown(2, view, ""); app.processEvents()
        html_s = time.monotonic() - started
        print("html", round(html_s, 2), dlg.message_pages.currentIndex(),
              dlg.cut_bar.isVisible())
        dlg.show_all_button.click(); app.processEvents()
        print("all", dlg.message_pages.currentIndex(),
              dlg.message_plain.toPlainText().startswith("\\u05d0a"))
        dlg.done(0)
    """)
    env = dict(os.environ, QT_QPA_PLATFORM="offscreen", HOME=str(tmp_path))
    started = time.monotonic()
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                         timeout=120, env=env)
    lines = {line.split()[0]: line.split()[1:] for line in out.stdout.splitlines() if line}
    assert "all" in lines, out.stdout + out.stderr[-2000:]
    plain_s, page, empty = lines["plain"]
    assert float(plain_s) < 3.0 and page == "1" and empty == "True"
    html_s, page, bar = lines["html"]
    assert float(html_s) < 5.0 and page == "0" and bar == "True"
    assert lines["all"] == ["1", "True"]
    assert time.monotonic() - started < 110
