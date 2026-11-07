"""core.mail_html and the project window's safe message view."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core.mail_html import sanitise  # noqa: E402

HOSTILE = """<html><head><style>body{background:url(http://track.example/p.gif)}</style>
<script>alert(1)</script></head><body onload="steal()">
<p style="color:red" onclick="x()">Dear customer,</p>
<img src="http://track.example/pixel.gif" alt="logo" width=1>
<a href="http://evil.example/login">https://www.bank.example/login</a>
<a href="javascript:alert(1)">click</a>
<a href="mailto:boss@corp.example">mail</a>
<iframe src="http://evil.example/frame"><p>inside</p></iframe>
<form action="http://evil.example/post"><input name="pw"></form>
<table><tr><td colspan="2" bgcolor="red">cell</td></tr></table>
<svg onload="x()"><script>1</script></svg>
&lt;not a tag&gt; &amp;
</body></html>"""


def test_happy_nothing_active_survives_and_links_say_where_they_go():
    out = sanitise(HOSTILE)
    low = out.lower()
    for bad in ("<script", "<style", "<iframe", "<form", "<input", "<svg", "<img", "onload", "onclick",
                "style=", "javascript:", "track.example", "bgcolor", "inside"):
        assert bad not in low, bad
    assert '<a href="http://evil.example/login">https://www.bank.example/login</a> <small>[&#8594; evil.example]</small>' in out
    assert "[image: logo]" in out
    assert '<a>click</a> <small>[&#8594; not a web address]</small>' in out
    assert "[&#8594; boss@corp.example]" in out
    assert '<td colspan="2">cell</td>' in out
    assert "&lt;not a tag&gt; &amp;" in out


@pytest.mark.parametrize("text", ["<p><b>unclosed", "</div></p>stray", "<a href='http://x.example'>a<b>b</a>c",
                                  "<script>never closed", "<<<>>>"])
def test_edge_broken_html_stays_balanced(text):
    out = sanitise(text)
    for tag in ("p", "b", "a", "div"):
        assert out.count(f"<{tag}") == out.count(f"</{tag}>"), out
    assert "never closed" not in out


def test_happy_the_project_window_shows_the_message_safely_and_asks_before_a_link(tmp_path, monkeypatch):
    from PyQt6.QtCore import QUrl
    from PyQt6.QtWidgets import QApplication, QMessageBox

    from test_mail_message_analyse import PHISH

    from ui.mail_project import MailProjectDialog

    app = QApplication.instance() or QApplication([])
    (tmp_path / "p.eml").write_bytes(PHISH)
    dlg = MailProjectDialog(folder=str(tmp_path / "proj"))
    dlg.project.import_paths([str(tmp_path / "p.eml")])
    dlg.refresh()
    dlg.table.selectRow(0)
    app.processEvents()
    html_out = dlg.message_view.toHtml()
    assert "203.0.113.9" in dlg.message_view.toPlainText()          # the real target is shown
    assert dlg.message_view.loadResource(2, QUrl("http://track.example/x.png")) is None
    opened = []
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: QMessageBox.StandardButton.No)
    monkeypatch.setattr("PyQt6.QtGui.QDesktopServices.openUrl", lambda url: opened.append(url))
    dlg.message_view.anchorClicked.emit(QUrl("http://203.0.113.9/login"))
    assert dlg.message_view.asked == ["http://203.0.113.9/login"] and opened == []
    assert "<script" not in html_out.lower()
    dlg.done(0)
