"""core.mail_html's safe view never hangs, and the project window parses and
sanitises a message off the GUI thread.

What was wrong: ``_Sanitiser.close()`` looped ``while self.stack:
self.handle_endtag(self.stack[-1])``, and ``handle_endtag`` returns without
popping while a dropped element is open (``skip > 0``) - so any message with
an element still open when a dropped one never ends spun at 100 % CPU, on the
GUI thread (ui/mail_project.py rendered the selection there):
``<div><embed src="x.swf"></div>`` (embed, source and track counted as
elements with content, waiting for an end tag that never comes),
``<p>a<video src=x></p>``, ``<b>x<script>...`` and ``<p>Hi<svg/>...`` (a
self-closing ``<svg/>`` raised ``skip`` too). The whole application froze
when such a mail was selected. The import also could not be cancelled.
"""

from __future__ import annotations

import itertools
import os
import random
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import mail_html  # noqa: E402
from core.mail_html import sanitise  # noqa: E402

LIMIT_S = 10.0


def bounded(func, *args, limit: float = LIMIT_S):
    """func(*args) on a thread; fails (instead of hanging) after *limit* s."""
    out: list = []
    t = threading.Thread(target=lambda: out.append(func(*args)), daemon=True)
    t.start()
    t.join(limit)
    assert not t.is_alive(), f"{func.__name__} did not end within {limit} s for {str(args)[:200]!r}"
    assert out, "the call raised"
    return out[0]


def balanced(out: str) -> bool:
    return all(out.count(f"<{tag}>") + out.count(f"<{tag} ") == out.count(f"</{tag}>")
               for tag in ("p", "b", "a", "div", "td", "table", "span"))


REPORTED = ['<div><embed src="x.swf"></div>', "<p>a<video src=x></p>", "<b>x<script>alert(1)",
            "<p>Hi<svg/>there</p>"]


@pytest.mark.parametrize("text", REPORTED)
def test_sad_the_reported_mails_end_and_drop_what_they_must(text):
    out = bounded(sanitise, text)
    assert balanced(out), out
    for bad in ("<embed", "<video", "<script", "alert", "<svg", "x.swf"):
        assert bad not in out.lower()


def test_edge_void_and_self_closing_dropped_elements_keep_the_rest():
    assert bounded(sanitise, '<p>Hi<svg/>there</p>') == "<p>Hithere</p>"
    assert bounded(sanitise, '<div><embed src="x.swf">after</div>') == "<div>after</div>"
    out = bounded(sanitise, "<video><source src=x><track src=y>fallback</video><p>after</p>")
    assert out == "<p>after</p>"
    # </embed> (a void element's end tag) does not end the video around it
    assert "inside" not in bounded(sanitise, "<video><embed></embed>inside</video>after")


PIECES = ["<p>", "</p>", "<b>", "</b>", "<div>", "</div>", "<a href='http://x.example/'>", "</a>", "<script>",
          "</script>", "<style>", "</style>", "<svg/>", "<svg>", "</svg>", "<embed src=x>", "</embed>",
          "<video src=v>", "</video>", "<source src=s>", "<track>", "<img alt=i>", "<br/>", "<b/>", "<a/>",
          "<iframe>", "</iframe>", "<table><tr><td>", "</td>", "<template>", "</template>", "<!--", "-->",
          "<math>", "</math>", "text", "&amp;", "<", ">", "</", "<p", '"', "<object>", "<frame>", "<link>",
          "</link>", "<noscript>", "</noscript>", "<x/>", "</x>", "<title>"]


def snippets():
    yield from REPORTED
    yield from ("".join(p) for p in itertools.product(PIECES[:14], repeat=2))
    rng = random.Random(7)
    for _ in range(1500):
        yield "".join(rng.choice(PIECES) for _ in range(rng.randint(1, 14)))


def test_sad_fuzz_no_malformed_snippet_hangs_and_the_output_stays_balanced():
    def run_all(texts):
        for text in texts:
            out = sanitise(text)
            assert balanced(out), (text, out)
            assert "<script" not in out.lower() and "<svg" not in out.lower(), (text, out)
        return True

    texts = list(snippets())
    assert bounded(run_all, texts, limit=60.0)


@pytest.mark.parametrize("text,kept", [
    ("<div>" * 20_000 + "</span>" * 20_000 + "<p>end</p>", "end"),   # every end tag searched all that was open
    ("<embed>" * 50_000 + "<p>end</p>", "end"),                      # each one opened a dropped region
    ("<svg/>" * 50_000 + "<p>end</p>", "end"),
])
def test_edge_long_hostile_markup_ends_in_time_and_keeps_the_text_after_it(text, kept):
    out = bounded(sanitise, text, limit=60.0)
    assert balanced(out) and kept in out
    assert out.count("<div>") <= 256


# --- the project window ----------------------------------------------------------------------

def _dialog(tmp_path):
    from PyQt6.QtWidgets import QApplication

    from test_mail_message_analyse import PHISH

    from ui.mail_project import MailProjectDialog

    app = QApplication.instance() or QApplication([])
    (tmp_path / "p.eml").write_bytes(PHISH)
    dlg = MailProjectDialog(folder=str(tmp_path / "proj"))
    dlg.project.import_paths([str(tmp_path / "p.eml")])
    dlg.refresh()
    return app, dlg


def test_happy_the_message_is_rendered_off_the_gui_thread(tmp_path, monkeypatch):
    app, dlg = _dialog(tmp_path)
    release, threads = threading.Event(), []
    real = mail_html.message_view

    def slow(msg):
        threads.append(threading.current_thread() is threading.main_thread())
        release.wait(5)
        return real(msg)
    monkeypatch.setattr(mail_html, "message_view", slow)
    started = time.monotonic()
    dlg.table.selectRow(0)
    assert time.monotonic() - started < 3, "the selection waited for the message to be rendered"
    release.set()
    deadline = time.monotonic() + 30
    while "203.0.113.9" not in dlg.message_view.toPlainText() and time.monotonic() < deadline:
        app.processEvents()
        time.sleep(0.01)
    assert threads == [False]
    assert "203.0.113.9" in dlg.message_view.toPlainText()
    assert "Score:" in dlg.detail.toPlainText()
    dlg.done(0)


def test_edge_an_older_selection_s_result_does_not_overwrite_a_newer_one(tmp_path):
    app, dlg = _dialog(tmp_path)
    dlg._showing = 5
    dlg._shown(4, "<p>old</p>", "")
    assert "old" not in dlg.message_view.toPlainText()
    dlg._shown(5, "<p>new</p>", "")
    assert "new" in dlg.message_view.toPlainText()
    dlg._shown(6, None, "unreadable")
    assert "unreadable" not in dlg.message_view.toPlainText()
    dlg.done(0)


def test_happy_an_import_can_be_cancelled(tmp_path):
    app, dlg = _dialog(tmp_path)
    seen = []

    class Result:
        errors: list = []

        def line(self):
            return "0 new"

    def work(cancel):
        deadline = time.monotonic() + 20
        while not cancel() and time.monotonic() < deadline:
            time.sleep(0.01)
        seen.append(cancel())
        return Result()

    dlg._run_import("test", work)
    assert dlg.cancel_button.isEnabled()
    dlg.cancel_button.click()
    deadline = time.monotonic() + 20
    while not dlg.status.text().startswith("0 new") and time.monotonic() < deadline:
        app.processEvents()
        time.sleep(0.01)
    assert seen == [True]
    assert "cancelled" in dlg.status.text() and not dlg.cancel_button.isEnabled()
    dlg.done(0)
