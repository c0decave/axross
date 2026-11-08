"""The mail viewer's "This link goes to:" question cannot be spoofed.

Before: the confirmation showed ``url.toString()``, which keeps a bidi
override (U+202E) as it is: ``https://<RLO>moc.lapyap.www@evil.example/``
rendered as a paypal.com address while the browser opened evil.example.

Now the dialog shows the fully encoded URL (the override as %E2%80%AE),
run through core.remote_name.sanitize_for_display, and the host in its
ASCII form on a line of its own.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QUrl  # noqa: E402
from PyQt6.QtWidgets import QApplication, QMessageBox  # noqa: E402

from ui.mail_project import _safe_browser_class  # noqa: E402

APP = QApplication.instance() or QApplication([])

RLO = "\u202e"


@pytest.fixture
def asked(monkeypatch):
    texts: list[str] = []

    def question(parent, title, text, *a, **k):
        texts.append(text)
        return QMessageBox.StandardButton.No

    monkeypatch.setattr(QMessageBox, "question", question)
    opened = []
    monkeypatch.setattr("core.desktop_open.open_url", lambda url: opened.append(url))
    yield texts
    assert opened == []          # every test answers No


def _click(href: str) -> None:
    browser = _safe_browser_class()()
    browser.anchorClicked.emit(QUrl(href))


def test_happy_a_bidi_override_in_the_user_part_is_shown_encoded_with_the_real_host(asked):
    _click(f"https://{RLO}moc.lapyap.www@evil.example/")
    (text,) = asked
    assert RLO not in text
    assert "%E2%80%AE" in text
    assert "\nHost: evil.example\n" in text


def test_sad_a_bidi_override_in_the_path_does_not_reach_the_dialog(asked):
    _click(f"https://evil.example/{RLO}moc.lapyap.www//:sptth")
    (text,) = asked
    assert RLO not in text
    assert "\nHost: evil.example\n" in text


def test_edge_an_international_host_is_shown_in_its_ascii_form_and_a_plain_link_unchanged(asked):
    _click("https://bücher.example/a b")
    _click("http://203.0.113.9/login")
    idn, plain = asked
    assert "Host: xn--bcher-kva.example" in idn and "a%20b" in idn
    assert "http://203.0.113.9/login" in plain and "Host: 203.0.113.9" in plain
