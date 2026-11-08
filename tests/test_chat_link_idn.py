"""Chat's Open Link question shows a punycode host as it is (review round 3).

Before: the question showed ``url.toString()``, which decodes an
internationalised host, so a link to ``xn--pple-43d.com`` read
"https://аpple.com/account" - with a Cyrillic "а", a perfect look-alike
of apple.com. All three chat panels (IRC, Matrix, XMPP) share that view.
Now the address is shown percent-encoded, the host in its ASCII form on a
line of its own, with a warning for an internationalised or mixed-script
name, as the mail view does for mail links.
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QUrl  # noqa: E402
from PyQt6.QtWidgets import QApplication, QMessageBox  # noqa: E402

from ui import chat_panel as CP  # noqa: E402


@pytest.fixture(autouse=True)
def app():
    return QApplication.instance() or QApplication([])


@pytest.fixture
def asked(monkeypatch):
    """What the Open Link question showed; the answer is always Cancel."""
    seen: list[str] = []

    def question(parent, title, text, *args, **kwargs):
        seen.append(text)
        return QMessageBox.StandardButton.Cancel

    monkeypatch.setattr(QMessageBox, "question", staticmethod(question))
    return seen


def _ask(url: str) -> None:
    CP.ConversationView._link(None, QUrl(url))


def test_sad_a_punycode_look_alike_is_shown_in_its_ascii_form(asked):
    _ask("https://xn--pple-43d.com/account")
    (text,) = asked
    assert "а" not in text.split("Warning")[0]  # no Cyrillic "а" in the address
    assert "https://xn--pple-43d.com/account" in text
    assert "\nHost: xn--pple-43d.com\n" in text  # the host on a line of its own
    assert "non-ASCII" in text and "CYRILLIC, LATIN" in text


def test_sad_a_unicode_host_in_the_message_is_shown_as_punycode(asked):
    _ask("https://аpple.com/")
    (text,) = asked
    assert "Host: xn--pple-43d.com" in text and "CYRILLIC" in text


def test_happy_an_ascii_host_gets_no_warning(asked):
    _ask("https://example.org/a?b=c")
    (text,) = asked
    assert "Host: example.org" in text
    assert "Warning" not in text


def test_edge_an_internationalised_name_in_one_script_is_noted_not_called_mixed():
    """münchen.de is a real name: noted as non-ASCII, no mixed scripts."""
    warnings = CP.host_warnings(QUrl("https://münchen.de/").host(
        QUrl.ComponentFormattingOption.FullyEncoded))
    assert len(warnings) == 1 and "münchen.de" in warnings[0]


def test_edge_hidden_characters_in_the_address_are_percent_encoded(asked):
    """A bidi override in the path is shown as %E2%80%AE, not applied."""
    _ask("https://example.org/\u202egpj.exe")
    (text,) = asked
    assert "\u202e" not in text and "%E2%80%AE" in text
