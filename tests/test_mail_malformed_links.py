"""A malformed link, or one with hidden characters, is a finding - not a
reason to drop the mail (review 2 of 0.15.176).

Before: ``urlsplit("https://[x")`` raises ValueError. core.mail_html's
sanitiser and core.mail_analyse called it unguarded, so one such ``<a>``
made the safe view fail and the mail project's import (which analyses
every mail) skip the message: a phishing mail kept itself out of the
analysis with a single extra link. A bidi override in an href was shown
as is in the "[→ host]" label.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.mail_analyse import analyse  # noqa: E402
from core.mail_html import sanitise  # noqa: E402
from core.mail_message import parse_any  # noqa: E402
from core.mail_project import MailProject  # noqa: E402

PHISH = (b"From: PayPal <service@paypa1.example>\r\nTo: you@example.org\r\nSubject: Verify now\r\n"
         b"MIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"
         b'<a href="https://paypa1-login.example/steal">https://www.paypal.com/</a>'
         b'<a href="%s">.</a>\r\n')


def _mail(href: str) -> bytes:
    return PHISH.replace(b"%s", href.encode())


@pytest.mark.parametrize("href", ["https://[x", "https://evil.example:99999/", "http://[::1"])
def test_sad_a_malformed_link_is_a_high_finding_not_a_crash(href):
    msg = parse_any(_mail(href), "x.eml", "x.eml")
    report = analyse(msg)
    texts = [f.text for f in report.findings if f.severity == "high"]
    assert any("malformed" in t for t in texts), texts
    assert any("www.paypal.com" in t for t in texts), texts  # the rest is still analysed
    out = sanitise(msg.html)
    assert "malformed link" in out and href not in out  # shown, but not as a link


def test_sad_the_mail_project_imports_a_mail_with_a_malformed_link(tmp_path):
    project = MailProject(tmp_path / "p")
    assert project.add_bytes(_mail("https://[x"), "test.eml", "test.eml")
    [row] = project.messages(search="")
    assert row["high"] >= 2


def test_sad_hidden_characters_in_an_href_are_removed_and_flagged():
    href = "https://evil.example/\u202egpj.exe"
    msg = parse_any(_mail(href), "x.eml", "x.eml")
    out = sanitise(msg.html)
    assert "\u202e" not in out and "hidden characters removed" in out
    assert 'href="https://evil.example/gpj.exe"' in out
    report = analyse(msg)
    assert any(f.severity == "high" and "hidden characters" in f.text for f in report.findings)
    # The host is read without the override.
    assert "evil.example" in {link.host for link in report.links}


def test_edge_a_bidi_override_in_the_host_does_not_reach_the_label():
    out = sanitise('<a href="https://moc.\u202elapyap.example/">x</a>')
    assert "\u202e" not in out
    assert "[&#8594; moc.lapyap.example (hidden characters removed)]" in out
