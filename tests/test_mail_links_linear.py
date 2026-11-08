"""core.mail_analyse finds a message's links in time linear in its length.

What was wrong: the links of an HTML body were found with one regular
expression, ``<a\\b[^>]*?\\bhref...>(.*?)</a\\s*>`` with re.S: for every
``<a href>`` without an end tag the lazy ``(.*?)`` ran to the end of the
text, so ``'<a href=x>' * n`` took 71 s at 200 KB (and a body may have 4 MB)
- the import of such a mail all but stopped. The links are now collected by
an HTMLParser (core.mail_html.links, shared with the safe view), one pass.
"""

from __future__ import annotations

import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.mail_analyse import analyse  # noqa: E402
from core.mail_message import MailMessage  # noqa: E402

LIMIT_S = 90.0


def bounded_analyse(html_text: str, limit: float = LIMIT_S):
    out: list = []
    t = threading.Thread(target=lambda: out.append(analyse(MailMessage(html=html_text))), daemon=True)
    started = time.monotonic()
    t.start()
    t.join(limit)
    assert not t.is_alive(), f"analyse() took more than {limit} s for {len(html_text)} characters"
    assert out
    return out[0], time.monotonic() - started


def test_sad_4_mb_of_unclosed_anchors_end_in_time():
    unit = '<a href="https://evil.example/x">'
    body = unit * (4 * 1024 * 1024 // len(unit))
    report, _took = bounded_analyse(body)
    assert [link.url for link in report.links] == ["https://evil.example/x"]


def test_sad_a_megabyte_of_bare_unclosed_anchors_is_quick():
    # the review's input ('<a href=x>' * n): the old expression needed 71 s for 200 KB
    report, _took = bounded_analyse("<a href=x>" * 100_000, limit=30.0)
    assert report.links == []


def test_happy_links_read_as_a_browser_reads_them():
    report, _took = bounded_analyse(
        '<p><a href="http://203.0.113.9/login?a=1&amp;b=2">https://www.<b>bank</b>.example/login</a></p>'
        "<a href='https://one.example/'>first<a href=https://two.example/>second"
        '<a href="javascript:x()">not a web address</a>')
    got = [(link.url, link.text) for link in report.links]
    assert got == [("http://203.0.113.9/login?a=1&b=2", "https://www.bank.example/login"),
                   ("https://one.example/", "first"),          # an <a> ends at the next <a>
                   ("https://two.example/", "second")]         # ... or at the end of the text
    assert "the text shows www.bank.example, the link leads to 203.0.113.9" in report.links[0].notes
