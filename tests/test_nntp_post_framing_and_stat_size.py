"""NNTP: POST sends the article as it is; stat reports the article's size.

* POST split the article at LF and ended every piece with CRLF. An
  article ending in CRLF - every RFC 5322 file does - left an empty last
  piece, so one extra empty line went on the wire before the "."
  terminator and the posted article differed from the file.
* stat() of an article not in the cached overview sent HEAD and reported
  the length of the HEADERS as the file size, while the listing (and the
  same stat after a listing) reported the overview's article size.
  stat now asks the overview for that one article, like the listing.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mail_fuzz_servers import FakeNntpServer  # noqa: E402

from core.nntp_client import NntpSession  # noqa: E402
from core.nntp_lib import NntpClient, NntpResponseError  # noqa: E402

_ARTICLE = "/comp.lang.python/1_Hello.eml"


class _Wire:
    """Records what the client writes; answers with scripted status lines."""

    def __init__(self, *status: bytes) -> None:
        self.out = b""
        self.status = list(status)

    def write(self, data: bytes) -> None:
        self.out += data

    def readline(self) -> bytes:
        return self.status.pop(0)


def _posted(article: bytes) -> bytes:
    c = NntpClient.__new__(NntpClient)
    c._posting_allowed = True
    c._reader = _Wire(b"340 send\r\n", b"240 ok\r\n")
    c.post(article)
    return c._reader.out.split(b"POST\r\n", 1)[1]


# --- POST framing -----------------------------------------------------------


def test_happy_an_article_ending_in_crlf_goes_out_unchanged():
    article = b"Newsgroups: alt.test\r\nSubject: t\r\n\r\nline1\r\nline2\r\n"
    assert _posted(article) == article + b".\r\n"


def test_sad_a_refused_article_raises_with_the_code():
    c = NntpClient.__new__(NntpClient)
    c._posting_allowed = True
    c._reader = _Wire(b"340 send\r\n", b"441 posting failed\r\n")
    with pytest.raises(NntpResponseError) as info:
        c.post(b"Subject: t\r\n\r\nbody\r\n")
    assert info.value.code == 441
    assert c._reader.out.endswith(b"\r\nbody\r\n.\r\n")


@pytest.mark.parametrize(
    "article, wire",
    [
        (b"Subject: t\r\n\r\nbody", b"Subject: t\r\n\r\nbody\r\n.\r\n"),
        (b"Subject: t\n\nbody\n", b"Subject: t\r\n\r\nbody\r\n.\r\n"),
        (b"Subject: t\r\n\r\nbody\r\n\r\n", b"Subject: t\r\n\r\nbody\r\n\r\n.\r\n"),
        (b"Subject: t\r\n\r\n.dot\r\n", b"Subject: t\r\n\r\n..dot\r\n.\r\n"),
        (b"", b"\r\n.\r\n"),
    ],
    ids=["no-final-newline", "lf-only", "real-empty-last-line", "dot-stuffing", "empty"],
)
def test_edge_line_endings_and_dots_are_framed_once(article, wire):
    assert _posted(article) == wire


# --- stat size ----------------------------------------------------------------


@pytest.fixture
def srv():
    server = FakeNntpServer()
    yield server
    server.close()


def test_happy_stat_before_a_listing_reports_the_listed_size_and_date(srv):
    s = NntpSession(srv.host, srv.port, use_tls=False)
    before = s.stat(_ARTICLE)
    listed = {i.name: i for i in s.list_dir("/comp.lang.python")}["1_Hello.eml"]
    after = s.stat(_ARTICLE)
    assert before.size == listed.size == after.size == 120
    when = datetime(2026, 1, 1, 10, 0, tzinfo=timezone.utc)
    assert before.modified.astimezone(timezone.utc) == when
    assert not any(c.startswith("HEAD") for c in srv.commands)


def test_sad_stat_of_a_missing_article_is_an_error(srv):
    srv.replies["OVER"] = b"423 no such article\r\n"
    s = NntpSession(srv.host, srv.port, use_tls=False)
    with pytest.raises(OSError):
        s.stat(_ARTICLE)
    assert not s.exists(_ARTICLE)


def test_edge_without_an_overview_record_the_size_is_the_articles(srv):
    srv.replies["OVER"] = b"224 overview\r\n.\r\n"
    s = NntpSession(srv.host, srv.port, use_tls=False)
    assert s.stat(_ARTICLE).size == len(s.open_read(_ARTICLE).read())
