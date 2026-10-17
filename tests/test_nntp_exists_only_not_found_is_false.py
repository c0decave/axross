"""NNTP exists() says False only for "no such group" / "no such article".

stat() of an article wrapped every failure into a plain OSError
(core/nntp_client.py, ``except Exception``), and exists() read any
OSError as "absent": a dropped connection, a timeout, a 503 to OVER, a
480 to GROUP, and a client nntp_lib had already closed after a broken
status line all answered False. The transfer worker's no-clobber check
takes False as the go-ahead to write.

Absence is now FileNotFoundError at its source: 411 (no such newsgroup),
423 / 430 (no such article), or a path that names no group or article.
Every other failure is an OSError that exists() passes on.

Driven end to end against the scripted NNTP server on 127.0.0.1.
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace as NS

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mail_fuzz_servers import STALL, FakeNntpServer  # noqa: E402

from core import nntp_lib as NL  # noqa: E402
from core.nntp_client import NntpSession  # noqa: E402
from core.transfer_worker import TransferWorker  # noqa: E402

GROUPS = {"comp.lang.python": (2, 1, 2), "alt.test": (3, 1, 3)}
ARTICLES = {1: 120, 2: 220, 3: 330}


@pytest.fixture(autouse=True)
def _short_timeout(monkeypatch):
    orig = NL.NntpClient.__init__

    def init(self, *a, timeout=0.4, **kw):
        orig(self, *a, timeout=0.4, **kw)

    monkeypatch.setattr(NL.NntpClient, "__init__", init)


def _group(arg: str) -> bytes:
    if arg not in GROUPS:
        return b"411 no such newsgroup\r\n"
    count, low, high = GROUPS[arg]
    return f"211 {count} {low} {high} {arg}\r\n".encode()


def _over(arg: str) -> bytes:
    low = int(arg.split("-")[0])
    if low not in ARTICLES:
        return b"423 no articles in that range\r\n"
    return (
        f"224 overview\r\n{low}\tSubject\tme@x\tThu, 1 Jan 2026 10:00:00 +0000"
        f"\t<{low}@x>\t\t{ARTICLES[low]}\t5\r\n.\r\n"
    ).encode()


@pytest.fixture
def srv():
    server = FakeNntpServer({"GROUP": _group, "OVER": _over})
    yield server
    server.close()


@pytest.fixture
def s(srv):
    session = NntpSession(srv.host, srv.port, use_tls=False)
    yield session
    try:
        session.close()
    except Exception:  # noqa: BLE001 - the connection may be gone on purpose
        pass


def _not_a_miss(exc: BaseException) -> bool:
    return isinstance(exc, OSError) and not isinstance(exc, FileNotFoundError)


# --- happy ------------------------------------------------------------------


def test_happy_present_and_absent_groups_and_articles(s):
    assert s.exists("/comp.lang.python") is True
    assert s.exists("/comp.lang.python/1_Hello.eml") is True
    assert s.exists("/alt.nope") is False
    assert s.exists("/comp.lang.python/9_gone.eml") is False
    assert s.exists("/alt.nope/1_Hello.eml") is False


def test_happy_a_missing_article_is_file_not_found(s):
    with pytest.raises(FileNotFoundError):
        s.stat("/comp.lang.python/9_gone.eml")
    with pytest.raises(FileNotFoundError):
        s.stat("/alt.nope/1_Hello.eml")


# --- sad --------------------------------------------------------------------


@pytest.mark.parametrize(
    "verb, reply",
    [
        ("OVER", b"503 program fault - command not performed\r\n"),
        ("OVER", None),  # the server hangs up
        ("OVER", STALL),  # the server goes silent: a timeout
        ("GROUP", b"480 authentication required\r\n"),
        ("GROUP", b"502 access restricted\r\n"),
        ("GROUP", None),
    ],
    ids=["over-503", "over-drop", "over-timeout", "group-480", "group-502", "group-drop"],
)
def test_sad_a_failed_answer_is_an_oserror(srv, s, verb, reply):
    srv.replies[verb] = reply
    with pytest.raises(OSError) as info:
        s.exists("/comp.lang.python/1_Hello.eml")
    assert _not_a_miss(info.value), info.value


def test_sad_an_article_lookup_that_fails_after_an_empty_overview_is_an_oserror(srv, s):
    srv.replies["OVER"] = b"224 overview\r\n.\r\n"
    srv.replies["ARTICLE"] = b"503 program fault\r\n"
    with pytest.raises(OSError) as info:
        s.exists("/comp.lang.python/1_Hello.eml")
    assert _not_a_miss(info.value)


def test_sad_a_closed_client_is_an_oserror_not_absent(srv, s):
    # A status line that cannot be read closes the connection (nntp_lib);
    # every later command meets NntpError("... is closed").
    srv.replies["OVER"] = b"\xff not a status line\r\n"
    with pytest.raises(OSError):
        s.exists("/comp.lang.python/1_Hello.eml")
    assert s._client.closed
    with pytest.raises(OSError) as info:
        s.exists("/alt.test/2_x.eml")
    assert _not_a_miss(info.value)
    with pytest.raises(OSError) as info:
        s.exists("/alt.test")
    assert _not_a_miss(info.value)


def test_sad_a_group_that_cannot_be_checked_is_no_answer_for_is_dir(srv, s):
    srv.replies["GROUP"] = b"502 access restricted\r\n"
    with pytest.raises(OSError) as info:
        s.is_dir("/comp.lang.python")
    assert _not_a_miss(info.value)


def test_sad_the_transfer_worker_does_not_write_over_an_unchecked_destination(srv, s):
    srv.replies["OVER"] = b"503 program fault\r\n"
    job = NS(
        if_exists="fail",
        dest_backend=s,
        dest_path="/comp.lang.python/1_Hello.eml",
        source_backend=None,
        source_path="/local/1_Hello.eml",
    )
    with pytest.raises(OSError, match="cannot check"):
        TransferWorker._check_existing_destination(job)


# --- edge -------------------------------------------------------------------


def test_edge_no_article_found_by_a_430_answer_is_absent(srv, s):
    srv.replies["OVER"] = b"224 overview\r\n.\r\n"
    srv.replies["ARTICLE"] = b"430 no such article\r\n"
    assert s.exists("/comp.lang.python/7_x.eml") is False


def test_edge_an_empty_overview_and_a_423_article_is_absent(srv, s):
    srv.replies["OVER"] = b"224 overview\r\n.\r\n"
    srv.replies["ARTICLE"] = b"423 no article with that number\r\n"
    assert s.exists("/comp.lang.python/7_x.eml") is False


def test_edge_a_path_that_names_no_group_or_article_is_absent(srv, s):
    before = len(srv.commands)
    assert s.exists("/comp.lang.python/readme.txt") is False
    assert s.exists("/comp.lang.python/1_x.eml/deeper") is False
    with pytest.raises(FileNotFoundError):
        s.stat("/comp.lang.python/readme.txt")
    # Decided from the path alone: no round trip.
    assert srv.commands[before:] == []


def test_edge_a_listed_article_needs_no_round_trip(srv, s):
    s.list_dir("/comp.lang.python")
    before = len(srv.commands)
    assert s.exists("/comp.lang.python/1_Hello.eml") is True
    assert srv.commands[before:] == []
