"""NNTP: a refresh re-reads the group, and one command runs at a time.

* list_dir took the cached GROUP answer whenever the server still had
  the group selected, so a refresh sent ``OVER`` for the old range and
  articles that arrived since never showed up.
* NntpSession had no session lock. open_read is ``GROUP`` + ``ARTICLE
  n``; a listing of another group on a second thread (pane navigation
  while the transfer worker downloads) running between the two switched
  the server's group, and the download saved article n of the WRONG
  group under the requested name.

Driven against an in-process NNTP server on 127.0.0.1.
"""

from __future__ import annotations

import socket
import threading

import pytest

from core.nntp_client import NntpSession
from core.session_lock import io_lock


class _Server:
    def __init__(self, groups: dict[str, int]) -> None:
        self.groups = groups
        self.commands: list[str] = []
        self._srv = socket.create_server(("127.0.0.1", 0))
        self.port = self._srv.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def close(self) -> None:
        self._srv.close()

    def _serve(self) -> None:
        while True:
            try:
                c, _ = self._srv.accept()
            except OSError:
                return
            threading.Thread(target=self._session, args=(c,), daemon=True).start()

    def _session(self, c: socket.socket) -> None:
        current = None
        c.sendall(b"200 ready\r\n")
        for raw in c.makefile("rb"):
            line = raw.decode().rstrip("\r\n")
            self.commands.append(line)
            verb, _, arg = line.partition(" ")
            verb = verb.upper()
            if verb == "MODE":
                out = "200 reader\r\n"
            elif verb == "GROUP" and arg in self.groups:
                current = arg
                high = self.groups[arg]
                out = f"211 {high} 1 {high} {arg}\r\n"
            elif verb == "OVER" and current:
                low, _, high = arg.partition("-")
                rows = "".join(
                    f"{n}\tsubject {n}\tme\tWed, 01 Jul 2026 09:00:00 +0000\t<{n}@{current}>"
                    "\t\t10\t1\r\n"
                    for n in range(int(low), int(high) + 1)
                )
                out = "224 overview\r\n" + rows + ".\r\n"
            elif verb == "ARTICLE" and current:
                out = f"220 {arg} <{arg}@{current}>\r\nNewsgroups: {current}\r\n\r\nbody\r\n.\r\n"
            elif verb == "QUIT":
                c.sendall(b"205 bye\r\n")
                break
            else:
                out = "412 no newsgroup selected\r\n"
            c.sendall(out.encode())
        c.close()


@pytest.fixture
def server():
    srv = _Server({"alt.a": 3, "alt.b": 3})
    try:
        yield srv
    finally:
        srv.close()


def _session(srv) -> NntpSession:
    return NntpSession("127.0.0.1", port=srv.port, use_tls=False)


# -- happy -------------------------------------------------------------------


def test_happy_refresh_shows_articles_that_arrived_since(server):
    s = _session(server)
    try:
        assert len(s.list_dir("/alt.a")) == 3
        server.groups["alt.a"] = 5
        names = [i.name for i in s.list_dir("/alt.a")]
        assert names[-1].startswith("5_")
        assert len(names) == 5
    finally:
        s.close()


# -- sad ---------------------------------------------------------------------


def test_sad_listing_on_another_thread_cannot_switch_the_group_mid_read(server):
    s = _session(server)
    try:
        between = threading.Event()
        real_article = s._client.article

        def article_after_a_pause(n):
            between.set()
            # The other thread's listing must not run in this gap.
            threading.Event().wait(0.5)
            return real_article(n)

        s._client.article = article_after_a_pause
        result: dict = {}

        def reader():
            with s.open_read("/alt.a/2_subject 2.eml") as fh:
                result["data"] = fh.read()

        t = threading.Thread(target=reader)
        t.start()
        assert between.wait(5)
        listing = s.list_dir("/alt.b")
        t.join(5)
        assert b"Newsgroups: alt.a" in result["data"]
        assert len(listing) == 3
    finally:
        s.close()


def test_sad_post_waits_for_the_session_lock(server):
    s = _session(server)
    posted = []
    s._client.post = lambda article: posted.append(article)
    try:
        held = threading.Event()
        release = threading.Event()

        def holder():
            with io_lock(s):
                held.set()
                release.wait(5)

        t = threading.Thread(target=holder)
        t.start()
        assert held.wait(5)
        w = s.open_write("/alt.a/new.eml")
        w.write(b"Subject: x\r\n\r\nbody\r\n")
        closer = threading.Thread(target=w.close)
        closer.start()
        closer.join(0.3)
        assert posted == []  # still waiting for the lock
        release.set()
        closer.join(5)
        t.join(5)
        assert len(posted) == 1
    finally:
        s.close()


# -- edge --------------------------------------------------------------------


def test_edge_reading_after_a_listing_needs_no_second_group(server):
    s = _session(server)
    try:
        s.list_dir("/alt.a")
        before = sum(c.startswith("GROUP") for c in server.commands)
        with s.open_read("/alt.a/1_subject 1.eml") as fh:
            assert b"Newsgroups: alt.a" in fh.read()
        assert sum(c.startswith("GROUP") for c in server.commands) == before
    finally:
        s.close()
