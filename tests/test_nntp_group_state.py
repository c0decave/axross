"""NNTP article numbers are read in the right group, and the stream stays framed.

docs/SECURITY-REVIEW-2026-10.md C-6:

* ``_ensure_group`` returned the cached GROUP answer without sending
  GROUP again. Article numbers are per group, so after listing ``/a`` and
  then ``/b``, opening ``/a/2_x.eml`` sent ``ARTICLE 2`` while the server
  still had ``b`` selected: the user got another group's article. The
  scripting verbs (``xover``, ``article_headers``, ``raw_head``) switch
  groups directly and left the cache believing the old group was current.
* ``xover`` stopped iterating the OVER generator after ``max_records``;
  the rest of the multi-line response stayed in the socket and the next
  command read overview lines as its status line.

Driven end to end against a stateful in-process NNTP server on 127.0.0.1.
"""

from __future__ import annotations

import socket
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import nntp_lib  # noqa: E402
from core.nntp_client import NntpSession  # noqa: E402

GROUPS = {"alt.a": 3, "alt.b": 3}


class _StatefulNntp:
    def __init__(self) -> None:
        self._srv = socket.create_server(("127.0.0.1", 0))
        self.port = self._srv.getsockname()[1]
        self.commands: list[str] = []
        threading.Thread(target=self._serve, daemon=True).start()

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
            elif verb == "GROUP" and arg in GROUPS:
                current = arg
                out = f"211 {GROUPS[arg]} 1 {GROUPS[arg]} {arg}\r\n"
            elif verb == "OVER" and current:
                low, _, high = arg.partition("-")
                rows = "".join(
                    f"{n}\t{current} subject {n}\tme\tWed, 01 Jul 2026 09:00:00 +0000\t<{n}@{current}>\t\t10\t1\r\n"
                    for n in range(int(low), int(high) + 1)
                )
                out = "224 overview\r\n" + rows + ".\r\n"
            elif verb in ("ARTICLE", "HEAD") and current:
                code = 220 if verb == "ARTICLE" else 221
                out = f"{code} {arg} <{arg}@{current}>\r\nNewsgroups: {current}\r\nX-Number: {arg}\r\n.\r\n"
            elif verb == "QUIT":
                c.sendall(b"205 bye\r\n")
                break
            else:
                out = "412 no newsgroup selected\r\n"
            c.sendall(out.encode())
        c.close()

    def stop(self) -> None:
        self._srv.close()


@pytest.fixture
def session():
    srv = _StatefulNntp()
    s = NntpSession(host="127.0.0.1", port=srv.port, use_tls=False)
    yield s
    s.close()
    srv.stop()


def _article_group(blob: bytes) -> str:
    for line in blob.decode().splitlines():
        if line.startswith("Newsgroups: "):
            return line.split(": ", 1)[1]
    raise AssertionError(blob)


def test_happy_article_comes_from_the_group_in_its_path(session):
    session.list_dir("/alt.a")
    session.list_dir("/alt.b")
    assert _article_group(session.open_read("/alt.a/2_x.eml").read()) == "alt.a"
    assert _article_group(session.open_read("/alt.b/2_x.eml").read()) == "alt.b"


def test_sad_scripting_verbs_do_not_leave_a_stale_current_group(session):
    session.list_dir("/alt.a")
    assert session.article_headers("alt.b", 1)["newsgroups"] == "alt.b"
    assert _article_group(session.open_read("/alt.a/1_x.eml").read()) == "alt.a"
    session.raw_head("alt.b", 1)
    assert _article_group(session.open_read("/alt.a/3_x.eml").read()) == "alt.a"


def test_sad_xover_stopping_early_keeps_the_connection_framed(session):
    assert [r["msgno"] for r in session.xover("alt.a", max_records=1)] == [1]
    # The next commands must read their own responses, not overview lines.
    assert session.article_headers("alt.b", 2)["x-number"] == "2"
    assert [i.name.split("_")[0] for i in session.list_dir("/alt.a")] == ["1", "2", "3"]


def test_edge_oversized_response_drops_the_connection_instead_of_desyncing(session, monkeypatch):
    monkeypatch.setattr(nntp_lib, "MAX_MULTILINE_BYTES", 60)
    with pytest.raises(OSError):
        session.list_dir("/alt.a")
    monkeypatch.setattr(nntp_lib, "MAX_MULTILINE_BYTES", 10**6)
    # Whatever happens next, it must not be another command's leftovers
    # served as an article.
    with pytest.raises(OSError):
        session.open_read("/alt.b/1_x.eml")
