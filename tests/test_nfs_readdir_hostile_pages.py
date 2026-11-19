"""NFS READDIR(PLUS) against a server whose pages never end (review round 2).

* NFSv4 READDIR had no cap on the entries of a whole folder: a server
  answering every page with entries and "not the end" grew the list for
  up to 100 000 rounds of up to 100 000 entries each.
* Neither version checked that the cookie moves on: a server answering
  the same page again (or a page of "." / ".." alone) was asked 100 000
  times. The same cookie twice is a protocol error now, at once.
"""

from __future__ import annotations

import errno
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import nfs3_rpc as R  # noqa: E402
from core import nfs4_rpc as R4  # noqa: E402


class _Rpc:
    def __init__(self, page):
        self.page = page
        self.calls = 0

    def call(self, _proc, _args):
        self.calls += 1
        if self.calls > 50:
            raise AssertionError("asked the same page again and again")
        return R.Unpacker(self.page(self.calls))


def _v3_page(names_cookies, eof=False) -> bytes:
    p = R.Packer().uint(0).boolean(False).fixed(b"\0" * 8)
    for name, cookie in names_cookies:
        p.boolean(True).hyper(1).string(name).hyper(cookie).boolean(False).boolean(False)
    return p.boolean(False).boolean(eof).bytes()


def _v3(page):
    c = object.__new__(R.Nfs3)
    c.rpc = _Rpc(page)
    return c


def test_sad_v3_same_page_again_is_refused_at_once() -> None:
    c = _v3(lambda _n: _v3_page([("a", 5)]))
    with pytest.raises(OSError) as info:
        c.readdirplus(b"fh")
    assert info.value.errno == errno.EPROTO
    assert c.rpc.calls <= 3


def test_sad_v3_dot_pages_without_progress_are_refused() -> None:
    c = _v3(lambda _n: _v3_page([(".", 1), ("..", 2)]))
    with pytest.raises(OSError):
        c.readdirplus(b"fh")
    assert c.rpc.calls <= 3


def test_happy_v3_pages_that_move_on() -> None:
    c = _v3(lambda n: _v3_page([(f"f{n}", n)], eof=n == 3))
    assert [e.name for e in c.readdirplus(b"fh")] == ["f1", "f2", "f3"]


def _v4(answer):
    c = object.__new__(R4.Nfs4)
    calls = {"n": 0}

    def compound(ops, what, **_kw):
        calls["n"] += 1
        if calls["n"] > 50:
            raise AssertionError("asked the same page again and again")
        return [(None, None), (R4.OP_READDIR, answer(calls["n"]))]

    c.compound = compound
    c._putfh = lambda fh: (0, b"")
    return c, calls


def test_sad_v4_same_cookie_again_is_refused_at_once() -> None:
    c, calls = _v4(lambda _n: (b"\0" * 8, [(5, "a", {})], False))
    with pytest.raises(OSError) as info:
        c.readdirplus(b"fh")
    assert info.value.errno == errno.EPROTO
    assert calls["n"] <= 3


def test_sad_v4_whole_folder_is_capped(monkeypatch) -> None:
    monkeypatch.setattr(R, "MAX_LIST", 10)
    c, calls = _v4(lambda n: (b"\0" * 8, [(n * 100 + i, f"f{n}-{i}", {}) for i in range(4)], False))
    with pytest.raises(OSError) as info:
        c.readdirplus(b"fh")
    assert info.value.errno == errno.EMSGSIZE
    assert calls["n"] <= 4


def test_happy_v4_pages_that_move_on() -> None:
    c, _calls = _v4(lambda n: (b"\0" * 8, [(n, f"f{n}", {})], n == 2))
    assert [e.name for e in c.readdirplus(b"fh")] == ["f1", "f2"]
