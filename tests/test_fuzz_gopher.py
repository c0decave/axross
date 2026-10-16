"""Fuzz: GopherSession against a hostile Gopher server.

Menus with missing fields, odd item types, traversal display strings,
selectors with CR/LF/TAB, garbage ports, oversized answers, early EOF and
stalls must end in sane items or an OSError - never a hang.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fuzz_testkit import (  # noqa: E402
    ScriptedServer,
    check_contract,
    iterations,
    mutants,
    recv_line,
    stall,
)

from core import gopher_client as G  # noqa: E402

STALL = object()

MENU = (
    b"1Docs\t/docs\tlocalhost\t70\r\n"
    b"0readme\t/readme.txt\tlocalhost\t70\r\n"
    b"iinfo line\tfake\t(NULL)\t0\r\n"
    b"9disk.iso\t/disk.iso\tother.example\t7070\r\n"
    b"hpage\tURL:http://x\tlocalhost\t70\r\n"
    b".\r\n"
)


class GopherServer:
    def __init__(self) -> None:
        self.menu = MENU
        self.files: dict[str, object] = {}
        self.selectors: list[bytes] = []
        self.server = ScriptedServer(self._handle)

    def _handle(self, conn) -> None:
        sel = recv_line(conn).rstrip(b"\r\n")
        self.selectors.append(sel)
        out = self.files.get(sel.decode("utf-8", "replace"), self.menu)
        if out is STALL:
            stall(conn, 10)
            return
        if out is None:
            return
        conn.sendall(out)

    def close(self) -> None:
        self.server.close()


@pytest.fixture(autouse=True)
def _short_timeout(monkeypatch):
    monkeypatch.setattr(G, "DEFAULT_TIMEOUT", 1.0)
    orig = G._open_socket

    def open_socket(host, port, use_tls, proxy_config, timeout=1.0):
        return orig(host, port, use_tls, proxy_config, timeout=1.0)

    monkeypatch.setattr(G, "_open_socket", open_socket)


@pytest.fixture
def gopher():
    srv = GopherServer()
    yield srv
    srv.close()


def _session(srv) -> G.GopherSession:
    return G.GopherSession("127.0.0.1", srv.server.port)


def _ops(s):
    return {
        "list_root": lambda: s.list_dir("/"),
        "list_sub": lambda: s.list_dir("/Docs"),
        "stat": lambda: s.stat("/readme.txt"),
        "is_dir": lambda: s.is_dir("/Docs"),
        "exists": lambda: s.exists("/nothing"),
        "open_read": lambda: s.open_read("/readme.txt"),
        "deep": lambda: s.list_dir("/Docs/Docs/Docs/Docs"),
    }


def _all_ops(s, ctx, only=None):
    for name, op in _ops(s).items():
        if only and name not in only:
            continue
        s._dir_cache.clear()
        result = check_contract(op, (OSError,), timeout=15.0, context=f"{ctx} {name}")
        if isinstance(result, list):
            for item in result:
                assert isinstance(item.name, str) and item.name
                assert "/" not in item.name


def test_happy_menu(gopher):
    names = [i.name for i in _session(gopher).list_dir("/")]
    assert names == ["Docs", "readme.txt", "disk.iso", "page.html"]


def test_edge_menu_host_and_port_are_never_dialled(gopher):
    """A menu entry naming another host must not make the client connect
    there. It is not fetched from the configured server either (that
    served this server's content under the other's name): it is a link to
    its gopher:// URL, and opening it says where it points."""
    s = _session(gopher)
    gopher.files["/disk.iso"] = b"ISO"
    entry = {i.name: i for i in s.list_dir("/")}["disk.iso"]
    assert entry.is_link and entry.link_target == "gopher://other.example:7070/9/disk.iso"
    with pytest.raises(OSError, match="other.example:7070"):
        s.open_read("/disk.iso")
    assert b"/disk.iso" not in gopher.selectors


@pytest.mark.parametrize(
    "menu",
    [
        b"1only-display\r\n.\r\n",
        b"1a\tb\r\n",
        b"\t\t\t\t\r\n",
        b"1..\t/up\th\t70\r\n0../../etc/passwd\t/x\th\t70\r\n0\x00\x00\t/nul\th\t70\r\n",
        b"0a\t/sel\r\nwith CR\th\t70\r\n",  # selector with CR inside
        b"0a\t/sel\twith-tab\th\tabc\r\n",
        b"1loop\t\th\t70\r\n",  # empty selector: the root again
        b"\xff\xfe\t\xff\th\t70\r\n",
        b"1" + b"x" * 100000 + b"\t/s\th\t70\r\n",
        b"",
        b".\r\n" * 3,
    ],
)
def test_sad_hostile_menus(gopher, menu):
    gopher.menu = menu
    s = check_contract(lambda: _session(gopher), (OSError,), timeout=15.0, context=repr(menu[:60]))
    if not isinstance(s, OSError):
        _all_ops(s, repr(menu[:60]))


def test_sad_oversized_answer_is_an_oserror(gopher, monkeypatch):
    monkeypatch.setattr(G, "MAX_DIR_BYTES", 64 * 1024)
    s = _session(gopher)
    gopher.menu = b"0x\t/x\th\t70\r\n" * 20000
    assert isinstance(check_contract(lambda: s.list_dir("/"), (OSError,)), OSError)


def test_sad_stall_and_hangup(gopher):
    s = _session(gopher)
    gopher.files["/readme.txt"] = STALL
    assert isinstance(check_contract(lambda: s.open_read("/readme.txt"), (OSError,)), OSError)
    gopher.menu = None
    s._dir_cache.clear()
    check_contract(lambda: s.list_dir("/"), (OSError,))


def test_fuzz_menu_mutants(gopher):
    s = _session(gopher)
    for n, payload in enumerate(mutants([MENU], 0x60F, iterations(80))):
        gopher.menu = payload
        _all_ops(s, f"menu mutant #{n}: {payload[:80]!r}", only=("list_root", "stat", "list_sub"))


def test_fuzz_parse_menu_direct():
    for payload in mutants([MENU], 0x610, iterations(800)):
        entries = check_contract(lambda: G._parse_menu(payload), (OSError,), context=repr(payload))
        if isinstance(entries, list):
            names = G._disambiguate(entries)
            assert all("/" not in v for v in names.values())
