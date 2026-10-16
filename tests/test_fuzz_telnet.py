"""Fuzz: TelnetSession against a hostile telnet shell.

``ls -la`` / ``stat`` / ``df`` / base64 output, IAC negotiation garbage,
unterminated subnegotiations, forged markers, stalls and hang-ups must end
in sane items or an OSError - never ValueError / OverflowError from the
output parsers, unbounded buffering or a hang.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fuzz_testkit import check_contract, iterations, mutants  # noqa: E402
from telnet_fuzz_server import STALL, FakeTelnetShell  # noqa: E402

from core import telnet_client as T  # noqa: E402


@pytest.fixture(autouse=True)
def _short_timeouts(monkeypatch):
    orig = T._ShellSession.execute

    def execute(self, cmd, timeout=T.CMD_TIMEOUT):
        return orig(self, cmd, timeout=min(timeout, 0.4))

    monkeypatch.setattr(T._ShellSession, "execute", execute)

    # The login waits up to 10 s for a prompt; the fake shell answers at
    # once, so a reconnect after a hostile answer only costs these waits.
    orig_read_some = T._TelnetTransport.read_some

    def read_some(self, timeout=1.0):
        return orig_read_some(self, timeout=min(timeout, 0.3))

    monkeypatch.setattr(T._TelnetTransport, "read_some", read_some)


@pytest.fixture(scope="module")
def shell():
    srv = FakeTelnetShell()
    yield srv
    srv.close()


@pytest.fixture(scope="module")
def session(shell):
    return T.TelnetSession(shell.host, shell.port, "u", "p")


def _ops(s):
    return {
        "list_dir": lambda: s.list_dir("/home/u"),
        "stat": lambda: s.stat("/a.txt"),
        "open_read": lambda: s.open_read("/a.txt"),
        "is_dir": lambda: s.is_dir("/sub"),
        "disk_usage": lambda: s.disk_usage("/"),
    }


def _all_ops(s, ctx, only=None):
    for name, op in _ops(s).items():
        if only and name not in only:
            continue
        result = check_contract(op, (OSError,), timeout=20.0, context=f"{ctx} {name}")
        if isinstance(result, list):
            for item in result:
                assert isinstance(item.name, str) and isinstance(item.size, int)


def test_happy_session(session):
    assert [i.name for i in session.list_dir("/home/u")] == ["a.txt", "sub dir"]
    assert session.stat("/a.txt").size == 5
    assert session.open_read("/a.txt").read() == b"hello"


@pytest.mark.parametrize(
    "prefix, out",
    [
        ("stat --format='%n|%s|%Y|%f|%U|%G|%F'", ("/a|x|y|z|u|g|f", 0)),
        ("stat --format='%n|%s|%Y|%f|%U|%G|%F'", ("/a|5|99999999999999999|81a4|u|u|file", 0)),
        ("stat --format='%n|%s|%Y|%f|%U|%G|%F'", ("/a|5|-99999999999|zz|u|u|file", 0)),
        ("stat --format='%n|%s|%Y|%f|%U|%G|%F'", ("garbage", 0)),
        ("ls -la", ("-rw-r--r-- 1 u u 99999999999999999999 Feb 30 25:61 x\n" * 3, 0)),
        ("ls -la", ("\x1b[31m-rw-r--r--\x1b[0m 1 u u 5 Jan  1 12:00 ../../etc/passwd", 0)),
        ("ls -la", ("crw-rw---- 1 root tty 4, 1 Jan  1 12:00 tty1", 0)),
        ("ls -la", ("ls: command not found", 127)),
        ("base64 <", ("!!!not base64!!!", 0)),
        ("base64 <", ("aGVsbG8", 0)),
        ("base64 <", ("", 1)),
        ("df", ("Filesystem\n/dev/x \xb2 1 1", 0)),
        ("df", ("", 0)),
        ("ls -la", STALL),
        ("ls -la", None),
        ("ls -la", b"\xff\xfb\x01\xff\xfd\x03\xff\xfa\x18\x01\xff\xf0garbage-without-markers\r\n"),
        ("ls -la", b"\xff\xff\xff\xfe\xff"),
    ],
)
def test_sad_hostile_command_output(session, shell, prefix, out):
    saved = shell.outputs.get(prefix)
    shell.outputs[prefix] = out
    try:
        # A stall, a hang-up or raw bytes without the command markers cost
        # a reconnect per call: one call shows it.
        only = ("list_dir",) if out is STALL or out is None or isinstance(out, bytes) else None
        _all_ops(session, f"{prefix} {out!r}"[:100], only=only)
    finally:
        shell.outputs[prefix] = saved


def test_edge_unterminated_subnegotiation_is_bounded():
    """IAC SB without IAC SE: the transport keeps the incomplete
    sequence for the next read - it must not keep it without bound."""
    import tracemalloc

    with FakeTelnetShell() as srv:
        s = T.TelnetSession(srv.host, srv.port, "u", "p")
        srv.outputs["ls -la"] = b"\xff\xfa\x18" + b"A" * (8 << 20)
        tracemalloc.start()
        try:
            check_contract(lambda: s.list_dir("/x"), (OSError,), timeout=60.0, context="SB")
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
    assert peak < 4 << 20, f"peak {peak} bytes buffering an unterminated subnegotiation"


def test_fuzz_ls_output_mutants(session, shell):
    corpus = [shell.outputs["ls -la"][0].encode()]
    for n, payload in enumerate(mutants(corpus, 0x7E1, iterations(20))):
        shell.outputs["ls -la"] = (payload.decode("utf-8", "replace"), 0)
        _all_ops(session, f"ls mutant #{n}: {payload[:80]!r}", only=("list_dir",))


def test_fuzz_parsers_direct():
    corpus_ls = [
        b"-rw-r--r-- 1 u u 5 Jan  1 12:00 a.txt\nlrwxrwxrwx 1 u u 4 Mar 16  2025 l -> /tmp",
    ]
    for payload in mutants(corpus_ls, 0x7E2, iterations(800)):
        text = payload.decode("utf-8", "replace")
        check_contract(lambda: T._parse_ls_la(text), (OSError,), context=repr(text))
    for payload in mutants(
        [b"Filesystem 1K Used Avail\n/dev/x 100 40 60 40% /"], 0x7E3, iterations(400)
    ):
        text = payload.decode("utf-8", "replace")
        check_contract(lambda: T._parse_df(text), (OSError,), context=repr(text))
