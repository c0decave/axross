"""Fuzz: SSHSession's SFTP surface against a hostile SFTP server.

A real paramiko SFTP server in-process, whose answers are scripted:
listings with non-UTF-8 / traversal / empty names, absurd sizes, modes and
times, short and over-long reads, error codes, and a server that drops the
connection mid-request. paramiko's packet layer is out of scope; what is
in scope is everything axross makes of the answers - every call must return
sane data or raise OSError, never UnicodeDecodeError / SSHException /
EOFError, and never hang.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fuzz_testkit import check_contract  # noqa: E402
from paramiko.sftp import SFTP_FAILURE, SFTP_NO_SUCH_FILE  # noqa: E402
from sftp_hostile_kit import attr, hostile_session  # noqa: E402

from core.path_policy import drop_unsafe_names  # noqa: E402


@pytest.fixture
def sftp():
    with hostile_session() as pair:
        yield pair


def _ops(s):
    return {
        "list_dir": lambda: s.list_dir("/"),
        "stat": lambda: s.stat("/a.txt"),
        "is_dir": lambda: s.is_dir("/sub"),
        "exists": lambda: s.exists("/a.txt"),
        "open_read": lambda: s.open_read("/a.txt").read(),
    }


def _all_ops(s, ctx, only=None):
    out = {}
    for name, op in _ops(s).items():
        if only and name not in only:
            continue
        out[name] = check_contract(op, (OSError,), timeout=20.0, context=f"{ctx} {name}")
        if name == "list_dir" and isinstance(out[name], list):
            for item in out[name]:
                assert isinstance(item.name, str) and isinstance(item.size, int)
    return out


def test_happy_listing_and_read(sftp):
    script, s = sftp
    assert sorted(i.name for i in s.list_dir("/")) == ["a.txt", "sub"]
    assert s.open_read("/a.txt").read() == b"hello"


@pytest.mark.parametrize(
    "listing",
    [
        [attr(b"caf\xe9.txt"), attr("ok.txt")],  # non-UTF-8 name
        [attr(b"\xff\xfe")],
        [attr("../escape"), attr("a/b"), attr(""), attr("."), attr("..")],
        [attr("nul\x00name"), attr("new\nline")],
        [attr("big", size=2**64 - 1), attr("t", mtime=2**32 - 1), attr("z", mtime=0)],
        [attr("m", mode=0o177777), attr("u", uid=2**32 - 1)],
        SFTP_FAILURE,
        SFTP_NO_SUCH_FILE,
    ],
    ids=[
        "latin1",
        "garbage",
        "traversal",
        "control",
        "absurd-numbers",
        "odd-mode",
        "failure",
        "enoent",
    ],
)
def test_sad_hostile_listings(sftp, listing):
    script, s = sftp
    script.listing = listing
    result = _all_ops(s, repr(listing)[:80], only=("list_dir",))["list_dir"]
    if isinstance(result, list):
        assert drop_unsafe_names(result) == result  # list_dir already dropped unsafe names


@pytest.mark.parametrize(
    "hook",
    [
        lambda off, n: b"",  # EOF at once although stat says 5 bytes
        lambda off, n: b"x" * (n + 100),  # more than asked
        lambda off, n: SFTP_FAILURE,
        lambda off, n: b"ab" if off == 0 else SFTP_FAILURE,
    ],
    ids=["early-eof", "over-long", "failure", "fails-mid-file"],
)
def test_sad_hostile_reads(sftp, hook):
    script, s = sftp
    script.read_hook = hook
    _all_ops(s, "read hook", only=("open_read",))


def test_sad_server_drops_the_connection_mid_request(sftp):
    script, s = sftp
    script.drop = True
    _all_ops(s, "drop")


@pytest.mark.parametrize("extra", [b"", b"\x00" * 7], ids=["exact", "padded"])
def test_edge_reads_longer_than_asked_never_corrupt_silently(sftp, extra):
    """A server answering READ with more bytes than requested breaks the
    protocol; the result must be the real content or an OSError."""
    script, s = sftp
    content = os.urandom(1024 * 1024 + 5)
    script.data = content

    def hook(off, n):
        if off >= len(content):
            return b""
        return content[off : off + n] + extra

    script.read_hook = hook
    result = check_contract(lambda: s.open_read("/a.txt").read(), (OSError,), timeout=20.0)
    assert isinstance(result, OSError) or result == content


def test_edge_large_file_read_through_window(sftp):
    script, s = sftp
    script.data = os.urandom(3 * 1024 * 1024 + 17)
    assert s.open_read("/a.txt").read() == script.data
