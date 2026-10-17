"""Fuzz: the SVN backend against hostile ``svn`` command output.

The backend parses ``svn info --xml`` / ``svn ls --xml`` and passes
``svn cat`` through. ``subprocess.run`` is replaced by a fake that hands
back mutated XML (bad encodings, entities, truncation, absurd sizes and
dates, traversal names, invalid UTF-8) or a failing exit with garbage on
stderr. Every call returns sane data or raises OSError.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fuzz_testkit import check_contract, iterations, mutants  # noqa: E402

from core import svn_fs_client as S  # noqa: E402
from tests.svn_fake import popen_from_run  # noqa: E402

INFO = (
    b'<?xml version="1.0" encoding="UTF-8"?>\n<info>\n'
    b'<entry kind="dir" path="repo" revision="42">\n<url>http://127.0.0.1/repo</url>\n'
    b"<repository><root>http://127.0.0.1/repo</root><uuid>u</uuid></repository>\n"
    b"</entry>\n</info>\n"
)
LS = (
    b'<?xml version="1.0" encoding="UTF-8"?>\n<lists>\n<list path="http://127.0.0.1/repo">\n'
    b'<entry kind="file"><name>a.txt</name><size>5</size>'
    b'<commit revision="7"><author>me</author><date>2024-01-02T03:04:05.123456Z</date></commit>'
    b"</entry>\n"
    b'<entry kind="dir"><name>sub</name>'
    b'<commit revision="8"><author>you</author><date>2024-02-03T04:05:06.000000Z</date></commit>'
    b"</entry>\n</list>\n</lists>\n"
)
HOSTILE_LS = [
    LS.replace(b"a.txt", b"../../etc/passwd"),
    LS.replace(b"a.txt", b"caf\xe9.txt"),
    LS.replace(b"<size>5</size>", b"<size>-1</size>"),
    LS.replace(b"<size>5</size>", b"<size>" + b"9" * 5000 + b"</size>"),
    LS.replace(b"2024-01-02T03:04:05.123456Z", b"9999-99-99T99:99:99.Z"),
    LS.replace(b'encoding="UTF-8"', b'encoding="bogus"'),
    b'<!DOCTYPE l [<!ENTITY a "b">]><lists>&a;</lists>',
    b'<!DOCTYPE l [<!ENTITY a SYSTEM "file:///etc/passwd">]><lists>&a;</lists>',
    b"<lists>" + b"<entry>" * 50000,
    b"",
    b"\x00\xff",
]


class _FakeSvn:
    """Stands in for subprocess.run: ``info`` and ``ls`` answer from
    tables the test mutates, ``cat`` returns ``self.cat``."""

    def __init__(self) -> None:
        self.info = INFO
        self.ls = LS
        self.cat = b"hello"
        self.returncode = 0
        self.stderr = b""

    def __call__(self, argv, **kwargs):
        sub = next(a for a in argv[1:] if a in ("info", "ls", "cat"))
        out = {"info": self.info, "ls": self.ls, "cat": self.cat}[sub]
        return subprocess.CompletedProcess(argv, self.returncode, out, self.stderr)


@pytest.fixture
def svn():
    fake = _FakeSvn()
    with (
        mock.patch.object(S, "_svn_available", return_value=True),
        mock.patch.object(S.subprocess, "run", fake),
        mock.patch.object(S.subprocess, "Popen", popen_from_run(fake)),
    ):
        client = S.SvnFsSession(url="http://127.0.0.1/repo")
        yield fake, client


def _ops(client):
    return {
        "list_dir": lambda: client.list_dir("/"),
        "stat": lambda: client.stat("/a.txt"),
        "is_dir": lambda: client.is_dir("/sub"),
        "exists": lambda: client.exists("/a.txt"),
        "open_read": lambda: client.open_read("/a.txt").read(),
    }


def _check_listing(result) -> None:
    if isinstance(result, list):
        for item in result:
            assert isinstance(item.name, str) and item.name
            assert isinstance(item.size, int)


def test_happy_listing(svn):
    _fake, client = svn
    items = client.list_dir("/")
    assert [(i.name, i.is_dir, i.size) for i in items] == [("sub", True, 0), ("a.txt", False, 5)]
    assert client.open_read("/a.txt").read() == b"hello"


@pytest.mark.parametrize("ls", HOSTILE_LS, ids=[str(i) for i in range(len(HOSTILE_LS))])
def test_sad_hostile_listings(svn, ls):
    fake, client = svn
    fake.ls = ls
    for name, op in _ops(client).items():
        result = check_contract(op, (OSError,), context=f"{name} {ls[:60]!r}")
        if name == "list_dir":
            _check_listing(result)


def test_sad_mutated_listings(svn):
    fake, client = svn
    for n, ls in enumerate(mutants([LS], seed=0x53564E, per_entry=iterations(1000))):
        fake.ls = ls
        result = check_contract(lambda: client.list_dir("/"), (OSError,), context=f"mutant {n}")
        _check_listing(result)


def test_sad_mutated_info_at_connect():
    fake = _FakeSvn()
    with (
        mock.patch.object(S, "_svn_available", return_value=True),
        mock.patch.object(S.subprocess, "run", fake),
    ):
        for n, info in enumerate(mutants([INFO], seed=0x494E, per_entry=iterations(500))):
            fake.info = info
            check_contract(
                lambda: S.SvnFsSession(url="http://127.0.0.1/repo"),
                (OSError,),
                context=f"info mutant {n}",
            )


@pytest.mark.parametrize("stderr", [b"", b"\xff\xfe svn: E170000", b"x" * 100000])
def test_edge_failing_svn_with_garbage_stderr(svn, stderr):
    fake, client = svn
    fake.returncode, fake.stderr = 1, stderr
    for name, op in _ops(client).items():
        check_contract(op, (OSError,), context=name)
