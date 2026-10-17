"""SVN: a name with an '@' is passed to svn(1) with an empty peg revision.

svn reads everything after the last '@' of a target as a peg revision
("icon@2x.png" -> path "icon", peg "2x.png"), so such a file could not
be read and such a folder not listed. The documented escape is a
trailing '@' (an empty peg revision). svn itself is replaced by a fake
``subprocess.run`` that records the argv.
"""

from __future__ import annotations

import types

import pytest

from core import svn_fs_client as SV
from tests.svn_fake import popen_from_run

_INFO = (
    b'<info><entry kind="dir" path="." revision="1">'
    b"<url>https://svn.example.test/repo/trunk</url></entry></info>"
)
_LIST = b'<lists><list path="x"><entry kind="file"><name>a@b.txt</name></entry></list></lists>'


@pytest.fixture
def svn(monkeypatch):
    seen: list[list[str]] = []

    def fake_run(argv, **kw):
        seen.append(argv)
        out = _LIST if "ls" in argv else (b"data" if "cat" in argv else _INFO)
        return types.SimpleNamespace(returncode=0, stdout=out, stderr=b"")

    monkeypatch.setattr(SV.shutil, "which", lambda name: "/usr/bin/svn")
    monkeypatch.setattr(SV.subprocess, "run", fake_run)
    monkeypatch.setattr(SV.subprocess, "Popen", popen_from_run(fake_run))
    s = SV.SvnFsSession(url="https://svn.example.test/repo/trunk")
    seen.clear()
    return s, seen


def _target(argv: list[str]) -> str:
    return next(a for a in argv if a.startswith("https://"))


def test_happy_read_of_an_at_name_ends_in_an_empty_peg(svn):
    s, seen = svn
    assert s.open_read("/img/icon@2x.png").read() == b"data"
    assert _target(seen[-1]) == "https://svn.example.test/repo/trunk/img/icon@2x.png@"


def test_sad_listing_of_an_at_folder_ends_in_an_empty_peg(svn):
    s, seen = svn
    assert [i.name for i in s.list_dir("/v@1")] == ["a@b.txt"]
    assert _target(seen[-1]) == "https://svn.example.test/repo/trunk/v@1@"


def test_edge_names_without_an_at_are_passed_unchanged(svn):
    s, seen = svn
    s.open_read("/plain.txt")
    assert _target(seen[-1]) == "https://svn.example.test/repo/trunk/plain.txt"
    s.list_dir("/")
    assert _target(seen[-1]) == "https://svn.example.test/repo/trunk"
