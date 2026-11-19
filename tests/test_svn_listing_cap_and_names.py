"""SVN listings (review round 2).

* ``svn ls --xml`` was collected whole by subprocess.run: a server
  answering a listing without end filled the memory. It is read in steps
  and refused past _MAX_LS_BYTES, the process killed.
* A name with a "/" (``../../etc/passwd``) or "." / ".." is no entry of
  the folder: a hostile server's, and joined onto a destination it lands
  elsewhere. It is dropped.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import svn_fs_client as S  # noqa: E402
from test_fuzz_svn import LS, _FakeSvn  # noqa: E402
from tests.svn_fake import popen_from_run  # noqa: E402


@pytest.fixture
def svn():
    fake = _FakeSvn()
    with (
        mock.patch.object(S, "_svn_available", return_value=True),
        mock.patch.object(S.subprocess, "run", fake),
        mock.patch.object(S.subprocess, "Popen", popen_from_run(fake)),
    ):
        yield fake, S.SvnFsSession(url="http://127.0.0.1/repo")


def test_sad_listing_past_the_cap_is_refused(svn, monkeypatch) -> None:
    fake, client = svn
    monkeypatch.setattr(S, "_MAX_LS_BYTES", 4096)
    fake.ls = LS.replace(b"</list>", b"<entry kind='file'><name>x</name></entry>" * 500 + b"</list>")
    with pytest.raises(OSError, match="cap"):
        client.list_dir("/")


@pytest.mark.parametrize("name", [b"..", b"."])
def test_sad_dot_names_are_dropped(svn, name) -> None:
    fake, client = svn
    fake.ls = LS.replace(b"<name>a.txt</name>", b"<name>" + name + b"</name>")
    assert [i.name for i in client.list_dir("/")] == ["sub"]


@pytest.mark.parametrize("name", [b"../../etc/passwd", b"a/b"])
def test_sad_impossible_names_are_listed_unusable(svn, name) -> None:
    """Listed under a NUL-marked name (a row nothing acts on), not left out."""
    fake, client = svn
    fake.ls = LS.replace(b"<name>a.txt</name>", b"<name>" + name + b"</name>")
    names = sorted(i.name for i in client.list_dir("/"))
    assert names == sorted(["sub", "\x00" + name.decode()])
