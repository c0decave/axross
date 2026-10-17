"""SVN exists() and is_dir() say False only for "not found".

stat() looks a path up in the ``svn ls`` of its parent, and both
exists() and is_dir() answered False for every OSError it raised: a
server that could not be reached (E170013), refused credentials
(E215004), a certificate failure (E230001), a timed-out command, a
listing that was not XML. server_side_copy(overwrite=False) and the
transfer worker's no-clobber check take False as the go-ahead to write.
Now only FileNotFoundError means False: the parent lists no such name,
or svn says the parent does not exist (SVN_ERR_FS_NOT_FOUND, W160013).

svn itself is replaced by a fake ``subprocess.run``.
"""

from __future__ import annotations

import subprocess
import types

import pytest

from core import svn_fs_client as SV
from tests.svn_fake import popen_from_run

ROOT = "https://svn.example.test/repo/trunk"
_INFO = (
    b'<info><entry kind="dir" path="." revision="1">'
    b"<url>" + ROOT.encode() + b"</url></entry></info>"
)
_ROOT_LIST = (
    b'<lists><list path="x">'
    b'<entry kind="file"><name>a.txt</name><size>4</size></entry>'
    b'<entry kind="dir"><name>dir</name></entry>'
    b"</list></lists>"
)
_EMPTY_LIST = b'<lists><list path="x"></list></lists>'
_MISSING = (
    b"svn: warning: W160013: URL '" + ROOT.encode() + b"/nodir' non-existent in revision 1\n"
    b"svn: E200009: Could not list all targets because some targets don't exist\n"
)


def _ok(out: bytes):
    return types.SimpleNamespace(returncode=0, stdout=out, stderr=b"")


def _err(stderr: bytes):
    return types.SimpleNamespace(returncode=1, stdout=b"", stderr=stderr)


@pytest.fixture
def svn(monkeypatch):
    state = types.SimpleNamespace(ls=None)

    def fake_run(argv, **kw):
        if "info" in argv:
            return _ok(_INFO)
        if "ls" in argv:
            if state.ls is not None:
                return state.ls(argv)
            target = next(a for a in argv if a.startswith("https://"))
            if target == ROOT:
                return _ok(_ROOT_LIST)
            if target == ROOT + "/dir":
                return _ok(_EMPTY_LIST)
            return _err(_MISSING)
        return _ok(b"")

    monkeypatch.setattr(SV.shutil, "which", lambda name: "/usr/bin/svn")
    monkeypatch.setattr(SV.subprocess, "run", fake_run)
    monkeypatch.setattr(SV.subprocess, "Popen", popen_from_run(fake_run))
    return state, SV.SvnFsSession(url=ROOT)


def test_happy_present_and_absent(svn):
    _state, s = svn
    assert s.exists("/a.txt") is True
    assert s.exists("/dir") is True
    assert s.is_dir("/dir") is True
    assert s.is_dir("/a.txt") is False
    assert s.exists("/missing.txt") is False
    assert s.is_dir("/missing") is False


@pytest.mark.parametrize(
    "answer",
    [
        lambda argv: _err(b"svn: E170013: Unable to connect to a repository at URL\n"),
        lambda argv: _err(b"svn: E215004: No more credentials or we tried too many times\n"),
        lambda argv: _err(b"svn: E230001: Server SSL certificate verification failed\n"),
        lambda argv: _ok(b"<html>proxy error</html"),
    ],
    ids=["unreachable", "credentials", "certificate", "not-xml"],
)
def test_sad_a_failed_listing_is_an_oserror_not_absent(svn, answer):
    state, s = svn
    state.ls = answer
    with pytest.raises(OSError) as err:
        s.exists("/a.txt")
    assert not isinstance(err.value, FileNotFoundError)
    with pytest.raises(OSError):
        s.is_dir("/dir")


def test_sad_a_timed_out_listing_is_an_oserror(svn):
    state, s = svn

    def hang(argv):
        raise subprocess.TimeoutExpired(argv, 30)

    state.ls = hang
    with pytest.raises(OSError, match="timed out"):
        s.exists("/a.txt")


def test_edge_a_missing_parent_means_absent(svn):
    _state, s = svn
    with pytest.raises(FileNotFoundError):
        s.list_dir("/nodir")
    assert s.exists("/nodir/a.txt") is False
    assert s.is_dir("/nodir/sub") is False


def test_edge_the_root_needs_no_listing(svn):
    state, s = svn
    state.ls = lambda argv: pytest.fail("no listing for the root")
    assert s.exists("/") is True
    assert s.is_dir("/") is True
