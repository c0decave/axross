"""Telnet and SCP: exists() and is_dir() say False only for "not found".

Both asked ``test -e`` / ``test -d`` and read every non-zero exit as
"no". test(1) exits 1 for a missing path and for one below a folder it
may not search alike, and a dropped command or a cut stream ended there
too. server_side_copy(overwrite=False) and the transfer worker's
no-clobber check take False from exists() as the go-ahead to write.

The probe runs here in a local ``sh`` with stderr merged into the
output, the way both _exec_raw() hand it back (a terminal mixes the
streams; SCP appends stderr on a non-zero exit).
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.scp_client import SCPSession  # noqa: E402
from core.telnet_client import TelnetSession  # noqa: E402

_ROOT = os.geteuid() == 0


def _local(cmd: str, timeout: float = 30.0, **_kw) -> tuple[str, int]:
    # A German locale on the remote: only LC_ALL=C in the probe keeps
    # the "No such file or directory" wording the classifier reads.
    env = {**os.environ, "LANG": "de_DE.UTF-8", "LANGUAGE": "de", "LC_ALL": "de_DE.UTF-8"}
    p = subprocess.run(
        ["sh", "-c", cmd],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=env,
        timeout=timeout,
    )
    return p.stdout.decode("utf-8", "replace"), p.returncode


def _session(cls, runner=_local):
    s = object.__new__(cls)
    s._exec_raw = runner
    return s


@pytest.fixture(params=[TelnetSession, SCPSession], ids=["telnet", "scp"])
def cls(request):
    return request.param


@pytest.fixture
def tree(tmp_path):
    (tmp_path / "keep.txt").write_text("keep")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "hidden.txt").write_text("x")
    os.symlink(tmp_path / "gone", tmp_path / "dangling")
    yield tmp_path
    os.chmod(tmp_path / "sub", 0o755)


def test_happy_present_and_absent(cls, tree):
    s = _session(cls)
    assert s.exists(str(tree / "keep.txt")) is True
    assert s.exists(str(tree / "sub")) is True
    assert s.exists(str(tree / "gone.txt")) is False
    assert s.is_dir(str(tree / "sub")) is True
    assert s.is_dir(str(tree / "keep.txt")) is False
    assert s.is_dir(str(tree / "gone")) is False


@pytest.mark.skipif(_ROOT, reason="root searches every folder")
def test_sad_a_folder_it_may_not_search_is_an_oserror_not_absent(cls, tree):
    os.chmod(tree / "sub", 0o000)
    s = _session(cls)
    with pytest.raises(PermissionError):
        s.exists(str(tree / "sub" / "hidden.txt"))
    with pytest.raises(PermissionError):
        s.is_dir(str(tree / "sub" / "hidden.txt"))


def test_sad_a_failed_command_is_an_oserror_not_absent(cls):
    s = _session(cls, lambda cmd, timeout=30.0, **_kw: ("sh: 1: Syntax error\n", 2))
    with pytest.raises(OSError):
        s.exists("/srv/keep.txt")
    with pytest.raises(OSError):
        s.is_dir("/srv/sub")


def test_sad_a_lost_connection_is_not_a_go_ahead_for_a_no_clobber_copy(cls, monkeypatch):
    from core.server_ops import server_side_copy

    def gone(cmd, timeout=30.0, **_kw):
        raise OSError("connection reset")

    s = _session(cls, gone)
    written = []
    monkeypatch.setattr(s, "copy", lambda src, dst: written.append(dst), raising=False)
    monkeypatch.setattr(
        s, "open_write", lambda path, append=False: written.append(path), raising=False
    )
    with pytest.raises(OSError):
        server_side_copy(s, "/srv/a.txt", "/srv/b.txt", overwrite=False)
    assert written == []


def test_edge_a_path_below_a_file_is_absent(cls, tree):
    s = _session(cls)
    assert s.exists(str(tree / "keep.txt" / "x")) is False
    assert s.is_dir(str(tree / "keep.txt" / "x")) is False


def test_edge_a_dangling_symlink_is_an_entry(cls, tree):
    """test -e followed the link and said "no": a no-clobber copy then
    wrote through it to the missing target."""
    s = _session(cls)
    assert s.exists(str(tree / "dangling")) is True
    assert s.is_dir(str(tree / "dangling")) is False


def test_edge_odd_names_are_quoted(cls, tree):
    name = tree / "it's a $(file) -n"
    name.write_text("x")
    s = _session(cls)
    assert s.exists(str(name)) is True
    assert s.exists(str(tree / "-n")) is False


def test_edge_an_unreadable_answer_is_an_oserror(cls):
    s = _session(cls, lambda cmd, timeout=30.0, **_kw: ("Welcome!\n", 0))
    with pytest.raises(OSError, match="unreadable"):
        s.exists("/srv/keep.txt")
