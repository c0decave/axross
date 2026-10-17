"""SVN: names are percent-encoded in the URL, and the read cap stops the
download instead of measuring it afterwards.

Measured 2026-10-17 with svn 1.14 (debian bookworm, file:// repository):
svn decodes %XX in a URL, so the raw URL of a file named "100%25.txt"
returned the content of "100%.txt" - another file, silently - and
"d %25x/in.txt" was "path not found"; percent-encoded, every name read
right ('#', '?', ' ', 'ü', '@' with its empty peg included).

open_read's 256 MiB cap was checked after subprocess.run had collected
all of svn's output: a bigger file was read completely into memory (and
waited for) before being refused.
"""

from __future__ import annotations

import os
import stat
import sys
import time
import types

import pytest

from core import svn_fs_client as SV
from tests.svn_fake import popen_from_run

_INFO = (
    b'<info><entry kind="dir" path="." revision="1">'
    b"<url>https://svn.example.test/repo/trunk</url></entry></info>"
)


@pytest.fixture
def svn(monkeypatch):
    seen: list[list[str]] = []

    def fake_run(argv, **kw):
        seen.append(argv)
        out = (
            b"<lists><list path='x'></list></lists>"
            if "ls" in argv
            else (b"data" if "cat" in argv else _INFO)
        )
        return types.SimpleNamespace(returncode=0, stdout=out, stderr=b"")

    monkeypatch.setattr(SV.shutil, "which", lambda name: "/usr/bin/svn")
    monkeypatch.setattr(SV.subprocess, "run", fake_run)
    monkeypatch.setattr(SV.subprocess, "Popen", popen_from_run(fake_run))
    s = SV.SvnFsSession(url="https://svn.example.test/repo/trunk")
    seen.clear()
    return s, seen


def _target(argv):
    return next(a for a in argv if a.startswith("https://"))


BASE = "https://svn.example.test/repo/trunk"


# -- URLs ------------------------------------------------------------------------------


@pytest.mark.parametrize("name, encoded", [
    ("100%25.txt", "100%2525.txt"),
    ("sp ace.txt", "sp%20ace.txt"),
    ("a#b.txt", "a%23b.txt"),
    ("q?x.txt", "q%3Fx.txt"),
    ("ü.txt", "%C3%BC.txt"),
])
def test_happy_odd_names_reach_svn_encoded(svn, name, encoded):
    s, seen = svn
    s.list_dir(f"/d/{name}")
    assert _target(seen[-1]) == f"{BASE}/d/{encoded}"


def test_sad_a_folder_with_an_escape_lookalike_is_listed_as_named(svn):
    s, seen = svn
    s.list_dir("/d %25x")
    assert _target(seen[-1]) == f"{BASE}/d%20%2525x"


def test_edge_an_at_name_keeps_its_empty_peg_and_plain_names_stay_as_they_are(svn):
    s, seen = svn
    s.open_read("/img/icon@2x.png")
    assert _target(seen[-1]) == f"{BASE}/img/icon@2x.png@"
    s.open_read("/plain-name_1.txt")
    assert _target(seen[-1]) == f"{BASE}/plain-name_1.txt"
    s.list_dir("/")
    assert _target(seen[-1]) == BASE


# -- the read cap ------------------------------------------------------------------------


def _fake_svn(tmp_path, body: str):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    script = bin_dir / "svn"
    script.write_text(f"#!{sys.executable}\n{body}")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return bin_dir


_STREAMER = """
import sys, time
args = sys.argv[1:]
if "info" in args:
    sys.stdout.write('<info><entry kind="dir" path="." revision="1"><url>u</url></entry></info>')
    sys.exit(0)
out = sys.stdout.buffer
for _ in range(64):
    out.write(b"x" * 65536)
    out.flush()
time.sleep(30)
"""


def test_sad_a_file_over_the_cap_is_refused_while_it_streams(tmp_path, monkeypatch):
    bin_dir = _fake_svn(tmp_path, _STREAMER)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setattr(SV, "_MAX_CAT_BYTES", 1024 * 1024)
    s = SV.SvnFsSession(url="https://svn.example.test/repo/trunk")
    started = time.monotonic()
    with pytest.raises(OSError, match="read cap"):
        s.open_read("/big.bin")
    assert time.monotonic() - started < 10  # not after svn's 30 s


def test_edge_a_file_under_the_cap_reads_whole_and_a_failing_cat_says_why(tmp_path, monkeypatch):
    body = """
import sys
args = sys.argv[1:]
if "info" in args:
    sys.stdout.write('<info><entry kind="dir" path="." revision="1"><url>u</url></entry></info>')
    sys.exit(0)
if any(a.endswith("/gone.txt") for a in args):
    sys.stderr.write("svn: E160013: path not found")
    sys.exit(1)
sys.stdout.buffer.write(b"y" * 70000)
"""
    bin_dir = _fake_svn(tmp_path, body)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    s = SV.SvnFsSession(url="https://svn.example.test/repo/trunk")
    assert s.open_read("/ok.bin").read() == b"y" * 70000
    with pytest.raises(OSError, match="E160013"):
        s.open_read("/gone.txt")
