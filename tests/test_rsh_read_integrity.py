"""rsh reads never pass a short or failed read off as the file's content.

Two holes, both of which handed the caller a short ``BytesIO`` as if it
were the whole file:

* ``open_read`` ran ``head -c 64MiB`` and returned whatever came back —
  a 100 MiB file was silently cut to 64 MiB, and a copy of it "succeeded".
* The rsh protocol carries the remote command's stdout and stderr, not its
  exit status: classic ``rsh`` exits 0 whenever the connection worked.
  ``_run_remote`` trusted ``returncode`` alone, so a read of a missing or
  unreadable file returned ``b""``, and a connection cut mid-stream
  returned the bytes received so far.

The remote command now reports its own status in a per-call tagged
trailer on stdout; a missing trailer means the stream was cut.

Driven end to end through a stand-in ``rsh`` executable that runs the
command with ``sh -c`` in a temp directory and, like classic rsh, always
exits 0.
"""

from __future__ import annotations

import os
import shutil
import stat
import sys
import textwrap
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import rsh_client as RC  # noqa: E402

pytestmark = pytest.mark.skipif(not shutil.which("sh"), reason="needs sh")


def _fake_rsh(tmp_path: Path, *, cut_after: int | None = None) -> Path:
    """An ``rsh`` that runs ``argv[-1]`` locally and exits 0 regardless."""
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    script = bindir / "rsh"
    script.write_text(
        textwrap.dedent(
            f"""\
            #!{sys.executable}
            import subprocess, sys
            proc = subprocess.run(["sh", "-c", sys.argv[-1]], stdin=sys.stdin,
                                  capture_output=True, cwd={str(tmp_path)!r})
            out = proc.stdout
            cut = {cut_after!r}
            if cut is not None:
                out = out[:cut]
            sys.stdout.buffer.write(out)
            sys.stderr.buffer.write(proc.stderr)
            sys.exit(0)  # rsh carries no remote exit status
            """
        )
    )
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return bindir


@pytest.fixture
def session(tmp_path, monkeypatch):
    def make(**kw) -> RC.RshSession:
        bindir = _fake_rsh(tmp_path, **kw)
        monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ.get('PATH', '')}")
        return RC.RshSession(host="rsh.invalid", username="u")

    return make


def test_happy_binary_read_round_trips(session, tmp_path):
    payload = bytes(range(256)) * 300 + b"\n"
    (tmp_path / "f.bin").write_bytes(payload)
    s = session()
    assert s.open_read(str(tmp_path / "f.bin")).read() == payload


def test_happy_file_exactly_at_the_cap_is_read(session, tmp_path, monkeypatch):
    monkeypatch.setattr(RC, "MAX_FILE_BYTES", 1000)
    (tmp_path / "f.bin").write_bytes(b"x" * 1000)
    assert session().open_read(str(tmp_path / "f.bin")).read() == b"x" * 1000


def test_sad_file_above_the_cap_is_refused_not_truncated(session, tmp_path, monkeypatch):
    monkeypatch.setattr(RC, "MAX_FILE_BYTES", 1000)
    (tmp_path / "f.bin").write_bytes(b"x" * 1001)
    with pytest.raises(OSError, match="1000"):
        session().open_read(str(tmp_path / "f.bin"))


def test_sad_missing_file_raises_although_rsh_exits_zero(session, tmp_path):
    with pytest.raises(OSError):
        session().open_read(str(tmp_path / "nope.bin"))


def test_sad_failed_write_side_command_raises(session, tmp_path):
    s = session()
    with pytest.raises(OSError):
        s.rename(str(tmp_path / "nope"), str(tmp_path / "other"))
    (tmp_path / "plain").write_bytes(b"")
    with pytest.raises(OSError):
        s.mkdir(str(tmp_path / "plain" / "sub"))


def test_edge_stream_cut_mid_read_raises(session, tmp_path):
    (tmp_path / "f.bin").write_bytes(b"y" * 5000)
    s = session()  # probe passes: its output is short
    _fake_rsh(tmp_path, cut_after=2000)
    with pytest.raises(OSError):
        s.open_read(str(tmp_path / "f.bin"))


def test_edge_content_that_looks_like_a_trailer_is_kept(session, tmp_path):
    payload = b"data\n__AXROSS_RSH_STATUS__ 1\n0\n"
    (tmp_path / "f.txt").write_bytes(payload)
    assert session().open_read(str(tmp_path / "f.txt")).read() == payload


def test_edge_upload_and_listing_still_work(session, tmp_path):
    s = session()
    with s.open_write(str(tmp_path / "up.bin")) as fh:
        fh.write(b"\x00\xffpayload")
    assert (tmp_path / "up.bin").read_bytes() == b"\x00\xffpayload"
    assert "up.bin" in [i.name for i in s.list_dir(str(tmp_path))]
