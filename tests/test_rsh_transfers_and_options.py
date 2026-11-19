"""rsh: transfers stream, slow commands get time, and the command line is
built safely.

* Downloads were one ``head -c 64MiB`` answer held in memory: a larger
  file could not be read at all, the bar did not move, Cancel was seen
  only at the end. Uploads were held in memory as a whole and sent in
  close() under the 30 s time-out: a large upload failed half-way (the
  file truncated on the server) and memory grew with the file. Both now
  stream through the rsh process: progress per piece, Cancel kills it, a
  spool on disk instead of memory, and a time-out only when nothing moves.
* cp / mv / rm -r / sha256sum ran under the 30 s time-out: a large copy
  or checksum failed while it was still running on the server.
* A host name that starts with "-" was read by rsh as an option.
* The rsh process inherited axross' stdin (the terminal it was started
  from) and forwarded it to the server.
* The profile's IP version reaches rsh as -4 / -6.

Driven through a stand-in ``rsh`` executable that runs the command with
``sh -c`` locally and, like classic rsh, exits 0.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import sys
import textwrap
import threading
import time
from pathlib import Path

import pytest

from core import rsh_client as RC
from core import transfer_hooks

pytestmark = pytest.mark.skipif(not shutil.which("sh"), reason="needs sh")


def _fake_rsh(tmp_path: Path) -> Path:
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    script = bindir / "rsh"
    script.write_text(
        textwrap.dedent(
            f"""\
            #!{sys.executable}
            import os, sys
            os.chdir({str(tmp_path)!r})
            os.execvp("sh", ["sh", "-c", sys.argv[-1]])
            """
        )
    )
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return bindir


@pytest.fixture
def session(tmp_path, monkeypatch):
    bindir = _fake_rsh(tmp_path)
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ.get('PATH', '')}")
    return RC.RshSession(host="rsh.invalid", username="u")


def test_a_download_streams_with_progress_and_has_no_64_mib_limit(session, tmp_path):
    assert RC.MAX_FILE_BYTES >= 1024**3
    data = os.urandom(3 * 1024 * 1024 + 7)
    (tmp_path / "f.bin").write_bytes(data)
    seen: list[int] = []
    hooks = transfer_hooks.TransferHooks(progress=lambda kind, done, total: seen.append(done))
    with transfer_hooks.active(hooks):
        assert session.open_read(str(tmp_path / "f.bin")).read() == data
    assert len(seen) >= 2 and seen[-1] == len(data), seen[-3:]


def test_cancel_stops_a_download(session, tmp_path):
    (tmp_path / "f.bin").write_bytes(os.urandom(4 * 1024 * 1024))
    cancel = threading.Event()

    def progress(kind, done, total):
        if done > 0:
            cancel.set()

    with transfer_hooks.active(transfer_hooks.TransferHooks(cancel_event=cancel, progress=progress)):
        with pytest.raises(InterruptedError):
            session.open_read(str(tmp_path / "f.bin"))


def test_a_missing_file_is_still_an_error(session, tmp_path):
    with pytest.raises(FileNotFoundError):
        session.open_read(str(tmp_path / "missing"))


def test_an_upload_streams_while_it_is_written(session, tmp_path):
    target = tmp_path / "up.bin"
    data = os.urandom(2 * 1024 * 1024)
    fh = session.open_write(str(target))
    fh.write(data)
    # The bytes are on their way before close(): nothing waits in memory.
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and (not target.exists() or target.stat().st_size == 0):
        time.sleep(0.05)
    assert target.exists() and target.stat().st_size > 0
    fh.close()
    assert target.read_bytes() == data


def test_a_failed_upload_raises_and_a_discarded_one_ends(session, tmp_path):
    with pytest.raises(OSError):
        with session.open_write(str(tmp_path / "no" / "such" / "dir" / "f")) as fh:
            fh.write(b"x" * 100)
    fh = session.open_write(str(tmp_path / "gone.bin"))
    fh.write(b"partial")
    fh.discard()


@pytest.fixture
def recorded(monkeypatch):
    calls: list[tuple[list[str], dict]] = []

    def run(argv, **kw):
        calls.append((list(argv), kw))
        script = argv[-1]
        tag = re.search(r"__AXROSS_RSH_STATUS_[0-9a-f]+__", script).group(0)
        out = b"axross-rsh-probe" if "axross-rsh-probe" in script else b""
        return subprocess.CompletedProcess(argv, 0, stdout=out + b"\n" + tag.encode() + b" 0\n",
                                           stderr=b"")

    monkeypatch.setattr(RC, "_ensure_rsh_available", lambda: "/usr/bin/rsh")
    monkeypatch.setattr(RC.subprocess, "run", run)
    return calls


def test_slow_server_side_commands_get_the_long_time_out(recorded):
    s = RC.RshSession(host="h", username="u")
    recorded.clear()
    s.copy("/a", "/b")
    s.rename("/a", "/c")
    s.remove("/d", recursive=True)
    s.checksum("/a")
    timeouts = [kw["timeout"] for _argv, kw in recorded]
    assert timeouts and all(t >= RC.TREE_OP_TIMEOUT for t in timeouts), timeouts


def test_no_command_reads_axross_stdin(recorded):
    s = RC.RshSession(host="h", username="u")
    s.list_dir("/")
    for _argv, kw in recorded:
        assert kw.get("stdin") is subprocess.DEVNULL or "input" in kw and kw["input"] is not None


def test_a_host_that_looks_like_an_option_is_refused(recorded):
    with pytest.raises(OSError):
        RC.RshSession(host="-lroot", username="u")
    assert recorded == []


@pytest.mark.parametrize("family, flag", [("ipv4", "-4"), ("ipv6", "-6")])
def test_the_ip_version_reaches_rsh(recorded, family, flag):
    RC.RshSession(host="h", username="u", address_family=family)
    argv = recorded[0][0]
    assert flag in argv[: argv.index("h")]
