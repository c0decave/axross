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
    # They go into a temp file beside the target, which appears only at
    # the end.
    def arrived() -> int:
        return sum((tmp_path / n).stat().st_size for n in _others(tmp_path))

    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and arrived() == 0:
        time.sleep(0.05)
    assert arrived() > 0 and not target.exists()
    fh.close()
    assert target.read_bytes() == data
    assert _others(tmp_path, target.name) == []


def test_a_failed_upload_raises_and_a_discarded_one_ends(session, tmp_path):
    with pytest.raises(OSError):
        with session.open_write(str(tmp_path / "no" / "such" / "dir" / "f")) as fh:
            fh.write(b"x" * 100)
    fh = session.open_write(str(tmp_path / "gone.bin"))
    fh.write(b"partial")
    fh.discard()


# --- an upload that does not complete leaves the server's file as it was ---
#
# The upload streamed into ``cat > target``: the target was emptied when the
# upload started, and a cancelled or cut upload left it empty or half-written
# (a spooled backend never touched it). It now streams into a temp file
# beside the target, moved onto it only once the upload completed.


def _others(folder: Path, *keep: str) -> list[str]:
    """Names in *folder* besides *keep*: a temp file left behind."""
    return sorted(set(os.listdir(folder)) - set(keep) - {"bin"})


def _on_the_server(folder: Path, payload: bytes) -> None:
    """Wait until *payload* reached a file in *folder*: the upload is under
    way on the server when the test cancels it."""
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        for name in _others(folder):
            try:
                if (folder / name).read_bytes().startswith(payload):
                    return
            except OSError:
                pass
        time.sleep(0.02)
    raise AssertionError("the upload never reached the server")


def _old_file(tmp_path: Path, name: str = "keep.txt", mode: int = 0o640) -> Path:
    target = tmp_path / name
    target.write_bytes(b"the old content\n")
    target.chmod(mode)
    return target


def test_sad_a_cancelled_upload_keeps_the_old_content(session, tmp_path):
    target = _old_file(tmp_path)
    data = os.urandom(2 * 1024 * 1024)
    fh = session.open_write(str(target))
    fh.write(data)
    _on_the_server(tmp_path, data[:1024])
    fh.discard()
    assert target.read_bytes() == b"the old content\n"
    assert _others(tmp_path, target.name) == []


def test_sad_an_exception_in_the_with_block_keeps_the_old_content(session, tmp_path):
    target = _old_file(tmp_path)
    with pytest.raises(RuntimeError):
        with session.open_write(str(target)) as fh:
            fh.write(b"half of the new")
            _on_the_server(tmp_path, b"half of the new")
            raise RuntimeError("cancelled")
    assert target.read_bytes() == b"the old content\n"
    assert _others(tmp_path, target.name) == []


def test_sad_a_cut_connection_keeps_the_old_content(session, tmp_path):
    target = _old_file(tmp_path)
    fh = session.open_write(str(target))
    fh.write(b"half of the new")
    _on_the_server(tmp_path, b"half of the new")
    fh._proc.kill()  # the connection is gone before the end of the data
    with pytest.raises(OSError):
        fh.close()
    assert target.read_bytes() == b"the old content\n"
    assert _others(tmp_path, target.name) == []


def test_sad_a_cancelled_append_keeps_the_old_content(session, tmp_path):
    target = _old_file(tmp_path)
    fh = session.open_write(str(target), append=True)
    fh.write(b"more")
    _on_the_server(tmp_path, b"the old content\nmore")
    fh.discard()
    assert target.read_bytes() == b"the old content\n"
    assert _others(tmp_path, target.name) == []


def test_happy_a_completed_upload_replaces_the_file_and_keeps_its_mode(session, tmp_path):
    target = _old_file(tmp_path, mode=0o640)
    data = os.urandom(300 * 1024)
    with session.open_write(str(target)) as fh:
        fh.write(data)
    assert target.read_bytes() == data
    assert stat.S_IMODE(target.stat().st_mode) == 0o640
    assert _others(tmp_path, target.name) == []


def test_edge_a_read_only_file_is_written_only_where_cat_could(session, tmp_path):
    """A writable folder is no licence to replace a file the login may not
    write (``cat > path`` asked for the file's own permission): refused
    then, and left as it was. Where the login may (root), the new content
    comes in and the file stays read-only."""
    target = _old_file(tmp_path, mode=0o444)
    if not os.access(target, os.W_OK):
        with pytest.raises(PermissionError):
            session.open_write(str(target))
        assert target.read_bytes() == b"the old content\n"
    else:
        with session.open_write(str(target)) as fh:
            fh.write(b"new")
        assert target.read_bytes() == b"new"
    assert stat.S_IMODE(target.stat().st_mode) == 0o444
    assert _others(tmp_path, target.name) == []


def test_edge_a_folder_that_takes_no_new_file_is_written_in_place(session, tmp_path):
    """A writable file in a folder the login may not create files in has
    no room for a temp file beside it: written in place, as before, rather
    than not at all."""
    folder = tmp_path / "locked"
    folder.mkdir()
    target = _old_file(folder)
    folder.chmod(0o555)
    try:
        if os.access(folder, os.W_OK):
            pytest.skip("this login may write into any folder (root)")
        with session.open_write(str(target)) as fh:
            fh.write(b"new")
        assert target.read_bytes() == b"new"
        assert stat.S_IMODE(target.stat().st_mode) == 0o640
    finally:
        folder.chmod(0o755)


def test_happy_a_completed_append_adds_to_the_end(session, tmp_path):
    target = _old_file(tmp_path, mode=0o600)
    with session.open_write(str(target), append=True) as fh:
        fh.write(b"more\n")
    assert target.read_bytes() == b"the old content\nmore\n"
    assert stat.S_IMODE(target.stat().st_mode) == 0o600


def test_edge_a_new_file_gets_the_mode_a_new_file_gets(session, tmp_path):
    umask = os.umask(0)
    os.umask(umask)
    target = tmp_path / "new.txt"
    with session.open_write(str(target)) as fh:
        fh.write(b"new")
    assert target.read_bytes() == b"new"
    assert stat.S_IMODE(target.stat().st_mode) == 0o666 & ~umask
    assert _others(tmp_path, target.name) == []


def test_edge_an_upload_through_a_symlink_writes_the_file_it_names(session, tmp_path):
    real = _old_file(tmp_path, "real.txt", mode=0o600)
    link = tmp_path / "link.txt"
    link.symlink_to("real.txt")
    with session.open_write(str(link)) as fh:
        fh.write(b"new")
    assert link.is_symlink()
    assert real.read_bytes() == b"new"
    assert stat.S_IMODE(real.stat().st_mode) == 0o600


def test_hostile_a_name_with_quotes_and_spaces(session, tmp_path):
    target = _old_file(tmp_path, "it's a $(touch pwned) file.txt")
    with session.open_write(str(target)) as fh:
        fh.write(b"new")
    assert target.read_bytes() == b"new"
    assert not (tmp_path / "pwned").exists()
    assert _others(tmp_path, target.name) == []


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
