"""rsync exists() and is_dir() say False only for "not found".

stat() looks a name up in the ``rsync --list-only`` of its parent, and
exists() / is_dir() answered False for every OSError it raised: a daemon
that refuses the connection, a folder the daemon may not read
("Permission denied (13)", exit 23), a timeout. server_side_copy(
overwrite=False) and the transfer worker's no-clobber check take False
as the go-ahead to write, and remove() took a False from exists() after
its delete run as proof the entry was gone. A name the listing lacks, a
missing parent ("No such file or directory (2)") and a file where a
folder of the path should be ("Not a directory (20)") are
FileNotFoundError now, and only that means False.

Driven end to end against a real ``rsync --daemon`` on 127.0.0.1.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

RSYNC = shutil.which("rsync")
pytestmark = pytest.mark.skipif(not RSYNC, reason="rsync binary not installed")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def rsyncd():
    from core.rsync_client import RsyncSession

    tmp = tempfile.mkdtemp(prefix="axross-rsyncd-")
    data = Path(tmp, "data")
    (data / "dir").mkdir(parents=True)
    (data / "dir" / "b.txt").write_text("b")
    (data / "locked").mkdir()
    (data / "locked" / "keep.txt").write_text("keep")
    (data / "a.txt").write_text("keep")
    port = _free_port()
    conf = Path(tmp, "rsyncd.conf")
    conf.write_text(
        f"pid file = {tmp}/pid\nuse chroot = no\nmunge symlinks = no\n"
        f"address = 127.0.0.1\nport = {port}\n"
        f"[mod]\npath = {data}\nread only = no\n"
    )
    daemon = subprocess.Popen(
        [RSYNC, "--daemon", "--no-detach", f"--config={conf}"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.05)
    try:
        yield RsyncSession("127.0.0.1", port=port, module="mod"), data, daemon
    finally:
        (data / "locked").chmod(0o755)
        if daemon.poll() is None:
            daemon.terminate()
            daemon.wait(5)
        shutil.rmtree(tmp, ignore_errors=True)


# --- happy ----------------------------------------------------------------


def test_happy_present_and_absent(rsyncd):
    s, _data, _daemon = rsyncd
    assert s.exists("/a.txt") is True
    assert s.exists("/dir") is True
    assert s.is_dir("/dir") is True
    assert s.is_dir("/a.txt") is False
    assert s.exists("/missing.txt") is False
    assert s.is_dir("/missing") is False
    with pytest.raises(FileNotFoundError):
        s.stat("/missing.txt")


# --- sad ------------------------------------------------------------------


def test_sad_a_daemon_that_is_gone_is_an_oserror_not_absent(rsyncd):
    s, _data, daemon = rsyncd
    daemon.terminate()
    daemon.wait(5)
    with pytest.raises(OSError) as err:
        s.exists("/a.txt")
    assert not isinstance(err.value, FileNotFoundError)
    with pytest.raises(OSError):
        s.is_dir("/dir")


@pytest.mark.skipif(
    not hasattr(os, "geteuid") or os.geteuid() == 0, reason="needs a non-root POSIX user"
)
def test_sad_a_folder_the_daemon_may_not_read_is_an_oserror(rsyncd):
    s, data, _daemon = rsyncd
    (data / "locked").chmod(0)
    with pytest.raises(OSError, match="Permission denied") as err:
        s.exists("/locked/keep.txt")
    assert not isinstance(err.value, FileNotFoundError)
    with pytest.raises(OSError, match="Permission denied"):
        s.is_dir("/locked/sub")


def test_sad_remove_reports_a_failed_lookup_as_a_failure_not_as_gone(rsyncd):
    s, _data, daemon = rsyncd
    daemon.terminate()
    daemon.wait(5)
    with pytest.raises(OSError) as err:
        s.remove("/a.txt")
    assert not isinstance(err.value, FileNotFoundError)


# --- edge -----------------------------------------------------------------


def test_edge_a_missing_parent_means_absent(rsyncd):
    s, _data, _daemon = rsyncd
    assert s.exists("/nodir/a.txt") is False
    assert s.is_dir("/nodir/sub") is False


def test_edge_a_file_on_the_way_means_absent(rsyncd):
    s, _data, _daemon = rsyncd
    assert s.exists("/a.txt/b") is False
    assert s.is_dir("/a.txt/b") is False


def test_edge_remove_of_a_missing_entry_is_still_file_not_found(rsyncd):
    s, data, _daemon = rsyncd
    with pytest.raises(FileNotFoundError):
        s.remove("/missing.txt")
    assert (data / "a.txt").read_text() == "keep"
