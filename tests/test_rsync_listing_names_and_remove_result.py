"""rsync: the MOTD is no folder, names keep their spaces, remove tells the truth.

* ``rsync --list-only`` against a daemon prints the MOTD first; list_dir
  passed no ``--no-motd`` and fed every line that is no listing line to
  the module-listing branch, so each MOTD line became a folder - also
  inside a module.
* list_dir ``rstrip()``-ed each line, cutting the trailing spaces of a
  name: ``keep `` was listed as ``keep``, so stat / is_dir of the real
  name failed.
* remove() reported success without checking: when is_dir() could not
  confirm a folder the file branch ran, and when nothing was deleted
  the caller still heard "done". The file branch's filter matched a
  FOLDER of that name too (``--include NAME``), which ``--delete``
  removes with its tree. Now the file filter cannot match a folder and
  remove fails when the entry is still there afterwards.

Driven end to end against a real ``rsync --daemon`` on 127.0.0.1.
"""

from __future__ import annotations

import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path

import pytest

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
    (data / "sub").mkdir(parents=True)
    (data / "sub" / "real.txt").write_text("x")
    (data / "keep " / "deep").mkdir(parents=True)
    (data / "keep " / "a.txt").write_text("important")
    (data / "keep " / "deep" / "b.txt").write_text("important")
    (data / "f.txt").write_text("f")
    (data / "dup").mkdir()
    (data / "dup" / "x.txt").write_text("x")
    motd = Path(tmp, "motd")
    motd.write_text("Welcome to the example mirror\nPlease use the nearest mirror\n")
    port = _free_port()
    conf = Path(tmp, "rsyncd.conf")
    conf.write_text(
        f"pid file = {tmp}/pid\nuse chroot = no\nmotd file = {motd}\n"
        f"address = 127.0.0.1\nport = {port}\n"
        f"[mod]\npath = {data}\nread only = no\n"
    )
    daemon = subprocess.Popen(
        [RSYNC, "--daemon", "--no-detach", f"--config={conf}"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.05)
        yield RsyncSession("127.0.0.1", port=port, module="mod"), data
    finally:
        daemon.terminate()
        daemon.wait(5)
        shutil.rmtree(tmp, ignore_errors=True)


# -- happy -------------------------------------------------------------------


def test_happy_motd_lines_are_not_listed(rsyncd):
    sess, _data = rsyncd
    assert [(i.name, i.is_dir) for i in sess.list_dir("/sub")] == [("real.txt", False)]
    names = {i.name for i in sess.list_dir("/")}
    assert "Welcome" not in names and "Please" not in names
    # (Only the module list of a session without a module still shows the
    # MOTD: there --no-motd would suppress the module list as well.)


def test_happy_file_remove_deletes_and_reports(rsyncd):
    sess, data = rsyncd
    sess.remove("/f.txt")
    assert not (data / "f.txt").exists()


# -- sad ---------------------------------------------------------------------


def test_sad_trailing_space_name_is_kept_and_its_folder_refused(rsyncd):
    sess, data = rsyncd
    assert "keep " in [i.name for i in sess.list_dir("/")]
    assert sess.is_dir("/keep ")
    with pytest.raises(OSError):
        sess.remove("/keep ", recursive=False)
    assert (data / "keep " / "deep" / "b.txt").exists()


def test_sad_file_branch_never_deletes_a_folder_of_that_name(rsyncd, monkeypatch):
    sess, data = rsyncd
    # is_dir cannot confirm the folder (a listing failed, a name it cannot
    # match): the file branch runs for a folder.
    monkeypatch.setattr(type(sess), "is_dir", lambda self, path: False)
    with pytest.raises(OSError):
        sess.remove("/dup", recursive=False)
    assert (data / "dup" / "x.txt").exists()


# -- edge --------------------------------------------------------------------


def test_edge_remove_of_a_missing_file_is_an_error(rsyncd):
    sess, _data = rsyncd
    with pytest.raises(OSError):
        sess.remove("/no-such-file.txt")
