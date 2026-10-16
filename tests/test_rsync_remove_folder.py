"""rsync remove() of a folder removes the folder, not only its contents.

Lab matrix: after remove(work, recursive=True) the work folder still
existed. remove() synced an empty directory with --delete into the
folder - emptying it - but never removed the folder itself, although its
docstring says it does; an empty folder removed without recursive stayed
too. The folder's entry is now deleted from its parent with the same
include/exclude filter a file removal uses.
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
    (data / "tree" / "deep").mkdir(parents=True)
    (data / "tree" / "deep" / "f.txt").write_text("x")
    (data / "tree" / "g.txt").write_text("y")
    (data / "empty").mkdir()
    (data / "glob[1]*").mkdir()
    (data / "glob1x").mkdir()
    (data / "keep.txt").write_text("k")
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
        yield RsyncSession("127.0.0.1", port=port, module="mod"), data
    finally:
        daemon.terminate()
        daemon.wait(5)
        shutil.rmtree(tmp, ignore_errors=True)


# --- happy ----------------------------------------------------------------


def test_happy_a_tree_is_removed_with_its_folder(rsyncd):
    s, data = rsyncd
    s.remove("/tree", recursive=True)
    assert not (data / "tree").exists()
    assert not s.exists("/tree")
    assert (data / "keep.txt").exists()


def test_happy_an_empty_folder_is_removed_without_recursive(rsyncd):
    s, data = rsyncd
    s.remove("/empty")
    assert not (data / "empty").exists()


# --- sad ------------------------------------------------------------------


def test_sad_a_full_folder_without_recursive_is_refused_and_kept(rsyncd):
    s, data = rsyncd
    with pytest.raises(OSError):
        s.remove("/tree")
    assert (data / "tree" / "deep" / "f.txt").exists()


# --- edge -----------------------------------------------------------------


def test_edge_a_name_with_pattern_characters_removes_only_itself(rsyncd):
    s, data = rsyncd
    s.remove("/glob[1]*", recursive=True)
    assert not (data / "glob[1]*").exists()
    assert (data / "glob1x").exists() and (data / "keep.txt").exists()


def test_edge_emptying_the_module_root_keeps_the_root(rsyncd):
    s, data = rsyncd
    s.remove("/", recursive=True)
    assert data.is_dir() and list(data.iterdir()) == []
