"""SCP: a running download or upload does not hold up the session's other
commands.

Every SCP command - the whole of a file transfer included - ran under one
lock per session. The connection manager shares one session between all
panes on a host, so a 4 GB download kept every pane on that host from
listing a folder (and the next transfer from starting) until it ended.
Each command runs on its own SSH channel; nothing needs the lock.

Driven end to end against a loopback SSH server that runs the commands
through /bin/sh (tests/ssh_shell_testkit.py). A FIFO stands for a file
whose transfer takes a long time: its read blocks until it is written.
"""

from __future__ import annotations

import os
import shutil
import threading

import pytest

from core.scp_client import SCPSession
from tests.ssh_shell_testkit import SshShellServer, connect, profile

pytestmark = pytest.mark.skipif(
    not (shutil.which("base64") and hasattr(os, "mkfifo")), reason="needs sh, base64, mkfifo"
)


@pytest.fixture
def scp(tmp_path):
    root = tmp_path / "srv"
    root.mkdir()
    srv = SshShellServer(str(root))
    s = connect(SCPSession(profile(srv, "scp")), known_hosts=tmp_path / "known_hosts")
    yield s, root
    s.disconnect()
    srv.close()


def _background(fn):
    out: dict = {}

    def run():
        try:
            out["value"] = fn()
        except BaseException as exc:  # noqa: BLE001 - reported by the test
            out["error"] = exc

    t = threading.Thread(target=run, daemon=True)
    t.start()
    return t, out


def test_happy_listing_answers_while_a_download_runs(scp):
    s, root = scp
    (root / "a.txt").write_text("a")
    fifo = root / "slow"
    os.mkfifo(fifo)
    reader, got = _background(lambda: s.open_read(str(fifo)).read())
    try:
        lister, listed = _background(lambda: [i.name for i in s.list_dir(str(root))])
        lister.join(10)
        assert not lister.is_alive(), "the listing waited for the download"
        assert "a.txt" in listed["value"]
        assert reader.is_alive()  # the download still runs
    finally:
        with open(fifo, "wb") as fh:
            fh.write(b"done")
        reader.join(10)
    assert got["value"] == b"done"


def test_sad_stat_answers_while_an_upload_waits_for_its_target(scp):
    s, root = scp
    (root / "b.txt").write_text("b")
    fifo = root / "sink"
    os.mkfifo(fifo)

    def upload():
        with s.open_write(str(fifo)) as fh:
            fh.write(b"payload")

    writer, result = _background(upload)
    try:
        statter, st = _background(lambda: s.stat(str(root / "b.txt")))
        statter.join(10)
        assert not statter.is_alive(), "stat waited for the upload"
        assert st["value"].size == 1
    finally:
        with open(fifo, "rb") as fh:
            assert fh.read() == b"payload"
        writer.join(10)
    assert "error" not in result


def test_edge_parallel_reads_each_get_their_own_bytes(scp):
    s, root = scp
    for n in range(6):
        (root / f"f{n}").write_bytes(bytes([n]) * (100_000 + n))
    threads = [_background(lambda n=n: s.open_read(str(root / f"f{n}")).read()) for n in range(6)]
    for n, (t, out) in enumerate(threads):
        t.join(30)
        assert out["value"] == bytes([n]) * (100_000 + n)
