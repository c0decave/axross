"""TFTP against tftpy's own server: what a failed request says, progress
and Cancel of a transfer, the listing of a configured file list, the size
probe's limit and the IP version.

* A missing file was reported as "/tmp/.axross-spool-tftp-... was not
  found": tftpy deletes the output FILE it was given by name when the
  server answers "File not found", and the spool's own clean-up then
  failed on it. tftpy now writes into the open spool (a file object).
* A server that does not answer read as tftpy's "Timed-out waiting for
  traffic"; it is a TimeoutError now ("did not answer in time").
* A download or upload had no progress and no Cancel (up to 16 MiB in
  512-byte steps); both report through core.transfer_hooks now, and a
  repeated block (a resend) is counted once - also for the size cap.
* The listing showed a configured file the server does not have as an
  empty file; it is left out now.
* The size probe of a server without ``tsize`` downloaded the whole file,
  past the size cap: it stops at the cap (size unknown, 0).
* TFTP here is IPv4 only (tftpy): an "IPv6 only" profile is refused
  with a reason instead of connecting over IPv4.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

tftpy = pytest.importorskip("tftpy")

from core import tftp_client as TC  # noqa: E402
from core import transfer_hooks as TH  # noqa: E402
from core.user_errors import describe  # noqa: E402


@pytest.fixture
def server(tmp_path):
    root = tmp_path / "srv"
    root.mkdir()
    (root / "small.txt").write_bytes(b"hello")
    (root / "big.bin").write_bytes(os.urandom(300_000))
    srv = tftpy.TftpServer(str(root))
    thread = threading.Thread(target=srv.listen, args=("127.0.0.1", 0, 1), daemon=True)
    thread.start()
    deadline = time.monotonic() + 5
    while srv.sock is None and time.monotonic() < deadline:
        time.sleep(0.01)
    yield root, srv.sock.getsockname()[1]
    srv.stop(now=True)
    thread.join(5)


def _session(port, **kw):
    return TC.TftpSession("127.0.0.1", port, timeout=1.0, retries=1, **kw)


def test_missing_file_is_named_not_the_spool(server):
    _root, port = server
    sess = _session(port)
    for call in (lambda: sess.open_read("/nope.txt"), lambda: sess.stat("/nope.txt")):
        with pytest.raises(FileNotFoundError) as info:
            call()
        assert "spool" not in str(info.value)
        assert "nope.txt" in describe(info.value)
    assert sess.exists("/nope.txt") is False


def test_no_server_is_a_timeout(tmp_path):
    import socket

    quiet = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    quiet.bind(("127.0.0.1", 0))
    try:
        sess = TC.TftpSession("127.0.0.1", quiet.getsockname()[1], timeout=0.3, retries=1)
        with pytest.raises(TimeoutError) as info:
            sess.open_read("/x")
        assert describe(info.value, "127.0.0.1").startswith("127.0.0.1 did not answer in time")
        with pytest.raises(TimeoutError):
            with sess.open_write("/x") as fh:
                fh.write(b"a")
    finally:
        quiet.close()


def test_download_reports_progress_and_cancels(server):
    root, port = server
    sess = _session(port)
    seen = []
    hooks = TH.TransferHooks(threading.Event(), lambda kind, done, total: seen.append((kind, done)))
    with TH.active(hooks):
        data = sess.open_read("/big.bin").read()
    assert data == (root / "big.bin").read_bytes()
    assert seen and seen[-1] == ("download", 300_000)

    cancel = threading.Event()

    def progress(kind, done, total):
        if done >= 50_000:
            cancel.set()

    with TH.active(TH.TransferHooks(cancel, progress)):
        with pytest.raises(InterruptedError):
            sess.open_read("/big.bin")


def test_upload_reports_progress_and_cancels(server):
    root, port = server
    sess = _session(port)
    seen = []
    hooks = TH.TransferHooks(threading.Event(), lambda kind, done, total: seen.append((kind, done)))
    payload = os.urandom(200_000)
    with TH.active(hooks):
        writer = sess.open_write("/up.bin")
    writer.write(payload)
    with TH.active(hooks):
        writer.close()
    # tftpy's server closes the file after its last ACK went out.
    deadline = time.monotonic() + 5
    while (root / "up.bin").read_bytes() != payload and time.monotonic() < deadline:
        time.sleep(0.05)
    assert (root / "up.bin").read_bytes() == payload
    assert ("upload", 200_000) in seen

    cancel = threading.Event()

    def progress(kind, done, total):
        if done >= 50_000:
            cancel.set()

    hooks = TH.TransferHooks(cancel, progress)
    with TH.active(hooks):
        writer = sess.open_write("/up2.bin")
    writer.write(payload)
    with TH.active(hooks), pytest.raises(InterruptedError):
        writer.close()


def test_listing_leaves_out_files_the_server_does_not_have(server):
    _root, port = server
    sess = _session(port, filelist=["small.txt", "gone.txt"], filelist_enabled=True)
    assert [(i.name, i.size) for i in sess.list_dir("/")] == [("small.txt", 5)]


def test_size_probe_without_tsize_stops_at_the_cap(server, monkeypatch):
    _root, port = server
    sess = _session(port, max_size_bytes=10_000)
    # tftpy's server answers tsize; a request without the option is what a
    # server that ignores options sees.
    monkeypatch.setattr(TC, "_TSIZE_OPTIONS", {})
    received = []
    real_download = tftpy.TftpClient.download

    def spy(self, filename, output, packethook=None, **kw):
        def hook(pkt):
            if isinstance(pkt, tftpy.TftpPacketTypes.TftpPacketDAT):
                received.append(len(pkt.data))
            if packethook is not None:
                packethook(pkt)

        return real_download(self, filename, output, packethook=hook, **kw)

    monkeypatch.setattr(tftpy.TftpClient, "download", spy)
    assert sess.stat("/big.bin").size == 0  # unknown: larger than the cap
    assert 0 < sum(received) <= 10_000 + 512
    received.clear()
    assert sess.stat("/small.txt").size == 5


def test_ipv6_only_is_refused():
    with pytest.raises(OSError, match="IPv4"):
        TC.TftpSession("127.0.0.1", 69, address_family="ipv6")
    TC.TftpSession("127.0.0.1", 69, address_family="ipv4")
