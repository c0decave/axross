"""ADB transfers: progress, Cancel, and browsing that does not wait.

Review 2026-11-18 (finding 8): one lock held each pull and push for its
whole length, so a listing in another pane waited for a running download
(7.8 s behind a 16 MiB one); open_read returned only after the whole
pull, open_write pushed everything in close(), neither reported progress
nor heard Cancel (core.transfer_hooks).

Now a transfer runs on a connection of its own (a second one, made without
asking the phone; where that would need the phone's approval, or over
USB, the command connection) and reports and checks Cancel per chunk.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

adb = pytest.importorskip("core.adb_client")
if not adb.ADB_SHELL_AVAILABLE:  # pragma: no cover - optional dependency
    pytest.skip("adb-shell not installed", allow_module_level=True)

from core import transfer_hooks  # noqa: E402
from tests.fake_adbd import FakeAdbd, make_device_tree  # noqa: E402

SIZE = 4 * 1024 * 1024  # 64 chunks of 64 KiB


@pytest.fixture()
def phone(tmp_path):
    key = tmp_path / "android" / "adbkey"
    adb.ensure_adb_key(str(key))
    root = str(tmp_path / "device")
    make_device_tree(root)
    big = Path(root, "storage/emulated/0/Download/video.mp4")
    big.write_bytes(os.urandom(SIZE))
    device = FakeAdbd(root, auth="key", authorized=[Path(str(key) + ".pub").read_text()],
                      maxdata=256 * 1024, recv_delay=0.03)  # ~2 s for the file
    session = adb.AdbSession("127.0.0.1", device.port, adb_key_path=str(key))
    yield device, session, big
    session.close()
    device.stop()


def test_happy_a_listing_does_not_wait_for_a_running_download(phone):
    _device, s, big = phone
    got: dict = {}

    def pull():
        started = time.monotonic()
        with s.open_read("/sdcard/Download/video.mp4") as fh:
            got["data"] = fh.read()
        got["took"] = time.monotonic() - started

    th = threading.Thread(target=pull)
    th.start()
    time.sleep(0.3)
    started = time.monotonic()
    assert [i.name for i in s.list_dir("/sdcard/DCIM")] == ["Camera"]
    listing_took = time.monotonic() - started
    th.join(30)
    assert got["data"] == big.read_bytes()
    assert listing_took < 0.5 < got["took"]


def test_happy_a_download_reports_progress(phone):
    _device, s, big = phone
    seen: list[tuple[str, int, int | None]] = []
    hooks = transfer_hooks.TransferHooks(threading.Event(), lambda *a: seen.append(a))
    with transfer_hooks.active(hooks):
        with s.open_read("/sdcard/Download/video.mp4") as fh:
            assert fh.read() == big.read_bytes()
    assert len(seen) > 10
    assert all(kind == "download" for kind, _done, _total in seen)
    assert [done for _k, done, _t in seen] == sorted(done for _k, done, _t in seen)
    assert seen[-1][1:] == (SIZE, SIZE)


def test_sad_cancel_stops_a_download_and_the_session_goes_on(phone):
    _device, s, _big = phone
    cancel = threading.Event()

    def progress(_kind, done, _total):
        if done > SIZE // 4:
            cancel.set()

    hooks = transfer_hooks.TransferHooks(cancel, progress)
    started = time.monotonic()
    with transfer_hooks.active(hooks):
        with pytest.raises(InterruptedError):
            s.open_read("/sdcard/Download/video.mp4")
    assert time.monotonic() - started < 1.9  # not the whole file
    assert s.connected
    with s.open_read("/sdcard/Download/hello.txt") as fh:
        assert fh.read() == b"hello android\n"


def test_happy_an_upload_reports_progress_and_hears_cancel(phone, tmp_path):
    device, s, _big = phone
    payload = os.urandom(SIZE)
    seen: list[tuple[str, int, int | None]] = []
    hooks = transfer_hooks.TransferHooks(threading.Event(), lambda *a: seen.append(a))
    with transfer_hooks.active(hooks):
        writer = s.open_write("/sdcard/Download/up.bin")
    assert hooks.upload_expected
    writer.write(payload)
    writer.close()
    assert Path(device.local("/sdcard/Download/up.bin")).read_bytes() == payload
    assert seen and seen[-1][0] == "upload" and seen[-1][1] == SIZE
    cancel = threading.Event()
    cancel.set()
    hooks = transfer_hooks.TransferHooks(cancel)
    with transfer_hooks.active(hooks):
        writer = s.open_write("/sdcard/Download/never.bin")
    writer.write(payload)
    with pytest.raises(InterruptedError):
        writer.close()
    assert s.list_dir("/sdcard/Download")


def test_edge_without_always_allow_transfers_share_the_one_connection(tmp_path):
    key = tmp_path / "adbkey"
    root = str(tmp_path / "device")
    make_device_tree(root)
    device = FakeAdbd(root, auth="key", remember=False)  # "Always allow" not ticked
    try:
        s = adb.AdbSession("127.0.0.1", device.port, adb_key_path=str(key))
        with s.open_read("/sdcard/Download/hello.txt") as fh:
            assert fh.read() == b"hello android\n"
        with s.open_write("/sdcard/Download/x.txt") as fh:
            fh.write(b"x")
        assert device.prompts == 1  # the phone was not asked a second time
        s.close()
    finally:
        device.stop()
