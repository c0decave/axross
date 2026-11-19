"""Device commands that run long without output are waited for.

Review 2026-11-18 (finding 4): adb_shell's ``read_timeout_s`` (10 s by
default) also caps the transport time-out, and AdbSession never passed
it, so every shell command silent for 10 s failed - a checksum of a big
video, a copy of a big file on the device, ``rm -rf`` of a big folder,
``pm install`` - while the device went on and finished it. The 30 s
DEFAULT_TRANSPORT_TIMEOUT never applied.

Now ordinary commands (ls, stat, mkdir) wait the transport time-out and
the ones that may run long wait the long-command time-out.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

adb = pytest.importorskip("core.adb_client")
if not adb.ADB_SHELL_AVAILABLE:  # pragma: no cover - optional dependency
    pytest.skip("adb-shell not installed", allow_module_level=True)

from tests.fake_adbd import FakeAdbd, make_device_tree  # noqa: E402

SLOW = 1.5  # seconds the device needs; the transport time-out below is 0.5 s


@pytest.fixture()
def phone(tmp_path):
    key = tmp_path / "android" / "adbkey"
    adb.ensure_adb_key(str(key))
    root = str(tmp_path / "device")
    make_device_tree(root)

    def hook(cmd):
        if cmd.startswith(("sha256sum", "if test -d", "if LC_ALL=C ls -d", "pm install",
                           "sh -c")) or "SLOWLIST" in cmd:
            time.sleep(SLOW)
        if cmd.startswith("pm install"):
            return b"Success\n"
        return None

    device = FakeAdbd(root, auth="key", authorized=[Path(str(key) + ".pub").read_text()],
                      shell_hook=hook)
    session = adb.AdbSession("127.0.0.1", device.port, adb_key_path=str(key),
                             transport_timeout=0.5)
    yield device, session
    session.close()
    device.stop()


def test_happy_a_slow_checksum_copy_rename_and_delete_finish(phone):
    device, s = phone
    assert s.checksum("/sdcard/Download/hello.txt").startswith("sha256:")
    s.copy("/sdcard/Download/hello.txt", "/sdcard/Download/copy.txt")
    s.rename("/sdcard/Download/copy.txt", "/sdcard/Download/moved.txt")
    s.remove("/sdcard/Download/moved.txt")
    assert [i.name for i in s.list_dir("/sdcard/Download")] == ["hello.txt"]
    assert s.connected


def test_happy_a_slow_pm_install_reports_its_answer(phone, tmp_path):
    _device, s = phone
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04 not really an apk")
    assert s.install_apk(str(apk)).strip() == "Success"


def test_happy_exec_waits_for_its_own_time_out(phone):
    _device, s = phone
    assert s.exec("echo done", timeout=10).stdout.strip() == b"done"


def test_sad_an_ordinary_command_still_times_out(phone):
    _device, s = phone
    started = time.monotonic()
    with pytest.raises(TimeoutError):
        s.list_dir("/sdcard/SLOWLIST")
    assert time.monotonic() - started < SLOW + 0.5


def test_edge_the_long_command_time_out_is_generous_by_default():
    assert adb.DEFAULT_LONG_COMMAND_TIMEOUT >= 600
    assert adb.DEFAULT_TRANSPORT_TIMEOUT >= 30
