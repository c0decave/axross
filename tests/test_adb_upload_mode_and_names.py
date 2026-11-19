"""Uploads get an ordinary mode and their source's time; any name works.

Review 2026-11-18:

* finding 12 - every upload had mode 0770 (adb_shell's default push mode,
  rwxrwx---: executable, group-writable; an overwritten file lost its
  mode) and the time of the upload, not the source's;
* finding 13 - a name that is not UTF-8 (``caf\\xe9.txt``) was listed as
  ``caf\\\\xe9.txt`` (adb_shell decoded with backslashreplace), and
  reading or deleting it then said "not found".
"""

from __future__ import annotations

import os
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

adb = pytest.importorskip("core.adb_client")
if not adb.ADB_SHELL_AVAILABLE:  # pragma: no cover - optional dependency
    pytest.skip("adb-shell not installed", allow_module_level=True)

from tests.fake_adbd import FakeAdbd, make_device_tree  # noqa: E402


@pytest.fixture()
def phone(tmp_path):
    key = tmp_path / "adbkey"
    root = str(tmp_path / "device")
    make_device_tree(root)
    device = FakeAdbd(root)
    session = adb.AdbSession("127.0.0.1", device.port, adb_key_path=str(key))
    yield device, session
    session.close()
    device.stop()


def test_happy_an_upload_is_rw_r__r__(phone):
    device, s = phone
    with s.open_write("/data/local/tmp/tool.txt") as fh:
        fh.write(b"x")
    modes = [op[2] for op in device.sync_ops if op[0] == "SEND"]
    assert modes == [stat.S_IFREG | 0o644]
    local = device.local("/data/local/tmp/tool.txt")
    assert os.stat(local).st_mode & 0o777 == 0o644


def test_happy_the_source_time_can_be_set(phone):
    device, s = phone
    with s.open_write("/sdcard/Download/old.txt") as fh:
        fh.write(b"x")
    when = datetime(2024, 1, 2, 15, 30, 45, tzinfo=timezone.utc).timestamp()
    s.set_modified("/sdcard/Download/old.txt", when)
    assert os.stat(device.local("/sdcard/Download/old.txt")).st_mtime == when
    with pytest.raises(OSError):
        s.set_modified("/sdcard/Download/missing.txt", when)


def test_sad_a_name_that_is_not_utf8_is_listed_read_and_removed(phone):
    device, s = phone
    local = os.path.join(os.fsencode(device.local("/sdcard/Download")), b"caf\xe9.txt")
    with open(local, "wb") as fh:
        fh.write(b"latin-1 name")
    names = [i.name for i in s.list_dir("/sdcard/Download")]
    name = os.fsdecode(b"caf\xe9.txt")  # as the local file system names it
    assert name in names
    path = "/sdcard/Download/" + name
    assert s.stat(path).size == len(b"latin-1 name")
    with s.open_read(path) as fh:
        assert fh.read() == b"latin-1 name"
    s.remove(path)
    assert not os.path.exists(local)
