"""ADB lists Android 5 (toolbox ``ls``) folders, device nodes included,
and never reads an answer it cannot parse as an empty folder.

The ``ls -la`` parser knew only toybox's columns (Android 6 and newer).
Toolbox has no link-count column and prints no size for a folder or a
link, so no line matched; list_dir dropped every one and, with no
``ls:`` error line among them, returned ``[]`` - every folder on an
Android 5 device looked empty, and a copy of it copied nothing. A device
node ("major, minor" in place of the size) did not match on any Android
and vanished from /dev. Now both layouts parse, a device node, FIFO or
socket is listed (and refused by open_read: a pull of /dev/zero never
ends), and an answer with lines but none understood is an OSError.
"""

from __future__ import annotations

import errno
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.adb_client import AdbSession  # noqa: E402

TOOLBOX = (
    "drwxrwx--x root     sdcard_r          2014-03-28 10:40 Alarms\n"
    "-rw-rw---- root     sdcard_r   123456 2014-03-28 10:41 photo.jpg\n"
    "-rw-rw---- 10055    10055         321 2014-03-28 10:42 by uid.txt\n"
    "lrwxrwxrwx root     root              2014-03-28 10:40 sdcard -> /storage/emulated/legacy\n"
)
TOYBOX = (
    "total 16\n"
    "drwxrwx--x 2 root sdcard_rw 4096 2024-03-28 10:40 .\n"
    "drwxrwx--x 2 root sdcard_rw 4096 2024-03-28 10:40 ..\n"
    "drwxrwx--x 2 root sdcard_rw 4096 2024-03-28 10:40 Alarms\n"
    "-rw-rw---- 1 root sdcard_rw 123456 2024-03-28 10:41 photo.jpg\n"
)
DEV_TOOLBOX = "crw-rw---- system   audio     14,   3 2014-03-28 10:40 dsp\n"
DEV_TOYBOX = (
    "crw-rw-rw- 1 root root 10, 229 2024-03-28 10:40 fuse\n"
    "brw------- 1 root root 179,   0 2024-03-28 10:40 mmcblk0\n"
    "-rw-r--r-- 1 root root 0 2024-03-28 10:40 plain\n"
)


def _session(out: str) -> AdbSession:
    s = AdbSession.__new__(AdbSession)
    s._shell = lambda cmd: out
    return s


def test_sad_toolbox_folders_list_their_entries():
    items = {i.name: i for i in _session(TOOLBOX).list_dir("/sdcard")}
    assert sorted(items) == ["Alarms", "by uid.txt", "photo.jpg", "sdcard"]
    assert items["Alarms"].is_dir and items["Alarms"].size == 0
    assert items["photo.jpg"].size == 123456
    assert items["by uid.txt"].size == 321
    assert items["sdcard"].is_link
    assert items["sdcard"].link_target == "/storage/emulated/legacy"


def test_sad_toolbox_stat_reads_the_line():
    s = _session("-rw-rw---- root     sdcard_r   123456 2014-03-28 10:41 /sdcard/photo.jpg\n")
    item = s.stat("/sdcard/photo.jpg")
    assert (item.name, item.size) == ("photo.jpg", 123456)


def test_happy_toybox_folders_list_as_before():
    items = {i.name: i for i in _session(TOYBOX).list_dir("/sdcard")}
    assert sorted(items) == ["Alarms", "photo.jpg"]
    assert items["Alarms"].is_dir and items["photo.jpg"].size == 123456


@pytest.mark.parametrize("out, names", [
    (DEV_TOOLBOX, ["dsp"]),
    (DEV_TOYBOX, ["fuse", "mmcblk0", "plain"]),
], ids=["toolbox", "toybox"])
def test_sad_device_nodes_are_listed_not_dropped(out, names):
    items = _session(out).list_dir("/dev")
    assert sorted(i.name for i in items) == names
    assert all(not i.is_dir and i.size == 0 for i in items)


def test_edge_a_listed_device_node_is_not_pulled():
    s = _session(DEV_TOYBOX)
    pulled = []
    s._device = type("D", (), {"pull": lambda self, a, b: pulled.append(a)})()
    s._conn_lock = __import__("threading").Lock()
    s._label = "dev"
    s.list_dir("/dev")
    with pytest.raises(OSError) as info:
        s.open_read("/dev/fuse")
    assert info.value.errno == errno.EINVAL
    assert pulled == []
    s.open_read("/dev/plain").close()
    assert pulled == ["/dev/plain"]


def test_sad_lines_none_of_which_parse_are_an_error():
    with pytest.raises(OSError, match="unreadable answer"):
        _session("Alarms  photo.jpg\nsomething else\n").list_dir("/sdcard")


def test_edge_an_empty_folder_is_empty():
    assert _session("").list_dir("/sdcard/empty") == []
    assert _session("total 0\n").list_dir("/sdcard/empty") == []
