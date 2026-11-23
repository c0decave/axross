"""The ADB pane's ``ls -l`` parser (core.adb_client) against what Android's
``ls`` really prints.

On a real phone, listing ``/`` showed "Skipping
unsafe item name: oem\\nd?????????   ? ?      ?             ?
? postinstall - name contains control chars: U+000A". toybox prints an
entry it cannot stat (EACCES) with every field but the type and the name
as "?"; the parser did not know that line, took it for the second line of
the name before it and joined the two - so ``oem`` and ``postinstall``
were both lost, and the safety filter refused the joined name.

Now:

* the "?" form is an entry: its name and type, unknown size, time and
  mode, and ``stat_error`` set (as LocalFS lists an entry lstat refuses);
* the listing runs ``ls -la -b`` where ls takes -b (toybox, GNU, busybox):
  a line feed, a blank or any other odd byte of a name comes escaped, one
  physical line is one entry, and the name is decoded; the toolbox ls of
  Android 5 and older refuses -b and is listed without - there an entry
  whose name went on over a line break is left out, never joined with the
  next line nor listed under its first line (another file's name);
* total lines, links (targets with blanks), device numbers, both date
  forms, names with blanks, leading blanks, Unicode, line breaks and
  bytes that are no UTF-8, ``ls -Z`` contexts and ``ls:`` messages.

The fixtures are lines as the phones print them (toybox of Android 10 and
14, toolbox of Android 4.4 and 6, ``/proc``). A fuzz test builds listings
of random names and noise and checks that no line ever ends up in another
entry's name.

The MCP adb tools (core.adb_device) and the Android Device window list no
folders: the MCP file tools on an ADB backend and the pane go through
AdbSession.list_dir / stat, this parser.
"""

from __future__ import annotations

import random
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

adb = pytest.importorskip("core.adb_client")
from core.adb_client import AdbSession  # noqa: E402

#: ``ls -la -b /`` of a Pixel on Android 14 (toybox), as the shell user.
TOYBOX_ROOT = """total 72
drwxr-xr-x  24 root   root       4096 2009-01-01 08:00 .
drwxr-xr-x  24 root   root       4096 2009-01-01 08:00 ..
dr-xr-xr-x  52 root   root          0 2024-05-02 09:13 acct
drwxr-xr-x  44 root   root        960 2024-05-02 09:13 apex
lrw-r--r--   1 root   root         11 2009-01-01 08:00 bin -> /system/bin
lrw-r--r--   1 root   root         50 2009-01-01 08:00 bugreports -> /data/user_de/0/com.android.shell/files/bugreports
l?????????   ? ?      ?             ?                ? cache
d?????????   ? ?      ?             ?                ? config
lrw-r--r--   1 root   root         17 2009-01-01 08:00 d -> /sys/kernel/debug
drwxrwx--x  49 system system     4096 2024-05-02 09:13 data
d?????????   ? ?      ?             ?                ? data_mirror
drwxr-xr-x  20 root   root       4440 2024-05-02 09:13 dev
lrw-r--r--   1 root   root         11 2009-01-01 08:00 etc -> /system/etc
??????????   ? ?      ?             ?                ? init
drwxr-xr-x  10 root   root        200 2024-05-02 09:13 mnt
drwxr-xr-x  13 root   root       4096 2009-01-01 08:00 oem
d?????????   ? ?      ?             ?                ? postinstall
dr-xr-xr-x 693 root   root          0 2024-05-02 09:13 proc
lrw-r--r--   1 root   root         21 2009-01-01 08:00 sdcard -> /storage/self/primary
drwxr-xr-x   4 root   root         80 2024-05-02 09:13 storage
dr-xr-xr-x  14 root   root          0 2024-05-02 09:13 sys
drwxr-xr-x  13 root   root       4096 2009-01-01 08:00 system
"""

#: ``ls -la /`` of a Nexus on Android 6 (toolbox: no link count, no size
#: for folders and links; an entry it cannot read is an "ls:" line).
TOOLBOX_ROOT = """drwxr-xr-x root     root              2016-03-01 10:00 acct
drwxrwx--- system   cache             2016-03-01 10:00 cache
lrwxrwxrwx root     root              1970-01-01 00:00 charger -> /sbin/healthd
dr-x------ root     root              2016-03-01 10:00 config
lrwxrwxrwx root     root              2016-03-01 10:00 d -> /sys/kernel/debug
drwxrwx--x system   system            2016-03-01 10:00 data
-rw-r--r-- root     root          607 1970-01-01 00:00 default.prop
ls: /verity_key: Permission denied
drwxr-xr-x root     root              2016-03-01 10:00 dev
crw-rw-rw- root     root       1,   3 2016-03-01 10:00 null
-rwxr-x--- root     root      1180940 1970-01-01 00:00 init
lrwxrwxrwx root     root              2016-03-01 10:00 sdcard -> /storage/self/primary
"""

#: ``ls -la -b /proc/self/`` (toybox, Android 10): size 0 everywhere, links
#: the shell may not read show no target.
TOYBOX_PROC = """total 0
dr-xr-xr-x   9 shell shell 0 2024-05-02 10:01 .
dr-xr-xr-x 693 root  root  0 2024-05-02 09:13 ..
-r--r--r--   1 shell shell 0 2024-05-02 10:01 cmdline
lrwxrwxrwx   1 shell shell 0 2024-05-02 10:01 cwd -> /
lrwxrwxrwx   1 shell shell 0 2024-05-02 10:01 exe -> /system/bin/toybox
dr-x------   2 shell shell 0 2024-05-02 10:01 fd
l?????????   ? ?     ?     ?                ? root
-r--r--r--   1 shell shell 0 2024-05-02 10:01 status
"""

#: ``ls -la -b /sdcard/Download`` (toybox, Android 14): names escaped.
TOYBOX_ESCAPED = r"""total 40
-rw-rw----  1 u0_a234 media_rw    12 2024-05-02 10:11 two\ words.txt
-rw-rw----  1 u0_a234 media_rw    13 2024-05-02 10:11 \ \ leading.txt
-rw-rw----  1 u0_a234 media_rw    14 2024-05-02 10:11 line\nbreak.txt
-rw-rw----  1 u0_a234 media_rw    15 2024-05-02 10:11 caf\303\251.txt
-rw-rw----  1 u0_a234 media_rw    16 2024-05-02 10:11 raw\351.bin
-rw-rw----  1 u0_a234 media_rw    17 2024-05-02 10:11 back\\slash
-rw-rw----  1 u0_a234 media_rw    18 2024-05-02 10:11 tab\tand\033esc
-rw-rw----  1 u0_a234 media_rw    19 2024-05-02 10:11 d?????????\ ?\ x
lrwxrwxrwx  1 u0_a234 media_rw    16 2024-05-02 10:11 my\ link -> /sdcard/a\ \->\ b
"""

#: A busybox ls (a Magisk module's) with month dates, and toybox ``ls -laZ``.
BUSYBOX = """-rw-r--r--    1 root     root          1234 Jan  2 03:04 recent.txt
drwxr-xr-x    2 root     root          4096 Mar 16  2023 old
"""
TOYBOX_Z = ("drwxr-xr-x  2 root root u:object_r:system_file:s0 4096 2024-05-02 09:13 bin\n"
            "-rw-------  1 system system u:object_r:system_data_file:s0:c512,c768 7 "
            "2024-05-02 09:13 secret\n")


class Shell:
    """A device whose ls answers *out*; *takes_b* False: the toolbox ls
    that refuses -b. Records the commands."""

    def __init__(self, out: str, takes_b: bool = True):
        self.out = out
        self.takes_b = takes_b
        self.commands: list[str] = []

    def __call__(self, cmd: str) -> str:
        self.commands.append(cmd)
        if " -b" in cmd and not self.takes_b:
            return "ls: Unknown option '-b'. Aborting.\n"
        return self.out


def _session(out: str, takes_b: bool = True) -> AdbSession:
    s = AdbSession.__new__(AdbSession)
    s._shell = Shell(out, takes_b)
    return s


def _listed(out: str, takes_b: bool = True) -> dict:
    return {i.name: i for i in _session(out, takes_b).list_dir("/")}


def test_happy_a_phones_root_lists_the_entries_it_cannot_stat():
    items = _listed(TOYBOX_ROOT)
    assert {"oem", "postinstall", "config", "data_mirror", "cache", "init"} <= set(items)
    assert not any("\n" in name for name in items)
    oem, post = items["oem"], items["postinstall"]
    assert oem.is_dir and oem.size == 4096 and oem.stat_error == ""
    assert post.is_dir and post.stat_error == adb.NOT_STATTABLE and post.size == 0
    assert items["cache"].is_link and items["cache"].stat_error
    assert not items["init"].is_dir and items["init"].stat_error
    assert items["bin"].link_target == "/system/bin"
    assert items["bugreports"].link_target.endswith("/bugreports")
    assert len(items) == 20  # every line but total, "." and ".."


def test_happy_the_listing_asks_ls_for_escaped_names():
    s = _session(TOYBOX_ROOT)
    s.list_dir("/sdcard")
    assert s._shell.commands == ["TZ=UTC0 ls -la -b /sdcard/"]
    s.stat("/sdcard/a b")
    assert s._shell.commands[-1] == "TZ=UTC0 ls -la -b -d '/sdcard/a b'"


def test_happy_escaped_names_are_decoded():
    items = _listed(TOYBOX_ESCAPED)
    assert set(items) == {"two words.txt", "  leading.txt", "line\nbreak.txt", "café.txt",
                          "raw\udce9.bin", "back\\slash", "tab\tand\x1besc", "d????????? ? x",
                          "my link"}
    assert items["two words.txt"].size == 12 and items["  leading.txt"].size == 13
    assert items["my link"].link_target == "/sdcard/a -> b"
    assert items["d????????? ? x"].stat_error == ""  # a file named like that, not a "?" line


def test_sad_toolbox_without_b_lists_without_and_reports_its_ls_errors():
    s = _session(TOOLBOX_ROOT, takes_b=False)
    items = {i.name: i for i in s.list_dir("/")}
    assert s._shell.commands == ["TZ=UTC0 ls -la -b /", "TZ=UTC0 ls -la /"]
    assert "verity_key" not in items and "ls: /verity_key: Permission denied" not in items
    assert items["null"].size == 0 and items["default.prop"].size == 607
    assert items["charger"].link_target == "/sbin/healthd"
    assert items["init"].size == 1180940 and items["acct"].is_dir
    assert len(items) == 11
    s.list_dir("/dev")  # asked once per session
    assert s._shell.commands[-1] == "TZ=UTC0 ls -la /dev/"


def test_sad_without_b_a_name_with_a_line_break_is_left_out_never_joined():
    out = ("-rw-r--r-- root root 1 2016-03-01 10:00 before\n"
           "-rw-r--r-- root root 2 2016-03-01 10:00 two\n"
           "lines\n"
           "-rw-r--r-- root root 3 2016-03-01 10:00 after\n")
    items = _listed(out, takes_b=False)
    assert set(items) == {"before", "after"}  # "two" would name another file


def test_happy_proc_entries():
    items = _listed(TOYBOX_PROC)
    assert items["exe"].link_target == "/system/bin/toybox" and items["cwd"].link_target == "/"
    assert items["fd"].is_dir and items["root"].is_link and items["root"].stat_error
    assert items["cmdline"].size == 0 and items["cmdline"].stat_error == ""


def test_happy_month_dates_and_selinux_contexts():
    items = _listed(BUSYBOX)
    assert items["recent.txt"].size == 1234 and items["recent.txt"].modified.month == 1
    assert items["old"].is_dir and items["old"].modified.year == 2023
    items = _listed(TOYBOX_Z)
    assert items["bin"].is_dir and items["bin"].size == 4096
    assert items["secret"].size == 7
    assert items["secret"].modified == datetime(2024, 5, 2, 9, 13, tzinfo=timezone.utc).astimezone(
    ).replace(tzinfo=None)


def test_sad_a_folder_ls_refuses_is_an_error_not_an_empty_listing():
    s = _session("ls: /data/: Permission denied\n")
    with pytest.raises(PermissionError):
        s.list_dir("/data")


def test_happy_stat_of_an_entry_it_cannot_read():
    s = _session("d?????????   ? ?      ?             ?                ? /postinstall\n")
    item = s.stat("/postinstall")
    assert item.name == "postinstall" and item.is_dir and item.stat_error


# -- fuzz: no line ever merges into another entry's name ----------------------------------------

def _escape(name: str) -> str:
    """*name* as toybox ``ls -b`` prints it."""
    out = []
    for byte in name.encode("utf-8", "surrogateescape"):
        ch = chr(byte)
        if ch in " \\":
            out.append("\\" + ch)
        elif ch in "\n\t\r":
            out.append({"\n": "\\n", "\t": "\\t", "\r": "\\r"}[ch])
        elif byte < 32 or byte >= 127:
            out.append(f"\\{byte:03o}")
        else:
            out.append(ch)
    return "".join(out)


_ALPHABET = ["a", "b", " ", "\n", "?", "-", ">", "\\", "é", "\udce9", "\t", "1", ":", "d"]
_NOISE = ["total 12", "", "ls: /x: Permission denied", "garbage", "d????????? ? ? ? x",
          "Row: 0", "-> /target", "2024-01-01 00:00 name"]


def _random_listing(rng: random.Random, escaped: bool):
    lines, expected, dropped = [], set(), set()
    for n in range(rng.randint(0, 30)):
        name = "".join(rng.choice(_ALPHABET) for _ in range(rng.randint(1, 12))) + f"#{n}"
        if name in (".", ".."):
            continue
        kind = rng.choice(["-", "d", "c", "?form"])
        if kind == "?form":
            shown = _escape(name) if escaped else name
            line = f"d?????????   ? ?      ?             ?                ? {shown}"
        elif kind == "c":
            line = f"crw-rw-rw-  1 root root 10, 229 2024-03-28 10:40 {_escape(name) if escaped else name}"
        else:
            line = (f"{kind}rw-r--r--  1 root root {rng.randint(0, 9999)} 2024-03-28 10:40 "
                    f"{_escape(name) if escaped else name}")
        lines.append(line)
        if escaped or "\n" not in name:
            expected.add(name)
        else:
            dropped.add(name)
        if rng.random() < 0.2:
            lines.append(rng.choice(_NOISE))
    return "\n".join(lines) + "\n", expected, dropped


@pytest.mark.parametrize("escaped", [True, False])
def test_fuzz_no_line_merges_into_another_entrys_name(escaped):
    rng = random.Random(0x4C53 + escaped)
    for _ in range(400):
        out, expected, dropped = _random_listing(rng, escaped)
        s = _session(out, takes_b=escaped)
        try:
            names = {i.name for i in s.list_dir("/f")}
        except OSError:
            assert not expected  # only an answer without one entry may fail
            continue
        assert all("\n" not in n or escaped for n in names), out
        if escaped:
            assert names == expected, out
        else:
            # Without -b: a name with a line break is left out, and so is
            # an entry a stray line follows (it could be one); any other
            # name is listed exactly, never a piece of another one.
            assert names <= expected, out
            heads = {n.split("\n", 1)[0] for n in dropped} - expected
            assert not names & heads, out
