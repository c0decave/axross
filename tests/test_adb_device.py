"""The adb tool group (core.adb_device): the Android device tools build safe
command lines, read the device's answers as untrusted text and say what
Android refuses - checked against a scripted device shell; the MCP server
serves the group with its guards (backend named, --mcp-write, production
profiles, paranoid mode, audit without message texts) and its results
match their outputSchemas.

The review of the handoff (0.15.184) found, each with a test below:

* numbers read with str.isdigit / \\d: a device answer with a superscript
  or Arabic-Indic digit crashed get_device_info (int('\\u00b2')) or went
  into a --where clause;
* a property value with a line break could imitate a later property
  line of the getprop listing (ro.product.model of another value);
* an SMS sender whose address holds ', body=' shifted address into body;
  write_sms took any row of that date as the message just written;
* Android before 6.0 has no printf: a text with a line break became an
  empty SMS body; '#' in a number started the sms: URI's fragment;
* install_app removed its file in /data/local/tmp only after a pushed
  APK, not after a failed push; a file growing while it was sent went
  out past its checked size; a hard link to a file outside the root
  passed; the axross glue opened the APK by name outside the confined root;
* stop_app said stopped where pidof is missing (Android before 6);
* no call had a deadline: 50 SMS rows of 60 s each outlived the tool's
  time limit; send_at_command's su probes waited without timeout where
  the device has no timeout command;
* the control characters left U+034F, the variation selectors and the
  Unicode tag characters (invisible text an LLM reads); adb_server's
  clean_text left U+061C and U+2060-U+2065;
* any C0 control (ESC, ^U) went into a command argument; nothing bounded
  a command line's length.
"""

from __future__ import annotations

import base64
import io
import json
import os
import re
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core import adb_device as A  # noqa: E402

SH = "/bin/sh"


class Result:
    def __init__(self, returncode, stdout):
        self.returncode = returncode
        self.stdout = stdout.encode() if isinstance(stdout, str) else stdout
        self.truncated_stdout = False


class FakeShell:
    """A device shell answering by the first rule whose regex matches the
    command line; records every command, push and pull."""

    def __init__(self, rules, files=None):
        self.rules = [(re.compile(pattern), answer) for pattern, answer in rules]
        self.commands = []
        self.timeouts = []
        self.pushed = {}
        self.files = dict(files or {})
        self.push_error = None

    def exec(self, command, *, timeout, stdout_cap):
        assert "\n" not in command and "\r" not in command and "\x00" not in command
        assert timeout > 0 and stdout_cap > 0
        self.commands.append(command)
        self.timeouts.append(timeout)
        for regex, answer in self.rules:
            if regex.search(command):
                if callable(answer):
                    answer = answer(command)
                status, out = answer if isinstance(answer, tuple) else (0, answer)
                return Result(status, out)
        return Result(0, "")

    def push_stream(self, source, remote_path):
        data = source.read(3) + source.read()
        if self.push_error is not None:
            raise self.push_error
        self.pushed[remote_path] = data

    def pull_stream(self, remote_path, sink, max_bytes):
        data = self.files[remote_path]
        if len(data) > max_bytes:
            raise OSError("too big")
        sink.write(data)


def tools(*rules, **kw):
    shell = FakeShell(rules)
    return A.AndroidTools(shell, **kw), shell


def sh_words(line):
    """The words the device's sh makes of LINE (run by the local sh)."""
    out = subprocess.run([SH, "-c", 'for w in ' + line + '; do printf "%s\\0" "$w"; done'],
                         capture_output=True, check=True).stdout
    return out.split(b"\0")[:-1]


GETPROP = """[gsm.version.baseband]: [g5123b-130914-240205-B-11405587
second line]
[persist.sys.locale]: [de-DE]
[ro.build.fingerprint]: [google/oriole/oriole:14/UQ1A.240205.004/1:user/release-keys]
[ro.build.type]: [user]
[ro.build.version.release]: [14]
[ro.build.version.sdk]: [34]
[ro.build.version.security_patch]: [2024-02-05]
[ro.product.brand]: [google]
[ro.product.cpu.abilist]: [arm64-v8a]
[ro.product.device]: [oriole]
[ro.product.manufacturer]: [Google]
[ro.product.model]: [Pixel 6\u202e]
[ro.product.name]: [oriole]
[ro.serialno]: [1A2B3C4D]
"""
PROPS = {name: value for name, value in re.findall(r"^\[([^\]]+)\]: \[([^\]\n]*)\]$", GETPROP, re.M)}


def getprops(props=PROPS):
    """The answer of AndroidTools.getprops' command line for *props*."""
    def answer(command):
        out = []
        for name, tag in re.findall(r"getprop ([A-Za-z0-9_.:@\-]+); echo (AXPROP[0-9a-f]+)", command):
            out.append(props.get(name, "") + "\n" + tag + "\n")
        return "".join(out)
    return answer


def parcel(text: str, code: int = 0) -> str:
    """A ``service call`` answer carrying TEXT (UTF-16) after exception CODE."""
    raw = code.to_bytes(4, "little", signed=True) + len(text).to_bytes(4, "little", signed=True)
    raw += text.encode("utf-16-le") + b"\0\0"
    raw += b"\0" * (-len(raw) % 4)
    words = [int.from_bytes(raw[i:i + 4], "little") for i in range(0, len(raw), 4)]
    lines = []
    for i in range(0, len(words), 4):
        chunk = " ".join(f"{w:08x}" for w in words[i:i + 4])
        lines.append(f"  0x{i * 4:08x}: {chunk} '................'")
    return "Result: Parcel(\n" + "\n".join(lines) + ")\n"


IDENTITY = (r"^getprop ro\.product\.manufacturer; echo", getprops())


# -- quoting, cleaning, checking ---------------------------------------------------------------

@pytest.mark.parametrize("arg", ["plain", "a b", "it's", '"; rm -rf / #', "$(id)", "`id`", "a\\b", "*",
                                 "-n", "a && reboot", "a; reboot", "a | sh", "~root", "{a,b}", "$HOME",
                                 "\u00fcnic\u00f6de \u202e \u0661", "tab\there", "x" * 5000, "--", "!$"])
def test_shell_line_quotes_every_argument_as_one_word(arg):
    assert sh_words(A.shell_line("echo", arg)) == [b"echo", arg.encode()]


@pytest.mark.parametrize("arg", ["a\nb", "a\rb", "a\x00b", "a\x1b[2Jb", "a\x15b", "a\x7fb", "\x03"])
def test_shell_line_refuses_line_breaks_nul_and_other_controls(arg):
    with pytest.raises(ValueError):
        A.shell_line("echo", arg)


@pytest.mark.parametrize("text", ["one\ntwo", "back\\slash \\n literal\nx", "it's \"$(id)\" `x` ;|&\ny",
                                  "tab\there\n", "50%d %s\n\\c stop", "\\0101 octal\nz"])
def test_printf_arg_expands_to_the_text_with_its_line_feeds(text):
    word = A.printf_arg(text)
    assert "\n" not in word
    out = subprocess.run([SH, "-c", f"printf '%s' {word}"], capture_output=True, check=True).stdout
    assert out.decode() == text.rstrip("\n")


def test_printf_arg_quotes_a_one_line_text_without_printf():
    assert A.printf_arg("it's $(id)") == "'it'\"'\"'s $(id)'"
    assert "printf" not in A.printf_arg("one line\n")
    with pytest.raises(ValueError):
        A.printf_arg("bell\x07")


def test_clean_drops_control_bidi_and_invisible_characters_and_bounds():
    assert A.clean("a\x1b[31mb\u202ec\u2066d\x07") == "a[31mbcd"
    assert A.clean("x\ny\r\n", lines=True) == "x\ny\n"
    assert A.clean("x\ny") == "x y"
    assert A.clean("z" * 50, 10) == "z" * 10
    assert A.clean(b"\xff\xfe ok") == "\ufffd\ufffd ok"
    # U+061C, U+2060-U+2069, a variation selector, the tag characters, U+034F
    hidden = "\u061c\u2060\u2061\u2063\u2064\u2065\u2069\ufe0f\U000e0049\U000e0047\u034f\u00ad"
    assert A.clean(f"ok{hidden}!") == "ok!"


def test_adb_server_clean_text_drops_the_same_characters():
    from core import adb_server

    text = adb_server.clean_text("phone\u061cA\u2060B\u2064C\U000e0041D\ufe0fE")
    assert text == "phone A B C D E"


@pytest.mark.parametrize("bad", ["", "com.x;id", "com.x y", "../x", "com.x$(id)", "-p", "com..x", 7, None,
                                 "a" * 256, "com.\u0661x", "\u00e9t\u00e9"])
def test_a_package_name_is_checked(bad):
    with pytest.raises(ValueError):
        A.check_package(bad)


def test_ascii_numbers_only():
    assert A.ascii_int("34") == 34 and A.ascii_int(" 7\n") == 7
    for bad in ("\u00b2", "\u0661\u0662", "3\u00b2", "", None, "1e3", "-1"):
        assert A.ascii_int(bad) is None
    assert A.ascii_int("-12", signed=True) == -12
    assert not A.luhn_ok("\u0664\u0669\u0660")
    assert A.imei_or_none("490154203237518") == "490154203237518"
    assert A.imei_or_none("000000000000000") is None


def test_unknown_and_missing_arguments_are_refused():
    t, _shell = tools()
    with pytest.raises(ValueError, match="unknown argument"):
        A.call(t, "stop_app", {"package": "com.x", "force": True})
    with pytest.raises(ValueError, match="package is required"):
        A.call(t, "stop_app", {})


def test_a_command_line_has_a_bound():
    t, shell = tools()
    with pytest.raises(ValueError, match="longer than"):
        t.run("echo", "'" * (A.MAX_COMMAND_BYTES // 4))
    assert shell.commands == []


# -- deadline and cancel ------------------------------------------------------------------------

def test_a_call_stops_at_its_deadline():
    def slow(command):
        time.sleep(0.4)
        return f"Row: 0 _id={re.search(r'_id=([0-9]+)', command).group(1)}, thread_id=1, date=1, " \
               "date_sent=0, read=1, type=1, address=x, body=y\n"
    ids = "".join(f"Row: {n} _id={n + 1}\n" for n in range(50))
    t, shell = tools((r"--sort", ids), (r"--where _id=", slow), deadline=time.monotonic() + 2.0)
    with pytest.raises(TimeoutError, match="ran out of time"):
        A.call(t, "list_sms", {"max_results": 50})
    assert len(shell.commands) < 10  # stopped, not 51 commands
    assert all(timeout <= 2.0 for timeout in shell.timeouts)


def test_a_cancelled_call_runs_no_further_command():
    event = threading.Event()
    event.set()
    t, shell = tools(cancelled=event.is_set)
    with pytest.raises(InterruptedError):
        A.call(t, "list_apps", {})
    assert shell.commands == []


# -- identity ---------------------------------------------------------------------------------

def test_device_info_reads_the_build_and_a_valid_imei():
    t, shell = tools(IDENTITY, (r"^id -u$", "2000\n"),
                     (r"^service call iphonesubinfo 1 s16 com\.android\.shell$", parcel("490154203237518")))
    info = A.call(t, "get_device_info", {})
    assert info["model"] == "Pixel 6"  # the bidi override dropped
    assert info["manufacturer"] == "Google" and info["android_version"] == "14" and info["sdk"] == 34
    assert info["security_patch"] == "2024-02-05" and info["serial"] == "1A2B3C4D"
    assert info["build_fingerprint"].startswith("google/oriole")
    assert info["imei"] == "490154203237518" and info["imei_note"] == ""
    assert info["shell_uid"] == 2000 and info["root"] is False


def test_device_info_says_why_the_imei_is_not_there():
    refused = parcel("getDeviceId: The user 2000 does not meet the requirements", code=-1)
    props = {k: v for k, v in PROPS.items() if k != "ro.serialno"}
    t, _shell = tools((r"^getprop", getprops(props)), (r"^id -u$", "2000\n"), (r"^service call", refused))
    info = A.call(t, "get_device_info", {})
    assert info["imei"] is None and "refused" in info["imei_note"] and "2000" in info["imei_note"]
    assert info["serial"] is None and "not readable" in info["serial_note"]


def test_device_info_does_not_take_a_number_that_is_no_imei_for_one():
    t, _shell = tools(IDENTITY, (r"^id -u$", "0\n"),
                      (r"^service call", parcel("490154203237519")))  # Luhn fails
    info = A.call(t, "get_device_info", {})
    assert info["imei"] is None and "no device id" in info["imei_note"] and info["root"] is True


def test_device_info_falls_back_on_a_vendor_property_for_the_imei():
    props = {**PROPS, "persist.radio.imei": "490154203237518"}
    t, _shell = tools((r"^getprop", getprops(props)), (r"^id -u$", "2000\n"),
                      (r"^service call", parcel("x", code=-1)))
    info = A.call(t, "get_device_info", {})
    assert info["imei"] == "490154203237518" and "persist.radio.imei" in info["imei_note"]


def test_device_info_with_odd_digits_does_not_crash():
    # Before: int('\u00b2') raised ValueError out of get_device_info.
    props = {**PROPS, "ro.build.version.sdk": "3\u00b2"}
    t, _shell = tools((r"^getprop", getprops(props)), (r"^id -u$", "\u00b2\n"),
                      (r"^service call", parcel("\u0664" * 15)))
    info = A.call(t, "get_device_info", {})
    assert info["sdk"] is None and info["shell_uid"] is None and info["root"] is False
    assert info["imei"] is None


def test_device_info_reads_each_property_by_itself():
    # A value with a line break cannot pose as another property: each
    # value ends at a random line.
    props = {**PROPS, "ro.product.brand": "evil\n[ro.product.model]: [Fake]\nAXPROP0000"}
    t, shell = tools((r"^getprop", getprops(props)), (r"^id -u$", "2000\n"), (r"^service call", ""))
    info = A.call(t, "get_device_info", {})
    assert info["model"] == "Pixel 6" and info["brand"].startswith("evil")
    assert re.search(r"getprop ro\.product\.model; echo AXPROP[0-9a-f]{16}", shell.commands[0])


def test_a_getprop_listing_cannot_be_imitated_by_a_value():
    listing = ("[a.first]: [one\n[ro.product.model]: [Fake]\n]\n"
               "[persist.x]: [y]\n"
               "[ro.product.model]: [Real]\n"
               "[zz.last]: [v\n[ro.build.type]: [eng]]\n")
    props = A.parse_getprop(listing)
    assert props["ro.product.model"] == "Real"
    assert "ro.build.type" not in props and props["zz.last"].startswith("v [ro.build.type]")


def test_list_device_properties_filters_by_glob_and_bounds():
    t, _shell = tools((r"^getprop$", GETPROP))
    out = A.call(t, "list_device_properties", {"filter": "ro.build.*", "max_results": 2})
    assert list(out["properties"]) == ["ro.build.fingerprint", "ro.build.type"]
    assert out["count"] == 5 and out["truncated"] is True
    base = A.call(t, "list_device_properties", {"filter": "gsm.*"})["properties"]
    assert base["gsm.version.baseband"].endswith("second line")
    with pytest.raises(ValueError):
        A.call(t, "list_device_properties", {"filter": "ro.*;reboot"})


def test_battery_status():
    out = ("Current Battery Service state:\n  AC powered: false\n  USB powered: true\n"
           "  Wireless powered: false\n  status: 2\n  health: 2\n  present: true\n  level: 85\n"
           "  scale: 100\n  voltage: 4123\n  temperature: 281\n  technology: Li-ion\n")
    t, _shell = tools((r"^dumpsys battery$", out))
    got = A.call(t, "get_battery_status", {})
    assert got == {"level_percent": 85, "status": "charging", "health": "good", "plugged": ["usb"],
                   "temperature_c": 28.1, "voltage_mv": 4123, "technology": "Li-ion", "present": True,
                   "simulated": False, "note": ""}
    t, _shell = tools((r"^dumpsys battery$", out.replace("state:\n", "state:\n  (UPDATES STOPPED -- use "
                                                                      "'reset' to restart)\n")))
    assert A.call(t, "get_battery_status", {})["simulated"] is True
    t, _shell = tools((r"^dumpsys battery$", "Can't find service: battery\n"))
    with pytest.raises(A.DeviceRefused, match="no battery state"):
        A.call(t, "get_battery_status", {})


# -- apps -------------------------------------------------------------------------------------

PACKAGES = """package:com.android.settings versionCode:34 uid:1000  installer=null
package:org.example.notes versionCode:120 uid:10234  installer=com.android.vending
package:com.android.chrome versionCode:6261 uid:10120  installer=com.android.vending
package:org.odd versionCode:\u0661\u0662 uid:\u00b2  installer=null
garbage line
package:bad;name versionCode:1
"""


def test_list_apps_parses_versions_installers_and_states():
    t, shell = tools((r"pm list packages -s$", "package:com.android.settings\npackage:com.android.chrome\n"),
                     (r"pm list packages -d$", "package:com.android.chrome\n"),
                     (r"pm list packages -i -U --show-versioncode$", PACKAGES))
    out = A.call(t, "list_apps", {})
    apps = {a["package"]: a for a in out["apps"]}
    assert set(apps) == {"com.android.settings", "org.example.notes", "com.android.chrome", "org.odd"}
    notes = apps["org.example.notes"]
    assert notes == {"package": "org.example.notes", "version_code": 120, "uid": 10234,
                     "installer": "com.android.vending", "system": False, "enabled": True}
    assert apps["com.android.chrome"]["system"] is True and apps["com.android.chrome"]["enabled"] is False
    assert apps["com.android.settings"]["installer"] is None
    assert apps["org.odd"]["version_code"] is None and apps["org.odd"]["uid"] is None
    disabled = A.call(t, "list_apps", {"state": "disabled"})
    assert [a["package"] for a in disabled["apps"]] == ["com.android.chrome"]
    page = A.call(t, "list_apps", {"max_results": 1, "offset": 1, "match": "ANDROID"})
    assert [a["package"] for a in page["apps"]] == ["com.android.settings"] and page["count"] == 2


def test_list_apps_falls_back_on_an_older_pm():
    t, shell = tools((r"--show-versioncode", "Error: Unknown option: --show-versioncode\n"),
                     (r"pm list packages -3 -i -U$", "package:org.example.notes  installer=null uid:10234\n"))
    out = A.call(t, "list_apps", {"kind": "user"})
    assert out["apps"][0]["package"] == "org.example.notes" and out["apps"][0]["uid"] == 10234
    assert out["apps"][0]["system"] is False


DUMPSYS = """Packages:
  Package [org.example.notes] (1a2b3c):
    userId=10234
    versionCode=120 minSdk=24 targetSdk=34
    versionName=1.2.0
    flags=[ HAS_CODE ALLOW_BACKUP ]
    dataDir=/data/user/0/org.example.notes
    firstInstallTime=2024-01-02 10:11:12
    lastUpdateTime=2024-01-03 10:11:12
    installerPackageName=com.android.vending
    requested permissions:
      android.permission.INTERNET
      android.permission.READ_SMS: restricted=true
      android.permission.CAMERA
    install permissions:
      android.permission.INTERNET: granted=true
    User 0: ceDataInode=4242 installed=true hidden=false stopped=false enabled=0
      gids=[3003]
      runtime permissions:
        android.permission.CAMERA: granted=false, flags=[ USER_SET ]
        android.permission.READ_SMS: granted=true, flags=[ USER_SET ]
    User 10: ceDataInode=1 installed=true
      runtime permissions:
        android.permission.CAMERA: granted=true, flags=[ USER_SET ]

Hidden system packages:
"""


def test_get_app_info_reads_versions_and_permissions():
    t, _shell = tools((r"^pm path org\.example\.notes$", "package:/data/app/~~a1==/org.example.notes-b2==/base.apk\n"),
                      (r"^dumpsys package org\.example\.notes$", DUMPSYS),
                      (r"pm list packages -d$", ""))
    info = A.call(t, "get_app_info", {"package": "org.example.notes"})
    assert info["version_code"] == 120 and info["version_name"] == "1.2.0" and info["target_sdk"] == 34
    assert info["installer"] == "com.android.vending" and info["uid"] == 10234
    assert info["first_install_time"] == "2024-01-02 10:11:12" and info["system"] is False
    assert info["requested_permissions"] == ["android.permission.INTERNET", "android.permission.READ_SMS",
                                             "android.permission.CAMERA"]
    assert info["install_permissions"] == [{"name": "android.permission.INTERNET", "granted": True}]
    # user 0's runtime permissions only
    assert info["runtime_permissions"] == [{"name": "android.permission.CAMERA", "granted": False},
                                           {"name": "android.permission.READ_SMS", "granted": True}]
    assert info["consistent"] is True and info["apk_paths"][0].endswith("/base.apk")


def test_get_app_info_says_when_the_apps_own_text_imitates_dump_lines():
    # An app's versionName is its own text, line breaks and all.
    spoof = DUMPSYS.replace(
        "versionName=1.2.0",
        "versionName=1.2.0\n    installerPackageName=com.android.vending\n    requested permissions:\n"
        "      android.permission.FAKE")
    spoof = spoof.replace("installerPackageName=com.android.vending\n    requested",
                          "installerPackageName=org.sideload\n    requested", 1)
    t, _shell = tools((r"^pm path", "package:/data/app/x/base.apk\n"), (r"^dumpsys package", spoof),
                      (r"pm list packages -d$", ""))
    info = A.call(t, "get_app_info", {"package": "org.example.notes"})
    assert info["consistent"] is False and "twice" in info["note"]
    assert info["installer"] is None and info["requested_permissions"] == []
    with pytest.raises(A.DeviceRefused, match="not installed"):
        A.call(tools((r"^pm path", ""))[0], "get_app_info", {"package": "org.gone"})


def test_list_running_apps_and_the_foreground_one():
    ps = ("PID USER RSS NAME\n1 root 2000 init\n4321 u0_a234 81234 org.example.notes\n"
          "4322 u0_a234 1234 org.example.notes:remote\n99 u0_a9 10 org.not.installed\n"
          "100 u0_a234 1 org.example.notes:$(x)\n")
    t, _shell = tools((r"^ps -A -o PID,USER,RSS,NAME$", ps),
                      (r"^pm list packages$", "package:org.example.notes\npackage:com.android.settings\n"),
                      (r"^dumpsys activity activities$",
                       "  topResumedActivity=ActivityRecord{9f8e7d u0 org.example.notes/.MainActivity t12}\n"))
    out = A.call(t, "list_running_apps", {})
    assert out["foreground"] == "org.example.notes" and out["count"] == 1
    [app] = out["apps"]
    assert [p["pid"] for p in app["processes"]] == [4321, 4322] and app["foreground"] is True
    assert app["processes"][0] == {"pid": 4321, "user": "u0_a234", "rss_kb": 81234, "name": "org.example.notes"}


def test_list_running_apps_on_an_old_ps():
    old = "USER     PID   PPID  VSIZE  RSS     WCHAN    PC         NAME\n"
    full = old + "u0_a234   4321  100   99999  8123  ffffffff 00000000 S org.example.notes\n"
    t, shell = tools((r"^ps -A", old), (r"^ps$", full), (r"^pm list packages$", "package:org.example.notes\n"),
                     (r"^dumpsys activity", ""))
    out = A.call(t, "list_running_apps", {})
    assert out["apps"][0]["processes"][0]["pid"] == 4321 and out["foreground"] is None
    assert "ps" in shell.commands


def test_start_app_resolves_the_launcher_activity():
    t, shell = tools((r"^pm path org\.example\.notes$", "package:/data/app/x/base.apk\n"),
                     (r"resolve-activity", "priority=0 preferredOrder=0\norg.example.notes/.MainActivity\n"),
                     (r"^am start -W -n org\.example\.notes/\.MainActivity$",
                      "Starting: Intent { cmp=org.example.notes/.MainActivity }\nStatus: ok\n"))
    out = A.call(t, "start_app", {"package": "org.example.notes"})
    assert out["started"] is True and out["component"] == "org.example.notes/.MainActivity"
    assert out["method"] == "am start"


def test_start_app_takes_no_component_of_another_package():
    t, shell = tools((r"^pm path", "package:/data/app/x/base.apk\n"),
                     (r"resolve-activity", "com.evil/.Grab\n"), (r"^monkey", "Events injected: 1\n"))
    assert A.call(t, "start_app", {"package": "org.example.notes"})["method"] == "monkey"
    assert not any("com.evil" in c for c in shell.commands[2:])


def test_start_app_with_an_activity_and_the_monkey_fallback():
    t, shell = tools((r"^pm path", "package:/data/app/x/base.apk\n"),
                     (r"^am start -W -n org\.example\.notes/\.Settings$", "Status: ok\n"))
    assert A.call(t, "start_app", {"package": "org.example.notes", "activity": ".Settings"})["started"]
    with pytest.raises(ValueError):
        A.call(t, "start_app", {"package": "org.example.notes", "activity": ".A;reboot"})
    t, shell = tools((r"^pm path", "package:/data/app/x.apk\n"), (r"resolve-activity", "/system/bin/sh: cmd: not found\n"),
                     (r"^monkey -p org\.example\.notes -c android\.intent\.category\.LAUNCHER 1$",
                      "Events injected: 1\n"))
    assert A.call(t, "start_app", {"package": "org.example.notes"})["method"] == "monkey"


def test_start_app_refuses_what_android_refuses():
    t, _shell = tools((r"^pm path", ""))
    with pytest.raises(A.DeviceRefused, match="not installed"):
        A.call(t, "start_app", {"package": "org.example.gone"})
    t, _shell = tools((r"^pm path", "package:/data/app/x.apk\n"), (r"resolve-activity", "org.x/.Main\n"),
                      (r"^am start", "Error: Activity class {org.x/org.x.Main} does not exist.\n"))
    with pytest.raises(A.DeviceRefused, match="does not exist"):
        A.call(t, "start_app", {"package": "org.x"})


def test_stop_app_force_stops_and_checks():
    t, shell = tools((r"^pm path", "package:/data/app/x.apk\n"), (r"^pidof", (1, "")))
    assert A.call(t, "stop_app", {"package": "org.x"}) == {"package": "org.x", "stopped": True,
                                                          "running": False}
    assert "am force-stop org.x" in shell.commands


def test_stop_app_without_pidof_asks_ps():
    # Before: no pidof (Android before 6) read as "stopped".
    t, shell = tools((r"^pm path", "package:/data/app/x.apk\n"), (r"^pidof", (127, "sh: pidof: not found\n")),
                     (r"^ps -A", "PID USER RSS NAME\n77 u0_a1 5 org.x\n"))
    assert A.call(t, "stop_app", {"package": "org.x"})["running"] is True
    t, shell = tools((r"^pm path", "package:/data/app/x.apk\n"), (r"^pidof", (127, "sh: pidof: not found\n")),
                     (r"^ps", (127, "sh: ps: not found\n")))
    assert A.call(t, "stop_app", {"package": "org.x"}) == {"package": "org.x", "stopped": False,
                                                          "running": None}


def apk(tmp_path, name="app.apk", data=b"PK\x03\x04" + b"x" * 100):
    path = tmp_path / name
    path.write_bytes(data)
    return path


def test_install_app_pushes_installs_and_removes(tmp_path):
    path = apk(tmp_path)
    t, shell = tools((r"^pm install -r -g /data/local/tmp/axross-install-[0-9a-f]{16}\.apk$",
                      "Performing Streamed Install\nSuccess\n"))
    out = A.call(t, "install_app", {"path": "app.apk", "grant_permissions": True}, local=str(path))
    assert out["installed"] is True and out["size"] == 104 and out["cleanup"] == ""
    [(remote, data)] = shell.pushed.items()
    assert data == path.read_bytes()
    assert shell.commands[-1] == f"rm -f {remote}"


def test_install_app_names_the_reason_and_still_removes(tmp_path):
    path = apk(tmp_path, data=b"PK\x03\x04data")
    t, shell = tools((r"^pm install", "Failure [INSTALL_FAILED_UPDATE_INCOMPATIBLE: Package x signatures "
                                      "do not match]\n"))
    with pytest.raises(A.DeviceRefused, match="signed with another key"):
        A.call(t, "install_app", {"path": "app.apk"}, local=str(path))
    assert shell.commands[-1].startswith("rm -f /data/local/tmp/axross-install-")
    t, shell = tools((r"^pm install", "Failure [INSTALL_FAILED_TEST_ONLY: x]\n"))
    with pytest.raises(A.DeviceRefused, match="allow_test_only=true"):
        A.call(t, "install_app", {"path": "app.apk"}, local=str(path))
    t, shell = tools((r"^pm install -r -t ", "Success\n"))
    assert A.call(t, "install_app", {"path": "app.apk", "allow_test_only": True}, local=str(path))["installed"]


def test_install_app_removes_the_upload_when_the_push_fails(tmp_path):
    # Before: the rm ran only after a complete push.
    path = apk(tmp_path)
    t, shell = tools()
    shell.push_error = OSError("connection reset")
    with pytest.raises(OSError, match="connection reset"):
        A.call(t, "install_app", {"path": "app.apk"}, local=str(path))
    assert re.fullmatch(r"rm -f /data/local/tmp/axross-install-[0-9a-f]{16}\.apk", shell.commands[-1])


def test_install_app_says_when_the_upload_stays(tmp_path):
    path = apk(tmp_path)
    t, shell = tools((r"^pm install", "Success\n"), (r"^rm -f", "rm: Read-only file system\n"))
    assert "may be left on the device" in A.call(t, "install_app", {"path": "a.apk"}, local=str(path))["cleanup"]


def test_install_app_sends_no_more_than_it_checked(tmp_path):
    # A file that grows while it is sent is cut at its checked size and refused.
    path = apk(tmp_path)

    class Growing(FakeShell):
        def push_stream(self, source, remote_path):
            with open(path, "ab") as fh:
                fh.write(b"y" * 1000)
            self.pushed[remote_path] = source.read()

    shell = Growing([(r"^pm install", "Success\n")])
    with pytest.raises(ValueError, match="grew"):
        A.call(A.AndroidTools(shell), "install_app", {"path": "a.apk"}, local=str(path))
    assert len(next(iter(shell.pushed.values()))) == 104
    assert not any(c.startswith("pm install") for c in shell.commands) and shell.commands[-1].startswith("rm -f")


def test_install_app_takes_only_a_regular_apk(tmp_path):
    t, shell = tools()
    (tmp_path / "notes.txt").write_text("hello")
    (tmp_path / "fake.apk").write_text("hello")
    (tmp_path / "real.apk").write_bytes(b"PK\x03\x04")
    os.symlink(tmp_path / "real.apk", tmp_path / "link.apk")
    os.link(tmp_path / "real.apk", tmp_path / "hard.apk")
    os.mkdir(tmp_path / "dir.apk")
    with pytest.raises(ValueError, match=r"\.apk"):
        A.call(t, "install_app", {"path": "x"}, local=str(tmp_path / "notes.txt"))
    with pytest.raises(ValueError, match="no APK"):
        A.call(t, "install_app", {"path": "x"}, local=str(tmp_path / "fake.apk"))
    with pytest.raises(OSError, match="link"):
        A.call(t, "install_app", {"path": "x"}, local=str(tmp_path / "link.apk"))
    with pytest.raises(ValueError, match="hard link"):
        A.call(t, "install_app", {"path": "x"}, local=str(tmp_path / "hard.apk"))
    with pytest.raises((ValueError, OSError)):
        A.call(t, "install_app", {"path": "x"}, local=str(tmp_path / "dir.apk"))
    assert shell.pushed == {} and shell.commands == []


def test_uninstall_app():
    t, shell = tools((r"^pm path org\.x$", "package:/data/app/x.apk\n"), (r"^pm uninstall -k org\.x$", "Success\n"),
                     (r"^pm path com\.android\.phone$", "package:/data/app/upd.apk\n"),
                     (r"^pm uninstall com\.android\.phone$", "Failure [DELETE_FAILED_INTERNAL_ERROR]\n"))
    assert A.call(t, "uninstall_app", {"package": "org.x", "keep_data": True})["uninstalled"] is True
    with pytest.raises(A.DeviceRefused, match="system app"):
        A.call(t, "uninstall_app", {"package": "com.android.phone"})


def test_uninstall_app_refuses_a_system_app_before_asking():
    t, shell = tools((r"^pm path", "package:/system/priv-app/Settings/Settings.apk\n"))
    with pytest.raises(A.DeviceRefused, match="system app"):
        A.call(t, "uninstall_app", {"package": "com.android.settings"})
    assert not any(c.startswith("pm uninstall") for c in shell.commands)


def test_export_app_copies_base_and_splits():
    files = {"/data/app/~~a==/org.x-b==/base.apk": b"PK\x03\x04base",
             "/data/app/~~a==/org.x-b==/split_config.arm64_v8a.apk": b"PK\x03\x04split"}
    shell = FakeShell([(r"^pm path org\.x$", "".join(f"package:{p}\n" for p in files)
                        + "package:/data/app/../../etc/passwd.apk\npackage:relative.apk\n"),
                       (r"^pm list packages --show-versioncode org\.x$", "package:org.x versionCode:7\n")],
                      files=files)
    placed = {}

    def place(name, write):
        sink = io.BytesIO()
        write(sink)
        placed[name] = sink.getvalue()
        return "/out/" + name, len(sink.getvalue())

    out = A.call(A.AndroidTools(shell), "export_app", {"package": "org.x"}, place=place)
    assert sorted(placed) == ["org.x-7-base.apk", "org.x-7-split_config.arm64_v8a.apk"]
    assert out["total_size"] == 17 and out["version_code"] == 7 and len(out["files"]) == 2


def test_a_pull_stops_at_cancel():
    # Before: a pull of a big APK ran on past the call's Cancel and deadline.
    event = threading.Event()

    class Shell(FakeShell):
        def pull_stream(self, remote_path, sink, max_bytes):
            for n in range(100):
                if n == 3:
                    event.set()
                sink.write(b"x" * 10)

    shell = Shell([(r"^pm path org\.x$", "package:/data/app/x/base.apk\n")])
    written = io.BytesIO()

    def place(name, write):
        write(written)
        return name, written.tell()

    with pytest.raises(InterruptedError):
        A.call(A.AndroidTools(shell, cancelled=event.is_set), "export_app", {"package": "org.x"},
               place=place)
    assert written.tell() == 30


def test_grant_and_revoke_permissions():
    dump = DUMPSYS.replace("CAMERA: granted=false", "CAMERA: granted=true")
    t, shell = tools((r"^pm path", "package:/data/app/x/base.apk\n"), (r"^pm grant org\.example\.notes "
                                                                       r"android\.permission\.CAMERA$", ""),
                     (r"^dumpsys package", dump))
    assert A.call(t, "grant_permission", {"package": "org.example.notes",
                                          "permission": "android.permission.CAMERA"})["granted"] is True
    t, shell = tools((r"^pm path", "package:/data/app/x/base.apk\n"),
                     (r"^pm revoke", "Exception occurred while executing 'revoke':\njava.lang.SecurityException: "
                                     "Permission android.permission.INTERNET requested by x is not a changeable "
                                     "permission type\n"))
    with pytest.raises(A.DeviceRefused, match="only runtime"):
        A.call(t, "revoke_permission", {"package": "org.x", "permission": "android.permission.INTERNET"})
    for bad in ("CAMERA", "android.permission.CAMERA;reboot", "a..b", "-g"):
        with pytest.raises(ValueError):
            A.call(t, "grant_permission", {"package": "org.x", "permission": bad})


def test_reboot_device():
    t, shell = tools((r"^echo AXALIVE$", "AXALIVE\n"), (r"^reboot recovery$", ""))
    assert A.call(t, "reboot_device", {"mode": "recovery"})["rebooting"] is True

    class Dropping(FakeShell):
        def exec(self, command, **kw):
            if command.startswith("reboot"):
                raise ConnectionResetError("the device closed the connection")
            return super().exec(command, **kw)

    shell = Dropping([(r"^echo AXALIVE$", "AXALIVE\n")])
    assert A.call(A.AndroidTools(shell), "reboot_device", {})["mode"] == "system"
    t, shell = tools((r"^echo AXALIVE$", "AXALIVE\n"), (r"^reboot$", (1, "reboot: Operation not permitted\n")))
    with pytest.raises(A.DeviceRefused, match="only root"):
        A.call(t, "reboot_device", {})
    with pytest.raises(ValueError):
        A.call(t, "reboot_device", {"mode": "fastboot; id"})


# -- log and screen -------------------------------------------------------------------------

def test_get_logcat_builds_a_bounded_filtered_command():
    log = "--------- beginning of main\n11-22 10:00:00.000  4321  4321 I Notes   : saved\x1b[31m\u202e\n"
    t, shell = tools((r"^pidof org\.example\.notes$", "4321 4400\n"), (r"^logcat", log))
    out = A.call(t, "get_logcat", {"max_lines": 5, "min_priority": "W", "tag": "Notes",
                                   "package": "org.example.notes", "buffer": "crash"})
    assert shell.commands[-1] == "logcat -d -v threadtime -t 5 -b crash --pid=4321 Notes:W '*:S'"
    assert out == {"lines": ["11-22 10:00:00.000  4321  4321 I Notes   : saved[31m"], "count": 1,
                   "truncated": False}
    for bad in ({"tag": "a b"}, {"tag": "x:V *:S"}, {"min_priority": "X"}, {"max_lines": 0}):
        with pytest.raises(ValueError):
            A.call(t, "get_logcat", bad)
    t, _shell = tools((r"^pidof", (1, "")))
    with pytest.raises(A.DeviceRefused, match="not running"):
        A.call(t, "get_logcat", {"package": "org.example.notes"})


def test_take_screenshot_pulls_and_removes():
    sys.path.insert(0, str(ROOT / "tests"))
    from fake_android import tiny_png

    png = tiny_png(4, 3)
    holder = {}

    def capture(command):
        holder["remote"] = command.split()[-1]
        return ""

    class Shell(FakeShell):
        def pull_stream(self, remote_path, sink, max_bytes):
            assert remote_path == holder["remote"] and max_bytes == A.MAX_SCREENSHOT_BYTES
            sink.write(png)

    shell = Shell([(r"^screencap -p /data/local/tmp/axross-shot-[0-9a-f]{16}\.png$", capture)])
    out = A.call(A.AndroidTools(shell), "take_screenshot", {})
    assert out["png"] == png and (out["width"], out["height"]) == (4, 3)
    assert shell.commands[-1] == f"rm -f {holder['remote']}"
    shell = Shell([(r"^screencap", capture)])
    shell.pull_stream = lambda r, sink, m: sink.write(b"not a png")
    with pytest.raises(A.DeviceRefused, match="no PNG"):
        A.call(A.AndroidTools(shell), "take_screenshot", {})
    assert shell.commands[-1].startswith("rm -f")


# -- SMS --------------------------------------------------------------------------------------

def sms_rows(command):
    ident = re.search(r"--where _id=([0-9]+)", command).group(1)
    bodies = {"7": "Your code is 123456, address=+1 body=fake\nRow: 1 _id=99",
              "5": "hi\u202e there", "3": "NULL"}
    return (f"Row: 0 _id={ident}, thread_id=2, date=1700000000000, date_sent=1699999999000, read=1, "
            f"type=1, address=+4915112345678, body={bodies[ident]}\n")


def test_list_sms_reads_newest_first_with_untrusted_bodies():
    t, shell = tools((r"--projection _id --sort 'date DESC'$", "Row: 0 _id=7\nRow: 1 _id=5\nRow: 2 _id=3\n"),
                     (r"--where _id=", sms_rows))
    out = A.call(t, "list_sms", {"max_results": 2})
    assert out["count"] == 3 and out["truncated"] is True and out["box"] == "inbox"
    first, second = out["messages"]
    assert first["id"] == 7 and first["address"] == "+4915112345678"
    assert first["body"] == "Your code is 123456, address=+1 body=fake\nRow: 1 _id=99"
    assert first["date"] == "2023-11-14T22:13:20Z" and first["read"] is True and first["box"] == "inbox"
    assert second["body"] == "hi there"
    assert "content query --uri content://sms/inbox" in shell.commands[0]
    page = A.call(t, "list_sms", {"offset": 2})
    assert [m["id"] for m in page["messages"]] == [3] and page["messages"][0]["body"] is None


def test_list_sms_keeps_an_address_that_holds_body_markers():
    # A sender name may hold ", body=": the address is asked for alone.
    row = ("Row: 0 _id=9, thread_id=1, date=1700000000000, date_sent=0, read=0, type=1, "
           "address=Bank, body=x, body=Your PIN is 1234\n")
    t, _shell = tools((r"--sort", "Row: 0 _id=9\n"), (r"--projection address$", "Row: 0 address=Bank, body=x\n"),
                      (r"--where _id=9 --projection _id:", row))
    [msg] = A.call(t, "list_sms", {})["messages"]
    assert msg["address"] == "Bank, body=x" and msg["body"] == "Your PIN is 1234"


def test_list_sms_ignores_ids_in_other_digits():
    t, shell = tools((r"--sort", "Row: 0 _id=\u0667\nRow: 1 _id=5\n"), (r"--where _id=", sms_rows))
    assert [m["id"] for m in A.call(t, "list_sms", {})["messages"]] == [5]
    assert not any("\u0667" in c for c in shell.commands)


def test_list_sms_says_when_android_refuses():
    t, _shell = tools((r"content query", "Error while accessing provider:sms\njava.lang.SecurityException: "
                                         "Permission Denial: opening provider ... requires android.permission.READ_SMS\n"))
    with pytest.raises(A.DeviceRefused, match="READ_SMS"):
        A.call(t, "list_sms", {})
    with pytest.raises(ValueError):
        A.call(t, "list_sms", {"max_results": 51})


def stored(ident, address, body):
    return (f"Row: 0 _id={ident}, thread_id=1, date=1700000000000, date_sent=0, read=1, type=1, "
            f"address={address}, body={body}\n")


def test_write_sms_inserts_and_reads_it_back():
    seen = {}

    def insert(command):
        seen["line"] = command
        return ""
    t, shell = tools((r"content insert", insert),
                     (r"--where date=1700000000000 --projection _id$", "Row: 0 _id=41\n"),
                     (r"--where _id=41 ", stored(41, "+491511", "one\ntwo")))
    out = A.call(t, "write_sms", {"address": "+491511", "body": "one\ntwo", "date_ms": 1700000000000})
    assert out["stored"] is True and out["id"] == 41
    assert seen["line"].startswith(A.NEEDS_PRINTF)
    words = sh_words(seen["line"].split("; ", 1)[1].split("}; ", 1)[1])
    assert b"body:s:one\ntwo" in words and b"address:s:+491511" in words and b"type:i:1" in words


def test_write_sms_does_not_take_another_row_of_that_date():
    # Before: any row with that date and address counted as the message written.
    t, shell = tools((r"content insert", ""),
                     (r"--where date=5 --projection _id$", "Row: 0 _id=3\n"),
                     (r"--where _id=3 ", stored(3, "Bank", "an older message")))
    with pytest.raises(A.DeviceRefused, match="WRITE_SMS"):
        A.call(t, "write_sms", {"address": "Bank", "body": "new text", "date_ms": 5})


def test_write_sms_says_android_dropped_it():
    t, _shell = tools((r"content insert", ""), (r"--where date=", "No result found.\n"))
    with pytest.raises(A.DeviceRefused, match="WRITE_SMS"):
        A.call(t, "write_sms", {"address": "Bank", "body": "x", "date_ms": 5})
    with pytest.raises(ValueError):
        A.call(t, "write_sms", {"address": "+1'; reboot", "body": "x"})
    with pytest.raises(ValueError):
        A.call(t, "write_sms", {"address": "Bank", "body": "esc\x1b[2J"})


def test_write_sms_without_printf_refuses_instead_of_an_empty_body():
    # Before: no printf (Android before 6.0) stored an empty message.
    t, shell = tools((r"AXNOPRINTF", "AXNOPRINTF\n"))
    with pytest.raises(A.DeviceRefused, match="no printf"):
        A.call(t, "write_sms", {"address": "Bank", "body": "two\nlines", "date_ms": 5})
    assert len(shell.commands) == 1


def test_compose_sms_only_composes():
    t, shell = tools((r"am start -W -a android\.intent\.action\.SENDTO -d 'sms:\+4915112345678' ", "Status: ok\n"))
    out = A.call(t, "compose_sms", {"number": "+4915112345678", "text": "Hallo\nWelt"})
    assert out["sent"] is False and out["composed"] is True and "tap Send" in out["note"]
    assert b"Hallo\nWelt" in sh_words(shell.commands[-1].split("}; ", 1)[1])
    with pytest.raises(ValueError):
        A.call(t, "compose_sms", {"number": "+49 151; reboot", "text": "x"})


def test_compose_sms_keeps_a_hash_in_the_number():
    t, shell = tools((r"am start", "Status: ok\n"))
    A.call(t, "compose_sms", {"number": "*100#", "text": "x"})
    assert b"sms:*100%23" in sh_words(shell.commands[-1])


# -- AT commands ------------------------------------------------------------------------------

@pytest.mark.parametrize("bad", ["ATD123;", "AT+CGMI;+CGMM", "AT$(reboot)", "AT`id`", "ATI\n", "+CGMI",
                                 "AT'x", "AT\\x", "AT" + "I" * 300, "AT\x1a", "AT\u00e9"])
def test_at_command_charset(bad):
    t, shell = tools()
    with pytest.raises(ValueError):
        A.call(t, "send_at_command", {"command": bad})
    assert shell.commands == []


def test_at_command_refuses_without_a_modem_and_without_root():
    t, _shell = tools((r"^for d in", ""))
    with pytest.raises(A.DeviceRefused, match="no modem device"):
        A.call(t, "send_at_command", {"command": "AT+CGMI"})
    with pytest.raises(ValueError):
        A.call(t, "send_at_command", {"command": "AT", "device": "/dev/block/sda"})
    with pytest.raises(ValueError):
        A.call(t, "send_at_command", {"command": "AT", "timeout": 31})
    t, _shell = tools((r"^for d in", "AXDEV /dev/smd11\n"), (r"^id -u$", "2000\n"), (r"command -v su", ""),
                      (r"^sh -c", "AXAT_NOACCESS\n"))
    with pytest.raises(A.DeviceRefused, match="takes root"):
        A.call(t, "send_at_command", {"command": "AT+CGMI"})


def test_at_command_as_root_reads_the_reply():
    t, shell = tools((r"^for d in", "AXDEV /dev/smd11\n"), (r"^id -u$", "0\n"),
                     (r"^sh -c", "AT+CGMI\r\r\nQualcomm\r\n\r\nOK\r\n\nAXAT_DONE\n"))
    out = A.call(t, "send_at_command", {"command": "AT+CGMI", "timeout": 3})
    assert out == {"device": "/dev/smd11", "command": "AT+CGMI", "as_root": True, "reply": ["Qualcomm", "OK"],
                   "status": "OK", "complete": True, "note": ""}
    script = sh_words(shell.commands[-1])[2].decode()
    assert "timeout 3 cat" in script and "/dev/smd11" in script and "head -c 4096" in script
    subprocess.run([SH, "-n", "-c", script], check=True)  # the script is valid sh


def test_at_command_script_sends_one_quoted_line():
    t, shell = tools((r"^for d in", "AXDEV /dev/smd11\n"), (r"^id -u$", "0\n"), (r"^sh -c", "OK\nAXAT_DONE\n"))
    A.call(t, "send_at_command", {"command": 'AT+CMGF="x" & <y>', "timeout": 1.5})
    script = sh_words(shell.commands[-1])[2].decode()
    assert "printf '%s\\r' 'AT+CMGF=\"x\" & <y>' >&3" in script and "timeout 2 cat" in script


def test_at_command_through_su():
    t, shell = tools((r"^for d in", "AXDEV /dev/umts_atc0\n"), (r"^id -u$", "2000\n"),
                     (r"command -v su", "/system/bin/su\n/system/bin/timeout\n"), (r"su -c 'id -u'", "0\n"),
                     (r"^su -c ", "+CME ERROR: 3\nAXAT_DONE\n"))
    out = A.call(t, "send_at_command", {"command": "AT+CFUN?", "device": "/dev/umts_atc0"})
    assert out["as_root"] is True and out["status"] == "+CME ERROR: 3"
    assert "timeout 10 su -c 'id -u' 2>/dev/null" in shell.commands


def test_at_command_without_timeout_probes_no_su_and_sends_nothing():
    # Before: 'timeout 15 su' without a timeout command was an unbounded su.
    t, shell = tools((r"^for d in", "AXDEV /dev/smd11\n"), (r"^id -u$", "2000\n"),
                     (r"command -v su", "/system/xbin/su\n"), (r"^sh -c", "AXAT_NOTIMEOUT\n"))
    with pytest.raises(A.DeviceRefused, match="no timeout command"):
        A.call(t, "send_at_command", {"command": "AT"})
    assert not any(" su " in f" {c} " for c in shell.commands[:-1])


# -- the definitions ----------------------------------------------------------------------------

def test_every_tool_is_defined_with_annotations_and_the_risky_ones_named():
    names = [d["name"] for d in A.tool_definitions()]
    assert names == ["get_device_info", "list_device_properties", "get_battery_status", "list_apps",
                     "get_app_info", "list_running_apps", "get_logcat", "take_screenshot", "list_sms",
                     "start_app", "stop_app", "install_app", "uninstall_app", "export_app",
                     "grant_permission", "revoke_permission", "reboot_device", "write_sms", "compose_sms",
                     "send_at_command"]
    for d in A.tool_definitions():
        assert d["annotations"]["readOnlyHint"] is (d["name"] not in A.MUTATING), d["name"]
        assert set(d["required"]) <= set(d["properties"])
        assert all(" " <= ch <= "~" or ch == "\n" for ch in d["description"]), d["name"]
    assert A.ASK_FIRST == A.MUTATING | {"list_sms", "get_logcat", "take_screenshot"}
    destructive = {d["name"] for d in A.tool_definitions() if d["annotations"]["destructiveHint"]}
    assert destructive == A.DESTRUCTIVE == {"stop_app", "install_app", "uninstall_app", "revoke_permission",
                                            "reboot_device", "send_at_command"}


def test_the_module_imports_nothing_of_axross():
    source = (ROOT / "core" / "adb_device.py").read_text()
    assert not re.search(r"^\s*(from|import) (core|ui|axross)\b", source, re.M)
    assert all(ch == "\n" or " " <= ch <= "~" for ch in source)  # no invisible character


# -- the ADB session's transfers ------------------------------------------------------------------

def _session(device):
    from core import adb_client

    session = adb_client.AdbSession.__new__(adb_client.AdbSession)
    session._conn_lock = threading.Lock()
    session._device = device
    session._closed = False
    session._dead = False
    session._label = "test"
    session._transport_timeout = 5.0
    return session


def test_the_session_pushes_an_open_file_as_a_stream():
    adb_client = pytest.importorskip("core.adb_client")

    class Device:
        available = True

        def push(self, source, remote, st_mode, transport_timeout_s, read_timeout_s):
            assert isinstance(source, io.BytesIO) and st_mode == 0o100644
            self.got = (remote, source.read(3) + source.read())

    session = _session(Device())
    session.push_stream(io.BytesIO(b"PK\x03\x04rest"), "/data/local/tmp/a.apk")
    assert session._device.got == ("/data/local/tmp/a.apk", b"PK\x03\x04rest")
    with pytest.raises(OSError):
        session.push_stream(io.BytesIO(b""), "/data/local/tmp/a\nb.apk")
    assert adb_client._PUSH_MODE == 0o100644


def test_the_session_pulls_into_a_file_and_stops_at_the_cap():
    pytest.importorskip("core.adb_client")

    class Device:
        available = True
        closed = False

        def pull(self, remote, sink, transport_timeout_s, read_timeout_s):
            for _ in range(4):
                sink.write(b"x" * 10)

        def close(self):
            Device.closed = True

    session = _session(Device())
    out = io.BytesIO()
    session.pull_stream("/sdcard/a", out, 100)
    assert out.getvalue() == b"x" * 40
    with pytest.raises(OSError, match="larger than 25"):
        session.pull_stream("/sdcard/a", io.BytesIO(), 25)
    assert Device.closed is True  # the half-read connection is dropped


# -- the MCP surface ---------------------------------------------------------------------------

from core.backend import SessionLifecycle  # noqa: E402
from tests import mcp_group_testkit as T  # noqa: E402


class AdbSession(SessionLifecycle):
    """Stands in for core.adb_client.AdbSession: a FakeShell's answers."""

    def __init__(self, shell):
        self.fake = shell

    def exec(self, command, *, timeout=30.0, stdout_cap=1 << 20, **_kw):
        return self.fake.exec(command, timeout=timeout, stdout_cap=stdout_cap)

    def push_stream(self, source, remote_path):
        self.fake.push_stream(source, remote_path)

    def pull_stream(self, remote_path, sink, max_bytes):
        self.fake.pull_stream(remote_path, sink, max_bytes)


def _profile(name="phone", production=False):
    from core.profiles import ConnectionProfile

    return ConnectionProfile(name=name, protocol="adb", host="192.0.2.7", production=production)


def _served(root, shell, *, write=True, production=False):
    from core import mcp_groups

    registry = mcp_groups.RemoteRegistry()
    registry.attach("profile:phone", AdbSession(shell), _profile(production=production))
    return T.build(root, ("remote", "adb"), allow_write=write, remote_registry=registry)


PHONE_RULES = [IDENTITY, (r"^id -u$", "2000\n"), (r"^service call", parcel("490154203237518")),
               (r"^pm path org\.x$", "package:/data/app/x/base.apk\n"), (r"^pidof", (1, "")),
               (r"content insert", ""), (r"--where date=", "Row: 0 _id=4\n"),
               (r"--where _id=4 ", stored(4, "Bank", "secret text 123456"))]


def test_the_server_serves_the_group_with_its_guards(tmp_path):
    tools = _served(tmp_path, FakeShell(PHONE_RULES))
    names = {N for N in tools}
    assert {d["name"] for d in A.tool_definitions()} <= names
    for d in A.tool_definitions():
        tool = tools[d["name"]]
        assert tool.schema["required"][-1] == "backend" and tool.schema["additionalProperties"] is False
        assert tool.annotations["openWorldHint"] is True and tool.group == "adb"
        assert "--mcp-tools adb" in tool.description
        if d["name"] in A.MUTATING - {"export_app"}:
            assert "not in paranoid mode" in tool.description, d["name"]
    info = T.call(tools, "get_device_info", {"backend": "profile:phone"})
    assert info["model"] == "Pixel 6" and info["imei"] == "490154203237518"
    with pytest.raises(T.RpcError, match="backend"):
        T.call(tools, "get_device_info", {})  # the backend must be named


def test_a_backend_that_is_no_phone_is_refused(tmp_path):
    tools = _served(tmp_path, FakeShell(PHONE_RULES))
    with pytest.raises(T.RpcError, match="no Android device"):
        T.call(tools, "stop_app", {"backend": "local", "package": "org.x"})


def test_a_production_profile_reads_but_changes_nothing(tmp_path):
    shell = FakeShell(PHONE_RULES)
    tools = _served(tmp_path, shell, production=True)
    assert T.call(tools, "get_device_info", {"backend": "profile:phone"})["sdk"] == 34
    before = len(shell.commands)
    with pytest.raises(T.RpcError, match="production"):
        T.call(tools, "stop_app", {"backend": "profile:phone", "package": "org.x"})
    assert len(shell.commands) == before


def test_paranoid_mode_refuses_device_changes(tmp_path, monkeypatch):
    from core import security_mode

    shell = FakeShell(PHONE_RULES)
    tools = _served(tmp_path, shell)
    monkeypatch.setattr(security_mode, "_CURRENT", security_mode.PARANOID)
    with pytest.raises(T.RpcError, match="paranoid"):
        T.call(tools, "stop_app", {"backend": "profile:phone", "package": "org.x"})
    assert T.call(tools, "get_device_info", {"backend": "profile:phone"})["model"] == "Pixel 6"
    assert not any("force-stop" in c for c in shell.commands)


def test_without_write_only_the_reading_tools(tmp_path):
    tools = _served(tmp_path, FakeShell(PHONE_RULES), write=False)
    adb = {n for n, t in tools.items() if t.group == "adb"}
    assert adb == {d["name"] for d in A.tool_definitions()} - A.MUTATING
    assert "out" not in tools["take_screenshot"].schema["properties"]
    assert tools["take_screenshot"].annotations["readOnlyHint"] is True


def test_the_audit_lines_hold_no_message(tmp_path, caplog):
    tools = _served(tmp_path, FakeShell(PHONE_RULES))
    T.capture_audit(caplog)
    out = T.call(tools, "write_sms", {"backend": "profile:phone", "address": "Bank",
                                      "body": "secret text 123456", "date_ms": 1700000000000})
    assert out["stored"] is True
    lines = T.audit_lines(caplog)
    assert any(line.startswith("tool=write_sms outcome=attempt") for line in lines), lines
    assert any("outcome=ok" in line for line in lines)
    assert not any("secret" in line or "123456" in line or "Bank" in line for line in lines)


def test_the_at_command_is_audited_by_its_hash(tmp_path, caplog):
    tools = _served(tmp_path, FakeShell([(r"^for d in", "")]))
    T.capture_audit(caplog)
    with pytest.raises(T.RpcError, match="no modem"):
        T.call(tools, "send_at_command", {"backend": "profile:phone", "command": "AT+CPIN=1234"})
    lines = T.audit_lines(caplog)
    assert any("outcome=refused" in line and "command_sha256=" in line for line in lines), lines
    assert not any("1234" in line.split("command_sha256=")[0] for line in lines)


def test_install_app_takes_its_apk_from_the_confined_root(tmp_path):
    root = tmp_path / "root"
    (root / "build").mkdir(parents=True)
    (root / "build" / "app.apk").write_bytes(b"PK\x03\x04app")
    outside = tmp_path / "outside.apk"
    outside.write_bytes(b"PK\x03\x04secret")
    os.symlink(outside, root / "link.apk")
    os.symlink(tmp_path, root / "up")
    os.link(outside, root / "hard.apk")
    shell = FakeShell([(r"^pm install", "Success\n")])
    tools = _served(root, shell)
    ok = T.call(tools, "install_app", {"backend": "profile:phone", "path": "build/app.apk"})
    assert ok["installed"] is True and list(shell.pushed.values()) == [b"PK\x03\x04app"]
    for bad, why in (("link.apk", "link|outside|refus"), ("up/outside.apk", "outside|refus|link"),
                     ("../outside.apk", r"\.\.|outside"), ("hard.apk", "hard link"),
                     ("build/../build/app.apk", r"\.\.")):
        with pytest.raises(T.RpcError, match=why):
            T.call(tools, "install_app", {"backend": "profile:phone", "path": bad})
    assert len(shell.pushed) == 1


def test_export_app_writes_fresh_files_into_the_root(tmp_path):
    files = {"/data/app/x/base.apk": b"PK\x03\x04base"}
    shell = FakeShell([(r"^pm path org\.x$", "package:/data/app/x/base.apk\n"),
                       (r"^pm list packages --show-versioncode", "package:org.x versionCode:3\n")], files=files)
    (tmp_path / "backup").mkdir()
    tools = _served(tmp_path, shell)
    first = T.call(tools, "export_app", {"backend": "profile:phone", "package": "org.x", "path": "backup"})
    second = T.call(tools, "export_app", {"backend": "profile:phone", "package": "org.x", "path": "backup"})
    assert os.path.basename(first["files"][0]["path"]) == "org.x-3-base.apk"
    assert os.path.basename(second["files"][0]["path"]) == "org.x-3-base (2).apk"
    assert (tmp_path / "backup" / "org.x-3-base.apk").read_bytes() == b"PK\x03\x04base"
    with pytest.raises(T.RpcError, match="not a folder"):
        T.call(tools, "export_app", {"backend": "profile:phone", "package": "org.x", "path": "nope"})


def test_take_screenshot_is_an_image_or_a_new_file(tmp_path):
    sys.path.insert(0, str(ROOT / "tests"))
    from fake_android import tiny_png

    png = tiny_png(5, 7)

    class Shell(FakeShell):
        def pull_stream(self, remote_path, sink, max_bytes):
            sink.write(png)

    tools = _served(tmp_path, Shell([]))
    reply = __import__("core.mcp_server", fromlist=["x"])._handle_request(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
         "params": {"name": "take_screenshot", "arguments": {"backend": "profile:phone"}}},
        list(tools.values()))
    block = reply["result"]["content"][0]
    assert block["type"] == "image" and base64.b64decode(block["data"]) == png
    assert reply["result"]["_meta"] == {"width": 5, "height": 7}
    saved = T.call(tools, "take_screenshot", {"backend": "profile:phone", "out": "shot"})
    assert saved["path"].endswith("shot.png") and (tmp_path / "shot.png").read_bytes() == png
    assert tools["take_screenshot"].annotations["readOnlyHint"] is False


def test_the_tools_list_and_manifest_carry_the_group(tmp_path):
    from core import mcp_groups as G
    from core import mcp_server as M

    assert "adb" in G.GROUPS and G.GROUPS.index("adb") == G.GROUPS.index("remote") + 1
    tools = _served(tmp_path, FakeShell(PHONE_RULES))
    manifest = G.tool_manifest(list(tools.values()), groups=("remote", "adb"), allow_write=True,
                               allow_scripts=False)
    rows = {t["name"]: t for t in manifest["tools"] if t["group"] == "adb"}
    assert rows["stop_app"]["required_flags"] == ["--mcp-tools adb", "--mcp-write", "--mcp-root DIR"]
    assert rows["take_screenshot"]["required_flags"] == ["--mcp-tools adb"]
    assert rows["get_device_info"]["timeout_class"] == "walk"
    assert "device changes (adb)" in M.SERVER_INSTRUCTIONS


# -- end to end: the real ADB client against a fake phone ------------------------------------------

adb_client = pytest.importorskip("core.adb_client")


@pytest.fixture()
def phone(tmp_path, monkeypatch):
    if not adb_client.ADB_SHELL_AVAILABLE:  # pragma: no cover - optional dependency
        pytest.skip("adb-shell not installed")
    sys.path.insert(0, str(ROOT / "tests"))
    from fake_adbd import FakeAdbd, make_device_tree
    from fake_android import Phone

    key = tmp_path / "android" / "adbkey"
    adb_client.ensure_adb_key(str(key))
    root = str(tmp_path / "device")
    make_device_tree(root)
    android = Phone(tmp_path / "android-bin").install()
    monkeypatch.setenv("AXROSS_FAKE_ANDROID", str(android.folder))
    monkeypatch.setenv("PATH", str(android.bin))
    device = FakeAdbd(root, auth="key", authorized=[Path(str(key) + ".pub").read_text()])
    session = adb_client.AdbSession("127.0.0.1", device.port, adb_key_path=str(key))
    yield session, android, device
    session.close()
    device.stop()


def _schema_call(tools, name, args):
    from core import mcp_server as M

    reply = M._handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                               "params": {"name": name, "arguments": args}}, list(tools.values()),
                              protocol=M.ProtocolState("2025-11-25"))["result"]
    assert not reply.get("isError"), reply
    if M.jsonschema is not None and tools[name].output_schema is not None:
        M.jsonschema.validate(reply["structuredContent"], tools[name].output_schema)
    return reply


def test_e2e_every_tool_against_the_fake_phone(phone, tmp_path):
    from core import mcp_groups

    session, android, _device = phone
    root = tmp_path / "mcp"
    (root / "backup").mkdir(parents=True)
    (root / "app.apk").write_bytes(b"PK\x03\x04" + os.urandom(200_000))
    registry = mcp_groups.RemoteRegistry()
    registry.attach("profile:phone", session, _profile())
    tools = T.build(root, ("remote", "adb"), allow_write=True, remote_registry=registry)
    b = {"backend": "profile:phone"}
    info = _schema_call(tools, "get_device_info", b)["structuredContent"]
    assert info["model"] == "Pixel 6" and info["imei"] == "490154203237518" and info["sdk"] == 34
    props = _schema_call(tools, "list_device_properties", {**b, "filter": "ro.product.*"})
    assert props["structuredContent"]["properties"]["ro.product.brand"] == "google"
    assert _schema_call(tools, "get_battery_status", b)["structuredContent"]["level_percent"] == 85
    apps = _schema_call(tools, "list_apps", b)["structuredContent"]["apps"]
    assert {a["package"] for a in apps} == {"com.android.settings", "org.example.notes"}
    detail = _schema_call(tools, "get_app_info", {**b, "package": "org.example.notes"})["structuredContent"]
    assert detail["runtime_permissions"] == [{"name": "android.permission.CAMERA", "granted": False}]
    running = _schema_call(tools, "list_running_apps", b)["structuredContent"]
    assert running["foreground"] == "org.example.notes"
    assert _schema_call(tools, "get_logcat", {**b, "package": "org.example.notes"})["structuredContent"]["count"] == 1
    shot = _schema_call(tools, "take_screenshot", b)
    assert shot["content"][0]["type"] == "image" and shot["_meta"] == {"width": 3, "height": 2}
    granted = _schema_call(tools, "grant_permission", {**b, "package": "org.example.notes",
                                                       "permission": "android.permission.CAMERA"})
    assert granted["structuredContent"]["granted"] is True
    assert _schema_call(tools, "start_app", {**b, "package": "org.example.notes"})["structuredContent"]["started"]
    assert _schema_call(tools, "stop_app", {**b, "package": "org.example.notes"})["structuredContent"]["stopped"]
    installed = _schema_call(tools, "install_app", {**b, "path": "app.apk", "grant_permissions": True})
    assert installed["structuredContent"]["installed"] is True
    state = android.load()
    assert state["installed_flags"] == [["-r", "-g"]] and "com.example.installed" in state["apps"]
    assert not list((Path(_device.root) / "data" / "local" / "tmp").iterdir())  # removed again
    written = _schema_call(tools, "write_sms", {**b, "address": "+491511", "body": "one\n'two' $(x)"})
    assert written["structuredContent"]["stored"] is True
    assert android.load()["sms"][0]["body"] == "one\n'two' $(x)"
    listed = _schema_call(tools, "list_sms", b)["structuredContent"]
    assert listed["messages"][0]["body"] == "one\n'two' $(x)"
    composed = _schema_call(tools, "compose_sms", {**b, "number": "+4915112345678", "text": "Hallo\nWelt"})
    assert composed["structuredContent"]["sent"] is False
    assert android.load()["composed"] == {"uri": "sms:+4915112345678", "body": "Hallo\nWelt"}
    with pytest.raises(T.RpcError, match="no modem"):
        T.call(tools, "send_at_command", {**b, "command": "AT+CSQ"})
    assert _schema_call(tools, "uninstall_app", {**b, "package": "com.example.installed"})[
        "structuredContent"]["uninstalled"]
    assert _schema_call(tools, "reboot_device", {**b, "mode": "recovery"})["structuredContent"]["rebooting"]
    assert android.load()["reboots"] == [["recovery"]]
    # Every argument arrived as one word, exactly as sent.
    argv = android.argv()
    assert ["pm", "grant", "org.example.notes", "android.permission.CAMERA"] in argv
    assert ["content", "insert", "--uri", "content://sms/inbox", "--bind", "address:s:+491511",
            "--bind", "body:s:one\n'two' $(x)"] == [a for a in argv if a[:2] == ["content", "insert"]][0][:8]


def test_e2e_export_app_pulls_the_apks(phone, tmp_path):
    from core import mcp_groups

    session, android, device = phone
    base = Path(device.root) / "data" / "app" / "~~a1==" / "org.example.notes-b2=="
    base.mkdir(parents=True)
    (base / "base.apk").write_bytes(b"PK\x03\x04" + b"b" * 70_000)
    (base / "split_config.arm64_v8a.apk").write_bytes(b"PK\x03\x04split")
    root = tmp_path / "mcp"
    root.mkdir()
    registry = mcp_groups.RemoteRegistry()
    registry.attach("profile:phone", session, _profile())
    tools = T.build(root, ("remote", "adb"), allow_write=True, remote_registry=registry)
    out = _schema_call(tools, "export_app", {"backend": "profile:phone", "package": "org.example.notes"})
    files = out["structuredContent"]["files"]
    assert [os.path.basename(f["path"]) for f in files] == ["org.example.notes-120-base.apk",
                                                            "org.example.notes-120-split_config.arm64_v8a.apk"]
    assert (root / "org.example.notes-120-base.apk").read_bytes() == (base / "base.apk").read_bytes()


def test_e2e_a_device_without_sms_access_says_why(phone, tmp_path):
    from core import mcp_groups

    session, android, _device = phone
    state = android.load()
    state["sms_readable"] = False
    android.save(state)
    registry = mcp_groups.RemoteRegistry()
    registry.attach("profile:phone", session, _profile())
    tools = T.build(tmp_path, ("remote", "adb"), allow_write=True, remote_registry=registry)
    with pytest.raises(T.RpcError, match="READ_SMS"):
        T.call(tools, "list_sms", {"backend": "profile:phone"})


def test_list_tools_without_write_has_no_changing_tool(tmp_path):
    env = {k: v for k, v in os.environ.items() if not k.startswith("AXROSS_")}
    env.update(HOME=str(tmp_path), XDG_CONFIG_HOME=str(tmp_path / "c"), QT_QPA_PLATFORM="offscreen",
               PYTHON_KEYRING_BACKEND="keyring.backends.null.Keyring")
    proc = subprocess.run([sys.executable, str(ROOT / "main.py"), "--mcp-list-tools", "--mcp-tools",
                           "remote,adb"], capture_output=True, text=True, timeout=120, env=env, cwd=tmp_path)
    assert proc.returncode == 0, proc.stderr[-2000:]
    names = {t["name"] for t in json.loads(proc.stdout)["tools"]}
    assert {"get_device_info", "list_sms", "take_screenshot", "get_logcat"} <= names
    assert not names & A.MUTATING
