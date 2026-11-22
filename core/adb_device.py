"""Android device tools over ADB: what the phone is, its properties, its
apps and their permissions, its battery, its log, its screen, its SMS
store and its modem.

This module only builds ``adb shell`` command lines and reads their
answers; the connection is the caller's. It takes a *shell*: any object
with

* ``exec(command, *, timeout, stdout_cap)`` - run one ``sh`` command line
  on the device and return an object with ``returncode`` (int),
  ``stdout`` (bytes, stderr mixed in) and ``truncated_stdout`` (bool), as
  :meth:`core.adb_client.AdbSession.exec` does;
* ``push_stream(source, remote_path)`` - send the open binary file
  *source* to *remote_path* on the device (mode 0644);
* ``pull_stream(remote_path, sink, max_bytes)`` - write the device file
  *remote_path* into the open binary file *sink*, OSError past
  *max_bytes* (take_screenshot and export_app only).

It imports nothing of axross, so another server can carry it unchanged
next to its own connection code.

Every command is built as an argument vector and each argument quoted for
the device's ``sh`` (:func:`shell_line`); an argument with a control
character other than a tab is refused (no quoting is safe for every line
an ``adb shell`` command passes through), and so is a command line longer
than :data:`MAX_COMMAND_BYTES`. Every input is checked against a narrow
pattern before it gets there: package, activity and permission names,
property filters, log tags, phone numbers, SMS boxes, AT commands and
modem devices. Every answer is read as untrusted text: decoded, control,
bidi and other invisible characters dropped (:func:`clean`), every field
and every list bounded, numbers read as ASCII digits only. Where an app's
own text can imitate the lines of an answer (an app's versionName in
``dumpsys package``, a property value with a line break), the parser says
so instead of trusting the copy.

Each call of :class:`AndroidTools` may carry a deadline and a cancel
check: no command then runs past the call's time.

What Android allows (the tools say so in their answers):

* identity (:meth:`AndroidTools.device_info`): the build properties are
  readable by the shell everywhere; the serial number on most builds; the
  IMEI / MEID only where the phone service answers the shell
  (``service call iphonesubinfo``; READ_PRIVILEGED_PHONE_STATE since
  Android 10) or a vendor property carries it - else ``imei`` is null and
  ``imei_note`` says why;
* apps: ``pm`` / ``cmd package`` / ``am`` / ``dumpsys`` work as the shell
  on every Android of the last decade; installing may still be refused by
  the phone (Xiaomi's "Install via USB", Android 14's minimum target SDK);
  only runtime permissions can be granted or revoked;
* SMS: reading needs READ_SMS, which the shell has on some builds only;
  writing works only for the default SMS app since Android 4.4 - the
  shell's insert is silently dropped, which :meth:`AndroidTools.write_sms`
  detects by reading the message back; sending is never done silently: the
  SMS app is opened with the number and text, a person taps Send;
* AT commands: only where a modem device node exists and the caller may
  open it - in practice root (``adb root`` on a userdebug build, or
  ``su``); everything else is refused with the reason.
"""

from __future__ import annotations

import fnmatch
import io
import os
import re
import secrets
import shlex
import stat
import time
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Limits
# ---------------------------------------------------------------------------

#: The longest text kept of one field of an answer (a property value, an
#: app's installer, a line of the device's output).
FIELD_CAP = 1000
#: The most a device answer may hold before it is cut (getprop, pm list).
OUTPUT_CAP = 8 * 1024 * 1024
#: The longest command line sent, as the device's sh gets it quoted once
#: more (core.adb_client.AdbSession.exec): adbd before Android 7 takes
#: 4 KiB, newer ones 1 MiB; far more than any tool here needs.
MAX_COMMAND_BYTES = 16 * 1024
#: Seconds one ordinary query may take.
QUERY_TIMEOUT = 60.0
#: Seconds ``pm install`` / ``pm uninstall`` may take.
INSTALL_TIMEOUT = 600.0
MAX_PROPERTIES = 5000
MAX_APPS = 5000
#: The biggest APK install_app sends and export_app copies.
MAX_APK_BYTES = 4 * 1024 ** 3
#: The most APK files (base and splits) export_app copies of one app.
MAX_APK_FILES = 64
#: The biggest screenshot take_screenshot returns.
MAX_SCREENSHOT_BYTES = 12 * 1024 * 1024
#: get_logcat: the most lines, and the most bytes read.
LOGCAT_MAX_LINES = 2000
LOGCAT_BYTES = 2 * 1024 * 1024
#: get_app_info: the most permissions listed per kind.
MAX_PERMISSIONS = 1000
#: SMS: the most messages one list_sms call returns, the longest body kept
#: by default and at most, the longest body write_sms / compose_sms take.
SMS_MAX_LIMIT = 50
SMS_BODY_DEFAULT = 1000
SMS_BODY_MAX = 4000
SMS_TEXT_MAX = 1600
#: AT commands: the longest one, the longest reply kept, seconds to wait.
AT_MAX_LEN = 256
AT_REPLY_CAP = 4096
AT_TIMEOUT_DEFAULT = 5
AT_TIMEOUT_MAX = 30
#: Seconds kept back from a call's deadline for the answer itself.
DEADLINE_MARGIN = 2.0

# ---------------------------------------------------------------------------
# Input patterns (ASCII only: Python's \d and str.isdigit take other digits)
# ---------------------------------------------------------------------------

_NAME = r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)*"
#: An Android package name (``android``, ``com.example.app``).
PACKAGE_RE = re.compile(_NAME)
#: An activity: a class name, absolute or relative to the package (``.Main``).
_CLASS = r"\.?[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*"
ACTIVITY_RE = re.compile(_CLASS)
#: ``package/activity`` as ``cmd package resolve-activity --brief`` prints it.
COMPONENT_RE = re.compile(f"({_NAME})/({_CLASS})")
#: A permission name (``android.permission.CAMERA``, an app's own).
PERMISSION_RE = re.compile(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+")
#: A property filter: a name or a glob of names (``ro.build.*``).
PROPERTY_FILTER_RE = re.compile(r"[A-Za-z0-9_.:@*?\-]{1,128}")
_PROPERTY_NAME_RE = re.compile(r"[A-Za-z0-9_.:@\-]{1,256}")
_PROPERTY_LINE_RE = re.compile(r"\[([^\]\n]{1,256})\]: \[(.*)")
#: A log tag filter.
LOG_TAG_RE = re.compile(r"[A-Za-z0-9_.\-]{1,64}")
LOG_PRIORITIES = ("V", "D", "I", "W", "E", "F")
#: The address a message is stored under: a phone number or a sender name.
SMS_ADDRESS_RE = re.compile(r"[0-9A-Za-z+#*() .\-]{1,40}")
#: A number a message is composed to: digits, a leading +, * and #.
PHONE_NUMBER_RE = re.compile(r"\+?[0-9*#]{2,20}")
#: Characters an AT command may hold: no ';' (one command per call), no
#: quote, backslash, '$' or '`'.
AT_COMMAND_RE = re.compile(r"[Aa][Tt][A-Za-z0-9+#*=?,.:\"&%!/<>@^_()\- ]{0," + str(AT_MAX_LEN - 2) + "}")
#: Modem device nodes an AT command may be written to.
MODEM_DEVICE_RE = re.compile(
    r"/dev/(?:smd[0-9]{1,3}|umts_atc[0-9]|at_mdm[0-9]|ttyUSB[0-9]{1,2}|ttyACM[0-9]{1,2}"
    r"|ttyMT[0-9]{1,2}|ttyGS[0-9]|radio/(?:atci|pttycmd|pttynoti|ttyC)[0-9A-Za-z_]{0,16})")
#: Where an AT port is on the phones known to have one (Qualcomm smd,
#: Samsung umts_atc, MediaTek radio/, USB modems).
MODEM_CANDIDATES = (
    "/dev/smd11", "/dev/smd7", "/dev/smd8", "/dev/smd0", "/dev/umts_atc0", "/dev/at_mdm0",
    "/dev/radio/atci1", "/dev/radio/pttycmd1", "/dev/ttyACM0", "/dev/ttyUSB0", "/dev/ttyUSB1",
    "/dev/ttyUSB2", "/dev/ttyUSB3",
)
#: An APK path ``pm path`` prints (``/data/app/~~x==/com.x-y==/base.apk``).
APK_PATH_RE = re.compile(r"/[A-Za-z0-9._~+=,@\-]+(?:/[A-Za-z0-9._~+=,@\-]+)*\.apk")
#: reboot's targets.
REBOOT_MODES = ("system", "recovery", "bootloader")

#: SMS boxes: the URI of each and the ``type`` column's value.
SMS_BOXES = {"all": ("content://sms", None), "inbox": ("content://sms/inbox", 1),
             "sent": ("content://sms/sent", 2), "draft": ("content://sms/draft", 3),
             "outbox": ("content://sms/outbox", 4), "failed": ("content://sms/failed", 5),
             "queued": ("content://sms/queued", 6)}
SMS_TYPES = {value: name for name, (_uri, value) in SMS_BOXES.items() if value is not None}
#: The boxes write_sms stores into.
SMS_WRITE_BOXES = ("inbox", "sent", "draft")

#: Characters dropped from every answer: C0 / C1 controls but tab and line
#: feed, the invisible and bidirectional formatting characters (U+061C,
#: U+200B-U+200F, U+202A-U+202E, U+2060-U+206F among them), variation
#: selectors and the Unicode tag characters (invisible text an LLM reads).
CONTROL_CHARS = (
    "\x00-\x08\x0b-\x1f\x7f-\x9f\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180b-\u180f"
    "\u200b-\u200f\u2028-\u202e\u2060-\u206f\u3164\ufe00-\ufe0f\ufeff\uffa0\ufff9-\ufffb"
    "\U0001d173-\U0001d17a\U000e0000-\U000e007f\U000e0100-\U000e01ef")
_CONTROL_RE = re.compile(f"[{CONTROL_CHARS}]")
#: What a command argument may not hold: every C0 control but tab, and DEL.
_ARG_REFUSED = re.compile("[\x00-\x08\x0a-\x1f\x7f]")


class DeviceRefused(OSError):
    """The device (Android) refused what was asked; the message says why."""


# ---------------------------------------------------------------------------
# Text and commands
# ---------------------------------------------------------------------------


def clean(text, cap: int = FIELD_CAP, *, lines: bool = False) -> str:
    """*text* (bytes or str) as text to hand out: decoded, CR dropped,
    control, bidi and invisible characters removed (line feeds and tabs
    kept only with *lines*, else they become blanks), at most *cap*
    characters."""
    if isinstance(text, (bytes, bytearray)):
        text = bytes(text).decode("utf-8", "replace")
    text = str(text).replace("\r", "")
    if not lines:
        text = text.replace("\n", " ").replace("\t", " ")
    text = _CONTROL_RE.sub("", text)
    if len(text) > cap:
        return text[:cap]
    return text


def ascii_int(text, *, signed: bool = False) -> int | None:
    """The ASCII integer *text* is, else None (U+00B2's isdigit() is true, and
    int() of it raises)."""
    if not isinstance(text, str):
        return None
    text = text.strip()
    if re.fullmatch(r"-?[0-9]{1,18}" if signed else r"[0-9]{1,18}", text):
        return int(text)
    return None


def shell_line(*argv: str) -> str:
    """The argument vector *argv* as one command line for the device's
    ``sh``, each argument quoted. ValueError for an argument holding a
    control character other than a tab."""
    for arg in argv:
        if not isinstance(arg, str):
            raise TypeError("a command argument must be a string")
        if _ARG_REFUSED.search(arg):
            raise ValueError("a command argument holds a control character (NUL, CR, LF, ESC ...)")
    return " ".join(shlex.quote(arg) for arg in argv)


def printf_arg(text: str) -> str:
    """A shell word that expands to *text* with its line feeds: ``"$(printf
    %b QUOTED)"``, where QUOTED has each backslash doubled and each line
    feed written ``\\n`` - so the command line itself holds none. Trailing
    line feeds are dropped (command substitution removes them). A text
    without a line feed or backslash is simply quoted (no printf needed)."""
    if _ARG_REFUSED.search(text.replace("\n", "")):
        raise ValueError("the text holds a control character other than a line feed or tab")
    if "\n" not in text.rstrip("\n"):
        return shlex.quote(text.rstrip("\n"))
    escaped = text.rstrip("\n").replace("\\", "\\\\").replace("\n", "\\n")
    return '"$(printf %b ' + shlex.quote(escaped) + ')"'


#: Put in front of a command line that uses printf_arg's printf: Android
#: before 6.0 has no printf, and the substitution then gave an empty text.
NEEDS_PRINTF = "command -v printf >/dev/null 2>&1 || { echo AXNOPRINTF; exit 0; }; "


def check_package(value, key: str = "package") -> str:
    if not isinstance(value, str) or len(value) > 255 or not PACKAGE_RE.fullmatch(value):
        raise ValueError(f"{key} must be an Android package name such as com.example.app "
                         "(letters, digits, '_' and dots; list_apps lists them)")
    return value


def check_activity(value) -> str:
    if not isinstance(value, str) or len(value) > 255 or not ACTIVITY_RE.fullmatch(value):
        raise ValueError("activity must be a class name such as .MainActivity or "
                         "com.example.app.MainActivity")
    return value


def check_permission(value) -> str:
    if not isinstance(value, str) or len(value) > 255 or not PERMISSION_RE.fullmatch(value):
        raise ValueError("permission must be a permission name such as android.permission.CAMERA "
                         "(get_app_info lists an app's)")
    return value


def check_int(args: dict, key: str, default: int, minimum: int, maximum: int) -> int:
    value = args.get(key, default)
    if value is None:
        value = default
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{key} must be an integer from {minimum} to {maximum}")
    return value


def check_number(args: dict, key: str, default: float, minimum: float, maximum: float) -> float:
    value = args.get(key, default)
    if value is None:
        value = default
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not minimum <= value <= maximum:
        raise ValueError(f"{key} must be a number from {minimum:g} to {maximum:g}")
    return float(value)


def check_bool(args: dict, key: str, default: bool) -> bool:
    value = args.get(key, default)
    if value is None:
        return default
    if not isinstance(value, bool):
        raise ValueError(f"{key} must be true or false")
    return value


def check_choice(args: dict, key: str, default: str, choices) -> str:
    value = args.get(key, default)
    if value is None:
        value = default
    if not isinstance(value, str) or value not in choices:
        raise ValueError(f"{key} must be one of {', '.join(choices)}")
    return value


def _text(args: dict, key: str, maximum: int) -> str:
    value = args.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{key} must be a non-empty string")
    if len(value) > maximum:
        raise ValueError(f"{key} is longer than {maximum} characters")
    if _ARG_REFUSED.search(value.replace("\n", "")):
        raise ValueError(f"{key} holds a control character (only line feeds and tabs are taken)")
    return value


def iso_ms(value) -> str | None:
    """Milliseconds since 1970 (as the SMS store keeps dates) in ISO 8601."""
    ms = ascii_int(value) if isinstance(value, str) else (value if isinstance(value, int) else None)
    if ms is None or ms <= 0 or ms > 32503680000000:  # before 1970, after 3000
        return None
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def luhn_ok(digits: str) -> bool:
    """Whether *digits* (ASCII) passes the Luhn check (an IMEI's last digit)."""
    if not re.fullmatch(r"[0-9]+", digits or ""):
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = ord(ch) - 48
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def imei_or_none(value: str) -> str | None:
    """*value* when it is an IMEI: 15 ASCII digits, the last the Luhn
    check digit, not all zeros."""
    value = (value or "").strip()
    if re.fullmatch(r"[0-9]{15}", value) and luhn_ok(value) and value.strip("0"):
        return value
    return None


_PARCEL_WORDS_RE = re.compile(r"0x[0-9a-fA-F]{8}:((?: [0-9a-fA-F]{8}){1,4})")


def parcel_string(text: str) -> tuple[str | None, str]:
    """The string a ``service call`` answer carries, as ``(string, note)``:
    ``(None, why)`` for an exception, a null string or an answer that is no
    Parcel. The Parcel is the exception code (0: none) and a UTF-16 string
    (its length in characters, -1 for null)."""
    words = []
    for match in _PARCEL_WORDS_RE.finditer(text):
        words += match.group(1).split()
        if len(words) > 4096:
            break
    if not words:
        return None, "the phone service gave no Parcel"
    raw = b"".join(int(word, 16).to_bytes(4, "little") for word in words)
    if len(raw) < 8:
        return None, "the Parcel is too short"
    code = int.from_bytes(raw[:4], "little", signed=True)
    length = int.from_bytes(raw[4:8], "little", signed=True)
    if code != 0:
        message = ""
        if 0 < length < 512 and len(raw) >= 8 + 2 * length:
            message = raw[8:8 + 2 * length].decode("utf-16-le", "replace")
        return None, f"the phone service refused: {clean(message, 300) or 'exception ' + str(code)}"
    if length < 0:
        return None, "the phone service answered null"
    if length > 64 or len(raw) < 8 + 2 * length:
        return None, "the Parcel holds no short string"
    return raw[8:8 + 2 * length].decode("utf-16-le", "replace"), ""


def _first_error(text: str) -> str:
    """The first line of *text* that reads like an error, else its first line."""
    lines = [line.strip() for line in text.replace("\r", "").split("\n") if line.strip()]
    for line in lines:
        lowered = line.lower()
        if any(word in lowered for word in ("error", "exception", "denied", "failure", "not found",
                                            "unknown", "refused", "cannot", "can't", "no such",
                                            "not permitted")):
            return clean(line, 300)
    return clean(lines[0], 300) if lines else ""


def _not_found(status: int, out: str) -> bool:
    """Whether the command itself is missing on the device (sh's 127)."""
    lowered = out.lower()
    return status == 127 or ("not found" in lowered and len(lowered) < 300) \
        or "inaccessible or not found" in lowered


def png_size(data: bytes) -> tuple[int, int] | None:
    """``(width, height)`` of a PNG's IHDR, None when *data* is no PNG."""
    if len(data) < 24 or data[:8] != b"\x89PNG\r\n\x1a\n" or data[12:16] != b"IHDR":
        return None
    return int.from_bytes(data[16:20], "big"), int.from_bytes(data[20:24], "big")


class _Capped(io.BytesIO):
    """A sink that refuses more than *limit* bytes (a pull's answer)."""

    def __init__(self, limit: int, what: str) -> None:
        super().__init__()
        self._limit = limit
        self._what = what

    def write(self, data) -> int:  # type: ignore[override]
        if self.tell() + len(data) > self._limit:
            raise OSError(f"{self._what} is larger than {self._limit // (1024 * 1024)} MiB")
        return super().write(data)


class _Checked:
    """A file *fh* written through, *check* called before each chunk (a
    pull stops at the call's Cancel or deadline: the exception out of the
    write ends it, and the connection that carried it is dropped)."""

    def __init__(self, fh, check) -> None:
        self._fh = fh
        self._check = check

    def write(self, data) -> int:
        self._check()
        return self._fh.write(data)


class _Bounded(io.BytesIO):
    """The open APK *fh* as push_stream reads it: never more than *size*
    bytes (the size checked when it was opened; a file that grows while it
    is sent is cut there and refused), each read checked for Cancel."""

    def __init__(self, fh, size: int, check) -> None:
        super().__init__()
        self._fh = fh
        self._left = size
        self._check = check
        self.grew = False

    def read(self, n: int | None = -1) -> bytes:  # type: ignore[override]
        self._check()
        if n is None or n < 0 or n > self._left:
            n = self._left
        data = self._fh.read(n) if n else b""
        self._left -= len(data)
        if not self._left and not self.grew and self._fh.read(1):
            self.grew = True
        return data


# ---------------------------------------------------------------------------
# Parsers of device answers
# ---------------------------------------------------------------------------


def parse_getprop(out: str) -> dict[str, str]:
    """The properties of a ``getprop`` listing, values cleaned and bounded.

    getprop prints them sorted by name, one ``[name]: [value]`` each; a
    value with a line break goes on in the next lines. A line that reads
    like a property but is not after the one before in that order is part
    of a value (a value can imitate a property line), and of a name listed
    twice the later line counts (an imitation comes before the real one)."""
    props: dict[str, str] = {}
    last = None
    open_value = False
    for line in out.replace("\r", "").split("\n"):
        match = _PROPERTY_LINE_RE.fullmatch(line)
        name = match.group(1) if match is not None else None
        if name is not None and _PROPERTY_NAME_RE.fullmatch(name) and (last is None or name >= last):
            last = name
            value = match.group(2)
            open_value = not line.endswith("]")
            props[name] = clean(value[:-1] if not open_value else value)
            if len(props) >= MAX_PROPERTIES:
                break
        elif last is not None and open_value:
            open_value = not line.endswith("]")
            props[last] = clean(props[last] + " " + (line if open_value else line[:-1]))
    return props


def _package_entry(line: str) -> dict | None:
    """One ``pm list packages -i -U --show-versioncode`` line as a dict."""
    rest = line[len("package:"):].strip()
    parts = rest.split()
    if not parts:
        return None
    name = parts[0]
    if "=" in name and not PACKAGE_RE.fullmatch(name):
        name = name.rsplit("=", 1)[1]  # with -f: path=package
    if len(name) > 255 or not PACKAGE_RE.fullmatch(name):
        return None
    entry = {"package": name, "version_code": None, "uid": None, "installer": None}
    for token in parts[1:]:
        key, sep, value = token.partition(":") if token.startswith(("versionCode:", "uid:")) \
            else token.partition("=")
        if not sep:
            continue
        if key == "versionCode":
            entry["version_code"] = ascii_int(value)
        elif key == "uid":
            entry["uid"] = ascii_int(value.split(",")[0])
        elif key == "installer" and value != "null" and PACKAGE_RE.fullmatch(value):
            entry["installer"] = value
    return entry


def parse_ps(out: str) -> list[dict] | None:
    """The processes of a ``ps`` listing as ``{pid, user, rss_kb, name}``;
    None when the answer has no PID and NAME header (an old ps that took
    the options for a filter answers with the header alone: [])."""
    lines = [line for line in out.replace("\r", "").split("\n") if line.strip()]
    if not lines:
        return None
    header = lines[0].split()
    if "PID" not in header or not ({"NAME", "CMD", "ARGS"} & set(header)):
        return None
    pid_at = header.index("PID")
    user_at = header.index("USER") if "USER" in header else None
    rss_at = header.index("RSS") if "RSS" in header else None
    rows = []
    for line in lines[1:20001]:
        fields = line.split()
        if len(fields) < len(header):
            continue
        pid = ascii_int(fields[pid_at])
        if pid is None:
            continue
        rows.append({"pid": pid, "user": clean(fields[user_at], 64) if user_at is not None else None,
                     "rss_kb": ascii_int(fields[rss_at]) if rss_at is not None else None,
                     "name": clean(fields[-1], 255)})
    return rows


_BATTERY_STATUS = {1: "unknown", 2: "charging", 3: "discharging", 4: "not charging", 5: "full"}
_BATTERY_HEALTH = {1: "unknown", 2: "good", 3: "overheat", 4: "dead", 5: "over voltage",
                   6: "failure", 7: "cold"}


def parse_battery(out: str) -> dict:
    """``dumpsys battery`` as the battery's state."""
    values: dict[str, str] = {}
    for line in out.replace("\r", "").split("\n")[:200]:
        key, sep, value = line.strip().partition(": ")
        if sep and key and key not in values:
            values[key] = value.strip()
    if "level" not in values:
        raise DeviceRefused(f"dumpsys battery gave no battery state: {_first_error(out) or 'empty answer'}")
    level, scale = ascii_int(values.get("level")), ascii_int(values.get("scale")) or 100
    temp = ascii_int(values.get("temperature"), signed=True)
    plugged = [kind for kind, key in (("ac", "AC powered"), ("usb", "USB powered"),
                                      ("wireless", "Wireless powered"), ("dock", "Dock powered"))
               if values.get(key) == "true"]
    status, health = ascii_int(values.get("status")), ascii_int(values.get("health"))
    simulated = "UPDATES STOPPED" in out
    return {
        "level_percent": round(100 * level / scale) if level is not None and scale else None,
        "status": _BATTERY_STATUS.get(status, "unknown"),
        "health": _BATTERY_HEALTH.get(health, "unknown"),
        "plugged": plugged,
        "temperature_c": temp / 10 if temp is not None else None,
        "voltage_mv": ascii_int(values.get("voltage")),
        "technology": clean(values.get("technology") or "", 40) or None,
        "present": values.get("present") != "false",
        "simulated": simulated,
        "note": "values set with 'dumpsys battery set', not the battery's own: 'dumpsys battery "
                "reset' brings those back" if simulated else "",
    }


_DUMPSYS_KEYS = {"versionCode": "version_code", "minSdk": "min_sdk", "targetSdk": "target_sdk",
                 "versionName": "version_name", "firstInstallTime": "first_install_time",
                 "lastUpdateTime": "last_update_time", "installerPackageName": "installer",
                 "userId": "uid", "appId": "uid", "dataDir": "data_dir"}
_DATE_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}")
#: A permission line: ``name`` or ``name: granted=true, flags=[ ... ]`` (or
#: ``: restricted=true`` in the requested ones).
_PERM_LINE_RE = re.compile(r"(" + PERMISSION_RE.pattern + r")(?::(?: [^\n]{0,600})?)?")


def parse_dumpsys_package(out: str, package: str) -> dict:
    """The first ``Package [<package>]`` block of a ``dumpsys package``
    answer: version, SDKs, times, installer, uid, flags, requested,
    install and runtime permissions (user 0).

    An app's versionName is its own text and may hold line breaks that
    imitate dumpsys lines: a field or section met twice, or a block of
    another package in between, makes ``consistent`` false and those
    values null."""
    lines = out.replace("\r", "").split("\n")
    head = f"Package [{package}] ("
    start = next((i for i, line in enumerate(lines) if line.strip().startswith(head)), None)
    if start is None:
        raise DeviceRefused(f"dumpsys package gave no entry for {package}: "
                            f"{_first_error(out) or 'empty answer'}")
    indent = len(lines[start]) - len(lines[start].lstrip())
    info: dict = {v: None for v in _DUMPSYS_KEYS.values()}
    info.update(system=None, debuggable=None, flags=[], requested_permissions=[],
                install_permissions=[], runtime_permissions=[])
    seen: set[str] = set()
    doubled: set[str] = set()
    section = None
    user = None
    for line in lines[start + 1:start + 20001]:
        if not line.strip():
            continue
        depth = len(line) - len(line.lstrip())
        text = line.strip()
        if depth <= indent:
            if text.startswith("Package [") and not text.startswith(head):
                doubled.add("another package's block")
            break
        if text.endswith(":") and " " in text and text[:-1].replace(" ", "").isalpha():
            section = text[:-1]
            key = f"{user}:{section}" if section == "runtime permissions" else section
            if key in seen:
                doubled.add(section)
            seen.add(key)
            continue
        if text.startswith("User ") and ":" in text:
            user = ascii_int(text[5:].split(":", 1)[0])
            section = None
            continue
        if section in ("requested permissions", "install permissions", "runtime permissions"):
            match = _PERM_LINE_RE.fullmatch(text)
            if match is not None and depth > indent + 2:
                if section == "runtime permissions" and user not in (0, None):
                    continue  # another user's
                kind = section.split()[0]
                bucket = info[f"{kind}_permissions"]
                if len(bucket) < MAX_PERMISSIONS:
                    if kind == "requested":
                        bucket.append(match.group(1))
                    else:
                        bucket.append({"name": match.group(1),
                                       "granted": "granted=true" in text})
                continue
            if depth <= indent + 4 and "=" in text.split()[0]:
                section = None  # back at the package's fields
            else:
                continue
        whole = text.startswith(("versionName=", "firstInstallTime=", "lastUpdateTime="))
        for token in [text] if whole else text.split(" "):
            key, sep, value = token.partition("=")
            if not sep:
                continue
            if key in ("flags", "pkgFlags"):
                words = re.findall(r"[A-Z_]{2,40}", value + " " + text)
                info["flags"] = sorted(set(words))[:40]
                info["system"] = "SYSTEM" in words
                info["debuggable"] = "DEBUGGABLE" in words
                break
            target = _DUMPSYS_KEYS.get(key)
            if target is None:
                continue
            if key in seen:
                doubled.add(key)
            seen.add(key)
            if target in ("version_code", "min_sdk", "target_sdk", "uid"):
                info[target] = ascii_int(value)
            elif target in ("first_install_time", "last_update_time"):
                info[target] = value if _DATE_RE.fullmatch(value) else None
            elif target == "installer":
                info[target] = value if PACKAGE_RE.fullmatch(value) and value != "null" else None
            else:
                info[target] = clean(value, 200)
    for kind in ("requested", "install", "runtime"):
        names = [p if isinstance(p, str) else p["name"] for p in info[f"{kind}_permissions"]]
        if len(names) != len(set(names)):
            doubled.add(f"{kind} permissions")
    info["consistent"] = not doubled
    info["note"] = "" if not doubled else (
        "the package's dump lists " + ", ".join(sorted(doubled)) + " twice: the app's own text "
        "(its versionName) imitates dumpsys lines, so those values are not shown")
    if doubled:
        for key in doubled:
            if key in _DUMPSYS_KEYS:
                info[_DUMPSYS_KEYS[key]] = None
        if "another package's block" in doubled or "requested permissions" in doubled \
                or "install permissions" in doubled or "runtime permissions" in doubled:
            for kind in ("requested", "install", "runtime"):
                info[f"{kind}_permissions"] = []
            info["version_name"] = None
    return info


#: What pm install's failure codes mean, for the answer.
INSTALL_HINTS = {
    "INSTALL_FAILED_UPDATE_INCOMPATIBLE": "the installed app is signed with another key: uninstall it first",
    "INSTALL_FAILED_VERSION_DOWNGRADE": "the installed version is newer: allow_downgrade=true",
    "INSTALL_FAILED_ALREADY_EXISTS": "the app is installed: replace=true",
    "INSTALL_FAILED_DEPRECATED_SDK_VERSION": "Android 14 and newer refuse apps that target a very old "
                                             "Android (below API 23)",
    "INSTALL_FAILED_USER_RESTRICTED": "the phone refused installs over USB (a setting such as Xiaomi's "
                                      "'Install via USB', or the prompt on the phone was declined)",
    "INSTALL_FAILED_INSUFFICIENT_STORAGE": "the phone has not enough free storage",
    "INSTALL_PARSE_FAILED_NO_CERTIFICATES": "the APK is not signed",
    "INSTALL_FAILED_TEST_ONLY": "the APK is test-only (built by an IDE): allow_test_only=true",
    "INSTALL_FAILED_NO_MATCHING_ABIS": "the APK has no native code for this phone's CPU",
    "INSTALL_FAILED_OLDER_SDK": "the app needs a newer Android than this phone has",
    "INSTALL_FAILED_INVALID_APK": "the file is no valid APK",
    "INSTALL_FAILED_MISSING_SPLIT": "the app is split into several APKs; this tool installs one",
    "INSTALL_FAILED_VERIFICATION_FAILURE": "the phone's package verifier (Play Protect) refused it",
}


def install_refusal(out: str) -> str:
    """The message for a ``pm install`` answer that is no Success."""
    match = re.search(r"Failure \[([A-Z_]+)(?::\s*([^\]]*))?\]", out)
    if match is None:
        return f"Android refused the install: {_first_error(out) or 'no answer from pm install'}"
    code = match.group(1)
    hint = INSTALL_HINTS.get(code, "")
    detail = clean(match.group(2) or "", 300)
    return (f"Android refused the install: {code}" + (f" ({detail})" if detail else "")
            + (f" - {hint}" if hint else ""))


# ---------------------------------------------------------------------------
# The tools
# ---------------------------------------------------------------------------


class AndroidTools:
    """The device tools on *shell* (see the module's docstring).

    *deadline* (time.monotonic()) ends the call: a command is given at most
    the time left, and none starts once it has passed. *cancelled*, a
    callable, ends it when it returns true (checked before each command)."""

    def __init__(self, shell, *, deadline: float | None = None, cancelled=None) -> None:
        self.shell = shell
        self.deadline = deadline
        self.cancelled = cancelled

    # -- running ------------------------------------------------------------
    def check(self) -> None:
        """Raise when the call was cancelled or its time is up."""
        if self.cancelled is not None and self.cancelled():
            raise InterruptedError("the call was cancelled")
        if self.deadline is not None and time.monotonic() > self.deadline:
            raise TimeoutError("the call ran out of time before the device answered every query; "
                               "ask for less (max_results) or try again")

    def _timeout(self, timeout: float) -> float:
        self.check()
        if self.deadline is None:
            return timeout
        left = self.deadline - time.monotonic()
        if left < 1.0:
            raise TimeoutError("the call ran out of time before the device answered every query; "
                               "ask for less (max_results) or try again")
        return min(timeout, left)

    def run(self, *argv: str, timeout: float = QUERY_TIMEOUT, cap: int = OUTPUT_CAP) -> tuple[int, str]:
        """``(exit status, output)`` of the command *argv*."""
        return self.run_line(shell_line(*argv), timeout=timeout, cap=cap)

    def run_line(self, line: str, *, timeout: float = QUERY_TIMEOUT,
                 cap: int = OUTPUT_CAP) -> tuple[int, str]:
        if any(c in line for c in "\x00\r\n"):
            raise ValueError("a device command line holds a NUL, CR or LF")
        if len(shlex.quote(line).encode("utf-8", "surrogateescape")) > MAX_COMMAND_BYTES:
            raise ValueError(f"the command for the device is longer than {MAX_COMMAND_BYTES} bytes; "
                             "shorten the text")
        result = self.shell.exec(line, timeout=self._timeout(timeout), stdout_cap=cap)
        out = result.stdout
        if isinstance(out, (bytes, bytearray)):
            out = bytes(out).decode("utf-8", "replace")
        return int(result.returncode), out

    def getprops(self, names) -> dict[str, str]:
        """The values of the properties *names*, one ``getprop NAME`` each in
        one command, split by a random line no value can know (a full
        listing can be imitated by a value with line breaks)."""
        tag = "AXPROP" + secrets.token_hex(8)
        line = "; ".join(f"{shell_line('getprop', name)}; echo {tag}" for name in names)
        _status, out = self.run_line(line)
        parts = out.replace("\r", "").split(tag + "\n")
        if len(parts) < len(names):
            raise DeviceRefused(f"getprop gave no properties: {_first_error(out) or 'empty answer'}")
        return {name: clean(part.removesuffix("\n")) for name, part in zip(names, parts)}

    def properties(self) -> dict[str, str]:
        """Every property ``getprop`` lists (:func:`parse_getprop`)."""
        _status, out = self.run("getprop")
        props = parse_getprop(out)
        if not props:
            raise DeviceRefused(f"getprop gave no properties: {_first_error(out) or 'empty answer'}")
        return props

    # -- identity -------------------------------------------------------------
    _IDENTITY = (
        "ro.product.manufacturer", "ro.product.vendor.manufacturer", "ro.product.brand",
        "ro.product.vendor.brand", "ro.product.model", "ro.product.vendor.model",
        "ro.product.device", "ro.product.vendor.device", "ro.product.name", "ro.product.vendor.name",
        "ro.build.version.release_or_codename", "ro.build.version.release", "ro.build.version.sdk",
        "ro.build.version.security_patch", "ro.build.display.id", "ro.build.id",
        "ro.build.fingerprint", "ro.vendor.build.fingerprint", "ro.build.type",
        "ro.product.cpu.abilist", "ro.product.cpu.abi", "ro.serialno", "ro.boot.serialno",
    )
    #: Vendor properties some builds keep the IMEI in (MediaTek, Xiaomi, ...).
    _IMEI_PROPS = ("persist.radio.imei", "persist.radio.imei1", "ril.imei", "ro.ril.oem.imei",
                   "vendor.ril.imei", "persist.sys.imei")

    def device_info(self, args: dict | None = None) -> dict:
        props = self.getprops(self._IDENTITY + self._IMEI_PROPS)

        def prop(*names):
            for name in names:
                if props.get(name):
                    return props[name]
            return None

        sdk = ascii_int(prop("ro.build.version.sdk") or "")
        _status, uid_text = self.run("id", "-u", timeout=20.0)
        uid = ascii_int(uid_text)
        serial = prop("ro.serialno", "ro.boot.serialno")
        info = {
            "manufacturer": prop("ro.product.manufacturer", "ro.product.vendor.manufacturer"),
            "brand": prop("ro.product.brand", "ro.product.vendor.brand"),
            "model": prop("ro.product.model", "ro.product.vendor.model"),
            "device": prop("ro.product.device", "ro.product.vendor.device"),
            "product": prop("ro.product.name", "ro.product.vendor.name"),
            "android_version": prop("ro.build.version.release_or_codename", "ro.build.version.release"),
            "sdk": sdk,
            "security_patch": prop("ro.build.version.security_patch"),
            "build_id": prop("ro.build.display.id", "ro.build.id"),
            "build_fingerprint": prop("ro.build.fingerprint", "ro.vendor.build.fingerprint"),
            "build_type": prop("ro.build.type"),
            "abis": prop("ro.product.cpu.abilist", "ro.product.cpu.abi"),
            "serial": serial,
            "serial_note": "" if serial else (
                "not readable by the shell on this build (ro.serialno is empty or restricted)"),
            "shell_uid": uid,
            "root": uid == 0,
        }
        info.update(self._identifiers(sdk, props))
        return info

    def _identifiers(self, sdk: int | None, props: dict) -> dict:
        """IMEI or MEID through the phone service, where it answers the
        shell, else from a vendor property that holds a valid IMEI."""
        none = {"imei": None, "meid": None}
        argv = ["service", "call", "iphonesubinfo", "1"]
        if sdk is None or sdk >= 21:
            # getDeviceId(String callingPackage) since Android 5
            argv += ["s16", "com.android.shell"]
        status, out = self.run(*argv, timeout=20.0, cap=64 * 1024)
        value, note = parcel_string(out)
        if value is None and _not_found(status, out) or "can't find service" in out.lower():
            note = "this device has no phone service (no telephony, e.g. a tablet without SIM)"
        if value is not None:
            value = value.strip()
            if imei_or_none(value):
                return {**none, "imei": value, "imei_note": ""}
            if re.fullmatch(r"[0-9A-Fa-f]{14}", value):
                return {**none, "meid": value.upper(), "imei_note": "a CDMA phone: its MEID"}
            note = ("the phone service answered no device id (another Android version numbers it "
                    "differently, or the vendor hides it from the shell)")
        for name in self._IMEI_PROPS:
            found = imei_or_none(props.get(name) or "")
            if found:
                return {**none, "imei": found, "imei_note": f"from the vendor property {name} "
                                                            f"(the phone service: {note})"}
        return {**none, "imei_note": f"IMEI / MEID not readable: {note}"}

    def get_properties(self, args: dict) -> dict:
        pattern = args.get("filter") or "*"
        if not isinstance(pattern, str) or not PROPERTY_FILTER_RE.fullmatch(pattern):
            raise ValueError("filter must be a property name or a glob of names such as ro.build.* "
                             "(letters, digits, . _ - : @ * ?; at most 128)")
        limit = check_int(args, "max_results", 500, 1, MAX_PROPERTIES)
        props = self.properties()
        names = sorted(name for name in props if fnmatch.fnmatchcase(name, pattern))
        return {"properties": {name: props[name] for name in names[:limit]},
                "count": len(names), "truncated": len(names) > limit}

    def battery(self, args: dict | None = None) -> dict:
        _status, out = self.run("dumpsys", "battery", timeout=30.0, cap=256 * 1024)
        return parse_battery(out)

    # -- apps -----------------------------------------------------------------
    def _package_lines(self, *flags: str) -> list[str]:
        _status, out = self.run("pm", "list", "packages", *flags)
        lines = [line.strip() for line in out.replace("\r", "").split("\n")]
        found = [line for line in lines if line.startswith("package:")]
        if not found and any(word in out.lower()
                             for word in ("error", "exception", "unknown option", "denied")):
            raise DeviceRefused(f"pm list packages {' '.join(flags)}: {_first_error(out)}")
        return found

    def _package_set(self, *flags: str) -> set[str]:
        out = set()
        for line in self._package_lines(*flags):
            entry = _package_entry(line)
            if entry is not None:
                out.add(entry["package"])
        return out

    def list_apps(self, args: dict) -> dict:
        kind = check_choice(args, "kind", "all", ("all", "user", "system"))
        state = check_choice(args, "state", "any", ("any", "enabled", "disabled"))
        match = args.get("match") or ""
        if not isinstance(match, str) or len(match) > 255 or (match and not re.fullmatch(r"[A-Za-z0-9_.]+", match)):
            raise ValueError("match must be a part of a package name (letters, digits, '_' and dots)")
        limit = check_int(args, "max_results", 200, 1, MAX_APPS)
        offset = check_int(args, "offset", 0, 0, 1_000_000)
        which = {"all": [], "user": ["-3"], "system": ["-s"]}[kind]
        lines = None
        for extra in (["-i", "-U", "--show-versioncode"], ["-i", "-U"], ["-i"], []):
            try:
                lines = self._package_lines(*which, *extra)
                break
            except DeviceRefused as exc:
                if "unknown option" not in str(exc).lower() or not extra:
                    raise
        system = self._package_set("-s") if kind == "all" else set()
        disabled = self._package_set("-d")
        apps = []
        for line in lines or []:
            entry = _package_entry(line)
            if entry is None:
                continue
            name = entry["package"]
            if match and match.lower() not in name.lower():
                continue
            entry["system"] = kind == "system" or (kind == "all" and name in system)
            entry["enabled"] = name not in disabled
            if state != "any" and entry["enabled"] != (state == "enabled"):
                continue
            apps.append(entry)
            if len(apps) >= MAX_APPS:
                break
        apps.sort(key=lambda e: e["package"])
        page = apps[offset:offset + limit]
        return {"apps": page, "count": len(apps), "offset": offset,
                "truncated": offset + limit < len(apps)}

    def _apk_paths(self, package: str) -> list[str]:
        _status, out = self.run("pm", "path", package)
        paths = []
        for line in out.replace("\r", "").split("\n"):
            line = line.strip()
            if line.startswith("package:"):
                path = line[len("package:"):]
                if APK_PATH_RE.fullmatch(path) and "/../" not in path and len(path) < 1024:
                    paths.append(path)
        return paths[:MAX_APK_FILES]

    def _installed(self, package: str) -> list[str]:
        """The APK paths of *package*; DeviceRefused when it is not installed."""
        paths = self._apk_paths(package)
        if not paths:
            raise DeviceRefused(f"{package} is not installed on the device (list_apps lists the "
                                "installed ones)")
        return paths

    def processes(self) -> list[dict]:
        """Every process (``ps -A -o``; an Android before 8 lists them all
        with a plain ``ps``)."""
        _status, out = self.run("ps", "-A", "-o", "PID,USER,RSS,NAME", cap=4 * 1024 * 1024)
        rows = parse_ps(out)
        header = out.replace("\r", "").strip().split("\n", 1)[0].split()
        if not rows or header != ["PID", "USER", "RSS", "NAME"]:
            _status, out = self.run("ps", cap=4 * 1024 * 1024)
            rows = parse_ps(out)
        if rows is None:
            raise DeviceRefused(f"ps gave no process list: {_first_error(out) or 'empty answer'}")
        return rows

    def _pids(self, package: str) -> list[int] | None:
        """The process ids of *package*'s main process, None when neither
        pidof nor ps answers."""
        status, out = self.run("pidof", package)
        if not _not_found(status, out):
            return [pid for pid in (ascii_int(w) for w in out.split()) if pid is not None]
        try:
            rows = self.processes()
        except DeviceRefused:
            return None
        return [row["pid"] for row in rows if row["name"] == package]

    def _foreground(self) -> str | None:
        _status, out = self.run("dumpsys", "activity", "activities", cap=4 * 1024 * 1024)
        match = re.search(r"(?:mResumedActivity|topResumedActivity|ResumedActivity)[:=] ?"
                          r"ActivityRecord\{[0-9a-f]+ u[0-9]+ (" + _NAME + r")/", out)
        return match.group(1) if match else None

    def running_apps(self, args: dict) -> dict:
        limit = check_int(args, "max_results", 200, 1, MAX_APPS)
        installed = self._package_set()
        apps: dict[str, list] = {}
        for row in self.processes():
            package, _sep, suffix = row["name"].partition(":")
            if package in installed and (not suffix or re.fullmatch(r"[A-Za-z0-9_.]{1,64}", suffix)):
                apps.setdefault(package, []).append(row)
        try:
            foreground = self._foreground()
        except (DeviceRefused, ValueError):
            foreground = None
        listed = [{"package": name, "foreground": name == foreground,
                   "processes": sorted(rows, key=lambda r: r["pid"])[:32]}
                  for name, rows in sorted(apps.items())]
        return {"apps": listed[:limit], "count": len(listed),
                "foreground": foreground if foreground in apps else None,
                "truncated": len(listed) > limit}

    def app_info(self, args: dict) -> dict:
        package = check_package(args.get("package"))
        paths = self._installed(package)
        _status, out = self.run("dumpsys", "package", package, cap=4 * 1024 * 1024)
        info = parse_dumpsys_package(out, package)
        disabled = package in self._package_set("-d")
        return {"package": package, "apk_paths": paths, "enabled": not disabled, **info}

    def start_app(self, args: dict) -> dict:
        package = check_package(args.get("package"))
        activity = args.get("activity")
        self._installed(package)
        if activity:
            component = f"{package}/{check_activity(activity)}"
        else:
            _status, out = self.run("cmd", "package", "resolve-activity", "--brief",
                                    "-a", "android.intent.action.MAIN",
                                    "-c", "android.intent.category.LAUNCHER", package)
            found = [line.strip() for line in out.split("\n") if COMPONENT_RE.fullmatch(line.strip())
                     and line.strip().startswith(package + "/")]
            component = found[-1] if found else ""
        if component:
            _status, out = self.run("am", "start", "-W", "-n", component, timeout=60.0)
            text = clean(out, 2000, lines=True).strip()
            if "Error" in out or "Exception" in out:
                raise DeviceRefused(f"am start {component}: {_first_error(out)}")
            return {"package": package, "component": component, "method": "am start",
                    "started": True, "already_running": "brought to the front" in out,
                    "output": text}
        # No launcher activity resolved (Android before 7 has no cmd package
        # resolve-activity): the monkey sends one launcher intent.
        _status, out = self.run("monkey", "-p", package, "-c", "android.intent.category.LAUNCHER", "1",
                                timeout=60.0)
        text = clean(out, 2000, lines=True).strip()
        if "Events injected: 1" not in out:
            raise DeviceRefused(f"{package} has no activity to launch ({_first_error(out) or 'monkey aborted'})")
        return {"package": package, "component": None, "method": "monkey", "started": True,
                "already_running": False, "output": text}

    def stop_app(self, args: dict) -> dict:
        package = check_package(args.get("package"))
        self._installed(package)
        _status, out = self.run("am", "force-stop", package)
        if out.strip():
            raise DeviceRefused(f"am force-stop {package}: {_first_error(out)}")
        pids = self._pids(package)
        running = None if pids is None else bool(pids)
        return {"package": package, "stopped": running is False, "running": running}

    def install_app(self, args: dict, source, *, one_name: bool = True) -> dict:
        """Install the APK *source*: a path (opened here without following
        a link) or an open binary file the caller confined. It must be a
        regular ZIP file of at most MAX_APK_BYTES with one name only (no
        hard link); it is pushed to a fresh name in /data/local/tmp,
        installed with ``pm install`` and removed again - also when the
        push or the install fails. *one_name* False takes a file with
        further hard links (a file a person picked, not one of a root
        whose confinement a second name could leave)."""
        replace = check_bool(args, "replace", True)
        grant = check_bool(args, "grant_permissions", False)
        downgrade = check_bool(args, "allow_downgrade", False)
        test_only = check_bool(args, "allow_test_only", False)
        name = args.get("path") if isinstance(args.get("path"), str) else ""
        if isinstance(source, (str, bytes, os.PathLike)):
            name = os.fsdecode(source)
            if not name.lower().endswith(".apk"):
                raise ValueError("path must name an .apk file (split APKs / .apks / .xapk are not taken)")
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0) \
                | getattr(os, "O_NONBLOCK", 0)
            try:
                fd = os.open(source, flags)
            except OSError as exc:
                raise OSError(f"install_app: cannot open {os.path.basename(name)}: "
                              f"{exc.strerror or exc} (a symbolic link is not followed)") from None
            fh = os.fdopen(fd, "rb")
        else:
            fh = source
        with fh:
            st = os.fstat(fh.fileno())
            if not stat.S_ISREG(st.st_mode):
                raise ValueError("install_app: path is not a regular file")
            if one_name and st.st_nlink > 1:
                raise ValueError("install_app: the APK has another name (a hard link); copy it "
                                 "into the MCP root as a file of its own")
            if st.st_size > MAX_APK_BYTES:
                raise ValueError(f"install_app: the APK is larger than {MAX_APK_BYTES >> 30} GiB")
            if hasattr(os, "set_blocking"):
                os.set_blocking(fh.fileno(), True)
            if fh.read(4) != b"PK\x03\x04":
                raise ValueError("install_app: the file is no APK (not a ZIP archive)")
            fh.seek(0)
            self.check()
            remote = f"/data/local/tmp/axross-install-{secrets.token_hex(8)}.apk"
            out = ""
            cleanup = ""
            try:
                bounded = _Bounded(fh, st.st_size, self.check)
                self.shell.push_stream(bounded, remote)
                if bounded.grew:
                    raise ValueError("install_app: the APK grew while it was sent; not installed")
                argv = ["pm", "install"] + (["-r"] if replace else []) + (["-g"] if grant else []) \
                    + (["-d"] if downgrade else []) + (["-t"] if test_only else []) + [remote]
                _status, out = self.run(*argv, timeout=INSTALL_TIMEOUT, cap=64 * 1024)
            finally:
                cleanup = self._remove_remote(remote)
        text = clean(out, 2000, lines=True).strip()
        if "Success" in out.split():
            return {"installed": True, "replace": replace, "grant_permissions": grant,
                    "allow_downgrade": downgrade, "size": st.st_size, "output": text,
                    "cleanup": cleanup}
        raise DeviceRefused(install_refusal(out) + (f" ({cleanup})" if cleanup else ""))

    def _remove_remote(self, remote: str) -> str:
        """Remove our file *remote* in /data/local/tmp; '' or why not
        (it runs past the call's deadline: a leftover is worse)."""
        try:
            result = self.shell.exec(shell_line("rm", "-f", remote), timeout=30.0, stdout_cap=4096)
            out = result.stdout.decode("utf-8", "replace") if isinstance(result.stdout, bytes) \
                else str(result.stdout)
            if out.strip():
                return f"{remote} may be left on the device: {_first_error(out)}"
        except (OSError, ValueError) as exc:
            return f"{remote} may be left on the device: {clean(str(exc), 200)}"
        return ""

    def uninstall_app(self, args: dict) -> dict:
        package = check_package(args.get("package"))
        keep = check_bool(args, "keep_data", False)
        paths = self._installed(package)
        if all(p.startswith(("/system/", "/product/", "/vendor/", "/system_ext/", "/apex/", "/odm/"))
               for p in paths):
            raise DeviceRefused(f"{package} is a system app (it lives in {paths[0].split('/')[1]}): "
                                "the shell cannot uninstall it (pm uninstall --user 0 would hide it "
                                "for one user only; that is not offered)")
        _status, out = self.run(*(["pm", "uninstall"] + (["-k"] if keep else []) + [package]),
                                timeout=INSTALL_TIMEOUT, cap=64 * 1024)
        if "Success" in out.split():
            return {"package": package, "uninstalled": True, "kept_data": keep}
        reason = _first_error(out) or "no answer"
        if "DELETE_FAILED_INTERNAL_ERROR" in out or "DELETE_FAILED_SYSTEM_APP" in out:
            reason += (" - a system app cannot be uninstalled by the shell (pm uninstall --user 0 "
                       "would remove it for one user only; that is not offered)")
        elif "DELETE_FAILED_DEVICE_POLICY_MANAGER" in out:
            reason += " - the app is a device administrator: turn that off on the phone first"
        raise DeviceRefused(f"Android refused to uninstall {package}: {reason}")

    def export_app(self, args: dict, place) -> dict:
        """Copy *package*'s APK files (base and splits) off the device:
        ``place(name, write)`` makes a new local file *name* and calls
        ``write(fh)`` to fill it (the caller confines and names it) and
        returns where it went."""
        package = check_package(args.get("package"))
        paths = self._installed(package)
        version = None
        for line in self._package_lines("--show-versioncode", package):
            entry = _package_entry(line)
            if entry is not None and entry["package"] == package:
                version = entry["version_code"]
        files = []
        total = 0
        for remote in paths:
            self.check()
            base = remote.rsplit("/", 1)[1]
            name = f"{package}-{version}-{base}" if version is not None else f"{package}-{base}"

            def write(fh, remote=remote):
                self.shell.pull_stream(remote, _Checked(fh, self.check), MAX_APK_BYTES)

            where, size = place(name, write)
            total += size
            files.append({"source": remote, "path": where, "size": size})
        return {"package": package, "version_code": version, "files": files, "total_size": total}

    def _permission(self, args: dict, verb: str) -> dict:
        package = check_package(args.get("package"))
        permission = check_permission(args.get("permission"))
        self._installed(package)
        _status, out = self.run("pm", verb, package, permission)
        if out.strip():
            reason = _first_error(out)
            hint = ""
            if "not a changeable permission type" in out or "not a runtime permission" in out:
                hint = " - only runtime (dangerous) and development permissions can be changed"
            elif "has not requested permission" in out:
                hint = " - the app does not declare it (get_app_info lists what it requests)"
            elif "Unknown permission" in out:
                hint = " - no such permission on this device"
            raise DeviceRefused(f"Android refused pm {verb} {permission}: {reason}{hint}")
        granted = None
        try:
            info = parse_dumpsys_package(
                self.run("dumpsys", "package", package, cap=4 * 1024 * 1024)[1], package)
            for entry in info["runtime_permissions"] + info["install_permissions"]:
                if entry["name"] == permission:
                    granted = entry["granted"]
        except (DeviceRefused, ValueError):
            pass
        return {"package": package, "permission": permission, "granted": granted}

    def grant_permission(self, args: dict) -> dict:
        return self._permission(args, "grant")

    def revoke_permission(self, args: dict) -> dict:
        return self._permission(args, "revoke")

    def reboot(self, args: dict) -> dict:
        mode = check_choice(args, "mode", "system", REBOOT_MODES)
        _status, out = self.run("echo", "AXALIVE", timeout=20.0)
        if "AXALIVE" not in out:
            raise DeviceRefused(f"the device does not answer: {_first_error(out) or 'no answer'}")
        argv = ["reboot"] + ([] if mode == "system" else [mode])
        try:
            status, out = self.run(*argv, timeout=20.0, cap=64 * 1024)
        except (OSError, TimeoutError):
            # The connection ends as the device goes down.
            status, out = 0, ""
        if "not permitted" in out.lower() or "permission denied" in out.lower():
            raise DeviceRefused(f"the device refused to reboot: {_first_error(out)} (this build "
                                "lets only root reboot from the shell)")
        if _not_found(status, out):
            raise DeviceRefused("this device has no reboot command for the shell")
        return {"rebooting": True, "mode": mode,
                "note": "The device is restarting; this connection is gone. Close the profile with "
                        "close_remote_profile and open it again once the device has booted."}

    # -- log and screen -----------------------------------------------------------
    def logcat(self, args: dict) -> dict:
        lines = check_int(args, "max_lines", 200, 1, LOGCAT_MAX_LINES)
        priority = check_choice(args, "min_priority", "V", LOG_PRIORITIES)
        buffer = check_choice(args, "buffer", "default", ("default", "crash"))
        tag = args.get("tag")
        if tag is not None and (not isinstance(tag, str) or not LOG_TAG_RE.fullmatch(tag)):
            raise ValueError("tag must be a log tag: letters, digits, '_', '.' and '-' (at most 64)")
        package = args.get("package")
        argv = ["logcat", "-d", "-v", "threadtime", "-t", str(lines)]
        if buffer == "crash":
            argv += ["-b", "crash"]
        if package is not None:
            check_package(package)
            pids = self._pids(package)
            if not pids:
                raise DeviceRefused(f"{package} is not running: its log lines are told by its process "
                                    "id (start_app starts it; list_running_apps lists what runs)")
            argv.append(f"--pid={min(pids)}")
        argv += [f"{tag}:{priority}", "*:S"] if tag else [f"*:{priority}"]
        status, out = self.run(*argv, timeout=60.0, cap=LOGCAT_BYTES)
        text = out.replace("\r", "")
        if package is not None and "--pid" in text[:500] and ("unknown" in text[:500].lower()
                                                             or "unrecognized" in text[:500].lower()):
            raise DeviceRefused("this logcat has no --pid (Android before 7): filter by tag instead")
        if status != 0 and not text.strip().startswith("-"):
            first = _first_error(text)
            if first and not re.match(r"[0-9]{2}-[0-9]{2} ", first):
                raise DeviceRefused(f"logcat refused: {first}")
        rows = [clean(line, FIELD_CAP) for line in text.split("\n")
                if line.strip() and not line.startswith("--------- beginning of")]
        cut = len(out.encode("utf-8", "replace")) >= LOGCAT_BYTES
        return {"lines": rows[-lines:], "count": len(rows[-lines:]),
                "truncated": cut or len(rows) >= lines}

    def screenshot(self, args: dict | None = None) -> dict:
        """The screen as PNG: ``screencap -p`` into a fresh file in
        /data/local/tmp, pulled (binary-safe, unlike its stdout through an
        old adbd's terminal) and removed."""
        remote = f"/data/local/tmp/axross-shot-{secrets.token_hex(8)}.png"
        sink = _Capped(MAX_SCREENSHOT_BYTES, "the screenshot")
        try:
            status, out = self.run("screencap", "-p", remote, timeout=30.0, cap=64 * 1024)
            if _not_found(status, out) or "error" in out.lower() or "denied" in out.lower():
                raise DeviceRefused(f"screencap failed: {_first_error(out) or 'no answer'}")
            self.check()
            self.shell.pull_stream(remote, _Checked(sink, self.check), MAX_SCREENSHOT_BYTES)
        finally:
            cleanup = self._remove_remote(remote)
        data = sink.getvalue()
        size = png_size(data)
        if size is None:
            raise DeviceRefused("screencap gave no PNG image (the screen may be off or the device "
                                "too old for screencap -p)")
        return {"png": data, "width": size[0], "height": size[1], "size": len(data),
                "cleanup": cleanup}

    # -- SMS ------------------------------------------------------------------
    def _content_refusal(self, out: str, what: str) -> DeviceRefused | None:
        if "Exception" in out or "Error while accessing provider" in out or "denied" in out.lower():
            reason = _first_error(out)
            hint = ""
            if "READ_SMS" in out or "Permission Denial" in out or "SecurityException" in out:
                hint = (" - the shell lacks READ_SMS / WRITE_SMS for the SMS store on this build "
                        "(Android lets only the default SMS app and holders of READ_SMS in)")
            return DeviceRefused(f"Android refused {what}: {reason}{hint}")
        return None

    def list_sms(self, args: dict) -> dict:
        box = check_choice(args, "box", "inbox", tuple(SMS_BOXES))
        limit = check_int(args, "max_results", 20, 1, SMS_MAX_LIMIT)
        offset = check_int(args, "offset", 0, 0, 1_000_000)
        body_cap = check_int(args, "max_body", SMS_BODY_DEFAULT, 1, SMS_BODY_MAX)
        uri = SMS_BOXES[box][0]
        _status, out = self.run("content", "query", "--uri", uri, "--projection", "_id",
                                "--sort", "date DESC")
        refused = self._content_refusal(out, "reading the SMS store")
        if refused is not None:
            raise refused
        ids = []
        for line in out.replace("\r", "").split("\n"):
            match = re.fullmatch(r"Row: [0-9]+ _id=([0-9]{1,12})", line.strip())
            if match:
                ids.append(match.group(1))
        if not ids and "No result found" not in out and out.strip():
            raise DeviceRefused(f"the SMS store gave no rows: {_first_error(out)}")
        messages = []
        for ident in ids[offset:offset + limit]:
            message = self._sms_row(ident, body_cap)
            if message is not None:
                messages.append(message)
        return {"box": box, "count": len(ids), "offset": offset, "messages": messages,
                "truncated": offset + limit < len(ids)}

    _SMS_ROW_RE = re.compile(
        r"Row: 0 _id=([0-9]+), thread_id=(\S*), date=(\S*), date_sent=(\S*), read=(\S*), "
        r"type=(\S*), address=(.*?), body=(.*)", re.S)

    def _sms_row(self, ident: str, body_cap: int) -> dict | None:
        _status, out = self.run("content", "query", "--uri", "content://sms", "--where", f"_id={ident}",
                                "--projection", "_id:thread_id:date:date_sent:read:type:address:body",
                                cap=256 * 1024)
        text = out.replace("\r", "").strip("\n")
        match = self._SMS_ROW_RE.match(text)
        if match is None or match.group(1) != ident:
            return None
        address, body = match.group(7), match.group(8)
        if ", body=" in body:
            # The sender's address may hold ", body=" itself: ask for it alone.
            _status, alone = self.run("content", "query", "--uri", "content://sms", "--where",
                                      f"_id={ident}", "--projection", "address", cap=64 * 1024)
            got = re.match(r"Row: 0 address=(.*)", alone.replace("\r", "").strip("\n"), re.S)
            if got is not None and text.find(", body=", match.start(7) + len(got.group(1))) >= 0:
                address = got.group(1)
                body = text[match.start(7) + len(address) + len(", body="):]
        cleaned = clean(body, body_cap, lines=True)
        kind = ascii_int(match.group(6))
        thread = ascii_int(match.group(2))
        return {
            "id": int(ident),
            "thread_id": thread,
            "address": clean(address, 64) if address != "NULL" else None,
            "date": iso_ms(match.group(3)),
            "date_sent": iso_ms(match.group(4)),
            "read": match.group(5) == "1",
            "box": SMS_TYPES.get(kind) if kind is not None else None,
            "body": cleaned if body != "NULL" else None,
            "body_truncated": body != "NULL" and len(clean(body, SMS_BODY_MAX * 4, lines=True)) > len(cleaned),
        }

    def write_sms(self, args: dict, *, now_ms: int | None = None) -> dict:
        box = check_choice(args, "box", "inbox", SMS_WRITE_BOXES)
        address = args.get("address")
        if not isinstance(address, str) or not SMS_ADDRESS_RE.fullmatch(address):
            raise ValueError("address must be a phone number or a sender name (letters, digits, "
                             "+ # * ( ) . - and blanks; at most 40)")
        body = _text(args, "body", SMS_TEXT_MAX)
        read = check_bool(args, "read", True)
        if now_ms is None:
            now_ms = int(time.time() * 1000)
        date = check_int(args, "date_ms", now_ms, 1, 32503680000000)
        uri, kind = SMS_BOXES[box]
        word = printf_arg(body)
        line = " ".join([
            shell_line("content", "insert", "--uri", uri, "--bind", f"address:s:{address}"),
            "--bind", (shlex.quote("body:s:") + word),
            shell_line("--bind", f"date:l:{date}", "--bind", f"read:i:{1 if read else 0}",
                       "--bind", f"type:i:{kind}"),
        ])
        if "printf" in word:
            line = NEEDS_PRINTF + line
        _status, out = self.run_line(line, cap=64 * 1024)
        if "AXNOPRINTF" in out:
            raise DeviceRefused("this Android has no printf (before 6.0): a text with line breaks "
                                "cannot be written; write it on one line")
        refused = self._content_refusal(out, "writing the SMS store")
        if refused is not None:
            raise refused
        # The shell's insert is dropped without a word where Android does not
        # let it write (app-op WRITE_SMS): only reading it back tells.
        _status, found = self.run("content", "query", "--uri", "content://sms", "--where",
                                  f"date={date}", "--projection", "_id", cap=256 * 1024)
        if self._content_refusal(found, "reading the SMS store") is not None:
            return {"stored": None, "id": None, "box": box, "date_ms": date,
                    "note": "written as asked, but not checked: the shell may not read the SMS store "
                            "on this build, so whether Android kept it is unknown"}
        ids = sorted({int(m.group(1)) for m in re.finditer(r"(?m)^Row: [0-9]+ _id=([0-9]{1,12})$",
                                                         found.replace("\r", ""))}, reverse=True)
        expected = clean(body.rstrip("\n"), SMS_TEXT_MAX, lines=True)
        for ident in ids[:20]:
            row = self._sms_row(str(ident), SMS_TEXT_MAX)
            if row is not None and row["address"] == clean(address, 64) and row["body"] == expected:
                return {"stored": True, "id": ident, "box": box, "date_ms": date, "note": ""}
        raise DeviceRefused(
            "Android did not store the message: since Android 4.4 only the default SMS app may "
            "write the SMS store, and a write of the shell (com.android.shell) is dropped without "
            "an error unless its app-op WRITE_SMS is allowed (as the shell: appops set "
            "com.android.shell WRITE_SMS allow - this tool does not change app-ops)")

    def compose_sms(self, args: dict) -> dict:
        number = args.get("number")
        if not isinstance(number, str) or not PHONE_NUMBER_RE.fullmatch(number):
            raise ValueError("number must be a phone number: digits, a leading +, * and # (2 to 20)")
        text = _text(args, "text", SMS_TEXT_MAX)
        word = printf_arg(text)
        line = " ".join([
            # '#' starts a URI's fragment: written %23, it stays part of the number.
            shell_line("am", "start", "-W", "-a", "android.intent.action.SENDTO", "-d",
                       "sms:" + number.replace("#", "%23"), "--es", "sms_body"),
            word,
            shell_line("--ez", "exit_on_sent", "true"),
        ])
        if "printf" in word:
            line = NEEDS_PRINTF + line
        _status, out = self.run_line(line, timeout=60.0, cap=64 * 1024)
        if "AXNOPRINTF" in out:
            raise DeviceRefused("this Android has no printf (before 6.0): a text with line breaks "
                                "cannot be prepared; write it on one line")
        if "Error" in out or "Exception" in out:
            raise DeviceRefused(f"no SMS app took the message ({_first_error(out)})")
        return {
            "sent": False, "composed": True, "number": number,
            "note": "The default SMS app is open on the phone with this number and text; nothing has "
                    "been sent. A person at the phone has to tap Send.",
            "why_not_sent": "Android gives the shell no stable way to send an SMS: the SMS service's "
                            "binder calls (service call isms) are numbered differently on every "
                            "Android version and vendor build, and a wrong number calls another "
                            "method of the service, so this tool never sends on its own.",
        }

    # -- AT commands ------------------------------------------------------------
    def send_at_command(self, args: dict) -> dict:
        command = args.get("command")
        if not isinstance(command, str) or not AT_COMMAND_RE.fullmatch(command):
            raise ValueError(f"command must be one AT command: AT followed by letters, digits and "
                             f"+ # * = ? , . : \" & % ! / < > @ ^ _ ( ) - and blanks, at most "
                             f"{AT_MAX_LEN} characters, no ';' (one command per call)")
        timeout = int(check_number(args, "timeout", AT_TIMEOUT_DEFAULT, 1, AT_TIMEOUT_MAX) + 0.999)
        wanted = args.get("device")
        if wanted is not None and (not isinstance(wanted, str) or not MODEM_DEVICE_RE.fullmatch(wanted)):
            raise ValueError("device must be a modem device node such as /dev/smd11, /dev/umts_atc0, "
                             "/dev/radio/atci1, /dev/ttyACM0 or /dev/ttyUSB2")
        candidates = [wanted] if wanted else list(MODEM_CANDIDATES)
        probe = "for d in " + " ".join(shlex.quote(c) for c in candidates) \
            + '; do [ -c "$d" ] && echo "AXDEV $d"; done; true'
        _status, out = self.run_line(probe, timeout=20.0, cap=64 * 1024)
        present = [m.group(1) for m in re.finditer(r"(?m)^AXDEV (\S+)$", out.replace("\r", ""))
                   if MODEM_DEVICE_RE.fullmatch(m.group(1)) and m.group(1) in candidates]
        if not present:
            raise DeviceRefused(
                (f"{wanted} is no character device on this phone" if wanted else
                 f"no modem device on this phone (looked for {', '.join(MODEM_CANDIDATES)})")
                + ". On most phones the modem is reached only by the radio daemon (rild) and "
                  "vendor services the shell cannot use; where a vendor exposes an AT port "
                  "(Qualcomm /dev/smd*, Samsung /dev/umts_atc0, MediaTek /dev/radio/*) it is "
                  "open to root only.")
        device = present[0]
        wrap, as_root = self._root_wrapper()
        script = (
            # (a failing exec redirection ends a non-interactive sh: tried in a subshell first)
            f"d={shlex.quote(device)}; ( exec 3<>\"$d\" ) 2>/dev/null || {{ echo AXAT_NOACCESS; exit 0; }}; "
            "command -v timeout >/dev/null 2>&1 || { echo AXAT_NOTIMEOUT; exit 0; }; "
            "exec 3<>\"$d\"; "
            "stty -F \"$d\" raw -echo 2>/dev/null; "
            f"( timeout {timeout} cat <&3 | head -c {AT_REPLY_CAP} ) & p=$!; sleep 0.3; "
            f"printf '%s\\r' {shlex.quote(command)} >&3; wait $p; echo; echo AXAT_DONE")
        line = wrap(script)
        _status, out = self.run_line(line, timeout=timeout + 20.0, cap=AT_REPLY_CAP + 4096)
        if "AXAT_NOTIMEOUT" in out:
            raise DeviceRefused("this device has no timeout command (Android before 6.0): the reply "
                                "could not be bounded, so nothing was sent")
        if "AXAT_NOACCESS" in out or ("Permission denied" in out and "AXAT_DONE" not in out):
            reason = _first_error(out.replace("AXAT_NOACCESS", ""))
            raise DeviceRefused(
                f"{device} exists but cannot be opened by the {'root ' if as_root else ''}shell"
                + ("" if as_root else ": it takes root (adb root on a userdebug build, or su), "
                                      "which this device does not give the shell")
                + (f" ({reason})" if reason else ""))
        reply = out.split("AXAT_DONE")[0]
        lines = [clean(line, 500) for line in reply.replace("\r", "\n").split("\n")]
        lines = [line.strip() for line in lines if line.strip()]
        if lines and lines[0].upper() == command.upper():
            lines = lines[1:]  # the modem's echo
        final = next((line for line in reversed(lines)
                      if line in ("OK", "ERROR", "NO CARRIER", "BUSY", "NO ANSWER", "NO DIALTONE")
                      or line.startswith(("+CME ERROR", "+CMS ERROR"))), None)
        return {"device": device, "command": command, "as_root": as_root, "reply": lines[:200],
                "status": final, "complete": final is not None,
                "note": "" if final is not None else
                f"no final result code within {timeout} s (the modem may be busy with the radio "
                "daemon, or this node is no AT port)"}

    def _root_wrapper(self):
        """``(wrap, as_root)``: *wrap* makes a script one command line - run
        by the shell itself when it is root (adb root) or no ``su`` gives
        root, else through ``su -c`` (Magisk, SuperSU) or ``su 0`` (the su
        of a userdebug build). Each probe is bounded (``timeout 10``): a su
        that asks on the phone does not hold the call."""
        def plain(script):
            return shell_line("sh", "-c", script)

        _status, uid = self.run("id", "-u", timeout=20.0)
        if ascii_int(uid) == 0:
            return plain, True
        _status, out = self.run_line("command -v su; command -v timeout", timeout=20.0)
        found = out.split()
        if not any(w.endswith("/su") for w in found) or not any(w.endswith("/timeout") for w in found):
            return plain, False
        _status, out = self.run_line("timeout 10 su -c 'id -u' 2>/dev/null", timeout=20.0)
        if out.strip().split("\n")[-1:] == ["0"]:
            return (lambda script: shell_line("su", "-c", script)), True
        _status, out = self.run_line("timeout 10 su 0 id -u 2>/dev/null", timeout=20.0)
        if out.strip().split("\n")[-1:] == ["0"]:
            return (lambda script: shell_line("su", "0", "sh", "-c", script)), True
        return plain, False


# ---------------------------------------------------------------------------
# The tool definitions (name, description, schemas, annotations)
# ---------------------------------------------------------------------------

#: Tools that change the device or the local folder, or reach someone.
MUTATING = frozenset({"start_app", "stop_app", "install_app", "uninstall_app", "export_app",
                      "grant_permission", "revoke_permission", "reboot_device", "write_sms",
                      "compose_sms", "send_at_command"})
#: Tools whose answer is private (messages, one-time codes, what the
#: screen and the log show).
PRIVATE = frozenset({"list_sms", "get_logcat", "take_screenshot"})
#: The tools a person should confirm before each call: everything that
#: changes the device or reaches someone, and the private reads.
ASK_FIRST = MUTATING | PRIVATE
#: Tools that change or remove what exists (destructiveHint).
DESTRUCTIVE = frozenset({"stop_app", "install_app", "uninstall_app", "revoke_permission",
                         "reboot_device", "send_at_command"})
#: What the axross server tells the model the device is.
DEVICE_REQUIRES = "an ADB profile opened with open_remote_profile"


def _annotations(title, *, read_only, destructive, idempotent):
    return {"title": title, "readOnlyHint": read_only, "destructiveHint": destructive,
            "idempotentHint": idempotent, "openWorldHint": True}


_PACKAGE_PROP = {"type": "string", "minLength": 1, "maxLength": 255,
                 "pattern": r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)*$",
                 "description": "The app's package name, e.g. 'com.example.app'."}
_S = {"type": "string"}
_SN = {"type": ["string", "null"]}
_I = {"type": "integer"}
_IN = {"type": ["integer", "null"]}
_B = {"type": "boolean"}
_BN = {"type": ["boolean", "null"]}


def _obj(props: dict, *required) -> dict:
    return {"type": "object", "properties": props, "required": list(required or props)}


def _arr(items: dict) -> dict:
    return {"type": "array", "items": items}


_APP_ROW = _obj({"package": _S, "version_code": _IN, "uid": _IN, "installer": _SN, "system": _B,
                 "enabled": _B})
_PERM_ROW = _obj({"name": _S, "granted": _B})


def tool_definitions(device_requires: str = DEVICE_REQUIRES) -> list[dict]:
    """The tools: each a dict of ``name``, ``title``, ``description``,
    ``properties``, ``required``, ``annotations``, ``output_schema`` (None:
    the answer is an image), ``timeout_class`` (core.mcp_server's names:
    walk 60 s, stream 5 min, long 30 min), ``mutating`` and ``method``
    (the :class:`AndroidTools` method)."""
    ro = dict(read_only=True, destructive=False, idempotent=True)
    req = f"Requires: {device_requires}"
    out = [
        {"name": "get_device_info", "title": "Android device info", "method": "device_info",
         "description": (
             "Identify the Android device: maker, model, Android version, SDK, security patch, build, "
             "CPU ABIs, serial, IMEI or MEID.\n"
             "Use when: knowing which phone this is or how current its patches are.\n"
             "Instead: list_device_properties for any other property.\n"
             f"{req}.\n"
             "Behavior: read-only. A value the shell may not read is null; its _note says why.\n"
             "Returns: {manufacturer, brand, model, device, product, android_version, sdk, "
             "security_patch, build_id, build_fingerprint, build_type, abis, serial, serial_note, "
             "imei, meid, imei_note, shell_uid, root}."),
         "properties": {}, "required": [], "annotations": _annotations("Android device info", **ro),
         "output_schema": _obj({k: (_IN if k in ("sdk", "shell_uid") else _B if k == "root" else
                                    _S if k.endswith("_note") else _SN)
                                for k in ("manufacturer", "brand", "model", "device", "product",
                                          "android_version", "sdk", "security_patch", "build_id",
                                          "build_fingerprint", "build_type", "abis", "serial",
                                          "serial_note", "imei", "meid", "imei_note", "shell_uid",
                                          "root")}),
         "timeout_class": "walk"},
        {"name": "list_device_properties", "title": "Android system properties",
         "method": "get_properties",
         "description": (
             "List the device's system properties (getprop) whose names match a glob.\n"
             "Use when: a detail get_device_info does not give (persist.*, gsm.*, a vendor's).\n"
             "Instead: get_device_info for the usual identity fields.\n"
             f"{req}.\n"
             f"Behavior: read-only; values cut at {FIELD_CAP} characters.\n"
             "Returns: {properties: {name: value}, count (matching), truncated}."),
         "properties": {
             "filter": {"type": "string", "minLength": 1, "maxLength": 128,
                        "pattern": r"^[A-Za-z0-9_.:@*?\-]+$", "default": "*",
                        "description": "A property name or a glob of names, e.g. 'ro.build.*'."},
             "max_results": {"type": "integer", "minimum": 1, "maximum": MAX_PROPERTIES, "default": 500,
                             "description": "The most properties returned."}},
         "required": [], "annotations": _annotations("Android system properties", **ro),
         "output_schema": _obj({"properties": {"type": "object", "additionalProperties": _S},
                                "count": _I, "truncated": _B}),
         "timeout_class": "walk"},
        {"name": "get_battery_status", "title": "Android battery status", "method": "battery",
         "description": (
             "Read the battery's charge, charging state, health, temperature and voltage "
             "(dumpsys battery).\n"
             "Use when: checking whether the phone charges or overheats.\n"
             "Instead: get_device_info for what the phone is.\n"
             f"{req}.\n"
             "Behavior: read-only; simulated is true when 'dumpsys battery set' overrides the "
             "values.\n"
             "Returns: {level_percent, status, health, plugged [ac, usb, wireless, dock], "
             "temperature_c, voltage_mv, technology, present, simulated, note}."),
         "properties": {}, "required": [], "annotations": _annotations("Android battery status", **ro),
         "output_schema": _obj({"level_percent": _IN, "status": _S, "health": _S, "plugged": _arr(_S),
                                "temperature_c": {"type": ["number", "null"]}, "voltage_mv": _IN,
                                "technology": _SN, "present": _B, "simulated": _B, "note": _S}),
         "timeout_class": "walk"},
        {"name": "list_apps", "title": "Installed Android apps", "method": "list_apps",
         "description": (
             "List the installed apps with version code, uid, installer, system or user app, "
             "enabled or not.\n"
             "Use when: finding a package name for the other app tools.\n"
             "Instead: get_app_info for one app's permissions; list_running_apps for what runs.\n"
             f"{req}.\n"
             "Behavior: read-only; older pm versions give fewer fields (null).\n"
             "Returns: {apps: [{package, version_code, uid, installer, system, enabled}], count, "
             "offset, truncated}, by package."),
         "properties": {
             "kind": {"type": "string", "enum": ["all", "user", "system"], "default": "all",
                      "description": "user: installed by the user; system: part of the system image."},
             "state": {"type": "string", "enum": ["any", "enabled", "disabled"], "default": "any",
                       "description": "Only enabled or only disabled apps."},
             "match": {"type": "string", "maxLength": 255, "pattern": r"^[A-Za-z0-9_.]*$",
                       "description": "Only packages whose name contains this (any case). "
                                      "Default: all."},
             "max_results": {"type": "integer", "minimum": 1, "maximum": MAX_APPS, "default": 200,
                             "description": "The most apps returned."},
             "offset": {"type": "integer", "minimum": 0, "maximum": 1_000_000, "default": 0,
                        "description": "Apps to skip (the next page)."}},
         "required": [], "annotations": _annotations("Installed Android apps", **ro),
         "output_schema": _obj({"apps": _arr(_APP_ROW), "count": _I, "offset": _I, "truncated": _B}),
         "timeout_class": "walk"},
        {"name": "get_app_info", "title": "Android app details", "method": "app_info",
         "description": (
             "Get one app's version, SDK levels, install times, installer, flags, APK paths and "
             "permissions (requested, install-time and runtime, granted or not).\n"
             "Use when: checking what an app may do or which version is installed.\n"
             "Instead: list_apps to find the package; grant_permission (needs --mcp-write) to "
             "change one.\n"
             f"{req}.\n"
             "Behavior: read-only (dumpsys package). consistent is false when the app's own "
             "versionName imitates dump lines; those values are then null.\n"
             "Returns: {package, apk_paths, enabled, version_code, version_name, min_sdk, target_sdk, "
             "first_install_time, last_update_time, installer, uid, data_dir, system, debuggable, "
             "flags, requested_permissions, install_permissions, runtime_permissions [{name, granted}], "
             "consistent, note}."),
         "properties": {"package": _PACKAGE_PROP}, "required": ["package"],
         "annotations": _annotations("Android app details", **ro),
         "output_schema": _obj({"package": _S, "apk_paths": _arr(_S), "enabled": _B,
                                "version_code": _IN, "version_name": _SN, "min_sdk": _IN,
                                "target_sdk": _IN, "first_install_time": _SN,
                                "last_update_time": _SN, "installer": _SN, "uid": _IN,
                                "data_dir": _SN, "system": _BN, "debuggable": _BN,
                                "flags": _arr(_S), "requested_permissions": _arr(_S),
                                "install_permissions": _arr(_PERM_ROW),
                                "runtime_permissions": _arr(_PERM_ROW), "consistent": _B,
                                "note": _S}),
         "timeout_class": "walk"},
        {"name": "list_running_apps", "title": "Running Android apps", "method": "running_apps",
         "description": (
             "List the apps that have a process now, with process ids and memory, and the app in "
             "front.\n"
             "Use when: checking whether an app runs before stop_app (needs --mcp-write) or "
             "get_logcat.\n"
             "Instead: list_apps for every installed app.\n"
             f"{req}.\n"
             "Behavior: read-only (ps, dumpsys activity).\n"
             "Returns: {apps: [{package, foreground, processes: [{pid, user, rss_kb, name}]}], count, "
             "foreground, truncated}."),
         "properties": {
             "max_results": {"type": "integer", "minimum": 1, "maximum": MAX_APPS, "default": 200,
                             "description": "The most apps returned."}},
         "required": [], "annotations": _annotations("Running Android apps", **ro),
         "output_schema": _obj({"apps": _arr(_obj({"package": _S, "foreground": _B, "processes": _arr(
             _obj({"pid": _I, "user": _SN, "rss_kb": _IN, "name": _S}))})), "count": _I,
             "foreground": _SN, "truncated": _B}),
         "timeout_class": "walk"},
        {"name": "get_logcat", "title": "Android log", "method": "logcat",
         "description": (
             "Read the newest lines of the device's log (logcat -d), by priority, tag or app.\n"
             "Use when: finding why an app crashed or what it logged.\n"
             "Instead: list_running_apps to see whether the app runs.\n"
             f"{req}.\n"
             "Behavior: read-only. The log is app text and may hold private data; lines are cut at "
             f"{FIELD_CAP} characters.\n"
             "Returns: {lines: [threadtime lines], count, truncated}."),
         "properties": {
             "max_lines": {"type": "integer", "minimum": 1, "maximum": LOGCAT_MAX_LINES, "default": 200,
                           "description": "The most log lines returned (the newest)."},
             "min_priority": {"type": "string", "enum": list(LOG_PRIORITIES), "default": "V",
                              "description": "Lowest priority: V(erbose), D, I, W, E, F(atal)."},
             "tag": {"type": "string", "minLength": 1, "maxLength": 64,
                     "pattern": r"^[A-Za-z0-9_.\-]+$",
                     "description": "Only this log tag, e.g. 'ActivityManager'. Default: every tag."},
             "package": {**_PACKAGE_PROP,
                         "description": "Only the lines of this running app's main process "
                                        "(Android 7 and newer). Default: every process."},
             "buffer": {"type": "string", "enum": ["default", "crash"], "default": "default",
                        "description": "default: main and system; crash: the crash reports."}},
         "required": [], "annotations": _annotations("Android log", **ro),
         "output_schema": _obj({"lines": _arr(_S), "count": _I, "truncated": _B}),
         "timeout_class": "walk"},
        {"name": "take_screenshot", "title": "Android screenshot", "method": "screenshot",
         "description": (
             "Capture what the device's screen shows as a PNG image (screencap).\n"
             "Use when: seeing the screen, e.g. after start_app (needs --mcp-write).\n"
             "Instead: get_logcat for what an app reports.\n"
             f"{req}.\n"
             "Behavior: read-only; a temporary file on the device is removed again. Secure "
             "windows (banking, DRM) show black.\n"
             f"Returns: an MCP image content block (image/png, at most {MAX_SCREENSHOT_BYTES >> 20} "
             "MiB) with _meta {width, height}."),
         "properties": {}, "required": [], "annotations": _annotations("Android screenshot", **ro),
         "output_schema": None, "timeout_class": "walk"},
        {"name": "list_sms", "title": "Read SMS messages", "method": "list_sms",
         "description": (
             "Read the device's SMS messages (content://sms), newest first.\n"
             "Use when: a message's text or sender is needed, e.g. a one-time code.\n"
             "Instead: write_sms (needs --mcp-write) to add one.\n"
             f"{req}; the shell may read the SMS store (READ_SMS), which many builds refuse "
             "(the error says so).\n"
             "Behavior: read-only. Messages are private.\n"
             "Returns: {box, count, offset, messages: [{id, thread_id, address, date, date_sent, "
             "read, box, body, body_truncated}], truncated}; dates ISO 8601 UTC."),
         "properties": {
             "box": {"type": "string", "enum": list(SMS_BOXES), "default": "inbox",
                     "description": "Which messages: inbox, sent, draft, outbox, failed, queued or all."},
             "max_results": {"type": "integer", "minimum": 1, "maximum": SMS_MAX_LIMIT, "default": 20,
                             "description": "The most messages returned."},
             "offset": {"type": "integer", "minimum": 0, "maximum": 1_000_000, "default": 0,
                        "description": "Messages to skip (the next page)."},
             "max_body": {"type": "integer", "minimum": 1, "maximum": SMS_BODY_MAX,
                          "default": SMS_BODY_DEFAULT,
                          "description": "The longest text kept of a message."}},
         "required": [], "annotations": _annotations("Read SMS messages", **ro),
         "output_schema": _obj({"box": _S, "count": _I, "offset": _I, "truncated": _B,
                                "messages": _arr(_obj({"id": _I, "thread_id": _IN, "address": _SN,
                                                       "date": _SN, "date_sent": _SN, "read": _B,
                                                       "box": _SN, "body": _SN,
                                                       "body_truncated": _B}))}),
         "timeout_class": "stream"},
        {"name": "start_app", "title": "Start an Android app", "method": "start_app",
         "description": (
             "Start an installed app at its launcher activity, or at the activity named.\n"
             "Use when: opening an app on the phone.\n"
             "Instead: stop_app to end it; list_running_apps to see what runs.\n"
             f"{req}.\n"
             "Behavior: the app runs and comes to the front (am start; the monkey's launcher "
             "intent where Android cannot resolve the activity).\n"
             "Returns: {package, component, method, started, already_running, output}."),
         "properties": {
             "package": _PACKAGE_PROP,
             "activity": {"type": "string", "minLength": 1, "maxLength": 255,
                          "pattern": r"^\.?[A-Za-z_$][A-Za-z0-9_$]*(\.[A-Za-z_$][A-Za-z0-9_$]*)*$",
                          "description": "An activity of the app instead of the launcher one, e.g. "
                                         "'.SettingsActivity'. Default: the launcher activity."}},
         "required": ["package"],
         "annotations": _annotations("Start an Android app", read_only=False, destructive=False,
                                     idempotent=False),
         "output_schema": _obj({"package": _S, "component": _SN, "method": _S, "started": _B,
                                "already_running": _B, "output": _S}),
         "timeout_class": "walk"},
        {"name": "stop_app", "title": "Stop an Android app", "method": "stop_app",
         "description": (
             "Force-stop an app (am force-stop).\n"
             "Use when: an app hangs or has to start afresh.\n"
             "Instead: uninstall_app to remove it; start_app to start it again.\n"
             f"{req}.\n"
             "Behavior: destructive: its processes end, alarms and jobs are cancelled until it "
             "starts again, unsaved work is lost. A repeat stops nothing more; a package that "
             "is not installed fails with 'is not installed'.\n"
             "Returns: {package, stopped, running (null: not checkable)}."),
         "properties": {"package": _PACKAGE_PROP}, "required": ["package"],
         "annotations": _annotations("Stop an Android app", read_only=False, destructive=True,
                                     idempotent=True),
         "output_schema": _obj({"package": _S, "stopped": _B, "running": _BN}),
         "timeout_class": "walk"},
        {"name": "install_app", "title": "Install an Android app", "method": "install_app",
         "description": (
             "Install one APK file from the MCP root on the device (pm install).\n"
             "Use when: putting a built or downloaded app onto the phone.\n"
             "Instead: uninstall_app to remove one; export_app to copy one off the phone.\n"
             f"{req}; a regular .apk (a ZIP, at most 4 GiB, no link) in the local root, no split "
             "APKs.\n"
             "Behavior: destructive with replace=true (an installed app of that package is updated, "
             "its data kept). Sent to a fresh name in /data/local/tmp, removed again. A refusal "
             "names Android's reason.\n"
             "Returns: {installed, replace, grant_permissions, allow_downgrade, size, output, cleanup}."),
         "properties": {
             "path": {"type": "string", "minLength": 1,
                      "description": "The APK, in the MCP root, e.g. 'build/app.apk'."},
             "replace": {"type": "boolean", "default": True,
                         "description": "Update an installed app of the same package (pm install -r)."},
             "grant_permissions": {"type": "boolean", "default": False,
                                   "description": "Grant every runtime permission it asks for (-g)."},
             "allow_downgrade": {"type": "boolean", "default": False,
                                 "description": "Allow a lower version code than the installed one (-d)."},
             "allow_test_only": {"type": "boolean", "default": False,
                                 "description": "Take an APK an IDE built as test-only (-t)."}},
         "required": ["path"],
         "annotations": _annotations("Install an Android app", read_only=False, destructive=True,
                                     idempotent=False),
         "output_schema": _obj({"installed": _B, "replace": _B, "grant_permissions": _B,
                                "allow_downgrade": _B, "size": _I, "output": _S, "cleanup": _S}),
         "timeout_class": "long"},
        {"name": "uninstall_app", "title": "Uninstall an Android app", "method": "uninstall_app",
         "description": (
             "Uninstall an app (pm uninstall), with its data unless keep_data=true.\n"
             "Use when: an app has to go for good.\n"
             "Instead: stop_app to only end it; export_app first to keep its APK.\n"
             f"{req}.\n"
             "Behavior: destructive: the app and by default everything it stored are gone. "
             "System apps are refused. A repeat fails with 'is not installed'.\n"
             "Returns: {package, uninstalled, kept_data}."),
         "properties": {
             "package": _PACKAGE_PROP,
             "keep_data": {"type": "boolean", "default": False,
                           "description": "Keep the app's data and caches (pm uninstall -k)."}},
         "required": ["package"],
         "annotations": _annotations("Uninstall an Android app", read_only=False, destructive=True,
                                     idempotent=True),
         "output_schema": _obj({"package": _S, "uninstalled": _B, "kept_data": _B}),
         "timeout_class": "stream"},
        {"name": "export_app", "title": "Copy an app's APK off the device", "method": "export_app",
         "description": (
             "Copy an installed app's APK files (base and splits) into a folder of the MCP root.\n"
             "Use when: keeping a backup of an app or inspecting its APK.\n"
             "Instead: get_app_info for its paths and version only.\n"
             f"{req}; a local MCP root.\n"
             "Behavior: changes nothing on the device; each file gets a fresh name "
             "('<package>-<versionCode>-base.apk', then ' (2)'). Not the app's data.\n"
             "Returns: {package, version_code, files: [{source, path, size}], total_size}."),
         "properties": {
             "package": _PACKAGE_PROP,
             "path": {"type": "string", "minLength": 1, "default": ".",
                      "description": "The folder in the MCP root that takes the files."}},
         "required": ["package"],
         "annotations": _annotations("Copy an app's APK off the device", read_only=False,
                                     destructive=False, idempotent=False),
         "output_schema": _obj({"package": _S, "version_code": _IN, "total_size": _I,
                                "files": _arr(_obj({"source": _S, "path": _S, "size": _I}))}),
         "timeout_class": "long"},
        {"name": "grant_permission", "title": "Grant an app permission", "method": "grant_permission",
         "description": (
             "Grant an app one runtime permission it declares (pm grant).\n"
             "Use when: an app needs a permission without a tap on the phone.\n"
             "Instead: revoke_permission to take one back; get_app_info to see the state.\n"
             f"{req}.\n"
             "Behavior: changes what the app may do. Install-time and signature permissions are "
             "refused with Android's reason.\n"
             "Returns: {package, permission, granted (as read back; null: not readable)}."),
         "properties": {
             "package": _PACKAGE_PROP,
             "permission": {"type": "string", "minLength": 3, "maxLength": 255,
                            "pattern": r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$",
                            "description": "The permission, e.g. 'android.permission.CAMERA'."}},
         "required": ["package", "permission"],
         "annotations": _annotations("Grant an app permission", read_only=False, destructive=False,
                                     idempotent=True),
         "output_schema": _obj({"package": _S, "permission": _S, "granted": _BN}),
         "timeout_class": "walk"},
        {"name": "revoke_permission", "title": "Revoke an app permission",
         "method": "revoke_permission",
         "description": (
             "Revoke one runtime permission of an app (pm revoke).\n"
             "Use when: taking back what an app was allowed.\n"
             "Instead: grant_permission to give one; get_app_info to see the state.\n"
             f"{req}.\n"
             "Behavior: destructive: Android ends the app's processes when it loses a permission, "
             "unsaved work is lost.\n"
             "Returns: {package, permission, granted (as read back; null: not readable)}."),
         "properties": {
             "package": _PACKAGE_PROP,
             "permission": {"type": "string", "minLength": 3, "maxLength": 255,
                            "pattern": r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$",
                            "description": "The permission, e.g. 'android.permission.CAMERA'."}},
         "required": ["package", "permission"],
         "annotations": _annotations("Revoke an app permission", read_only=False, destructive=True,
                                     idempotent=True),
         "output_schema": _obj({"package": _S, "permission": _S, "granted": _BN}),
         "timeout_class": "walk"},
        {"name": "reboot_device", "title": "Reboot the Android device", "method": "reboot",
         "description": (
             "Restart the device, into Android, recovery or the bootloader.\n"
             "Use when: a restart is the fix, or recovery or fastboot is needed.\n"
             "Instead: stop_app when one app is the problem.\n"
             f"{req}.\n"
             "Behavior: destructive: every app ends, unsaved work is lost, the connection drops; "
             "close_remote_profile and open it again once the device is up.\n"
             "Returns: {rebooting, mode, note}."),
         "properties": {
             "mode": {"type": "string", "enum": list(REBOOT_MODES), "default": "system",
                      "description": "system: Android; recovery; bootloader (fastboot)."}},
         "required": [],
         "annotations": _annotations("Reboot the Android device", read_only=False, destructive=True,
                                     idempotent=False),
         "output_schema": _obj({"rebooting": _B, "mode": _S, "note": _S}),
         "timeout_class": "walk"},
        {"name": "write_sms", "title": "Write an SMS into the store", "method": "write_sms",
         "description": (
             "Store a message in the device's SMS store: in the inbox as if received, in sent or as "
             "a draft.\n"
             "Use when: a test needs a message on the phone.\n"
             "Instead: compose_sms to prepare a real one; list_sms to read them.\n"
             f"{req}; Android lets only the default SMS app write (since 4.4): the shell's write "
             "is dropped unless its app-op WRITE_SMS is allowed.\n"
             "Behavior: adds one message, sends nothing; read back, a dropped one fails with the "
             "reason.\n"
             "Returns: {stored (null: not checkable), id, box, date_ms, note}."),
         "properties": {
             "box": {"type": "string", "enum": list(SMS_WRITE_BOXES), "default": "inbox",
                     "description": "Where the message goes."},
             "address": {"type": "string", "minLength": 1, "maxLength": 40,
                         "pattern": r"^[0-9A-Za-z+#*() .\-]+$",
                         "description": "The sender (inbox) or recipient: a number or a sender name."},
             "body": {"type": "string", "minLength": 1, "maxLength": SMS_TEXT_MAX,
                      "description": "The text; line feeds and tabs kept, trailing line feeds "
                                     "dropped."},
             "read": {"type": "boolean", "default": True, "description": "Mark it as read."},
             "date_ms": {"type": "integer", "minimum": 1, "maximum": 32503680000000,
                         "description": "Its date in milliseconds since 1970. Default: now."}},
         "required": ["address", "body"],
         "annotations": _annotations("Write an SMS into the store", read_only=False, destructive=False,
                                     idempotent=False),
         "output_schema": _obj({"stored": _BN, "id": _IN, "box": _S, "date_ms": _I, "note": _S}),
         "timeout_class": "walk"},
        {"name": "compose_sms", "title": "Prepare an SMS on the phone", "method": "compose_sms",
         "description": (
             "Open the device's SMS app with a number and a text filled in (a SENDTO intent); "
             "it does not send.\n"
             "Use when: a message is to go out once a person at the phone agrees.\n"
             "Instead: write_sms to store one without sending.\n"
             f"{req}.\n"
             "Behavior: changes what the phone shows; never sends: a person taps Send (Android "
             "gives the shell no stable way to send).\n"
             "Returns: {sent: false, composed: true, number, note, why_not_sent}."),
         "properties": {
             "number": {"type": "string", "pattern": r"^\+?[0-9*#]{2,20}$",
                        "description": "The recipient's number, e.g. '+4915112345678'."},
             "text": {"type": "string", "minLength": 1, "maxLength": SMS_TEXT_MAX,
                      "description": "The message."}},
         "required": ["number", "text"],
         "annotations": _annotations("Prepare an SMS on the phone", read_only=False, destructive=False,
                                     idempotent=False),
         "output_schema": _obj({"sent": _B, "composed": _B, "number": _S, "note": _S,
                                "why_not_sent": _S}),
         "timeout_class": "walk"},
        {"name": "send_at_command", "title": "Send an AT command to the modem", "method": "send_at_command",
         "description": (
             "Send one AT command to the device's modem and return its reply.\n"
             "Use when: asking the modem itself (AT+CSQ signal, AT+CGMI maker, AT+COPS? network).\n"
             "Instead: get_device_info for the IMEI and build.\n"
             f"{req}; a modem node (/dev/smd*, /dev/umts_atc0, /dev/radio/*, ttyACM, ttyUSB) and "
             "root (adb root or su); else refused with the reason.\n"
             "Behavior: destructive: an AT command can change modem settings or switch the radio "
             f"off. Time limit: timeout; the reply is cut at {AT_REPLY_CAP} bytes.\n"
             "Returns: {device, command, as_root, reply: [lines], status (OK, ERROR, +CME ERROR: n), "
             "complete, note}."),
         "properties": {
             "command": {"type": "string", "minLength": 2, "maxLength": AT_MAX_LEN,
                         "pattern": r"^[Aa][Tt][A-Za-z0-9+#*=?,.:\"&%!/<>@^_() \-]*$",
                         "description": "One AT command, e.g. 'AT+CSQ' (no ';')."},
             "device": {"type": "string", "minLength": 6, "maxLength": 64,
                        "pattern": r"^/dev/[A-Za-z0-9_/]+$",
                        "description": "The modem's device node. Default: the first known one present."},
             "timeout": {"type": "number", "minimum": 1, "maximum": AT_TIMEOUT_MAX,
                         "default": AT_TIMEOUT_DEFAULT,
                         "description": "Seconds to wait for the reply."}},
         "required": ["command"],
         "annotations": _annotations("Send an AT command to the modem", read_only=False, destructive=True,
                                     idempotent=False),
         "output_schema": _obj({"device": _S, "command": _S, "as_root": _B, "reply": _arr(_S),
                                "status": _SN, "complete": _B, "note": _S}),
         "timeout_class": "stream"},
    ]
    for definition in out:
        definition["mutating"] = definition["name"] in MUTATING
    return out


def call(tools: AndroidTools, name: str, args: dict, *, local=None, place=None) -> dict:
    """Run the tool *name* with *args* on *tools*: install_app on the APK
    *local* (a path or an open file the caller confined), export_app with
    the caller's *place* (see :meth:`AndroidTools.export_app`)."""
    if not isinstance(args, dict):
        raise ValueError("the arguments must be an object")
    for definition in tool_definitions():
        if definition["name"] == name:
            allowed = set(definition["properties"]) | {"backend"}
            unknown = set(args) - allowed
            if unknown:
                raise ValueError(f"unknown argument(s): {', '.join(sorted(unknown))}")
            for key in definition["required"]:
                if args.get(key) is None:
                    raise ValueError(f"{key} is required")
            method = getattr(tools, definition["method"])
            if name == "install_app":
                if local is None:
                    raise ValueError("install_app needs path")
                return method(args, local)
            if name == "export_app":
                if place is None:
                    raise ValueError("export_app needs a local folder")
                return method(args, place)
            return method(args)
    raise ValueError(f"unknown tool {name!r}")


__all__ = ["ASK_FIRST", "AndroidTools", "DESTRUCTIVE", "DeviceRefused", "MUTATING", "PRIVATE",
           "call", "clean", "shell_line", "tool_definitions"]
