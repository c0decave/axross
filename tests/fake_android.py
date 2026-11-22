"""A fake Android userland for the adb tool tests: getprop, id, pm, cmd,
am, monkey, pidof, ps, dumpsys, service, content, screencap, logcat and
reboot as one Python program, installed under those names in a folder that
is the device shell's whole PATH (with sh, printf, rm, cat, head, timeout,
sleep and stty of this computer).

tests/fake_adbd.py runs every ``shell:`` command with /bin/sh and this
process's environment, so a test that sets PATH to :func:`install`'s folder
runs the real client code (core.adb_client, core.adb_device) against these
commands, with the real quoting of the real sh. The device's state - its
properties, apps, permissions, SMS store, log - is a JSON file
(:class:`Phone`); every command's argv goes to ``argv.log`` (one JSON list a
line), so a test sees exactly which words a command line made.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import zlib
from pathlib import Path

COMMANDS = ("getprop", "id", "pm", "cmd", "am", "monkey", "pidof", "ps", "dumpsys", "service",
            "content", "screencap", "logcat", "reboot")
HOST_TOOLS = ("sh", "printf", "rm", "cat", "head", "timeout", "sleep", "stty", "echo", "mv", "ls")

#: The props of a Pixel 6 on Android 14.
PROPS = {
    "ro.build.fingerprint": "google/oriole/oriole:14/UQ1A.240205.004/1:user/release-keys",
    "ro.build.version.release": "14", "ro.build.version.sdk": "34",
    "ro.build.version.security_patch": "2024-02-05", "ro.product.manufacturer": "Google",
    "ro.product.brand": "google", "ro.product.model": "Pixel 6", "ro.product.device": "oriole",
    "ro.product.name": "oriole", "ro.build.type": "user", "ro.product.cpu.abilist": "arm64-v8a",
    "ro.serialno": "1A2B3C4D", "persist.sys.locale": "de-DE",
}
APPS = {
    "com.android.settings": {"version_code": 34, "uid": 1000, "installer": None, "system": True,
                             "path": "/system/priv-app/Settings/Settings.apk",
                             "requested": ["android.permission.WRITE_SETTINGS"], "runtime": {}},
    "org.example.notes": {"version_code": 120, "version_name": "1.2.0", "uid": 10234,
                          "installer": "com.android.vending", "system": False,
                          "path": "/data/app/~~a1==/org.example.notes-b2==/base.apk",
                          "splits": ["split_config.arm64_v8a.apk"],
                          "requested": ["android.permission.INTERNET", "android.permission.CAMERA"],
                          "install": {"android.permission.INTERNET": True},
                          "runtime": {"android.permission.CAMERA": False},
                          "activity": ".MainActivity"},
}


def tiny_png(width: int = 3, height: int = 2) -> bytes:
    raw = b"".join(b"\x00" + b"\xff\x00\x00" * width for _ in range(height))

    def chunk(kind, data):
        return (len(data).to_bytes(4, "big") + kind + data
                + zlib.crc32(kind + data).to_bytes(4, "big"))

    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", width.to_bytes(4, "big") + height.to_bytes(4, "big") + b"\x08\x02\x00\x00\x00")
            + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))


class Phone:
    """The fake device's state file, and the folder of its commands."""

    def __init__(self, folder: Path) -> None:
        self.folder = Path(folder)
        self.bin = self.folder / "bin"
        self.state_file = self.folder / "state.json"
        self.log_file = self.folder / "argv.log"

    def install(self, **state) -> "Phone":
        """The commands under :attr:`bin`, the state *state* over the default."""
        self.bin.mkdir(parents=True, exist_ok=True)
        program = self.bin / "_android.py"
        program.write_text(f"#!{sys.executable} -I\nimport sys\nsys.path.insert(0, {str(Path(__file__).parent)!r})\n"
                           "import fake_android\nfake_android.main()\n")
        program.chmod(0o755)
        for name in COMMANDS:
            link = self.bin / name
            if not link.exists():
                link.symlink_to(program)
        for name in HOST_TOOLS:
            found = shutil.which(name, path="/usr/bin:/bin")
            link = self.bin / name
            if found and not link.exists():
                link.symlink_to(found)
        base = {"props": dict(PROPS), "uid": "2000", "imei": "490154203237518", "imei_refused": False,
                "apps": json.loads(json.dumps(APPS)), "running": {"org.example.notes": [4321]},
                "foreground": "org.example.notes", "sms": [], "sms_readable": True,
                "sms_writable": True, "logcat": ["11-22 10:00:00.000  4321  4321 I Notes   : saved"],
                "battery": {"level": 85, "status": 2, "health": 2, "usb": True, "temperature": 281},
                "toybox_ps": True, "pidof": True, "next_install": "com.example.installed",
                "reboots": []}
        base.update(state)
        self.save(base)
        os.environ["AXROSS_FAKE_ANDROID"] = str(self.folder)
        return self

    def load(self) -> dict:
        return json.loads(self.state_file.read_text())

    def save(self, state: dict) -> None:
        self.state_file.write_text(json.dumps(state))

    def argv(self) -> list[list[str]]:
        if not self.log_file.exists():
            return []
        return [json.loads(line) for line in self.log_file.read_text().splitlines()]


# ---------------------------------------------------------------------------
# The commands (run as a program, argv[0] names the command)
# ---------------------------------------------------------------------------

def _parcel(text: str, code: int = 0) -> str:
    raw = code.to_bytes(4, "little", signed=True) + len(text).to_bytes(4, "little", signed=True)
    raw += text.encode("utf-16-le") + b"\0\0"
    raw += b"\0" * (-len(raw) % 4)
    words = [int.from_bytes(raw[i:i + 4], "little") for i in range(0, len(raw), 4)]
    lines = []
    for i in range(0, len(words), 4):
        lines.append(f"  0x{i * 4:08x}: " + " ".join(f"{w:08x}" for w in words[i:i + 4]) + " '....'")
    return "Result: Parcel(\n" + "\n".join(lines) + ")\n"


def _pm(state, args, out):
    apps = state["apps"]
    if args[:2] == ["list", "packages"]:
        flags = [a for a in args[2:] if a.startswith("-")]
        names = [a for a in args[2:] if not a.startswith("-")]
        if "--show-versioncode" in flags and state.get("old_pm"):
            out.append("Error: Unknown option: --show-versioncode")
            return 1
        for name, app in sorted(apps.items()):
            if names and names[0] not in name:
                continue
            if "-3" in flags and app.get("system") or "-s" in flags and not app.get("system"):
                continue
            if "-d" in flags and not app.get("disabled"):
                continue
            line = f"package:{name}"
            if "--show-versioncode" in flags:
                line += f" versionCode:{app.get('version_code')}"
            if "-U" in flags:
                line += f" uid:{app.get('uid')}"
            if "-i" in flags:
                line += f"  installer={app.get('installer') or 'null'}"
            out.append(line)
        return 0
    if args[:1] == ["path"]:
        app = apps.get(args[1])
        if app:
            out.append(f"package:{app['path']}")
            folder = app["path"].rsplit("/", 1)[0]
            out.extend(f"package:{folder}/{split}" for split in app.get("splits", []))
        return 0 if app else 1
    if args[:1] == ["install"]:
        path = args[-1]
        try:
            with open(path, "rb") as fh:
                head = fh.read(4)
        except OSError as exc:
            out.append(f"Failure [INSTALL_FAILED_INVALID_URI: {exc}]")
            return 1
        if state.get("install_failure"):
            out.append(f"Failure [{state['install_failure']}: no]")
            return 1
        if head != b"PK\x03\x04":
            out.append("Failure [INSTALL_PARSE_FAILED_NOT_APK: not a zip]")
            return 1
        state.setdefault("installed_flags", []).append(args[1:-1])
        apps[state["next_install"]] = {"version_code": 1, "uid": 10300, "installer": None,
                                       "system": False, "path": "/data/app/~~n==/x==/base.apk",
                                       "requested": [], "runtime": {}}
        out.append("Performing Streamed Install")
        out.append("Success")
        return 0
    if args[:1] == ["uninstall"]:
        name = args[-1]
        if name not in apps:
            out.append("Failure [DELETE_FAILED_INTERNAL_ERROR]")
            return 1
        del apps[name]
        out.append("Success")
        return 0
    if args[:1] in (["grant"], ["revoke"]):
        name, perm = args[1], args[2]
        app = apps.get(name)
        if app is None:
            out.append(f"Exception occurred while executing '{args[0]}':")
            out.append(f"java.lang.IllegalArgumentException: Unknown package: {name}")
            return 255
        if perm not in app.get("requested", []):
            out.append(f"Exception occurred while executing '{args[0]}':")
            out.append(f"java.lang.SecurityException: Package {name} has not requested permission {perm}")
            return 255
        if perm in app.get("install", {}):
            out.append(f"Exception occurred while executing '{args[0]}':")
            out.append(f"java.lang.SecurityException: Permission {perm} requested by {name} is not a "
                       "changeable permission type")
            return 255
        app.setdefault("runtime", {})[perm] = args[0] == "grant"
        if args[0] == "revoke":
            state["running"].pop(name, None)
        return 0
    out.append(f"Unknown command: {' '.join(args)}")
    return 1


def _dumpsys_package(state, name, out):
    app = state["apps"].get(name)
    if app is None:
        out.append("Unable to find package: " + name)
        return
    flags = "SYSTEM HAS_CODE" if app.get("system") else "HAS_CODE ALLOW_BACKUP"
    out += ["Activity Resolver Table:", "  Non-Data Actions:", "", "Packages:",
            f"  Package [{name}] (1a2b3c):", f"    userId={app.get('uid')}",
            f"    pkg=Package{{4d5e {name}}}",
            f"    versionCode={app.get('version_code')} minSdk=24 targetSdk=34",
            f"    versionName={app.get('version_name', '1.0')}",
            f"    flags=[ {flags} ]", f"    dataDir=/data/user/0/{name}",
            "    firstInstallTime=2024-01-02 10:11:12", "    lastUpdateTime=2024-01-03 10:11:12",
            f"    installerPackageName={app.get('installer') or 'null'}",
            f"    pkgFlags=[ {flags} ]", "    requested permissions:"]
    out += [f"      {perm}" for perm in app.get("requested", [])]
    out.append("    install permissions:")
    out += [f"      {perm}: granted={str(g).lower()}" for perm, g in app.get("install", {}).items()]
    out.append("    User 0: ceDataInode=4242 installed=true hidden=false suspended=false "
               "stopped=false notLaunched=false enabled=0 instant=false virtual=false")
    out.append("      gids=[3003]")
    out.append("      runtime permissions:")
    out += [f"        {perm}: granted={str(g).lower()}, flags=[ USER_SET ]"
            for perm, g in app.get("runtime", {}).items()]
    out += ["", "Hidden system packages:", ""]


def _content(state, args, out):
    opts = {}
    binds = []
    i = 1
    while i < len(args):
        if args[i] == "--bind":
            binds.append(args[i + 1])
        else:
            opts[args[i]] = args[i + 1]
        i += 2
    if not state["sms_readable"] and args[0] == "query":
        out.append("Error while accessing provider:sms")
        out.append("java.lang.SecurityException: Permission Denial: opening provider "
                   "com.android.providers.telephony.SmsProvider requires android.permission.READ_SMS")
        return 1
    sms = state["sms"]
    if args[0] == "insert":
        row = {}
        for bind in binds:
            key, _kind, value = bind.split(":", 2)
            row[key] = value
        if state["sms_writable"]:
            row["_id"] = str(max([int(m["_id"]) for m in sms] + [0]) + 1)
            row.setdefault("thread_id", "1")
            row.setdefault("date_sent", "0")
            sms.append(row)
        return 0
    rows = list(sms)
    uri = opts.get("--uri", "")
    box = uri.rsplit("/", 1)[1] if uri.count("/") > 2 else ""
    types = {"inbox": "1", "sent": "2", "draft": "3"}
    if box:
        rows = [r for r in rows if r.get("type") == types.get(box)]
    where = opts.get("--where")
    if where:
        key, value = where.split("=", 1)
        rows = [r for r in rows if r.get(key) == value]
    if opts.get("--sort") == "date DESC":
        rows.sort(key=lambda r: int(r.get("date", "0")), reverse=True)
    columns = opts.get("--projection", "_id").split(":")
    if not rows:
        out.append("No result found.")
    for n, row in enumerate(rows):
        out.append(f"Row: {n} " + ", ".join(f"{c}={row.get(c, 'NULL')}" for c in columns))
    return 0


def main() -> None:  # pragma: no cover - runs in the fake device's processes
    command = os.path.basename(sys.argv[0])
    args = sys.argv[1:]
    phone = Phone(Path(os.environ["AXROSS_FAKE_ANDROID"]))
    with open(phone.log_file, "a") as log:
        log.write(json.dumps([command, *args]) + "\n")
    state = phone.load()
    out: list[str] = []
    status = 0
    if command == "getprop":
        if args:
            out.append(state["props"].get(args[0], ""))
        else:
            out += [f"[{k}]: [{v}]" for k, v in sorted(state["props"].items())]
    elif command == "id":
        out.append(state["uid"])
    elif command == "service":
        if state.get("imei_refused"):
            out.append(_parcel("getDeviceId: The user 2000 does not meet the requirements", code=-1))
        else:
            out.append(_parcel(state["imei"]))
    elif command == "pm":
        status = _pm(state, args, out)
    elif command == "cmd" and args[:2] == ["package", "resolve-activity"]:
        app = state["apps"].get(args[-1])
        if app and app.get("activity"):
            out += ["priority=0 preferredOrder=0 match=0x108000 specificIndex=-1 isDefault=false",
                    f"{args[-1]}/{app['activity']}"]
        else:
            out.append("No activity found")
    elif command == "am":
        if args[:1] == ["force-stop"]:
            state["running"].pop(args[1], None)
        elif "-n" in args:
            component = args[args.index("-n") + 1]
            package = component.split("/")[0]
            state["running"][package] = [5555]
            state["foreground"] = package
            out += [f"Starting: Intent {{ cmp={component} }}", "Status: ok", "LaunchState: COLD"]
        elif "android.intent.action.SENDTO" in args:
            state["composed"] = {"uri": args[args.index("-d") + 1],
                                 "body": args[args.index("--es") + 2]}
            out += ["Starting: Intent { act=android.intent.action.SENDTO }", "Status: ok"]
    elif command == "monkey":
        out.append("Events injected: 1")
    elif command == "pidof":
        if not state["pidof"]:
            sys.stderr.write("pidof: not found\n")
            sys.exit(127)
        pids = state["running"].get(args[0])
        out.append(" ".join(map(str, pids)) if pids else "")
        status = 0 if pids else 1
    elif command == "ps":
        if state["toybox_ps"] and args[:1] == ["-A"]:
            out.append("PID USER RSS NAME")
            out.append("1 root 2000 init")
            for name, pids in state["running"].items():
                out += [f"{pid} u0_a234 81234 {name}" for pid in pids]
                out += [f"{pid + 1} u0_a234 1234 {name}:remote" for pid in pids]
        elif not state["toybox_ps"] and args:
            out.append("USER     PID   PPID  VSIZE  RSS     WCHAN    PC         NAME")
        else:
            out.append("USER     PID   PPID  VSIZE  RSS     WCHAN    PC         NAME")
            out.append("root      1     0     1000   200   ffffffff 00000000 S /init")
            for name, pids in state["running"].items():
                out += [f"u0_a234   {pid}  100   99999  8123  ffffffff 00000000 S {name}" for pid in pids]
    elif command == "dumpsys":
        if args[:1] == ["battery"]:
            b = state["battery"]
            out += ["Current Battery Service state:"] + (["  (UPDATES STOPPED -- use 'reset' to restart)"]
                                                        if b.get("fake") else [])
            out += [f"  AC powered: {str(b.get('ac', False)).lower()}",
                    f"  USB powered: {str(b.get('usb', False)).lower()}", "  Wireless powered: false",
                    f"  status: {b['status']}", f"  health: {b['health']}", "  present: true",
                    f"  level: {b['level']}", "  scale: 100", "  voltage: 4123",
                    f"  temperature: {b['temperature']}", "  technology: Li-ion"]
        elif args[:1] == ["package"]:
            _dumpsys_package(state, args[1], out)
        elif args[:2] == ["activity", "activities"]:
            fg = state.get("foreground")
            if fg:
                activity = state["apps"].get(fg, {}).get("activity", ".Main")
                out.append(f"  topResumedActivity=ActivityRecord{{9f8e7d u0 {fg}/{activity} t12}}")
    elif command == "content":
        status = _content(state, args, out)
    elif command == "screencap":
        if state.get("screencap_missing"):
            sys.stderr.write("screencap: not found\n")
            sys.exit(127)
        with open(args[-1], "wb") as fh:
            fh.write(state.get("screen_bytes", "").encode("latin-1") or tiny_png())
    elif command == "logcat":
        lines = list(state["logcat"])
        if any(a.startswith("--pid=") for a in args):
            pid = [a for a in args if a.startswith("--pid=")][0][6:]
            lines = [line for line in lines if f" {pid} " in line]
        count = int(args[args.index("-t") + 1]) if "-t" in args else len(lines)
        out += lines[-count:]
    elif command == "reboot":
        state["reboots"].append(args)
    phone.save(state)
    if out:
        sys.stdout.write("\n".join(out) + "\n")
    sys.exit(status)


if __name__ == "__main__":  # pragma: no cover
    main()
