"""Smoke-test a built axross one-file binary.

Usage: python scripts/bundle_smoke.py [--native | --libs | --system-libs] DIST_DIR

Finds ``axross-slim`` / ``axross-full`` (``.exe`` on Windows) in DIST_DIR,
then checks that it answers ``--version`` and that ``--script`` runs a
script which lists a folder through the axross API, renders an SVG
thumbnail (the 0.10.24 bundle's Qt 6.10.0 crashed on the first one) and
writes a marker file. The binary runs with its own HOME (and USERPROFILE / APPDATA), so a
smoke run never touches a real configuration. Exit status 0 means both
checks passed.

``--native`` starts the main window instead, on the platform the machine
has (no ``offscreen``: Cocoa on macOS, the Windows desktop), with
``AXROSS_SMOKE_GUI_MS`` so it quits once the window is up. The checks
above never open a window, so a crash on the way to it passed every
run. When the binary dies, the newest macOS crash report of it is shown.

``--libs`` runs ``axross-full`` and imports its native packages inside it
(numpy with a real computation, onnxruntime, ctranslate2, piper,
faster_whisper): a library the bundling broke passes --version and
--script and fails only on first use.

``--system-libs`` runs every axross binary in DIST_DIR and reads the
DT_NEEDED entries of all ELF files in its unpacked folder
(scripts/elf_needs.py): a system library that is neither bundled nor in
bundle_options.HOST_PROVIDED fails. PyInstaller leaves what it cannot find
on the build machine to the target system without a word. So does a
bundled library the host must own (glibc, libstdc++: host code loaded into
the process would get ours), and every symbol version a bundled ELF needs
from the host that this build machine - the oldest supported system - does
not define (elf_needs.version_floor_problems).
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

TIMEOUT = 180
#: How long the window stays up in a --native run before axross quits.
GUI_MS = 3000
WINDOW_LINE = "gui smoke: window shown on "
_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" width="200" height="100">'
    '<rect width="200" height="100" fill="#00ff00"/></svg>'
)
_SCRIPT = """\
from pathlib import Path
from core import previews
fs = axross.localfs()
names = sorted(i.name for i in fs.list_dir({folder!r}) if i.name.endswith(".txt"))
thumb = previews.thumbnail(fs, {svg!r}, edge=64, use_cache=False, allow_svg=True)
Path({marker!r}).write_text(
    "listed " + ",".join(names) + "; svg %dx%d" % (thumb.width, thumb.height),
    encoding="utf-8",
)
"""
EXPECTED_MARKER = "listed a.txt; svg 64x32"


def bundled_host_libraries(folder: str) -> list[str]:
    """The libraries under *folder* (a bundle's extraction folder) that the
    host must provide (bundle_options.host_owned), sorted."""
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from bundle_options import host_owned

    found = []
    for root, _dirs, files in os.walk(folder):
        found += [os.path.relpath(os.path.join(root, f), folder) for f in files if host_owned(f)]
    return sorted(found)


#: The native packages of axross-full that must load inside the binary.
FULL_NATIVE = ("numpy", "onnxruntime", "ctranslate2", "piper", "faster_whisper")
LIBS_OK = "native libs ok"
_LIBS_SCRIPT = """\
import importlib, traceback
from pathlib import Path
failed = []
for name in {modules!r}:
    try:
        mod = importlib.import_module(name)
        if name == "numpy":
            assert float(mod.ones(64).dot(mod.ones(64))) == 64.0
    except BaseException as exc:
        failed.append(name + ": " + type(exc).__name__ + ": " + str(exc).strip().splitlines()[-1][:300]
                      if str(exc).strip() else name + ": " + type(exc).__name__)
import os, sys
for root, _dirs, files in os.walk(getattr(sys, "_MEIPASS", "")):
    for f in files:
        if f.startswith({host_owned!r}):
            failed.append("bundled host library " + os.path.relpath(os.path.join(root, f),
                                                                 sys._MEIPASS))
Path({marker!r}).write_text("\\n".join(failed) if failed else {ok!r}, encoding="utf-8")
"""


def native_libs(dist: Path, modules: tuple = FULL_NATIVE) -> list[str]:
    """Import *modules* inside ``axross-full``; one problem per module
    that does not load (empty: all loaded)."""
    exe = next((c for c in (dist / "axross-full", dist / "axross-full.exe") if c.is_file()), None)
    if exe is None:
        return [f"no axross-full binary in {dist}: --libs checks the full bundle only"]
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        home = work / "home"
        home.mkdir()
        marker = work / "libs.txt"
        script = work / "libs_script.py"
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from bundle_options import HOST_OWNED

        script.write_text(_LIBS_SCRIPT.format(modules=tuple(modules), marker=str(marker),
                                              ok=LIBS_OK, host_owned=HOST_OWNED),
                          encoding="utf-8")
        r = subprocess.run([str(exe), "--script", str(script)], capture_output=True, text=True,
                           timeout=TIMEOUT, env=_env(home))
        text = marker.read_text(encoding="utf-8") if marker.exists() else ""
    if text == LIBS_OK:
        return []
    if not text:
        return [f"--script exited {r.returncode} without a result: {(r.stdout + r.stderr)[-800:]}"]
    return [f"does not load in {exe.name}: {line}" for line in text.splitlines()]


def marker_problem(text: str) -> str | None:
    """What is wrong with the marker the smoke script wrote, or ``None``."""
    if text == EXPECTED_MARKER:
        return None
    if text.startswith("listed ") and "svg" not in text:
        return f"script marker is {text!r}: no SVG thumbnail rendered"
    return f"script marker is {text!r}, expected {EXPECTED_MARKER!r}"


def find_binary(dist: Path) -> Path:
    for name in ("axross-slim", "axross-full"):
        for candidate in (dist / name, dist / f"{name}.exe"):
            if candidate.is_file():
                return candidate
    raise FileNotFoundError(f"no axross-slim or axross-full binary in {dist}")


def crash_report(binary_name: str, reports: Path, *, since: float) -> str:
    """The newest crash report of *binary_name* written after *since*
    (macOS: ~/Library/Logs/DiagnosticReports), or ""."""
    try:
        found = [p for p in reports.iterdir()
                 if p.name.startswith(binary_name) and p.stat().st_mtime >= since]
    except OSError:
        return ""
    if not found:
        return ""
    newest = max(found, key=lambda p: p.stat().st_mtime)
    return f"{newest.name}:\n{newest.read_text(encoding='utf-8', errors='replace')[:6000]}"


def native(dist: Path) -> list[str]:
    """Start the main window on the machine's own platform; problems found."""
    exe = find_binary(dist)
    started = time.time()
    with tempfile.TemporaryDirectory() as tmp:
        home = Path(tmp) / "home"
        home.mkdir()
        env = _env(home)
        # The platform the machine has, unless the caller chose one (a CI
        # Linux runner without a display passes offscreen itself).
        if "QT_QPA_PLATFORM" in os.environ:
            env["QT_QPA_PLATFORM"] = os.environ["QT_QPA_PLATFORM"]
        else:
            env.pop("QT_QPA_PLATFORM", None)
        env["AXROSS_SMOKE_GUI_MS"] = str(GUI_MS)
        r = subprocess.run([str(exe)], capture_output=True, text=True, timeout=TIMEOUT, env=env)
    out = r.stdout + r.stderr
    line = next((ln for ln in r.stdout.splitlines() if ln.startswith(WINDOW_LINE)), "")
    problems = []
    if r.returncode != 0 or not line:
        problems.append(f"no window: exit {r.returncode}: {out[-1500:]}")
        report = crash_report(exe.name, Path.home() / "Library" / "Logs" / "DiagnosticReports",
                              since=started - 1)
        if report:
            problems.append(f"crash report {report}")
    else:
        print(line)
    return problems


def _env(home: Path) -> dict:
    env = dict(os.environ)
    env.update(
        HOME=str(home),
        USERPROFILE=str(home),
        APPDATA=str(home / "AppData" / "Roaming"),
        LOCALAPPDATA=str(home / "AppData" / "Local"),
        XDG_CONFIG_HOME=str(home / ".config"),
        QT_QPA_PLATFORM="offscreen",
        PYTHON_KEYRING_BACKEND="keyring.backends.null.Keyring",
    )
    return env


def smoke(dist: Path) -> list[str]:
    """Problems found; empty when the binary passed."""
    exe = find_binary(dist)
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        home = work / "home"
        folder = work / "folder"
        home.mkdir()
        folder.mkdir()
        (folder / "a.txt").write_text("a", encoding="utf-8")
        svg = folder / "a.svg"
        svg.write_text(_SVG, encoding="utf-8")
        marker = work / "marker.txt"
        script = work / "smoke_script.py"
        script.write_text(
            _SCRIPT.format(folder=str(folder), svg=str(svg), marker=str(marker)), encoding="utf-8"
        )
        env = _env(home)
        problems = []
        r = subprocess.run(
            [str(exe), "--version"], capture_output=True, text=True, timeout=TIMEOUT, env=env
        )
        if r.returncode != 0:
            problems.append(f"--version exited {r.returncode}: {(r.stdout + r.stderr)[-500:]}")
        r = subprocess.run(
            [str(exe), "--script", str(script)],
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
            env=env,
        )
        if r.returncode != 0:
            problems.append(f"--script exited {r.returncode}: {(r.stdout + r.stderr)[-500:]}")
        text = marker.read_text(encoding="utf-8") if marker.exists() else ""
        problem = marker_problem(text)
        if problem is not None:
            problems.append(problem)
    return problems


SYSTEM_LIBS_OK = "system libs ok"
_SYSTEM_LIBS_SCRIPT = """\
import sys
from pathlib import Path
sys.path.insert(0, {scripts!r})
import elf_needs, bundle_options
meipass = getattr(sys, "_MEIPASS", None)
if not meipass:
    lines = ["not a frozen binary: no unpacked folder to check"]
else:
    import bundle_smoke
    scan = elf_needs.system_needs(meipass, bundle_options.host_provided,
                                  skip=bundle_options.dropped)
    lines = elf_needs.problems(scan)
    lines += ["bundled host library " + p for p in bundle_smoke.bundled_host_libraries(meipass)]
    lines += elf_needs.version_floor_problems(meipass, skip=bundle_options.dropped,
                                              known=bundle_options.HOST_VERSION_FLOOR)
    lines += bundle_smoke.child_env_problems(meipass)
    lines = lines or [{ok!r} + " (%d ELF files)" % scan["elf_files"]]
Path({marker!r}).write_text("\\n".join(lines), encoding="utf-8")
"""


def _bundle_vars(env: dict, bundle: str) -> list[str]:
    """Variables of *env* that point into the unpacked folder *bundle* or
    describe its unpacking (``_PYI_*``)."""
    bundle = bundle.rstrip("/")
    return sorted(k for k, v in env.items()
                  if k.startswith("_PYI_") or k == "_MEIPASS2"
                  or any(p.rstrip("/") == bundle or p.startswith(bundle + "/")
                         for p in v.split(os.pathsep)))


def child_env_problems(bundle: str) -> list[str]:
    """Start children the ways third-party code does - subprocess without
    ``env=``, os.system, QProcess - and name every variable one of them
    sees that points into *bundle* (runs inside the frozen binary)."""
    seen: dict[str, dict] = {}
    r = subprocess.run(["env", "-0"], capture_output=True, timeout=60)
    seen["subprocess"] = _parse_env0(r.stdout)
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "env.bin"
        status = os.system(f"env -0 > '{out}'")  # noqa: S605 - fixed command, the point of the check
        seen["os.system"] = _parse_env0(out.read_bytes() if out.exists() else b"")
        statuses = {"os.system": status}
    try:
        from PyQt6.QtCore import QProcess

        proc = QProcess()
        proc.start("env", ["-0"])
        proc.waitForFinished(60000)
        seen["QProcess"] = _parse_env0(bytes(proc.readAllStandardOutput()))
    except ImportError:
        pass
    problems = []
    for how, env in seen.items():
        if not env:
            problems.append(f"child via {how} printed no environment (wait status "
                            f"{statuses.get(how, 'n/a')}): the child itself failed to start - "
                            "/bin/sh loading the bundle's libraries does exactly that")
            continue
        problems += [f"child via {how} sees {k}={env[k][:120]}" for k in _bundle_vars(env, bundle)]
    return problems


def _parse_env0(data: bytes) -> dict:
    env = {}
    for item in data.split(b"\0"):
        if b"=" in item:
            k, v = item.split(b"=", 1)
            env[k.decode(errors="replace")] = v.decode(errors="replace")
    return env


def system_libs(dist: Path) -> list[str]:
    """Check the unpacked folder of the binary *dist*, or of every axross
    binary in the folder *dist*, for system
libraries that are neither bundled nor host-provided; one problem per
    finding, prefixed with the binary's name (empty: all clean)."""
    if dist.is_file():
        binaries = [dist]
    else:
        binaries = [c for c in (dist / "axross-slim", dist / "axross-full") if c.is_file()]
    if not binaries:
        return [f"no axross binary in {dist}"]
    problems = []
    for exe in binaries:
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            home = work / "home"
            home.mkdir()
            marker = work / "system_libs.txt"
            script = work / "system_libs_script.py"
            script.write_text(_SYSTEM_LIBS_SCRIPT.format(
                scripts=os.path.dirname(os.path.abspath(__file__)), ok=SYSTEM_LIBS_OK,
                marker=str(marker)), encoding="utf-8")
            r = subprocess.run([str(exe), "--script", str(script)], capture_output=True,
                               text=True, timeout=TIMEOUT, env=_env(home))
            text = marker.read_text(encoding="utf-8") if marker.exists() else ""
        if not text:
            problems.append(f"{exe.name}: --script exited {r.returncode} without a result: "
                            f"{(r.stdout + r.stderr)[-800:]}")
        elif not text.startswith(SYSTEM_LIBS_OK):
            problems += [f"{exe.name}: {line}" for line in text.splitlines()]
        else:
            print(f"{exe.name}: {text}")
    return problems


def main(argv: list[str]) -> int:
    args = argv[1:]
    run = smoke
    if args[:1] == ["--native"]:
        run, args = native, args[1:]
    elif args[:1] == ["--libs"]:
        run, args = native_libs, args[1:]
    elif args[:1] == ["--system-libs"]:
        run, args = system_libs, args[1:]
    if len(args) != 1:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        problems = run(Path(args[0]))
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        print(f"smoke failed: {exc}")
        return 1
    for p in problems:
        print(f"smoke failed: {p}")
    if problems:
        return 1
    print("smoke ok")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
