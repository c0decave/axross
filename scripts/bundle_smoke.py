"""Smoke-test a built axross one-file binary.

Usage: python scripts/bundle_smoke.py [--native] DIST_DIR

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


def main(argv: list[str]) -> int:
    args = argv[1:]
    run = smoke
    if args[:1] == ["--native"]:
        run, args = native, args[1:]
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
