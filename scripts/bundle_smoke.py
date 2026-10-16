"""Smoke-test a built axross one-file binary.

Usage: python scripts/bundle_smoke.py DIST_DIR

Finds ``axross-slim`` / ``axross-full`` (``.exe`` on Windows) in DIST_DIR,
then checks that it answers ``--version`` and that ``--script`` runs a
script which lists a folder through the axross API, renders an SVG
thumbnail (the 0.10.24 bundle's Qt 6.10.0 crashed on the first one) and
writes a marker file. The binary runs with its own HOME (and USERPROFILE / APPDATA), so a
smoke run never touches a real configuration. Exit status 0 means both
checks passed.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

TIMEOUT = 180
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
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        problems = smoke(Path(argv[1]))
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
