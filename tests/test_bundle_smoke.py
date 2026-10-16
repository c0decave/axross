"""scripts/bundle_smoke.py: does a built axross binary run at all?

CI calls it on the macOS and Windows one-file builds. The binary must
answer ``--version`` and run a ``--script`` that lists a folder through the
axross API and writes a marker file - with its own HOME, so a run never
reads or writes a real configuration. Here a shell wrapper around
``main.py`` stands in for the binary.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SMOKE = ROOT / "scripts" / "bundle_smoke.py"

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="the stand-in is a sh wrapper")


def _fake_binary(dist: Path, body: str) -> Path:
    dist.mkdir(parents=True, exist_ok=True)
    exe = dist / "axross-slim"
    exe.write_text(f"#!/bin/sh\n{body}\n")
    exe.chmod(0o755)
    return exe


def _smoke(dist: Path) -> subprocess.CompletedProcess:
    env = {**os.environ, "QT_QPA_PLATFORM": "offscreen"}
    return subprocess.run(
        [sys.executable, str(SMOKE), str(dist)],
        capture_output=True,
        text=True,
        timeout=300,
        env=env,
    )


# --- happy ----------------------------------------------------------------


def test_happy_a_working_binary_passes(tmp_path):
    _fake_binary(tmp_path / "dist", f'exec "{sys.executable}" "{ROOT / "main.py"}" "$@"')
    r = _smoke(tmp_path / "dist")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "smoke ok" in r.stdout


# --- sad ------------------------------------------------------------------


def test_sad_a_binary_that_fails_fails_the_smoke(tmp_path):
    _fake_binary(tmp_path / "dist", "echo broken >&2; exit 3")
    r = _smoke(tmp_path / "dist")
    assert r.returncode != 0
    assert "--version" in r.stdout + r.stderr


def test_sad_a_script_that_renders_no_svg_fails():
    # The 0.10.24 bundle listed folders fine and crashed on the first SVG
    # thumbnail (Qt 6.10.0 and the combined DisableAnimations option).
    sys.path.insert(0, str(SMOKE.parent))
    import bundle_smoke

    assert bundle_smoke.marker_problem(bundle_smoke.EXPECTED_MARKER) is None
    problem = bundle_smoke.marker_problem("listed a.txt")
    assert problem is not None and "svg" in problem.lower()


def test_sad_a_script_that_writes_no_marker_fails(tmp_path):
    # --version works, --script does nothing.
    _fake_binary(tmp_path / "dist", "exit 0")
    r = _smoke(tmp_path / "dist")
    assert r.returncode != 0
    assert "marker" in r.stdout + r.stderr


# --- edge -----------------------------------------------------------------


def test_edge_an_empty_dist_names_what_is_missing(tmp_path):
    (tmp_path / "dist").mkdir()
    r = _smoke(tmp_path / "dist")
    assert r.returncode != 0
    assert "axross-slim" in r.stdout + r.stderr
