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


# --- --native: the real window ---------------------------------------------


def _native(dist: Path) -> subprocess.CompletedProcess:
    # No display on a CI Linux runner: the outer environment's offscreen
    # stands in for the native platform, which --native never overrides.
    env = {**os.environ, "QT_QPA_PLATFORM": "offscreen"}
    return subprocess.run(
        [sys.executable, str(SMOKE), "--native", str(dist)],
        capture_output=True, text=True, timeout=300, env=env,
    )


def test_happy_native_opens_the_window(tmp_path):
    _fake_binary(tmp_path / "dist", f'exec "{sys.executable}" "{ROOT / "main.py"}" "$@"')
    r = _native(tmp_path / "dist")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "window shown on offscreen" in r.stdout and "smoke ok" in r.stdout


def test_sad_native_reports_a_crash_on_the_way_to_the_window(tmp_path):
    # What a crashing GUI start looks like: Qt aborts, no window line.
    _fake_binary(
        tmp_path / "dist", 'echo "Cannot create window: no screens available" >&2; kill -ABRT $$'
    )
    r = _native(tmp_path / "dist")
    assert r.returncode != 0
    assert "no window" in r.stdout and "no screens available" in r.stdout


def test_edge_the_newest_crash_report_of_the_binary_is_shown(tmp_path):
    sys.path.insert(0, str(SMOKE.parent))
    import bundle_smoke

    reports = tmp_path / "DiagnosticReports"
    reports.mkdir()
    old = reports / "axross-slim-2026-10-01-090000.ips"
    old.write_text("old crash")
    os.utime(old, (1, 1))
    other = reports / "Safari-2026-10-16-210000.ips"
    other.write_text("not ours")
    new = reports / "axross-slim-2026-10-16-213000.ips"
    new.write_text('{"exception": {"type": "EXC_CRASH", "signal": "SIGABRT"}}')
    text = bundle_smoke.crash_report("axross-slim", reports, since=2.0)
    assert "SIGABRT" in text and "old crash" not in text and "not ours" not in text
    assert bundle_smoke.crash_report("axross-slim", tmp_path / "missing", since=0) == ""


# --- the native libraries of axross-full (--libs) ---------------------------
#
# axross-full 0.13.22 passed --version and --script, yet numpy could not
# load its OpenBLAS (stripped by the builder): voice output and recognition
# failed on first use. --libs imports the native packages inside the binary
# and does real work with numpy.


def _libs(dist: Path, *modules: str) -> list[str]:
    sys.path.insert(0, str(SMOKE.parent))
    import bundle_smoke

    return bundle_smoke.native_libs(dist, modules=modules or bundle_smoke.FULL_NATIVE)


def _full_binary(dist: Path) -> Path:
    dist.mkdir(parents=True, exist_ok=True)
    exe = dist / "axross-full"
    exe.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{ROOT / "main.py"}" "$@"\n')
    exe.chmod(0o755)
    return exe


def test_happy_libs_passes_when_every_module_imports(tmp_path):
    _full_binary(tmp_path / "dist")
    assert _libs(tmp_path / "dist", "json", "math") == []


def test_happy_the_full_list_covers_voice_and_numpy_work():
    sys.path.insert(0, str(SMOKE.parent))
    import bundle_smoke

    for name in ("numpy", "onnxruntime", "ctranslate2", "piper", "faster_whisper"):
        assert name in bundle_smoke.FULL_NATIVE
    assert "dot" in bundle_smoke._LIBS_SCRIPT  # numpy does real work, not just import


def test_sad_a_module_that_does_not_load_is_named(tmp_path):
    _full_binary(tmp_path / "dist")
    problems = _libs(tmp_path / "dist", "json", "no_such_native_module_xyz")
    assert len(problems) == 1
    assert "no_such_native_module_xyz" in problems[0]
    assert "ModuleNotFoundError" in problems[0]


def test_sad_the_command_line_fails_on_a_broken_module(tmp_path):
    _fake_binary(tmp_path / "dist", "exit 0")  # a slim stand-in only
    r = subprocess.run([sys.executable, str(SMOKE), "--libs", str(tmp_path / "dist")],
                       capture_output=True, text=True, timeout=120)
    assert r.returncode != 0
    assert "axross-full" in r.stdout + r.stderr


def test_edge_libs_wants_the_full_binary_not_slim(tmp_path):
    _fake_binary(tmp_path / "dist", f'exec "{sys.executable}" "{ROOT / "main.py"}" "$@"')
    problems = _libs(tmp_path / "dist", "json")
    assert problems and "axross-full" in problems[0]


def test_edge_the_build_runs_the_libs_check_for_full():
    text = (ROOT / "scripts" / "build_bundle.sh").read_text(encoding="utf-8")
    assert "bundle_smoke.py --libs" in text


def test_sad_libs_reports_a_bundled_glibc_part(tmp_path):
    # The frozen check also lists the bundle's own folder: a glibc part
    # there (libmvec, 0.13.22 full) shadows the host's.
    sys.path.insert(0, str(SMOKE.parent))
    import bundle_smoke

    meipass = tmp_path / "meipass"
    meipass.mkdir()
    (meipass / "libmvec.so.1").write_bytes(b"")
    (meipass / "libstdc++.so.6").write_bytes(b"")
    (meipass / "libz.so.1").write_bytes(b"")
    # libstdc++ is the host's too since the GL abort (test_bundle_version_floor).
    assert bundle_smoke.bundled_host_libraries(str(meipass)) == ["libmvec.so.1", "libstdc++.so.6"]


# --- system libraries of both binaries (--system-libs) -----------------------
#
# PyInstaller leaves a library it cannot find on the build machine to the
# target system without a word: 0.13.x shipped Qt's TIFF plugin needing
# libtiff.so.5 and Qt's xcb plugin needing libxcb-cursor.so.0. The check
# runs inside each binary, on its unpacked folder (sys._MEIPASS).


def _frozen_stand_in(dist: Path, name: str, meipass: Path) -> Path:
    """A binary whose --script runs with sys._MEIPASS = *meipass*."""
    dist.mkdir(parents=True, exist_ok=True)
    exe = dist / name
    exe.write_text(
        "#!/bin/sh\n"
        f'exec "{sys.executable}" -c "import runpy, sys; sys._MEIPASS = sys.argv[1]; '
        f'runpy.run_path(sys.argv[2])" "{meipass}" "$2"\n'
    )
    exe.chmod(0o755)
    return exe


def _system_libs(dist: Path) -> list[str]:
    sys.path.insert(0, str(SMOKE.parent))
    import bundle_smoke

    return bundle_smoke.system_libs(dist)


def _tree(path: Path, needs: dict[str, list[str]]) -> Path:
    sys.path.insert(0, str(ROOT / "tests"))
    from test_bundle_system_libs import _elf

    for rel, sonames in needs.items():
        (path / rel).parent.mkdir(parents=True, exist_ok=True)
        (path / rel).write_bytes(_elf(sonames))
    return path


def test_happy_system_libs_passes_a_bundle_that_carries_its_libraries(tmp_path):
    tree = _tree(tmp_path / "mei", {"plugins/libqtiff.so": ["libtiff.so.5", "libc.so.6"],
                                    "libtiff.so.5": ["libc.so.6", "libGL.so.1"]})
    _frozen_stand_in(tmp_path / "dist", "axross-slim", tree)
    _frozen_stand_in(tmp_path / "dist", "axross-full", tree)
    assert _system_libs(tmp_path / "dist") == []


def test_sad_system_libs_names_the_missing_library_per_binary(tmp_path):
    good = _tree(tmp_path / "good", {"libok.so": ["libc.so.6"]})
    bad = _tree(tmp_path / "bad", {"plugins/libqxcb.so": ["libxcb-cursor.so.0"]})
    _frozen_stand_in(tmp_path / "dist", "axross-slim", good)
    _frozen_stand_in(tmp_path / "dist", "axross-full", bad)
    problems = _system_libs(tmp_path / "dist")
    assert len(problems) == 1
    assert problems[0].startswith("axross-full:") and "libxcb-cursor.so.0" in problems[0]


def test_sad_system_libs_fails_on_a_binary_that_is_not_frozen(tmp_path):
    _fake_binary(tmp_path / "dist", f'exec "{sys.executable}" "{ROOT / "main.py"}" "$@"')
    problems = _system_libs(tmp_path / "dist")
    assert problems and "not a frozen binary" in problems[0]


def test_sad_the_command_line_fails_without_any_binary(tmp_path):
    (tmp_path / "dist").mkdir()
    r = subprocess.run([sys.executable, str(SMOKE), "--system-libs", str(tmp_path / "dist")],
                       capture_output=True, text=True, timeout=120)
    assert r.returncode != 0 and "no axross binary" in r.stdout


def test_edge_a_dropped_plugin_does_not_count(tmp_path):
    tree = _tree(tmp_path / "mei", {"libok.so": ["libc.so.6"],
                                    "PyQt6/Qt6/plugins/platformthemes/libqgtk3.so":
                                        ["libgtk-3.so.0"]})
    _frozen_stand_in(tmp_path / "dist", "axross-slim", tree)
    assert _system_libs(tmp_path / "dist") == []


def test_edge_the_build_runs_the_system_libs_check_for_every_flavor():
    text = (ROOT / "scripts" / "build_bundle.sh").read_text(encoding="utf-8")
    at = text.index("bundle_smoke.py --system-libs")
    # Not inside the full-only block.
    assert text.rfind('if [[ "$FLAVOR" == "full" ]]', 0, at) < text.rfind("fi\n", 0, at)


def test_edge_system_libs_on_one_binary_ignores_a_stale_sibling(tmp_path):
    # build_bundle.sh builds one flavor; dist/ may hold an old binary of the other.
    good = _tree(tmp_path / "good", {"libok.so": ["libc.so.6"]})
    bad = _tree(tmp_path / "bad", {"plugins/libqtiff.so": ["libtiff.so.5"]})
    slim = _frozen_stand_in(tmp_path / "dist", "axross-slim", good)
    _frozen_stand_in(tmp_path / "dist", "axross-full", bad)
    assert _system_libs(slim) == []
    text = (ROOT / "scripts" / "build_bundle.sh").read_text(encoding="utf-8")
    assert 'bundle_smoke.py --system-libs "$ELF_PATH"' in text


def test_sad_system_libs_reports_a_bundled_libstdcxx(tmp_path):
    tree = _tree(tmp_path / "mei", {"libok.so": ["libc.so.6"], "libstdc++.so.6": ["libc.so.6"]})
    _frozen_stand_in(tmp_path / "dist", "axross-slim", tree)
    problems = _system_libs(tmp_path / "dist")
    assert problems and "bundled host library libstdc++.so.6" in problems[0]


# --- what a child process of the binary sees -----------------------------------
#
# A frozen binary pointed LD_LIBRARY_PATH, QT_PLUGIN_PATH and QML2_IMPORT_PATH
# into its unpacked folder and passed them (and _PYI_*) to every child: bash
# died on our readline, ffprobe on our libstdc++. --system-libs starts children
# inside the binary the ways third-party code does - subprocess without env=,
# os.system, QProcess - and fails when one of them sees the bundle.


def _leaky_stand_in(dist: Path, name: str, meipass: Path, **env: str) -> Path:
    dist.mkdir(parents=True, exist_ok=True)
    exe = dist / name
    exports = "".join(f'export {k}="{v}"\n' for k, v in env.items())
    exe.write_text(
        "#!/bin/sh\n" + exports +
        f'exec "{sys.executable}" -c "import runpy, sys; sys._MEIPASS = sys.argv[1]; '
        f'runpy.run_path(sys.argv[2])" "{meipass}" "$2"\n'
    )
    exe.chmod(0o755)
    return exe


def test_sad_a_child_that_sees_the_bundle_fails_the_gate(tmp_path):
    tree = _tree(tmp_path / "mei", {"libok.so": ["libc.so.6"]})
    _leaky_stand_in(tmp_path / "dist", "axross-slim", tree,
                    QT_PLUGIN_PATH=f"{tree}/PyQt6/Qt6/plugins", _PYI_ARCHIVE_FILE="/x/axross-slim")
    text = "\n".join(_system_libs(tmp_path / "dist"))
    for how in ("subprocess", "os.system", "QProcess"):
        assert f"child via {how} sees QT_PLUGIN_PATH" in text, how
    assert "_PYI_ARCHIVE_FILE" in text


def test_sad_ld_library_path_into_the_bundle_is_named(tmp_path):
    tree = _tree(tmp_path / "mei", {"libok.so": ["libc.so.6"]})
    _leaky_stand_in(tmp_path / "dist", "axross-slim", tree, LD_LIBRARY_PATH=str(tree))
    assert "sees LD_LIBRARY_PATH" in "\n".join(_system_libs(tmp_path / "dist"))


def test_edge_a_clean_child_environment_passes(tmp_path):
    tree = _tree(tmp_path / "mei", {"libok.so": ["libc.so.6"]})
    _leaky_stand_in(tmp_path / "dist", "axross-slim", tree, QT_PLUGIN_PATH="/opt/own/plugins")
    assert _system_libs(tmp_path / "dist") == []
