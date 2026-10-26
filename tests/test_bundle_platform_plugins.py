"""Release gate: a built Linux bundle carries the Qt platform plugins axross
starts on (xcb, wayland, offscreen) and none that bundle_options.DROPPED
removes - libqvnc above all (CVE-2026-79680, VNC password authentication
bypass, open in Qt 6.11.2).

Reads dist/axross-full and dist/axross-slim, or the one binary
AXROSS_FROZEN_BINARY names, with PyInstaller's archive reader; skips
without them. The rule itself is tested in tests/test_bundle_options.py.
"""

from __future__ import annotations

import os
import posixpath
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import bundle_options as B  # noqa: E402

PLATFORMS = "PyQt6/Qt6/plugins/platforms/"


def _binaries() -> list[Path]:
    named = os.environ.get("AXROSS_FROZEN_BINARY", "")
    if named:
        return [Path(named)]
    return [p for p in (ROOT / "dist" / "axross-full", ROOT / "dist" / "axross-slim") if p.is_file()]


def toc_names(path: Path) -> list[str]:
    readers = pytest.importorskip("PyInstaller.archive.readers")
    return list(readers.CArchiveReader(str(path)).toc)


def dangling_links(links: dict[str, str], names: list[str]) -> list[str]:
    """Symbolic-link entries (name -> relative target) of a table of contents
    whose target is not in it."""
    present = set(names)
    return [f"{n} -> {t}" for n, t in sorted(links.items())
            if posixpath.normpath(posixpath.join(posixpath.dirname(n), t)) not in present]


def toc_links(path: Path) -> dict[str, str]:
    readers = pytest.importorskip("PyInstaller.archive.readers")
    archive = readers.CArchiveReader(str(path))
    return {n: archive.extract(n).rstrip(b"\0").decode("utf-8")
            for n, entry in archive.toc.items() if entry[-1] == "n"}


def platform_problems(names: list[str]) -> list[str]:
    """What is wrong with the table of contents *names* of a Linux bundle."""
    problems = [f"dropped file in the bundle: {n}" for n in names if B.dropped(n)]
    plugins = {n[len(PLATFORMS):] for n in names if n.startswith(PLATFORMS)}
    for needed in ("libqxcb.so", "libqoffscreen.so"):
        if needed not in plugins:
            problems.append(f"platform plugin missing: {needed}")
    if not any(p.startswith("libqwayland") for p in plugins):
        problems.append("platform plugin missing: libqwayland*")
    return problems


# --- the check on made-up tables of contents -------------------------------


def test_happy_a_bundle_with_only_the_used_platforms_passes():
    names = [PLATFORMS + "libqxcb.so", PLATFORMS + "libqwayland.so", PLATFORMS + "libqoffscreen.so",
             "PyQt6/Qt6/lib/libQt6Core.so.6"]
    assert platform_problems(names) == []


def test_sad_the_vnc_plugin_and_a_missing_platform_are_reported():
    names = [PLATFORMS + "libqxcb.so", PLATFORMS + "libqvnc.so", PLATFORMS + "libqoffscreen.so",
             "PyQt6/Qt6/plugins/egldeviceintegrations/libqeglfs-x11-integration.so"]
    problems = platform_problems(names)
    assert f"dropped file in the bundle: {PLATFORMS}libqvnc.so" in problems
    assert any("egldeviceintegrations" in p for p in problems)
    assert "platform plugin missing: libqwayland*" in problems


def test_sad_a_link_to_a_dropped_library_dangles():
    names = ["PyQt6/Qt6/lib/libQt6Core.so.6", "libQt6Core.so.6", "libQt6EglFSDeviceIntegration.so.6"]
    links = {"libQt6Core.so.6": "PyQt6/Qt6/lib/libQt6Core.so.6",
             "libQt6EglFSDeviceIntegration.so.6": "PyQt6/Qt6/lib/libQt6EglFSDeviceIntegration.so.6"}
    assert dangling_links(links, names) == [
        "libQt6EglFSDeviceIntegration.so.6 -> PyQt6/Qt6/lib/libQt6EglFSDeviceIntegration.so.6"]


def test_edge_wayland_under_either_name_counts():
    """Qt 6.10 shipped libqwayland-egl / -generic, 6.11 one libqwayland."""
    base = [PLATFORMS + "libqxcb.so", PLATFORMS + "libqoffscreen.so"]
    assert platform_problems(base + [PLATFORMS + "libqwayland-generic.so"]) == []


# --- release: the real binaries --------------------------------------------

BINARIES = _binaries()


@pytest.mark.skipif(not BINARIES, reason="no built binary in dist/ and AXROSS_FROZEN_BINARY unset")
@pytest.mark.parametrize("path", BINARIES, ids=[p.name for p in BINARIES])
def test_release_the_bundle_carries_only_the_used_platform_plugins(path):
    assert platform_problems(toc_names(path)) == []


@pytest.mark.skipif(not BINARIES, reason="no built binary in dist/ and AXROSS_FROZEN_BINARY unset")
@pytest.mark.parametrize("path", BINARIES, ids=[p.name for p in BINARIES])
def test_release_no_link_in_the_bundle_dangles(path):
    """A file the build drops must take its links along."""
    assert dangling_links(toc_links(path), toc_names(path)) == []
