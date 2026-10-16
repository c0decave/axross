"""The PyInstaller EXE options per operating system.

build/axross.spec was written for Linux: strip=True and upx=True on every
platform. On Windows strip has no tool to run and UPX corrupts Qt DLLs;
on macOS stripping invalidates the code signatures of the bundled
libraries, and a windowed one-file build is deprecated there. Linux keeps
exactly what it had.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import bundle_options as B  # noqa: E402

# --- happy ----------------------------------------------------------------


def test_happy_linux_keeps_strip_upx_and_no_console():
    o = B.exe_options("linux")
    assert (o["strip"], o["upx"], o["console"]) == (True, True, False)
    assert o["upx_exclude"] == ["libQt6*.so*", "libicu*.so*"]


def test_happy_windows_is_a_windowed_exe_without_strip_or_upx():
    o = B.exe_options("win32")
    assert (o["strip"], o["upx"], o["console"]) == (False, False, False)


def test_happy_macos_is_a_plain_unsigned_executable():
    o = B.exe_options("darwin")
    assert (o["strip"], o["upx"], o["console"]) == (False, False, True)


# --- sad ------------------------------------------------------------------


def test_sad_an_unknown_platform_is_refused():
    with pytest.raises(ValueError, match="sunos5"):
        B.exe_options("sunos5")


def test_sad_the_spec_takes_its_options_from_here():
    spec = (ROOT / "build" / "axross.spec").read_text(encoding="utf-8")
    assert "exe_options(sys.platform)" in spec
    assert not re.search(r"^\s*(strip|upx|console)=", spec, re.M), "spec still hard-codes them"


# --- edge -----------------------------------------------------------------


@pytest.mark.parametrize("name", ["linux", "linux2"])
def test_edge_every_linux_spelling_is_linux(name):
    assert B.exe_options(name) == B.exe_options("linux")


def test_edge_each_call_returns_a_fresh_dict():
    a = B.exe_options("linux")
    a["upx_exclude"].append("x")
    assert "x" not in B.exe_options("linux")["upx_exclude"]
