"""No screen: say so and exit 1, instead of Qt's abort.

Measured 2026-10-16 on macOS 27.0.1: the bundle started over SSH as a
user without a desktop session loaded the cocoa platform with zero
screens, and Qt aborted in ``QMainWindow.menuBar()`` with "Cannot create
window: no screens available" - SIGABRT and two crash reports that read
like a bug in axross. main() now checks for a screen before it builds
the window.
"""

from __future__ import annotations

import main


class _App:
    def __init__(self, screens, platform="cocoa"):
        self._screens = screens
        self._platform = platform

    def screens(self):
        return self._screens

    def platformName(self):
        return self._platform


def test_happy_a_screen_means_no_message():
    assert main._no_screen_message(_App([object()])) is None


def test_sad_no_screen_names_the_platform_and_the_ways_out():
    msg = main._no_screen_message(_App([], "cocoa"))
    assert msg is not None
    assert "no screen" in msg and "'cocoa'" in msg
    for way_out in ("desktop session", "--mcp-server", "--script", "QT_QPA_PLATFORM=offscreen"):
        assert way_out in msg


def test_edge_several_screens_and_another_platform_are_fine():
    assert main._no_screen_message(_App([object(), object()], "wayland")) is None
    assert "'xcb'" in main._no_screen_message(_App([], "xcb"))
