"""A restored terminal of a profile is that profile's shell or a
placeholder - never a local shell.

Review 2026-11-20 (sessions round 2): File > Restore Last Session (and a
start that connects) made a saved terminal whose profile is gone a local
shell: _preset_make_terminal_pane falls back to "Local Shell" for an
unknown profile. Commands meant for the server then ran on this machine.
A file pane of a missing profile becomes a placeholder that says so; a
terminal does now too. And a profile an older version let be called
"local" restores (and reconnects) as that profile's shell, not as the
local shell its name looks like.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets")

from PyQt6.QtWidgets import QApplication  # noqa: E402

APP = QApplication.instance() or QApplication([])

from ui import main_window as MW  # noqa: E402


class _Splitter:
    def __init__(self):
        self.widgets = []

    def addWidget(self, widget):  # noqa: N802 - Qt's name
        self.widgets.append(widget)


class _Host:
    """The parts of MainWindow that restoring a terminal uses."""

    _restore_terminal = MW.MainWindow._restore_terminal
    _preset_make_terminal_pane = MW.MainWindow._preset_make_terminal_pane

    def __init__(self, profiles):
        self._profile_manager = SimpleNamespace(get=profiles.get)
        self._connection_manager = object()
        self.placeholders = []
        self.made = []

    def _make_placeholder(self, splitter, kind, name, path=""):
        self.placeholders.append((kind, name))

    def _local_folder_or_home(self, folder):
        return folder or "/"

    def _wire_terminal_pane(self, term):
        pass


@pytest.fixture
def panes(monkeypatch):
    made = []

    class FakePane:
        def __init__(self, transport=None, label="Local Shell", profile=None,
                     connection_manager=None, parent=None, cwd=None):
            made.append(SimpleNamespace(label=label, profile=profile, cwd=cwd))

    monkeypatch.setattr(MW, "TerminalPaneWidget", FakePane)
    return made


def test_sad_a_terminal_of_a_missing_profile_is_a_placeholder(panes):
    host = _Host({})
    host._restore_terminal(_Splitter(), {"type": "terminal", "profile": "gone"},
                           connect_remote=True)
    assert panes == []
    assert host.placeholders == [(MW.KIND_TERMINAL, "gone")]


def test_sad_a_profile_called_local_restores_as_that_profile(panes):
    profile = SimpleNamespace(name="local", terminal_theme="")
    host = _Host({"local": profile})
    host._restore_terminal(_Splitter(), {"type": "terminal", "profile": "local"},
                           connect_remote=True)
    assert [p.profile for p in panes] == [profile]


def test_happy_a_local_shell_and_a_known_profile_restore_as_before(panes):
    profile = SimpleNamespace(name="nas", terminal_theme="")
    host = _Host({"nas": profile})
    host._restore_terminal(_Splitter(), {"type": "terminal", "local": True, "cwd": "/tmp"},
                           connect_remote=True)
    host._restore_terminal(_Splitter(), {"type": "terminal", "profile": "nas"},
                           connect_remote=True)
    assert [(p.label, p.profile) for p in panes] == [("Local Shell", None), ("nas", profile)]
