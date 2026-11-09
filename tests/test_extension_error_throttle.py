"""A failing extension handler logs its traceback once, not on every event.

Review round 6 (F3): an extension whose ``selection_changed`` handler
raised logged a full ERROR traceback for every selection change - 50
clicks, 101 ERROR records - and rewrote the status bar each time. Now the
traceback is logged once per (extension, handler, exception type); repeats
are counted at DEBUG, and the status bar and the manager's error text
follow at most every ERROR_REPEAT_SECONDS.
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication, QMainWindow, QMenu  # noqa: E402

from ui import extension_host as EH  # noqa: E402

APP = QApplication.instance() or QApplication([])


class _Counting(logging.Handler):
    def __init__(self):
        super().__init__(level=logging.DEBUG)
        self.records: list[logging.LogRecord] = []

    def emit(self, record):
        if record.name == EH.log.name:
            self.records.append(record)

    def at(self, level):
        return [r for r in self.records if r.levelno == level]


@pytest.fixture
def host(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "home" / ".config"))
    window = QMainWindow()
    menu = QMenu(window)
    the_host = EH.ExtensionHost(window, menu)
    yield the_host
    window.deleteLater()


@pytest.fixture
def counted():
    handler = _Counting()
    logger = EH.log
    old_level = logger.level
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    yield handler
    logger.removeHandler(handler)
    logger.setLevel(old_level)


def _api(ext_id="user:spam", name="Spam"):
    return SimpleNamespace(info=SimpleNamespace(ext_id=ext_id, name=name))


def _boom(_ctx):
    return 1 / 0


def test_sad_a_handler_failing_on_every_event_logs_one_traceback(host, counted, monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(EH.time, "monotonic", lambda: clock[0])
    shown: list = []
    host.window.statusBar().messageChanged.connect(shown.append)
    api = _api()
    for _ in range(50):
        host.call(api, _boom, None)
        clock[0] += 0.01
    errors = counted.at(logging.ERROR)
    assert len(errors) == 1
    assert "Traceback" in errors[0].getMessage()
    assert len(counted.at(logging.DEBUG)) == 49
    assert len([m for m in shown if m]) == 1  # 0.5 s of events: one status message
    assert host.error("user:spam").startswith("ZeroDivisionError")


def test_happy_the_count_reaches_the_status_bar_every_few_seconds(host, counted, monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(EH.time, "monotonic", lambda: clock[0])
    api = _api()
    host.call(api, _boom, None)
    for _ in range(3):
        clock[0] += 1.0
        host.call(api, _boom, None)
    clock[0] += EH.ERROR_REPEAT_SECONDS
    host.call(api, _boom, None)
    assert "5 times" in host.window.statusBar().currentMessage()
    assert len(counted.at(logging.ERROR)) == 1


def test_edge_another_handler_or_exception_type_gets_its_own_traceback(host, counted):
    api = _api()

    def other(_ctx):
        raise KeyError("x")

    def boom_value(ctx):
        raise ValueError(ctx)

    host.call(api, _boom, None)
    host.call(api, other, None)
    host.call(api, boom_value, "a")
    host.call(api, boom_value, "b")  # same handler, same type: a repeat
    host.call(_api("user:other", "Other"), _boom, None)  # another extension
    assert len(counted.at(logging.ERROR)) == 4
