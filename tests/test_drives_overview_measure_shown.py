"""Drives Overview measures only the mounts it shows, and never an automount.

The review found ``activate`` refreshing with ``measure(list_drives())``:
statvfs on every mount of /proc/self/mounts - proc, sysfs, cgroup, the
autofs points - although the panel hides system and memory mounts by
default. statvfs on an autofs point mounts what is behind it, and each
dead one left a probe thread hanging for good. Now only the shown drives
are measured (system and memory mounts once "Show system and memory
mounts" is ticked), autofs never.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import extensions as EX  # noqa: E402

APP = QApplication.instance() or QApplication([])


def _load():
    spec = importlib.util.spec_from_file_location(
        "drives_overview_measure_shown", EX.bundled_dir() / "drives_overview.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses need it
    spec.loader.exec_module(module)
    return module


DO = _load()

MOUNTS = """\
/dev/sda3 / ext4 rw,relatime 0 0
proc /proc proc rw 0 0
sysfs /sys sysfs rw 0 0
cgroup2 /sys/fs/cgroup cgroup2 rw 0 0
systemd-1 /mnt/auto autofs rw,fd=40 0 0
tmpfs /tmp tmpfs rw 0 0
//nas/share /mnt/nas cifs rw 0 0
"""


class Usage:
    def __init__(self) -> None:
        self.asked: list[str] = []

    def __call__(self, path):
        self.asked.append(path)
        return (100, 50, 50)


def test_happy_only_the_drives_the_panel_shows_are_measured():
    usage = Usage()
    drives = DO.measure_shown(DO.parse_proc_mounts(MOUNTS), usage=usage)
    assert sorted(usage.asked) == ["/", "/mnt/nas"]
    by_mount = {d.mount: d for d in drives}
    assert by_mount["/"].total == 100 and by_mount["/proc"].total is None
    assert len(drives) == 7  # the others are still listed, size unknown


def test_happy_system_mounts_are_measured_once_shown_but_never_autofs():
    usage = Usage()
    drives = DO.measure_shown(DO.parse_proc_mounts(MOUNTS), True, usage=usage)
    assert "/proc" in usage.asked and "/tmp" in usage.asked
    assert "/mnt/auto" not in usage.asked
    auto = next(d for d in drives if d.mount == "/mnt/auto")
    assert auto.total is None and auto.error == DO.AUTOFS_NOTE


class Api:
    def __init__(self) -> None:
        self.jobs: list = []
        self.dock = None

    def add_dock(self, title, widget, icon=None):
        self.dock = widget

    def current(self):
        return None

    def notify(self, text):
        pass

    def run_in_background(self, work, on_done=None, on_error=None):
        self.jobs.append((work, on_done, on_error))


def test_happy_the_panel_measures_the_shown_drives_and_more_when_ticked(monkeypatch):
    usage = Usage()
    monkeypatch.setattr(DO, "_usage", usage)
    monkeypatch.setattr(DO, "list_drives", lambda: DO.parse_proc_mounts(MOUNTS))
    real_measure_shown = DO.measure_shown
    monkeypatch.setattr(DO, "measure_shown",
                        lambda drives, show=False: real_measure_shown(drives, show, usage=usage))
    api = Api()
    DO.activate(api)
    panel = api.dock
    try:
        (work, done, _failed), = api.jobs
        done(work())
        assert sorted(usage.asked) == ["/", "/mnt/nas"]
        usage.asked.clear()
        panel.show_system.setChecked(True)  # the hidden ones are measured now
        work, done, _failed = api.jobs[-1]
        done(work())
        assert "/proc" in usage.asked and "/mnt/auto" not in usage.asked
        assert panel.table.rowCount() == 7
    finally:
        panel.close()


def test_edge_ticking_while_a_measurement_runs_measures_again_after_it():
    api = Api()
    DO.activate(api)
    panel = api.dock
    try:
        assert len(api.jobs) == 1
        panel.show_system.setChecked(True)  # busy: noted, not started
        assert len(api.jobs) == 1
        _work, done, _failed = api.jobs[0]
        done([])
        assert len(api.jobs) == 2
    finally:
        panel.close()
