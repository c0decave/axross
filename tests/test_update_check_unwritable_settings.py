"""The update check ends - and says how - when settings.json cannot be written.

Review 2026-11-19 (round 1): ``UpdateController._on_checked`` stored the
result with ``record_check`` unguarded. A settings.json that cannot be read
for the merge or a config folder that cannot be written (read-only home,
disk full) raised OSError out of the ScanJob slot: the check at start showed
an "Unexpected Error" dialog although it never shows one, and the state
stayed CHECKING - "Checking for updates…" for the rest of the run. Skip
This Version raised the same way. The result is shown now; that it could
not be stored goes to the log.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import self_update as SU  # noqa: E402

APP = QApplication.instance() or QApplication([])


@pytest.fixture
def controller(monkeypatch):
    from ui import update_ui

    def refuse(*_args, **_kwargs):
        raise PermissionError(13, "Permission denied", "settings.json")

    monkeypatch.setattr(SU, "record_check", refuse)
    monkeypatch.setattr(SU, "set_skipped_version", refuse)
    monkeypatch.setattr(SU, "skipped_version", lambda: "")
    c = update_ui.UpdateController()
    c.install_info = SU.detect_install(frozen=False)
    yield c
    c.deleteLater()


def test_sad_a_failed_check_is_shown_though_it_cannot_be_stored(controller, caplog):
    controller._on_checked("error", SU.UpdateError("no route to host"), False)
    assert controller.state == "error"
    assert "no route to host" in controller.message
    assert "Permission denied" in caplog.text


def test_sad_a_current_version_is_shown_though_it_cannot_be_stored(controller):
    result = SU.CheckResult(current="1.0.0", release=None, newer=False,
                            message="axross is up to date.")
    controller._on_checked("done", result, False)
    assert controller.state == "current"


def test_sad_skip_version_with_unwritable_settings_still_dismisses(controller, caplog):
    controller.release = SU.Release(version="99.0.0", tag="v99.0.0", page_url="", notes="",
                                    assets=())
    controller.skip_version()
    assert controller._dismissed
    assert "Permission denied" in caplog.text
