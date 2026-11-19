"""The busy strip's Cancel button is disabled while the job cancels, in
every language.

Reproduced 2026-11-19 (independent review): BusyStrip disabled the button
when the progress text started with "Cancelling" - the English text. In
German the strip said "Wird abgebrochen…" and the button stayed enabled.
Now it asks the job (ScanJob.cancelling) instead of reading the text.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets")
from PyQt6.QtWidgets import QApplication  # noqa: E402

APP = QApplication.instance() or QApplication([])


@pytest.fixture
def language():
    from core import i18n

    before = i18n.active()

    def use(lang: str) -> None:
        i18n.install(lang)

    yield use
    i18n._ACTIVE = before


def _pump(seconds: float) -> None:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        APP.processEvents()
        time.sleep(0.01)


@pytest.mark.parametrize("lang", ["en", "de", "es"])
def test_happy_the_cancel_button_is_off_while_cancelling(language, lang):
    from ui.scan_job import BusyStrip, ScanJob

    language(lang)
    job = ScanJob(interval_ms=20)
    strip = BusyStrip(job)
    tidying = threading.Event()

    def work(cancel, report):
        while not cancel():
            time.sleep(0.005)
        tidying.wait(2.0)  # still tidying up after the cancel
        return 1

    try:
        job.start(work)
        _pump(0.05)
        assert strip.cancel_button.isEnabled()
        job.cancel()
        _pump(0.2)
        assert job.cancelling
        assert not strip.cancel_button.isEnabled(), strip.label.text()
    finally:
        tidying.set()
        _pump(0.1)
        strip.deleteLater()
        job.deleteLater()


def test_edge_a_new_job_enables_it_again(language):
    from ui.scan_job import BusyStrip, ScanJob

    language("de")
    job = ScanJob(interval_ms=20)
    strip = BusyStrip(job)
    try:
        job.start(lambda cancel, report: [time.sleep(0.01) for _ in range(5) if not cancel()])
        job.cancel()
        _pump(0.2)
        job.start(lambda cancel, report: time.sleep(0.2))
        _pump(0.05)
        assert strip.cancel_button.isEnabled()
        _pump(0.3)
    finally:
        strip.deleteLater()
        job.deleteLater()
