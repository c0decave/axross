"""Forensic Tools: long conversions run to the end, with progress and Cancel
(review round 3).

Before: Convert to Raw Image ran ``qemu-img convert`` with the fixed
``TIMEOUT = 600``, so every conversion over 10 minutes - a large disk
image takes hours - was killed and its output deleted, with no progress
shown and no way to stop one either. Hash Image had a ``cancel`` hook
that nothing used. Now the conversion has no fixed limit, reports
``qemu-img -p``'s percentages, and both jobs show a dialog with Cancel.
"""

from __future__ import annotations

import os
import subprocess
import threading
import time

import pytest

from tests.test_forensic_tools_extension import FT, qapp, stub

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")
if os.name != "posix":  # pragma: no cover
    pytest.skip("the qemu-img stand-in is a shell script", allow_module_level=True)

from PyQt6.QtWidgets import QMainWindow, QMessageBox, QPushButton  # noqa: E402

INFO = 'if [ "$1" = info ]; then echo \'{"format": "qcow2", "virtual-size": 1}\'; exit 0; fi\n'


def _qemu(tmp_path, monkeypatch, convert_body: str):
    bin_dir = stub(tmp_path, "qemu-img", INFO + "for last; do :; done\n" + convert_body)
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
    src = tmp_path / "disk.qcow2"
    src.write_bytes(b"x")
    return src


def _wait(predicate, timeout=15.0):
    app = qapp()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        app.processEvents()
        if predicate():
            return True
        time.sleep(0.02)
    return predicate()


class ThreadedApi:
    """Runs the work on a worker thread and its callbacks on the GUI thread,
    as the extension host does."""

    def __init__(self):
        self.window = QMainWindow()
        self.actions = {}
        self.notes = []
        self.pending = []

    def add_context_action(self, label, cb, applies_to="any", extensions=()):
        self.actions[label] = cb

    def notify(self, text):
        self.notes.append(text)

    def run_in_background(self, work, on_done=None, on_error=None):
        box = {}

        def runner():
            try:
                box["value"] = work()
            except Exception as exc:  # noqa: BLE001
                box["error"] = exc

        thread = threading.Thread(target=runner, daemon=True)
        thread.start()

        def deliver():
            if thread.is_alive():
                return False
            if "error" in box:
                on_error(box["error"])
            else:
                on_done(box["value"])
            return True

        self.pending.append(deliver)

    def settle(self):
        self.pending = [d for d in self.pending if not d()]
        return not self.pending


def _cancel_button(api):
    buttons = [b for b in api.window.findChildren(QPushButton)
               if b.text() == "Cancel" and b.isVisible()]
    return buttons[0] if buttons else None


def test_sad_a_conversion_longer_than_ten_minutes_is_not_killed(tmp_path, monkeypatch):
    """Any fixed timeout is too short for some image: one given to
    subprocess.run expires here at once, standing for the 10 minutes."""
    src = _qemu(tmp_path, monkeypatch, 'printf raw > "$last"')
    real_run = subprocess.run

    def run(argv, *args, timeout=None, **kwargs):
        if "convert" in argv and timeout is not None:
            raise subprocess.TimeoutExpired(argv, timeout)
        return real_run(argv, *args, timeout=timeout, **kwargs)

    monkeypatch.setattr(FT.subprocess, "run", run)
    target = FT.convert_to_raw(str(src))
    assert open(target, "rb").read() == b"raw"


def test_happy_the_conversion_reports_its_progress(tmp_path, monkeypatch):
    log = tmp_path / "argv.log"
    src = _qemu(tmp_path, monkeypatch,
                f'echo "$@" > "{log}"\n'
                'printf "    (0.00/100%%)\\r    (37.50/100%%)\\r" ; printf raw > "$last"\n'
                'printf "    (100.00/100%%)\\r\\n"')
    seen = []
    FT.convert_to_raw(str(src), str(tmp_path / "out.raw"), progress=seen.append)
    assert 37.5 in seen and seen[-1] == 100.0
    assert "-p" in log.read_text().split()  # qemu-img prints its progress


def test_sad_cancel_stops_the_conversion_and_removes_the_half_written_image(tmp_path, monkeypatch):
    src = _qemu(tmp_path, monkeypatch, 'printf partial > "$last"; exec sleep 60')
    target = tmp_path / "out.raw"
    cancel = threading.Event()
    threading.Timer(0.5, cancel.set).start()
    started = time.monotonic()
    with pytest.raises(FT.Cancelled):
        FT.convert_to_raw(str(src), str(target), cancel=cancel.is_set)
    assert time.monotonic() - started < 10
    assert not target.exists()


def test_e2e_the_convert_dialog_has_a_cancel_button_that_stops_it(tmp_path, monkeypatch):
    src = _qemu(tmp_path, monkeypatch,
                'printf "    (12.00/100%%)\\r"; printf partial > "$last"; exec sleep 60')
    qapp()
    monkeypatch.setattr(QMessageBox, "exec", lambda box: QMessageBox.StandardButton.Yes)
    api = ThreadedApi()
    FT.activate(api)
    from types import SimpleNamespace

    ctx = SimpleNamespace(backend=None, folder=str(tmp_path), paths=[str(src)], items=[],
                          pane=None, is_local=True)
    api.actions["Convert to Raw Image (qemu-img)…"](ctx)
    assert _wait(lambda: _cancel_button(api) is not None), "no dialog with Cancel"
    assert _wait(lambda: (tmp_path / "disk.raw").exists())
    _cancel_button(api).click()
    assert _wait(api.settle), "the conversion did not stop"
    assert not (tmp_path / "disk.raw").exists()
    assert any("cancelled" in note for note in api.notes)
    assert _cancel_button(api) is None  # the dialog is gone


def test_e2e_hash_image_can_be_cancelled_and_shows_no_partial_hashes(tmp_path, monkeypatch):
    """Before, nothing called hash_image's cancel hook: no way to stop it."""
    qapp()
    shown = []
    monkeypatch.setattr(QMessageBox, "exec", lambda box: shown.append(box.text()))

    class Slow:
        def __init__(self):
            self.left = 10_000

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self, size=-1):
            time.sleep(0.01)
            self.left -= 1
            return b"\0" * 4096 if self.left > 0 else b""

    from types import SimpleNamespace

    api = ThreadedApi()
    FT.activate(api)
    backend = SimpleNamespace(open_read=lambda path: Slow())
    ctx = SimpleNamespace(backend=backend, folder="/img", paths=["/img/d.dd"], items=[],
                          pane=None, is_local=False)
    api.actions["Hash Image (MD5, SHA-1, SHA-256)"](ctx)
    assert _wait(lambda: _cancel_button(api) is not None), "no dialog with Cancel"
    _cancel_button(api).click()
    assert _wait(api.settle, 10), "hashing did not stop"
    assert shown == []  # no box with the hashes of the part read so far
    assert any("cancelled" in note for note in api.notes)
