"""Mount as FUSE / Unmount FUSE report what really happened.

UX review round 3: the pane said "Mounted ... at ..." when libfuse refused
the mount a moment after ``core.fuse_mount.mount()`` returned (no
/dev/fuse, a busy or non-empty folder) - the loop thread had already died
and nothing was mounted - and then refused every new try with "This pane
already has a FUSE mount". Unmount ran ``fusermount -u`` and ``umount``
without looking at their exit codes, said "Unmounted" after a busy
unmount (the mount still served) and forgot the handle, so Unmount FUSE
vanished from the menu while the mount stayed.

Now the pane waits until ``os.path.ismount()`` shows the mount while its
loop thread lives, ``MountHandle.unmount()`` raises ``UnmountError`` unless
the mount is gone and its loop ended, and the pane keeps the handle then.
"""

from __future__ import annotations

import os
import subprocess
import sys
import threading
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication, QFileDialog, QMessageBox  # noqa: E402

from core import fuse_mount as FM  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

APP = QApplication.instance() or QApplication([])


class _Boxes:
    """Every QMessageBox.information / warning / critical, as (kind, text)."""

    def __init__(self) -> None:
        self.shown: list[tuple[str, str]] = []

    def patches(self):
        def record(kind):
            def box(_parent, _title, text, *_a, **_k):
                self.shown.append((kind, str(text)))
                return QMessageBox.StandardButton.Ok
            return box

        return [mock.patch.object(QMessageBox, kind, staticmethod(record(kind)))
                for kind in ("information", "warning", "critical")]

    def kinds(self) -> list[str]:
        return [kind for kind, _text in self.shown]


@pytest.fixture
def pane(tmp_path):
    from ui.file_pane import FilePaneWidget

    widget = FilePaneWidget(LocalFS())
    widget.navigate(str(tmp_path))
    yield widget
    widget._fuse_handle = None  # a fake handle must not reach shutdown's unmount
    widget.shutdown()
    widget.deleteLater()


@pytest.fixture
def boxes():
    recorder = _Boxes()
    patches = recorder.patches()
    for p in patches:
        p.start()
    yield recorder
    for p in patches:
        p.stop()


def _refusing_fuse(*_args, **_kwargs):
    raise RuntimeError(1)  # what fusepy raises when fuse_main() fails


def _mount_with(pane, mount_point: Path, fuse) -> None:
    with mock.patch.object(FM, "FUSE", fuse, create=True), \
            mock.patch.object(FM, "FUSE_AVAILABLE", True), \
            mock.patch.object(FM, "BackendFuseFS", lambda *a, **k: object()), \
            mock.patch.object(QFileDialog, "getExistingDirectory",
                              staticmethod(lambda *a, **k: str(mount_point))):
        pane._mount_as_fuse()


def _handle(mount_point: str, thread: threading.Thread) -> FM.MountHandle:
    return FM.MountHandle(mount_point=mount_point, backend_id="LocalFS", _thread=thread)


def _completed(returncode: int, stderr: bytes = b""):
    def run(cmd, **_kwargs):
        return subprocess.CompletedProcess(cmd, returncode, b"", stderr)
    return run


# --- mount ------------------------------------------------------------------


def test_sad_a_mount_libfuse_refuses_is_not_reported_as_mounted(pane, boxes, tmp_path):
    """The loop thread died at once; the pane said "Mounted" and kept it."""
    mnt = tmp_path / "mnt"
    mnt.mkdir()
    _mount_with(pane, mnt, _refusing_fuse)
    assert boxes.kinds() == ["critical"], boxes.shown
    assert "Mounted" not in boxes.shown[0][1]
    assert "/dev/fuse" in boxes.shown[0][1]  # what to check next
    assert pane._fuse_handle is None


def test_sad_a_failed_mount_does_not_block_the_next_try(pane, boxes, tmp_path):
    """The dead handle answered every new try with "already has a FUSE
    mount" - until the pane was closed."""
    mnt = tmp_path / "mnt"
    mnt.mkdir()
    _mount_with(pane, mnt, _refusing_fuse)
    _mount_with(pane, mnt, _refusing_fuse)
    assert boxes.kinds() == ["critical", "critical"], boxes.shown
    assert not any("already has" in text for _kind, text in boxes.shown)


def test_edge_a_mount_is_reported_only_once_the_kernel_shows_it(pane, boxes, tmp_path):
    """A loop that runs but never mounts is no mount; one that mounts is."""
    mnt = tmp_path / "mnt"
    mnt.mkdir()
    release = threading.Event()
    mounted = {"now": False}

    def serving_fuse(*_args, **_kwargs):
        release.wait(10)

    try:
        with mock.patch.object(FM.os.path, "ismount",
                               lambda p: mounted["now"] and str(p) == str(mnt)), \
                mock.patch("ui.file_pane.FUSE_MOUNT_WAIT_S", 0.3):
            _mount_with(pane, mnt, serving_fuse)  # never shows up
            assert boxes.kinds() == ["critical"], boxes.shown
            assert "did not come up" in boxes.shown[0][1]
            # the loop that is still running stays unmountable
            assert pane._fuse_handle is not None
            release.set()
            pane._fuse_handle._thread.join(5)
            boxes.shown.clear()
            release.clear()
            mounted["now"] = True
            _mount_with(pane, mnt, serving_fuse)
        assert boxes.kinds() == ["information"], boxes.shown
        assert "Mounted" in boxes.shown[0][1]
        assert pane._fuse_handle is not None and pane._fuse_handle.is_alive()
    finally:
        release.set()


def test_edge_wait_until_mounted_is_false_for_a_loop_that_ended(tmp_path):
    """The error of the loop is kept on the handle for the message."""
    with mock.patch.object(FM, "FUSE", _refusing_fuse, create=True), \
            mock.patch.object(FM, "FUSE_AVAILABLE", True), \
            mock.patch.object(FM, "BackendFuseFS", lambda *a, **k: object()):
        handle = FM.mount(LocalFS(), str(tmp_path))
        assert handle.wait_until_mounted(5.0) is False
    assert isinstance(handle.error, RuntimeError)
    assert not handle.is_alive()


# --- unmount ----------------------------------------------------------------


def test_sad_a_busy_unmount_keeps_the_handle_for_another_try(pane, boxes, tmp_path):
    """fusermount -u exits 1 ("Device or resource busy"): the pane said
    "Unmounted" and forgot the handle while the mount still served."""
    busy = threading.Event()
    loop = threading.Thread(target=busy.wait, daemon=True)
    loop.start()
    try:
        handle = _handle(str(tmp_path), loop)
        pane._fuse_handle = handle
        with mock.patch.object(subprocess, "run", _completed(
                1, b"fusermount: failed to unmount: Device or resource busy")), \
                mock.patch.object(FM.os.path, "ismount", lambda p: True):
            pane._unmount_fuse()
        assert boxes.kinds() == ["warning"], boxes.shown
        assert "still mounted" in boxes.shown[0][1]
        assert "in use" in boxes.shown[0][1]  # the next step: close what uses it
        assert pane._fuse_handle is handle
    finally:
        busy.set()
    loop.join(5)
    boxes.shown.clear()
    # the second try, once nothing uses it any more
    with mock.patch.object(subprocess, "run", _completed(0)), \
            mock.patch.object(FM.os.path, "ismount", lambda p: False):
        pane._unmount_fuse()
    assert boxes.kinds() == ["information"], boxes.shown
    assert "Unmounted" in boxes.shown[0][1]
    assert pane._fuse_handle is None


def test_edge_unmount_judges_by_the_mount_and_its_loop_not_only_the_exit_code(tmp_path):
    """No exit code said success and the loop still runs: an error, not a
    silent return. A failing fusermount with nothing left is no error."""
    busy = threading.Event()
    loop = threading.Thread(target=busy.wait, daemon=True)
    loop.start()
    try:
        handle = _handle(str(tmp_path / "gone"), loop)
        with mock.patch.object(subprocess, "run", _completed(1, b"not mounted")):
            with pytest.raises(FM.UnmountError) as caught:
                handle.unmount(timeout=0.2)
        assert "exit 1" in str(caught.value)
    finally:
        busy.set()
    loop.join(5)
    with mock.patch.object(subprocess, "run", _completed(1, b"not mounted")):
        handle.unmount(timeout=0.2)  # the loop ended, nothing mounted: fine
