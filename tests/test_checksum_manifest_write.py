"""Checksum Manifest writes all of SHA256SUMS or nothing, and an empty one
never verifies (review round 2).

Before: a folder with a name that is no UTF-8 (``caf\\xe9.txt``, a
surrogate escape in Python) made ``text.encode("utf-8")`` raise *after*
``open_write`` had truncated SHA256SUMS. The empty file stayed, and
Verify then said OK 0 / FAILED 0 / Missing 0 - a clean folder. Now the
name is written as its own bytes (as sha256sum writes it), the text goes
to a temporary file renamed into place (removed when anything fails), and
a manifest with no entries is a warning, never "verified".
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import extensions as EX  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

FS = LocalFS()
LATIN1 = b"caf\xe9.txt"


def _load():
    path = EX.bundled_dir() / "checksum_manifest.py"
    spec = importlib.util.spec_from_file_location("checksum_manifest_write_ext", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CM = _load()


def _names(folder: Path) -> list[str]:
    return [i.name for i in FS.list_dir(str(folder)) if not i.is_dir]


def _read(path: Path) -> str:
    return path.read_bytes().decode("utf-8", "surrogateescape")


class _FailingWrites(LocalFS):
    """A backend whose writes break after the first chunk (a full disk,
    a dropped connection)."""

    def open_write(self, path, append=False):
        real = super().open_write(path, append)

        class Broken:
            def __enter__(self):
                real.__enter__()
                return self

            def write(self, data):
                real.write(data[:10])
                raise OSError(28, "No space left on device")

            def __exit__(self, *exc):
                return real.__exit__(*exc)

        return Broken()


def test_happy_a_name_that_is_no_utf8_is_written_and_verifies(tmp_path):
    (tmp_path / "good.txt").write_bytes(b"x")
    with open(os.path.join(os.fsencode(tmp_path), LATIN1), "wb") as fh:
        fh.write(b"y")
    target = tmp_path / CM.MANIFEST_NAME
    CM._write(FS, str(target), CM.manifest_text(FS, str(tmp_path), _names(tmp_path)))
    assert LATIN1 in target.read_bytes()  # its own bytes, as sha256sum writes them
    result = CM.verify(FS, str(tmp_path), _read(target))
    assert sorted(result["ok"]) == sorted(["good.txt", os.fsdecode(LATIN1)])
    assert result["failed"] == result["missing"] == result["errors"] == []
    assert sorted(os.listdir(tmp_path)) == sorted(["good.txt", os.fsdecode(LATIN1),
                                                   CM.MANIFEST_NAME])  # no temp file left


def test_sad_a_write_that_fails_leaves_no_manifest_and_no_temp_file(tmp_path):
    (tmp_path / "a.txt").write_bytes(b"a")
    target = tmp_path / CM.MANIFEST_NAME
    with pytest.raises(OSError):
        CM._write(_FailingWrites(), str(target), CM.manifest_text(FS, str(tmp_path), ["a.txt"]))
    assert os.listdir(tmp_path) == ["a.txt"]


def test_sad_an_empty_manifest_is_no_verified_folder():
    result = CM.verify(FS, "/nowhere", "")
    assert result["ok"] == result["failed"] == result["missing"] == []
    assert result["errors"] == [CM.NO_ENTRIES]


def test_edge_verify_of_an_empty_manifest_warns_that_nothing_was_checked(tmp_path):
    pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")
    from PyQt6.QtCore import QTimer
    from PyQt6.QtWidgets import QApplication, QLabel, QMainWindow, QMessageBox

    app = QApplication.instance() or QApplication([])
    (tmp_path / CM.MANIFEST_NAME).write_bytes(b"")

    class Api:
        window = QMainWindow()
        actions: dict = {}

        def add_context_action(self, label, cb, applies_to="any", extensions=()):
            self.actions[label] = cb

        def notify(self, text):
            pass

        def run_in_background(self, work, on_done=None, on_error=None):
            on_done(work())

    api = Api()
    CM.activate(api)
    seen = []

    def answer():
        box = QApplication.activeModalWidget()
        if isinstance(box, QMessageBox):
            seen.append((box.icon(), box.findChild(QLabel, "qt_msgbox_label").text()))
            box.accept()
        else:
            QTimer.singleShot(20, answer)

    QTimer.singleShot(0, answer)
    item = SimpleNamespace(name=CM.MANIFEST_NAME, is_dir=False)
    api.actions["Verify SHA256SUMS"](SimpleNamespace(backend=FS, folder=str(tmp_path),
                                                     items=[item]))
    app.processEvents()
    assert len(seen) == 1
    icon, text = seen[0]
    assert icon == QMessageBox.Icon.Warning
    assert "OK: 0" not in text and "nothing was verified" in text
