"""A double-click on an image on a remote backend (ADB, SFTP, SMB, ...) opens
the media viewer, which reads it off the GUI thread. Before, the image viewer
refused every backend that is not local and the PNG fell through to the hex
editor (a user's report over ADB)."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from core.local_fs import LocalFS  # noqa: E402

APP = QApplication.instance() or QApplication([])


class _PhoneFS(LocalFS):
    """A backend the previews do not count as local (as ADB's)."""


@pytest.fixture
def pane(tmp_path, monkeypatch):
    from core import previews
    from ui.file_pane import FilePaneWidget

    monkeypatch.setattr(previews, "_is_local_backend",
                        lambda backend: not isinstance(backend, _PhoneFS))
    (tmp_path / "photo.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\0" * 64)
    (tmp_path / "data.bin").write_bytes(b"\0\1\2\3")
    widget = FilePaneWidget(_PhoneFS())
    widget.navigate(str(tmp_path))
    yield widget, tmp_path
    widget.deleteLater()


def _item(widget, name):
    return next(i for i in widget._backend.list_dir(widget._current_path) if i.name == name)


def test_happy_a_remote_png_opens_in_the_media_viewer_not_the_hex_editor(pane, monkeypatch):
    widget, folder = pane
    media, hexed = [], []
    monkeypatch.setattr(widget, "open_media_viewer",
                        lambda options, only_names=None: media.append((options, only_names)))
    monkeypatch.setattr(widget, "_open_hex_editor", lambda *a, **k: hexed.append(a))
    widget._activate_file(_item(widget, "photo.png"), str(folder / "photo.png"))
    assert hexed == []
    assert len(media) == 1
    options, names = media[0]
    from core import media_collect as MC

    assert options.kinds == frozenset({MC.IMAGE})
    assert names == {"photo.png"}


def test_sad_the_security_mode_that_blocks_previews_still_falls_back(pane, monkeypatch):
    widget, folder = pane
    from core import security_mode

    class _Strict:
        allow_auto_preview = False
        name = "paranoid"

    monkeypatch.setattr(security_mode, "current_policy", lambda: _Strict())
    media = []
    monkeypatch.setattr(widget, "open_media_viewer",
                        lambda options, only_names=None: media.append(options))
    assert widget._open_remote_image("photo.png") is False
    assert media == []


def test_edge_a_non_image_name_is_not_taken(pane):
    widget, _folder = pane
    assert widget._open_remote_image("data.bin") is False
