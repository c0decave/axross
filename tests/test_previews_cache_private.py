"""The thumbnail cache is private to the user.

Review (round 1 of the release reviews): core.previews kept its thumbnails
in ~/.cache/axross/thumbnails with the umask's modes - 0755 and 0644 under
the usual 022 - so on a shared machine (a home other users may enter, as on
older Debian and Ubuntu installs) anyone could look at small copies of the
user's pictures, the media viewer's and the pane's, also of a folder the
user keeps closed. The freedesktop thumbnail rules ask 0700 for the folder
and 0600 for each file; the cache now keeps to them, an existing folder
included.
"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX modes")


@pytest.fixture
def cache(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    old = os.umask(0o022)
    yield tmp_path / "cache" / "axross" / "thumbnails"
    os.umask(old)


def _mode(path: Path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


def _picture(path: Path) -> None:
    from PyQt6.QtGui import QColor, QImage

    image = QImage(32, 24, QImage.Format.Format_RGB32)
    image.fill(QColor("teal"))
    assert image.save(str(path), "PNG")


def test_safety_thumbnails_are_kept_private(tmp_path, cache):
    from PyQt6.QtWidgets import QApplication

    QApplication.instance() or QApplication([])
    from core import previews as P
    from core.local_fs import LocalFS

    _picture(tmp_path / "private.png")
    result = P.thumbnail(LocalFS(), str(tmp_path / "private.png"), edge=64)
    assert not result.from_cache
    files = list(cache.glob("*.png"))
    assert len(files) == 1
    assert _mode(cache) == 0o700
    assert _mode(files[0]) == 0o600
    assert P.thumbnail(LocalFS(), str(tmp_path / "private.png"), edge=64).from_cache


def test_safety_an_open_cache_folder_is_closed(tmp_path, cache):
    from core import previews as P

    cache.mkdir(parents=True)
    os.chmod(cache, 0o755)
    assert P._cache_root() == cache
    assert _mode(cache) == 0o700
