"""Help > Tours > Watch Video: pinned download, cache, fallback, the button.

The tour videos are assets of their own release; axross pins each file's
size and SHA-256 in resources/tours/tour_videos.json and keeps (and plays)
only a file that matches. The network is faked: core.self_update.fetch is
replaced by one that hands the bytes to the sink.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import self_update as SU  # noqa: E402
from core import tour_videos as TV  # noqa: E402

_APP = None  # the QApplication, kept alive for the module
BODY = b"\x00\x00\x00\x18ftypmp42" + b"x" * 1000
SHA = hashlib.sha256(BODY).hexdigest()


def _manifest(tmp_path, videos=None, tag="tour-videos-1") -> Path:
    path = tmp_path / "tour_videos.json"
    if videos is None:
        videos = {"en/connect": {"file": "axross-tour-en-connect.mp4", "size": len(BODY), "sha256": SHA},
                  "de/connect": {"file": "axross-tour-de-connect.mp4", "size": len(BODY), "sha256": SHA},
                  "en/automate": {"file": "axross-tour-en-automate.mp4", "size": len(BODY), "sha256": SHA}}
    path.write_text(json.dumps({"tag": tag, "videos": videos}), encoding="utf-8")
    return path


@pytest.fixture
def cache(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    return tmp_path / "cache" / "axross" / "tour-videos"


@pytest.fixture
def net(monkeypatch):
    seen: list[str] = []
    state = {"body": BODY}

    def fake_fetch(url, *, opener, max_bytes, sink=None, progress=None, total=0, cancel=None, **_k):
        seen.append(url)
        body = state["body"]
        if len(body) > max_bytes:
            raise SU.UpdateError("more than the limit - refused")
        sink(body)
        if progress:
            progress(len(body), total)
        return len(body)
    monkeypatch.setattr(SU, "fetch", fake_fetch)
    monkeypatch.setattr(SU, "build_opener", lambda **k: object())
    return seen, state


# -- happy -------------------------------------------------------------------


def test_happy_a_video_is_fetched_from_its_release_checked_and_cached(tmp_path, cache, net):
    seen, _ = net
    video = TV.video_for("connect", "de", manifest=_manifest(tmp_path))
    assert video.url == f"{SU.RELEASES_PREFIX}download/tour-videos-1/axross-tour-de-connect.mp4"
    path = TV.fetch(video)
    assert path == cache / "axross-tour-de-connect.mp4" and path.read_bytes() == BODY
    assert TV.fetch(video) == path and len(seen) == 1  # the second time from the cache


def test_happy_a_language_without_its_video_gets_the_english_one(tmp_path):
    video = TV.video_for("automate", "de", manifest=_manifest(tmp_path))
    assert video.language == "en" and video.name == "axross-tour-en-automate.mp4"


# -- sad ---------------------------------------------------------------------


def test_sad_a_file_that_does_not_match_its_pin_is_not_kept(tmp_path, cache, net):
    _, state = net
    state["body"] = BODY[:-1] + b"y"  # same size, other bytes
    video = TV.video_for("connect", "en", manifest=_manifest(tmp_path))
    with pytest.raises(TV.VideoError, match="checksum"):
        TV.fetch(video)
    assert not any(cache.iterdir())  # neither the file nor a partial one


def test_sad_a_bigger_file_is_refused_by_the_size_pin(tmp_path, cache, net):
    _, state = net
    state["body"] = BODY + b"more"
    video = TV.video_for("connect", "en", manifest=_manifest(tmp_path))
    with pytest.raises(TV.VideoError, match="refused"):
        TV.fetch(video)


def test_sad_a_tampered_cached_file_is_fetched_again(tmp_path, cache, net):
    seen, _ = net
    video = TV.video_for("connect", "en", manifest=_manifest(tmp_path))
    TV.fetch(video)
    (cache / video.name).write_bytes(b"z" * len(BODY))
    assert TV.fetch(video).read_bytes() == BODY and len(seen) == 2


@pytest.mark.parametrize("entry", [
    {"file": "a.mp4\n", "size": 10, "sha256": SHA},
    {"file": "a.mp4", "size": 10, "sha256": SHA + "\n"},
    {"file": "../evil.mp4", "size": 10, "sha256": SHA},
    {"file": "a.exe", "size": 10, "sha256": SHA},
    {"file": "a.mp4", "size": 0, "sha256": SHA},
    {"file": "a.mp4", "size": TV.MAX_VIDEO_BYTES + 1, "sha256": SHA},
    {"file": "a.mp4", "size": True, "sha256": SHA},
    {"file": "a.mp4", "size": 10, "sha256": "nothex"},
])
def test_sad_a_bad_manifest_entry_names_no_video(tmp_path, entry):
    assert TV.video_for("connect", "en", manifest=_manifest(tmp_path, {"en/connect": entry})) is None


@pytest.mark.parametrize("tag", ["../x", "a/b", "", None, "x" * 65])
def test_sad_a_bad_tag_names_no_video(tmp_path, tag):
    assert TV.video_for("connect", "en", manifest=_manifest(tmp_path, tag=tag)) is None


# -- edge --------------------------------------------------------------------


def test_edge_no_manifest_or_no_videos_means_no_button(tmp_path):
    assert not TV.has_videos(manifest=tmp_path / "missing.json")
    assert not TV.has_videos(manifest=_manifest(tmp_path, {}))
    assert TV.has_videos(manifest=_manifest(tmp_path))


def test_edge_the_shipped_manifest_is_valid():
    data = json.loads(TV.MANIFEST.read_text(encoding="utf-8"))
    assert TV._base(data)
    from ui.tours import TOURS

    ids = {t.id for t in TOURS}
    for key in data["videos"]:
        lang, tour_id = key.split("/")
        assert tour_id in ids, key
        assert TV.video_for(tour_id, lang) is not None, key


def test_edge_a_cancelled_fetch_leaves_no_part_file(tmp_path, cache, monkeypatch):
    def cancelled(url, *, sink, **_k):
        sink(BODY[:10])
        raise SU.Cancelled("cancelled")
    monkeypatch.setattr(SU, "fetch", cancelled)
    monkeypatch.setattr(SU, "build_opener", lambda **k: object())
    video = TV.video_for("connect", "en", manifest=_manifest(tmp_path))
    with pytest.raises(SU.Cancelled):
        TV.fetch(video, cancel=threading.Event())
    assert not any(cache.iterdir())


# -- the Tours dialog --------------------------------------------------------


@pytest.fixture
def dialog(tmp_path, cache, net, monkeypatch):
    pytest.importorskip("PyQt6.QtWidgets")
    from PyQt6.QtWidgets import QApplication, QWidget

    global _APP
    _APP = QApplication.instance() or QApplication([])
    monkeypatch.setattr(TV, "MANIFEST", _manifest(tmp_path))
    from ui.tour_engine import ToursDialog
    from ui.tours import TOURS

    host = QWidget()
    dlg = ToursDialog(host, TOURS)
    yield dlg
    dlg.close()
    host.deleteLater()


def _wait(predicate, seconds=5.0):
    import time

    from PyQt6.QtWidgets import QApplication

    end = time.monotonic() + seconds
    while time.monotonic() < end and not predicate():
        QApplication.processEvents()
        time.sleep(0.01)
    return predicate()


def test_happy_watch_video_opens_the_checked_file(dialog, cache, monkeypatch):
    import core.desktop_open as DO

    opened = []
    monkeypatch.setattr(DO, "open_url", lambda url: opened.append(url) or True)
    assert not dialog.video_button.isHidden()
    for i in range(dialog.list.topLevelItemCount()):
        if dialog.list.topLevelItem(i).data(0, 256) == "connect":
            dialog.list.setCurrentItem(dialog.list.topLevelItem(i))
    dialog.watch_selected()
    assert _wait(lambda: opened)
    assert opened[0] == str(cache / "axross-tour-en-connect.mp4")
    assert dialog.video_button.isEnabled()


def test_sad_watch_video_reports_a_bad_file(dialog, net, monkeypatch):
    from PyQt6.QtWidgets import QMessageBox

    _, state = net
    state["body"] = b"y" * len(BODY)
    warned = []
    monkeypatch.setattr(QMessageBox, "exec", lambda box: warned.append(box.text()) or 0)
    for i in range(dialog.list.topLevelItemCount()):
        if dialog.list.topLevelItem(i).data(0, 256) == "connect":
            dialog.list.setCurrentItem(dialog.list.topLevelItem(i))
    dialog.watch_selected()
    assert _wait(lambda: warned)
    assert "checksum" in warned[0] and dialog.video_button.isEnabled()


def test_edge_the_button_is_hidden_without_videos(tmp_path, monkeypatch):
    pytest.importorskip("PyQt6.QtWidgets")
    from PyQt6.QtWidgets import QApplication, QWidget

    global _APP
    _APP = QApplication.instance() or QApplication([])
    monkeypatch.setattr(TV, "MANIFEST", _manifest(tmp_path, {}))
    from ui.tour_engine import ToursDialog
    from ui.tours import TOURS

    host = QWidget()
    dlg = ToursDialog(host, TOURS)
    assert dlg.video_button.isHidden()
    dlg.close()
