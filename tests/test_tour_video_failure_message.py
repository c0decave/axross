"""Watch Video: a failure is one translated sentence, with Start Tour.

Measured before (UX review round 4): with the video release not yet
published the box said "The tour video could not be shown: github.com
answered HTTP 404", offline "cannot reach github.com: [Errno -3] Temporary
failure in name resolution" - English in the German UI as well. Now 404 is
"not published yet", a network failure gets core.user_errors' sentence,
anything else a translated generic one with the detail, and the box offers
Start Tour.
"""

from __future__ import annotations

import io
import os
import socket
import sys
import urllib.error
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import i18n  # noqa: E402
from core import self_update as SU  # noqa: E402
from core import tour_videos as TV  # noqa: E402

_APP = None
VIDEO = TV.Video("connect", "de", "axross-tour-de-connect.mp4",
                 "https://github.com/c0decave/axross/releases/download/tour-videos-1/x.mp4",
                 10, "0" * 64)


@pytest.fixture(params=["en", "de"])
def lang(request):
    previous = i18n.active().language
    i18n.install(request.param)
    yield request.param
    i18n.install(previous)


@pytest.fixture
def cache(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))


def _failing_fetch(monkeypatch, inner: BaseException, text: str):
    def fake_fetch(*_a, **_k):
        try:
            raise inner
        except BaseException:
            raise SU.UpdateError(text) from None  # as core.self_update does

    monkeypatch.setattr(SU, "fetch", fake_fetch)
    monkeypatch.setattr(SU, "build_opener", lambda **k: object())


def _error(monkeypatch, inner, text) -> TV.VideoError:
    _failing_fetch(monkeypatch, inner, text)
    with pytest.raises(TV.VideoError) as info:
        TV.fetch(VIDEO)
    return info.value


def test_happy_404_says_not_published_yet(lang, cache, monkeypatch):
    http = urllib.error.HTTPError(VIDEO.url, 404, "Not Found", {}, io.BytesIO(b""))
    error = _error(monkeypatch, http, "github.com answered HTTP 404")
    assert error.kind == "unpublished"
    text = error.user_text()
    assert "404" not in text and "HTTP" not in text
    assert ("noch nicht veröffentlicht" if lang == "de" else "not published yet") in text


def test_sad_offline_gets_the_network_sentence(lang, cache, monkeypatch):
    gai = urllib.error.URLError(socket.gaierror(-3, "Temporary failure in name resolution"))
    error = _error(monkeypatch, gai,
                   "cannot reach github.com: [Errno -3] Temporary failure in name resolution")
    assert error.kind == "network"
    text = error.user_text()
    assert "Errno" not in text and "cannot reach" not in text
    # Round 6: about the video and GitHub, not a host name and DNS.
    assert "GitHub" in text and "DNS" not in text
    assert text.startswith("Das Video ließ sich nicht von GitHub laden" if lang == "de"
                           else "The video could not be loaded from GitHub")


def test_sad_other_errors_are_generic_with_the_detail(lang, cache, monkeypatch):
    error = _error(monkeypatch, ValueError("x"), "more than 5 redirects - refused")
    text = error.user_text()
    assert "more than 5 redirects - refused" in text
    assert text.startswith("Das Tour-Video" if lang == "de" else "The tour video")


def test_edge_the_box_offers_start_tour_and_starts_it(lang, monkeypatch):
    pytest.importorskip("PyQt6.QtWidgets")
    from PyQt6.QtWidgets import QApplication, QMessageBox, QWidget

    global _APP
    _APP = QApplication.instance() or QApplication([])
    from ui.tour_engine import ToursDialog
    from ui.tours import TOURS

    started = []

    class Host(QWidget):
        def start_tour(self, tour_id):
            started.append(tour_id)

    host = Host()
    dialog = ToursDialog(host, TOURS)
    seen = {}

    def fake_exec(box):
        seen["text"] = box.text()
        seen["buttons"] = [b.text() for b in box.buttons()]
        start = [b for b in box.buttons() if b.text() == i18n.tr("Start Tour")][0]
        start.click()
        return 0

    monkeypatch.setattr(QMessageBox, "exec", fake_exec)
    dialog._video_failed(TV.VideoError("github.com answered HTTP 404", kind="unpublished"))
    assert i18n.tr("Start Tour") in seen["buttons"]
    assert "404" not in seen["text"]
    assert started and started[0] == dialog.selected_id()
    host.deleteLater()
