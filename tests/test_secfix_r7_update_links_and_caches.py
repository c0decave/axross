"""Round-7 security L3:

* the release notes' "Open Link" question showed an IDN host decoded
  (``https://gıthub.com/`` for ``xn--gthub-n4a.com``) and a percent-encoded
  bidi override of the path decoded (the address read backwards), and a
  ``github.com@evil.example`` link was asked for as if it went to GitHub.
  The question now shows the fully encoded address (punycode host, %-encoded
  path), the host on a line of its own and the link text with control
  characters made visible; a link with a user name is not opened.
* the update cache and the tour-video cache were used in a folder another
  user owns or may write to (XDG_CACHE_HOME on a shared folder); like the
  extension code cache, they are now made 0700 and refused when they are a
  symlink, owned by someone else or writable by group/others.
"""

from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QUrl  # noqa: E402

from core import self_update as SU  # noqa: E402
from core import tour_videos as TV  # noqa: E402


@pytest.fixture
def app():
    from PyQt6.QtWidgets import QApplication

    return QApplication.instance() or QApplication([])

posix_only = pytest.mark.skipif(not hasattr(os, "geteuid"), reason="owners and modes: POSIX")


# -- the Open Link question ---------------------------------------------------------------


def test_sad_an_idn_host_is_shown_as_punycode():
    from ui.update_ui import open_link_question

    href = QUrl("https://xn--gthub-n4a.com/c0decave/axross/releases").toString()
    assert "ı" in href  # what the view hands over: decoded
    body = open_link_question(href, "")
    assert "https://xn--gthub-n4a.com/c0decave/axross/releases" in body
    assert "Host: xn--gthub-n4a.com" in body
    assert "ı" not in body


def test_sad_a_bidi_override_in_the_path_or_the_text_is_never_shown_raw():
    from ui.update_ui import open_link_question

    href = QUrl("https://evil.example/%E2%80%AE/sesaeler/ssorxa/moc.buhtig").toString()
    body = open_link_question(href, "https://github.com\u202e/x\u200b")
    assert "\u202e" not in body and "\u200b" not in body
    assert "%E2%80%AE" in body and "Host: evil.example" in body
    assert "\\u202e" in body and "\\u200b" in body  # the text's controls made visible


def test_happy_a_plain_link_reads_as_before(app):
    from ui.update_ui import open_link_question

    href = "https://github.com/c0decave/axross/releases"
    body = open_link_question(href, href)
    assert body.splitlines()[2] == href
    assert "Host: github.com" in body
    assert "reads:" not in body  # the text is the address: not repeated


def test_edge_a_link_with_a_user_name_is_not_opened(app):
    from ui.update_ui import ReleaseNotesView

    view = ReleaseNotesView()
    view.set_notes("[GitHub](https://github.com@evil.example/)")
    with mock.patch("ui.update_ui.ask_open_link", return_value=True) as asked, \
            mock.patch("core.desktop_open.open_url") as open_url:
        view._open_link(QUrl("https://github.com@evil.example/"))
    asked.assert_not_called()
    open_url.assert_not_called()


# -- the cache folders --------------------------------------------------------------------


@posix_only
def test_happy_a_missing_cache_folder_is_made_private(tmp_path):
    folder = tmp_path / "cache" / "axross" / "update"
    assert SU.private_dir_problem(folder) == ""
    assert folder.is_dir() and (folder.stat().st_mode & 0o777) == 0o700


@posix_only
@pytest.mark.parametrize("mode", [0o777, 0o775, 0o757])
def test_sad_a_folder_others_may_write_is_refused(tmp_path, mode):
    folder = tmp_path / "update"
    folder.mkdir()
    folder.chmod(mode)
    assert "writable by other users" in SU.private_dir_problem(folder)
    assert (folder.stat().st_mode & 0o777) == mode  # not "repaired": refused


@posix_only
def test_sad_a_symlinked_or_foreign_cache_folder_is_refused(tmp_path):
    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    link = tmp_path / "link"
    link.symlink_to(real)
    assert "symbolic link" in SU.private_dir_problem(link)
    foreign = tmp_path / "foreign"
    foreign.mkdir(mode=0o700)
    with mock.patch("core.posix_compat.effective_uid", return_value=os.geteuid() + 1):
        assert "another user" in SU.private_dir_problem(foreign)


@posix_only
def test_edge_a_parent_others_may_write_is_refused_unless_sticky(tmp_path):
    shared = tmp_path / "shared"
    shared.mkdir()
    shared.chmod(0o777)
    assert "can be changed by other users" in SU.private_dir_problem(shared / "update")
    sticky = tmp_path / "sticky"
    sticky.mkdir()
    sticky.chmod(0o1777)
    assert SU.private_dir_problem(sticky / "update") == ""


@posix_only
def test_sad_the_update_does_not_stage_into_a_shared_cache(tmp_path, monkeypatch):
    cache = tmp_path / "xdg" / "axross" / "update"
    cache.mkdir(parents=True)
    cache.chmod(0o777)
    monkeypatch.setattr(SU, "cache_dir", lambda: cache)
    monkeypatch.setattr(SU, "_writable", lambda folder: False)
    monkeypatch.setattr(SU, "download", lambda *a, **k: pytest.fail("downloaded into it"))
    inst = mock.Mock(executable=tmp_path / "bin" / "axross")
    with pytest.raises(SU.UpdateError, match="writable by other users"):
        SU._update_binary(mock.Mock(), inst, opener=None, progress=None, cancel=None)


BODY = b"\x00\x00\x00\x18ftypmp42" + b"v" * 500


@posix_only
def test_sad_a_tour_video_is_not_kept_or_served_from_a_shared_folder(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
    folder = TV.cache_dir()
    folder.mkdir(parents=True)
    video = TV.Video("t", "en", "axross-tour-en-t.mp4",
                     "https://github.com/c0decave/axross/releases/download/tour-videos-1/x.mp4",
                     len(BODY), hashlib.sha256(BODY).hexdigest())
    (folder / video.name).write_bytes(BODY)
    folder.chmod(0o700)
    assert TV.cached(video) == folder / video.name
    folder.chmod(0o777)
    assert TV.cached(video) is None  # a checked file there could be swapped before it plays
    monkeypatch.setattr(SU, "fetch", lambda *a, **k: pytest.fail("downloaded into it"))
    with pytest.raises(TV.VideoError) as caught:
        TV.fetch(video)
    assert caught.value.kind == "unsafe"
    assert str(folder) in caught.value.user_text()
