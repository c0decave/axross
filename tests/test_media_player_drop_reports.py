"""Dropping folders onto the player: what it takes, and why it took nothing.

The operator dropped further folders onto the playlist; it said "Nothing to
add." and did not grow. Measured: a folder said exactly that, with no reason,
when its tracks were behind a link to a folder (links were never followed),
deeper than MAX_DROP_DEPTH, in a folder that cannot be read, or in a format
the player plays but did not list (.m4b, .wv, .webm ... - each decoded by
the real engine, from source and in the frozen axross-full). Now links to
folders are followed (a loop is walked once), those formats count, and
whatever a folder held that is no track is counted and said.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

pytest.importorskip("PyQt6.QtMultimedia", reason="QtMultimedia not installed")

from test_media_player_controls import MP, FakeEngine, drop_on, rows, touch, url_mime, wait  # noqa: E402


def _found(tmp_path, *paths):
    found, skipped, truncated = MP.collect_local([str(p) for p in paths])
    return [os.path.basename(p) for p, _t in found], skipped, truncated


# -- happy --------------------------------------------------------------------------------------

def test_happy_a_link_to_a_folder_is_followed(tmp_path):
    touch(tmp_path / "real" / "album" / "a.mp3")
    (tmp_path / "library").mkdir()
    os.symlink(tmp_path / "real" / "album", tmp_path / "library" / "album")
    assert _found(tmp_path, tmp_path / "library") == (["a.mp3"], 0, False)


@pytest.mark.parametrize("suffix", [".m4b", ".wv", ".spx", ".tta", ".ac3", ".mp2", ".caf",
                                    ".au", ".amr", ".webm"])
def test_happy_formats_the_engine_plays_are_tracks(tmp_path, suffix):
    touch(tmp_path / "f" / f"song{suffix}")
    assert _found(tmp_path, tmp_path / "f") == ([f"song{suffix}"], 0, False)


def test_happy_e2e_two_folders_dropped_one_after_the_other_both_land(tmp_path):
    for name in ("one", "two"):
        touch(tmp_path / name / "CD1" / f"{name}-a.mp3")
        touch(tmp_path / name / "CD2" / f"{name}-b.flac")
    panel = MP.PlayerPanel(engine=FakeEngine())
    try:
        panel.resize(500, 500)
        panel.show()
        assert drop_on(panel.playlist, url_mime(tmp_path / "one"))
        assert wait(lambda: panel.playlist.count() == 2, 10), rows(panel)
        assert drop_on(panel.playlist, url_mime(tmp_path / "two"))
        assert wait(lambda: panel.playlist.count() == 4, 10), rows(panel)
        assert rows(panel) == ["one-a.mp3", "one-b.flac", "two-a.mp3", "two-b.flac"]
        assert "Added 2 track(s)." in panel.note.text()
    finally:
        panel.close()


# -- sad ----------------------------------------------------------------------------------------

def test_edge_files_beside_found_tracks_are_no_news(tmp_path):
    touch(tmp_path / "album" / "01.mp3")
    touch(tmp_path / "album" / "cover.jpg")
    touch(tmp_path / "album" / "album.cue")
    assert _found(tmp_path, tmp_path / "album") == (["01.mp3"], 0, False)


def test_sad_a_folder_without_tracks_says_what_it_held(tmp_path):
    touch(tmp_path / "docs" / "a.txt")
    touch(tmp_path / "docs" / "sub" / "cover.jpg")
    names, skipped, _t = _found(tmp_path, tmp_path / "docs")
    assert names == [] and skipped == 2


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads every folder")
def test_sad_a_folder_that_cannot_be_read_is_counted(tmp_path):
    touch(tmp_path / "lib" / "locked" / "a.mp3")
    touch(tmp_path / "lib" / "open" / "b.mp3")
    os.chmod(tmp_path / "lib" / "locked", 0)
    try:
        assert _found(tmp_path, tmp_path / "lib") == (["b.mp3"], 1, False)
    finally:
        os.chmod(tmp_path / "lib" / "locked", 0o755)


def test_sad_e2e_the_note_never_says_nothing_without_a_reason(tmp_path):
    touch(tmp_path / "pictures" / "a.png")
    touch(tmp_path / "pictures" / "b.png")
    panel = MP.PlayerPanel(engine=FakeEngine())
    try:
        panel.resize(500, 500)
        panel.show()
        assert drop_on(panel.playlist, url_mime(tmp_path / "pictures"))
        assert wait(lambda: "2" in panel.note.text(), 10), panel.note.text()
        assert panel.note.text() != "Nothing to add."
        assert panel.playlist.count() == 0
    finally:
        panel.close()


# -- edge ---------------------------------------------------------------------------------------

def test_edge_a_link_loop_is_walked_once(tmp_path):
    touch(tmp_path / "a" / "x.mp3")
    os.symlink(tmp_path / "a", tmp_path / "a" / "again")
    os.symlink(tmp_path / "a", tmp_path / "a" / "and-again")
    assert _found(tmp_path, tmp_path / "a") == (["x.mp3"], 0, False)


def test_edge_two_links_to_one_album_add_it_once(tmp_path):
    touch(tmp_path / "store" / "album" / "x.mp3")
    (tmp_path / "lib").mkdir()
    os.symlink(tmp_path / "store" / "album", tmp_path / "lib" / "by-artist")
    os.symlink(tmp_path / "store" / "album", tmp_path / "lib" / "by-year")
    assert _found(tmp_path, tmp_path / "lib") == (["x.mp3"], 0, False)


def test_edge_folders_below_the_depth_bound_are_counted(tmp_path):
    deep = tmp_path / "top"
    for level in range(MP.MAX_DROP_DEPTH + 1):
        deep = deep / f"l{level}"
    touch(deep / "far.mp3")
    touch(tmp_path / "top" / "near.mp3")
    names, skipped, _t = _found(tmp_path, tmp_path / "top")
    assert names == ["near.mp3"] and skipped == 1


def test_edge_a_dropped_link_to_a_file_is_a_track(tmp_path):
    touch(tmp_path / "x.mp3")
    os.symlink(tmp_path / "x.mp3", tmp_path / "link.mp3")
    assert _found(tmp_path, tmp_path / "link.mp3") == (["link.mp3"], 0, False)


def test_edge_video_containers_stay_out(tmp_path):
    touch(tmp_path / "v" / "movie.mp4")
    touch(tmp_path / "v" / "clip.mkv")
    names, skipped, _t = _found(tmp_path, tmp_path / "v")
    assert names == [] and skipped == 2


# -- a folder on a remote pane ------------------------------------------------------------------

def _ram(*files):
    from core.ram_fs import RamFsSession

    ram = RamFsSession("drop-ram")
    for path in files:
        parts = path.strip("/").split("/")
        for i in range(1, len(parts)):
            folder = "/" + "/".join(parts[:i])
            if not ram.exists(folder):
                ram.mkdir(folder)
        with ram.open_write(path) as fh:
            fh.write(b"RIFF" + bytes(64))
    return ram


def test_sad_a_remote_folder_without_tracks_says_what_it_held(tmp_path):
    ram = _ram("/docs/a.txt", "/docs/sub/cover.jpg")
    found, skipped, truncated, folder = MP.fetch_remote(ram, ["/docs"], str(tmp_path))
    assert found == [] and skipped == 2 and not truncated and folder == ""


def test_happy_a_remote_folder_takes_the_new_formats(tmp_path):
    ram = _ram("/m/a.m4b", "/m/b.wv", "/m/c.txt")
    found, skipped, _t, _folder = MP.fetch_remote(ram, ["/m"], str(tmp_path))
    assert [os.path.basename(p) for p, _n in found] == ["a.m4b", "b.wv"]
    assert skipped == 0  # c.txt beside the tracks is no news


def test_edge_remote_folders_below_the_depth_bound_are_counted(tmp_path):
    deep = "/top"
    for level in range(MP.MAX_DROP_DEPTH + 1):
        deep += f"/l{level}"
    ram = _ram(deep + "/far.wav", "/top/near.wav")
    found, skipped, _t, _folder = MP.fetch_remote(ram, ["/top"], str(tmp_path))
    assert [os.path.basename(p) for p, _n in found] == ["near.wav"] and skipped == 1


def test_happy_e2e_the_note_names_every_reason(tmp_path):
    panel = MP.PlayerPanel(engine=FakeEngine())
    try:
        panel.add_collected([], 3, False)
        text = panel.note.text()
        assert "3" in text and "not audio" in text and "too deep" in text
    finally:
        panel.close()
