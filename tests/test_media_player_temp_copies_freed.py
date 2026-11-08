"""The Media Player frees its copies of remote tracks (review round 3).

Before: a remote track was copied into a temporary ``axross-media-*``
folder, and the copy stayed until the extension unloaded - removing its
row, clearing the list or loading a playlist freed nothing, so every
Clear and re-add of a remote folder kept up to 2 GB more on the disk. A
crash or a kill left the folders for good. Now a copy goes with its row
(the one playing once it stops), and a start removes the folders of an
axross that is gone; each folder names its process.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time

import pytest

from tests.test_media_player_review_fixes import MP, FakeEngine


@pytest.fixture
def temp_root(tmp_path, monkeypatch):
    root = tmp_path / "tmp"
    root.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(root))
    yield root
    while MP._TEMP_FOLDERS:
        MP._forget_temp(MP._TEMP_FOLDERS[-1])


@pytest.fixture
def remote():
    from core.ram_fs import RamFsSession

    ram = RamFsSession()
    ram.mkdir("/music")
    for name in ("a.wav", "b.wav", "c.wav"):
        with ram.open_write(f"/music/{name}") as fh:
            fh.write(b"RIFF" + bytes(64 * 1024))
    return ram


def _copies(root) -> list[str]:
    return sorted(os.path.join(d, f) for d, _s, files in os.walk(root) for f in files
                  if f.endswith(".wav"))


def _panel(remote, *, play_first=False):
    panel = MP.PlayerPanel(engine=FakeEngine())  # no runner: synchronous
    panel.add_remote(remote, ["/music"], play_first=play_first)
    assert panel.playlist.count() == 3
    return panel


def test_sad_clearing_the_list_deletes_the_copies(temp_root, remote):
    panel = _panel(remote)
    try:
        assert len(_copies(temp_root)) == 3
        panel.clear_playlist()
        assert _copies(temp_root) == []
        assert os.listdir(temp_root) == []  # the emptied folder went too
    finally:
        panel.shutdown()


def test_sad_removing_a_row_deletes_only_its_copy(temp_root, remote):
    panel = _panel(remote)
    try:
        panel.playlist.item(1).setSelected(True)
        panel._remove_selected()
        left = [os.path.basename(p) for p in _copies(temp_root)]
        assert left == ["a.wav", "c.wav"]
    finally:
        panel.shutdown()


def test_sad_loading_a_playlist_deletes_the_copies(temp_root, remote, tmp_path):
    track = tmp_path / "local.wav"
    track.write_bytes(b"RIFF" + bytes(64))
    playlist = tmp_path / "list.m3u"
    playlist.write_text(f"{track}\n", encoding="utf-8")
    panel = _panel(remote)
    try:
        panel.load_playlist(str(playlist))
        assert panel.playlist.count() == 1
        assert _copies(temp_root) == []
    finally:
        panel.shutdown()


def test_edge_the_playing_copy_stays_until_it_stops(temp_root, remote):
    panel = _panel(remote, play_first=True)
    try:
        playing = panel.engine.path
        panel.clear_playlist()
        assert _copies(temp_root) == [playing]  # still played from
        panel.engine.stop()
        panel.engine.changed.emit()
        assert _copies(temp_root) == []
        assert os.listdir(temp_root) == []
    finally:
        panel.shutdown()


def test_edge_a_copy_removed_while_playing_goes_when_the_next_track_starts(temp_root, remote,
                                                                           tmp_path):
    other = tmp_path / "other.wav"
    other.write_bytes(b"RIFF" + bytes(64))
    panel = _panel(remote, play_first=True)
    try:
        playing = panel.engine.path
        panel.playlist.item(0).setSelected(True)
        panel._remove_selected()
        assert os.path.exists(playing)
        panel.play_item(panel._append(str(other)))
        assert not os.path.exists(playing)
        assert len(_copies(temp_root)) == 2  # b and c are still in the list
    finally:
        panel.shutdown()


def _dead_pid() -> int:
    proc = subprocess.Popen([sys.executable, "-c", "pass"])
    proc.wait()
    return proc.pid


def test_happy_a_start_sweeps_the_folders_of_an_axross_that_is_gone(temp_root):
    gone = temp_root / "axross-media-crashed"
    (gone / "0").mkdir(parents=True)
    (gone / "0" / "song.wav").write_bytes(b"RIFF")
    (gone / "owner.json").write_text(json.dumps({"pid": _dead_pid(), "proc_start": None}))
    ours = MP.remote_temp_folder()  # this process: alive
    with open(os.path.join(ours, "owner.json"), encoding="utf-8") as fh:
        assert json.load(fh)["pid"] == os.getpid()
    old_unmarked = temp_root / "axross-media-before-markers"
    old_unmarked.mkdir()
    long_ago = time.time() - MP.STALE_UNMARKED_SECONDS - 60
    os.utime(old_unmarked, (long_ago, long_ago))
    recent_unmarked = temp_root / "axross-media-unknown"
    recent_unmarked.mkdir()
    unrelated = temp_root / "something-else"
    unrelated.mkdir()

    removed = MP.sweep_stale_temp_folders()

    assert sorted(os.path.basename(p) for p in removed) == [
        "axross-media-before-markers", "axross-media-crashed"]
    assert not gone.exists() and not old_unmarked.exists()
    assert os.path.isdir(ours) and recent_unmarked.exists() and unrelated.exists()


def test_edge_another_running_process_keeps_its_folder(temp_root):
    from core.extensions import _process_start

    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        folder = temp_root / "axross-media-running"
        folder.mkdir()
        (folder / "owner.json").write_text(json.dumps(
            {"pid": proc.pid, "proc_start": _process_start(proc.pid)}))
        assert MP.sweep_stale_temp_folders() == []
        assert folder.exists()
    finally:
        proc.kill()
        proc.wait()
