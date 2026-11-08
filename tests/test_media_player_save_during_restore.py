"""The Media Player saves while its restore is still checking tracks
(review round 3).

Before: the restore checks off the GUI thread whether each saved track
still exists, and until it finished every save was skipped ("the file
still holds more than the list"). One track on a hung mount meant the
check never finished - nothing of the session was saved, not the tracks
added, not the settings, not even at shutdown. Now a save during the
restore writes the tracks it is still checking as the file had them,
ahead of what was added since.
"""

from __future__ import annotations

import json

from tests.test_media_player_review_fixes import MP, FakeEngine


def _hung_restore(tmp_path):
    state = tmp_path / "mp-state.json"
    state.write_text(json.dumps({"version": MP.STATE_VERSION, "current": 0, "position_ms": 5000,
                                 "tracks": [{"path": "/mnt/hung-nfs/old.mp3", "title": "Old"}]}))
    song = tmp_path / "new.mp3"
    song.write_bytes(b"x")
    pending = []  # the restore's check: never run, as on a hung mount
    panel = MP.PlayerPanel(engine=FakeEngine(), state_path=str(state),
                           run_in_background=lambda work, done, failed: pending.append(
                               (work, done)))
    return panel, state, song, pending


def test_sad_a_restore_that_never_finishes_does_not_block_every_save(tmp_path):
    panel, state, song, pending = _hung_restore(tmp_path)
    try:
        panel.add_collected(*MP.collect_local([str(song)]))
        panel.set_repeat("all")
        panel.save_state()
        saved = json.loads(state.read_text())
        assert [t["path"] for t in saved["tracks"]] == ["/mnt/hung-nfs/old.mp3", str(song)]
        assert saved["tracks"][0]["title"] == "Old"
        assert saved["repeat"] == "all"
        assert (saved["current"], saved["position_ms"]) == (0, 5000)  # still the old one

        # The check answers after all: the list saves as itself, nothing twice.
        (work, done), = pending
        done([(0, "/mnt/hung-nfs/old.mp3", "Old", 0)])
        panel.save_state()
        paths = [t["path"] for t in json.loads(state.read_text())["tracks"]]
        assert sorted(paths) == sorted(["/mnt/hung-nfs/old.mp3", str(song)])
    finally:
        panel.shutdown()


def test_edge_the_shutdown_save_keeps_the_tracks_still_being_checked(tmp_path):
    panel, state, song, _pending = _hung_restore(tmp_path)
    panel.add_collected(*MP.collect_local([str(song)]))
    panel.shutdown()
    saved = json.loads(state.read_text())
    assert [t["path"] for t in saved["tracks"]] == ["/mnt/hung-nfs/old.mp3", str(song)]
