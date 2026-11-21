"""media_player.json is shared with axross-amp, which reads and writes it as
well and stores more than axross does: keys of its own, a track's artist,
album, disc and track number, options of its own and 49 visualizer faces
(axross has 18). Before: every save in axross wrote only its own keys and
fields, and the face read from the file was replaced by axross's own (it
accepts only faces it knows) - the amp user's face, tags and settings were
lost each time axross ran. Now a save merges with what the file holds then:
what axross does not know is kept, and a face axross does not know stays
until the user picks one in axross."""

from __future__ import annotations

import json

import pytest

from tests.test_media_player_review_fixes import MP, FakeEngine

AMP_FACE = "amp_only_face"
assert AMP_FACE not in MP.Visualizer.MODES


def _sync(work, done, failed):
    try:
        result = work()
    except Exception as exc:  # noqa: BLE001
        failed(exc)
    else:
        done(result)


def _songs(tmp_path, *names):
    out = []
    for name in names:
        song = tmp_path / name
        song.write_bytes(b"x")
        out.append(str(song))
    return out


def _panel(state):
    return MP.PlayerPanel(engine=FakeEngine(), state_path=str(state), run_in_background=_sync)


def _write(state, data):
    state.write_text(json.dumps(data), encoding="utf-8")


def _saved(state):
    return json.loads(state.read_text(encoding="utf-8"))


def test_happy_unknown_top_level_keys_are_kept(tmp_path):
    state = tmp_path / "media_player.json"
    _write(state, {"version": MP.STATE_VERSION, "volume": 40, "amp_window": [10, 20, 640, 480],
                   "amp_theme": "dark", "tracks": []})
    panel = _panel(state)
    try:
        panel.set_repeat("all")
        panel.save_state()
        saved = _saved(state)
        assert saved["amp_window"] == [10, 20, 640, 480]
        assert saved["amp_theme"] == "dark"
        assert saved["repeat"] == "all"
        assert saved["volume"] == 40
    finally:
        panel.shutdown()
    assert _saved(state)["amp_theme"] == "dark"  # the shutdown save as well


def test_happy_a_key_written_while_axross_runs_is_kept(tmp_path):
    state = tmp_path / "media_player.json"
    _write(state, {"version": MP.STATE_VERSION, "tracks": []})
    panel = _panel(state)
    try:
        on_disk = _saved(state) if state.exists() else {}
        _write(state, {**on_disk, "amp_queue": ["x"]})  # axross-amp saved meanwhile
        panel.set_shuffle(True)
        panel.save_state()
        saved = _saved(state)
        assert saved["amp_queue"] == ["x"]
        assert saved["shuffle"] is True
    finally:
        panel.shutdown()


def test_happy_per_track_tags_axross_amp_added_are_kept(tmp_path):
    a, b = _songs(tmp_path, "a.mp3", "b.mp3")
    state = tmp_path / "media_player.json"
    _write(state, {"version": MP.STATE_VERSION, "current": -1, "tracks": [
        {"path": a, "title": "A", "duration": 1000, "artist": "Art", "album": "Alb",
         "disc": 1, "track": 3, "amp_rating": 5},
        {"path": b, "title": "", "duration": 0, "artist": "Other", "album": "", "disc": 0,
         "track": 0},
    ]})
    panel = _panel(state)
    try:
        assert panel.playlist.count() == 2
        c, = _songs(tmp_path, "c.mp3")
        panel.add_collected(*MP.collect_local([c]))
        # The order changes in axross: the tags go with their track's path.
        item = panel.playlist.takeItem(0)
        panel.playlist.addItem(item)
        panel.save_state()
        tracks = {t["path"]: t for t in _saved(state)["tracks"]}
        assert [t["path"] for t in _saved(state)["tracks"]] == [b, c, a]
        assert tracks[a]["artist"] == "Art"
        assert tracks[a]["album"] == "Alb"
        assert (tracks[a]["disc"], tracks[a]["track"]) == (1, 3)
        assert tracks[a]["amp_rating"] == 5
        assert tracks[a]["title"] == "A"
        assert tracks[b]["artist"] == "Other"
        assert set(tracks[c]) == {"path", "title", "duration"}  # nothing made up
    finally:
        panel.shutdown()


def test_edge_a_removed_track_takes_its_tags_with_it(tmp_path):
    a, b = _songs(tmp_path, "a.mp3", "b.mp3")
    state = tmp_path / "media_player.json"
    _write(state, {"version": MP.STATE_VERSION, "current": -1, "tracks": [
        {"path": a, "title": "", "artist": "Art"}, {"path": b, "title": "", "artist": "B"}]})
    panel = _panel(state)
    try:
        panel.playlist.takeItem(0)
        panel.save_state()
        tracks = _saved(state)["tracks"]
        assert [(t["path"], t["artist"]) for t in tracks] == [(b, "B")]
    finally:
        panel.shutdown()


def test_happy_unknown_visual_options_are_kept(tmp_path):
    state = tmp_path / "media_player.json"
    _write(state, {"version": MP.STATE_VERSION, "visual_options": {
        "bars": 64, "smoothing": 80, "peak_fall": 120, "fps": 50, "hide_cursor": False,
        "amp_glow": 0.7, "amp_mirror": True}})
    panel = _panel(state)
    try:
        assert panel.visualizer.options["bars"] == 64
        panel.visualizer.set_option("fps", 60)
        panel.save_state()
        options = _saved(state)["visual_options"]
        assert options["amp_glow"] == 0.7
        assert options["amp_mirror"] is True
        assert (options["bars"], options["smoothing"], options["peak_fall"],
                options["fps"], options["hide_cursor"]) == (64, 80, 120, 60, False)
    finally:
        panel.shutdown()


@pytest.mark.parametrize("smoothing,peak_fall", [(0, 5), (95, 300), (75, 100)])
def test_edge_option_values_axross_amp_can_write_come_back_unchanged(tmp_path, smoothing,
                                                                     peak_fall):
    # axross-amp's ranges are axross's (0..95, 5..300): no clamp rewrites them.
    state = tmp_path / "media_player.json"
    _write(state, {"version": MP.STATE_VERSION,
                   "visual_options": {"smoothing": smoothing, "peak_fall": peak_fall}})
    panel = _panel(state)
    try:
        panel.save_state()
        options = _saved(state)["visual_options"]
        assert (options["smoothing"], options["peak_fall"]) == (smoothing, peak_fall)
    finally:
        panel.shutdown()


def test_happy_a_face_axross_does_not_know_stays_in_the_file(tmp_path):
    state = tmp_path / "media_player.json"
    _write(state, {"version": MP.STATE_VERSION, "visualizer": AMP_FACE})
    panel = _panel(state)
    try:
        shown = panel.visualizer.mode
        assert shown in MP.Visualizer.MODES  # axross shows a face of its own
        panel.set_repeat("one")
        panel.save_state()
        assert _saved(state)["visualizer"] == AMP_FACE
    finally:
        panel.shutdown()
    assert _saved(state)["visualizer"] == AMP_FACE
    # And at the next start of axross as well.
    panel = _panel(state)
    try:
        panel.save_state()
        assert _saved(state)["visualizer"] == AMP_FACE
    finally:
        panel.shutdown()


def test_happy_a_face_picked_in_axross_is_written(tmp_path):
    state = tmp_path / "media_player.json"
    _write(state, {"version": MP.STATE_VERSION, "visualizer": AMP_FACE})
    panel = _panel(state)
    try:
        other = next(m for m in MP.Visualizer.MODES if m != panel.visualizer.mode)
        panel.visualizer.set_mode(other)
        panel.save_state()
        assert _saved(state)["visualizer"] == other
        # Picked: from now on axross's face, also back to the first one.
        first = next(m for m in MP.Visualizer.MODES if m != other)
        panel.visualizer.set_mode(first)
        panel.save_state()
        assert _saved(state)["visualizer"] == first
    finally:
        panel.shutdown()


def test_edge_a_face_axross_amp_set_while_axross_runs_is_kept(tmp_path):
    state = tmp_path / "media_player.json"
    _write(state, {"version": MP.STATE_VERSION, "visualizer": "mirror"})
    panel = _panel(state)
    try:
        assert panel.visualizer.mode == "mirror"
        _write(state, {**_saved(state), "visualizer": AMP_FACE})
        panel.save_state()
        assert _saved(state)["visualizer"] == AMP_FACE
    finally:
        panel.shutdown()


def test_edge_axross_own_face_is_saved_as_before(tmp_path):
    state = tmp_path / "media_player.json"
    _write(state, {"version": MP.STATE_VERSION, "visualizer": "mirror"})
    panel = _panel(state)
    try:
        panel.save_state()
        assert _saved(state)["visualizer"] == "mirror"
        panel.visualizer.set_mode("scope")
        panel.save_state()
        assert _saved(state)["visualizer"] == "scope"
    finally:
        panel.shutdown()


def test_sad_extras_too_large_are_dropped_not_the_save(tmp_path, monkeypatch):
    monkeypatch.setattr(MP, "MAX_STATE_BYTES", 6000)
    a, = _songs(tmp_path, "a.mp3")
    state = tmp_path / "media_player.json"
    _write(state, {"version": MP.STATE_VERSION, "current": -1,
                   "tracks": [{"path": a, "title": "", "artist": "Art"}],
                   "amp_blob": "x" * 5600})
    panel = _panel(state)
    try:
        panel.set_repeat("all")
        panel.save_state()
        assert "Cannot save" not in panel.note.text()
        saved = _saved(state)
        assert len(state.read_bytes()) <= 6000
        assert saved["repeat"] == "all"
        assert [t["path"] for t in saved["tracks"]] == [a]
        assert "amp_blob" not in saved
    finally:
        panel.shutdown()


def test_sad_a_broken_file_is_no_reason_to_fail(tmp_path):
    state = tmp_path / "media_player.json"
    state.write_bytes(b"{broken")
    panel = _panel(state)
    try:
        panel.save_state()
        saved = _saved(state)
        assert saved["version"] == MP.STATE_VERSION
        assert panel.visualizer.mode == saved["visualizer"]
    finally:
        panel.shutdown()
