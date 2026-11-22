"""media_player.json is shared with axross-amp: both programs keep their
playlist in it (review 14, M3). Before: a save in axross wrote the list it
had loaded at its start whole - a track added in axross-amp while axross ran
was lost at axross's next save (a volume change, the periodic save while
playing, the shutdown). Now the playlist is merged three ways, as axross-amp
does on its side: against what axross last read or wrote of it (the base),
by the tracks' paths in order. A list only the file changed is the file's
(with what axross knows of the same tracks where the file lacks it), the
track playing in axross found there by its path; a list only axross changed
is axross's, as before. A list both changed (review 15: a track added in
axross-amp was still lost when axross removed or added one) is axross's with
the file's changes since the base made in it: the tracks it removed taken
out, the tracks it added put after their neighbours in the file's list."""

from __future__ import annotations

import json

from tests.test_media_player_review_fixes import MP, FakeEngine


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


def _paths(state_or_dict):
    data = state_or_dict if isinstance(state_or_dict, dict) else _saved(state_or_dict)
    return [t["path"] for t in data["tracks"]]


def _t(path, title="", duration=0, **extra):
    return {"path": path, "title": title, "duration": duration, **extra}


def _st(tracks, current=-1, position_ms=0, **extra):
    return {"version": MP.STATE_VERSION, "tracks": tracks, "current": current,
            "position_ms": position_ms, **extra}


# -- the pure merge -------------------------------------------------------------------


def test_happy_a_track_the_file_added_survives_an_unchanged_list():
    base = _st([_t("/m/1"), _t("/m/2")], current=1)
    own = _st([_t("/m/1"), _t("/m/2")], current=1, position_ms=4000, volume=30)
    stored = _st([_t("/m/1"), _t("/m/2"), _t("/m/3", "Three", 9000, artist="Art")],
                 current=1, position_ms=8000, volume=80)
    merged = MP.merge_shared_state(own, stored, base)
    assert _paths(merged) == ["/m/1", "/m/2", "/m/3"]
    assert merged["tracks"][2] == _t("/m/3", "Three", 9000, artist="Art")  # as it was
    assert (merged["current"], merged["position_ms"]) == (1, 8000)  # the file's
    assert merged["volume"] == 30  # axross's own settings still win


def test_edge_without_a_base_the_list_is_axross_s_as_before():
    own = _st([_t("/m/1"), _t("/m/2")], current=1, position_ms=4000)
    stored = _st([_t("/m/1"), _t("/m/2"), _t("/m/3")], current=0, position_ms=8000)
    merged = MP.merge_shared_state(own, stored)
    assert _paths(merged) == ["/m/1", "/m/2"]
    assert (merged["current"], merged["position_ms"]) == (1, 4000)
    assert _paths(MP.merge_shared_state(own, stored, None)) == ["/m/1", "/m/2"]


def test_happy_axross_s_own_edit_still_wins():
    base = _st([_t("/m/1"), _t("/m/2")], current=0)
    own = _st([_t("/m/1"), _t("/m/2"), _t("/m/4")], current=0, position_ms=100)
    stored = _st([_t("/m/1", artist="A"), _t("/m/2")], current=0, position_ms=50)
    merged = MP.merge_shared_state(own, stored, base)
    assert _paths(merged) == ["/m/1", "/m/2", "/m/4"]
    assert merged["tracks"][0]["artist"] == "A"  # the file's tags still kept
    assert (merged["current"], merged["position_ms"]) == (0, 100)


def test_edge_both_changed_axross_s_edit_and_the_file_s_are_both_kept():
    base = _st([_t("/m/1"), _t("/m/2")], current=0)
    own = _st([_t("/m/2")], current=0, position_ms=100)
    stored = _st([_t("/m/1"), _t("/m/2", artist="B"), _t("/m/3")], current=2,
                 position_ms=50)
    merged = MP.merge_shared_state(own, stored, base)
    assert _paths(merged) == ["/m/2", "/m/3"]  # 1 removed in axross, 3 added in the file
    assert merged["tracks"][0]["artist"] == "B"
    assert (merged["current"], merged["position_ms"]) == (0, 100)


def test_happy_the_track_axross_moved_to_is_found_by_its_path():
    base = _st([_t("/m/a"), _t("/m/b"), _t("/m/c")], current=0)
    own = _st([_t("/m/a"), _t("/m/b"), _t("/m/c")], current=2, position_ms=1234)
    # axross-amp put a track ahead of them: c is the fourth now.
    stored = _st([_t("/m/x"), _t("/m/a"), _t("/m/b"), _t("/m/c")], current=0,
                 position_ms=999)
    merged = MP.merge_shared_state(own, stored, base)
    assert _paths(merged) == ["/m/x", "/m/a", "/m/b", "/m/c"]
    assert (merged["current"], merged["position_ms"]) == (3, 1234)


def test_edge_a_path_twice_takes_the_place_nearest_to_axross_s():
    base = _st([_t("/m/a"), _t("/m/b"), _t("/m/c")], current=0)
    own = _st([_t("/m/a"), _t("/m/b"), _t("/m/c")], current=2, position_ms=5)
    stored = _st([_t("/m/c"), _t("/m/a"), _t("/m/b"), _t("/m/c")], current=0)
    assert MP.merge_shared_state(own, stored, base)["current"] == 3
    stored = _st([_t("/m/c"), _t("/m/c"), _t("/m/a"), _t("/m/b"), _t("/m/z"),
                  _t("/m/z"), _t("/m/c")], current=0)
    assert MP.merge_shared_state(own, stored, base)["current"] == 1


def test_edge_the_track_axross_moved_to_is_gone_from_the_file():
    base = _st([_t("/m/a"), _t("/m/b")], current=0)
    own = _st([_t("/m/a"), _t("/m/b")], current=1, position_ms=5)
    stored = _st([_t("/m/a"), _t("/m/c")], current=1, position_ms=70)
    merged = MP.merge_shared_state(own, stored, base)
    assert _paths(merged) == ["/m/a", "/m/c"]
    assert (merged["current"], merged["position_ms"]) == (1, 70)


def test_happy_what_axross_knows_of_a_track_fills_the_file_s_gaps():
    base = _st([_t("/m/a"), _t("/m/b")])
    own = _st([_t("/m/a", "Own A", 3000), _t("/m/b", "Own B", 4000)])
    stored = _st([_t("/m/a", "", 0, artist="Art"), _t("/m/b", "Amp B", 4100),
                  _t("/m/c", "", 0)])
    tracks = MP.merge_shared_state(own, stored, base)["tracks"]
    assert tracks[0] == _t("/m/a", "Own A", 3000, artist="Art")
    assert tracks[1] == _t("/m/b", "Amp B", 4100)  # the file's values stay
    assert tracks[2] == _t("/m/c", "", 0)  # nothing made up


def test_edge_the_same_list_only_the_file_moved_to_another_track():
    base = _st([_t("/m/a"), _t("/m/b")], current=0)
    own = _st([_t("/m/a"), _t("/m/b")], current=0, position_ms=10)
    stored = _st([_t("/m/a"), _t("/m/b")], current=1, position_ms=6000)
    merged = MP.merge_shared_state(own, stored, base)
    assert (merged["current"], merged["position_ms"]) == (1, 6000)
    # Both moved: axross's.
    own = _st([_t("/m/a"), _t("/m/b")], current=-1)
    merged = MP.merge_shared_state(own, stored, base)
    assert (merged["current"], merged["position_ms"]) == (-1, 0)


# -- the panel ------------------------------------------------------------------------


def _amp_added(tmp_path, current=1, position_ms=8000):
    """A state of [a, b] axross restores, then axross-amp's save of [a, b, c]."""
    a, b, c = _songs(tmp_path, "a.mp3", "b.mp3", "c.mp3")
    state = tmp_path / "media_player.json"
    _write(state, _st([_t(a, "A", 1000), _t(b)], current=1, position_ms=7000, volume=50))
    panel = _panel(state)
    assert panel.playlist.count() == 2
    _write(state, _st([_t(a, "A", 1000, artist="Art"), _t(b), _t(c, "C", 2000, album="Alb")],
                      current=current, position_ms=position_ms, volume=50))
    return panel, state, (a, b, c)


def test_happy_the_review_scenario_a_save_keeps_the_track_axross_amp_added(tmp_path):
    panel, state, (a, b, c) = _amp_added(tmp_path)
    try:
        panel.volume.setValue(30)
        panel.save_state()
        saved = _saved(state)
        assert _paths(saved) == [a, b, c]
        assert saved["tracks"][2] == _t(c, "C", 2000, album="Alb")
        assert saved["tracks"][0]["artist"] == "Art"
        assert (saved["current"], saved["position_ms"]) == (1, 8000)
        assert saved["volume"] == 30
    finally:
        panel.shutdown()
    assert _paths(state) == [a, b, c]  # the shutdown save as well


def test_happy_a_save_after_the_merge_is_stable_and_a_later_edit_is_written(tmp_path):
    panel, state, (a, b, c) = _amp_added(tmp_path)
    try:
        panel.save_state()
        first = state.read_text(encoding="utf-8")
        panel.save_state()
        panel.save_state()
        assert state.read_text(encoding="utf-8") == first
        assert _paths(state) == [a, b, c]
        # An edit in axross is merged in (the file's track it never showed
        # stays: review 15).
        d, = _songs(tmp_path, "d.mp3")
        panel.add_collected(*MP.collect_local([d]))
        panel.save_state()
        assert _paths(state) == [a, b, c, d]
        panel.save_state()
        assert _paths(state) == [a, b, c, d]
    finally:
        panel.shutdown()
    assert _paths(state) == [a, b, c, d]


def test_happy_the_track_played_in_axross_is_current_in_the_file_s_list(tmp_path):
    panel, state, (a, b, c) = _amp_added(tmp_path, current=2)
    try:
        # axross-amp also put a track ahead: a is the second now.
        x, = _songs(tmp_path, "x.mp3")
        _write(state, {**_saved(state), "tracks": [_t(x)] + _saved(state)["tracks"],
                       "current": 3})
        panel.play_item(panel.playlist.item(0))  # a, in axross
        panel.save_state()
        saved = _saved(state)
        assert _paths(saved) == [x, a, b, c]
        assert saved["current"] == 1
    finally:
        panel.shutdown()


def test_edge_a_save_while_the_restore_is_pending_keeps_the_file_s_track(tmp_path):
    state = tmp_path / "media_player.json"
    _write(state, _st([_t("/mnt/hung-nfs/old.mp3", "Old")], current=0, position_ms=5000))
    pending = []  # the restore's check: never run, as on a hung mount
    panel = MP.PlayerPanel(engine=FakeEngine(), state_path=str(state),
                           run_in_background=lambda work, done, failed: pending.append(
                               (work, done)))
    try:
        _write(state, _st([_t("/mnt/hung-nfs/old.mp3", "Old"), _t("/m/amp.mp3")],
                          current=0, position_ms=6000))
        panel.set_repeat("all")
        panel.save_state()
        saved = _saved(state)
        assert _paths(saved) == ["/mnt/hung-nfs/old.mp3", "/m/amp.mp3"]
        assert (saved["current"], saved["position_ms"]) == (0, 6000)
        assert saved["repeat"] == "all"
    finally:
        panel.shutdown()


def test_sad_the_file_s_list_too_large_with_its_extras_still_saves_whole(tmp_path,
                                                                        monkeypatch):
    monkeypatch.setattr(MP, "MAX_STATE_BYTES", 6000)
    panel, state, (a, b, c) = _amp_added(tmp_path)
    try:
        _write(state, {**_saved(state), "tracks": _saved(state)["tracks"][:2]
                       + [_t(c, "C", 2000, amp_blob="x" * 5400)]})
        panel.save_state()
        assert "Cannot save" not in panel.note.text()
        assert len(state.read_bytes()) <= 6000
        saved = _saved(state)
        assert _paths(saved) == [a, b, c]
        assert "amp_blob" not in saved["tracks"][2]
        assert saved["tracks"][2]["title"] == "C"
    finally:
        panel.shutdown()


# -- both changed: the three-way merge (review 15; its order, review 16) ---------------
#
# Both lists changed since the base: axross's list, every track the file
# removed since the base taken out, every track the file added inserted right
# after the nearest track before it in the file's list that is in the result.


def test_happy_s2_a_removal_in_axross_keeps_the_track_axross_amp_added():
    base = _st([_t("/m/1"), _t("/m/2"), _t("/m/3")], current=0)
    own = _st([_t("/m/1"), _t("/m/3")], current=0, position_ms=10)
    stored = _st([_t("/m/1"), _t("/m/2"), _t("/m/3"), _t("/m/x", "X", 5, artist="Art")],
                 current=3, position_ms=20)
    assert MP.playlist_merge(own, stored, base) == "both"
    merged = MP.merge_shared_state(own, stored, base)
    assert _paths(merged) == ["/m/1", "/m/3", "/m/x"]
    assert merged["tracks"][2] == _t("/m/x", "X", 5, artist="Art")  # the file's entry
    assert (merged["current"], merged["position_ms"]) == (0, 10)


def test_happy_s3_both_added_keeps_both_tracks():
    base = _st([_t("/m/1"), _t("/m/2"), _t("/m/3")])
    own = _st([_t("/m/1"), _t("/m/2"), _t("/m/3"), _t("/m/y")])
    stored = _st([_t("/m/1"), _t("/m/2"), _t("/m/3"), _t("/m/x")])
    assert _paths(MP.merge_shared_state(own, stored, base)) == \
        ["/m/1", "/m/2", "/m/3", "/m/x", "/m/y"]


def test_happy_s1_a_removal_in_axross_of_the_file_s_track_sticks():
    # axross restarted after axross-amp added x (the base has it), the user
    # removed x in axross: x is written no more.
    base = _st([_t("/m/1"), _t("/m/2"), _t("/m/x")])
    own = _st([_t("/m/1"), _t("/m/2")])
    stored = _st([_t("/m/1"), _t("/m/2"), _t("/m/x", artist="Art")])
    assert _paths(MP.merge_shared_state(own, stored, base)) == ["/m/1", "/m/2"]
    # And the file changed besides (a track added): x still stays out.
    stored = _st([_t("/m/1"), _t("/m/2"), _t("/m/x"), _t("/m/z")])
    assert _paths(MP.merge_shared_state(own, stored, base)) == ["/m/1", "/m/2", "/m/z"]


def test_happy_both_added_tracks_go_after_their_neighbours_in_the_file():
    base = _st([_t("/m/a"), _t("/m/b"), _t("/m/c")])
    own = _st([_t("/m/c"), _t("/m/a"), _t("/m/b"), _t("/m/y")])  # moved c, added y
    stored = _st([_t("/m/x0"), _t("/m/a"), _t("/m/x1"), _t("/m/x2"), _t("/m/b"),
                  _t("/m/c"), _t("/m/x3")])
    # (x3, added at the end of the file's list, at the end of the file's
    # tracks here - after b, not after c, which axross moved to the top)
    assert _paths(MP.merge_shared_state(own, stored, base)) == \
        ["/m/x0", "/m/c", "/m/a", "/m/x1", "/m/x2", "/m/b", "/m/x3", "/m/y"]
    # A track both added is in the list once, where axross has it.
    stored = _st([_t("/m/a"), _t("/m/y", artist="Y"), _t("/m/b"), _t("/m/c")])
    merged = MP.merge_shared_state(own, stored, base)
    assert _paths(merged) == ["/m/c", "/m/a", "/m/b", "/m/y"]
    assert merged["tracks"][3]["artist"] == "Y"  # its extras still kept


def test_happy_both_removed():
    base = _st([_t("/m/1"), _t("/m/2"), _t("/m/3"), _t("/m/4")])
    own = _st([_t("/m/1"), _t("/m/3"), _t("/m/4")])
    stored = _st([_t("/m/1"), _t("/m/2"), _t("/m/4")])
    assert _paths(MP.merge_shared_state(own, stored, base)) == ["/m/1", "/m/4"]
    stored = _st([_t("/m/1"), _t("/m/4")])  # the same track as well
    assert _paths(MP.merge_shared_state(own, stored, base)) == ["/m/1", "/m/4"]


def test_edge_the_track_current_in_axross_was_removed_by_the_file():
    base = _st([_t("/m/1"), _t("/m/2"), _t("/m/3")], current=1)
    own = _st([_t("/m/1"), _t("/m/2"), _t("/m/3"), _t("/m/y")], current=1,
              position_ms=10)
    stored = _st([_t("/m/1"), _t("/m/3")], current=1, position_ms=70)
    merged = MP.merge_shared_state(own, stored, base)
    assert _paths(merged) == ["/m/1", "/m/3", "/m/y"]
    assert (merged["current"], merged["position_ms"]) == (1, 70)  # the file's: 3
    # The file's current track gone from the result as well: none.
    own = _st([_t("/m/1"), _t("/m/2"), _t("/m/y")], current=1, position_ms=10)
    merged = MP.merge_shared_state(own, stored, base)
    assert _paths(merged) == ["/m/1", "/m/y"]
    assert (merged["current"], merged["position_ms"]) == (-1, 0)


def test_edge_duplicates_axross_s_stay_the_file_s_added_once():
    base = _st([_t("/m/a"), _t("/m/b")])
    own = _st([_t("/m/a"), _t("/m/b"), _t("/m/a"), _t("/m/c"), _t("/m/c")], current=2,
              position_ms=9)
    stored = _st([_t("/m/a"), _t("/m/x"), _t("/m/b"), _t("/m/x"), _t("/m/a"), _t("/m/z")],
                 current=1)
    merged = MP.merge_shared_state(own, stored, base)
    # Each copy of a path is an entry of its own (review 16): the file's two
    # x are both kept; z follows the file's second a - the second a, which
    # axross has too.
    assert _paths(merged) == ["/m/a", "/m/x", "/m/b", "/m/x", "/m/a", "/m/z", "/m/c", "/m/c"]
    # axross's current entry (its second a), not the first a.
    assert (merged["current"], merged["position_ms"]) == (4, 9)
    # A path the file has twice that axross removed goes from the whole list.
    base = _st([_t("/m/a"), _t("/m/b"), _t("/m/a")])
    own = _st([_t("/m/a"), _t("/m/a"), _t("/m/b"), _t("/m/y")])
    stored = _st([_t("/m/a"), _t("/m/a")])
    assert _paths(MP.merge_shared_state(own, stored, base)) == ["/m/a", "/m/a", "/m/y"]


def test_happy_the_file_s_current_track_is_found_by_its_path():
    base = _st([_t("/m/a"), _t("/m/b")], current=-1)
    own = _st([_t("/m/b"), _t("/m/a")], current=-1)
    stored = _st([_t("/m/a"), _t("/m/b"), _t("/m/x")], current=2, position_ms=33)
    merged = MP.merge_shared_state(own, stored, base)
    # (x added at the end of the file's list: at the end here, after
    # axross's reorder)
    assert _paths(merged) == ["/m/b", "/m/a", "/m/x"]
    assert (merged["current"], merged["position_ms"]) == (2, 33)


def test_edge_a_file_entry_without_a_path_is_not_added():
    base = _st([_t("/m/a")])
    own = _st([_t("/m/a"), _t("/m/y")])
    stored = _st([_t("/m/a"), {"title": "no path"}, "junk", _t("/m/x")])
    assert _paths(MP.merge_shared_state(own, stored, base)) == ["/m/a", "/m/x", "/m/y"]


def test_happy_plain_state_of_a_both_merge_has_the_merged_list():
    base = _st([_t("/m/1"), _t("/m/2")])
    own = _st([_t("/m/1")])
    stored = _st([_t("/m/1", artist="A"), _t("/m/2"), _t("/m/x", "X", 4, blob="b")])
    plain = MP.plain_state(MP.merge_shared_state(own, stored, base), own)
    assert plain["tracks"] == [_t("/m/1"), _t("/m/x", "X", 4)]


def _remove_row(panel, row):
    panel.playlist.clearSelection()
    panel.playlist.item(row).setSelected(True)
    panel._remove_selected()


def test_happy_panel_s2_a_removal_in_axross_keeps_axross_amp_s_track(tmp_path):
    a, b, c, x = _songs(tmp_path, "a.mp3", "b.mp3", "c.mp3", "x.mp3")
    state = tmp_path / "media_player.json"
    _write(state, _st([_t(a), _t(b), _t(c)], current=0))
    panel = _panel(state)
    try:
        _write(state, _st([_t(a), _t(b), _t(c), _t(x, "X")], current=0))
        _remove_row(panel, 1)  # b removed in axross
        panel.save_state()
        assert _paths(state) == [a, c, x]
        panel.save_state()  # stable: the file's list, which has axross's edit
        assert _paths(state) == [a, c, x]
        # A later edit in axross is merged against axross's own list.
        y, = _songs(tmp_path, "y.mp3")
        panel.add_collected(*MP.collect_local([y]))
        panel.save_state()
        assert _paths(state) == [a, c, x, y]
        _remove_row(panel, 1)  # c
        panel.save_state()
        assert _paths(state) == [a, x, y]
    finally:
        panel.shutdown()
    assert _paths(state) == [a, x, y]


def test_happy_panel_s3_both_add_keeps_both(tmp_path):
    a, b, x, y = _songs(tmp_path, "a.mp3", "b.mp3", "x.mp3", "y.mp3")
    state = tmp_path / "media_player.json"
    _write(state, _st([_t(a), _t(b)], current=0))
    panel = _panel(state)
    try:
        _write(state, _st([_t(a), _t(b), _t(x)], current=0))
        panel.add_collected(*MP.collect_local([y]))
        panel.save_state()
        assert _paths(state) == [a, b, x, y]
        # axross-amp removes b meanwhile: that sticks at axross's next saves.
        _write(state, _st([_t(a), _t(x), _t(y)], current=0))
        panel.save_state()
        assert _paths(state) == [a, x, y]
    finally:
        panel.shutdown()
    assert _paths(state) == [a, x, y]


# -- the order is part of the merge (review 16, M7) ---------------------------------------


def test_happy_a_reorder_in_one_program_survives_an_edit_in_the_other():
    base = _st([_t("/m/1"), _t("/m/2"), _t("/m/3")])
    # 3 moved to the top in axross; X added in axross-amp (the file)
    own = _st([_t("/m/3"), _t("/m/1"), _t("/m/2")])
    stored = _st([_t("/m/1"), _t("/m/2"), _t("/m/3"), _t("/m/x")])
    assert _paths(MP.merge_shared_state(own, stored, base)) == ["/m/3", "/m/1", "/m/2", "/m/x"]
    # 3 moved to the top in axross-amp; Y added in axross
    own = _st([_t("/m/1"), _t("/m/2"), _t("/m/3"), _t("/m/y")])
    stored = _st([_t("/m/3"), _t("/m/1"), _t("/m/2")])
    assert _paths(MP.merge_shared_state(own, stored, base)) == ["/m/3", "/m/1", "/m/2", "/m/y"]


def test_happy_each_copy_of_a_track_is_an_entry_of_its_own():
    # a second 1 added in axross-amp, Y in axross: both
    base = _st([_t("/m/1"), _t("/m/2")])
    own = _st([_t("/m/1"), _t("/m/2"), _t("/m/y")])
    stored = _st([_t("/m/1"), _t("/m/2"), _t("/m/1")])
    assert _paths(MP.merge_shared_state(own, stored, base)) == ["/m/1", "/m/2", "/m/1", "/m/y"]
    # the second of two 1s removed in axross-amp, Y added in axross: it stays out
    base = _st([_t("/m/1"), _t("/m/2"), _t("/m/1")])
    own = _st([_t("/m/1"), _t("/m/2"), _t("/m/1"), _t("/m/y")])
    stored = _st([_t("/m/1"), _t("/m/2")])
    assert _paths(MP.merge_shared_state(own, stored, base)) == ["/m/1", "/m/2", "/m/y"]


def test_happy_panel_a_track_not_there_at_the_start_stays_in_the_shared_list(tmp_path):
    # review 16, M8: a track on a drive not mounted when axross starts was
    # taken out for good - axross-amp followed
    a, b = _songs(tmp_path, "a.mp3", "b.mp3")
    gone = str(tmp_path / "unmounted" / "c.mp3")
    state = tmp_path / "media_player.json"
    _write(state, _st([_t(a), _t(b), _t(gone, "C")], current=0))
    panel = _panel(state)
    try:
        assert [panel.playlist.item(n).data(MP._PATH_ROLE)
                for n in range(panel.playlist.count())] == [a, b, gone]
        assert panel.playlist.item(2).data(MP._MISSING_ROLE)
        panel.save_state()
        assert _paths(state) == [a, b, gone]
        # axross-amp adds a track meanwhile: still there
        x, = _songs(tmp_path, "x.mp3")
        _write(state, _st([_t(a), _t(b), _t(gone, "C"), _t(x)], current=0))
        panel.save_state()
        assert _paths(state) == [a, b, gone, x]
        # played while missing: skipped, kept; the drive back: it plays
        panel.play_item(panel.playlist.item(2))
        assert panel.playlist.item(2).data(MP._PATH_ROLE) == gone  # kept
        (tmp_path / "unmounted").mkdir()
        (tmp_path / "unmounted" / "c.mp3").write_bytes(b"x")
        panel.play_item(panel.playlist.item(2))
        assert not panel.playlist.item(2).data(MP._MISSING_ROLE)
    finally:
        panel.shutdown()
    assert gone in _paths(state)
