"""A bookmarks.json written by a newer axross survives an older one's edit.

Measured before: a bookmark of a kind this version does not know (say a
newer version's ``"rdp"``) was loaded as a folder and saved back as one -
the newer version then opened it as a folder. Fields this version does not
know (on a bookmark or a group) were dropped by the next save. Entries that
could not be loaded at all (not a mapping, a name that is no string, a group
nested deeper than 16) were dropped without a copy kept anywhere.

Now unknown kinds and fields go through load, the three-way merge and save
verbatim, and a file holding entries that cannot be kept is copied aside as
``bookmarks.json.unreadable-<time>-<id>`` before a save replaces it.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import bookmarks as BM  # noqa: E402

_NEWER = [
    {
        "name": "desk",
        "path": "/",
        "backend_name": "rdp.example:3389",
        "profile_name": "",
        "kind": "rdp",
        "host": "rdp.example",
        "port": 3389,
        "resolution": [1920, 1080],
    },
    {
        "name": "home",
        "path": "/home",
        "backend_name": "Local",
        "pinned_at": 12.5,
        "tags": {"colour": "blue"},
    },
    {
        "type": "group",
        "name": "work",
        "sort_mode": "age",
        "children": [
            {"name": "logs", "path": "/var/log", "backend_name": "Local", "badge": "x"}
        ],
    },
]


@pytest.fixture()
def store(tmp_path):
    file = tmp_path / "bookmarks.json"
    with mock.patch.object(BM, "BOOKMARKS_FILE", file):
        yield file


def _set_aside(file: Path) -> list[Path]:
    return sorted(file.parent.glob("bookmarks.json.unreadable-*"))


def _by_name(nodes: list) -> dict:
    out = {}
    for item in nodes:
        out[item["name"]] = item
        if item.get("type") == "group":
            out.update(_by_name(item["children"]))
    return out


def test_happy_unknown_kind_and_fields_survive_an_unrelated_edit(store):
    store.write_text(json.dumps(_NEWER), encoding="utf-8")
    mgr = BM.BookmarkManager()
    mgr.add(BM.Bookmark(name="tmp", path="/tmp"))

    saved = _by_name(json.loads(store.read_text(encoding="utf-8")))
    desk = saved["desk"]
    assert desk["kind"] == "rdp"
    assert desk["host"] == "rdp.example"
    assert desk["port"] == 3389
    assert desk["resolution"] == [1920, 1080]
    assert saved["home"]["pinned_at"] == 12.5
    assert saved["home"]["tags"] == {"colour": "blue"}
    assert saved["work"]["sort_mode"] == "age"
    assert saved["logs"]["badge"] == "x"
    assert "tmp" in saved
    assert _set_aside(store) == []


def test_happy_an_edit_of_an_unknown_kind_keeps_kind_and_fields(store):
    import dataclasses

    store.write_text(json.dumps(_NEWER), encoding="utf-8")
    mgr = BM.BookmarkManager()
    desk = next(b for b in mgr.all() if b.name == "desk")
    mgr.update_bookmark(desk, dataclasses.replace(desk, name="desk 2"))

    saved = _by_name(json.loads(store.read_text(encoding="utf-8")))
    assert saved["desk 2"]["kind"] == "rdp"
    assert saved["desk 2"]["resolution"] == [1920, 1080]


def test_happy_the_merge_keeps_what_the_newer_writer_added(store):
    store.write_text("[]", encoding="utf-8")
    mgr = BM.BookmarkManager()  # an older window, open meanwhile
    store.write_text(json.dumps(_NEWER), encoding="utf-8")  # the newer one saves
    mgr.add(BM.Bookmark(name="tmp", path="/tmp"))

    saved = _by_name(json.loads(store.read_text(encoding="utf-8")))
    assert saved["desk"]["kind"] == "rdp"
    assert saved["desk"]["resolution"] == [1920, 1080]
    assert saved["home"]["tags"] == {"colour": "blue"}
    assert saved["work"]["sort_mode"] == "age"
    assert saved["logs"]["badge"] == "x"


def test_happy_the_merge_takes_their_edit_of_an_unknown_field(store):
    store.write_text(json.dumps(_NEWER), encoding="utf-8")
    mgr = BM.BookmarkManager()
    changed = json.loads(json.dumps(_NEWER))
    changed[1]["tags"] = {"colour": "green"}
    changed[2]["sort_mode"] = "name"
    store.write_text(json.dumps(changed), encoding="utf-8")
    mgr.add(BM.Bookmark(name="tmp", path="/tmp"))

    saved = _by_name(json.loads(store.read_text(encoding="utf-8")))
    assert saved["home"]["tags"] == {"colour": "green"}
    assert saved["work"]["sort_mode"] == "name"


def test_happy_unknown_kind_is_not_a_duplicate_of_a_folder(store):
    store.write_text(json.dumps(_NEWER[:1]), encoding="utf-8")
    mgr = BM.BookmarkManager()
    assert mgr.add(BM.Bookmark(name="root", path="/", backend_name="rdp.example:3389"))
    assert len(mgr.all()) == 2


def test_sad_malformed_entries_are_kept_aside_before_the_save(store):
    raw = json.dumps(
        [
            {"name": "good", "path": "/srv"},
            "not a mapping",
            {"name": 7, "path": "/x"},
            {"type": "group", "name": None, "children": []},
        ]
    ).encode("utf-8")
    store.write_bytes(raw)
    mgr = BM.BookmarkManager()
    assert [b.name for b in mgr.all()] == ["good"]
    assert _set_aside(store) == []  # reading alone copies nothing
    mgr.add(BM.Bookmark(name="tmp", path="/tmp"))

    kept = _set_aside(store)
    assert len(kept) == 1
    assert kept[0].read_bytes() == raw
    assert kept[0].stat().st_mode & 0o777 == 0o600
    # The next save has nothing left to lose: no second copy.
    mgr.add(BM.Bookmark(name="tmp2", path="/tmp2"))
    assert len(_set_aside(store)) == 1


def test_sad_groups_nested_too_deep_are_kept_aside(store):
    leaf: dict = {"name": "deep", "path": "/deep"}
    for depth in range(20):
        leaf = {"type": "group", "name": f"g{depth}", "children": [leaf]}
    raw = json.dumps([leaf]).encode("utf-8")
    store.write_bytes(raw)
    mgr = BM.BookmarkManager()
    assert all(b.name != "deep" for b in mgr.all())
    mgr.add(BM.Bookmark(name="tmp", path="/tmp"))

    kept = _set_aside(store)
    assert len(kept) == 1
    assert kept[0].read_bytes() == raw


def test_sad_a_newer_writers_malformed_entry_is_kept_aside_at_the_merge(store):
    store.write_text("[]", encoding="utf-8")
    mgr = BM.BookmarkManager()
    raw = json.dumps([{"name": "x", "path": ["not", "a", "path"]}]).encode("utf-8")
    store.write_bytes(raw)
    mgr.add(BM.Bookmark(name="tmp", path="/tmp"))

    kept = _set_aside(store)
    assert len(kept) == 1
    assert kept[0].read_bytes() == raw


def test_sad_an_unknown_field_nested_too_deep_is_kept_aside_not_saved(store):
    deep: object = 1
    for _ in range(60):
        deep = [deep]
    raw = json.dumps([{"name": "a", "path": "/a", "blob": deep}]).encode("utf-8")
    store.write_bytes(raw)
    mgr = BM.BookmarkManager()
    mgr.add(BM.Bookmark(name="tmp", path="/tmp"))

    saved = json.loads(store.read_text(encoding="utf-8"))
    assert [item["name"] for item in saved] == ["a", "tmp"]
    assert "blob" not in saved[0]
    assert len(_set_aside(store)) == 1


def test_sad_no_save_when_the_copy_cannot_be_made(store):
    raw = json.dumps([{"name": "good", "path": "/srv"}, 5]).encode("utf-8")
    store.write_bytes(raw)
    mgr = BM.BookmarkManager()
    failures = []
    with mock.patch("core.bookmarks.keep_unreadable_copy", return_value=False), mock.patch(
        "core.json_store.report_save_failure", lambda what, exc: failures.append(what)
    ):
        mgr.add(BM.Bookmark(name="tmp", path="/tmp"))
    assert store.read_bytes() == raw
    assert failures == ["bookmarks"]


def test_happy_a_script_built_unknown_kind_is_still_a_folder(store):
    mgr = BM.BookmarkManager()
    mgr.add(BM.Bookmark(name="x", path="/x", kind="bogus"))
    assert json.loads(store.read_text(encoding="utf-8"))[0]["kind"] == "folder"


def test_sad_a_file_replaced_after_a_failed_read_is_not_set_aside(store, monkeypatch):
    """Two windows: this one reads a broken file, the other sets it aside and
    saves a good one before this one sets it aside - the good one stayed."""
    store.write_bytes(b"[{broken")
    real_loads = json.loads
    calls = {"n": 0}

    def loads_then_other_window(text, *args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            store.rename(store.with_name("bookmarks.json.unreadable-other"))
            store.write_text(json.dumps([{"name": "theirs", "path": "/t"}]), encoding="utf-8")
        return real_loads(text, *args, **kwargs)

    monkeypatch.setattr(BM.json, "loads", loads_then_other_window)
    mgr = BM.BookmarkManager()
    monkeypatch.setattr(BM.json, "loads", real_loads)
    assert [b.name for b in mgr.all()] == ["theirs"]
    assert [p.name for p in _set_aside(store)] == ["bookmarks.json.unreadable-other"]


def _chain(mgr, levels):
    parent = None
    for depth in range(levels):
        parent = mgr.add_group(f"g{depth}", parent=parent)
    return parent


def test_happy_groups_16_deep_survive_a_restart(store):
    mgr = BM.BookmarkManager()
    deepest = _chain(mgr, 16)
    mgr.add(BM.Bookmark(name="deep", path="/deep"), group=deepest)
    again = BM.BookmarkManager()
    assert [b.name for b in again.all()] == ["deep"]
    assert len(again.groups()) == 16


def test_sad_a_group_17_deep_is_refused_not_lost_at_the_next_start(store):
    """The sidebar could make one (New Group, a drop into a group), and the
    next start dropped it with everything in it."""
    mgr = BM.BookmarkManager()
    deepest = _chain(mgr, 16)
    with pytest.raises(ValueError):
        mgr.add_group("g16", parent=deepest)
    pair = mgr.add_group("top")
    mgr.add_group("inner", parent=pair)
    mgr.add(BM.Bookmark(name="kept", path="/kept"), group=pair.children[0])
    level15 = mgr.parent_of(deepest)
    with pytest.raises(ValueError):
        mgr.move(pair, level15)
    with pytest.raises(ValueError):
        mgr.move_nodes([pair], deepest)
    mgr.move_nodes([pair], mgr.parent_of(level15))  # 14 + 2 levels: fits
    again = BM.BookmarkManager()
    assert "kept" in [b.name for b in again.all()]
    assert _set_aside(store) == []
