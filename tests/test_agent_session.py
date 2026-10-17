"""Agent tabs as sessions: one simple JSON file per tab (core.agent_session)."""

from __future__ import annotations

import json
import stat

from core import agent_session as AS


def _session(**kw):
    s = AS.AgentSession(title="Disk report", folder="~", mode="plan", sandbox="Normal",
                        groups=["metadata"], extra_folders=[("/srv/data", False)], **kw)
    s.transcript.append({"who": "You:", "text": "how full is /srv?", "muted": False})
    s.messages.append({"role": "user", "content": "how full is /srv?"})
    return s


# -- happy ---------------------------------------------------------------------


def test_happy_a_session_round_trips_through_its_file(tmp_path):
    store = AS.SessionStore(tmp_path / "sessions")
    session = _session()
    store.save(session)
    path = store.path(session.id)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    data = json.loads(path.read_text())
    assert data["version"] == 1 and data["extra_folders"] == [{"path": "/srv/data", "mode": "ro"}]
    back = store.load(session.id)
    assert back.to_dict() == session.to_dict()


def test_happy_all_sessions_come_back_in_tab_order(tmp_path):
    store = AS.SessionStore(tmp_path)
    first, second = _session(created="2026-01-01T00:00:00"), _session(created="2026-02-01T00:00:00")
    store.save(second)
    store.save(first)
    assert [s.id for s in store.all()] == [first.id, second.id]


# -- sad -----------------------------------------------------------------------


def test_sad_broken_files_are_skipped(tmp_path):
    store = AS.SessionStore(tmp_path)
    good = _session()
    store.save(good)
    (tmp_path / ("a" * 32 + ".json")).write_text("{broken")
    (tmp_path / ("b" * 32 + ".json")).write_text(json.dumps({"id": "not-an-id"}))
    (tmp_path / "notes.json").write_text("{}")
    assert [s.id for s in store.all()] == [good.id]


def test_sad_a_session_id_is_never_a_path(tmp_path):
    store = AS.SessionStore(tmp_path)
    for bad in ("../x", "a" * 31, "A" * 32, "x" * 32):
        assert store.load(bad) is None
    try:
        store.path("../../etc/passwd")
    except ValueError:
        pass
    else:
        raise AssertionError("a path was accepted as a session id")


def test_sad_wrong_types_take_defaults():
    s = AS.AgentSession.from_dict(
        {
            "id": "c" * 32,
            "mode": "yolo",
            "allow_write": "yes",
            "groups": ["a", 3],
            "extra_folders": [{"path": "rel"}, "x"],
            "transcript": ["x", {"who": "A", "text": 5}],
            "messages": [{"x": 1}],
        }
    )
    assert s.mode == "ask" and s.allow_write is False
    assert s.groups == ["a"] and s.extra_folders == []
    assert s.transcript == [{"who": "A", "text": "5", "muted": False}]
    assert s.messages == []


# -- edge ----------------------------------------------------------------------


def test_edge_deleting_a_session_removes_its_file_only(tmp_path):
    store = AS.SessionStore(tmp_path)
    a, b = _session(), _session()
    store.save(a)
    store.save(b)
    store.delete(a.id)
    store.delete(a.id)  # twice is fine
    assert [s.id for s in store.all()] == [b.id]


def test_edge_an_oversized_file_is_not_read(tmp_path, monkeypatch):
    store = AS.SessionStore(tmp_path)
    s = _session()
    store.save(s)
    monkeypatch.setattr(AS, "MAX_FILE_BYTES", 10)
    assert store.load(s.id) is None


def test_edge_a_missing_folder_has_no_sessions(tmp_path):
    assert AS.SessionStore(tmp_path / "nope").all() == []


def test_edge_sessions_made_within_one_second_keep_their_order(tmp_path):
    store = AS.SessionStore(tmp_path)
    made = [AS.AgentSession(title=str(n)) for n in range(20)]
    for session in reversed(made):
        store.save(session)
    assert [s.id for s in store.all()] == [s.id for s in made]
