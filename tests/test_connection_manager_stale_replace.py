"""A stale session that gets replaced keeps its own references.

Found in review: when a session under one key went stale and a new
connect() replaced it, the references the old holders still had were
counted against the NEW session (both live under the same key). The
first old holder to close its pane then disconnected the live session
another pane was using, and the dead one was never closed.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.connection_manager import ConnectionManager  # noqa: E402
from core.profiles import ConnectionProfile  # noqa: E402


class _FakeSession:
    def __init__(self) -> None:
        self.connected = True
        self.disconnects = 0

    def disconnect(self) -> None:
        self.disconnects += 1
        self.connected = False


def _manager() -> ConnectionManager:
    cm = ConnectionManager()
    cm._create_session = lambda *a, **k: _FakeSession()
    cm._enroll_health = lambda *a, **k: None
    cm._unenroll_health = lambda *a, **k: None
    cm._record_visit = lambda *a, **k: None
    return cm


def _profile(name: str = "srv") -> ConnectionProfile:
    return ConnectionProfile(name=name, protocol="sftp", host="example.invalid", username="u")


class StaleSessionReplaceTest(unittest.TestCase):
    def test_happy_closing_the_dead_pane_keeps_the_new_session(self) -> None:
        cm = _manager()
        profile = _profile()
        old = cm.connect(profile)  # pane A
        old.connected = False  # its link drops
        new = cm.connect(profile)  # pane B opens the same profile
        self.assertIsNot(new, old)

        cm.release(profile)  # pane A (dead) closes

        self.assertTrue(new.connected)
        self.assertEqual(new.disconnects, 0)
        self.assertIs(cm.get_session(profile), new)
        self.assertEqual(old.disconnects, 1)  # the dead one is closed now

        cm.release(profile)  # pane B closes
        self.assertEqual(new.disconnects, 1)
        self.assertEqual(cm.active_sessions(), [])

    def test_happy_terminal_reference_on_old_session_stays_with_it(self) -> None:
        cm = _manager()
        profile = _profile()
        old = cm.connect(profile)  # file pane
        self.assertTrue(cm.acquire(profile))  # terminal pane beside it
        old.connected = False
        new = cm.connect(profile)  # file pane auto-reconnect
        cm.release(profile)  # the file pane gives back its old reference

        cm.release(profile)  # the dead terminal pane closes
        self.assertTrue(new.connected)
        self.assertEqual(new.disconnects, 0)
        self.assertEqual(old.disconnects, 1)

        cm.release(profile)  # the file pane closes
        self.assertEqual(new.disconnects, 1)

    def test_sad_extra_release_does_not_touch_an_unrelated_session(self) -> None:
        cm = _manager()
        profile = _profile()
        other = _profile("other")
        other.host = "other.invalid"
        live = cm.connect(other)
        cm.release(profile)  # never connected: nothing to give back
        self.assertTrue(live.connected)
        self.assertEqual(live.disconnects, 0)

    def test_edge_old_session_closed_only_after_its_last_holder(self) -> None:
        cm = _manager()
        profile = _profile()
        old = cm.connect(profile)
        self.assertTrue(cm.acquire(profile))  # two references on the old one
        old.connected = False
        new = cm.connect(profile)

        cm.release(profile)
        self.assertEqual(old.disconnects, 0)  # one holder left
        cm.release(profile)
        self.assertEqual(old.disconnects, 1)
        self.assertTrue(new.connected)

    def test_edge_disconnect_all_closes_replaced_sessions_too(self) -> None:
        cm = _manager()
        profile = _profile()
        old = cm.connect(profile)
        old.connected = False
        new = cm.connect(profile)
        cm.disconnect_all()
        self.assertEqual(old.disconnects, 1)
        self.assertEqual(new.disconnects, 1)
        cm.release(profile)  # a late release after shutdown is harmless
        self.assertEqual(old.disconnects, 1)


if __name__ == "__main__":
    unittest.main()


def test_edge_disconnect_all_closes_in_parallel_and_never_waits_past_its_bound():
    """Quitting disconnected every session one after the other: a dead
    link held the exit for its whole timeout, and each further session for
    its own. They close together now, waited for up to a bound."""
    import threading
    import time

    from core.connection_manager import ConnectionManager

    started: list[float] = []
    closed: list[str] = []

    class Session:
        def __init__(self, name, delay) -> None:
            self.name, self.delay = name, delay

        def disconnect(self):
            started.append(time.monotonic())
            time.sleep(self.delay)
            closed.append(self.name)

    manager = ConnectionManager()
    manager._sessions = {f"k{i}": Session(f"s{i}", 0.3) for i in range(4)}
    manager._sessions["dead"] = Session("dead", 5.0)
    manager._ref_counts = {k: 1 for k in manager._sessions}
    begin = time.monotonic()
    manager.disconnect_all(timeout=1.0)
    took = time.monotonic() - begin
    assert sorted(closed) == ["s0", "s1", "s2", "s3"]  # the live ones are closed
    assert took < 2.0  # not 0.3 * 4 + 5 s
    assert max(started) - min(started) < 0.25  # together, not in turn
    assert manager._sessions == {}
    assert threading.active_count() >= 1
