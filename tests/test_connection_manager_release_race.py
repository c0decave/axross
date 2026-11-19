"""ConnectionManager.release racing a reconnect never closes another pane's
live session.

Reproduced 2026-11-19 (independent review): release() took the pane's
reference out of ``_held`` in one locked section and decremented the
count in a second one. A connect() in between - the link had dropped, a
second profile to the same server connected and replaced the dead session
under the same key - made the release decrement and close the NEW session,
which the other pane held. Now the reference is taken and the count
decremented in one locked section, and only while the session it holds is
still the registered one.
"""

from __future__ import annotations

import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.connection_manager import ConnectionManager  # noqa: E402
from core.profiles import ConnectionProfile  # noqa: E402


class Fake:
    made = 0

    def __init__(self):
        Fake.made += 1
        self.id = Fake.made
        self.connected = True
        self.closed = False

    def disconnect(self):
        self.closed = True
        self.connected = False


class HookLock:
    """A real lock that runs *hook* once, right after its n-th release:
    what another thread does at exactly that moment."""

    def __init__(self):
        self._lock = threading.RLock()
        self.exits = 0
        self.hook_at = None
        self.hook = None

    def __enter__(self):
        self._lock.acquire()
        return self

    def __exit__(self, *exc):
        self._lock.release()
        self.exits += 1
        if self.hook_at == self.exits and self.hook:
            hook, self.hook = self.hook, None
            hook()


def _manager(unenrolled: list):
    cm = ConnectionManager()
    cm._create_session = lambda *a, **k: Fake()
    cm._enroll_health = staticmethod(lambda *a, **k: None)
    cm._unenroll_health = staticmethod(lambda key: unenrolled.append(key))
    cm._record_visit = staticmethod(lambda *a, **k: None)
    lock = HookLock()
    cm._lock = lock
    return cm, lock


def _profiles():
    return (ConnectionProfile(name="A", protocol="sftp", host="h", username="u"),
            ConnectionProfile(name="B", protocol="sftp", host="h", username="u"))


def test_sad_a_reconnect_after_the_take_does_not_close_the_new_session():
    unenrolled: list = []
    cm, lock = _manager(unenrolled)
    pa, pb = _profiles()
    s1 = cm.connect(pa)
    replaced = {}

    def other_pane_reconnects():
        s1.connected = False  # the link dropped
        replaced["s2"] = cm.connect(pb)

    lock.hook_at = lock.exits + 1  # after release()'s first locked section
    lock.hook = other_pane_reconnects
    cm.release(pa)
    s2 = replaced["s2"]
    assert s2 is not s1
    assert not s2.closed, "pane B's live session was disconnected by pane A's release"
    assert cm.get_session(pb) is s2
    assert s1.closed  # pane A's own session, no references left, is closed
    # The key's health enrolment belongs to the session that replaced it.
    assert unenrolled == []


def test_happy_the_last_release_closes_the_session():
    unenrolled: list = []
    cm, _lock = _manager(unenrolled)
    pa, _pb = _profiles()
    s1 = cm.connect(pa)
    cm.release(pa)
    assert s1.closed
    assert cm.get_session(pa) is None
    assert len(unenrolled) == 1


def test_edge_a_shared_session_stays_until_its_last_holder_goes():
    unenrolled: list = []
    cm, _lock = _manager(unenrolled)
    pa, pb = _profiles()
    s1 = cm.connect(pa)
    assert cm.connect(pb) is s1  # the same server: shared
    cm.release(pa)
    assert not s1.closed
    cm.release(pb)
    assert s1.closed
