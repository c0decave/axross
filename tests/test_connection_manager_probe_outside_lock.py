"""The connection manager never asks a session whether it is alive while
it holds its lock.

Found in review: ``session.connected`` is network I/O for several
backends (an SMB listdir, a WebDAV PROPFIND, an FTP NOOP). connect()
evaluated it under the manager-wide lock, so a background connect to a
server that stopped answering held the lock for the whole I/O timeout,
and the GUI thread's release() of an unrelated pane waited for it.
"""

from __future__ import annotations

import sys
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.connection_manager import ConnectionManager  # noqa: E402
from core.profiles import ConnectionProfile  # noqa: E402


class _HungProbe:
    """A session whose liveness probe blocks until *gate* opens."""

    def __init__(self, gate: threading.Event, entered: threading.Event, alive: bool) -> None:
        self._gate = gate
        self._entered = entered
        self._alive = alive
        self.closed = 0

    @property
    def connected(self) -> bool:
        self._entered.set()
        self._gate.wait(2)
        return self._alive

    def close(self) -> None:
        self.closed += 1


class _Plain:
    connected = True

    def __init__(self) -> None:
        self.closed = 0

    def close(self) -> None:
        self.closed += 1


def _manager() -> ConnectionManager:
    cm = ConnectionManager()
    cm._enroll_health = lambda *a, **k: None
    cm._unenroll_health = lambda *a, **k: None
    cm._record_visit = lambda *a, **k: None
    return cm


def _profiles() -> tuple[ConnectionProfile, ConnectionProfile]:
    nas = ConnectionProfile(name="nas", protocol="smb", host="nas", username="u", smb_share="s")
    web = ConnectionProfile(name="web", protocol="sftp", host="web", username="u")
    return nas, web


class ProbeOutsideLockTest(unittest.TestCase):
    def _run_blocked_reuse(self, alive: bool):
        cm = _manager()
        nas, web = _profiles()
        gate, entered = threading.Event(), threading.Event()
        hung = _HungProbe(gate, entered, alive)
        cm._create_session = lambda prof, *a, **k: hung if prof.protocol == "smb" else _Plain()
        cm.connect(nas)  # registered without probing
        cm.connect(web)
        replacement = _Plain()
        cm._create_session = lambda *a, **k: replacement
        result: list = []
        worker = threading.Thread(target=lambda: result.append(cm.connect(nas)), daemon=True)
        worker.start()
        self.assertTrue(entered.wait(5), "the reuse never probed the session")
        start = time.monotonic()
        cm.release(web)  # an unrelated pane closes while the probe hangs
        elapsed = time.monotonic() - start
        gate.set()
        worker.join(10)
        return cm, nas, hung, replacement, result, elapsed

    def test_happy_unrelated_release_does_not_wait_for_a_hung_probe(self) -> None:
        _cm, _nas, _hung, _replacement, _result, elapsed = self._run_blocked_reuse(alive=True)
        self.assertLess(elapsed, 1.0)

    def test_sad_stale_after_probe_is_replaced_once(self) -> None:
        cm, nas, hung, replacement, result, _elapsed = self._run_blocked_reuse(alive=False)
        self.assertEqual(result, [replacement])
        self.assertIs(cm._sessions[cm._session_key(nas)], replacement)
        self.assertEqual(cm._ref_counts[cm._session_key(nas)], 1)

    def test_edge_live_after_probe_is_reused_with_one_more_reference(self) -> None:
        cm, nas, hung, _replacement, result, _elapsed = self._run_blocked_reuse(alive=True)
        self.assertEqual(result, [hung])
        self.assertEqual(cm._ref_counts[cm._session_key(nas)], 2)
        cm.release(nas)
        cm.release(nas)
        self.assertEqual(hung.closed, 1)


if __name__ == "__main__":
    unittest.main()
