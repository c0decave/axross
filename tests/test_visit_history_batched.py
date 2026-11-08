"""record_visit queues the visit; flush writes the queued ones at once.

Measured 2026-11-08: every mutating script call (copy, move, write ...)
read and rewrote the whole visit_history.json - 0.5 MB with a full
history, 95 ms per call. Now :func:`core.visit_history.flush` (a timer,
at exit, before clear) reads the file once under the lock, applies every
queued visit to what is on disk - so a peer process's visits stay - and
writes once. The counts below are of reads and replacements of the file.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core import visit_history as VH  # noqa: E402


class _Writes:
    """Counts the replacements of the history file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.count = 0

    def __enter__(self):
        replace = VH.os.replace

        def counted(src, dst, *a, **kw):
            if Path(dst) == self.path:
                self.count += 1
            return replace(src, dst, *a, **kw)

        self._patch = mock.patch.object(VH.os, "replace", counted)
        self._patch.start()
        return self

    def __exit__(self, *exc) -> None:
        self._patch.stop()


def _stored(path: Path) -> dict[str, dict]:
    return {f"{e['protocol']}://{e['username']}@{e['host']}": e
            for e in json.loads(path.read_text(encoding="utf-8"))}


class BatchedVisitsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "visit_history.json"
        patcher = mock.patch.object(VH, "HISTORY_FILE", self.path)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(VH.flush)  # nothing of this test is left queued

    # -- happy -----------------------------------------------------------------

    def test_happy_fifty_visits_are_one_write_and_seen_at_once(self) -> None:
        with _Writes(self.path) as writes:
            for i in range(50):
                VH.record_visit("sftp", "box", "alice", path=f"/srv/{i}", verb="copy",
                                desc=f"copy {i}")
            self.assertEqual(writes.count, 0)
            visit = VH.where_was_i("box")  # the queued visits count
            self.assertEqual((visit.visit_count, visit.last_path), (50, "/srv/49"))
            self.assertEqual(len(visit.recent_ops), VH.MAX_OPS_PER_HOST)
            self.assertTrue(VH.flush())
            self.assertEqual(writes.count, 1)
            self.assertTrue(VH.flush())  # nothing queued: nothing written
            self.assertEqual(writes.count, 1)
        stored = _stored(self.path)["sftp://alice@box"]
        self.assertEqual((stored["visit_count"], stored["recent_ops"][0]["desc"]), (50, "copy 49"))
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_happy_the_timer_writes_them_by_itself(self) -> None:
        with mock.patch.object(VH, "FLUSH_DELAY_S", 0.05):
            VH.record_visit("sftp", "timed", "u")
        end = time.monotonic() + 30
        while not self.path.exists():
            self.assertLess(time.monotonic(), end, "the timer never wrote")
            time.sleep(0.01)
        self.assertIn("sftp://u@timed", _stored(self.path))

    def test_happy_a_normal_exit_writes_what_is_queued(self) -> None:
        code = (
            "import sys; sys.path.insert(0, sys.argv[1])\n"
            "from pathlib import Path\n"
            "from core import visit_history as VH\n"
            "VH.HISTORY_FILE = Path(sys.argv[2])\n"
            "VH.FLUSH_DELAY_S = 3600\n"
            "VH.record_visit('sftp', 'at-exit', 'u', path='/x', verb='write', desc='w')\n"
        )
        env = dict(os.environ, HOME=self.tmp.name)
        subprocess.run([sys.executable, "-c", code, str(ROOT), str(self.path)],
                       check=True, env=env, timeout=120)
        self.assertEqual(_stored(self.path)["sftp://u@at-exit"]["last_path"], "/x")

    # -- sad -------------------------------------------------------------------

    def test_sad_a_peer_process_s_visits_written_meanwhile_stay(self) -> None:
        VH.record_visit("sftp", "mine", "u")
        peer = [{"protocol": "sftp", "host": "peer", "username": "u", "last_seen": time.time(),
                 "visit_count": 3, "recent_ops": []}]
        self.path.write_text(json.dumps(peer), encoding="utf-8")  # another axross wrote
        self.assertTrue(VH.flush())
        stored = _stored(self.path)
        self.assertEqual(set(stored), {"sftp://u@mine", "sftp://u@peer"})
        self.assertEqual(stored["sftp://u@peer"]["visit_count"], 3)

    def test_sad_a_failed_write_keeps_the_visits_queued(self) -> None:
        VH.record_visit("sftp", "kept", "u")
        with mock.patch.object(VH, "_save", side_effect=OSError("disk full")):
            self.assertFalse(VH.flush())
        self.assertIsNotNone(VH.where_was_i("kept"))
        VH.record_visit("sftp", "later", "u")
        self.assertTrue(VH.flush())
        self.assertEqual(set(_stored(self.path)), {"sftp://u@kept", "sftp://u@later"})

    def test_sad_a_file_rewritten_in_place_at_the_same_size_is_read_again(self) -> None:
        """The parsed file is reused only while its bytes are the same -
        not by time stamps, which such a rewrite need not change."""
        entry = {"protocol": "sftp", "host": "aaaa", "username": "u", "last_seen": 1.0}
        self.path.write_text(json.dumps([entry]), encoding="utf-8")
        self.assertEqual([v.host for v in VH.where_was_i()], ["aaaa"])
        entry["host"] = "bbbb"
        self.path.write_text(json.dumps([entry]), encoding="utf-8")
        self.assertEqual([v.host for v in VH.where_was_i()], ["bbbb"])

    # -- edge ------------------------------------------------------------------

    def test_edge_many_queued_visits_are_written_without_waiting(self) -> None:
        with mock.patch.object(VH, "FLUSH_AT_PENDING", 10), \
                mock.patch.object(VH, "FLUSH_DELAY_S", 3600), _Writes(self.path) as writes:
            for i in range(10):
                VH.record_visit("sftp", f"h{i}", "u")
            self.assertEqual(writes.count, 1)
        self.assertEqual(len(_stored(self.path)), 10)

    def test_edge_clear_takes_the_queued_visits_with_it(self) -> None:
        VH.record_visit("sftp", "a", "u")
        VH.record_visit("sftp", "b", "u")
        self.assertEqual(VH.clear("a"), 1)  # queued "a" counted and dropped
        self.assertEqual(set(_stored(self.path)), {"sftp://u@b"})  # queued "b" written
        VH.record_visit("sftp", "c", "u")
        self.assertEqual(VH.clear(), 2)
        self.assertFalse(self.path.exists())
        self.assertEqual(VH.where_was_i(), [])

    def test_edge_a_new_history_file_gets_none_of_the_old_one_s_visits(self) -> None:
        VH.record_visit("sftp", "old-file", "u")
        other = Path(self.tmp.name) / "other.json"
        with mock.patch.object(VH, "HISTORY_FILE", other):
            self.assertIsNone(VH.where_was_i("old-file"))
            VH.record_visit("sftp", "new-file", "u")
            self.assertTrue(VH.flush())
            self.assertEqual(set(_stored(other)), {"sftp://u@new-file"})
        self.assertFalse(self.path.exists())

    def test_edge_the_returned_visits_are_copies(self) -> None:
        VH.record_visit("sftp", "copy", "u", verb="get", desc="x")
        VH.flush()
        VH.where_was_i("copy").recent_ops.clear()
        self.assertEqual(len(VH.where_was_i("copy").recent_ops), 1)


if __name__ == "__main__":
    unittest.main()
