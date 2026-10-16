"""Which file the worker analyses: local paths as they are, remote files as a
bounded temporary copy, and nothing that is not a regular file."""

from __future__ import annotations

import io
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import file_analysis as FA  # noqa: E402
from core.analysis_worker import WorkerResult  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402


class _FakeWorker:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, bytes | None]] = []
        self.cancelled = 0

    def analyse(self, path, display_name, **kw):
        self.kwargs = kw
        data = None
        if os.path.isfile(path):
            with open(path, "rb") as fh:
                data = fh.read()
        self.calls.append((path, display_name, data))
        summary = {"filename": display_name, "kind": "text", "llm_used": bool(kw.get("llm"))}
        return WorkerResult(True, summary=summary)

    def cancel(self):
        self.cancelled += 1

    def close(self):
        pass


class _RemoteBackend:
    """Reads from a dict; counts opens."""

    name = "Fake SFTP"

    def __init__(self, files: dict[str, bytes]) -> None:
        self.files = files
        self.opened: list[str] = []

    def open_read(self, path):
        self.opened.append(path)
        return io.BytesIO(self.files[path])


def _target(backend, path, data_len, name=None, mtime=1000.0):
    return FA.Target(
        backend=backend, path=path, name=name or os.path.basename(path), size=data_len, mtime=mtime
    )


class FileAnalyzerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.worker = _FakeWorker()
        self.fa = FA.FileAnalyzer(worker=self.worker, max_remote_bytes=1000)

    def _local(self, name, data=b"hello\n"):
        path = os.path.join(self.tmp.name, name)
        with open(path, "wb") as fh:
            fh.write(data)
        return path

    def test_happy_a_local_file_is_analysed_in_place(self) -> None:
        path = self._local("notes.txt")
        res = self.fa.analyse(_target(LocalFS(), path, 6))
        self.assertTrue(res.ok)
        self.assertEqual(self.worker.calls[0][:2], (path, "notes.txt"))

    def test_happy_a_remote_file_is_copied_and_the_copy_removed(self) -> None:
        backend = _RemoteBackend({"/srv/report.csv": b"a,b\n1,2\n"})
        res = self.fa.analyse(_target(backend, "/srv/report.csv", 8))
        self.assertTrue(res.ok, res.error)
        path, name, data = self.worker.calls[0]
        self.assertEqual((name, data), ("report.csv", b"a,b\n1,2\n"))
        self.assertTrue(path.endswith(".csv"))  # the extension survives
        self.assertFalse(os.path.exists(path))
        self.assertFalse(os.path.exists(os.path.dirname(path)))

    def test_happy_a_second_look_comes_from_the_session_cache(self) -> None:
        path = self._local("a.txt")
        t = _target(LocalFS(), path, 6)
        self.fa.analyse(t)
        again = self.fa.analyse(t)
        self.assertTrue(again.ok)
        self.assertTrue(again.from_session_cache)
        self.assertEqual(len(self.worker.calls), 1)
        self.fa.analyse(t, force=True)
        self.assertEqual(len(self.worker.calls), 2)

    def test_sad_a_changed_file_is_analysed_again(self) -> None:
        path = self._local("a.txt")
        self.fa.analyse(_target(LocalFS(), path, 6, mtime=1.0))
        self.fa.analyse(_target(LocalFS(), path, 6, mtime=2.0))
        self.assertEqual(len(self.worker.calls), 2)

    def test_sad_a_large_remote_file_is_not_downloaded(self) -> None:
        backend = _RemoteBackend({"/big.bin": b"x" * 5000})
        res = self.fa.analyse(_target(backend, "/big.bin", 5000))
        self.assertFalse(res.ok)
        self.assertIn("too large", res.error)
        self.assertEqual(backend.opened, [])
        self.assertEqual(self.worker.calls, [])

    def test_sad_a_remote_file_bigger_than_listed_is_cut_off_and_refused(self) -> None:
        backend = _RemoteBackend({"/grew.txt": b"y" * 5000})
        res = self.fa.analyse(_target(backend, "/grew.txt", 10))  # listing said 10 bytes
        self.assertFalse(res.ok)
        self.assertIn("too large", res.error)
        self.assertEqual(self.worker.calls, [])

    def test_sad_local_non_regular_files_are_refused(self) -> None:
        fifo = os.path.join(self.tmp.name, "pipe")
        os.mkfifo(fifo)
        for path in (fifo, self.tmp.name, os.path.join(self.tmp.name, "missing")):
            with self.subTest(path=path):
                res = self.fa.analyse(_target(LocalFS(), path, 0))
                self.assertFalse(res.ok)
        self.assertEqual(self.worker.calls, [])

    def test_sad_a_remote_read_error_is_reported(self) -> None:
        class Broken(_RemoteBackend):
            def open_read(self, path):
                raise PermissionError("denied")

        res = self.fa.analyse(_target(Broken({}), "/x.txt", 3))
        self.assertFalse(res.ok)
        self.assertIn("denied", res.error)

    def test_edge_a_hostile_remote_name_cannot_leave_the_temp_dir(self) -> None:
        backend = _RemoteBackend({"/a": b"z"})
        for name in ("../../etc/passwd", "a/../../b", "..", "", "x\x00y.txt"):
            with self.subTest(name=name):
                self.worker.calls.clear()
                self.fa.analyse(_target(backend, "/a", 1, name=name, mtime=hash(name)))
                path = self.worker.calls[0][0]
                self.assertEqual(os.path.dirname(os.path.dirname(path)), tempfile.gettempdir())
                self.assertNotIn("\x00", path)

    def test_edge_the_session_cache_is_bounded(self) -> None:
        fa = FA.FileAnalyzer(worker=self.worker, session_cache_size=3)
        for i in range(5):
            fa.analyse(_target(LocalFS(), self._local(f"f{i}.txt"), 6))
        self.assertEqual(len(fa._session), 3)


_LLM = {
    "provider": "ollama",
    "endpoint": "http://localhost:11434",
    "model": "m",
    "api_key": "",
    "temperature": 0.2,
    "timeout": 50.0,
    "max_output_tokens": 100,
    "allow_model_load": False,
}


class LLMRequestTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "a.txt")
        with open(self.path, "w") as fh:
            fh.write("hello\n")
        self.worker = _FakeWorker()
        self.fa = FA.FileAnalyzer(worker=self.worker)
        self.t = _target(LocalFS(), self.path, 6)

    def test_happy_the_request_and_events_reach_the_worker(self) -> None:
        seen = []
        self.fa.analyse(self.t, llm=_LLM, on_event=seen.append)
        self.assertEqual(self.worker.kwargs["llm"], _LLM)
        self.assertIs(self.worker.kwargs["on_event"].__self__, seen)
        # No total timeout: the worker bounds the child's silence from the
        # request itself (tests/test_analysis_llm_bound.py).
        self.assertNotIn("timeout", self.worker.kwargs)

    def test_sad_the_heuristic_result_is_not_served_for_an_llm_request(self) -> None:
        self.fa.analyse(self.t)
        res = self.fa.analyse(self.t, llm=_LLM)
        self.assertFalse(res.from_session_cache)
        self.assertEqual(len(self.worker.calls), 2)

    def test_edge_each_model_has_its_own_cached_answer(self) -> None:
        self.fa.analyse(self.t, llm=_LLM)
        self.assertTrue(self.fa.analyse(self.t, llm=dict(_LLM)).from_session_cache)
        self.assertFalse(self.fa.analyse(self.t, llm=dict(_LLM, model="n")).from_session_cache)
        self.assertTrue(self.fa.analyse(self.t, llm=dict(_LLM, api_key="other")).from_session_cache)

    def test_sad_other_generation_settings_are_another_answer(self) -> None:
        self.fa.analyse(self.t, llm=_LLM)
        for change in (
            {"temperature": 1.5},
            {"max_output_tokens": 50},
            {"allow_model_load": True},
            {"provider": "openai"},
            {"endpoint": "http://127.0.0.1:9999"},
        ):
            with self.subTest(change=change):
                self.assertFalse(
                    self.fa.analyse(self.t, llm=dict(_LLM, **change)).from_session_cache
                )

    def test_edge_neither_the_key_nor_the_timeout_splits_the_cache(self) -> None:
        self.fa.analyse(self.t, llm=_LLM)
        n = len(self.worker.calls)
        hit = self.fa.analyse(self.t, llm=dict(_LLM, api_key="other-key", timeout=999.0))
        self.assertTrue(hit.from_session_cache)
        self.assertEqual(len(self.worker.calls), n)
        self.assertNotIn("other-key", repr(list(self.fa._session)))


class ReviewFixesTest(unittest.TestCase):
    """Defects found in review, each reproduced first."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "a.txt")
        with open(self.path, "w") as fh:
            fh.write("hello\n")

    def test_sad_a_fallback_without_the_model_is_not_kept_as_the_models_answer(self) -> None:
        class Fallback(_FakeWorker):
            def analyse(self, path, display_name, **kw):
                super().analyse(path, display_name, **kw)
                return WorkerResult(True, summary={"llm_used": False, "summary": "heuristic"})

        worker = Fallback()
        fa = FA.FileAnalyzer(worker=worker)
        t = _target(LocalFS(), self.path, 6)
        fa.analyse(t, llm=_LLM)
        again = fa.analyse(t, llm=_LLM)
        self.assertFalse(again.from_session_cache)
        self.assertEqual(len(worker.calls), 2)

    def test_sad_cancel_during_a_remote_copy_runs_nothing(self) -> None:
        import threading

        cancel = threading.Event()

        class Slow(_RemoteBackend):
            def open_read(self, path):
                class R:
                    def read(self_, n):
                        cancel.set()  # the user moved on while the copy runs
                        return b"x" * 4

                    def close(self_):
                        pass

                return R()

        worker = _FakeWorker()
        fa = FA.FileAnalyzer(worker=worker, max_remote_bytes=1000)
        res = fa.analyse(_target(Slow({}), "/r.txt", 400), cancel=cancel)
        self.assertFalse(res.ok)
        self.assertIn("cancelled", res.error)
        self.assertEqual(worker.calls, [])

    def test_happy_cancel_reaches_a_copy_in_flight_and_leaves_an_idle_worker(self) -> None:
        import threading

        started = threading.Event()

        class Slow(_RemoteBackend):
            def open_read(self, path):
                class R:
                    def read(self_, n):
                        started.set()
                        threading.Event().wait(0.05)
                        return b"x"

                    def close(self_):
                        pass

                return R()

        worker = _FakeWorker()
        fa = FA.FileAnalyzer(worker=worker, max_remote_bytes=10_000)
        out = {}
        th = threading.Thread(
            target=lambda: out.setdefault("r", fa.analyse(_target(Slow({}), "/s", 5000)))
        )
        th.start()
        started.wait(5)
        fa.cancel()
        th.join(5)
        self.assertIn("cancelled", out["r"].error)
        self.assertEqual(worker.calls, [])
        self.assertEqual(worker.cancelled, 0)  # nothing ran in the worker to cancel

    def test_sad_a_remote_read_that_hangs_does_not_hold_the_lane(self) -> None:
        import threading
        import time

        release = threading.Event()

        class Hang(_RemoteBackend):
            def open_read(self, path):
                class R:
                    def read(self_, n):
                        release.wait(10)
                        return b""

                    def close(self_):
                        pass

                return R()

        fa = FA.FileAnalyzer(worker=_FakeWorker(), copy_timeout=0.5)
        start = time.monotonic()
        res = fa.analyse(_target(Hang({}), "/h.txt", 3))
        self.assertLess(time.monotonic() - start, 5)
        self.assertFalse(res.ok)
        self.assertIn("timed out", res.error)
        release.set()

    def _trickle(self, chunk_seconds: float = 0.03):
        """A backend whose reads are slow but never hang: one byte per read."""
        import threading

        state = {"reads": 0, "closed": False, "tmp": None}
        started = threading.Event()

        class Trickle(_RemoteBackend):
            def open_read(self, path):
                class R:
                    def read(self_, n):
                        started.set()
                        threading.Event().wait(chunk_seconds)
                        state["reads"] += 1
                        return b"x"

                    def close(self_):
                        state["closed"] = True

                return R()

        return Trickle({}), state, started

    def test_sad_a_timed_out_copy_stops_reading_from_the_backend(self) -> None:
        import time

        backend, state, _started = self._trickle()
        fa = FA.FileAnalyzer(worker=_FakeWorker(), max_remote_bytes=100_000, copy_timeout=0.3)
        res = fa.analyse(_target(backend, "/slow.bin", 50_000))
        self.assertIn("timed out", res.error)
        time.sleep(0.15)  # the read in flight when the copy was given up returns
        reads = state["reads"]
        time.sleep(0.4)
        # Given up is given up: the connection is free for the next file.
        self.assertEqual(state["reads"], reads)
        self.assertTrue(state["closed"])

    def test_edge_a_given_up_copy_removes_its_temp_dir(self) -> None:
        import time

        before = set(os.listdir(tempfile.gettempdir()))
        backend, state, _started = self._trickle()
        fa = FA.FileAnalyzer(worker=_FakeWorker(), max_remote_bytes=100_000, copy_timeout=0.2)
        fa.analyse(_target(backend, "/slow.bin", 50_000))
        end = time.monotonic() + 3
        while time.monotonic() < end and not state["closed"]:
            time.sleep(0.02)
        time.sleep(0.05)
        left = {
            n
            for n in set(os.listdir(tempfile.gettempdir())) - before
            if n.startswith("axross-analysis-")
        }
        self.assertEqual(left, set())

    def test_happy_a_slow_copy_within_the_timeout_is_complete(self) -> None:
        backend, state, _started = self._trickle(chunk_seconds=0.001)
        worker = _FakeWorker()
        fa = FA.FileAnalyzer(worker=worker, max_remote_bytes=1000, copy_timeout=10)
        res = fa.analyse(_target(backend, "/slow.bin", 20))
        # The trickle never ends by itself: the copy stops at the limit + 1.
        self.assertIn("too large", res.error)
        self.assertEqual(state["reads"], 1001)

    def test_edge_after_close_nothing_starts(self) -> None:
        worker = _FakeWorker()
        fa = FA.FileAnalyzer(worker=worker)
        fa.close()
        res = fa.analyse(_target(LocalFS(), self.path, 6))
        self.assertFalse(res.ok)
        self.assertEqual(worker.calls, [])

    def test_edge_a_new_backend_at_a_reused_address_gets_no_old_answer(self) -> None:
        from unittest import mock

        fa = FA.FileAnalyzer(worker=_FakeWorker())
        a, b = LocalFS(), LocalFS()
        # Both objects report one address: what CPython does once a is freed.
        with mock.patch.object(FA, "id", lambda obj: 4242, create=True):
            fa.analyse(_target(a, self.path, 6))
            self.assertIsNotNone(fa.cached(_target(a, self.path, 6)))
            self.assertIsNone(fa.cached(_target(b, self.path, 6)))


if __name__ == "__main__":
    unittest.main()
