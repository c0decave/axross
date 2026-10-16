"""The sift worker process: one long-lived child, killed and restarted on a hang.

sift bounds its own work between steps; a hang inside C code (zlib,
sqlite3, Pillow, a regex) is not interrupted. The worker runs sift in a
child process that the parent kills after a wall-clock bound.
"""

from __future__ import annotations

import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import analysis_worker as AW  # noqa: E402


@unittest.skipUnless(AW.sift_available(), "sift is not installed")
class AnalysisWorkerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.worker = AW.AnalysisWorker(cache_dir=None)
        self.addCleanup(self.worker.close)

    def _file(self, name: str, data: bytes) -> str:
        path = os.path.join(self.tmp.name, name)
        with open(path, "wb") as fh:
            fh.write(data)
        return path

    def test_happy_a_csv_is_explained_without_an_llm(self) -> None:
        path = self._file("people.csv", b"name,age\nann,31\nbob,45\n")
        res = self.worker.analyse(path, "people.csv")
        self.assertTrue(res.ok, res.error)
        self.assertEqual(res.summary["kind"], "csv")
        self.assertFalse(res.summary["llm_used"])
        self.assertIn("2 rows", res.summary["summary"])

    def test_happy_the_process_is_reused_between_files(self) -> None:
        a = self._file("a.txt", b"hello\n")
        b = self._file("b.json", b'{"k": 1}')
        self.assertTrue(self.worker.analyse(a, "a.txt").ok)
        pid = self.worker.pid
        self.assertTrue(self.worker.analyse(b, "b.json").ok)
        self.assertEqual(self.worker.pid, pid)

    def test_happy_display_name_is_what_sift_reports(self) -> None:
        path = self._file("tmp123", b"col1,col2\n1,2\n")
        res = self.worker.analyse(path, "report.csv")
        self.assertTrue(res.ok, res.error)
        self.assertEqual(res.summary["filename"], "report.csv")

    def test_sad_a_missing_file_is_an_error_summary_not_a_crash(self) -> None:
        res = self.worker.analyse(os.path.join(self.tmp.name, "nope.txt"), "nope.txt")
        self.assertTrue(res.ok)  # sift answers; the summary carries the error
        self.assertEqual(res.summary["kind"], "error")
        pid = self.worker.pid
        self.assertTrue(self.worker.analyse(self._file("x.txt", b"x"), "x.txt").ok)
        self.assertEqual(self.worker.pid, pid)

    def test_sad_a_fifo_is_refused_without_blocking(self) -> None:
        fifo = os.path.join(self.tmp.name, "pipe.txt")
        os.mkfifo(fifo)
        res = self.worker.analyse(fifo, "pipe.txt", timeout=20.0)
        self.assertTrue(res.ok, res.error)
        self.assertEqual(res.summary["kind"], "error")


#: A child that speaks the protocol and sleeps for a file named "hang*".
#: A key no secret scanner reads as one: the mirror's scrub would rewrite an
#: sk-shaped literal and change what this test asserts.
FAKE_KEY = "fake-api-key-for-tests-0001"

_STUB_CHILD = r"""
import json, os, sys, time
out = os.fdopen(os.dup(1), "wb", buffering=0)
os.dup2(2, 1)
print("stray output that is not a reply")
for raw in sys.stdin.buffer:
    req = json.loads(raw)
    name = os.path.basename(req["path"])
    if name.startswith("hang"):
        time.sleep(3600)
    if name.startswith("die"):
        os._exit(3)
    reply = {"id": req["id"], "ok": True, "summary": {"filename": req["display_name"]},
             "error": "", "from_cache": False, "elapsed": 0.0}
    if name.startswith("bad-elapsed"):
        reply["elapsed"] = "soon"
    if name.startswith("bad-calls"):
        reply["calls"] = 5
    if name.startswith("nested"):
        out.write(b'{"id": %d, "summary": ' % req["id"] + b"[" * 200000 + b"]" * 200000 + b"}\n")
        continue
    out.write(json.dumps(reply).encode() + b"\n")
"""


class WorkerKillTest(unittest.TestCase):
    def setUp(self) -> None:
        self.worker = AW.AnalysisWorker(command=[sys.executable, "-c", _STUB_CHILD])
        self.addCleanup(self.worker.close)

    def test_happy_replies_flow_and_stray_prints_are_not_replies(self) -> None:
        res = self.worker.analyse("/x/a.txt", "a.txt", timeout=10)
        self.assertTrue(res.ok, res.error)
        self.assertEqual(res.summary, {"filename": "a.txt"})

    def test_sad_a_hang_is_killed_and_the_next_file_still_works(self) -> None:
        self.assertTrue(self.worker.analyse("/x/first.txt", "first.txt", timeout=10).ok)
        pid = self.worker.pid
        start = time.monotonic()
        res = self.worker.analyse("/x/hang.txt", "hang.txt", timeout=1.0)
        self.assertLess(time.monotonic() - start, 8)
        self.assertFalse(res.ok)
        self.assertIn("timed out", res.error)
        self.assertIsNone(self.worker.pid)
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)  # really gone
        after = self.worker.analyse("/x/after.txt", "after.txt", timeout=10)
        self.assertTrue(after.ok, after.error)
        self.assertNotEqual(self.worker.pid, pid)

    def test_edge_cancel_from_another_thread_ends_a_running_job(self) -> None:
        import threading

        self.assertTrue(self.worker.analyse("/x/warm.txt", "warm.txt", timeout=10).ok)
        threading.Timer(0.5, self.worker.cancel).start()
        start = time.monotonic()
        res = self.worker.analyse("/x/hang2.txt", "hang2.txt", timeout=60)
        self.assertLess(time.monotonic() - start, 8)
        self.assertFalse(res.ok)
        self.assertIn("cancelled", res.error)

    def test_sad_a_child_that_dies_during_a_request_is_reported_and_replaced(self) -> None:
        self.assertTrue(self.worker.analyse("/x/a.txt", "a.txt", timeout=10).ok)
        pid = self.worker.pid
        res = self.worker.analyse("/x/die.txt", "die.txt", timeout=10)
        self.assertFalse(res.ok)
        self.assertIn("exit status 3", res.error)
        after = self.worker.analyse("/x/c.txt", "c.txt", timeout=10)
        self.assertTrue(after.ok, after.error)
        self.assertNotEqual(self.worker.pid, pid)

    def test_edge_a_child_that_died_while_idle_is_replaced_before_the_request(self) -> None:
        self.assertTrue(self.worker.analyse("/x/a.txt", "a.txt", timeout=10).ok)
        pid = self.worker.pid
        os.kill(pid, 9)
        _wait_dead(pid)  # dead before the request: no race with the kill
        res = self.worker.analyse("/x/b.txt", "b.txt", timeout=10)
        self.assertTrue(res.ok, res.error)
        self.assertNotEqual(self.worker.pid, pid)


def _wait_dead(pid: int, seconds: float = 5.0) -> None:
    """Until ``pid`` has exited (a zombie or gone)."""
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        try:
            with open(f"/proc/{pid}/stat") as fh:
                if fh.read().rsplit(")", 1)[1].split()[0] in ("Z", "X"):
                    return
        except FileNotFoundError:
            return
        time.sleep(0.01)
    raise AssertionError(f"{pid} did not exit")


class MalformedReplyTest(unittest.TestCase):
    """A reply the parent cannot read is an error result, never an exception,
    and the child that sent it is replaced."""

    def setUp(self) -> None:
        self.worker = AW.AnalysisWorker(command=[sys.executable, "-c", _STUB_CHILD])
        self.addCleanup(self.worker.close)

    def test_sad_malformed_values_and_nesting_give_an_error_result(self) -> None:
        for name in ("bad-elapsed.txt", "bad-calls.txt", "nested.txt"):
            with self.subTest(name=name):
                self.assertTrue(self.worker.analyse("/x/ok.txt", "ok.txt", timeout=10).ok)
                pid = self.worker.pid
                res = self.worker.analyse("/x/" + name, name, timeout=10)
                self.assertFalse(res.ok)
                self.assertIn("analysis process failed", res.error)
                self.assertIsNone(self.worker.pid)
                with self.assertRaises(ProcessLookupError):
                    os.kill(pid, 0)

    def test_happy_the_next_request_after_a_malformed_reply_works(self) -> None:
        self.assertFalse(self.worker.analyse("/x/bad-calls.txt", "x", timeout=10).ok)
        res = self.worker.analyse("/x/fine.txt", "fine.txt", timeout=10)
        self.assertTrue(res.ok, res.error)
        self.assertEqual(res.summary, {"filename": "fine.txt"})


class HighDescriptorTest(unittest.TestCase):
    def test_edge_a_pipe_past_descriptor_1024_is_read(self) -> None:
        import resource

        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        need = 1200
        if hard != resource.RLIM_INFINITY and hard < need:
            self.skipTest(f"RLIMIT_NOFILE hard limit {hard} < {need}")
        if soft != resource.RLIM_INFINITY and soft < need:
            resource.setrlimit(resource.RLIMIT_NOFILE, (need, hard))
            self.addCleanup(resource.setrlimit, resource.RLIMIT_NOFILE, (soft, hard))
        held = []
        self.addCleanup(lambda: [os.close(fd) for fd in held])
        while not held or held[-1] < 1100:
            held.append(os.open(os.devnull, os.O_RDONLY))
        worker = AW.AnalysisWorker(command=[sys.executable, "-c", _STUB_CHILD])
        self.addCleanup(worker.close)
        res = worker.analyse("/x/a.txt", "a.txt", timeout=10)
        self.assertTrue(res.ok, res.error)
        self.assertGreaterEqual(worker._proc.stdout.fileno(), 1024)


class CloseRaceTest(unittest.TestCase):
    def test_sad_close_between_the_check_and_the_start_starts_no_child(self) -> None:
        import threading

        worker = AW.AnalysisWorker(command=[sys.executable, "-c", _STUB_CHILD])
        self.addCleanup(worker.close)
        started = []
        real_start = worker._start
        worker._start = lambda: started.append(1) or real_start()

        class _CloseOnFirstCheck(threading.Event):
            checked = False

            def is_set(self) -> bool:
                if not self.checked:
                    self.checked = True
                    worker.close()  # what another thread does right after the _closed check
                return super().is_set()

        res = worker.analyse("/x/a.txt", "a.txt", timeout=10, cancel_event=_CloseOnFirstCheck())
        self.assertFalse(res.ok)
        self.assertEqual(started, [])
        self.assertIsNone(worker.pid)


@unittest.skipUnless(AW.sift_available(), "sift is not installed")
class WorkerLLMTest(unittest.TestCase):
    """sift's LLM mode in the worker, against a real socket."""

    def setUp(self) -> None:
        from tests.fake_llm_server import FakeOllama

        self.FakeOllama = FakeOllama
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "people.csv")
        with open(self.path, "w") as fh:
            fh.write("name,age\nann,31\nbob,45\n")
        self.worker = AW.AnalysisWorker(cache_dir=None)
        self.addCleanup(self.worker.close)

    def _llm(self, url, model="demo:latest", key=FAKE_KEY):
        return {
            "provider": "ollama",
            "endpoint": url,
            "model": model,
            "api_key": key,
            "temperature": 0.2,
            "timeout": 20.0,
            "max_output_tokens": 500,
            "allow_model_load": False,
        }

    def test_happy_the_model_explains_the_file_with_progress_and_usage(self) -> None:
        events = []
        with self.FakeOllama() as srv:
            res = self.worker.analyse(
                self.path, "people.csv", llm=self._llm(srv.url), on_event=events.append, timeout=60
            )
        self.assertTrue(res.ok, res.error)
        self.assertTrue(res.summary["llm_used"])
        self.assertEqual(res.summary["model"], "demo:latest")
        self.assertIn("table of two people", res.summary["summary"])
        progress = [e for e in events if e.get("event") == "progress"]
        self.assertTrue(progress)
        self.assertGreater(progress[-1]["answer"], 0)
        self.assertEqual(len(res.calls), 1)
        self.assertEqual(
            (res.calls[0]["prompt_tokens"], res.calls[0]["completion_tokens"]), (26, 12)
        )
        self.assertEqual(res.calls[0]["tokens_per_second"], 25.0)  # 12 tokens / 0.48 s

    def test_sad_the_api_key_reaches_the_server_and_nothing_else(self) -> None:
        events = []
        with self.FakeOllama() as srv:
            res = self.worker.analyse(
                self.path, "people.csv", llm=self._llm(srv.url), on_event=events.append, timeout=60
            )
            sent = srv.headers[-1].get("Authorization", "")
        self.assertEqual(sent, "Bearer " + FAKE_KEY)
        import json as _json

        everything = _json.dumps([res.summary, res.calls, events, res.error])
        self.assertNotIn(FAKE_KEY, everything)

    def test_sad_an_unreachable_server_falls_back_to_the_heuristic(self) -> None:
        import socket

        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()  # nothing listens there now
        res = self.worker.analyse(
            self.path, "people.csv", llm=self._llm(f"http://127.0.0.1:{port}"), timeout=60
        )
        self.assertTrue(res.ok, res.error)
        self.assertFalse(res.summary["llm_used"])
        self.assertIn("2 rows", res.summary["summary"])

    def test_edge_a_model_that_is_not_resident_is_never_loaded(self) -> None:
        with self.FakeOllama() as srv:
            res = self.worker.analyse(
                self.path, "people.csv", llm=self._llm(srv.url, model="other:7b"), timeout=60
            )
            refused = list(srv.refused_loads)
        self.assertTrue(res.ok, res.error)
        self.assertFalse(res.summary["llm_used"])
        self.assertEqual(refused, [])  # sift did not even ask


class WorkerCancelEventTest(unittest.TestCase):
    def setUp(self) -> None:
        self.worker = AW.AnalysisWorker(command=[sys.executable, "-c", _STUB_CHILD])
        self.addCleanup(self.worker.close)

    def test_sad_an_already_cancelled_request_starts_nothing(self) -> None:
        import threading

        ev = threading.Event()
        ev.set()
        res = self.worker.analyse("/x/a.txt", "a.txt", timeout=10, cancel_event=ev)
        self.assertFalse(res.ok)
        self.assertIn("cancelled", res.error)
        self.assertIsNone(self.worker.pid)

    def test_happy_the_event_ends_this_request_only(self) -> None:
        import threading

        ev = threading.Event()
        threading.Timer(0.5, ev.set).start()
        res = self.worker.analyse("/x/hang.txt", "hang.txt", timeout=30, cancel_event=ev)
        self.assertIn("cancelled", res.error)
        self.assertTrue(self.worker.analyse("/x/next.txt", "next.txt", timeout=10).ok)

    def test_edge_a_closed_worker_starts_no_child(self) -> None:
        self.worker.close()
        res = self.worker.analyse("/x/a.txt", "a.txt", timeout=10)
        self.assertFalse(res.ok)
        self.assertIsNone(self.worker.pid)


class ReplyLimitTest(unittest.TestCase):
    def test_sad_an_oversized_reply_is_refused(self) -> None:
        reader = AW._LineReader(limit=16)
        reader.feed(b"x" * 40)
        with self.assertRaises(AW.WorkerProtocolError):
            reader.next_line()

    def test_edge_lines_split_across_reads_are_joined(self) -> None:
        reader = AW._LineReader(limit=1024)
        reader.feed(b'{"a":')
        self.assertIsNone(reader.next_line())
        reader.feed(b' 1}\n{"b": 2}\n')
        self.assertEqual(reader.next_line(), b'{"a": 1}')
        self.assertEqual(reader.next_line(), b'{"b": 2}')
        self.assertIsNone(reader.next_line())


if __name__ == "__main__":
    unittest.main()
