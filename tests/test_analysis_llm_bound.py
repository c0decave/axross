"""The parent never kills a healthy LLM analysis, and still ends a hang.

Before: an LLM analysis was killed after ``MODEL_TIME_BUDGET + timeout +
WALL_MARGIN`` (900 + 180 + 30 s) in total. sift checks its model-time
budget only *before* each map call of a long file (summarize.py
``_map_reduce``), always makes the reduce call after the loop, and its
per-call ``timeout`` is a socket-inactivity timeout (llm/base.py
``_stream_lines``: ``urlopen(req, timeout=self.timeout)``), so a model
streaming slowly but steadily made sift run past that total, and the
parent killed it with every token spent. sift's 60 s budget for its own
work was not in the total either, and the model-time budget was typed in
both programs (sift's Config default, axross' MODEL_TIME_BUDGET).

Now the parent bounds the child's *silence* (``llm_silence_bound``),
derived from the timeout and time budget it sends, and sends the
model-time budget, which the child sets on sift's Config.

The scaled-down numbers below keep each run to seconds; the relations
are the production ones.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import time
import unittest
from contextlib import ExitStack
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import analysis_worker as AW  # noqa: E402
from core import file_analysis as FA  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402


def _patch_everywhere(stack: ExitStack, name: str, value) -> None:
    """Patch a constant in analysis_worker and wherever it was imported."""
    for module in (AW, FA):
        if hasattr(module, name):
            stack.enter_context(mock.patch.object(module, name, value))


def _long_text(directory: str) -> str:
    path = os.path.join(directory, "notes.txt")
    with open(path, "w") as fh:
        for i in range(6000):  # 450 kB: a dozen map-reduce parts at 8192 tokens
            fh.write(f"Paragraph {i}: the quarterly report lists item {i} with value {i * 7}.\n")
    return path


def _target(path: str) -> FA.Target:
    st = os.stat(path)
    return FA.Target(LocalFS(), path, os.path.basename(path), st.st_size, st.st_mtime)


@unittest.skipUnless(AW.sift_available(), "sift is not installed")
class HealthyStreamingTest(unittest.TestCase):
    """Real child, real sift, a model that streams slowly but steadily."""

    def test_happy_a_map_reduce_past_the_old_total_completes(self) -> None:
        from tests.fake_llm_server import FakeOllama

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = _long_text(tmp.name)
        worker = AW.AnalysisWorker(cache_dir=None)
        self.addCleanup(worker.close)
        self.assertTrue(worker.analyse(path, "warm-up").ok)  # child started, sift imported
        llm_timeout, model_budget, margin = 1.0, 1.0, 0.5
        old_total = model_budget + llm_timeout + margin
        with ExitStack() as stack, FakeOllama(delay=0.15) as srv:
            _patch_everywhere(stack, "MODEL_TIME_BUDGET", model_budget)
            _patch_everywhere(stack, "WALL_MARGIN", margin)
            llm = {
                "provider": "ollama",
                "endpoint": srv.url,
                "model": "demo:latest",
                "api_key": "",
                "temperature": 0.2,
                "timeout": llm_timeout,
                "max_output_tokens": 200,
                "allow_model_load": False,
            }
            started = time.monotonic()
            res = FA.FileAnalyzer(worker=worker).analyse(_target(path), llm=llm)
            elapsed = time.monotonic() - started
        self.assertTrue(res.ok, res.error)
        self.assertTrue(res.summary["llm_used"])
        self.assertGreater(elapsed, old_total)  # the old bound would have killed it
        kinds = [c.get("kind") for c in res.calls]
        self.assertEqual(kinds[-1], "reduce")
        # sift ran on the parent's model-time budget, not its own default.
        self.assertIn("model-time budget", json.dumps(res.summary))
        self.assertLess(kinds.count("map"), 12)


_STREAM_THEN_HANG = r"""
import json, os, sys, time
out = os.fdopen(os.dup(1), "wb", buffering=0)
os.dup2(2, 1)
for raw in sys.stdin.buffer:
    req = json.loads(raw)
    if req["path"].endswith("stream-then-hang"):
        end = time.monotonic() + 1.5
        while time.monotonic() < end:
            out.write(json.dumps({"id": req["id"], "event": "progress", "answer": 1,
                                  "reasoning": 0}).encode() + b"\n")
            time.sleep(0.1)
        time.sleep(3600)
    out.write(json.dumps({"id": req["id"], "ok": True, "summary": {"request": req},
                          "error": "", "from_cache": False, "elapsed": 0.0}).encode() + b"\n")
"""


class SilenceBoundTest(unittest.TestCase):
    def setUp(self) -> None:
        self.worker = AW.AnalysisWorker(command=[sys.executable, "-c", _STREAM_THEN_HANG])
        self.addCleanup(self.worker.close)
        self.assertTrue(self.worker.analyse("/x/warm", "warm", timeout=10).ok)

    def test_sad_a_child_that_falls_silent_is_killed_after_the_bound(self) -> None:
        with mock.patch.object(AW, "WALL_MARGIN", 0.1):
            started = time.monotonic()
            res = self.worker.analyse(
                "/x/stream-then-hang", "f", llm={"timeout": 0.2}, time_budget=0.1
            )
            elapsed = time.monotonic() - started
            bound = AW.llm_silence_bound(0.2, 0.1)
        self.assertFalse(res.ok)
        self.assertIn("stopped answering", res.error)
        self.assertGreater(elapsed, 1.5)  # not while events were still coming
        self.assertLess(elapsed, 1.5 + bound + 2.0)
        self.assertIsNone(self.worker.pid)

    def test_edge_the_child_gets_the_numbers_the_bound_is_made_of(self) -> None:
        llm = {"timeout": 7.0, "model": "m"}
        res = self.worker.analyse("/x/plain", "f", llm=llm, time_budget=11.0)
        self.assertTrue(res.ok, res.error)
        sent = res.summary["request"]
        self.assertEqual(sent["model_time_budget"], AW.MODEL_TIME_BUDGET)
        self.assertEqual(sent["time_budget"], 11.0)
        self.assertEqual(sent["llm"]["timeout"], 7.0)
        self.assertEqual(
            AW.llm_silence_bound(sent["llm"]["timeout"], sent["time_budget"]),
            11.0 + AW.SIFT_SILENT_REQUESTS * 7.0 + AW.WALL_MARGIN,
        )


@unittest.skipUnless(AW.sift_available(), "sift is not installed")
class ChildConfigTest(unittest.TestCase):
    def test_edge_sift_runs_on_the_parents_budgets(self) -> None:
        request = {
            "time_budget": 11.0,
            "model_time_budget": 33.0,
            "llm": {"provider": "openai", "endpoint": "http://127.0.0.1:1/v1", "timeout": 7.0},
        }
        config = AW._config_for(request)
        self.assertEqual(
            (config.time_budget, config.model_time_budget, config.timeout), (11.0, 33.0, 7.0)
        )
        heuristic = AW._config_for({"time_budget": 5.0, "llm": None})
        self.assertTrue(heuristic.no_llm)
        self.assertEqual(heuristic.time_budget, 5.0)


class _SlowOpenAI:
    """An OpenAI-compatible server on which every request takes ``delay``
    seconds before its first byte, and which makes sift take its longest
    silent path: no LM Studio inventory (404), the plain /models list, and
    a chat request refused for stream_options and sent again."""

    def __init__(self, delay: float) -> None:
        self.delay = delay
        self.seen: list[str] = []

    def __enter__(self) -> "_SlowOpenAI":
        fake = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def _json(self, code, obj):
                body = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                fake.seen.append("GET " + self.path)
                time.sleep(fake.delay)
                if self.path.rstrip("/") == "/v1/models":
                    self._json(200, {"data": [{"id": "some-other-model"}]})
                else:
                    self._json(404, {"error": "no such endpoint"})

            def do_POST(self):
                payload = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)))
                usage = " +usage" if "stream_options" in payload else ""
                fake.seen.append("POST " + self.path + usage)
                time.sleep(fake.delay)
                if "stream_options" in payload:
                    self._json(400, {"error": {"message": "unknown field stream_options"}})
                    return
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Connection", "close")
                self.end_headers()
                for piece in ("TYPE: Notes\n", "SUMMARY: A short ", "test file."):
                    event = {"choices": [{"delta": {"content": piece}, "finish_reason": None}]}
                    self.wfile.write(f"data: {json.dumps(event)}\n\n".encode())
                done = {"choices": [{"delta": {}, "finish_reason": "stop"}]}
                self.wfile.write(f"data: {json.dumps(done)}\n\ndata: [DONE]\n\n".encode())
                self.wfile.flush()
                self.close_connection = True

        self._srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self._srv.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc) -> bool:
        self._srv.shutdown()
        self._srv.server_close()
        return False

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self._srv.server_address[1]}/v1"


@unittest.skipUnless(AW.sift_available(), "sift is not installed")
class SilentRequestChainTest(unittest.TestCase):
    """The silence bound covers sift's longest run of requests without a
    streamed piece; with fewer requests counted it would kill this run."""

    # sift needs its own budget for its own work (a 0.5 s one ran out in the
    # manipulation scan); each request stays under the per-request timeout.
    llm_timeout, delay, time_budget, margin = 1.5, 1.25, 3.0, 0.2

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = os.path.join(tmp.name, "a.txt")
        with open(self.path, "w") as fh:
            fh.write("a short test file\n")
        self.worker = AW.AnalysisWorker(cache_dir=None)
        self.addCleanup(self.worker.close)
        self.assertTrue(self.worker.analyse(self.path, "warm-up").ok)

    def _run(self, srv: _SlowOpenAI):
        llm = {
            "provider": "openai",
            "endpoint": srv.url,
            "model": "demo",
            "api_key": "",
            "timeout": self.llm_timeout,
            "max_output_tokens": 200,
        }
        with mock.patch.object(AW, "WALL_MARGIN", self.margin):
            return self.worker.analyse(
                self.path, "a.txt", llm=llm, time_budget=self.time_budget
            )

    def test_happy_the_whole_silent_chain_fits_the_bound(self) -> None:
        with _SlowOpenAI(self.delay) as srv:
            res = self._run(srv)
        self.assertTrue(res.ok, res.error)
        self.assertTrue(res.summary["llm_used"], res.summary.get("error"))
        self.assertEqual(
            srv.seen,
            [
                "GET /api/v0/models",
                "GET /v1/models",
                "POST /v1/chat/completions +usage",
                "POST /v1/chat/completions",
            ],
        )
        self.assertEqual(len(srv.seen), AW.SIFT_SILENT_REQUESTS)
        one_request_bound = self.llm_timeout + self.time_budget + self.margin
        self.assertGreater(len(srv.seen) * self.delay, one_request_bound)

    def test_sad_counting_one_request_would_kill_the_healthy_run(self) -> None:
        with _SlowOpenAI(self.delay) as srv, mock.patch.object(AW, "SIFT_SILENT_REQUESTS", 1):
            res = self._run(srv)
        self.assertFalse(res.ok)
        self.assertIn("stopped answering", res.error)


if __name__ == "__main__":
    unittest.main()
