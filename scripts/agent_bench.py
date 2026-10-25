"""Measure the Agent dock with a long conversation and a fake LLM server.

Usage: python scripts/agent_bench.py [--steps 170] [--run-steps 20] [--delay 0.02]
                                     [--json OUT] [--tree DIR]

The numbers the operator's "optimise the LLM / agent parts" asked for, made
repeatable: a dock restoring four kept tabs of ``--steps`` tasks each (five
transcript lines per task: task, thinking, tool call, tool result, answer;
the model's history with a 16,000-character tool output per task), then

* opening one more such tab, switching tabs, opening a Thinking block,
  appending lines to a fresh and to the long tab;
* a task of ``--run-steps`` tool calls on the long tab against an
  OpenAI-compatible server that answers after ``--delay`` seconds: the time
  Send blocks the GUI thread, Send to the request on the wire, the GUI
  event loop's gaps (a 10 ms QTimer), every agent event's handling time and
  the session saves;
* detaching and attaching the long tab, a New Agent Window, peak RSS.

Everything runs in a temporary HOME with Qt offscreen (unless
QT_QPA_PLATFORM is set): no real settings, sessions or keyring are read or
written. The fake server runs in a process of its own, so its work does not
compete for this process's GIL. ``--tree`` imports axross from another
checkout (an old version extracted with ``git archive``) for an A/B; the
script checks that the modules really come from there. Compare minima of
alternating runs: the numbers move with the host's load.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


# -- the fake LLM server ----------------------------------------------------------------------


def serve(steps: int, delay: float) -> None:
    """``--serve``: an OpenAI-compatible /chat/completions. axross sends
    ``"stream": false``, so an answer comes whole after *delay* seconds;
    *steps* answers call read_file (each with a thinking block), then one
    answers. Prints its URL; stdin commands: ``arrivals`` (the
    time.perf_counter() of every request, CLOCK_MONOTONIC on Linux),
    ``reset``."""
    arrivals: list[float] = []
    count = [0]
    tool_args = json.loads(os.environ.get("AGENT_BENCH_TOOL_ARGS", "{}"))
    reasoning = ("thinking about the files " * 200)[:1500]

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args) -> None:
            pass

        def do_GET(self) -> None:  # noqa: N802 - http.server API
            self.send_error(501)  # no model inventory: nothing is refused

        def do_POST(self) -> None:  # noqa: N802 - http.server API
            arrivals.append(time.perf_counter())
            self.rfile.read(int(self.headers["Content-Length"]))
            k = count[0]
            count[0] += 1
            if delay:
                time.sleep(delay)
            if k < steps:
                message = {"role": "assistant", "content": "", "reasoning_content": reasoning,
                           "tool_calls": [{"id": f"call{k}", "type": "function", "function": {
                               "name": "read_file", "arguments": json.dumps(tool_args)}}]}
            else:
                message = {"role": "assistant", "content": "The folder holds one big file.",
                           "reasoning_content": reasoning}
            data = json.dumps({"choices": [{"index": 0, "message": message,
                                            "finish_reason": "stop"}],
                               "usage": {"prompt_tokens": 100, "completion_tokens": 10}}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print(f"http://127.0.0.1:{server.server_address[1]}/v1", flush=True)
    for line in sys.stdin:
        if line.strip() == "arrivals":
            print(json.dumps(arrivals), flush=True)
        elif line.strip() == "reset":
            arrivals.clear()
            count[0] = 0
            print("{}", flush=True)
    server.shutdown()


class FakeServer:
    def __init__(self, steps: int, delay: float, tool_args: dict) -> None:
        env = {**os.environ, "AGENT_BENCH_TOOL_ARGS": json.dumps(tool_args)}
        self.proc = subprocess.Popen(
            [sys.executable, str(Path(__file__).resolve()), "--serve", str(steps), str(delay)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, env=env)
        self.url = self.proc.stdout.readline().strip()

    def ask(self, command: str):
        self.proc.stdin.write(command + "\n")
        self.proc.stdin.flush()
        return json.loads(self.proc.stdout.readline())

    def close(self) -> None:
        try:
            self.proc.stdin.close()
            self.proc.wait(5)
        except (OSError, subprocess.TimeoutExpired):
            self.proc.kill()


# -- a long conversation ----------------------------------------------------------------------


def long_conversation(steps: int, tool_chars: int = 16_000) -> tuple[list, list]:
    """(transcript, model history) of *steps* tasks, deterministic."""
    rnd = random.Random(1)
    words = ["file", "folder", "backup", "size", "report", "owner", "äöü", "λ", "日本"]

    def text(n: int) -> str:
        out = " ".join(rnd.choice(words) for _ in range(n // 4 + 1))[:n]
        return "\n".join(out[i:i + 100] for i in range(0, len(out), 100))

    transcript: list = []
    messages: list = [{"role": "system", "content": "rules " * 200}]
    for i in range(steps):
        task = f"task {i}: look at the folder and tell me"
        answer = text(600)
        transcript += [
            {"who": "You:", "text": task, "muted": False},
            {"who": "Thinking:", "text": text(1500), "muted": True, "kind": "reasoning"},
            {"who": "→", "text": f'read_file {{"path": "/srv/{i}", "encoding": "text"}}',
             "muted": True},
            {"who": "←", "text": "read_file: ok", "muted": True},
            {"who": "Agent:", "text": answer, "muted": False},
        ]
        messages += [
            {"role": "user", "content": task},
            {"role": "assistant", "content": "", "tool_calls": [{
                "id": f"c{i}", "type": "function",
                "function": {"name": "read_file", "arguments": '{"path": "/srv"}'}}]},
            {"role": "tool", "tool_call_id": f"c{i}", "content": text(tool_chars)},
            {"role": "assistant", "content": answer},
        ]
    return transcript, messages


# -- the benchmark ----------------------------------------------------------------------------


def bench(args) -> dict:
    import statistics

    from PyQt6.QtCore import QTimer
    from PyQt6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication([])
    import ui.agent_dock as AD
    from core import agent_settings as AGS
    from core import llm_profiles as LP
    from core.agent_session import AgentSession, SessionStore
    from core.mcp_detect import DetectResult

    if not Path(AD.__file__).resolve().is_relative_to(Path(args.tree).resolve()):
        raise SystemExit(f"ui.agent_dock came from {AD.__file__}, not from {args.tree}")
    results: dict = {}

    def record(name: str, value: float) -> None:
        results[name] = round(value, 2)
        print(f"{name:34s} {value:10.2f}", flush=True)

    def pump(seconds: float = 0.0) -> None:
        end = time.perf_counter() + seconds
        app.processEvents()
        while time.perf_counter() < end:
            app.processEvents()
            time.sleep(0.001)

    work = Path(tempfile.mkdtemp(prefix="agent-bench-"))
    root = work / "work"
    root.mkdir()
    (root / "big.txt").write_text("line of a big log file with words\n" * 3000)
    server = FakeServer(args.run_steps, args.delay,
                        {"path": str(root / "big.txt"), "encoding": "text"})
    try:
        profile = LP.LLMProfile(name="local", provider="lmstudio", endpoint=server.url,
                                model="tiny")
        llm = LP.LLMSettings([profile], "local")
        store = SessionStore(work / "sessions")
        transcript, messages = long_conversation(args.steps)

        def session(title: str) -> AgentSession:
            return AgentSession(title=title, folder=str(root),
                                transcript=[dict(e) for e in transcript],
                                messages=[dict(m) for m in messages])

        for i in range(4):
            store.save(session(f"long {i}"))
        settings = AGS.AgentSettings()
        settings.max_steps = args.run_steps + 1
        started = time.perf_counter()
        dock = AD.AgentDock(
            settings_loader=lambda: llm, settings_saver=lambda s: None,
            key_lookup=lambda name: "", confirm_remote=lambda p, h: True,
            confirm_call=lambda n, a: True, root_provider=lambda: str(root),
            agent_settings_loader=lambda: settings, agent_settings_saver=lambda s: None,
            session_store=store, mcp_detector=lambda **kw: DetectResult())
        dock.resize(700, 900)
        dock.show()
        pump()
        record("dock_open_4_long_tabs_ms", (time.perf_counter() - started) * 1000)

        started = time.perf_counter()
        tab = dock._add_tab(session("extra"))
        pump()
        record("tab_open_long_ms", (time.perf_counter() - started) * 1000)

        times = []
        for _round in range(3):
            for i in range(dock.tabs.count()):
                started = time.perf_counter()
                dock.tabs.setCurrentIndex(i)
                pump()
                times.append(time.perf_counter() - started)
        record("tab_switch_max_ms", max(times) * 1000)
        dock.tabs.setCurrentWidget(tab)
        pump()

        index = next((i for i, e in enumerate(tab._entries) if e["kind"] == "reasoning"), None)
        if index is not None:  # --steps 0: nothing to open
            times = []
            for _ in range(4):
                started = time.perf_counter()
                tab.toggle_reasoning(index)
                pump()
                times.append(time.perf_counter() - started)
            record("toggle_reasoning_min_ms", min(times) * 1000)

        def append_cost(target) -> float:
            costs = []
            for _ in range(40):
                started = time.perf_counter()
                target._append("Agent:", "The folder holds these files. " * 20)
                app.processEvents()
                costs.append(time.perf_counter() - started)
            return statistics.median(costs) * 1000

        record("append_fresh_median_ms", append_cost(dock.new_tab(save=False)))
        dock.tabs.setCurrentWidget(tab)
        pump()
        record("append_long_median_ms", append_cost(tab))

        gaps: list[float] = []
        last = [time.perf_counter()]

        def probe() -> None:
            now = time.perf_counter()
            gaps.append(now - last[0])
            last[0] = now

        timer = QTimer()
        timer.setInterval(10)
        timer.timeout.connect(probe)
        handled: dict[str, list[float]] = {}
        on_event = tab._on_event

        def timed(event) -> None:
            started = time.perf_counter()
            on_event(event)
            handled.setdefault(str(event.get("type")), []).append(time.perf_counter() - started)

        tab._bridge.event.disconnect()
        tab._bridge.event.connect(timed)
        saves: list[float] = []
        save = store.save

        def timed_save(s) -> None:
            started = time.perf_counter()
            save(s)
            saves.append(time.perf_counter() - started)

        store.save = timed_save
        server.ask("reset")
        tab.input.setPlainText("summarise the big file")
        last[0] = time.perf_counter()
        timer.start()
        began = time.perf_counter()
        tab.send()
        record("send_blocks_gui_ms", (time.perf_counter() - began) * 1000)
        deadline = time.perf_counter() + 300
        while (tab.busy() or tab._thread is not None) and time.perf_counter() < deadline:
            app.processEvents()
            time.sleep(0.001)
        total = time.perf_counter() - began
        pump(0.05)
        timer.stop()
        arrivals = server.ask("arrivals")
        record("send_to_first_request_ms", (arrivals[0] - began) * 1000 if arrivals else -1)
        record("run_requests", len(arrivals))
        record("run_overhead_per_step_ms",
               (total - args.delay * len(arrivals)) * 1000 / max(1, len(arrivals)))
        ordered = sorted(g * 1000 for g in gaps)
        record("run_loop_gap_max_ms", ordered[-1])
        record("run_loop_gap_p95_ms", ordered[int(len(ordered) * 0.95)])
        for kind, costs in sorted(handled.items()):
            record(f"event_{kind}_max_ms", max(costs) * 1000)
        record("run_session_save_max_ms", max(saves) * 1000 if saves else 0)

        started = time.perf_counter()
        panel = dock.detach_tab(tab)
        pump()
        record("detach_long_ms", (time.perf_counter() - started) * 1000)
        started = time.perf_counter()
        dock.attach_panel(panel)
        pump()
        record("attach_long_ms", (time.perf_counter() - started) * 1000)
        started = time.perf_counter()
        dock.new_window(str(root))
        pump()
        record("new_window_ms", (time.perf_counter() - started) * 1000)
        import resource

        record("peak_rss_mb", resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024)
        dock.shutdown()
    finally:
        server.close()
        shutil.rmtree(work, ignore_errors=True)
    return results


def main(argv=None) -> int:
    if argv is None and len(sys.argv) > 1 and sys.argv[1] == "--serve":
        serve(int(sys.argv[2]), float(sys.argv[3]))
        return 0
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--steps", type=int, default=170,
                        help="tasks in each kept tab (5 transcript lines each)")
    parser.add_argument("--run-steps", type=int, default=20, help="tool calls of the task run")
    parser.add_argument("--delay", type=float, default=0.02,
                        help="seconds the fake model takes per answer")
    parser.add_argument("--json", help="write the results to this file as well")
    parser.add_argument("--tree", default=str(ROOT), help="the axross checkout to measure")
    args = parser.parse_args(argv)
    home = tempfile.mkdtemp(prefix="agent-bench-home-")
    os.environ.update({
        "HOME": home, "XDG_CONFIG_HOME": f"{home}/.config", "XDG_DATA_HOME": f"{home}/.local",
        "XDG_CACHE_HOME": f"{home}/.cache", "XDG_STATE_HOME": f"{home}/.state",
        "PYTHON_KEYRING_BACKEND": "keyring.backends.null.Keyring",
    })
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    for name in ("http_proxy", "https_proxy", "all_proxy",
                 "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
        os.environ.pop(name, None)  # a proxy would make loopback "remote"
    sys.path.insert(0, str(Path(args.tree).resolve()))
    try:
        results = bench(args)
    finally:
        shutil.rmtree(home, ignore_errors=True)
    if args.json:
        Path(args.json).write_text(json.dumps(results, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
