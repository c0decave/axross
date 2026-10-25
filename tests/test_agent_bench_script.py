"""scripts/agent_bench.py, the repeatable Agent dock benchmark, keeps working.

It is run by hand for numbers (docs in its docstring); this runs it small,
in a child process, so a change to the dock that breaks it shows here.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "agent_bench.py"


def _run(tmp_path, *args, timeout=240):
    env = {k: v for k, v in os.environ.items() if not k.lower().endswith("_proxy")}
    env["QT_QPA_PLATFORM"] = "offscreen"
    return subprocess.run([sys.executable, str(SCRIPT), *args], cwd=tmp_path, env=env,
                          capture_output=True, text=True, timeout=timeout)


def test_happy_e2e_a_small_run_measures_every_item(tmp_path):
    out = tmp_path / "result.json"
    done = _run(tmp_path, "--steps", "4", "--run-steps", "2", "--delay", "0",
                "--json", str(out))
    assert done.returncode == 0, done.stderr[-2000:]
    results = json.loads(out.read_text())
    for name in ("dock_open_4_long_tabs_ms", "tab_open_long_ms", "toggle_reasoning_min_ms",
                 "send_blocks_gui_ms", "send_to_first_request_ms", "run_loop_gap_p95_ms",
                 "run_session_save_max_ms", "detach_long_ms", "attach_long_ms", "peak_rss_mb"):
        assert results[name] >= 0, name
    assert results["run_requests"] == 3, "two tool calls, then the answer"
    assert "toggle_reasoning_min_ms" in done.stdout


def test_sad_a_tree_without_axross_is_refused(tmp_path):
    done = _run(tmp_path, "--steps", "1", "--run-steps", "1", "--tree", str(tmp_path))
    assert done.returncode != 0
    assert "ui.agent_dock" in done.stderr or "ModuleNotFoundError" in done.stderr


def test_edge_empty_tabs_measure_without_a_thinking_block(tmp_path):
    out = tmp_path / "result.json"
    done = _run(tmp_path, "--steps", "0", "--run-steps", "1", "--delay", "0", "--json", str(out))
    assert done.returncode == 0, done.stderr[-2000:]
    results = json.loads(out.read_text())
    assert "toggle_reasoning_min_ms" not in results
    assert results["run_requests"] == 2


@pytest.mark.parametrize("flag", ["--serve"])
def test_edge_the_fake_server_alone_answers_and_ends_with_its_input(tmp_path, flag):
    proc = subprocess.Popen([sys.executable, str(SCRIPT), flag, "1", "0"], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, text=True, cwd=tmp_path)
    try:
        url = proc.stdout.readline().strip()
        assert url.startswith("http://127.0.0.1:") and url.endswith("/v1")
        import urllib.request

        body = json.dumps({"model": "m", "messages": []}).encode()
        request = urllib.request.Request(url + "/chat/completions", data=body,
                                         headers={"Content-Type": "application/json"})
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        first = json.loads(opener.open(request, timeout=10).read())
        assert first["choices"][0]["message"]["tool_calls"]
        second = json.loads(opener.open(request, timeout=10).read())
        assert second["choices"][0]["message"]["content"]
        proc.stdin.write("arrivals\n")
        proc.stdin.flush()
        assert len(json.loads(proc.stdout.readline())) == 2
    finally:
        proc.stdin.close()
        assert proc.wait(10) == 0
