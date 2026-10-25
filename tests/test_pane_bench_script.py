"""scripts/pane_bench.py, the repeatable file pane benchmark, keeps working.

It is run by hand for numbers (docs in its docstring); this runs it small,
in a child process, so a change to the pane, the transfer queue or Find
Files that breaks it shows here.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "pane_bench.py"


def _run(tmp_path, *args, timeout=300):
    env = {k: v for k, v in os.environ.items() if not k.lower().endswith("_proxy")}
    env["QT_QPA_PLATFORM"] = "offscreen"
    return subprocess.run([sys.executable, str(SCRIPT), *args], cwd=tmp_path, env=env,
                          capture_output=True, text=True, timeout=timeout)


def test_happy_e2e_a_small_run_measures_every_scenario(tmp_path):
    out = tmp_path / "result.json"
    done = _run(tmp_path, "--entries", "300", "--transfer-files", "20", "--transfer-mb", "2",
                "--search-files", "400", "--json", str(out))
    assert done.returncode == 0, done.stderr[-3000:]
    results = json.loads(out.read_text())
    for name in ("open_local", "refresh_local", "back", "forward", "sort_name_asc",
                 "sort_modified_desc", "select_all", "invert", "resize", "show_hidden_on",
                 "thumbnails_on", "open_ramfs", "open_slow", "transfer_many", "transfer_big",
                 "search"):
        for suffix in ("wall_ms", "gui_cpu_ms", "gap_max_ms"):
            assert results[f"{name}_{suffix}"] >= 0, f"{name}_{suffix}"
    assert results["filter_key_gui_cpu_max_ms"] >= 0
    assert results["idle_process_cpu_ms_per_s"] >= 0 and results["idle_gap_max_ms"] >= 0
    assert results["transfer_many_files_ok"] == 1
    assert results["transfer_big_bytes_ok"] == 1
    assert results["search_rows"] == 100, "every 4th of 400 files is a .log"
    assert results["selected_count"] == 300 - 300 // 10, "hidden dot names are not shown"
    assert results["open_slow_wall_ms"] >= 500, "the slow listing takes 0.5 s"


def test_sad_a_tree_without_axross_is_refused(tmp_path):
    done = _run(tmp_path, "--entries", "10", "--only", "open_local", "--tree", str(tmp_path))
    assert done.returncode != 0
    assert "ui.file_pane" in done.stderr or "ModuleNotFoundError" in done.stderr


def test_sad_an_unknown_scenario_is_refused(tmp_path):
    done = _run(tmp_path, "--entries", "10", "--only", "open_local,warp_drive")
    assert done.returncode != 0
    assert "warp_drive" in done.stderr


def test_edge_one_scenario_measures_only_that(tmp_path):
    out = tmp_path / "result.json"
    done = _run(tmp_path, "--entries", "50", "--only", "open_ramfs", "--json", str(out))
    assert done.returncode == 0, done.stderr[-3000:]
    results = json.loads(out.read_text())
    assert "open_ramfs_wall_ms" in results
    assert not any(k.startswith(("open_local", "transfer", "search")) for k in results)
