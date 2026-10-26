"""scripts/ui_bench.py, the repeatable benchmark of the windows, docks and
dialogs, keeps working.

It is run by hand for numbers (docs in its docstring); this runs it small,
in a child process, so a change to a dialog, the theme switch, the Log dock
or the terminal that breaks it shows here.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "ui_bench.py"


def _run(tmp_path, *args, timeout=600):
    env = {k: v for k, v in os.environ.items() if not k.lower().endswith("_proxy")}
    env["QT_QPA_PLATFORM"] = "offscreen"
    return subprocess.run([sys.executable, str(SCRIPT), *args], cwd=tmp_path, env=env,
                          capture_output=True, text=True, timeout=timeout)


def test_happy_e2e_a_small_run_measures_every_scenario(tmp_path):
    out = tmp_path / "result.json"
    done = _run(tmp_path, "--repeat", "2", "--terminal-mb", "0.1", "--json", str(out))
    assert done.returncode == 0, done.stderr[-3000:]
    results = json.loads(out.read_text())
    for name in ("window_open_close", "settings_open", "settings_find", "theme_modern",
                 "dialog_features", "dialog_shortcuts", "connection_dialog",
                 "bookmarks_manager", "mcp_catalog", "editor_open_text", "hex_open_30mib",
                 "properties", "metadata", "workspace_new_close", "workspace_detach_attach",
                 "log_burst_5000", "terminal_pty_yes_200000", "terminal_pty_cat",
                 "console_show", "menus_open_all", "window_close"):
        for suffix in ("cpu_ms", "gap_max_ms"):
            assert results[f"{name}_{suffix}"] >= 0, f"{name}_{suffix}"
    for name in ("settings", "theme_cycle", "dialog_features", "connection_dialog",
                 "workspace_detach_attach", "hex"):
        assert f"{name}_leak_widgets" in results and f"{name}_leak_objects" in results
    assert results["terminal_pty_cat_wall_ms"] > 0
    assert results["peak_rss_mb"] > 0


def test_sad_a_tree_without_axross_is_refused(tmp_path):
    done = _run(tmp_path, "--only", "dialogs", "--tree", str(tmp_path))
    assert done.returncode != 0
    assert "ui.main_window" in done.stderr or "ModuleNotFoundError" in done.stderr


def test_sad_an_unknown_scenario_is_refused(tmp_path):
    done = _run(tmp_path, "--only", "settings,warp_drive")
    assert done.returncode != 0
    assert "warp_drive" in done.stderr


def test_edge_one_scenario_measures_only_that(tmp_path):
    out = tmp_path / "result.json"
    done = _run(tmp_path, "--only", "properties", "--repeat", "1", "--json", str(out))
    assert done.returncode == 0, done.stderr[-3000:]
    results = json.loads(out.read_text())
    assert "properties_cpu_ms" in results
    assert not any(k.startswith(("settings", "theme", "terminal", "log")) for k in results)
