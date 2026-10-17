"""AXROSS_SMOKE_GUI_MS: open the main window, report the platform, quit.

The bundle smoke ran only ``--version`` and ``--script`` - no window. A
crash on the way to the main window (the native platform plugin, the
menu bar, the clipboard) passed every CI run, offscreen or not. With
``AXROSS_SMOKE_GUI_MS=<ms>`` axross opens the window as usual, prints
``gui smoke: window shown on <platform>`` once it is up and quits after
<ms> milliseconds, so a CI run on macOS and Windows can start the real
thing and see it come up.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _run(tmp_path, value, extra_env=None, timeout=120):
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    env = {k: v for k, v in os.environ.items() if not k.startswith("AXROSS_")}
    env.update(HOME=str(home), XDG_CONFIG_HOME=str(home / ".config"), XDG_DATA_HOME=str(home / "share"),
               XDG_STATE_HOME=str(home / "state"), QT_QPA_PLATFORM="offscreen",
               PYTHON_KEYRING_BACKEND="keyring.backends.null.Keyring", AXROSS_SMOKE_GUI_MS=value,
               **(extra_env or {}))
    return subprocess.run([sys.executable, str(ROOT / "main.py")], capture_output=True, text=True,
                          timeout=timeout, env=env, cwd=ROOT)


def test_happy_the_window_comes_up_and_the_app_quits(tmp_path):
    r = _run(tmp_path, "300")
    assert r.returncode == 0, r.stderr[-2000:]
    assert "gui smoke: window shown on offscreen" in r.stdout


def test_sad_a_value_that_is_no_number_is_refused(tmp_path):
    r = _run(tmp_path, "soon", timeout=60)
    assert r.returncode == 2 and "AXROSS_SMOKE_GUI_MS" in r.stderr


def test_edge_zero_quits_right_after_the_first_paint(tmp_path):
    r = _run(tmp_path, "0")
    assert r.returncode == 0 and "window shown" in r.stdout
