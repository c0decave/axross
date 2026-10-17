"""--help names every capability group --mcp-tools accepts."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from core.mcp_groups import GROUPS

ROOT = Path(__file__).resolve().parent.parent


def _help() -> str:
    env = {**os.environ, "QT_QPA_PLATFORM": "offscreen"}
    out = subprocess.run([sys.executable, str(ROOT / "main.py"), "--help"], capture_output=True,
                         text=True, timeout=120, env=env, cwd=str(ROOT))
    assert out.returncode == 0, out.stderr[-2000:]
    return " ".join(out.stdout.split())


def test_happy_every_group_is_named_in_the_help():
    text = _help()
    start = text.rindex("--mcp-tools GROUP")  # the option, not the usage line
    section = text[start:start + 1200]
    missing = [g for g in GROUPS if g not in section]
    assert missing == []
