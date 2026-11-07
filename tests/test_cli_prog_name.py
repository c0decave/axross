"""``axross --help`` names the command axross however it was started.

``python -m axross --help`` printed ``usage: __main__.py`` (argparse takes
the name of the script it was started as).
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_the_parser_is_named_axross():
    sys.path.insert(0, str(ROOT))
    import main

    assert main.build_parser().prog == "axross"


def test_python_m_axross_help_names_axross():
    env = dict(os.environ, PYTHONPATH=str(ROOT), QT_QPA_PLATFORM="offscreen")
    out = subprocess.run([sys.executable, "-m", "axross", "--help"], cwd=ROOT, env=env,
                         capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    assert out.stdout.startswith("usage: axross"), out.stdout[:80]
