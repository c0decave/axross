"""axross imports without the Unix-only standard modules (as on Windows).

``core/local_fs.py`` imported ``pwd`` and ``grp`` and ``ui/terminal_widget.py``
imported ``pty`` at module level. Windows has none of them, so importing
the main window - and with it starting the GUI - failed before a single
window appeared. Simulated here by making those modules unimportable in a
child interpreter: ``sys.modules[name] = None`` makes ``import name`` raise
ImportError exactly as a missing module does.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
UNIX_ONLY = ("pwd", "grp", "pty", "tty", "termios", "fcntl", "resource")


def _run_without_unix_modules(body: str) -> subprocess.CompletedProcess:
    prelude = (
        "import sys\n"
        f"sys.path.insert(0, {str(ROOT)!r})\n"
        f"for _m in {UNIX_ONLY!r}:\n"
        "    sys.modules[_m] = None\n"
    )
    env = {**os.environ, "QT_QPA_PLATFORM": "offscreen"}
    return subprocess.run(
        [sys.executable, "-c", prelude + textwrap.dedent(body)],
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
        cwd=ROOT,
    )


# --- happy ----------------------------------------------------------------


def test_happy_the_main_window_imports_without_unix_modules():
    r = _run_without_unix_modules(
        """
        import core.local_fs, ui.terminal_widget, ui.main_window, main
        print("imported")
        """
    )
    assert r.returncode == 0, r.stderr[-2000:]
    assert "imported" in r.stdout


def test_happy_a_listing_has_no_owner_names_without_a_user_database(tmp_path):
    (tmp_path / "a.txt").write_text("a")
    r = _run_without_unix_modules(
        f"""
        from core.local_fs import LocalFS, owner_name, group_name
        item = next(i for i in LocalFS().list_dir({str(tmp_path)!r}) if i.name == "a.txt")
        print(repr(item.owner), repr(item.group), repr(owner_name(0)), repr(group_name(0)))
        """
    )
    assert r.returncode == 0, r.stderr[-2000:]
    assert r.stdout.split() == ["''", "''", "''", "''"]


# --- sad ------------------------------------------------------------------


def test_sad_a_local_terminal_without_a_pty_says_why():
    r = _run_without_unix_modules(
        """
        from ui.terminal_widget import LocalTerminalSession
        try:
            LocalTerminalSession().start()
        except OSError as exc:
            print("refused:", exc)
        """
    )
    assert r.returncode == 0, r.stderr[-2000:]
    assert "refused:" in r.stdout and "pty" in r.stdout


# --- edge -----------------------------------------------------------------


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX user database")
def test_edge_with_a_user_database_names_stay_resolved():
    from core.local_fs import clear_name_cache, owner_name

    clear_name_cache()
    assert owner_name(0) == "root"
    assert owner_name(2**31 - 7) == str(2**31 - 7)  # no such user: the number
