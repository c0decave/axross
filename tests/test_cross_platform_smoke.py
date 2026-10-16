"""The smallest proof that axross runs on this operating system.

The CI matrix runs this file on Linux, macOS and Windows: the main window
opens and closes, the local file system lists a folder, and a local
terminal runs a command. Every check runs in a child interpreter with its
own HOME (and USERPROFILE / APPDATA on Windows), so no run touches the
user's real configuration.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _isolated_env(home: Path) -> dict:
    env = dict(os.environ)
    env.update(
        HOME=str(home),
        USERPROFILE=str(home),
        APPDATA=str(home / "AppData" / "Roaming"),
        LOCALAPPDATA=str(home / "AppData" / "Local"),
        XDG_CONFIG_HOME=str(home / ".config"),
        XDG_DATA_HOME=str(home / ".local" / "share"),
        XDG_CACHE_HOME=str(home / ".cache"),
        XDG_STATE_HOME=str(home / ".local" / "state"),
        QT_QPA_PLATFORM="offscreen",
        PYTHON_KEYRING_BACKEND="keyring.backends.null.Keyring",
    )
    return env


def _run(tmp_path: Path, body: str, timeout: float = 120) -> subprocess.CompletedProcess:
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    code = f"import sys\nsys.path.insert(0, {str(ROOT)!r})\n" + textwrap.dedent(body)
    return subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        env=_isolated_env(home),
        cwd=tmp_path,
    )


# --- happy ----------------------------------------------------------------


def test_happy_the_main_window_opens_and_closes(tmp_path):
    r = _run(
        tmp_path,
        """
        import time
        from PyQt6.QtWidgets import QApplication
        app = QApplication([])
        from ui.main_window import MainWindow
        win = MainWindow()
        win.show()
        end = time.monotonic() + 1.0
        while time.monotonic() < end:
            app.processEvents()
        assert win.isVisible() and win._panes, "no pane"
        win.close()
        app.processEvents()
        print("window ok")
        """,
    )
    assert r.returncode == 0, r.stderr[-3000:]
    assert "window ok" in r.stdout


def test_happy_the_local_file_system_lists_a_folder(tmp_path):
    folder = tmp_path / "data"
    (folder / "sub").mkdir(parents=True)
    (folder / "a.txt").write_bytes(b"12345")
    r = _run(
        tmp_path,
        f"""
        from core.local_fs import LocalFS
        items = {{i.name: i for i in LocalFS().list_dir({str(folder)!r})}}
        print(sorted(items), items["a.txt"].size, items["sub"].is_dir)
        """,
    )
    assert r.returncode == 0, r.stderr[-3000:]
    assert r.stdout.split() == ["['a.txt',", "'sub']", "5", "True"]


def test_happy_a_local_terminal_runs_a_command(tmp_path):
    r = _run(
        tmp_path,
        """
        import time
        from ui.terminal_widget import LocalTerminalSession
        s = LocalTerminalSession()
        s.start()
        s.write(b"echo axross-smoke-$((6*7))\\r\\n" if sys.platform != "win32"
                else b"echo axross-smoke-42\\r\\n")
        seen, end = b"", time.monotonic() + 20
        while b"axross-smoke-42" not in seen and time.monotonic() < end:
            seen += s.read()
        s.close()
        print("terminal ok" if b"axross-smoke-42" in seen else "terminal saw: %r" % seen[-300:])
        """,
    )
    assert r.returncode == 0, r.stderr[-3000:]
    assert "terminal ok" in r.stdout, r.stdout[-500:]


# --- sad ------------------------------------------------------------------


def test_sad_listing_a_missing_folder_is_an_oserror(tmp_path):
    r = _run(
        tmp_path,
        f"""
        from core.local_fs import LocalFS
        try:
            LocalFS().list_dir({str(tmp_path / "missing")!r})
        except OSError:
            print("refused")
        """,
    )
    assert r.returncode == 0, r.stderr[-3000:]
    assert "refused" in r.stdout


# --- edge -----------------------------------------------------------------


@pytest.mark.parametrize("name", ["äöü ß.txt", "测试 file.txt", "space in name.md"])
def test_edge_non_ascii_and_spaced_names_list_as_written(tmp_path, name):
    folder = tmp_path / "names"
    folder.mkdir()
    (folder / name).write_text("x", encoding="utf-8")
    r = _run(
        tmp_path,
        f"""
        from core.local_fs import LocalFS
        names = [i.name for i in LocalFS().list_dir({str(folder)!r})]
        sys.stdout.reconfigure(encoding="utf-8")
        print(names == [{name!r}])
        """,
    )
    assert r.returncode == 0, r.stderr[-3000:]
    assert r.stdout.strip() == "True"
