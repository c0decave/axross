"""The Media Player and System Information as programs of their own
(ui/media_player_app.py, ui/system_info_app.py on ui/standalone_app.py):
each starts, shows its window and ends cleanly; the player adds what the
command line names; ``axross-system-info --json FILE`` writes the report.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets")


def _run(module: str, home: Path, *args: str, smoke_ms: int | None = 1500) -> subprocess.CompletedProcess:
    env = dict(os.environ, HOME=str(home), QT_QPA_PLATFORM="offscreen",
               PYTHONPATH=str(ROOT))
    if smoke_ms is not None:
        env["AXROSS_SMOKE_MS"] = str(smoke_ms)
    return subprocess.run([sys.executable, "-m", module, *args], cwd=ROOT, env=env,
                          capture_output=True, text=True, timeout=120)


@pytest.mark.parametrize("module", ["ui.media_player_app", "ui.system_info_app"])
def test_happy_the_program_starts_and_ends_cleanly(tmp_path, module):
    result = _run(module, tmp_path)
    assert result.returncode == 0, result.stderr[-2000:]
    assert "Unhandled exception" not in result.stderr


def test_happy_system_info_writes_its_json_report(tmp_path):
    target = tmp_path / "report.json"
    result = _run("ui.system_info_app", tmp_path, "--json", str(target), smoke_ms=None)
    assert result.returncode == 0, result.stderr[-2000:]
    data = json.loads(target.read_text(encoding="utf-8"))
    assert data["identifiers"] == "hidden" and len(data["sections"]) > 5


def test_happy_the_player_adds_files_folders_and_streams_from_the_command_line(tmp_path):
    from PyQt6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication([])
    from tests.test_media_player_review_fixes import MP, FakeEngine
    from ui import media_player_app as A

    music = tmp_path / "music"
    music.mkdir()
    for name in ("a.mp3", "b.ogg", "notes.txt"):
        (music / name).write_bytes(b"x")
    engine = FakeEngine()
    panel = MP.PlayerPanel(engine=engine, state_path=str(tmp_path / "s.json"))
    import resources.extensions.media_player as real

    try:
        # The app imports the extension by its package path; the test's copy
        # is the same file.
        assert real.is_stream("https://radio.example.org/live")
        count = A.add_arguments(panel, [str(music), "https://radio.example.org/live",
                                        "--ignored-flag"])
        app.processEvents()
        assert count == 3
        paths = [panel.playlist.item(i).data(MP._PATH_ROLE) for i in range(panel.playlist.count())]
        assert paths[0] == "https://radio.example.org/live"
        assert sorted(os.path.basename(p) for p in paths[1:]) == ["a.mp3", "b.ogg"]
        assert engine.state == "playing" and engine.path == paths[0]
    finally:
        panel.shutdown()
        panel.deleteLater()


def test_sad_the_probe_child_mode_does_not_open_a_window(tmp_path):
    from ui.standalone_app import PROBE_ARG

    result = _run("ui.media_player_app", tmp_path, PROBE_ARG, smoke_ms=None)
    # The child answers on stdout (ok or why not) and never shows a window.
    assert result.stdout.strip()
    assert "Unhandled exception" not in result.stderr


def test_sad_a_script_runs_only_for_the_builds_check(tmp_path):
    from ui import standalone_app as SA

    marker = tmp_path / "ran"
    script = tmp_path / "check.py"
    script.write_text(f"open({str(marker)!r}, 'w').write('x')\n")
    os.environ.pop(SA.BUNDLE_CHECK_ENV, None)
    assert SA.bundle_check(["prog", "--script", str(script)]) is None   # a user's call: no
    assert not marker.exists()
    os.environ[SA.BUNDLE_CHECK_ENV] = "1"
    try:
        assert SA.bundle_check(["prog", "--script", str(script)]) == 0
        assert SA.bundle_check(["prog", "--other", str(script)]) is None
    finally:
        os.environ.pop(SA.BUNDLE_CHECK_ENV, None)
    assert marker.exists()
