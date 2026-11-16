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


@pytest.mark.parametrize("module", ["ui.media_player_app", "ui.system_info_app", "ui.amp_app", "ui.markdown_app"])
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
        # In the command line's order (tests/test_media_player_app_argument_order.py).
        assert [os.path.basename(p) for p in paths[:2]] == ["a.mp3", "b.ogg"]
        assert paths[2] == "https://radio.example.org/live"
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


def test_happy_amp_shows_player_mixer_and_bluetooth_and_the_sound_menu_opens_the_mixer(tmp_path, monkeypatch):
    """axross-amp: the Media Player, the Audio Mixer and Bluetooth as tabs of
    one window; the mixer and Bluetooth are built only when first shown, and
    the player's *Audio Mixer...* shows the mixer's tab."""
    from PyQt6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication([])
    monkeypatch.setenv("HOME", str(tmp_path))
    from resources.extensions import audio_mixer as AM
    from resources.extensions import bluetooth as BTX
    from ui import amp_app as A

    started = []

    class FakeHost(BTX.BluetoothHost.__mro__[1]):  # a plain QWidget
        def __init__(self, source, panel_options=None):
            super().__init__()
            self.options = panel_options

        def start(self):
            started.append(True)

        def shutdown(self):
            started.append("down")

    monkeypatch.setattr(BTX, "BluetoothHost", FakeHost)
    monkeypatch.setattr(AM, "make_system_mixer", lambda: None)
    monkeypatch.setattr("resources.extensions.media_player.state_file", lambda: tmp_path / "mp.json")
    amp = A.AmpWindow(app, [])
    try:
        assert [amp.tabs.tabText(i) for i in range(amp.tabs.count())] == \
            ["Media Player", "Audio Mixer", "Bluetooth"]
        assert amp.mixer is None and amp.bluetooth is None
        amp.player._open_mixer()  # the sound menu's Audio Mixer...
        assert amp.tabs.currentIndex() == 1 and isinstance(amp.mixer, AM.MixerPanel)
        amp.tabs.setCurrentIndex(2)
        assert isinstance(amp.bluetooth, FakeHost) and started == [True]
        assert "presence_path" in amp.bluetooth.options
    finally:
        amp.shutdown()
        amp.window.close()
        amp.window.deleteLater()
    assert started[-1] == "down"


def test_sad_without_the_voice_parts_the_bluetooth_sound_tests_say_so(monkeypatch):
    """An export without ui.audio_settings_page (axross-amp) offers no test
    sound: an OSError the device dialog shows, never an ImportError."""
    import builtins

    from ui import bluetooth_details as BD

    real = builtins.__import__

    def no_audio_page(name, *args, **kwargs):
        if name == "ui" and args and args[2] and "audio_settings_page" in args[2]:
            raise ImportError("not exported")
        if name == "ui.audio_settings_page":
            raise ImportError("not exported")
        return real(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_audio_page)
    for call in (lambda: BD._default_player("x"), lambda: BD._default_recorder("x"), BD.test_sound):
        with pytest.raises(OSError):
            call()


def test_happy_markdown_opens_files_edits_with_the_preview_and_welcomes_without_one(tmp_path, monkeypatch):
    """axross-markdown: a viewer per file, Edit opens the editor with the
    rendering beside the text, no file shows a viewer that offers Open..."""
    import time

    from PyQt6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication([])
    monkeypatch.setenv("HOME", str(tmp_path))
    from ui import markdown_app as A

    (tmp_path / "a.md").write_text("# A\n\n## B\n")
    program = A.MarkdownApp()
    viewer = program.open_paths([str(tmp_path / "a.md")])[0]
    end = time.time() + 5
    while not viewer.loaded_once and time.time() < end:
        app.processEvents()
    assert viewer.view.headings() == ["A", "B"] and viewer.open_button is not None
    editor = program.edit(viewer.backend, viewer.path)
    end = time.time() + 5
    while editor.current_tab() is None and time.time() < end:
        app.processEvents()
    tab = editor.current_tab()
    assert tab.previewing and tab.preview.headings() == ["A", "B"]
    welcome = program.open_paths([])[0]
    assert welcome.path == "" and welcome.loaded_once and not welcome.edit_button.isEnabled()
    # Open... replaces the viewer without a file by the files chosen.
    monkeypatch.setattr("PyQt6.QtWidgets.QFileDialog.getOpenFileNames",
                        lambda *a, **k: ([str(tmp_path / "a.md")], ""))
    opened = program.ask_open(welcome)
    assert len(opened) == 1 and opened[0].path == str(tmp_path / "a.md")
    for window in program.viewers:
        window.close()
    tab.editor.document().setModified(False)
    editor.close()
