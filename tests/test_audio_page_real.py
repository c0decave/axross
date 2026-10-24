"""Edit > Settings… > Audio against this machine's real audio server.

The page runs in a process of its own (a fresh QApplication, the user's
real runtime folder with the PipeWire / PulseAudio sockets - a test run
isolates XDG_RUNTIME_DIR): the real probe child, the real device list from
Qt, and the test tone played through QAudioSink on the real default output
(quietly: 15 %). Skipped where no audio server runs.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

pytest.importorskip("PyQt6.QtMultimedia", reason="QtMultimedia not installed")

from tests.test_audio_probe_real import RUNTIME, SERVERS  # noqa: E402

SCRIPT = textwrap.dedent("""
    import json, sys, time
    from pathlib import Path
    sys.path.insert(0, sys.argv[1])
    from PyQt6.QtWidgets import QApplication
    app = QApplication(["axross-audio-page-test"])
    from core import multimedia_probe as MPROBE
    from ui import audio_settings_page as AP

    def wait(cond, seconds):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            app.processEvents()
            if cond():
                return True
            time.sleep(0.01)
        return cond()

    page = AP.AudioPage(path=Path(sys.argv[2]))
    page.show()
    wait(lambda: MPROBE.cached() is not None and not page._checking, 60)
    result = MPROBE.cached()
    out = {"ok": bool(result and result.ok), "reason": result.reason if result else "",
           "status": page.status_label.text(), "active": page.active_label.text(),
           "outputs": [page.output_combo.itemData(i) for i in range(page.output_combo.count())],
           "probe_outputs": [d.device_id for d in (result.output_devices if result else ())]}
    if out["ok"]:
        page.output_combo.setCurrentIndex(0)  # System default
        page.output_slider.setValue(15)
        page.tone_button.click()
        wait(lambda: page.test_label.text() == "Test tone played."
             or page.test_label.text().startswith("No sound"), 20)
        out["tone"] = page.test_label.text()
    page.shutdown()
    print("RESULT " + json.dumps(out), flush=True)
""")


@pytest.mark.skipif(not any(SERVERS.values()), reason=f"no audio server in {RUNTIME}")
def test_happy_e2e_the_real_page_lists_the_real_devices_and_plays_the_tone(tmp_path):
    env = {k: v for k, v in os.environ.items() if k != "QT_AUDIO_BACKEND"}
    env.update(XDG_RUNTIME_DIR=RUNTIME, QT_QPA_PLATFORM="offscreen")
    env.pop("DISPLAY", None)
    env.pop("WAYLAND_DISPLAY", None)
    script = tmp_path / "page.py"
    script.write_text(SCRIPT, encoding="utf-8")
    run = subprocess.run([sys.executable, str(script), str(ROOT), str(tmp_path / "audio.json")],
                         capture_output=True, text=True, timeout=120, env=env, cwd=str(tmp_path))
    line = next((ln for ln in run.stdout.splitlines() if ln.startswith("RESULT ")), "")
    assert line, f"rc={run.returncode}\n{run.stdout[-2000:]}\n{run.stderr[-3000:]}"
    out = json.loads(line[len("RESULT "):])
    print(out)  # the evidence in a -s run
    assert out["ok"], out["reason"]
    assert out["status"].startswith("Audio works: "), out
    assert out["active"] in ("PipeWire", "PulseAudio"), out
    assert out["probe_outputs"], "the server lists no output device"
    # Qt's own list in the GUI process holds what the probe's child saw.
    assert set(out["probe_outputs"]) <= set(out["outputs"][1:]), out
    assert out["outputs"][0] == ""
    assert out["tone"] == "Test tone played.", out
