"""Without a Qt Multimedia backend that decodes audio the Media Player says
so and builds no engine.

Found while checking a crash in the full suite: with Qt Multimedia but no
backend plugin ("No QtMultimedia backends found" - Qt's FFmpeg plugin
missing, as in a slim build or a distribution's Qt without it), a
QAudioDecoder that was given a file and started, then deleted in its
thread, crashes the process when that thread ends (segfault, 30 of 30
runs of test_edge_the_exit_handler_closes_engines_and_ends_the_threads;
reduced to six lines of plain PyQt: source, start(), delete, quit the
thread). The Media Player's exit handler does exactly that after a track
was tried, so quitting axross crashed. QAudioDecoder.isSupported() says
True there all the same; the list of codecs it can decode is empty.

The multimedia probe's child now reports whether any audio codec can be
decoded (ProbeResult.decoding), and the Media Player shows why it is off
instead of building an engine. The other users of the probe (audio
routing, voice, Bluetooth, the media viewer) are unchanged: playing
sound needs no decoder.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtMultimedia", exc_type=ImportError)  # or no libpulse.so.0

from core import multimedia_probe as MPROBE  # noqa: E402
from tests.media_testkit import multimedia_backend_here  # noqa: E402
from tests.test_media_player_late_engine import (  # noqa: E402
    MP,
    late_panel,
    transport_enabled,
)

NO_DECODER = MPROBE.ProbeResult(ok=True, decoding=False)


# -- happy ------------------------------------------------------------------------------------


def test_happy_a_probe_with_decoders_builds_the_engine():
    panel, background, made, _ = late_panel(MPROBE.ProbeResult(ok=True, decoding=True))
    try:
        background.run_all()
        assert len(made) == 1 and panel.engine_ready
    finally:
        panel.close()


def test_happy_e2e_the_child_reports_what_this_qt_decodes():
    """The real probe child, against this process's own answer: it says
    False exactly where Qt lists no audio codec to decode."""
    result = MPROBE.run_probe()
    assert result.ok, result.reason
    assert result.decoding is multimedia_backend_here()


# -- sad --------------------------------------------------------------------------------------


def test_sad_without_a_decoder_the_panel_says_why_and_builds_nothing():
    panel, background, made, _ = late_panel(NO_DECODER)
    failures: list[str] = []
    panel.engine_failed.connect(failures.append)
    try:
        background.run_all()
        assert made == []  # no engine: no decoder that could crash the exit
        assert not panel.engine_ready
        assert transport_enabled(panel) == [False] * 4
        text = panel.audio_status.text()
        assert "decode" in text and "FFmpeg" in text
        assert "The Media Player is off; everything else works." in text
        assert failures == [text]
        assert panel.retry_button.isVisible() or not panel.isVisible()
    finally:
        panel.close()


def test_sad_the_probe_result_stays_ok_for_the_other_users():
    """Voice, audio routing and Bluetooth play sound: no decoder needed."""
    assert NO_DECODER.ok
    assert MPROBE.unavailable_text(NO_DECODER) == ""


# -- edge -------------------------------------------------------------------------------------


@pytest.mark.parametrize("reply, decoding", [
    ({"ok": True, "decoding": False}, False),
    ({"ok": True, "decoding": True}, True),
    ({"ok": True}, True),  # an older child: no claim, as before
    ({"ok": True, "decoding": "no"}, True),  # not a bool: no claim
])
def test_edge_the_reply_is_read_strictly(reply, decoding):
    assert MPROBE._result_from_reply(reply, 0.1).decoding is decoding


def test_edge_the_childs_reply_line_carries_it():
    step, reply = MPROBE._parse("noise\n" + json.dumps({"step": "decoder"}) + "\n"
                                + json.dumps({"ok": True, "decoding": False}) + "\n")
    assert step == "decoder" and reply == {"ok": True, "decoding": False}
    assert MPROBE._result_from_reply(reply, 0.0).decoding is False


def test_edge_a_retry_that_finds_a_decoder_builds_the_engine():
    panel, background, made, _ = late_panel(NO_DECODER)
    try:
        background.run_all()
        assert made == []
        panel._audio_probe = lambda: MPROBE.ProbeResult(ok=True)  # a plugin installed meanwhile
        panel.retry_audio()
        background.run_all()
        assert len(made) == 1 and panel.engine_ready
    finally:
        panel.close()


def test_edge_the_engine_module_names_the_reason_once():
    assert "FFmpeg" in MP.NO_DECODER_REASON
