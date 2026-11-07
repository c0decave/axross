"""Help > Features…: the voice packages (pip extra axross[voice]) and one
entry per voice and speech recognition model, downloaded with pinned
SHA-256 sums into ~/.local/share/axross/voice/."""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import features as F  # noqa: E402
from core import voice_models as VM  # noqa: E402

APP = QApplication.instance() or QApplication([])


@pytest.fixture
def share(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "share"))
    return tmp_path / "share" / "axross" / "voice"


def _install_fake(model: VM.VoiceModel) -> None:
    folder = VM.model_dir(model)
    folder.mkdir(parents=True, exist_ok=True)
    for f in model.files:
        with open(folder / f.name, "wb") as out:
            out.truncate(f.size)


def test_happy_every_model_is_a_feature_of_the_voice_group(share):
    found = {f.key: f for f in F.collect()}
    for model in VM.MODELS:
        feature = found[f"voice:{model.id}"]
        assert feature.group == "Voice" and feature.download == model.id
        assert not feature.available
        assert "MB" in F.how_to_get(feature)
    assert found["extra:voice"].group == "Voice"
    assert found["extra:voice"].requirements == F.EXTRAS["voice"]


def test_happy_an_installed_model_is_available(share):
    _install_fake(VM.model("piper-en-ryan"))
    found = {f.key: f for f in F.collect()}
    assert found["voice:piper-en-ryan"].available
    assert not found["voice:piper-en-lessac"].available


def test_edge_the_voice_extra_pins_the_checked_versions():
    reqs = dict(r.split(">=") for r in F.EXTRAS["voice"])
    assert reqs == {"piper-tts": "1.8.0", "onnxruntime": "1.31.0", "faster-whisper": "1.2.1",
                    "ctranslate2": "4.8.3"}


def test_sad_the_voice_extra_is_not_part_of_all():
    """piper-tts is GPL-3.0-or-later: it is chosen, never pulled in by "all"."""
    import tomllib

    data = tomllib.loads((Path(__file__).resolve().parent.parent / "pyproject.toml").read_text())
    extras = data["project"]["optional-dependencies"]
    assert not set(extras["voice"]) & set(extras["all"])


# -- the window -------------------------------------------------------------------------------


def _dialog(downloader):
    from ui.features_dialog import FeaturesDialog

    dlg = FeaturesDialog(downloader=downloader)
    dlg.show()
    APP.processEvents()
    assert _wait(lambda: dlg.loaded, 30)  # asked off the GUI thread
    return dlg


def _row(dlg, key):
    for row in range(dlg.table.rowCount()):
        if dlg.feature_at(row).key == key:
            return row
    raise AssertionError(key)


def _wait(cond, seconds=5.0):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        APP.processEvents()
        if cond():
            return True
        time.sleep(0.01)
    return False


def test_happy_e2e_download_selected_fetches_and_refreshes(share):
    got = []

    def downloader(model, progress, cancel):
        got.append(model.id)
        progress(model.size // 2, model.size)
        _install_fake(model)
        return VM.model_dir(model)

    dlg = _dialog(downloader)
    try:
        dlg.table.selectRow(_row(dlg, "voice:piper-de-kerstin"))
        assert dlg.download_models_button.isEnabled()
        dlg.download_models_button.click()
        assert _wait(lambda: "downloaded" in dlg.status.text().lower())
        # The window asks again when the downloads are done (off the GUI thread).
        assert _wait(lambda: dlg.loaded and dlg.feature_at(
            _row(dlg, "voice:piper-de-kerstin")).available)
        assert got == ["piper-de-kerstin"]
        assert dlg.feature_at(_row(dlg, "voice:piper-de-kerstin")).available
        assert "Kerstin" in dlg.log.toPlainText()
    finally:
        dlg.close()


def test_sad_e2e_a_refused_download_is_shown(share):
    def downloader(model, progress, cancel):
        raise VM.DownloadError("de_DE-thorsten-high.onnx: the SHA-256 differs - refused")

    dlg = _dialog(downloader)
    try:
        dlg.table.selectRow(_row(dlg, "voice:piper-de-thorsten"))
        dlg.download_models_button.click()
        assert _wait(lambda: "failed" in dlg.status.text().lower())
        assert "SHA-256" in dlg.log.toPlainText()
        assert not dlg.feature_at(_row(dlg, "voice:piper-de-thorsten")).available
    finally:
        dlg.close()


def test_edge_e2e_nothing_to_download_for_installed_or_pip_rows(share):
    _install_fake(VM.model("whisper-base"))
    dlg = _dialog(lambda *a: None)
    try:
        dlg.table.selectRow(_row(dlg, "voice:whisper-base"))
        assert not dlg.download_models_button.isEnabled()
        dlg.table.selectRow(_row(dlg, "extra:archive"))
        assert not dlg.download_models_button.isEnabled()
    finally:
        dlg.close()


def test_edge_e2e_closing_cancels_a_running_download(share):
    import threading

    started, cancelled = threading.Event(), []

    def downloader(model, progress, cancel):
        started.set()
        while not cancel.wait(0.02):
            pass
        cancelled.append(model.id)
        raise VM.DownloadCancelled("cancelled")

    dlg = _dialog(downloader)
    dlg.table.selectRow(_row(dlg, "voice:whisper-small"))
    dlg.download_models_button.click()
    assert started.wait(5)
    dlg.close()
    assert _wait(lambda: cancelled == ["whisper-small"])
