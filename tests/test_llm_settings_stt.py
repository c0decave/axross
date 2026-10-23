"""LLM profiles dialog: speech recognition per profile (local Whisper or an
OpenAI-compatible transcription server)."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import llm_profiles as LP  # noqa: E402

APP = QApplication.instance() or QApplication([])


@pytest.fixture
def dialog(tmp_path, monkeypatch):
    path = tmp_path / "llm.json"
    LP.LLMSettings([LP.LLMProfile(name="a", provider="openai",
                                  endpoint="http://127.0.0.1:1234/v1"),
                    LP.LLMProfile(name="b", provider="openai", stt_engine="server",
                                  stt_endpoint="http://127.0.0.1:9000/v1", stt_model="large")],
                   "a").save(path)
    monkeypatch.setattr(LP, "get_api_key", lambda n: "")
    warnings = []
    monkeypatch.setattr("ui.llm_settings_dialog.QMessageBox.warning",
                        lambda *a, **k: warnings.append(a[2]))
    from ui.llm_settings_dialog import LLMSettingsDialog

    dlg = LLMSettingsDialog(settings_path=path)
    dlg.warnings = warnings
    dlg.path = path
    yield dlg
    dlg.deleteLater()


def _saved(dlg):
    return {p["name"]: p for p in json.loads(dlg.path.read_text())["profiles"]}


def test_happy_each_profile_shows_its_recognition(dialog):
    dialog.profile_list.setCurrentRow(0)
    assert dialog.stt_engine_combo.currentData() == "local"
    assert not dialog.stt_endpoint_edit.isEnabled()
    models = [dialog.stt_model_combo.itemText(i) for i in range(dialog.stt_model_combo.count())]
    assert "base" in models and "small" in models
    dialog.profile_list.setCurrentRow(1)
    assert dialog.stt_engine_combo.currentData() == "server"
    assert dialog.stt_endpoint_edit.isEnabled()
    assert dialog.stt_endpoint_edit.text() == "http://127.0.0.1:9000/v1"
    assert dialog.stt_model_combo.currentText() == "large"


def test_happy_switching_to_a_server_is_saved(dialog):
    dialog.profile_list.setCurrentRow(0)
    dialog.stt_engine_combo.setCurrentIndex(dialog.stt_engine_combo.findData("server"))
    dialog.stt_endpoint_edit.setText("http://10.0.0.2:8000/v1")
    dialog.stt_model_combo.setEditText("whisper-1")
    assert dialog.save()
    a = _saved(dialog)["a"]
    assert (a["stt_engine"], a["stt_endpoint"], a["stt_model"]) == (
        "server", "http://10.0.0.2:8000/v1", "whisper-1")


def test_happy_local_small_model_is_saved(dialog):
    dialog.profile_list.setCurrentRow(1)
    dialog.stt_engine_combo.setCurrentIndex(dialog.stt_engine_combo.findData("local"))
    dialog.stt_model_combo.setEditText("small")
    assert dialog.save()
    b = _saved(dialog)["b"]
    assert (b["stt_engine"], b["stt_model"]) == ("local", "small")


def test_sad_an_invalid_transcription_endpoint_is_refused(dialog):
    dialog.profile_list.setCurrentRow(0)
    dialog.stt_engine_combo.setCurrentIndex(dialog.stt_engine_combo.findData("server"))
    dialog.stt_endpoint_edit.setText("ftp://x")
    assert not dialog.save()
    assert "transcription endpoint" in dialog.warnings[-1]


def test_sad_an_unknown_local_model_is_refused(dialog):
    dialog.profile_list.setCurrentRow(0)
    dialog.stt_model_combo.setEditText("gigantic")
    assert not dialog.save()
    assert "Whisper" in dialog.warnings[-1]


def test_edge_a_remote_transcription_server_is_flagged(dialog):
    dialog.profile_list.setCurrentRow(0)
    dialog.stt_engine_combo.setCurrentIndex(dialog.stt_engine_combo.findData("server"))
    dialog.stt_endpoint_edit.setText("https://stt.example.org/v1")
    assert not dialog.stt_remote_label.isHidden()
    assert "stt.example.org" in dialog.stt_remote_label.text()
    dialog.stt_endpoint_edit.setText("http://127.0.0.1:9000/v1")
    assert dialog.stt_remote_label.isHidden()
