"""The LLM profile dialog offers known endpoints and orders fetched models.

Reported: every new profile meant typing the same endpoint again; the
fetched model list should show the loaded models first with a green dot,
then all others by name, or by size with a checkbox.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import agent as A  # noqa: E402
from core import llm_profiles as LP  # noqa: E402

APP = QApplication.instance() or QApplication([])


@pytest.fixture
def dialog(tmp_path):
    from ui.llm_settings_dialog import LLMSettingsDialog

    with mock.patch.object(LP, "get_api_key", return_value=""):
        d = LLMSettingsDialog(settings_path=tmp_path / "llm.json")
        yield d
        d.deleteLater()


def _ids(combo) -> list[str]:
    return [combo.itemText(i) for i in range(combo.count())]


def test_happy_a_new_profile_offers_the_endpoints_already_used(dialog):
    dialog.add_profile()
    dialog.name_edit.setText("one")
    dialog.endpoint_edit.setText("http://gpu-box:11434")
    dialog.add_profile()
    offered = _ids(dialog.endpoint_combo)
    assert offered[0] == "http://gpu-box:11434"
    for default in LP.DEFAULT_ENDPOINTS.values():
        assert default in offered
    assert len(offered) == len(set(offered))
    assert dialog.endpoint_edit.text() == ""  # offered, not filled in


def test_happy_picking_an_offered_endpoint_sets_the_profile(dialog):
    dialog.add_profile()
    dialog.name_edit.setText("x")
    combo = dialog.endpoint_combo
    combo.setCurrentIndex(combo.findText(LP.DEFAULT_ENDPOINTS["lmstudio"]))
    assert dialog._current.endpoint == LP.DEFAULT_ENDPOINTS["lmstudio"]


MODELS = [
    A.ModelEntry("zeta", size=5_000, loaded=False),
    A.ModelEntry("Alpha", size=9_000, loaded=False),
    A.ModelEntry("mid", size=None, loaded=False),
    A.ModelEntry("beta", size=1_000, loaded=True),
    A.ModelEntry("tiny", size=10, loaded=False),
]


def _fetched(dialog):
    dialog.add_profile()
    dialog.name_edit.setText("p")
    dialog._on_models(dialog._fetch_token, MODELS, "")


def test_happy_loaded_first_with_a_green_dot_then_by_name(dialog):
    _fetched(dialog)
    combo = dialog.model_combo
    assert _ids(combo) == ["beta", "Alpha", "mid", "tiny", "zeta"]
    assert not combo.itemData(0, Qt.ItemDataRole.DecorationRole).isNull()
    assert combo.itemData(1, Qt.ItemDataRole.DecorationRole) is None


def test_happy_by_size_keeps_loaded_first_and_unknown_sizes_last(dialog):
    _fetched(dialog)
    dialog.model_combo.setEditText("zeta")
    dialog.size_order_check.setChecked(True)
    assert _ids(dialog.model_combo) == ["beta", "tiny", "zeta", "Alpha", "mid"]
    assert dialog.model_combo.currentText() == "zeta"  # the choice stays
    dialog.size_order_check.setChecked(False)
    assert _ids(dialog.model_combo) == ["beta", "Alpha", "mid", "tiny", "zeta"]
