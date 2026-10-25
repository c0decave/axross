"""The Analysis (sift) settings (core.analysis_settings): one JSON file, every
value checked by sift's own rules, a broken file kept aside before a save."""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import analysis_settings as AS  # noqa: E402

sift_config = pytest.importorskip("sift.config")


# -- happy -------------------------------------------------------------------------------------


def test_happy_defaults_are_sifts_own_and_auto_analysis_is_on():
    s = AS.AnalysisSettings()
    config = sift_config.Config()
    assert s.auto_analyse is True
    assert s.llm_profile == ""
    assert s.max_bytes == config.max_bytes
    assert s.time_budget == config.time_budget
    assert s.vision is config.vision
    assert s.context_tokens == config.context_tokens
    assert s.tags == config.tags
    assert s.categories == config.categories
    assert s.cache is config.cache
    assert list(AS.FIELDS) == [k for k in s.to_dict() if k != "version"]


def test_happy_the_ranges_are_sifts_validation():
    limits = AS.limits()
    low, _high, _flag, unset = sift_config._RANGES["max_bytes"]
    assert limits["max_bytes"][0] == low
    low, _high, _flag, unset = sift_config._RANGES["context_tokens"]
    assert limits["context_tokens"][0] == low and AS.CONTEXT_FROM_SERVER == unset
    assert limits["tags"] == (0, sift_config.MAX_TAGS)
    # sift's own refusals are axross's refusals, with sift's words.
    assert AS.problem("context_tokens", low - 1)
    assert AS.problem("context_tokens", unset) == ""
    assert AS.problem("tags", sift_config.MAX_TAGS + 1)
    assert AS.problem("tags", sift_config.MAX_TAGS) == ""
    assert "comma" in AS.problem("categories", ["a,b"])


@pytest.mark.parametrize("name,value", [
    ("auto_analyse", False), ("llm_profile", "local"), ("max_bytes", 1_000_000),
    ("max_bytes", 1), ("time_budget", 5.0), ("time_budget", 3600), ("vision", False),
    ("context_tokens", 8192), ("context_tokens", 0), ("tags", 5), ("tags", 0),
    ("categories", ["Invoices", "Contracts"]), ("categories", []), ("cache", False),
])
def test_happy_every_value_round_trips_through_set_get_save_load(tmp_path, name, value):
    path = tmp_path / "analysis.json"
    s = AS.AnalysisSettings()
    s.set(name, value)
    assert s.get(name) == value
    s.save(path)
    loaded = AS.AnalysisSettings.load(path)
    assert loaded.get(name) == value
    assert loaded.file_not_fully_loaded is False


def test_happy_the_file_is_private_and_lives_in_the_config_folder(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    assert AS.settings_file() == tmp_path / ".config" / "axross" / "analysis.json"
    AS.AnalysisSettings(tags=3).save()
    mode = stat.S_IMODE(os.stat(AS.settings_file()).st_mode)
    assert mode == 0o600
    assert json.loads(AS.settings_file().read_text())["tags"] == 3


def test_happy_run_options_carry_what_the_worker_hands_to_sift():
    s = AS.AnalysisSettings(max_bytes=2_000_000, time_budget=12.0, vision=False,
                            context_tokens=4096, tags=4, categories=["A", "B"], cache=False)
    assert s.run_options() == {
        "time_budget": 12.0, "max_bytes": 2_000_000, "vision": False,
        "context_tokens": 4096, "tags": 4, "categories": ["A", "B"], "cache": False,
    }


def test_happy_the_cache_folder_follows_xdg(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
    assert AS.cache_dir() == tmp_path / "xdg" / "axross" / "sift"
    monkeypatch.setenv("XDG_CACHE_HOME", "relative/ignored")
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    assert AS.cache_dir() == tmp_path / ".cache" / "axross" / "sift"


def test_happy_clear_cache_removes_sifts_entries(tmp_path):
    from sift.cache import SummaryCache

    cache = SummaryCache(directory=tmp_path)
    cache.put("ab" + "0" * 62, {"summary": "x"})
    cache.put("cd" + "1" * 62, {"summary": "y"})
    (tmp_path / "keep.txt").write_text("not sift's")
    assert AS.clear_cache(tmp_path) == 2
    assert [p.name for p in tmp_path.iterdir()] == ["keep.txt"]


def test_happy_sift_status_names_the_version():
    import sift

    assert AS.sift_status() == (True, sift.__version__)


# -- sad ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("name,value", [
    ("auto_analyse", "yes"), ("llm_profile", None), ("max_bytes", 0), ("max_bytes", -5),
    ("max_bytes", True), ("max_bytes", 1.5), ("max_bytes", AS.MAX_BYTES_CEILING + 1),
    ("time_budget", 0), ("time_budget", -1), ("time_budget", 3601), ("time_budget", "60"),
    ("time_budget", float("nan")), ("vision", 1), ("context_tokens", 255),
    ("context_tokens", -1), ("context_tokens", "8k"), ("tags", -1), ("tags", 33),
    ("tags", True), ("categories", "Invoices"), ("categories", ["a", "A"]),
    ("categories", [""]), ("categories", ["x" * 61]), ("categories", [3]), ("cache", None),
])
def test_sad_invalid_values_are_refused(name, value):
    s = AS.AnalysisSettings()
    assert AS.problem(name, value)
    with pytest.raises(ValueError):
        s.set(name, value)
    assert s.get(name) == getattr(AS.AnalysisSettings(), name)


def test_sad_an_unknown_name_is_a_key_error():
    with pytest.raises(KeyError):
        AS.AnalysisSettings().set("max_files", 3)
    with pytest.raises(KeyError):
        AS.AnalysisSettings().get("max_files")


@pytest.mark.parametrize("content", [b"{not json", b"[1, 2]", b"\xff\xfe", b'"text"'])
def test_sad_a_broken_file_gives_defaults_and_a_save_keeps_it_aside(tmp_path, content):
    path = tmp_path / "analysis.json"
    path.write_bytes(content)
    s = AS.AnalysisSettings.load(path)
    assert s == AS.AnalysisSettings()
    assert s.file_not_fully_loaded is True
    s.set("tags", 2)
    s.save(path)
    kept = [p for p in tmp_path.iterdir() if ".unreadable-" in p.name]
    assert len(kept) == 1 and kept[0].read_bytes() == content
    assert stat.S_IMODE(os.stat(kept[0]).st_mode) == 0o600
    assert AS.AnalysisSettings.load(path).tags == 2


def test_sad_an_invalid_value_keeps_its_default_and_the_file_is_kept_aside(tmp_path):
    path = tmp_path / "analysis.json"
    path.write_text(json.dumps({"tags": 99, "max_bytes": 5_000_000, "vision": "no"}))
    s = AS.AnalysisSettings.load(path)
    assert (s.tags, s.max_bytes, s.vision) == (0, 5_000_000, True)
    assert s.file_not_fully_loaded is True
    s.save(path)
    assert any(".unreadable-" in p.name for p in tmp_path.iterdir())


def test_sad_no_save_when_the_broken_file_cannot_be_kept(tmp_path):
    path = tmp_path / "analysis.json"
    path.write_text("{broken")
    s = AS.AnalysisSettings.load(path)
    with mock.patch.object(AS, "keep_unreadable_copy", return_value=False):
        with pytest.raises(OSError):
            s.save(path)
    assert path.read_text() == "{broken"


def test_sad_without_sift_the_status_says_so_and_clearing_does_nothing(tmp_path):
    with mock.patch.dict(sys.modules, {"sift": None, "sift.cache": None, "sift.config": None,
                                       "sift.categories": None}):
        assert AS.sift_status() == (False, "")
        assert AS.clear_cache(tmp_path) == 0
        # The values are still type-checked, with the documented fallback ranges.
        assert AS.problem("max_bytes", 0)
        assert AS.problem("tags", 99)
        assert AS.problem("tags", 3) == ""


# -- edge --------------------------------------------------------------------------------------


def test_edge_a_missing_file_is_defaults_and_not_kept_aside(tmp_path):
    path = tmp_path / "analysis.json"
    s = AS.AnalysisSettings.load(path)
    assert s == AS.AnalysisSettings() and s.file_not_fully_loaded is False
    s.save(path)
    assert [p.name for p in tmp_path.iterdir()] == ["analysis.json"]


def test_edge_unknown_keys_of_a_newer_version_are_ignored(tmp_path):
    path = tmp_path / "analysis.json"
    path.write_text(json.dumps({"version": 9, "tags": 2, "future": True}))
    s = AS.AnalysisSettings.load(path)
    assert s.tags == 2 and s.file_not_fully_loaded is False


def test_edge_the_fallback_ranges_are_sifts_ranges():
    """Without sift (axross-slim) the page is off, but a value is still
    checked: the fallback numbers are held to sift's here."""
    assert AS._FALLBACK_LIMITS["max_bytes"][0] == sift_config._RANGES["max_bytes"][0]
    assert AS._FALLBACK_LIMITS["context_tokens"][0] == sift_config._RANGES["context_tokens"][0]
    assert AS._FALLBACK_LIMITS["tags"] == (0, sift_config.MAX_TAGS)


def test_edge_the_ceilings_derive_from_the_worker():
    from core import analysis_worker as AW

    assert AS.MAX_BYTES_CEILING == AW.ADDRESS_SPACE_LIMIT // 2
    assert AS.limits()["max_bytes"][1] == AS.MAX_BYTES_CEILING
    # A larger time budget gets as much CPU time as the default's ratio gives.
    assert AW.cpu_seconds_for(AW.DEFAULT_TIME_BUDGET) == AW.DEFAULT_CPU_SECONDS
    assert AW.cpu_seconds_for(AS.TIME_BUDGET_RANGE[1]) >= AS.TIME_BUDGET_RANGE[1]
    assert AW.cpu_seconds_for(1) == AW.DEFAULT_CPU_SECONDS


def test_edge_the_categories_are_a_copy():
    s = AS.AnalysisSettings()
    cats = ["A"]
    s.set("categories", cats)
    cats.append("B")
    assert s.categories == ["A"]
    assert s.run_options()["categories"] is not s.categories
