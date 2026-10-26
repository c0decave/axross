"""scripts/coverage_matrix.py - the generator of docs/TEST_COVERAGE_MATRIX.md.

The feature map is the part that ages: a renamed test, a moved module or a
new module nobody mapped would leave the matrix claiming what is no longer
true. ``check()`` is the completeness gate (the settings matrix has the same
kind of gate for its widgets); it runs here on the real tree.
"""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import coverage_matrix as CM  # noqa: E402


# ------------------------------------------------------------- the gate
def test_happy_the_feature_map_of_this_tree_is_current():
    assert CM.check() == []


def test_happy_every_module_is_mapped_or_named_infrastructure():
    mapped = {m for f in CM.FEATURES for m in CM.expand(f.modules)}
    assert set(CM.all_modules()) <= mapped | set(CM.INFRASTRUCTURE)


def test_happy_the_readme_main_features_have_a_row():
    keys = {f.key for f in CM.FEATURES}
    for key in (
        "find-files",
        "tags",
        "trail",
        "archive-browse",
        "encryption",
        "fuse-mount",
        "reverse-serve",
        "terminal",
        "scripting",
        "mcp-server",
        "agent",
        "voice",
        "sift-analysis",
        "extensions",
        "self-update",
        "proxy",
        "security",
        "xlink",
    ):
        assert key in keys


def test_sad_a_renamed_e2e_test_fails_the_gate(monkeypatch):
    feat = CM.FEATURES[0]
    broken = CM.Feature(
        feat.group,
        feat.key,
        feat.name,
        feat.modules,
        (("tests/test_quick_connect_menu.py::test_does_not_exist", "ui"),),
    )
    monkeypatch.setattr(CM, "FEATURES", (broken,) + CM.FEATURES[1:])
    problems = CM.check()
    assert any("test_does_not_exist does not exist" in p for p in problems)


def test_sad_an_unknown_e2e_kind_and_a_missing_module_fail_the_gate(monkeypatch):
    feat = CM.FEATURES[0]
    broken = CM.Feature(
        feat.group,
        feat.key,
        feat.name,
        feat.modules + ("core/gone.py",),
        ((feat.e2e[0][0], "manual"),),
    )
    monkeypatch.setattr(CM, "FEATURES", (broken,) + CM.FEATURES[1:])
    problems = CM.check()
    assert any("unknown kind manual" in p for p in problems)
    assert any("core/gone.py does not exist" in p for p in problems)


def test_sad_an_unmapped_new_module_fails_the_gate(monkeypatch):
    real = CM.all_modules
    monkeypatch.setattr(CM, "all_modules", lambda root=CM.ROOT: real(root) + ["core/brand_new.py"])
    assert (
        "core/brand_new.py belongs to no feature and is not named in INFRASTRUCTURE" in CM.check()
    )


def test_edge_a_module_in_two_features_fails_the_gate(monkeypatch):
    a, b = CM.FEATURES[0], CM.FEATURES[1]
    twice = CM.Feature(b.group, b.key, b.name, b.modules + (a.modules[0],), b.e2e)
    monkeypatch.setattr(CM, "FEATURES", (a, twice) + CM.FEATURES[2:])
    assert any(f"{a.modules[0]} is in {a.key} and {b.key}" == p for p in CM.check())


def test_edge_a_parametrized_node_id_is_found_by_its_function():
    index = CM.SuiteIndex()
    nodeid = (
        "tests/test_audio_settings_page_real.py::"
        "test_happy_e2e_record_and_play_back_goes_from_microphone_to_speaker"
    )
    assert index.node_exists(nodeid + "[pipewire]")
    assert not index.node_exists("tests/no_such_file.py::test_x")


# ------------------------------------------------------- classification
@pytest.mark.parametrize(
    "name, kind",
    [
        ("test_happy_a_snapshot_records_every_file", "happy"),
        ("test_sad_export_refuses_a_symlinked_destination", "sad"),
        ("test_edge_max_files_truncates", "edge"),
        ("test_happy_e2e_create_xlink_from_the_menu", "happy"),
        ("test_live_e2e_open_a_hit_in_a_new_pane", "happy"),
        ("test_sad_e2e_cancel_in_the_window_is_no_answer", "sad"),
        ("test_bruteforce_refuses_without_authorized", "sad"),  # old name, keyword
        ("test_empty_partial_is_ignored", "edge"),  # old name, keyword
        ("test_snapshot_creates_record", "happy"),  # old name, no keyword
    ],
)
def test_happy_sad_edge_classification(name, kind):
    assert CM.classify(name) == kind


def test_edge_a_catch_all_file_counts_only_tests_that_name_the_feature(tmp_path):
    (tmp_path / "core").mkdir()
    (tmp_path / "core" / "widget_store.py").write_text("class WidgetStore:\n    pass\n")
    (tmp_path / "tests").mkdir()
    imports = "".join(f"import core.m{i}\n" for i in range(CM.CATCH_ALL_IMPORTS + 1))
    body = textwrap.dedent("""\
        import core.widget_store

        def test_happy_store():
            core.widget_store.WidgetStore()

        def test_sad_something_else():
            pass

        class T:
            def setUp(self):
                self.s = WidgetStore()

            def test_edge_via_setup(self):
                pass
        """)
    (tmp_path / "tests" / "test_all.py").write_text(imports + body)
    (tmp_path / "tests" / "test_focused.py").write_text(
        "from core import widget_store\n\ndef test_sad_one():\n    pass\n"
    )
    index = CM.SuiteIndex(tmp_path)
    files = index.importers(["core/widget_store.py"])
    assert files == ["tests/test_all.py", "tests/test_focused.py"]
    counts = CM.feature_counts(index, files, ["core/widget_store.py"], tmp_path)
    assert counts == {"happy": 1, "sad": 1, "edge": 1}


# ------------------------------------------------------------ rendering
def _coverage_of_one_module(tmp_path) -> Path:
    """Real coverage data: core/path_policy.py imported and called once, in
    a child process (a coverage run inside a coverage run would clash)."""
    data = tmp_path / "data.cov"
    code = textwrap.dedent(f"""\
        import coverage, sys
        sys.path.insert(0, {str(ROOT)!r})
        cov = coverage.Coverage(data_file={str(data)!r}, branch=True,
                                include=[{str(ROOT / "core" / "path_policy.py")!r}],
                                config_file=False)
        cov.start()
        import core.path_policy as pp
        pp.safe_leaf("ok.txt")
        cov.stop()
        cov.save()
        """)
    subprocess.run([sys.executable, "-c", code], check=True, cwd=tmp_path)
    return data


def test_happy_e2e_the_script_writes_the_matrix_from_real_coverage_data(tmp_path):
    data = _coverage_of_one_module(tmp_path)
    rc = tmp_path / "rc.txt"
    rc.write_text("0 3 tests/test_a.py\n1 9 tests/test_b.py\nDONE\n")
    out = tmp_path / "matrix.md"
    proc = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "coverage_matrix.py"),
            "--data",
            str(data),
            "--rc",
            str(rc),
            "--command",
            "cov_scope.sh tree out list",
            "--date",
            "2026-10-26",
            "--out",
            str(out),
        ],
        capture_output=True,
        text=True,
        cwd=ROOT,
        timeout=600,
    )
    assert proc.returncode == 0, proc.stderr
    text = out.read_text()
    assert text.startswith("# Test Coverage Matrix\n\nMeasured on 2026-10-26.")
    assert "cov_scope.sh tree out list" in text and "- `tests/test_b.py`" in text
    assert "`tests/test_a.py`" not in text
    every = text.split("## Every module", 1)[1].split("## How to refresh", 1)[0]
    cells = {
        line.split("|")[1].strip(): [c.strip() for c in line.split("|")[2:-1]]
        for line in every.splitlines()
        if line.startswith("| `")
    }
    feature, statements, lines, _branches = cells["`core/path_policy.py`"]
    assert feature == "`backend-layer`" and int(statements) > 0
    assert lines != "0.0 %"  # executed in that run
    assert cells["`core/trail.py`"][2:] == ["0.0 %", "0.0 %"]  # not executed
    assert f"Main features: **{len(CM.FEATURES)}**" in text


def test_sad_missing_data_is_an_error_not_an_empty_matrix(tmp_path):
    out = tmp_path / "m.md"
    proc = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "coverage_matrix.py"),
            "--data",
            str(tmp_path / "nope"),
            "--out",
            str(out),
        ],
        capture_output=True,
        text=True,
        cwd=ROOT,
        timeout=120,
    )
    assert proc.returncode == 2 and "no coverage data" in proc.stderr
    assert not out.exists()


def test_edge_check_mode_needs_no_data():
    proc = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "coverage_matrix.py"), "--check"],
        capture_output=True,
        text=True,
        cwd=ROOT,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    assert f"{len(CM.FEATURES)} features, map is current" in proc.stdout


def test_edge_the_committed_matrix_was_generated_by_this_script():
    text = (ROOT / "docs" / "TEST_COVERAGE_MATRIX.md").read_text()
    assert "Generated by `scripts/coverage_matrix.py`" in text
    for feat in CM.FEATURES:
        assert f"(`{feat.key}`)" in text, feat.key


def test_edge_failed_files_are_read_from_rc_txt(tmp_path):
    rc = tmp_path / "rc.txt"
    rc.write_text("0 1 tests/a.py\n2 0 tests/b.py (missing)\n1 5 tests/c.py\nDONE\n")
    assert CM.failed_files(rc) == ["tests/b.py", "tests/c.py"]
    assert json.dumps(CM.E2E_KINDS)  # plain data
