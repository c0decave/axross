"""The CI builds and checks what a release ships, on every supported Python.

``.github/workflows/python-app.yml``'s "package" job builds the sdist and
the wheel, runs ``twine check --strict``, the wheel-content test
(AXROSS_TEST_WHEEL), ``ruff check .`` with pyproject's rule set and the two
``--check`` modes of the generated documents - on Python 3.11 to 3.14, the
versions pyproject's classifiers name. Before, no workflow built either
artefact, and none of these checks ran in CI.
"""
from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

REPO = Path(__file__).resolve().parent.parent
WORKFLOW = REPO / ".github" / "workflows" / "python-app.yml"


def _job() -> dict:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]["package"]


def _runs(job: dict) -> list[str]:
    return [" ".join(step["run"].split()) for step in job["steps"] if "run" in step]


def _step_with(job: dict, needle: str) -> str:
    hits = [run for run in _runs(job) if needle in run]
    assert hits, f"no step of the package job runs {needle!r}"
    return hits[0]


def test_happy_the_package_job_runs_on_every_supported_python() -> None:
    classifiers = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))[
        "project"]["classifiers"]
    supported = sorted(
        m.group(1) for c in classifiers
        if (m := re.fullmatch(r"Programming Language :: Python :: (3\.\d+)", c))
    )
    assert supported[0] == "3.11"
    assert sorted(_job()["strategy"]["matrix"]["python-version"]) == supported


def test_happy_it_installs_the_dev_requirements() -> None:
    _step_with(_job(), "pip install -r dev-requirements.txt")


def test_happy_it_builds_both_artefacts_and_checks_them_strictly() -> None:
    job = _job()
    build = _step_with(job, "python -m build")
    assert "--sdist" in build and "--wheel" in build
    assert "--outdir dist" in build
    assert "twine check --strict dist/*" in _step_with(job, "twine check")


def test_happy_it_checks_the_built_wheel_content() -> None:
    run = _step_with(_job(), "AXROSS_TEST_WHEEL=")
    assert "dist/axross-*.whl" in run
    assert "tests/test_pypi_packaging.py::test_built_wheel_contains_runtime_resources" in run


def test_happy_it_runs_the_lint_gate_and_the_generated_document_checks() -> None:
    job = _job()
    assert _step_with(job, "ruff check").endswith("ruff check .")
    assert "scripts/coverage_matrix.py --check" in _step_with(job, "coverage_matrix")
    assert "-m core.llm_guide --check" in _step_with(job, "llm_guide")


def test_happy_the_lint_gate_is_configured_in_pyproject() -> None:
    """``ruff check .`` without --select: the rules are pyproject's, the same
    for CONTRIBUTING.md's local run and for CI."""
    lint = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))[
        "tool"]["ruff"]["lint"]
    assert {"F", "E9", "PLE2502", "B025"} <= set(lint["select"])
    assert "--select" not in _step_with(_job(), "ruff check")
    contributing = (REPO / "CONTRIBUTING.md").read_text(encoding="utf-8")
    assert "`ruff check .` must pass" in contributing


def test_happy_actions_are_pinned_to_a_commit() -> None:
    for step in _job()["steps"]:
        if "uses" in step:
            assert re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", step["uses"]), step["uses"]
