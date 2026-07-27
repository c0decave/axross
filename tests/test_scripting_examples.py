"""Executable examples for the public axross scripting API."""

from __future__ import annotations

import os
import py_compile
from pathlib import Path

import pytest

import axross
from examples import scripting_api
from examples.scripting_api import (
    credential_testing,
    docker_protocol_smoke,
    local_file_workflows,
    network_diagnostics,
    protocol_recipes,
    script_store,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_every_public_scripting_api_has_an_example_mapping() -> None:
    missing = scripting_api.missing(axross.__all__)
    assert missing == []


def test_example_modules_compile(tmp_path: Path) -> None:
    """Every bundled example must be syntactically valid.

    ``cfile`` is redirected into tmp_path on purpose. The default
    behaviour writes the ``.pyc`` next to the source, which (a) drops
    ``__pycache__`` directories into the checked-out examples tree on
    every run and (b) hard-fails with ``OSError: Read-only file
    system`` whenever the source is mounted read-only — a container
    test run, a CI cache, or an installed package directory. The
    syntax check itself needs no artefact to survive the call.
    """
    examples = sorted((REPO_ROOT / "examples").rglob("*.py"))
    assert examples, "no example modules found — the glob or layout changed"
    for path in examples:
        cfile = tmp_path / (path.relative_to(REPO_ROOT).as_posix().replace("/", "_") + "c")
        py_compile.compile(str(path), cfile=str(cfile), doraise=True)


def test_local_scripting_examples_run(tmp_path: Path) -> None:
    results = {
        "local_file_workflows": local_file_workflows.run(tmp_path / "files"),
        "script_store": script_store.run(tmp_path / "store"),
        "network_diagnostics": network_diagnostics.run(),
        "credential_testing": credential_testing.run(tmp_path / "creds"),
        "protocol_recipes": protocol_recipes.run(tmp_path / "protocols"),
    }

    assert results["local_file_workflows"]["grep_hits"] >= 1
    assert results["script_store"]["backends"] >= 1
    assert results["network_diagnostics"]["http_status"] == 200
    assert results["credential_testing"]["enum_hits"] == ["alice"]
    assert results["protocol_recipes"]["sqlite_rows"] == 1


@pytest.mark.skipif(
    os.environ.get("AXROSS_LIVE_SCRIPTING_EXAMPLE_TESTS") != "1",
    reason="set AXROSS_LIVE_SCRIPTING_EXAMPLE_TESTS=1 and run inside tests/docker lab",
)
def test_docker_scripting_examples_run_against_lab() -> None:
    results = docker_protocol_smoke.run()
    exercised = {
        name
        for name, result in results.items()
        if not (isinstance(result, dict) and "skipped" in result)
    }
    if not exercised:
        pytest.skip(f"no docker lab services reachable: {results}")

    # A partial lab is useful, but the services that did answer must
    # have gone through their real example code path.
    assert exercised <= set(results)
    for name in exercised:
        assert results[name], name
