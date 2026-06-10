"""Regression checks for the PyPI/sdist/wheel packaging path."""

from __future__ import annotations

import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 fallback
    import tomli as tomllib  # type: ignore[no-redef]


REPO_ROOT = Path(__file__).resolve().parent.parent


def test_axross_package_facade_exports_scripting_api() -> None:
    import axross
    from axross._version import __version__
    from core import scripting

    assert "localfs" in axross.__all__
    assert axross.localfs is scripting.localfs
    assert isinstance(axross.__version__, str)
    assert axross.__version__
    assert axross.__version__ == __version__


def test_module_cli_reports_version_without_qt_import() -> None:
    from axross._version import __version__

    result = subprocess.run(
        [sys.executable, "-m", "axross", "--version"],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        check=True,
    )
    assert result.stdout.strip() == f"axross {__version__}"
    assert result.stderr == ""


def test_pyproject_declares_publishable_package_metadata() -> None:
    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))

    assert pyproject["build-system"]["requires"] == ["setuptools>=77.0", "wheel"]
    assert pyproject["project"]["readme"] == {
        "file": "README_PYPI.md",
        "content-type": "text/markdown",
    }
    assert pyproject["project"]["dynamic"] == ["version"]
    assert pyproject["project"]["scripts"]["axross"] == "axross.cli:main"
    assert pyproject["tool"]["setuptools"]["dynamic"]["version"] == {
        "attr": "axross._version.__version__"
    }

    packages = set(pyproject["tool"]["setuptools"]["packages"])
    assert {
        "axross",
        "core",
        "ui",
        "models",
        "examples",
        "examples.scripting_api",
        "resources",
        "resources.logo",
        "resources.logo.concepts",
        "resources.scripts",
        "resources.wordlists",
    } <= packages

    package_data = pyproject["tool"]["setuptools"]["package-data"]
    assert set(package_data["resources.logo"]) == {"*.png", "*.svg"}
    assert set(package_data["resources.logo.concepts"]) == {"*.svg"}
    assert set(package_data["resources.scripts"]) == {"*.md"}
    assert set(package_data["resources.wordlists"]) == {"*.txt"}
    assert set(package_data["examples"]) == {"*.md"}
    assert set(package_data["examples.scripting_api"]) == {"*.md"}

    extras = pyproject["project"]["optional-dependencies"]
    assert {"winrm", "wmi", "exchange", "fuse"} <= set(extras)
    heavy_deps = {"pywinrm>=0.4", "impacket>=0.11", "exchangelib>=5.0", "fusepy>=3.0"}
    assert heavy_deps.isdisjoint(extras["all"])


def test_built_wheel_contains_runtime_resources() -> None:
    wheels = sorted((REPO_ROOT / "dist").glob("axross-*.whl"))
    if not wheels:
        pytest.skip("wheel not built; run `python -m build` for artifact smoke coverage")

    wheel = wheels[-1]

    with zipfile.ZipFile(wheel) as zf:
        names = set(zf.namelist())

    dist_infos = {
        name.rsplit("/", 1)[0]
        for name in names
        if name.startswith("axross-") and name.endswith(".dist-info/METADATA")
    }
    assert len(dist_infos) == 1
    dist_info = dist_infos.pop()

    required = {
        "axross/__init__.py",
        "axross/__main__.py",
        "axross/_version.py",
        "axross/cli.py",
        "main.py",
        "examples/__init__.py",
        "examples/README.md",
        "examples/scripting_api/__init__.py",
        "examples/scripting_api/README.md",
        "examples/scripting_api/local_file_workflows.py",
        "examples/scripting_api/docker_protocol_smoke.py",
        "resources/__init__.py",
        "resources/logo/__init__.py",
        "resources/logo/axross-logo-256.png",
        "resources/scripts/__init__.py",
        "resources/scripts/du.py",
        "resources/wordlists/__init__.py",
        "resources/wordlists/tftp_common.txt",
        f"{dist_info}/METADATA",
        f"{dist_info}/entry_points.txt",
    }

    with zipfile.ZipFile(wheel) as zf:
        metadata = zf.read(f"{dist_info}/METADATA").decode("utf-8")
        entry_points = zf.read(f"{dist_info}/entry_points.txt").decode("utf-8")

    from axross._version import __version__

    assert required <= names
    assert f"Version: {__version__}" in metadata
    assert "Description-Content-Type: text/markdown" in metadata
    assert "One UI for 30+ file" in metadata
    assert "License-Expression: Apache-2.0" in metadata
    assert "Classifier: Programming Language :: Python :: 3.14" in metadata
    for line in metadata.splitlines():
        if 'extra == "all"' in line:
            assert not any(
                package in line for package in ("pywinrm", "impacket", "exchangelib", "fusepy")
            )
    assert "axross = axross.cli:main" in entry_points
