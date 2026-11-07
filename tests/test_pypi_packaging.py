"""Regression checks for the PyPI/sdist/wheel packaging path."""

from __future__ import annotations

import fnmatch
import os
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


def _floors(specs) -> dict[str, tuple[int, ...]]:
    from packaging.requirements import Requirement

    out: dict[str, tuple[int, ...]] = {}
    for spec in specs:
        req = Requirement(spec)
        for s in req.specifier:
            if s.operator == ">=":
                out[req.name.lower()] = tuple(int(p) for p in s.version.split("."))
    return out


def test_happy_dev_floors_are_at_least_the_build_and_runtime_floors() -> None:
    """dev-requirements.txt builds the sdist with --no-isolation and runs the
    tests: its setuptools and wheel meet [build-system] (setuptools 84.1.0,
    wheel 0.46.2 - CVE-2026-24049), and a package it shares with
    pyproject.toml (cryptography) has at least pyproject's floor - it named
    42.0, below the advisories (fixed up to 49.0.0) that 50.0.0 clears."""
    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    dev_lines = [
        line.split("#")[0].strip()
        for line in (REPO_ROOT / "dev-requirements.txt").read_text(encoding="utf-8").splitlines()
    ]
    dev = _floors(line for line in dev_lines if line)
    build = _floors(pyproject["build-system"]["requires"])
    assert build["setuptools"] >= (84, 1, 0) and build["wheel"] >= (0, 46, 2)
    runtime_specs = list(pyproject["project"]["dependencies"])
    for extra in pyproject["project"]["optional-dependencies"].values():
        runtime_specs.extend(extra)
    runtime = _floors(runtime_specs)
    for name, floor in {**runtime, **build}.items():
        if name in dev:
            assert dev[name] >= floor, f"dev-requirements.txt: {name} below {floor}"
    assert {"setuptools", "wheel", "cryptography"} <= dev.keys()


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

    assert pyproject["build-system"]["requires"] == ["setuptools>=84.1.0", "wheel>=0.46.2"]
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
        "resources.extensions",
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


def _shipped_data_files() -> list[str]:
    """Every file below resources/ and examples/, as a wheel names it."""
    found = []
    for top in ("resources", "examples"):
        for path in sorted((REPO_ROOT / top).rglob("*")):
            if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc":
                found.append(path.relative_to(REPO_ROOT).as_posix())
    return found


def _resource_data_files() -> list[str]:
    return [
        rel for rel in _shipped_data_files()
        if rel.startswith("resources/") and not rel.endswith(".py")
    ]


def _declared_by_package_data(rel: str, packages: set[str], package_data: dict) -> bool:
    """Would setuptools put ``rel`` (a non-.py file) into the wheel?

    Every declared package that contains the file is asked; a glob is
    relative to the package's directory, as setuptools reads it.
    """
    parts = rel.split("/")
    for depth in range(len(parts) - 1, 0, -1):
        package = ".".join(parts[:depth])
        if package not in packages:
            continue
        inner = "/".join(parts[depth:])
        if any(fnmatch.fnmatchcase(inner, glob) and inner.count("/") == glob.count("/")
               for glob in package_data.get(package, ())):
            return True
    return False


#: Which of the paths on stdin the resources/ lines of MANIFEST.in (argv[1]) take.
_MANIFEST_FILTER = """
import sys
from setuptools._distutils.filelist import FileList
files = FileList()
files.allfiles = sys.stdin.read().split()
for line in open(sys.argv[1], encoding="utf-8").read().splitlines():
    line = line.strip()
    if line.startswith(("recursive-include resources", "include resources",
                        "graft resources", "prune resources", "exclude resources",
                        "recursive-exclude resources", "global-")):
        files.process_template_line(line)
print("\\n".join(files.files))
"""


def test_every_resource_data_file_is_declared_for_wheel_and_sdist() -> None:
    """Static, needs no build: resources/ data reaches both artefacts.

    resources/i18n was in the PyInstaller spec but in neither
    ``package-data`` nor MANIFEST.in, so a pip-installed axross had no
    German (or any other) interface. Any new data directory fails here.
    """
    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    setuptools_cfg = pyproject["tool"]["setuptools"]
    packages = set(setuptools_cfg["packages"])
    package_data = setuptools_cfg["package-data"]
    data_files = _resource_data_files()
    assert any(rel.startswith("resources/i18n/") for rel in data_files)

    not_in_wheel = [
        rel for rel in data_files
        if not _declared_by_package_data(rel, packages, package_data)
    ]
    assert not_in_wheel == [], f"no package-data glob in pyproject.toml covers {not_in_wheel}"

    # In a child: setuptools' distutils shim asserts when the stdlib
    # distutils was imported first (some test modules of the suite do).
    taken = subprocess.run(
        [sys.executable, "-c", _MANIFEST_FILTER, str(REPO_ROOT / "MANIFEST.in")],
        input="\n".join(data_files), capture_output=True, text=True, check=True, timeout=120,
    ).stdout.split()
    not_in_sdist = sorted(set(data_files) - set(taken))
    assert not_in_sdist == [], f"MANIFEST.in does not take {not_in_sdist} into the sdist"


def test_sad_a_data_file_without_a_glob_is_reported() -> None:
    packages = {"resources", "resources.logo"}
    package_data = {"resources": ["i18n/*.json"], "resources.logo": ["*.png"]}
    assert _declared_by_package_data("resources/i18n/de.json", packages, package_data)
    assert _declared_by_package_data("resources/logo/a.png", packages, package_data)
    assert not _declared_by_package_data("resources/logo/a.svg", packages, package_data)
    assert not _declared_by_package_data("resources/i18n/sub/x.json", packages, package_data)
    assert not _declared_by_package_data("resources/newdir/x.json", packages, package_data)


def _wheels_for(version: str) -> list[Path]:
    # Only a wheel of this tree's version says anything about this tree:
    # a stale one left in dist/ (0.7.21 next to a 0.8.67 tree) failed the
    # version check below although nothing was wrong with the code.
    return sorted((REPO_ROOT / "dist").glob(f"axross-{version}-*.whl"))


def test_edge_a_stale_wheel_of_another_version_is_not_checked(tmp_path, monkeypatch) -> None:
    (tmp_path / "dist").mkdir()
    (tmp_path / "dist" / "axross-0.0.1-py3-none-any.whl").write_bytes(b"")
    monkeypatch.setattr(sys.modules[__name__], "REPO_ROOT", tmp_path)
    assert _wheels_for("9.9.9") == []
    assert [w.name for w in _wheels_for("0.0.1")] == ["axross-0.0.1-py3-none-any.whl"]


def test_built_wheel_contains_runtime_resources() -> None:
    from axross._version import __version__

    # AXROSS_TEST_WHEEL: check a wheel built elsewhere (a release dir).
    override = os.environ.get("AXROSS_TEST_WHEEL")
    wheels = [Path(override)] if override else _wheels_for(__version__)
    if not wheels:
        pytest.skip(
            f"no wheel for {__version__} in dist/; "
            "run `python -m build` for artifact smoke coverage"
        )

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
        f"{dist_info}/METADATA",
        f"{dist_info}/entry_points.txt",
    }
    # Rule, not list: every file under resources/ and examples/ (the
    # PyInstaller spec ships each resources/ subdirectory whole). The
    # hand-written list this replaces named one file per directory and
    # never noticed that resources/i18n was missing from every wheel.
    required |= set(_shipped_data_files())
    missing = sorted(required - names)
    assert missing == [], f"the wheel lacks {missing}"

    with zipfile.ZipFile(wheel) as zf:
        metadata = zf.read(f"{dist_info}/METADATA").decode("utf-8")
        entry_points = zf.read(f"{dist_info}/entry_points.txt").decode("utf-8")

    from axross._version import __version__

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
