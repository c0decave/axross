"""scripts/build_release.sh names the release after the version a build gets.

The script read ``[project].version`` from pyproject.toml, but the
version is dynamic (``tool.setuptools.dynamic``, attr
``axross._version.__version__``): every run, ``--dry-run`` included,
stopped with exit 2. These tests run the script's version snippet (the
Python between its ``<<'PY'`` markers) on its own.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "build_release.sh"


def _snippet() -> str:
    text = SCRIPT.read_text(encoding="utf-8")
    match = re.search(r'VERSION="\$\(\n\s*python3 - <<\'PY\'[^\n]*\n(.*?)\nPY\n', text, re.S)
    assert match, "build_release.sh: version snippet not found"
    return match.group(1)


def _resolve(cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-I", "-c", _snippet()],
        cwd=cwd, capture_output=True, text=True, timeout=60, check=False,
    )


def _project(tmp_path: Path, pyproject: str, version_py: str | None = None) -> Path:
    (tmp_path / "pyproject.toml").write_text(pyproject, encoding="utf-8")
    if version_py is not None:
        (tmp_path / "axross").mkdir()
        (tmp_path / "axross" / "_version.py").write_text(version_py, encoding="utf-8")
    return tmp_path


DYNAMIC = (
    '[project]\nname = "axross"\ndynamic = ["version"]\n'
    '[tool.setuptools.dynamic]\nversion = { attr = "axross._version.__version__" }\n'
)


def test_happy_the_repository_resolves_to_axross_version() -> None:
    from axross._version import __version__

    done = _resolve(REPO_ROOT)
    assert done.returncode == 0, done.stderr
    assert done.stdout.strip() == __version__


def test_happy_a_dynamic_version_is_read_from_the_attr_module(tmp_path) -> None:
    root = _project(tmp_path, DYNAMIC, '"""v."""\nfrom __future__ import annotations\n\n'
                                       '__version__ = "1.2.3"\n')
    assert _resolve(root).stdout.strip() == "1.2.3"


def test_happy_an_annotated_assignment_counts(tmp_path) -> None:
    root = _project(tmp_path, DYNAMIC, '__version__: str = "4.5.6"\n')
    assert _resolve(root).stdout.strip() == "4.5.6"


def test_edge_a_static_project_version_wins(tmp_path) -> None:
    root = _project(tmp_path, '[project]\nname = "axross"\nversion = "7.8.9"\n')
    assert _resolve(root).stdout.strip() == "7.8.9"


def test_edge_the_module_is_read_not_imported(tmp_path) -> None:
    marker = tmp_path / "imported"
    root = _project(
        tmp_path, DYNAMIC,
        f'open({str(marker)!r}, "w").close()\n__version__ = "1.0"\n',
    )
    assert _resolve(root).stdout.strip() == "1.0"
    assert not marker.exists()


@pytest.mark.parametrize("version_py", [None, "", '__version__ = ""\n', "__version__ = 3\n",
                                        "VERSION = '1.0'\n", "this is ( not python\n"])
def test_sad_no_usable_version_fails(tmp_path, version_py) -> None:
    done = _resolve(_project(tmp_path, DYNAMIC, version_py))
    assert done.returncode == 1 and done.stdout == ""


@pytest.mark.skipif(os.name == "nt", reason="POSIX file mode")
def test_edge_the_script_is_executable() -> None:
    """docs/DEVELOPMENT.md runs it as ``scripts/build_release.sh``."""
    assert os.access(SCRIPT, os.X_OK)
