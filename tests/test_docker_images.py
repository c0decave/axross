"""Dockerfile.mcp and Dockerfile.agent carry every module their entry imports.

Dockerfile.mcp copied core/, models/ and main.py only: main.py's argument
parser imports ``axross._version`` and two dozen core modules import
``security.*``, so the image stopped at its first line with
``ModuleNotFoundError: No module named 'axross'``. Its pip floors were also
far below pyproject's security floors (``paramiko>=3``, ``cryptography>=41``,
``py7zr>=0.20``) and it installed ``webdavclient3``, which nothing uses.

These tests read the Dockerfiles and follow the imports of the entry point
(every ``import``, function-level ones too) through the first-party tree:
each first-party package reached has to be copied into the image, and every
requirement pip installs there has at least pyproject.toml's floor.
"""
from __future__ import annotations

import ast
import re
import shlex
import tomllib
from pathlib import Path

import pytest
from packaging.requirements import Requirement
from packaging.version import Version

REPO = Path(__file__).resolve().parent.parent

#: Packages the image leaves out on purpose: the GUI (no Qt in either image).
NOT_IN_IMAGES = {"ui"}

#: Data directories core reads by path (core.i18n's catalogues, wordlists,
#: the MCP catalog, scripts, credits) - no import leads to them.
DATA_DIRS = {"resources"}

#: image -> (entry modules, final-stage target dir)
IMAGES = {
    "Dockerfile.mcp": (("main", "core.mcp_server", "core.mcp_http"), "/app"),
    "Dockerfile.agent": (("core.agent_worker",), "/opt/axross"),
}


def _first_party() -> set[str]:
    return {p.name for p in REPO.iterdir() if (p / "__init__.py").is_file()} | {"main"}


def _source(module: str) -> Path | None:
    base = REPO.joinpath(*module.split("."))
    if base.with_suffix(".py").is_file():
        return base.with_suffix(".py")
    if (base / "__init__.py").is_file():
        return base / "__init__.py"
    return None


def imported_packages(entries: tuple[str, ...]) -> set[str]:
    """First-party top-level packages reached from ``entries`` by any import,
    not following into NOT_IN_IMAGES."""
    first = _first_party()
    seen: set[str] = set()
    todo = list(entries)
    while todo:
        module = todo.pop()
        if module in seen:
            continue
        seen.add(module)
        path = _source(module)
        if path is None:
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                names = [node.module] + [f"{node.module}.{a.name}" for a in node.names]
            else:
                continue
            for name in names:
                top = name.split(".")[0]
                if top in first and top not in NOT_IN_IMAGES:
                    todo.append(name)
    return {m.split(".")[0] for m in seen if _source(m) is not None}


def _instructions(path: Path) -> list[tuple[str, list[str]]]:
    text = re.sub(r"\\\n", " ", path.read_text(encoding="utf-8"))
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        word, _, rest = line.partition(" ")
        out.append((word.upper(), shlex.split(rest, comments=True)))
    return out


def _copied(path: Path, target: str) -> tuple[set[str], set[str]]:
    """(top-level names COPY'd from the build context in any stage, names
    the final stage puts under ``target``)."""
    stages: list[list[tuple[str, list[str]]]] = []
    for word, args in _instructions(path):
        if word == "FROM":
            stages.append([])
        stages[-1].append((word, args))
    context: set[str] = set()
    final: set[str] = set()
    for index, stage in enumerate(stages):
        last = index == len(stages) - 1
        for word, args in stage:
            if word != "COPY":
                continue
            *sources, dest = [a for a in args if not a.startswith("--")]
            from_stage = any(a.startswith("--from=") for a in args)
            if not from_stage:
                context |= {s.rstrip("/").split("/")[0] for s in sources}
            if last and dest.startswith(target + "/"):
                if from_stage or len(stages) == 1:
                    final |= {s.rstrip("/").rsplit("/", 1)[-1] for s in sources}
    return context, final


@pytest.mark.parametrize("dockerfile", sorted(IMAGES))
def test_happy_every_package_the_entry_imports_is_in_the_image(dockerfile) -> None:
    entries, target = IMAGES[dockerfile]
    needed = (imported_packages(entries) | DATA_DIRS) - {"main"}
    context, final = _copied(REPO / dockerfile, target)
    assert needed <= context, f"{dockerfile} does not COPY {sorted(needed - context)}"
    assert needed <= final, f"{dockerfile}: {sorted(needed - final)} missing under {target}"


def test_happy_the_mcp_entry_reaches_the_packages_it_crashed_without() -> None:
    reached = imported_packages(IMAGES["Dockerfile.mcp"][0])
    assert {"axross", "core", "models", "security"} <= reached
    assert "ui" not in reached


def _pyproject_floors() -> dict[str, Version]:
    project = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    specs = list(project["dependencies"])
    for extra in project["optional-dependencies"].values():
        specs.extend(extra)
    floors: dict[str, Version] = {}
    for spec in specs:
        req = Requirement(spec)
        for s in req.specifier:
            if s.operator == ">=":
                name = req.name.lower()
                floors[name] = max(floors.get(name, Version("0")), Version(s.version))
    return floors


def _dev_names() -> set[str]:
    names = set()
    for line in (REPO / "dev-requirements.txt").read_text(encoding="utf-8").splitlines():
        line = line.split("#")[0].strip()
        if line and not line.startswith("-"):
            names.add(Requirement(line).name.lower())
    return names


def _pip_requirements(dockerfile: str) -> list[Requirement]:
    reqs = []
    for word, args in _instructions(REPO / dockerfile):
        if word == "RUN" and args[:2] == ["pip", "install"]:
            for arg in args[2:]:
                if arg in ("&&", ";"):
                    break
                if not arg.startswith("-"):
                    reqs.append(Requirement(arg))
    return reqs


@pytest.mark.parametrize("dockerfile", sorted(IMAGES))
def test_happy_pip_floors_are_at_least_pyprojects(dockerfile) -> None:
    floors = _pyproject_floors()
    known = set(floors) | _dev_names()
    reqs = _pip_requirements(dockerfile)
    assert reqs, f"{dockerfile}: no pip install found"
    for req in reqs:
        name = req.name.lower()
        assert name in known, f"{dockerfile} installs {name}, which axross does not use"
        if name not in floors:
            continue
        mine = [Version(s.version) for s in req.specifier if s.operator == ">="]
        assert mine and max(mine) >= floors[name], (
            f"{dockerfile}: {req} is below pyproject's floor {name}>={floors[name]}"
        )


def test_sad_a_missing_copy_is_seen(tmp_path) -> None:
    text = (REPO / "Dockerfile.mcp").read_text(encoding="utf-8")
    broken = text.replace("COPY security/ security/\n", "")
    assert broken != text
    (tmp_path / "Dockerfile.mcp").write_text(broken, encoding="utf-8")
    context, final = _copied(tmp_path / "Dockerfile.mcp", "/app")
    assert "security" not in context
    assert "security" in final  # the final stage still names it; the build stage lacks it
