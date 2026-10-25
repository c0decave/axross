"""Every third-party package axross imports is declared in pyproject.toml.

Found: ui/code_editor.py imports Pygments unguarded, but pyproject.toml did
not name it, so a plain ``pip install axross`` gave an editor that failed
on the first file it opened. An import that is neither a base dependency,
nor in an extra, nor guarded by ``except ImportError`` fails here; a module
that has to work on a plain pip install must import base dependencies only.
"""

from __future__ import annotations

import ast
import importlib.metadata as md
import re
import sys
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
FIRST_PARTY = {"core", "ui", "models", "axross", "resources", "tests", "scripts", "main",
               "examples", "security"}
#: Import names whose distribution is not installed here or named otherwise.
KNOWN_NAMES = {"piper": "piper-tts"}
#: Modules that have to work on a plain pip install: base dependencies only.
ALWAYS_USED = ("ui/code_editor.py", "core/encrypted_overlay.py")


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _requirement_name(spec: str) -> str:
    return _norm(re.split(r"[ <>=;\[!~]", spec.strip())[0])


PROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text("utf-8"))["project"]
BASE = {_requirement_name(d) for d in PROJECT["dependencies"]}
EXTRA = {_requirement_name(d) for deps in PROJECT.get("optional-dependencies", {}).values()
         for d in deps}
DISTS = md.packages_distributions()


def _distributions(top: str) -> set[str]:
    if top in KNOWN_NAMES:
        return {_norm(KNOWN_NAMES[top])}
    return {_norm(d) for d in DISTS.get(top, [top])}


def _guarded(parents) -> bool:
    for node in parents:
        if isinstance(node, ast.Try):
            for handler in node.handlers:
                if handler.type is None:
                    return True
                types = handler.type.elts if isinstance(handler.type, ast.Tuple) else [handler.type]
                if any(getattr(t, "id", getattr(t, "attr", "")) in
                       ("ImportError", "ModuleNotFoundError", "Exception") for t in types):
                    return True
    return False


def third_party_imports(source: str):
    """(top-level module, guarded) of every absolute import in *source*."""
    out = []
    stack = [(ast.parse(source), ())]
    while stack:
        node, parents = stack.pop()
        for child in ast.iter_child_nodes(node):
            stack.append((child, parents + (node,)))
        names = []
        if isinstance(node, ast.Import):
            names = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names = [node.module]
        for name in names:
            top = name.split(".")[0]
            if top in sys.stdlib_module_names or top in FIRST_PARTY or top.startswith("_"):
                continue
            out.append((top, _guarded(parents)))
    return out


def _shipped_files():
    for folder in ("core", "ui", "models", "axross"):
        yield from sorted((ROOT / folder).rglob("*.py"))
    yield ROOT / "main.py"


def test_happy_the_scanner_sees_guarded_and_unguarded_imports():
    found = third_party_imports(
        "import pygments\ntry:\n    import jsonschema\nexcept ImportError:\n    pass\n"
        "def f():\n    from psutil import disk_partitions\n")
    assert sorted(found) == [("jsonschema", True), ("psutil", False), ("pygments", False)]


def test_sad_every_unguarded_import_is_declared():
    undeclared = {}
    for path in _shipped_files():
        for top, guarded in third_party_imports(path.read_text("utf-8")):
            if guarded or _distributions(top) & (BASE | EXTRA):
                continue
            undeclared.setdefault(top, []).append(str(path.relative_to(ROOT)))
    assert undeclared == {}, undeclared


@pytest.mark.parametrize("module", ALWAYS_USED)
def test_sad_a_plain_install_module_needs_base_dependencies_only(module):
    missing = sorted({top for top, guarded in third_party_imports((ROOT / module).read_text())
                      if not guarded and not _distributions(top) & BASE})
    assert missing == [], f"{module} imports {missing}, which a plain pip install lacks"


def test_edge_stdlib_first_party_and_relative_imports_do_not_count():
    assert third_party_imports("import os\nfrom core import x\nfrom . import y\nimport _thread\n") == []
