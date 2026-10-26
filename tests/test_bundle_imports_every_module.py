"""Release gate: every module of axross's own packages imports inside a built
bundle - what runs from the source tree must run from the binary too.

build/axross.spec collects core, ui and models with collect_submodules, which
imports each module at build time and quietly leaves out one that fails
there. Such a module is missing only from the binary: the feature behind it
breaks for every user of the release while every test from source passes.
The slim bundle leaves out the backends its spec excludes, and only those.

AXROSS_FROZEN_BINARY=<bundle> runs the check in that binary; skipped without
it. The verdict rules are tested without a bundle.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SPEC = ROOT / "build" / "axross.spec"

#: The packages the spec collects with collect_submodules.
PACKAGES = ("core", "ui", "models")

# Run inside the bundle: find and import every name, record what happened.
_PROBE = """\
import importlib, importlib.util, json, os, sys
from PyQt6.QtWidgets import QApplication
app = QApplication.instance() or QApplication([])
out = {}
for name in json.load(open(os.environ["AXROSS_E2E_MODULES"])):
    try:
        found = importlib.util.find_spec(name) is not None
    except BaseException as exc:
        out[name] = ["error", f"{type(exc).__name__}: {exc}"[:300]]
        continue
    if not found:
        out[name] = ["absent", ""]
        continue
    try:
        importlib.import_module(name)
        out[name] = ["ok", ""]
    except BaseException as exc:
        out[name] = ["error", f"{type(exc).__name__}: {exc}"[:300]]
flavor = open(os.path.join(sys._MEIPASS, "axross", "axross-bundle-flavor.txt")).read().strip()
json.dump({"flavor": flavor, "modules": out}, open(os.environ["AXROSS_E2E_OUT"], "w"))
"""


def own_modules(root: Path = ROOT) -> list[str]:
    """Every module of PACKAGES in the source tree, as a dotted name."""
    names = []
    for package in PACKAGES:
        for path in (root / package).rglob("*.py"):
            if "__pycache__" in path.parts:
                continue
            dotted = ".".join(path.relative_to(root).with_suffix("").parts)
            names.append(dotted.removesuffix(".__init__"))
    return sorted(names)


def slim_excluded(spec_text: str) -> set[str]:
    """The own modules the spec's slim block excludes."""
    block = spec_text.split('if FLAVOR == "slim":', 1)[1].split("\n# Unconditional excludes", 1)[0]
    pattern = r'"((?:' + "|".join(PACKAGES) + r')\.[\w.]+)"'
    return set(re.findall(pattern, block))


def problems(result: dict, excluded_in_slim: set[str]) -> list[str]:
    """What is wrong with one bundle's probe result: a module that fails to
    import, one missing that belongs in this flavor, one excluded from slim
    that is there after all."""
    flavor = result["flavor"]
    out = []
    for name, (state, detail) in sorted(result["modules"].items()):
        excluded = flavor == "slim" and name in excluded_in_slim
        if state == "error":
            out.append(f"{name}: does not import ({detail})")
        elif state == "absent" and not excluded:
            out.append(f"{name}: not in the {flavor} bundle")
        elif state == "ok" and excluded:
            out.append(f"{name}: in the slim bundle although the spec excludes it")
    if flavor not in ("full", "slim"):
        out.append(f"unknown flavor {flavor!r}")
    return out


def _result(flavor: str, **states) -> dict:
    return {"flavor": flavor, "modules": {n: [s, ""] for n, s in states.items()}}


def test_happy_every_module_imports():
    assert problems(_result("full", **{"core.a": "ok", "ui.b": "ok"}), set()) == []


def test_happy_slim_leaves_out_what_its_spec_excludes():
    assert problems(_result("slim", **{"core.a": "ok", "core.cloud": "absent"}),
                    {"core.cloud"}) == []


def test_sad_a_module_missing_from_the_bundle():
    assert problems(_result("full", **{"core.a": "absent"}), set()) == [
        "core.a: not in the full bundle"]


def test_sad_a_module_that_fails_to_import():
    result = {"flavor": "full", "modules": {"ui.c": ["error", "ImportError: no libfoo"]}}
    assert problems(result, set()) == ["ui.c: does not import (ImportError: no libfoo)"]


def test_sad_full_carries_what_slim_excludes():
    assert problems(_result("full", **{"core.cloud": "absent"}), {"core.cloud"}) == [
        "core.cloud: not in the full bundle"]


def test_edge_slim_carrying_an_excluded_module_is_reported():
    assert problems(_result("slim", **{"core.cloud": "ok"}), {"core.cloud"}) == [
        "core.cloud: in the slim bundle although the spec excludes it"]


def test_edge_an_unknown_flavor_is_reported():
    assert problems(_result("tiny"), set()) == ["unknown flavor 'tiny'"]


def test_happy_the_source_lists_every_package_and_the_spec_its_slim_backends():
    names = own_modules()
    assert {"core", "ui", "models", "core.transfer_manager", "ui.main_window"} <= set(names)
    assert not any(".__init__" in n or "__pycache__" in n for n in names)
    excluded = slim_excluded(SPEC.read_text())
    assert "core.gdrive_client" in excluded
    assert excluded <= set(names), excluded - set(names)


@pytest.mark.skipif(not os.environ.get("AXROSS_FROZEN_BINARY"), reason="needs a built bundle")
def test_e2e_every_own_module_imports_in_the_bundle(tmp_path):
    modules = tmp_path / "modules.json"
    modules.write_text(json.dumps(own_modules()))
    script = tmp_path / "probe.py"
    script.write_text(_PROBE)
    out = tmp_path / "out.json"
    home = tmp_path / "home"
    env = {"PATH": "/usr/bin:/bin", "HOME": str(home), "XDG_CONFIG_HOME": str(home / ".config"),
           "XDG_CACHE_HOME": str(home / ".cache"), "QT_QPA_PLATFORM": "offscreen",
           "AXROSS_NO_UPDATE_CHECK": "1", "AXROSS_E2E_MODULES": str(modules),
           "AXROSS_E2E_OUT": str(out)}
    run = subprocess.run([os.environ["AXROSS_FROZEN_BINARY"], "--script", str(script)], env=env,
                         capture_output=True, text=True, timeout=600)
    assert out.is_file(), run.stdout[-3000:] + run.stderr[-3000:]
    result = json.loads(out.read_text())
    assert len(result["modules"]) == len(own_modules())
    assert problems(result, slim_excluded(SPEC.read_text())) == []
