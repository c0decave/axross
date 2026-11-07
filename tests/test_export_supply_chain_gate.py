"""scripts/export_supply_chain_gate.py: the supply-chain gate as a project of
its own - complete, free of axross's review data, and its own tests pass."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "export_supply_chain_gate.py"


def _load():
    spec = importlib.util.spec_from_file_location("export_gate", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def exported(tmp_path_factory):
    out = tmp_path_factory.mktemp("gate") / "supply-chain-gate"
    _load().export(out)
    return out


def test_happy_the_export_is_a_complete_project(exported):
    files = {str(p.relative_to(exported)) for p in exported.rglob("*") if p.is_file()}
    for name in ("pyproject.toml", "README.md", "LICENSE", "supply-chain-gate.example.toml",
                 "requirements-scan-tools.txt", "src/supply_chain_gate/supply_chain_gate.py",
                 "src/supply_chain_gate/supply_chain_scan.py", "src/supply_chain_gate/top_pypi_packages.txt",
                 "src/supply_chain_gate/capa-sigs.txt", "src/supply_chain_gate/yara_rules/supply_chain.yar",
                 "tests/test_supply_chain_gate.py"):
        assert name in files, name
    # axross's own review stays here: no baseline, no lock of axross
    assert not any("baseline" in f or "requirements-bundle" in f for f in files)
    readme = (exported / "README.md").read_text(encoding="utf-8")
    assert "## Quick start" in readme and "## What a pin has to pass" in readme
    assert "supply-chain-gate = \"supply_chain_gate.supply_chain_gate:main\"" in \
        (exported / "pyproject.toml").read_text(encoding="utf-8")


def test_happy_the_exported_gate_runs_and_needs_its_config(exported, tmp_path):
    code = ("import sys; sys.path.insert(0, sys.argv[1]); "
            "from supply_chain_gate.supply_chain_gate import main; sys.exit(main(sys.argv[2:]))")
    run = lambda *args, cwd: subprocess.run([sys.executable, "-I", "-c", code, str(exported / "src"), *args],  # noqa: E731
                                            cwd=cwd, capture_output=True, text=True, timeout=120)
    proc = run("status", cwd=tmp_path)
    assert proc.returncode == 2 and "no ./supply-chain-gate.toml" in proc.stderr
    (tmp_path / "requirements.txt").write_text("six==1.17.0 \\\n    --hash=sha256:" + "a" * 64 + "\n")
    (tmp_path / "supply-chain-gate.toml").write_text('locks = ["requirements.txt"]\n')
    proc = run("status", cwd=tmp_path)
    assert proc.returncode == 0 and proc.stdout.split() == ["six", "1.17.0", "not", "reviewed"]


def test_happy_the_exported_tests_pass(exported):
    env = {k: v for k, v in os.environ.items() if not k.startswith(("AXROSS_", "PYTEST_"))}
    if os.environ.get("AXROSS_TEST_SCAN_PYTHON"):
        env["SUPPLY_CHAIN_GATE_TEST_SCAN_PYTHON"] = os.environ["AXROSS_TEST_SCAN_PYTHON"]
    proc = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests"],
                          cwd=exported, env=env, capture_output=True, text=True, timeout=600)
    assert proc.returncode == 0, proc.stdout[-3000:] + proc.stderr[-2000:]


def test_sad_a_rewrite_that_no_longer_applies_stops_the_export(tmp_path, monkeypatch):
    ep = _load()
    monkeypatch.setitem(ep.REWRITES, "package_inspect.py", [("text that is not there", "x", True)])
    with pytest.raises(SystemExit, match="no longer contains"):
        ep.export(tmp_path / "out")


def test_sad_an_axross_reference_left_in_a_module_stops_the_export():
    ep = _load()
    with pytest.raises(SystemExit, match="still refers to axross"):
        ep.rewrite("package_inspect.py", "import os\nX = os.environ.get('AXROSS_SOMETHING')\n")
    assert json.loads(json.dumps(ep.rewrite("package_inspect.py", "X = 1\n"))) == "X = 1\n"
