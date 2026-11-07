"""axross's own use of the supply-chain gate (the generic tests, exported
with the gate, are in tests/test_supply_chain_gate.py): every locked pin
has a reviewed baseline, the build cannot get around the gate, the
committed pins of the scanners fit their lock."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from security import supply_chain_gate as G  # noqa: E402


def test_happy_the_repository_has_no_extra_index():
    assert G.index_problems(ROOT) == [] or all("environment:" in p for p in G.index_problems(ROOT))


def test_happy_the_committed_capa_pins_name_the_scanner_venv_s_capa_release():
    locked = (ROOT / "build" / "requirements-scan-tools.txt").read_text()
    version = next(l.split("==")[1].split()[0] for l in locked.splitlines() if l.startswith("flare-capa=="))
    for name, repo in (("capa-rules.txt", "capa-rules"), ("capa-sigs.txt", "capa")):
        line = next(l for l in (ROOT / "build" / name).read_text().splitlines() if l.strip() and not l.startswith("#"))
        url, sha = line.split()
        assert url == f"https://github.com/mandiant/{repo}/archive/refs/tags/v{version}.tar.gz", name
        assert len(sha) == 64


def test_happy_build_dist_runs_every_stage_of_the_gate_before_building():
    script = (ROOT / "scripts" / "build_dist.sh").read_text(encoding="utf-8")
    first_gate = script.index('gate check --report "$WORK/gate-stdlib" --reduced-locks "$RL"')
    assert first_gate < script.index("uv python install")
    # the gate runs in the HEAD export (no stray ./supply-chain-gate.toml)
    assert 'gate() { (cd "$SRC" && python3 -I "$SRC/security/supply_chain_gate.py" "$@"); }' in script
    # every pip install reads a lock cut down to the inspected archives
    for line in script.splitlines():
        if "pip\" install" in line and "--require-hashes" in line and '"$req"' not in line:
            assert '-r "$RL/' in line, line
    assert 'fresh_venv "$VENV" "$RL/requirements-bootstrap.txt" "$RL/requirements-bundle.txt"' in script
    assert 'fresh_venv "$BVENV" "$RL/requirements-bootstrap.txt" "$RL/requirements-dist-tools.txt"' in script
    assert script.index('check --scan-python') < script.index("fresh_venv \"$VENV\"")
    assert script.count("verify-env") >= 3 and "check-system" in script
    assert script.index("check-system") < script.index("bash scripts/build_bundle.sh")
    for word in ("--skip-gate", "--no-gate", "SKIP_GATE", "AXROSS_NO_GATE"):
        assert word not in script


def test_happy_every_locked_pin_has_a_reviewed_baseline():
    """The gate in the test suite: a lock change without a review fails here
    already, offline, not only when a dist is built."""
    missing, stale = [], []
    for rel, pin in G.read_locks(ROOT):
        base = G.load_baseline(pin.name, pin.version)
        if base is None and G.reviewed_versions(pin.name):
            stale.append(f"{pin.name}: reviewed {G.reviewed_versions(pin.name)}, locked {pin.version}")
        elif base is None:
            missing.append(f"{pin.name}=={pin.version} ({rel})")
        else:
            reviewed = base.get("reviewed", {})
            assert reviewed.get("by") and len(reviewed.get("note", "")) >= 10, pin.name
    assert not missing and not stale, {"not reviewed": missing, "review out of date": stale}


def test_happy_build_dist_compiles_the_bootloader_from_the_reviewed_sdist():
    script = (ROOT / "scripts" / "build_dist.sh").read_text(encoding="utf-8")
    assert "PYINSTALLER_COMPILE_BOOTLOADER=1" in script and "ziglang cc" in script
    assert script.index("        build_bootloader\n") < script.index("bash scripts/build_bundle.sh")
    assert "pyinstaller" in G.built_from_source()
