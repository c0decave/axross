"""Every build/ file the release build reads is in git.

scripts/build_dist.sh builds from a clean ``git archive HEAD``. The CI
builder has nothing else, so a file under build/ that ``.gitignore``
leaves out (``build/*`` ignores everything there by default) only existed
on the maintainer's machine, and the CI build stopped at its first step
("build/requirements-scan-tools.txt is missing").
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
# the scripts whose build/ paths a clean export must have
READERS = (
    "scripts/build_dist.sh",
    "scripts/build_bundle.sh",
    "scripts/lock_bundle_deps.sh",
    "scripts/lock_scan_tools.sh",
    "security/supply_chain_gate.py",
    "scripts/export_supply_chain_gate.py",
)
# build/<name> references; <system>.txt placeholders and outputs are not inputs
_REF = re.compile(r"build/([A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)?)")
_OUTPUTS = {"dist-work", "lib", "sysroot"}


def _tracked() -> set[str]:
    if shutil.which("git") is None or not (ROOT / ".git").exists():
        pytest.skip("not a git checkout (an sdist has no build/ folder)")
    out = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "build"],
        capture_output=True, text=True, check=True,
    ).stdout
    return set(out.split())


def _referenced() -> set[str]:
    names: set[str] = set()
    for rel in READERS:
        path = ROOT / rel
        if not path.exists():
            continue
        for match in _REF.finditer(path.read_text(encoding="utf-8")):
            ref = match.group(1).rstrip(".")
            if ref.split("/")[0] in _OUTPUTS and "/" not in ref:
                continue
            if "<" in ref or not (ROOT / "build" / ref).is_file():
                continue
            names.add("build/" + ref)
    return names


def test_happy_every_build_input_the_scripts_name_is_tracked():
    tracked = _tracked()
    missing = sorted(_referenced() - tracked)
    assert not missing, (
        f"{missing} are read by the release build but not in git: "
        "add a !build/... line to .gitignore"
    )


def test_happy_the_target_systems_package_lists_are_tracked():
    tracked = _tracked()
    lists = {"build/sysroot/" + p.name for p in (ROOT / "build/sysroot").glob("*.txt")}
    assert lists, "build/sysroot/<system>.txt are the build's package lists"
    assert lists <= tracked, sorted(lists - tracked)


def test_sad_the_check_notices_an_ignored_input(tmp_path):
    # the same rule on a repo whose .gitignore still has only build/*
    if shutil.which("git") is None:
        pytest.skip("git is missing")
    repo = tmp_path / "r"
    (repo / "build").mkdir(parents=True)
    (repo / ".gitignore").write_text("build/*\n!build/kept.txt\n")
    (repo / "build/kept.txt").write_text("x")
    (repo / "build/lock.txt").write_text("x")
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
    out = subprocess.run(["git", "-C", str(repo), "ls-files", "build"],
                         capture_output=True, text=True, check=True).stdout.split()
    assert "build/kept.txt" in out and "build/lock.txt" not in out
