"""The hashed lock the one-file bundles are built from.

Before the lock, Dockerfile.build installed a list of unpinned floors
without hashes (and the macOS / Windows CI ``pip install ".[all]"``): what
shipped was whatever pip resolved the day the image was built, two base
dependencies (watchdog, Pygments) were missing from the list, and its
cryptography floor (>=41) was eight majors below pyproject's. Now
build/requirements-bundle.txt pins every package to one version and the
sha256 of its files, scripts/lock_bundle_deps.sh refreshes it in a
container, and every build installs it with ``--require-hashes``.

No network here: these tests hold the lock, its input, pyproject.toml, the
Dockerfile and the CI workflow together. The OSV check of the pins is
``python -m security.dep_floor_audit --lock`` (release gate).
"""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from security.dep_floor_audit import _normalise, _version_key, parse_lock  # noqa: E402

LOCK_PATH = ROOT / "build" / "requirements-bundle.txt"
LOCK_TEXT = LOCK_PATH.read_text(encoding="utf-8")
LOCK = parse_lock(LOCK_TEXT)
BOOTSTRAP_TEXT = (ROOT / "build" / "requirements-bootstrap.txt").read_text(encoding="utf-8")
IN_TEXT = (ROOT / "build" / "requirements-bundle.in").read_text(encoding="utf-8")
PYPROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
DOCKERFILE = (ROOT / "Dockerfile.build").read_text(encoding="utf-8")
CI = (ROOT / ".github" / "workflows" / "cross-platform.yml").read_text(encoding="utf-8")
LOCK_SCRIPT = (ROOT / "scripts" / "lock_bundle_deps.sh").read_text(encoding="utf-8")

_REQ_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*([^;]*)(?:;(.*))?$")


def _requirement(spec: str) -> tuple[str, str | None, str]:
    """(normalised name, lower bound or None, marker) of a PEP 508 string."""
    match = _REQ_RE.match(spec)
    assert match, spec
    floor = re.search(r">=\s*([0-9][^,\s]*)", match.group(2))
    return _normalise(match.group(1)), floor.group(1) if floor else None, \
        (match.group(3) or "").strip()


def _pyproject_requirements() -> list[str]:
    reqs = list(PYPROJECT["dependencies"])
    for specs in PYPROJECT["optional-dependencies"].values():
        reqs += specs
    return list(dict.fromkeys(reqs))


def _in_requirements() -> list[str]:
    return [line.split("#", 1)[0].strip() for line in IN_TEXT.splitlines()
            if line.split("#", 1)[0].strip()]


def _pins(name: str) -> list:
    return [p for p in LOCK if p.name == _normalise(name)]


def _ge(version: str, floor: str) -> bool:
    return _version_key(version) >= _version_key(floor)


# --- happy -----------------------------------------------------------------


def test_happy_every_pyproject_requirement_is_pinned_in_the_lock():
    """Base dependencies and every extra: the bundles ship all of them."""
    missing = [spec for spec in _pyproject_requirements() if not _pins(_requirement(spec)[0])]
    assert missing == []


def test_happy_every_pin_meets_its_pyproject_and_input_floor():
    low = []
    for spec in _pyproject_requirements() + _in_requirements():
        name, floor, _marker = _requirement(spec)
        if floor is None:
            continue
        low += [f"{p.name}=={p.version} < {floor}" for p in _pins(name) if not _ge(p.version, floor)]
    assert low == []


def test_happy_every_entry_carries_a_sha256():
    # parse_lock refuses an entry without one; count to be sure nothing was skipped.
    assert len(LOCK) == len(re.findall(r"^[A-Za-z0-9][^\s]*==", LOCK_TEXT, re.M))
    assert all(p.hashes and all(re.fullmatch(r"[0-9a-f]{64}", h) for h in p.hashes) for p in LOCK)


def test_happy_the_input_lists_every_pyproject_requirement_with_its_floor():
    """build/requirements-bundle.in is the resolver's input: a requirement
    pyproject gains must reach it, or the lock silently drops it."""
    given = {}
    for spec in _in_requirements():
        name, floor, _marker = _requirement(spec)
        given[name] = floor
    drift = []
    for spec in _pyproject_requirements():
        name, floor, _marker = _requirement(spec)
        if name not in given:
            drift.append(f"{name} missing")
        elif floor and (given[name] is None or not _ge(given[name], floor)):
            drift.append(f"{name}: input floor {given[name]} below pyproject {floor}")
    assert drift == []


def test_happy_the_dockerfile_installs_only_from_the_lock_with_hashes():
    run = re.search(r"\nRUN (?:(?!\n\n).)*requirements-bootstrap\.txt(?:(?!\n\n).)*",
                    DOCKERFILE, re.S)
    assert run, "no install from the lock in Dockerfile.build"
    step = run.group(0)
    assert step.count("--require-hashes") == 2, step
    assert step.count("--only-binary=:all:") == 2, step
    assert "-r /tmp/lock/requirements-bundle.txt" in step
    assert step.index("requirements-bootstrap.txt") < step.index("requirements-bundle.txt")
    # No package is installed from a bare requirement any more.
    assert not re.search(r'pip install[^\n]*"[A-Za-z0-9_.-]+[<>=]', DOCKERFILE)
    assert "--upgrade pip" not in DOCKERFILE


def test_happy_the_builder_applies_the_security_updates():
    """The bundle carries the image's libssl, libexpat, libpcre2 ...: an image
    without ``dnf upgrade`` ships whatever the base image had."""
    first_dnf = DOCKERFILE.index("RUN dnf ")
    assert "dnf upgrade -y" in DOCKERFILE[first_dnf:DOCKERFILE.index("COPY build/")]


def test_happy_the_bootstrap_lock_is_the_lock_s_own_pip_and_setuptools():
    boot = parse_lock(BOOTSTRAP_TEXT)
    assert sorted(p.name for p in boot) == ["pip", "setuptools"]
    for pin in boot:
        assert pin in _pins(pin.name), pin.name


def test_happy_the_ci_bundles_install_from_the_same_lock():
    bundle_job = CI[CI.index("\n  bundle:"):]
    assert "-r build/requirements-bootstrap.txt" in bundle_job
    assert "-r build/requirements-bundle.txt" in bundle_job
    assert bundle_job.count("--require-hashes") == 2
    assert '".[all]"' not in bundle_job


# --- sad -------------------------------------------------------------------


def test_sad_no_sdist_is_built_with_build_isolation():
    """An sdist built in an isolated environment fetches its build backend
    unhashed. The packages without a Python 3 wheel build against the hashed
    setuptools instead."""
    for text in (DOCKERFILE, CI):
        for line in re.findall(r"--no-binary=(\S+)", text):
            for name in line.split(","):
                assert _pins(name), f"{name} in --no-binary is not in the lock"
        if "--no-binary=" in text:
            assert "--no-build-isolation" in text


def test_sad_the_lock_script_runs_the_resolver_in_a_container():
    assert re.search(r'"\$ENGINE" run --rm --cap-drop=ALL', LOCK_SCRIPT)
    assert re.search(r"python:3\.12-slim@sha256:[0-9a-f]{64}", LOCK_SCRIPT)
    assert "--require-hashes" in LOCK_SCRIPT and "--generate-hashes" in LOCK_SCRIPT
    assert "--universal" in LOCK_SCRIPT and "--python-version 3.12" in LOCK_SCRIPT


def test_sad_no_known_vulnerable_qt_is_locked():
    """Qt 6.10.2 is subject to the SVG marker heap overflow CVE-2026-6210 and
    the SVG / QXmlStreamReader denial-of-service advisories fixed in 6.11.2."""
    (qt,) = _pins("PyQt6-Qt6")
    assert _ge(qt.version, "6.11.2")
    (pyqt,) = _pins("PyQt6")
    assert _ge(pyqt.version, "6.11.0")


# --- edge ------------------------------------------------------------------


def test_edge_platform_markers_reach_the_lock():
    """Universal lock: the Windows-only terminal backend stays Windows-only,
    the axross-full-only voice stack stays Linux-only."""
    (winpty,) = _pins("pywinpty")
    assert "win32" in winpty.marker
    for name in ("piper-tts", "onnxruntime", "faster-whisper", "ctranslate2", "fusepy"):
        assert all("linux" in p.marker for p in _pins(name)), name


def test_edge_the_voice_pins_are_the_lock_s():
    """The licence table and the credits name the voice versions the builder
    installs: they come from the lock now."""
    licences = (ROOT / "THIRD_PARTY_LICENSES.md").read_text(encoding="utf-8")
    for name in ("piper-tts", "onnxruntime", "faster-whisper", "ctranslate2"):
        (pin,) = _pins(name)
        assert f"| {name} {pin.version} |" in licences, name


@pytest.mark.parametrize("name", ["watchdog", "pygments", "cryptography", "pyinstaller", "pip",
                                  # optional MCP argument validation (core/mcp_server.py);
                                  # the first lock dropped it, not being a pyproject dependency
                                  "jsonschema"])
def test_edge_formerly_missing_or_unpinned_packages_are_pinned(name):
    assert len(_pins(name)) == 1


def test_happy_the_build_wrapper_refuses_an_image_with_pending_security_updates():
    """A cached ``dnf upgrade`` layer keeps the updates of the day it was
    built; scripts/build_bundle_docker.sh checks the finished image."""
    wrapper = (ROOT / "scripts" / "build_bundle_docker.sh").read_text(encoding="utf-8")
    check = wrapper.index("updateinfo list --security")
    assert check < wrapper.index('CONTAINER_ID=$("$ENGINE" create')
    assert 'if [[ -n "$PENDING" ]]' in wrapper[check:] and "exit 7" in wrapper[check:]
    assert "AXROSS_BUILDER_NO_CACHE" in wrapper and "BUILD_ARGS+=(--no-cache)" in wrapper


def test_sad_the_builder_base_image_is_pinned_by_digest():
    froms = re.findall(r"^FROM (\S+)", DOCKERFILE, re.M)
    assert froms and all(re.search(r"@sha256:[0-9a-f]{64}$", f) for f in froms), froms


@pytest.mark.parametrize("source", ["source .gitignore", "public mirror .gitignore"])
def test_edge_the_lock_files_are_not_ignored(source):
    """osv-scanner skips what .gitignore ignores, and the repository ignores
    build/*: without the negations the CI scan never reads the lock (measured
    with osv-scanner v2.7.0: only dev-requirements.txt was scanned)."""
    if source == "source .gitignore":
        text = (ROOT / ".gitignore").read_text(encoding="utf-8")
    else:
        export = (ROOT / "scripts" / "export-public.py").read_text(encoding="utf-8")
        text = re.search(r'PUBLIC_GITIGNORE = """\\\n(.*?)"""', export, re.S).group(1)
    lines = text.splitlines()
    assert "build/*" in lines
    for name in ("requirements-bundle.in", "requirements-bundle.txt", "requirements-bootstrap.txt"):
        assert f"!build/{name}" in lines, name
