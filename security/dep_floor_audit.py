#!/usr/bin/env python3
"""Audit the *declared dependency floors* in ``pyproject.toml`` against
the OSV vulnerability database.

Why this exists alongside pip-audit
-----------------------------------
``pip-audit`` (wired into ``security/run_analysis.sh``) inspects the
versions that happen to be *installed*. On a developer box that is
always "whatever pip resolved this morning", i.e. the newest release —
so it reports clean even when the published metadata permits a
vulnerable install.

What a consumer of the published wheel actually gets is bounded by the
floors in ``[project].dependencies`` / ``[project.optional-dependencies]``.
``foo>=1.0`` means "1.0 is acceptable", so every advisory fixed in 1.0.1
remains reachable for anyone with a pinned or cached resolution, an old
index mirror, or a conflicting co-dependency that forces the resolver
downwards. Auditing only the resolved set therefore cannot answer the
question "can a user install a vulnerable version of axross?".

This tool asks OSV that question directly, once per declared floor.

Usage
-----
    python -m security.dep_floor_audit [--pyproject PATH] [--json]

Exit codes:
    0  every declared floor is free of known advisories
    1  at least one floor admits a known-vulnerable release
    2  the audit could not run (network/parse failure)

Network: talks to https://api.osv.dev only, over stdlib ``urllib``. It
never invokes a package manager and never executes downloaded content,
so it is safe to run outside a build container — but the repo's
convention is to run it inside the disposable scanner image
(``security/Dockerfile``) along with the rest of the suite.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable

try:  # ``tomllib`` is stdlib from 3.11; the project supports 3.10 too.
    import tomllib
except ImportError:  # pragma: no cover - exercised only on 3.10
    import tomli as tomllib  # type: ignore[no-redef]

OSV_QUERY_URL = "https://api.osv.dev/v1/query"

# PEP 508-ish: a distribution name, optional extras, then the specifier
# soup. We deliberately do not implement the full grammar — the input is
# our own pyproject, and anything this does not understand raises rather
# than being silently skipped.
_NAME_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(.*)$", re.DOTALL)
_LOWER_BOUND_RE = re.compile(r"(?:>=|==|~=)\s*([0-9][0-9A-Za-z.*+!-]*)")


@dataclass(frozen=True)
class Finding:
    """One declared floor that admits a known-vulnerable release."""

    package: str
    floor: str
    advisories: list[str] = field(default_factory=list)
    suggested_floor: str | None = None

    def describe(self) -> str:
        ids = ", ".join(self.advisories)
        if self.suggested_floor:
            fix = f"raise floor to >={self.suggested_floor}"
        else:
            fix = "NO FIXED RELEASE — drop or replace this dependency"
        return f"{self.package}>={self.floor}: {ids} — {fix}"


def _normalise(name: str) -> str:
    """PEP 503 normalisation — OSV indexes PyPI under this form."""
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_requirement(requirement: str) -> tuple[str, str | None]:
    """Split a PEP 508 requirement into ``(normalised_name, floor)``.

    ``floor`` is ``None`` when the requirement declares no lower bound —
    those are not auditable (any resolver takes the newest release), so
    the caller skips them rather than guessing a version.

    Raises ``ValueError`` on input that is not a requirement at all; a
    silent skip there would turn a typo in pyproject.toml into an
    unaudited dependency.
    """
    # Environment markers do not affect which version is chosen.
    head = requirement.split(";", 1)[0]
    match = _NAME_RE.match(head)
    if not match:
        raise ValueError(f"not a parseable requirement: {requirement!r}")
    name, specifiers = match.group(1), match.group(2)
    bound = _LOWER_BOUND_RE.search(specifiers)
    return _normalise(name), bound.group(1) if bound else None


def declared_requirements(project_metadata: dict) -> list[str]:
    """Every requirement string in ``[project]``, deduplicated.

    The ``all`` extra repeats each per-backend extra verbatim; without
    deduplication the audit would issue ~30 redundant OSV requests.
    ``dict.fromkeys`` keeps first-seen order so output stays stable.
    """
    reqs: list[str] = list(project_metadata.get("dependencies", []))
    for pkgs in project_metadata.get("optional-dependencies", {}).values():
        reqs.extend(pkgs)
    return list(dict.fromkeys(reqs))


def _version_key(version: str) -> tuple:
    """Sort key for PyPI versions, newest highest.

    Uses ``packaging`` when available (correct PEP 440 ordering) and
    falls back to a numeric-segment tuple otherwise. The fallback still
    orders 1.10.0 above 1.9.0 — plain string comparison does not, and
    getting that backwards yields a floor bump that keeps admitting the
    vulnerable release.
    """
    try:
        from packaging.version import Version

        return (1, Version(version))
    except Exception:
        parts = re.findall(r"\d+", version)
        return (0, tuple(int(p) for p in parts))


def lowest_safe_version(vulns: Iterable[dict]) -> str | None:
    """Smallest version that clears *every* supplied OSV advisory.

    Returns ``None`` when at least one PyPI advisory has no ``fixed``
    event — no floor bump can escape an unfixed vulnerability, and
    reporting one anyway would be worse than reporting nothing.
    """
    fixes: list[str] = []
    saw_pypi = False
    for vuln in vulns:
        for affected in vuln.get("affected", []):
            if affected.get("package", {}).get("ecosystem") != "PyPI":
                continue
            saw_pypi = True
            fixed_here = [
                event["fixed"]
                for rng in affected.get("ranges", [])
                for event in rng.get("events", [])
                if "fixed" in event
            ]
            if not fixed_here:
                return None
            fixes.extend(fixed_here)
    if not saw_pypi or not fixes:
        return None
    return max(fixes, key=_version_key)


def osv_query(name: str, version: str, *, timeout: float = 30.0) -> list[dict]:
    """Ask OSV which advisories affect ``name==version``."""
    payload = json.dumps(
        {"version": version, "package": {"name": name, "ecosystem": "PyPI"}}
    ).encode()
    request = urllib.request.Request(  # noqa: S310 — constant https URL
        OSV_QUERY_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
        body = json.loads(response.read().decode())
    return body.get("vulns", [])


def audit_floors(
    project_metadata: dict,
    *,
    query: Callable[[str, str], list[dict]] = osv_query,
) -> list[Finding]:
    """Return one :class:`Finding` per declared floor with advisories."""
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for requirement in declared_requirements(project_metadata):
        name, floor = parse_requirement(requirement)
        if floor is None or (name, floor) in seen:
            continue
        seen.add((name, floor))
        vulns = query(name, floor)
        if not vulns:
            continue
        findings.append(
            Finding(
                package=name,
                floor=floor,
                advisories=sorted(v.get("id", "?") for v in vulns),
                suggested_floor=lowest_safe_version(vulns),
            )
        )
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--pyproject",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "pyproject.toml",
        help="path to pyproject.toml (default: repo root)",
    )
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args(argv)

    try:
        metadata = tomllib.loads(args.pyproject.read_text())["project"]
    except (OSError, KeyError, tomllib.TOMLDecodeError) as exc:
        print(f"cannot read project metadata from {args.pyproject}: {exc}", file=sys.stderr)
        return 2

    try:
        findings = audit_floors(metadata)
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        print(f"floor audit could not complete: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps([f.__dict__ for f in findings], indent=2))
    elif not findings:
        total = len(declared_requirements(metadata))
        print(f"OK — no known advisories against any declared floor ({total} requirements)")
    else:
        print(f"{len(findings)} declared floor(s) admit a known-vulnerable release:\n")
        for finding in findings:
            print(f"  {finding.describe()}")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
