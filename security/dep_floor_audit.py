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

``--lock`` asks the other question, for what axross itself ships: the
one-file bundles are built from the exact pins of
``build/requirements-bundle.txt`` (installed with ``--require-hashes``), so
every pin there is checked against OSV - in one batch request - and any
advisory fails, malicious-package entries (``MAL-*``) included. A floor can
be clean while the pinned release is not, and the other way round.

Usage
-----
    python -m security.dep_floor_audit [--pyproject PATH] [--json]
    python -m security.dep_floor_audit --lock build/requirements-bundle.txt [--json]

Exit codes:
    0  every declared floor (or every exact pin) is free of known advisories
    1  at least one floor admits a known-vulnerable release, or a pin has an
       advisory
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
OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"
#: OSV answers at most this many queries per batch request.
OSV_BATCH_LIMIT = 1000
#: OSV id prefix of the malicious-package database (OpenSSF).
MALICIOUS_PREFIX = "MAL-"

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


def _post_json(url: str, body: dict, *, timeout: float = 60.0) -> dict:
    """POST *body* as JSON to one of the constant OSV URLs; the decoded answer."""
    request = urllib.request.Request(  # noqa: S310 — constant https URL
        url,
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
        return json.loads(response.read().decode())


def osv_query(name: str, version: str, *, timeout: float = 30.0) -> list[dict]:
    """Ask OSV which advisories affect ``name==version``."""
    body = _post_json(
        OSV_QUERY_URL,
        {"version": version, "package": {"name": name, "ecosystem": "PyPI"}},
        timeout=timeout,
    )
    return body.get("vulns", [])


def osv_querybatch(pairs: list[tuple[str, str]]) -> list[list[dict]]:
    """The advisories of every ``(name, version)`` in *pairs*, in order, asked
    in batches of OSV_BATCH_LIMIT. A result OSV pages (``next_page_token``)
    is asked again on its own, so no advisory is cut off."""
    out: list[list[dict]] = []
    for start in range(0, len(pairs), OSV_BATCH_LIMIT):
        chunk = pairs[start:start + OSV_BATCH_LIMIT]
        queries = [{"package": {"name": n, "ecosystem": "PyPI"}, "version": v} for n, v in chunk]
        results = _post_json(OSV_QUERYBATCH_URL, {"queries": queries}).get("results", [])
        if len(results) != len(chunk):
            raise ValueError(f"OSV answered {len(results)} results for {len(chunk)} queries")
        for (name, version), result in zip(chunk, results):
            if result.get("next_page_token"):
                out.append(osv_query(name, version))
            else:
                out.append(list(result.get("vulns", [])))
    return out


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


# --------------------------------------------------------------------------
# --lock: exact pins of a hashed requirements lock
# --------------------------------------------------------------------------

_PIN_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;\\]+)\s*(?:;\s*(.*?))?\s*$")
_HASH_RE = re.compile(r"^--hash=sha256:([0-9a-f]{64})$")


@dataclass(frozen=True)
class LockedPin:
    """One entry of a hashed lock: ``name==version ; marker`` and its hashes."""

    name: str
    version: str
    marker: str
    hashes: tuple[str, ...]


def parse_lock(text: str) -> list[LockedPin]:
    """The entries of a ``pip install --require-hashes`` lock (as uv and
    pip-tools write it), names PEP 503 normalised.

    Raises ``ValueError`` on an entry that is not pinned with ``==``, an
    entry without a sha256 hash, a hash that is not 64 hex digits, and a
    lock without any entry - each would be installed unchecked or not
    audited at all.
    """
    # Join continuation lines: an entry is one logical line.
    logical: list[str] = []
    pending = ""
    for raw in text.splitlines():
        line = raw.split(" #", 1)[0] if not raw.lstrip().startswith("#") else ""
        line = line.rstrip()
        if line.endswith("\\"):
            pending += line[:-1] + " "
            continue
        pending += line
        if pending.strip():
            logical.append(pending.strip())
        pending = ""
    if pending.strip():
        logical.append(pending.strip())

    pins: list[LockedPin] = []
    for entry in logical:
        head, *options = re.split(r"\s+(?=--)", entry)
        match = _PIN_RE.match(head)
        if not match:
            raise ValueError(f"not an exact pin (name==version): {head!r}")
        hashes = []
        for option in options:
            found = _HASH_RE.match(option.strip())
            if not found:
                raise ValueError(f"{head}: not a sha256 hash option: {option.strip()!r}")
            hashes.append(found.group(1))
        if not hashes:
            raise ValueError(f"{head}: no --hash, pip would install it unchecked")
        pins.append(LockedPin(_normalise(match.group(1)), match.group(2),
                              (match.group(3) or "").strip(), tuple(hashes)))
    if not pins:
        raise ValueError("no pinned entry in the lock")
    return pins


@dataclass(frozen=True)
class LockFinding:
    """One exact pin with advisories."""

    package: str
    version: str
    advisories: list[str] = field(default_factory=list)
    malicious: bool = False

    def describe(self) -> str:
        kind = "MALICIOUS PACKAGE" if self.malicious else "advisories"
        return f"{self.package}=={self.version}: {kind}: {', '.join(self.advisories)}"


def audit_lock(
    pins: list[LockedPin],
    *,
    query_batch: Callable[[list[tuple[str, str]]], list[list[dict]]] = osv_querybatch,
) -> list[LockFinding]:
    """One :class:`LockFinding` per pinned ``name==version`` OSV has any
    advisory for; each pair is asked once, whatever its markers."""
    pairs = list(dict.fromkeys((p.name, p.version) for p in pins))
    results = query_batch(pairs)
    if len(results) != len(pairs):
        raise ValueError(f"{len(results)} results for {len(pairs)} pins")
    findings = []
    for (name, version), vulns in zip(pairs, results):
        ids = sorted({v.get("id", "?") for v in vulns})
        if ids:
            findings.append(LockFinding(name, version, ids,
                                        any(i.startswith(MALICIOUS_PREFIX) for i in ids)))
    return findings


def _main_lock(path: Path, as_json: bool) -> int:
    try:
        pins = parse_lock(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        print(f"cannot read the lock {path}: {exc}", file=sys.stderr)
        return 2
    try:
        # Looked up at call time, so a test can replace the network call.
        findings = audit_lock(pins, query_batch=lambda pairs: osv_querybatch(pairs))
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        print(f"lock audit could not complete: {exc}", file=sys.stderr)
        return 2
    pairs = len({(p.name, p.version) for p in pins})
    if as_json:
        print(json.dumps([f.__dict__ for f in findings], indent=2))
    elif not findings:
        print(f"OK — no known advisories against any of the {pairs} exact pins in {path}")
    else:
        malicious = sum(f.malicious for f in findings)
        print(f"{len(findings)} of {pairs} exact pins have advisories "
              f"({malicious} malicious):\n")
        for finding in findings:
            print(f"  {finding.describe()}")
    return 1 if findings else 0


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
    parser.add_argument(
        "--lock",
        type=Path,
        help="audit the exact pins of this hashed lock (build/requirements-bundle.txt) "
        "instead of the pyproject floors; any advisory fails, malicious ones included",
    )
    args = parser.parse_args(argv)
    if args.lock is not None:
        return _main_lock(args.lock, args.json)

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
