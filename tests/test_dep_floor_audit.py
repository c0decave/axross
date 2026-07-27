#!/usr/bin/env python3
"""Tests for security/dep_floor_audit.py.

``pip-audit`` answers "is the environment I just resolved vulnerable?".
It cannot answer "can a user resolve a vulnerable version from our
published metadata?" — and that is the question that matters for a
library on PyPI, because the floors in ``pyproject.toml`` are what a
consumer's resolver is actually bound by. A dependency pinned
``foo>=1.0`` is a supply-chain hole for every advisory fixed in 1.0.1.

These tests cover the pure logic (requirement parsing, advisory
interpretation, floor comparison). The network call itself is injected
so the suite stays offline-clean.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from security.dep_floor_audit import (  # noqa: E402
    Finding,
    audit_floors,
    declared_requirements,
    lowest_safe_version,
    parse_requirement,
)

# --------------------------------------------------------------------------
# parse_requirement
# --------------------------------------------------------------------------


def test_happy_parse_simple_lower_bound():
    assert parse_requirement("requests>=2.31") == ("requests", "2.31")


def test_happy_parse_strips_extras_and_whitespace():
    # psycopg[binary]>=3.1 is a real entry in pyproject.toml — the
    # extra must not become part of the package name or the OSV
    # lookup silently returns "no advisories" for a name that does
    # not exist.
    assert parse_requirement("psycopg[binary]>=3.1") == ("psycopg", "3.1")
    assert parse_requirement("  Pillow >= 10.0  ") == ("pillow", "10.0")


def test_happy_parse_keeps_lower_bound_when_upper_bound_present():
    assert parse_requirement("paramiko>=5.0,<6.0") == ("paramiko", "5.0")


def test_edge_parse_no_lower_bound_returns_none_version():
    # An unconstrained dependency has no floor to audit — the
    # resolver will take the newest release. Report it as "no floor"
    # rather than inventing 0.0.
    assert parse_requirement("PySocks") == ("pysocks", None)


def test_edge_parse_environment_marker_is_ignored():
    name, floor = parse_requirement('pywin32>=306; sys_platform == "win32"')
    assert (name, floor) == ("pywin32", "306")


def test_sad_parse_rejects_garbage():
    with pytest.raises(ValueError):
        parse_requirement("=====")


# --------------------------------------------------------------------------
# declared_requirements
# --------------------------------------------------------------------------


def test_happy_declared_requirements_covers_core_and_extras():
    meta = {
        "dependencies": ["alpha>=1.0"],
        "optional-dependencies": {"x": ["beta>=2.0"], "all": ["beta>=2.0", "gamma>=3.0"]},
    }
    got = declared_requirements(meta)
    # Deduplicated (``all`` repeats the per-backend extras) but every
    # distinct requirement present.
    assert sorted(got) == ["alpha>=1.0", "beta>=2.0", "gamma>=3.0"]


def test_edge_declared_requirements_handles_missing_optional_table():
    assert declared_requirements({"dependencies": ["alpha>=1.0"]}) == ["alpha>=1.0"]


def test_sad_declared_requirements_on_empty_metadata():
    assert declared_requirements({}) == []


# --------------------------------------------------------------------------
# lowest_safe_version — pick the floor bump that clears every advisory
# --------------------------------------------------------------------------


def _advisory(vid: str, introduced: str, fixed: str | None) -> dict:
    event: list[dict] = [{"introduced": introduced}]
    if fixed is not None:
        event.append({"fixed": fixed})
    return {
        "id": vid,
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "demo"},
                "ranges": [{"type": "ECOSYSTEM", "events": event}],
            }
        ],
    }


def test_happy_lowest_safe_version_picks_highest_fix():
    vulns = [_advisory("A", "0", "1.2.0"), _advisory("B", "0", "1.5.3")]
    assert lowest_safe_version(vulns) == "1.5.3"


def test_edge_lowest_safe_version_orders_by_version_not_string():
    # "1.10.0" sorts BELOW "1.9.0" as a string. Getting this wrong
    # produces a floor bump that still admits a vulnerable release.
    vulns = [_advisory("A", "0", "1.9.0"), _advisory("B", "0", "1.10.0")]
    assert lowest_safe_version(vulns) == "1.10.0"


def test_sad_lowest_safe_version_none_when_advisory_has_no_fix():
    # An unfixed advisory cannot be escaped by bumping a floor; the
    # caller has to drop or replace the dependency, so we must not
    # hand back a bogus "safe" version.
    assert lowest_safe_version([_advisory("A", "0", None)]) is None


def test_edge_lowest_safe_version_ignores_non_pypi_ecosystems():
    vuln = {
        "id": "X",
        "affected": [
            {
                "package": {"ecosystem": "Debian", "name": "demo"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "9.9"}]}
                ],
            }
        ],
    }
    assert lowest_safe_version([vuln]) is None


# --------------------------------------------------------------------------
# audit_floors — the integration point, with the OSV call injected
# --------------------------------------------------------------------------


def test_happy_audit_floors_clean_set_reports_nothing():
    meta = {"dependencies": ["alpha>=2.0"]}
    findings = audit_floors(meta, query=lambda name, version: [])
    assert findings == []


def test_sad_audit_floors_flags_vulnerable_floor():
    meta = {"dependencies": ["demo>=1.0"]}

    def fake_query(name, version):
        assert (name, version) == ("demo", "1.0")
        return [_advisory("GHSA-xxxx", "0", "1.4.0")]

    findings = audit_floors(meta, query=fake_query)
    assert len(findings) == 1
    found = findings[0]
    assert isinstance(found, Finding)
    assert found.package == "demo"
    assert found.floor == "1.0"
    assert found.advisories == ["GHSA-xxxx"]
    assert found.suggested_floor == "1.4.0"


def test_edge_audit_floors_skips_unbounded_requirement():
    # Nothing to query: without a floor there is no vulnerable
    # version a resolver could legally pick.
    calls = []

    def fake_query(name, version):
        calls.append((name, version))
        return []

    findings = audit_floors({"dependencies": ["demo"]}, query=fake_query)
    assert findings == []
    assert calls == []


def test_edge_audit_floors_queries_each_package_once():
    # The "all" extra duplicates every per-backend extra; a naive
    # implementation triples the OSV request count for no gain.
    meta = {
        "dependencies": [],
        "optional-dependencies": {"a": ["demo>=1.0"], "all": ["demo>=1.0"]},
    }
    calls = []

    def fake_query(name, version):
        calls.append((name, version))
        return []

    audit_floors(meta, query=fake_query)
    assert calls == [("demo", "1.0")]
