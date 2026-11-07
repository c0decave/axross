"""core.units: the units of the pack system against pyproject's extras,
the bundled extensions and the bundle lock."""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import units as U  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


def test_happy_every_extra_and_every_bundled_extension_is_a_unit():
    extras = set(tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["optional-dependencies"]) - {"all"}
    names = {u.name for u in U.units()}
    assert {f"extra:{e}" for e in extras} <= names
    exts = {p.stem for p in (ROOT / "resources" / "extensions").glob("*.py") if not p.name.startswith("_")}
    assert {f"extension:{e}" for e in exts} <= names
    assert set(U.EXTENSION_NEEDS) <= exts


def test_happy_units_hold_locked_distributions_beyond_the_base():
    versions, _children = U.parse_lock()
    base = U.base_distributions()
    assert {"pyqt6", "paramiko", "cryptography"} <= base
    for u in U.units():
        assert u.distributions <= set(versions), u.name
        assert not u.distributions & base, u.name
    by = {u.name: u for u in U.units()}
    assert {"matrix-nio", "vodozemac", "slixmpp"} <= by["extra:chat"].distributions
    assert by["extension:matrix"].distributions == by["extra:chat"].distributions   # shared, one set
    assert by["extension:arcade"].distributions == frozenset()
    assert "smbprotocol" in by["extra:smb"].distributions


def test_happy_the_lock_reader_follows_via_lines():
    versions, children = U.parse_lock()
    assert "faster-whisper" in versions
    assert "ctranslate2" in U.closure(["faster-whisper"], children)
