"""The container build context never carries the release signing keys or
other private key material (review B, 2026-11-19: build/release-key/*.pem
went into the builder image through `COPY . .`, because a bare `*.pem` in
.dockerignore matches only at the context root)."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _rules() -> set[str]:
    lines = (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
    return {line.strip() for line in lines if line.strip() and not line.startswith("#")}


def test_sad_the_release_keys_and_every_key_file_stay_out_of_the_build_context():
    rules = _rules()
    assert "build/release-key/" in rules
    for pattern in ("**/*.pem", "**/*.key", "**/*.p12", "**/*.pfx"):
        assert pattern in rules, pattern


def test_sad_no_rule_takes_them_back_in():
    assert not any(r.startswith("!") and ("key" in r or "pem" in r) for r in _rules())
