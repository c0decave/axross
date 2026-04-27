"""hash_audit.py — verify a manifest against a backend.

Reads a tab-separated manifest of ``<sha256>\\t<path>`` lines and
checks every path on BACKEND against the listed digest. Returns
``{"ok": [...], "mismatch": [...], "missing": [...]}`` so a CI
job can fail loudly when a deployment's binaries no longer match
the manifest baked at build time.

Usage::

    backend = axross.open("prod-bucket")
    report = audit("/etc/manifest.sha256", backend, "/")
"""
from __future__ import annotations


def audit(manifest_local_path: str, backend, root: str) -> dict[str, list]:
    text = axross.read_text(axross.localfs(), manifest_local_path)
    expected: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t", 1)
        if len(parts) != 2:
            continue
        expected[parts[1]] = parts[0].lower()

    ok, mismatch, missing = [], [], []
    for rel, expected_digest in expected.items():
        full = backend.join(root, rel) if rel else root
        try:
            cs = axross.checksum(backend, full, "sha256")
            digest = cs.split(":", 1)[-1].lower() if cs else ""
        except OSError:
            missing.append(rel)
            continue
        if digest == expected_digest:
            ok.append(rel)
        else:
            mismatch.append({"path": rel, "expected": expected_digest, "actual": digest})
    return {"ok": ok, "mismatch": mismatch, "missing": missing}
