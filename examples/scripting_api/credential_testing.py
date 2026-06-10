"""Credential-test examples that do not fire network packets."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

COVERS = (
    "bruteforce",
    "spray",
    "enumerate_users",
)


def run(base_dir: str | os.PathLike[str] | None = None) -> dict:
    """Run authorized dry-run examples and a local fake enumeration oracle."""
    import axross
    from core import cred_attack
    from core.cred_attack import EnumResult
    from core.profiles import ConnectionProfile

    tmp_ctx = None
    if base_dir is None:
        tmp_ctx = tempfile.TemporaryDirectory()
        root = Path(tmp_ctx.name)
    else:
        root = Path(base_dir)
        root.mkdir(parents=True, exist_ok=True)

    try:
        profile = ConnectionProfile(
            name="example-pop3",
            protocol="pop3",
            host="example.invalid",
            port=110,
            username="",
            pop3_ssl=False,
        )

        spray_report = axross.spray(
            profile,
            users=["alice", "bob"],
            passwords=["Spring2026!", "Summer2026!"],
            dry_run=True,
            authorized=True,
        )
        brute_report = axross.bruteforce(
            profile,
            users=["alice"],
            passwords=["wrong", "also-wrong"],
            dry_run=True,
            state_file=root / "bruteforce-state.json",
            authorized=True,
        )
        assert spray_report.attempted_count == 0
        assert brute_report.attempted_count == 0
        assert len(spray_report.attempts) == 4
        assert len(brute_report.attempts) == 2

        old_oracle = cred_attack._ORACLES.get("pop3")  # noqa: SLF001

        def fake_pop3_oracle(_profile, candidates, _timeout_s, **_kwargs):
            return [
                EnumResult(
                    username=name,
                    likely_exists=name == "alice",
                    confidence=0.95 if name == "alice" else 0.1,
                    method="oracle:example",
                    notes="local fake oracle for documentation tests",
                )
                for name in candidates
            ]

        cred_attack.register_oracle("pop3", fake_pop3_oracle)
        try:
            enum_report = axross.enumerate_users(
                profile,
                ["alice", "mallory"],
                method="oracle",
                authorized=True,
            )
        finally:
            if old_oracle is None:
                cred_attack._ORACLES.pop("pop3", None)  # noqa: SLF001
            else:
                cred_attack._ORACLES["pop3"] = old_oracle  # noqa: SLF001

        assert enum_report.hits() == ["alice"]

        return {
            "spray_plan": len(spray_report.attempts),
            "bruteforce_plan": len(brute_report.attempts),
            "enum_hits": enum_report.hits(),
        }
    finally:
        if tmp_ctx is not None:
            tmp_ctx.cleanup()


if __name__ == "__main__":
    print(run())
