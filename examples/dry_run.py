"""Dry-run a credential test plan — print what *would* be tried,
without firing any packets.

``dry_run=True`` walks the user × password generator the same way the
real run would, emits a ``SKIPPED`` outcome for each pair, and never
opens a socket. Useful for sanity-checking a wordlist before turning
it loose on a target.

No confirmation prompt because nothing intrusive happens.
"""

from __future__ import annotations

import logging
import sys

USERS = [
    "alice",
    "bob",
    "carol",
]

PASSWORDS = [
    "Welcome2026!",
    "Spring2026!",
    "Summer2026!",
]


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )

    from core.cred_attack import AttemptOutcome, spray
    from core.profiles import ConnectionProfile

    profile = ConnectionProfile(
        name="example-dry-run",
        protocol="pop3",
        host="example.invalid",  # Will not be contacted; dry_run=True.
        port=995,
        pop3_ssl=True,
    )

    print("Plan (password-major / spray order):")

    def show(o: AttemptOutcome) -> None:
        print(f"  [·] {o.username:<14} pwd_hash={o.password_hash}")

    report = spray(
        profile,
        users=USERS,
        passwords=PASSWORDS,
        progress=show,
        dry_run=True,
        authorized=True,
    )
    print()
    print(report.summary())
    return 0


if __name__ == "__main__":
    sys.exit(main())
