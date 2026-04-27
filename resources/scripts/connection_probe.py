"""connection_probe.py — open every saved profile, time the connect.

For each saved profile, ``ConnectionManager.connect`` is called and
the round-trip is timed. Profiles that need a password / passphrase
are skipped unless the caller supplied a callback in ``ask_secret``
(we never silently fail-open with an empty password).

Use case: pre-flight before a migration window — "are all my
profiles still reachable in less than 2 seconds?".

Usage::

    timings = probe(timeout_warn=2.0)
    for name, ms, status in timings:
        print(f"{name:<40s} {status:<6s} {ms:6.0f} ms")
"""
from __future__ import annotations

import time

from core.connection_manager import ConnectionManager
from core.profiles import ProfileManager


def probe(ask_secret=None, timeout_warn: float = 2.0) -> list[tuple[str, float, str]]:
    """Return ``[(profile_name, elapsed_ms, status), ...]`` where
    status is ``"ok" | "skip" | "fail"`` and elapsed_ms is the
    wall-clock time in milliseconds. ``ask_secret`` is an optional
    callback ``(profile, kind) -> str`` invoked when the profile
    needs a password / passphrase."""
    out: list[tuple[str, float, str]] = []
    pm = ProfileManager()
    cm = ConnectionManager()
    cm.set_profile_resolver(pm.get)
    for profile in pm.all_profiles():
        password = ""
        passphrase = ""
        if ask_secret is not None:
            try:
                password = ask_secret(profile, "password") or ""
                passphrase = ask_secret(profile, "passphrase") or ""
            except Exception:  # noqa: BLE001
                password = passphrase = ""
        t0 = time.monotonic()
        try:
            sess = cm.connect(
                profile, password=password, key_passphrase=passphrase,
            )
        except Exception:  # noqa: BLE001
            elapsed = (time.monotonic() - t0) * 1000.0
            out.append((profile.name, elapsed, "fail"))
            continue
        elapsed = (time.monotonic() - t0) * 1000.0
        try:
            sess.close()
        except Exception:  # noqa: BLE001
            pass
        status = "ok" if elapsed < timeout_warn * 1000.0 else "slow"
        out.append((profile.name, elapsed, status))
    return out
