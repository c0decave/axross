"""Tests for ``core.cred_attack`` — bruteforce / spray / user enum.

No network. Every test stubs out the connect path so the assertions
pin down the loop logic, classifier, rate-limiter, resume state, and
authorisation gate.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from core import cred_attack
from core.cred_attack import (
    AttackReport,
    AttemptOutcome,
    AttemptResult,
    EnumResult,
    bruteforce,
    classify_error,
    enumerate_users,
    register_marker,
    spray,
)
from core.profiles import ConnectionProfile

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _profile() -> ConnectionProfile:
    return ConnectionProfile(
        name="cred-attack-test",
        protocol="pop3",
        host="dummy.invalid",
        port=995,
        pop3_ssl=True,
    )


def _fake_attempt_factory(table):
    """Return a stand-in for ``_attempt_login`` driven by a lookup
    table mapping ``(username, password)`` → ``AttemptResult``.

    Missing keys default to ``AttemptResult.FAILED``. Each attempt
    bumps a counter so callers can assert how many real attempts the
    loop made.
    """
    state = {"calls": 0}

    def fake(template, username, password, *, timeout_s):
        state["calls"] += 1
        result = table.get((username, password), AttemptResult.FAILED)
        return AttemptOutcome(
            username=username,
            password_hash="hash:" + password[:8],
            result=result,
            elapsed_s=0.001,
            error_message="" if result is AttemptResult.SUCCESS else "stub-failed",
        )

    return fake, state


# ---------------------------------------------------------------------------
# Authorisation gate
# ---------------------------------------------------------------------------


class AuthorizationGateTests(unittest.TestCase):
    """The ``authorized=True`` kwarg is mandatory and unforgiving."""

    def test_bruteforce_refuses_without_authorized(self) -> None:
        with self.assertRaises(PermissionError):
            bruteforce(_profile(), users=["a"], passwords=["p"])

    def test_spray_refuses_without_authorized(self) -> None:
        with self.assertRaises(PermissionError):
            spray(_profile(), users=["a"], password="p")

    def test_enumerate_users_refuses_without_authorized(self) -> None:
        with self.assertRaises(PermissionError):
            enumerate_users(_profile(), ["a", "b"])

    def test_paranoid_mode_blocks_even_with_authorized(self) -> None:
        from core import security_mode

        prev = security_mode.current_policy().name
        try:
            security_mode.set_policy("paranoid")
            with self.assertRaises(PermissionError):
                bruteforce(
                    _profile(),
                    users=["a"],
                    passwords=["p"],
                    authorized=True,
                    dry_run=True,
                )
        finally:
            security_mode.set_policy(prev)


# ---------------------------------------------------------------------------
# Classifier
# ---------------------------------------------------------------------------


class ClassifierTests(unittest.TestCase):
    """``classify_error`` must distinguish lockout from failure from
    network error, with lockout markers winning over failure markers."""

    def test_plain_auth_failure(self) -> None:
        result, _reason = classify_error(OSError("Authentication failed"), "pop3")
        self.assertIs(result, AttemptResult.FAILED)

    def test_live_lab_auth_failure_markers(self) -> None:
        for text in (
            "WebDAV PROPFIND http://host/: HTTP 401",
            "Access denied to S3 bucket",
            "% Login invalid",
        ):
            with self.subTest(text=text):
                result, _reason = classify_error(OSError(text), "test")
                self.assertIs(result, AttemptResult.FAILED)

    def test_lockout_marker_wins(self) -> None:
        # The exception text contains both markers; lockout must win
        # so we don't keep attacking a locked account. ``reason``
        # carries whichever lockout marker matched first.
        exc = OSError("too many failed login attempts — account locked out")
        result, reason = classify_error(exc, "smb")
        self.assertIs(result, AttemptResult.LOCKOUT)
        self.assertTrue(reason.startswith("marker:"))

    def test_network_error_classified_as_error(self) -> None:
        result, _reason = classify_error(OSError("Connection refused"), "sftp")
        self.assertIs(result, AttemptResult.ERROR)

    def test_unknown_message_defaults_to_error(self) -> None:
        result, _reason = classify_error(OSError("XYZZY"), "ftp")
        self.assertIs(result, AttemptResult.ERROR)

    def test_register_custom_lockout_marker(self) -> None:
        register_marker("frobnicator melted", kind="lockout")
        result, _ = classify_error(OSError("the frobnicator melted"), "pop3")
        self.assertIs(result, AttemptResult.LOCKOUT)

    def test_register_marker_rejects_unknown_kind(self) -> None:
        with self.assertRaises(ValueError):
            register_marker("xxx", kind="bogus")


# ---------------------------------------------------------------------------
# Strategy + loop control
# ---------------------------------------------------------------------------


class SprayLoopTests(unittest.TestCase):
    """Spray iterates password-major and respects the loop controls."""

    def setUp(self) -> None:
        self.profile = _profile()

    def test_password_major_order(self) -> None:
        seen: list[tuple[str, str]] = []

        def fake(template, username, password, *, timeout_s):
            seen.append((username, password))
            return AttemptOutcome(
                username=username,
                password_hash="x",
                result=AttemptResult.FAILED,
                elapsed_s=0.0,
            )

        with mock.patch.object(cred_attack, "_attempt_login", fake):
            spray(
                self.profile,
                users=["alice", "bob"],
                passwords=["p1", "p2"],
                rate_per_min=10000,  # don't sleep
                authorized=True,
            )
        # Spray = password-major: p1/alice, p1/bob, p2/alice, p2/bob.
        self.assertEqual(
            seen,
            [
                ("alice", "p1"),
                ("bob", "p1"),
                ("alice", "p2"),
                ("bob", "p2"),
            ],
        )

    def test_lockout_aborts_run_immediately(self) -> None:
        """One LOCKOUT outcome → the run stops, even mid-pass."""
        table = {("bob", "p1"): AttemptResult.LOCKOUT}
        fake, state = _fake_attempt_factory(table)
        with mock.patch.object(cred_attack, "_attempt_login", fake):
            report = spray(
                self.profile,
                users=["alice", "bob", "carol"],
                passwords=["p1", "p2"],
                rate_per_min=10000,
                authorized=True,
            )
        self.assertTrue(report.aborted)
        self.assertIn("lockout", report.abort_reason)
        # alice + bob attempted in pass 1; carol never reached.
        self.assertEqual(state["calls"], 2)
        self.assertEqual(report.lockouts, 1)

    def test_stop_on_first_success_per_user(self) -> None:
        table = {("alice", "p1"): AttemptResult.SUCCESS}
        fake, state = _fake_attempt_factory(table)
        with mock.patch.object(cred_attack, "_attempt_login", fake):
            report = spray(
                self.profile,
                users=["alice", "bob"],
                passwords=["p1", "p2"],
                rate_per_min=10000,
                authorized=True,
            )
        # Pass 1: alice (SUCCESS), bob (FAILED). Pass 2: alice SKIPPED
        # (already auth'd), bob (FAILED).
        self.assertEqual(len(report.successes), 1)
        self.assertEqual(report.successes[0].username, "alice")
        skipped = [a for a in report.attempts if a.result is AttemptResult.SKIPPED]
        self.assertEqual(len(skipped), 1)
        self.assertEqual(skipped[0].username, "alice")
        # Real attempt count: 3 (alice/p1, bob/p1, bob/p2).
        self.assertEqual(state["calls"], 3)

    def test_max_attempts_caps_run(self) -> None:
        fake, state = _fake_attempt_factory({})
        with mock.patch.object(cred_attack, "_attempt_login", fake):
            report = spray(
                self.profile,
                users=["a", "b", "c", "d"],
                passwords=["p1", "p2"],
                rate_per_min=10000,
                max_attempts=3,
                authorized=True,
            )
        self.assertEqual(state["calls"], 3)
        self.assertTrue(report.aborted)

    def test_dry_run_makes_no_calls(self) -> None:
        fake, state = _fake_attempt_factory({})
        with mock.patch.object(cred_attack, "_attempt_login", fake):
            report = spray(
                self.profile,
                users=["alice", "bob"],
                passwords=["p1", "p2"],
                dry_run=True,
                authorized=True,
            )
        self.assertEqual(state["calls"], 0)
        self.assertEqual(len(report.attempts), 4)
        self.assertTrue(all(a.result is AttemptResult.SKIPPED for a in report.attempts))

    def test_progress_callback_exception_does_not_abort(self) -> None:
        fake, _ = _fake_attempt_factory({})

        def bad_progress(_outcome):
            raise RuntimeError("callback exploded")

        with mock.patch.object(cred_attack, "_attempt_login", fake):
            report = spray(
                self.profile,
                users=["a"],
                passwords=["p1", "p2"],
                rate_per_min=10000,
                progress=bad_progress,
                authorized=True,
            )
        # Two attempts still recorded — runner swallowed callback errors.
        self.assertEqual(report.attempted_count, 2)

    def test_unknown_host_callback_is_forwarded_when_supplied(self) -> None:
        callback = object()
        seen = []

        def fake(template, username, password, *, timeout_s, on_unknown_host=None):
            seen.append(on_unknown_host)
            return AttemptOutcome(
                username=username,
                password_hash="x",
                result=AttemptResult.FAILED,
                elapsed_s=0.0,
            )

        with mock.patch.object(cred_attack, "_attempt_login", fake):
            spray(
                self.profile,
                users=["a"],
                passwords=["p1"],
                rate_per_min=10000,
                on_unknown_host=callback,
                authorized=True,
            )
        self.assertEqual(seen, [callback])

    def test_dry_run_progress_callback_exception_does_not_abort(self) -> None:
        fake, state = _fake_attempt_factory({})

        def bad_progress(_outcome):
            raise RuntimeError("callback exploded")

        with mock.patch.object(cred_attack, "_attempt_login", fake):
            report = spray(
                self.profile,
                users=["a"],
                passwords=["p1"],
                dry_run=True,
                progress=bad_progress,
                authorized=True,
            )
        self.assertEqual(state["calls"], 0)
        self.assertEqual(len(report.attempts), 1)
        self.assertIs(report.attempts[0].result, AttemptResult.SKIPPED)

    def test_invalid_loop_controls_are_rejected_before_sleep(self) -> None:
        with self.assertRaises(ValueError):
            spray(
                self.profile,
                users=["a"],
                password="p",
                rate_per_min=0,
                authorized=True,
            )
        with self.assertRaises(ValueError):
            spray(
                self.profile,
                users=["a"],
                password="p",
                jitter_s=-0.1,
                authorized=True,
            )
        with self.assertRaises(ValueError):
            spray(
                self.profile,
                users=["a"],
                password="p",
                max_attempts=0,
                authorized=True,
            )


class BruteforceLoopTests(unittest.TestCase):
    def test_user_major_order(self) -> None:
        seen: list[tuple[str, str]] = []

        def fake(template, username, password, *, timeout_s):
            seen.append((username, password))
            return AttemptOutcome(
                username=username,
                password_hash="x",
                result=AttemptResult.FAILED,
                elapsed_s=0.0,
            )

        with mock.patch.object(cred_attack, "_attempt_login", fake):
            bruteforce(
                _profile(),
                users=["alice", "bob"],
                passwords=["p1", "p2"],
                rate_per_min=10000,
                authorized=True,
            )
        # Brute-force = user-major: alice/p1, alice/p2, bob/p1, bob/p2.
        self.assertEqual(
            seen,
            [
                ("alice", "p1"),
                ("alice", "p2"),
                ("bob", "p1"),
                ("bob", "p2"),
            ],
        )

    def test_abort_after_n_failures(self) -> None:
        fake, state = _fake_attempt_factory({})
        with mock.patch.object(cred_attack, "_attempt_login", fake):
            report = bruteforce(
                _profile(),
                users=["a"],
                passwords=["p1", "p2", "p3", "p4", "p5"],
                rate_per_min=10000,
                abort_after_n_failures=3,
                authorized=True,
            )
        self.assertEqual(state["calls"], 3)
        self.assertTrue(report.aborted)
        self.assertIn("consecutive failures", report.abort_reason)

    def test_empty_users_rejected(self) -> None:
        with self.assertRaises(ValueError):
            bruteforce(_profile(), users=[], passwords=["p"], authorized=True)

    def test_empty_passwords_rejected(self) -> None:
        with self.assertRaises(ValueError):
            bruteforce(_profile(), users=["a"], passwords=[], authorized=True)

    def test_usernames_with_control_chars_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            bruteforce(
                _profile(),
                users=["alice\r\nPASS injected"],
                passwords=["p"],
                authorized=True,
            )

    def test_passwords_with_control_chars_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            bruteforce(
                _profile(),
                users=["alice"],
                passwords=["pw\r\nUSER injected"],
                authorized=True,
            )

    def test_single_string_wordlists_are_rejected(self) -> None:
        with self.assertRaises(TypeError):
            bruteforce(_profile(), users="alice", passwords=["p"], authorized=True)
        with self.assertRaises(TypeError):
            bruteforce(_profile(), users=["alice"], passwords="secret", authorized=True)

    def test_spray_rejects_password_and_passwords_together(self) -> None:
        with self.assertRaises(ValueError):
            spray(_profile(), users=["a"], password="p", passwords=["p2"], authorized=True)

    def test_spray_requires_some_password(self) -> None:
        with self.assertRaises(ValueError):
            spray(_profile(), users=["a"], authorized=True)

    def test_protocols_that_do_not_consume_passwords_are_rejected(self) -> None:
        p = _profile()
        p.protocol = "tftp"
        p.port = 69
        with self.assertRaisesRegex(ValueError, "false positives"):
            spray(p, users=["a"], password="p", dry_run=True, authorized=True)

    def test_azure_static_secret_profiles_are_rejected(self) -> None:
        p = _profile()
        p.protocol = "azure_blob"
        p.azure_connection_string = "UseDevelopmentStorage=true"
        with self.assertRaisesRegex(ValueError, "bypass candidate passwords"):
            bruteforce(p, users=["acct"], passwords=["key"], authorized=True)

    def test_iscsi_without_chap_username_is_rejected(self) -> None:
        p = _profile()
        p.protocol = "iscsi"
        p.username = ""
        with self.assertRaisesRegex(ValueError, "CHAP username"):
            bruteforce(p, users=["chap"], passwords=["secret"], authorized=True)


# ---------------------------------------------------------------------------
# Resume state
# ---------------------------------------------------------------------------


class ResumeStateTests(unittest.TestCase):
    def test_resume_skips_previously_attempted_pairs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state_file = Path(tmp) / "resume.json"
            fake1, state1 = _fake_attempt_factory({})
            with mock.patch.object(cred_attack, "_attempt_login", fake1):
                spray(
                    _profile(),
                    users=["alice"],
                    passwords=["p1", "p2"],
                    rate_per_min=10000,
                    state_file=state_file,
                    authorized=True,
                )
            self.assertEqual(state1["calls"], 2)
            self.assertTrue(state_file.exists())
            self.assertEqual(state_file.stat().st_mode & 0o777, 0o600)
            data = json.loads(state_file.read_text())
            self.assertEqual(len(data["attempted"]), 2)

            # Second run with overlap → skipped, only the new pair fires.
            fake2, state2 = _fake_attempt_factory({})
            with mock.patch.object(cred_attack, "_attempt_login", fake2):
                report = spray(
                    _profile(),
                    users=["alice"],
                    passwords=["p1", "p2", "p3"],
                    rate_per_min=10000,
                    state_file=state_file,
                    authorized=True,
                )
            self.assertEqual(state2["calls"], 1)  # only p3 was new
            skipped = sum(1 for a in report.attempts if a.result is AttemptResult.SKIPPED)
            self.assertEqual(skipped, 2)

    def test_resume_state_for_different_target_is_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state_file = Path(tmp) / "resume.json"
            state_file.write_text(
                json.dumps(
                    {
                        "target_key": "ssh://other.host:22",
                        "started_at": time.time(),
                        "attempted": [["alice", "hash:x"]],
                        "successes": [],
                    }
                )
            )

            fake, state = _fake_attempt_factory({})
            with mock.patch.object(cred_attack, "_attempt_login", fake):
                spray(
                    _profile(),
                    users=["alice"],
                    passwords=["p1"],
                    rate_per_min=10000,
                    state_file=state_file,
                    authorized=True,
                )
            # The attempt fired — we did not skip. The mismatched
            # state file was discarded.
            self.assertEqual(state["calls"], 1)

    def test_resume_state_symlink_is_not_followed_or_replaced(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "target.json"
            target.write_text("keep-me", encoding="utf-8")
            state_file = Path(tmp) / "resume.json"
            state_file.symlink_to(target)

            fake, state = _fake_attempt_factory({})
            with mock.patch.object(cred_attack, "_attempt_login", fake):
                with self.assertLogs("core.cred_attack", level="WARNING") as logs:
                    spray(
                        _profile(),
                        users=["alice"],
                        passwords=["p1"],
                        rate_per_min=10000,
                        state_file=state_file,
                        authorized=True,
                    )
            self.assertEqual(state["calls"], 1)
            self.assertEqual(target.read_text(encoding="utf-8"), "keep-me")
            self.assertIn("refusing", "\n".join(logs.output))

    def test_malformed_resume_state_is_ignored_without_crashing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state_file = Path(tmp) / "resume.json"
            state_file.write_text(
                json.dumps(
                    {
                        "target_key": cred_attack._target_key(_profile()),
                        "started_at": time.time(),
                        "attempted": [["alice", []]],
                        "successes": [],
                    }
                ),
                encoding="utf-8",
            )

            fake, state = _fake_attempt_factory({})
            with mock.patch.object(cred_attack, "_attempt_login", fake):
                with self.assertLogs("core.cred_attack", level="WARNING") as logs:
                    spray(
                        _profile(),
                        users=["alice"],
                        passwords=["p1"],
                        rate_per_min=10000,
                        state_file=state_file,
                        authorized=True,
                    )
            self.assertEqual(state["calls"], 1)
            self.assertIn("malformed state", "\n".join(logs.output))


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------


class RateLimiterTests(unittest.TestCase):
    def test_tokenbucket_enforces_minimum_interval(self) -> None:
        # 60/min = 1/s, so 3 takes should consume ≥2s of wall time.
        bucket = cred_attack._TokenBucket(60.0)
        t0 = time.monotonic()
        for _ in range(3):
            bucket.take()
        elapsed = time.monotonic() - t0
        self.assertGreaterEqual(elapsed, 1.8)

    def test_tokenbucket_rejects_non_positive_rate(self) -> None:
        with self.assertRaises(ValueError):
            cred_attack._TokenBucket(0)


# ---------------------------------------------------------------------------
# Profile cloning + redaction
# ---------------------------------------------------------------------------


class ProfileCloneTests(unittest.TestCase):
    def test_clone_overrides_username_and_disables_password_storage(self) -> None:
        template = _profile()
        template.username = "original"
        template.store_password = True
        clone = cred_attack._clone_profile_for_attempt(template, username="candidate")
        self.assertEqual(clone.username, "candidate")
        self.assertFalse(clone.store_password)
        self.assertEqual(clone.host, template.host)
        self.assertEqual(clone.port, template.port)
        # Force password auth — never silently fall through to ssh-agent.
        self.assertEqual(clone.auth_type, "password")

    def test_redact_secret_replaces_cleartext(self) -> None:
        text = (
            "POP3 LOGIN failed for alice with hunter2 "
            "via http://alice:hunter2@example.invalid/?token=abc123"
        )
        self.assertIn("hunter2", text)
        red = cred_attack._redact_secret(text, "hunter2")
        self.assertNotIn("hunter2", red)
        self.assertNotIn("abc123", red)
        self.assertIn("<redacted>", red)

    def test_password_hash_does_not_carry_cleartext(self) -> None:
        h = cred_attack._hash_password("Spring2026!")
        self.assertTrue(h.startswith("hash:"))
        self.assertNotIn("Spring", h)
        self.assertNotIn("2026", h)

    def test_attempt_login_does_not_swallow_keyboardinterrupt(self) -> None:
        class FakeConnectionManager:
            def connect(self, _profile, *, password):
                raise KeyboardInterrupt()

        with mock.patch(
            "core.connection_manager.ConnectionManager",
            return_value=FakeConnectionManager(),
        ):
            with self.assertRaises(KeyboardInterrupt):
                cred_attack._attempt_login(
                    _profile(),
                    "alice",
                    "secret",
                    timeout_s=1.0,
                )

    def test_attempt_login_marks_slow_success_as_error(self) -> None:
        class FakeConnectionManager:
            def connect(self, _profile, *, password):
                return object()

            def disconnect_all(self):
                return None

        with mock.patch(
            "core.connection_manager.ConnectionManager",
            return_value=FakeConnectionManager(),
        ):
            with mock.patch.object(
                cred_attack.time,
                "monotonic",
                side_effect=[10.0, 12.5],
            ):
                outcome = cred_attack._attempt_login(
                    _profile(),
                    "alice",
                    "secret",
                    timeout_s=1.0,
                )

        self.assertIs(outcome.result, AttemptResult.ERROR)
        self.assertIn("timeout", outcome.error_message)

    def test_attempt_login_marks_slow_auth_failure_as_error(self) -> None:
        class FakeConnectionManager:
            def connect(self, _profile, *, password):
                raise OSError("Authentication failed")

        with mock.patch(
            "core.connection_manager.ConnectionManager",
            return_value=FakeConnectionManager(),
        ):
            with mock.patch.object(
                cred_attack.time,
                "monotonic",
                side_effect=[10.0, 12.5],
            ):
                outcome = cred_attack._attempt_login(
                    _profile(),
                    "alice",
                    "secret",
                    timeout_s=1.0,
                )

        self.assertIs(outcome.result, AttemptResult.ERROR)
        self.assertIn("Authentication failed", outcome.error_message)


# ---------------------------------------------------------------------------
# User enumeration
# ---------------------------------------------------------------------------


class EnumerateUsersTests(unittest.TestCase):
    def test_oracle_method_with_no_oracle_registered_rejects(self) -> None:
        # Pick a protocol with no registered oracle. NNTP has none.
        p = _profile()
        p.protocol = "nntp"
        with self.assertRaises(ValueError):
            enumerate_users(p, ["a"], method="oracle", authorized=True)

    def test_candidate_validation_rejects_single_string_and_controls(self) -> None:
        with self.assertRaises(TypeError):
            enumerate_users(_profile(), "alice", method="timing", authorized=True)
        with self.assertRaises(ValueError):
            enumerate_users(_profile(), ["alice\nPASS injected"], method="timing", authorized=True)

    def test_timing_enum_rejects_protocols_without_password_auth(self) -> None:
        p = _profile()
        p.protocol = "tftp"
        with self.assertRaisesRegex(ValueError, "false positives"):
            enumerate_users(p, ["alice"], method="timing", authorized=True)

    def test_timing_method_dispatches_to_timing_path(self) -> None:
        # Stub _attempt_login so timing collects synthetic latencies.
        def fake(template, username, password, *, timeout_s):
            elapsed = 0.5 if username == "alice" else 0.05
            return AttemptOutcome(
                username=username,
                password_hash="x",
                result=AttemptResult.FAILED,
                elapsed_s=elapsed,
            )

        with mock.patch.object(cred_attack, "_attempt_login", fake):
            report = enumerate_users(
                _profile(),
                ["alice", "bob", "carol", "dave"],
                method="timing",
                timing_samples=3,
                rate_per_min=10000,
                authorized=True,
            )
        # Alice's median is 10x the others — flag her, not the others.
        verdict = {r.username: r.likely_exists for r in report.results}
        self.assertTrue(verdict["alice"])
        self.assertFalse(verdict["bob"])

    def test_timing_ignores_error_samples(self) -> None:
        def fake(template, username, password, *, timeout_s):
            if username == "err":
                return AttemptOutcome(
                    username=username,
                    password_hash="x",
                    result=AttemptResult.ERROR,
                    elapsed_s=99.0,
                    error_message="connection reset",
                )
            elapsed = 0.5 if username == "alice" else 0.05
            return AttemptOutcome(
                username=username,
                password_hash="x",
                result=AttemptResult.FAILED,
                elapsed_s=elapsed,
            )

        with mock.patch.object(cred_attack, "_attempt_login", fake):
            report = enumerate_users(
                _profile(),
                ["err", "alice", "bob", "carol", "dave"],
                method="timing",
                timing_samples=3,
                rate_per_min=10000,
                authorized=True,
            )
        results = {r.username: r for r in report.results}
        self.assertFalse(results["err"].likely_exists)
        self.assertEqual(results["err"].confidence, 0.0)
        self.assertTrue(results["alice"].likely_exists)

    def test_timing_marks_direct_enum_probe_value_success_as_hit(self) -> None:
        def fake(template, username, password, *, timeout_s):
            result = AttemptResult.SUCCESS if username == "weird" else AttemptResult.FAILED
            return AttemptOutcome(
                username=username,
                password_hash="x",
                result=result,
                elapsed_s=0.05,
            )

        with mock.patch.object(cred_attack, "_attempt_login", fake):
            report = enumerate_users(
                _profile(),
                ["weird", "bob"],
                method="timing",
                timing_samples=3,
                rate_per_min=10000,
                authorized=True,
            )
        results = {r.username: r for r in report.results}
        self.assertTrue(results["weird"].likely_exists)
        self.assertEqual(results["weird"].confidence, 1.0)

    def test_timing_enum_uses_rate_limiter_per_sample(self) -> None:
        class FakeBucket:
            instances = []

            def __init__(self, rate_per_min):
                self.rate_per_min = rate_per_min
                self.takes = 0
                FakeBucket.instances.append(self)

            def take(self):
                self.takes += 1

        def fake(template, username, password, *, timeout_s):
            return AttemptOutcome(
                username=username,
                password_hash="x",
                result=AttemptResult.FAILED,
                elapsed_s=0.05,
            )

        with mock.patch.object(cred_attack, "_TokenBucket", FakeBucket):
            with mock.patch.object(cred_attack, "_attempt_login", fake):
                enumerate_users(
                    _profile(),
                    ["alice", "bob"],
                    method="timing",
                    timing_samples=3,
                    rate_per_min=123,
                    authorized=True,
                )

        self.assertEqual(len(FakeBucket.instances), 1)
        self.assertEqual(FakeBucket.instances[0].rate_per_min, 123)
        self.assertEqual(FakeBucket.instances[0].takes, 6)

    def test_custom_oracle_receives_pacing_when_supported(self) -> None:
        class FakeBucket:
            instances = []

            def __init__(self, rate_per_min):
                self.rate_per_min = rate_per_min
                self.takes = 0
                FakeBucket.instances.append(self)

            def take(self):
                self.takes += 1

        seen = []

        def my_oracle(
            profile,
            candidates,
            timeout_s,
            *,
            rate_limiter=None,
            jitter_s=0.0,
        ):
            seen.append((rate_limiter, jitter_s, timeout_s))
            rate_limiter.take()
            return [
                EnumResult(username=c, likely_exists=True, confidence=1.0, method="oracle:custom")
                for c in candidates
            ]

        cred_attack.register_oracle("nntp", my_oracle)
        try:
            p = _profile()
            p.protocol = "nntp"
            with mock.patch.object(cred_attack, "_TokenBucket", FakeBucket):
                report = enumerate_users(
                    p,
                    ["x", "y"],
                    method="oracle",
                    rate_per_min=77,
                    jitter_s=0.25,
                    authorized=True,
                )
        finally:
            cred_attack._ORACLES.pop("nntp", None)

        self.assertEqual(len(report.results), 2)
        self.assertEqual(len(FakeBucket.instances), 1)
        self.assertIs(seen[0][0], FakeBucket.instances[0])
        self.assertEqual(seen[0][1], 0.25)
        self.assertEqual(FakeBucket.instances[0].rate_per_min, 77)
        self.assertEqual(FakeBucket.instances[0].takes, 1)

    def test_pop3_oracle_does_not_send_pass_after_user_lockout(self) -> None:
        import poplib

        instances = []

        class FakePOP:
            def __init__(self, *args, **kwargs):
                self.pass_called = False
                instances.append(self)

            def user(self, _candidate):
                raise poplib.error_proto("-ERR account locked")

            def pass_(self, _password):
                self.pass_called = True
                raise poplib.error_proto("-ERR should not happen")

            def quit(self):
                return "+OK"

        p = _profile()
        p.pop3_ssl = False
        with mock.patch("poplib.POP3", FakePOP):
            results = cred_attack._pop3_oracle(p, ["alice"], 1.0)

        self.assertEqual(len(results), 1)
        self.assertFalse(instances[0].pass_called)
        self.assertEqual(results[0].confidence, 0.0)
        self.assertIn("lockout", results[0].notes)

    def test_ftps_oracle_auths_control_channel_before_user(self) -> None:
        import ftplib

        events: list[str] = []

        class FakeFTPTLS:
            def connect(self, _host, _port, timeout=None):
                events.append("connect")

            def auth(self):
                events.append("auth")

            def sendcmd(self, command):
                events.append(command)
                if command.startswith("USER "):
                    return "331 Password required"
                raise ftplib.error_perm("530 Login incorrect")

            def quit(self):
                events.append("quit")

        p = _profile()
        p.protocol = "ftps"
        p.port = 21
        with mock.patch("ftplib.FTP_TLS", return_value=FakeFTPTLS()):
            results = cred_attack._ftp_oracle(p, ["alice"], 1.0)

        self.assertEqual(len(results), 1)
        self.assertLess(events.index("auth"), events.index("USER alice"))

    def test_register_oracle_round_trip(self) -> None:
        called: list[tuple[str, list[str]]] = []

        def my_oracle(profile, candidates, timeout_s):
            called.append((profile.protocol, list(candidates)))
            return [
                EnumResult(username=c, likely_exists=True, confidence=1.0, method="oracle:custom")
                for c in candidates
            ]

        cred_attack.register_oracle("nntp", my_oracle)
        try:
            self.assertTrue(cred_attack.has_oracle("nntp"))
            p = _profile()
            p.protocol = "nntp"
            report = enumerate_users(p, ["x", "y"], method="oracle", authorized=True)
            self.assertEqual(len(report.results), 2)
            self.assertTrue(all(r.likely_exists for r in report.results))
            self.assertEqual(called, [("nntp", ["x", "y"])])
        finally:
            cred_attack._ORACLES.pop("nntp", None)

    def test_custom_oracle_wrong_result_count_is_rejected(self) -> None:
        def bad_oracle(profile, candidates, timeout_s):
            return []

        cred_attack.register_oracle("nntp", bad_oracle)
        try:
            p = _profile()
            p.protocol = "nntp"
            with self.assertRaises(ValueError):
                enumerate_users(p, ["x"], method="oracle", authorized=True)
        finally:
            cred_attack._ORACLES.pop("nntp", None)

    def test_register_oracle_validates_inputs(self) -> None:
        def oracle(profile, candidates, timeout_s):
            return []

        with self.assertRaises(ValueError):
            cred_attack.register_oracle("", oracle)
        with self.assertRaises(TypeError):
            cred_attack.register_oracle("custom", None)


# ---------------------------------------------------------------------------
# Public API surface
# ---------------------------------------------------------------------------


class ScriptingExposureTests(unittest.TestCase):
    def test_axross_namespace_exports(self) -> None:
        from core import scripting

        for name in ("bruteforce", "spray", "enumerate_users"):
            self.assertIn(name, scripting.__all__)
            self.assertTrue(callable(getattr(scripting, name)))

    def test_scripting_wrapper_routes_to_cred_attack(self) -> None:
        # Calling the scripting wrapper should hit the implementation.
        from core import scripting

        with mock.patch.object(cred_attack, "_attempt_login") as fake:
            fake.return_value = AttemptOutcome(
                username="x",
                password_hash="h",
                result=AttemptResult.FAILED,
                elapsed_s=0.0,
            )
            report = scripting.spray(
                _profile(),
                users=["x"],
                password="p",
                rate_per_min=10000,
                authorized=True,
            )
        self.assertIsInstance(report, AttackReport)


if __name__ == "__main__":
    unittest.main()
