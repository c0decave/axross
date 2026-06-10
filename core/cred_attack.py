"""Credential testing — brute-force, password spray, user enumeration.

A small, deliberately-bounded module for **authorised** credential
testing against a target the operator owns or has written permission
to assess. The whole module refuses to run unless the caller passes
``authorized=True`` explicitly; this is a hard gate, not a polite
suggestion.

Three top-level entry points:

* :func:`bruteforce` — iterate ``users × passwords`` against one
  target, in user-major order. Per-user lockout-aware abort.
* :func:`spray` — iterate ``passwords × users`` (password-major). The
  safer default for AD-style environments where lockout policies
  count attempts per-user inside a window. One password per user per
  pass dramatically reduces lockout risk.
* :func:`enumerate_users` — probe whether each candidate exists on
  the target. Two methods: ``"oracle"`` (protocol-specific behaviour
  difference, e.g. POP3 USER/PASS error wording) and ``"timing"``
  (statistical comparison of login-attempt latency). The oracle path
  delegates to a per-protocol implementation when one is registered.

OpSec defaults that this module bakes in (see ``docs/CRED_ATTACK.md``
for the full table):

* Authorisation gate: ``authorized=True`` is required, no env-var
  override, no cached "yes" answer.
* Rate limit: default 30 attempts/minute. Token-bucket; the loop
  blocks until the next token is available rather than burst-firing.
* Lockout abort: default ``True``. As soon as one attempt classifies
  as LOCKOUT the loop stops everything (not just that user). Override
  per-call with ``abort_on_lockout=False`` and a non-zero
  ``abort_after_n_lockouts`` only if the operator has explicit
  approval to keep going past the first signal.
* Per-attempt timeout budget: 10 s; backends that return after the
  budget are classified as ERROR. Blocking connect calls are bounded
  by the underlying protocol session timeout where available.
* Resume: optional ``state_file`` (JSON) — survives Ctrl-C and
  picks up where it left off.
* Redaction: passwords are NEVER logged in the clear, only as a
  short SHA-256 hash prefix. Successful credentials are returned to
  the caller in plaintext (the caller asked for them) but never sent
  to the structured logger.

Example::

    >>> from core.profiles import ConnectionProfile
    >>> from core.cred_attack import spray
    >>> profile = ConnectionProfile(
    ...     name="lab-pop3",
    ...     protocol="pop3",
    ...     host="lab.example.internal",
    ...     port=995,
    ...     pop3_ssl=True,
    ... )
    >>> report = spray(
    ...     profile,
    ...     users=["alice", "bob", "carol"],
    ...     passwords=["Spring2026!"],
    ...     rate_per_min=30,
    ...     authorized=True,
    ... )
    >>> for cred in report.successes:
    ...     print(cred.username)

The module does not call out to any third-party wordlist source. The
caller supplies users / passwords as in-memory iterables; that keeps
the OPSEC posture explicit and matches the rest of axross — no
hidden network fetches.
"""

from __future__ import annotations

import dataclasses
import hashlib
import inspect
import json
import logging
import math
import os
import random
import statistics
import tempfile
import threading
import time
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from core.profiles import ConnectionProfile
from core.security_mode import current_policy, require_protocol_allowed

log = logging.getLogger(__name__)

MAX_RESUME_STATE_BYTES = 4 * 1024 * 1024

_PASSWORD_AUTH_PROTOCOLS = frozenset(
    {
        "azure_blob",
        "azure_files",
        "cisco-telnet",
        "dfsn",
        "ftp",
        "ftps",
        "imap",
        "iscsi",
        "nntp",
        "pop3",
        "rsync",
        "s3",
        "scp",
        "sftp",
        "smb",
        "svn",
        "telnet",
        "webdav",
        "winrm",
    }
)


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


class AttemptResult(str, Enum):
    """Outcome of a single credential attempt."""

    SUCCESS = "success"  # Authentication accepted.
    FAILED = "failed"  # Wrong password / user unknown.
    LOCKOUT = "lockout"  # Account-locked / rate-limited / throttled.
    ERROR = "error"  # Network / protocol error, not authoritative.
    SKIPPED = "skipped"  # Resume state says we already did this one.


@dataclass(frozen=True)
class Credential:
    """A pair of (username, password) the loop discovered as valid."""

    username: str
    password: str


@dataclass
class AttemptOutcome:
    """The trace record for one credential attempt.

    ``password_hash`` is a short SHA-256 prefix — never the cleartext
    password. ``error_message`` carries the underlying exception text
    (with proxy_password / password substrings removed by the caller
    *before* it reaches here, since the attack module already controls
    what goes into the kwargs).
    """

    username: str
    password_hash: str
    result: AttemptResult
    elapsed_s: float
    error_message: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "username": self.username,
            "password_hash": self.password_hash,
            "result": self.result.value,
            "elapsed_s": round(self.elapsed_s, 4),
            "error_message": self.error_message,
            "timestamp": round(self.timestamp, 3),
        }


@dataclass
class AttackReport:
    """Final report from one bruteforce/spray run."""

    target_protocol: str
    target_host: str
    target_port: int
    started_at: float
    finished_at: float
    attempts: list[AttemptOutcome] = field(default_factory=list)
    successes: list[Credential] = field(default_factory=list)
    aborted: bool = False
    abort_reason: str = ""

    @property
    def attempted_count(self) -> int:
        return sum(1 for a in self.attempts if a.result is not AttemptResult.SKIPPED)

    @property
    def lockouts(self) -> int:
        return sum(1 for a in self.attempts if a.result is AttemptResult.LOCKOUT)

    @property
    def errors(self) -> int:
        return sum(1 for a in self.attempts if a.result is AttemptResult.ERROR)

    def summary(self) -> str:
        elapsed = max(0.0, self.finished_at - self.started_at)
        line = (
            f"target={self.target_protocol}://"
            f"{_redact_log_text(self.target_host)}:{self.target_port} "
            f"attempts={self.attempted_count} successes={len(self.successes)} "
            f"lockouts={self.lockouts} errors={self.errors} "
            f"elapsed={elapsed:.1f}s"
        )
        if self.aborted:
            line += f" ABORTED({self.abort_reason})"
        return line


# ---------------------------------------------------------------------------
# Lockout classifier
# ---------------------------------------------------------------------------

# Substrings (case-insensitive) that indicate the account is locked
# out, throttled or otherwise refusing further attempts. Keep the list
# tight: false positives here mean we abort runs that should have
# continued. False negatives mean we keep attacking past the lockout
# threshold, which is much worse — so we err towards listing more
# markers, not fewer. Sourced from real strings emitted by IIS,
# Exchange, OpenLDAP, sshd PAM, Postfix, MS AD/NTLM, Cisco IOS, Dovecot.
_LOCKOUT_MARKERS: tuple[str, ...] = (
    "account locked",
    "account is locked",
    "user locked",
    "locked out",
    "is locked",
    "STATUS_ACCOUNT_LOCKED_OUT".lower(),
    "STATUS_ACCOUNT_DISABLED".lower(),
    "STATUS_LOGON_FAILURE_ACCT_LOCKED".lower(),
    "too many login",
    "too many failed",
    "too many attempts",
    "too many auth",
    "rate limit",
    "rate-limit",
    "rate limited",
    "ratelimited",
    "throttle",
    "temporarily disabled",
    "temporarily blocked",
    "temporarily unavailable",  # some Postfix lockouts spell it like this
    "account suspended",
    "account disabled",
    "exceeded the maximum",
    "try again later",
    "please wait",
    "ERR_TOO_MANY_AUTHENTICATION_FAILURES".lower(),
    "503 5.7",  # SMTP throttle code
    "421 4.7",  # SMTP rate-limit code
    "554 5.7",  # SMTP policy reject (can mean throttle in some MTAs)
)


# Substrings indicating a clear authentication failure (wrong creds).
# These trump the lockout list — "Authentication failed" alone is NOT
# a lockout, even though "failed" is a fragment of "too many failed".
_AUTH_FAIL_MARKERS: tuple[str, ...] = (
    "authentication failed",
    "authentication failure",
    "auth failed",
    "permission denied",
    "access denied",
    "unauthorized",
    "http 401",
    "401 unauthorized",
    "login failed",
    "login incorrect",
    "login invalid",
    "invalid credentials",
    "incorrect password",
    "bad password",
    "wrong password",
    "no such user",
    "user unknown",
    "unknown user",
    "user not found",
    "STATUS_LOGON_FAILURE".lower(),
    "STATUS_NO_SUCH_USER".lower(),
    "STATUS_WRONG_PASSWORD".lower(),
    "535 5.7.8",  # SMTP auth failure
)


def classify_error(exc: BaseException, protocol: str) -> tuple[AttemptResult, str]:
    """Decide whether ``exc`` indicates a lockout, plain auth failure
    or a network/protocol error.

    Returns ``(result, reason)`` where ``reason`` is a short
    human-readable label (used for logging + abort messaging).

    The classifier is intentionally heuristic — every protocol uses
    slightly different phrasing and we cannot enumerate them all.
    Operators with bespoke targets can extend ``_LOCKOUT_MARKERS`` /
    ``_AUTH_FAIL_MARKERS`` via :func:`register_marker`.
    """
    text = str(exc).lower()
    # Lockout takes precedence — an account that's locked AND has the
    # wrong password also says "locked", and we want to stop, not
    # press on.
    for marker in _LOCKOUT_MARKERS:
        if marker in text:
            return AttemptResult.LOCKOUT, f"marker:{marker!r}"
    for marker in _AUTH_FAIL_MARKERS:
        if marker in text:
            return AttemptResult.FAILED, f"marker:{marker!r}"
    # Network-layer signals — these are NOT authoritative for "wrong
    # creds"; treat them as transient errors.
    network_markers = (
        "connection refused",
        "connection reset",
        "timed out",
        "timeout",
        "unreachable",
        "no route to host",
        "name or service not known",
        "name resolution",
        "broken pipe",
    )
    for marker in network_markers:
        if marker in text:
            return AttemptResult.ERROR, f"network:{marker!r}"
    # Default: treat unknown exceptions as operational errors. A
    # backend crash, parser error or TLS failure must not look like a
    # clean "wrong password" signal.
    return AttemptResult.ERROR, "unknown"


def register_marker(text: str, *, kind: str = "lockout") -> None:
    """Add a substring to the lockout (``kind="lockout"``) or auth-fail
    (``kind="auth_fail"``) marker list. Useful when assessing a target
    whose error wording differs from the built-in defaults.
    """
    global _LOCKOUT_MARKERS, _AUTH_FAIL_MARKERS  # noqa: PLW0603
    needle = text.strip().lower()
    if not needle:
        raise ValueError("register_marker: empty text")
    if kind == "lockout":
        if needle not in _LOCKOUT_MARKERS:
            _LOCKOUT_MARKERS = (*_LOCKOUT_MARKERS, needle)
            log.debug("cred_attack registered lockout marker %r", needle)
    elif kind == "auth_fail":
        if needle not in _AUTH_FAIL_MARKERS:
            _AUTH_FAIL_MARKERS = (*_AUTH_FAIL_MARKERS, needle)
            log.debug("cred_attack registered auth-fail marker %r", needle)
    else:
        raise ValueError(f"register_marker: kind must be 'lockout' or 'auth_fail', got {kind!r}")


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------


class _TokenBucket:
    """Simple thread-safe token bucket. Refills at a fixed rate;
    callers block in :meth:`take` until a token is available.

    Burst is 1 — we want a steady cadence, not a thundering herd at
    the start of the run.
    """

    def __init__(self, rate_per_min: float) -> None:
        try:
            rate = float(rate_per_min)
        except (TypeError, ValueError) as exc:
            raise ValueError("rate_per_min must be a positive number") from exc
        if not math.isfinite(rate) or rate <= 0:
            raise ValueError("rate_per_min must be a positive finite number")
        self._interval = 60.0 / rate
        self._next_at = time.monotonic()
        self._lock = threading.Lock()

    def take(self) -> None:
        with self._lock:
            now = time.monotonic()
            wait = self._next_at - now
            if wait > 0:
                time.sleep(wait)
                # Re-anchor on now+interval to avoid drift if the
                # caller stalls between takes.
                self._next_at = time.monotonic() + self._interval
            else:
                self._next_at = now + self._interval


def _pace_probe(
    rate_limiter: _TokenBucket | None,
    jitter_s: float,
    rng: random.Random,
) -> None:
    """Apply per-probe pacing for user enumeration paths."""
    if rate_limiter is not None:
        rate_limiter.take()
    if jitter_s > 0:
        time.sleep(rng.uniform(0, jitter_s))


# ---------------------------------------------------------------------------
# Validation + redaction helpers
# ---------------------------------------------------------------------------


def _redact_log_text(text: str) -> str:
    try:
        from core.redaction import redact_text

        return redact_text(str(text))
    except Exception:  # pragma: no cover - redaction must not break logging
        return str(text)


def _validate_positive_float(name: str, value: float) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be a positive number") from exc
    if not math.isfinite(number) or number <= 0:
        raise ValueError(f"{name} must be a positive finite number")
    return number


def _validate_non_negative_float(name: str, value: float) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be a non-negative number") from exc
    if not math.isfinite(number) or number < 0:
        raise ValueError(f"{name} must be a non-negative finite number")
    return number


def _validate_optional_positive_int(name: str, value: int | None) -> int | None:
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError(f"{name} must be a positive integer or None")
    return value


def _validate_positive_int(name: str, value: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


def _validate_username(value: object, *, field_name: str = "username") -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a string, got {type(value).__name__}")
    if value == "":
        raise ValueError(f"{field_name} must not be empty")
    bad = [ch for ch in value if ord(ch) < 32 or ch == "\x7f"]
    if bad:
        raise ValueError(
            f"{field_name} contains control characters; refusing log/protocol injection risk"
        )
    return value


def _validate_password(value: object, *, field_name: str = "password") -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a string, got {type(value).__name__}")
    bad = [ch for ch in value if ord(ch) < 32 or ch == "\x7f"]
    if bad:
        raise ValueError(
            f"{field_name} contains control characters; refusing log/protocol injection risk"
        )
    return value


def _materialize_usernames(values: Iterable[str], *, field_name: str) -> list[str]:
    if isinstance(values, (str, bytes)):
        raise TypeError(f"{field_name} must be an iterable of usernames, not a single string")
    return [
        _validate_username(value, field_name=f"{field_name}[{idx}]")
        for idx, value in enumerate(values)
    ]


def _materialize_passwords(values: Iterable[str], *, field_name: str) -> list[str]:
    if isinstance(values, (str, bytes)):
        raise TypeError(f"{field_name} must be an iterable of passwords, not a single string")
    return [
        _validate_password(value, field_name=f"{field_name}[{idx}]")
        for idx, value in enumerate(values)
    ]


# ---------------------------------------------------------------------------
# Profile helpers
# ---------------------------------------------------------------------------


def _hash_password(password: str) -> str:
    """SHA-256 prefix — used in logs and resume state. Never reversible
    in practice for passwords with ≥40 bits of entropy, but operators
    should still treat the resume file as sensitive."""
    if not password:
        return "hash:empty"
    return "hash:" + hashlib.sha256(password.encode("utf-8")).hexdigest()[:12]


def _clone_profile_for_attempt(
    template: ConnectionProfile,
    *,
    username: str,
) -> ConnectionProfile:
    """Return a fresh ``ConnectionProfile`` with the same network
    settings as ``template`` but with the candidate ``username`` set
    and ``store_password=False`` (so we never poke the keyring during
    a credential test)."""
    p = dataclasses.replace(
        template,
        name=f"cred_attack:{template.protocol}://{template.host}:{username}",
        username=username,
        store_password=False,
        store_proxy_password=False,
        # Force password auth: key/agent paths skip the candidate
        # password entirely and would silently authenticate via the
        # caller's SSH agent. That is not what a credential test means.
        auth_type="password",
    )
    return p


def _resolve_profile(profile: ConnectionProfile | str) -> ConnectionProfile:
    """Accept either a ``ConnectionProfile`` or a saved-profile name."""
    if isinstance(profile, ConnectionProfile):
        return profile
    if isinstance(profile, str):
        from core.profiles import ProfileManager

        p = ProfileManager().get(profile)
        if p is None:
            raise KeyError(f"No saved profile named {profile!r}")
        return p
    raise TypeError(
        f"profile must be a ConnectionProfile or saved-profile name; got {type(profile).__name__}"
    )


def _validate_password_auth_profile(profile: ConnectionProfile) -> None:
    """Fail closed when a protocol/profile would ignore candidate passwords."""
    proto = (profile.protocol or "").strip().lower()
    if proto not in _PASSWORD_AUTH_PROTOCOLS:
        raise ValueError(
            f"core.cred_attack does not support protocol {profile.protocol!r}: "
            "the backend does not consume candidate passwords during connect, "
            "so a credential test would produce false positives."
        )
    if proto in {"azure_blob", "azure_files"}:
        if profile.azure_connection_string or profile.azure_sas_token:
            raise ValueError(
                f"core.cred_attack refuses {proto} profiles with "
                "azure_connection_string or azure_sas_token set: those static "
                "secrets bypass candidate passwords."
            )
    if proto == "iscsi" and not profile.username:
        raise ValueError(
            "core.cred_attack refuses iSCSI profiles without a CHAP username: "
            "the target would not necessarily authenticate candidate passwords."
        )


# ---------------------------------------------------------------------------
# One attempt
# ---------------------------------------------------------------------------


def _attempt_login(
    template: ConnectionProfile,
    username: str,
    password: str,
    *,
    timeout_s: float,
    on_unknown_host: Callable[[object], bool] | None = None,
) -> AttemptOutcome:
    """Try one (username, password) pair. Always returns an
    :class:`AttemptOutcome`; never raises for ordinary auth failures."""
    from core.connection_manager import ConnectionManager

    profile = _clone_profile_for_attempt(template, username=username)
    cm = ConnectionManager()
    pwd_hash = _hash_password(password)
    t0 = time.monotonic()
    try:
        # Most per-protocol sessions already carry their own connect
        # timeout. We still flag attempts that return after the caller's
        # requested budget; Python cannot safely kill an arbitrary
        # blocking connector inside the same process.
        connect_kwargs = {"password": password}
        if on_unknown_host is not None:
            connect_kwargs["on_unknown_host"] = on_unknown_host
        session = cm.connect(profile, **connect_kwargs)
    except Exception as exc:  # noqa: BLE001 — backend errors are heterogeneous
        elapsed = time.monotonic() - t0
        result, reason = classify_error(exc, profile.protocol)
        if elapsed > timeout_s and result is not AttemptResult.LOCKOUT:
            result, reason = AttemptResult.ERROR, f"timeout>{timeout_s:.1f}s"
        # Never log the cleartext password; redact any incidental
        # appearance in the exception text.
        msg = _redact_secret(str(exc), password)
        log_fn = log.warning if result is AttemptResult.ERROR else log.info
        log_fn(
            "cred_attack[%s] user=%r pwd=%s -> %s (%s) %.2fs",
            profile.protocol,
            username,
            pwd_hash,
            result.value,
            reason,
            elapsed,
        )
        return AttemptOutcome(
            username=username,
            password_hash=pwd_hash,
            result=result,
            elapsed_s=elapsed,
            error_message=msg,
        )

    # Connect succeeded → credential is valid. Tear down immediately;
    # we don't want to keep a privileged session open for the duration
    # of the loop.
    elapsed = time.monotonic() - t0
    try:
        cm.disconnect_all()
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "cred_attack[%s] disconnect after success raised: %s",
            profile.protocol,
            _redact_log_text(str(exc)),
        )
    if elapsed > timeout_s:
        log.warning(
            "cred_attack[%s] user=%r pwd=%s -> timeout budget exceeded "
            "after successful connect (%.2fs > %.2fs); marking ERROR",
            profile.protocol,
            username,
            pwd_hash,
            elapsed,
            timeout_s,
        )
        del session
        return AttemptOutcome(
            username=username,
            password_hash=pwd_hash,
            result=AttemptResult.ERROR,
            elapsed_s=elapsed,
            error_message=f"timeout>{timeout_s:.1f}s after successful connect",
        )
    log.info(
        "cred_attack[%s] user=%r pwd=%s -> SUCCESS %.2fs",
        profile.protocol,
        username,
        pwd_hash,
        elapsed,
    )
    del session  # don't keep a reference past the loop iteration
    return AttemptOutcome(
        username=username,
        password_hash=pwd_hash,
        result=AttemptResult.SUCCESS,
        elapsed_s=elapsed,
    )


def _redact_secret(text: str, secret: str) -> str:
    """Replace any literal occurrence of ``secret`` in ``text`` with
    ``<redacted>``. A backstop in case a backend echoed the password
    into its exception text."""
    redacted = str(text)
    if secret:
        redacted = redacted.replace(secret, "<redacted>")
    return _redact_log_text(redacted)


# ---------------------------------------------------------------------------
# Resume state
# ---------------------------------------------------------------------------


@dataclass
class _ResumeState:
    """JSON-serialised progress marker. Atomic-write to disk after
    every attempt so Ctrl-C is recoverable."""

    target_key: str  # protocol://host:port
    started_at: float
    attempted: list[list[str]]  # [[username, password_hash], ...]
    successes: list[list[str]]  # [[username, password_hash], ...]

    @classmethod
    def load(cls, path: Path) -> "_ResumeState | None":
        try:
            if path.is_symlink():
                log.warning(
                    "cred_attack resume: refusing symlink state file %s",
                    path,
                )
                return None
            try:
                mode = path.stat().st_mode & 0o777
                if mode & 0o077:
                    log.warning(
                        "cred_attack resume: state file %s is too permissive "
                        "(mode=%s); expected 0o600",
                        path,
                        oct(mode),
                    )
                if path.stat().st_size > MAX_RESUME_STATE_BYTES:
                    log.warning(
                        "cred_attack resume: state file %s exceeds %d bytes; ignoring",
                        path,
                        MAX_RESUME_STATE_BYTES,
                    )
                    return None
            except FileNotFoundError:
                return None
            data = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None
        except (OSError, json.JSONDecodeError) as exc:
            log.warning("cred_attack resume: cannot read %s: %s", path, exc)
            return None
        try:
            if not isinstance(data, dict):
                raise TypeError("state root must be a JSON object")
            target_key = data["target_key"]
            if not isinstance(target_key, str):
                raise TypeError("target_key must be a string")

            def entries(name: str) -> list[list[str]]:
                raw = data.get(name, [])
                if not isinstance(raw, list):
                    raise TypeError(f"{name} must be a list")
                out: list[list[str]] = []
                for idx, item in enumerate(raw):
                    if not isinstance(item, (list, tuple)) or len(item) < 2:
                        raise TypeError(f"{name}[{idx}] must be [username, hash]")
                    username, password_hash = item[0], item[1]
                    if not isinstance(username, str) or not isinstance(password_hash, str):
                        raise TypeError(f"{name}[{idx}] must contain string username/hash")
                    out.append([username, password_hash])
                return out

            return cls(
                target_key=target_key,
                started_at=float(data.get("started_at", time.time())),
                attempted=entries("attempted"),
                successes=entries("successes"),
            )
        except (KeyError, TypeError, ValueError) as exc:
            log.warning("cred_attack resume: malformed state in %s: %s", path, exc)
            return None

    def save(self, path: Path) -> None:
        payload = {
            "target_key": self.target_key,
            "started_at": self.started_at,
            "attempted": self.attempted,
            "successes": self.successes,
        }
        tmp = ""
        try:
            if path.is_symlink():
                log.warning(
                    "cred_attack resume: refusing to replace symlink state file %s",
                    path,
                )
                return
            parent = path.parent
            parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            encoded = json.dumps(payload, indent=2).encode("utf-8")
            fd, tmp = tempfile.mkstemp(
                prefix=f".{path.name}.",
                suffix=".tmp",
                dir=str(parent),
            )
            try:
                try:
                    os.fchmod(fd, 0o600)
                except OSError:
                    pass
                with os.fdopen(fd, "wb") as fh:
                    fd = -1
                    fh.write(encoded)
                    fh.flush()
                    try:
                        os.fsync(fh.fileno())
                    except OSError as exc:
                        log.debug(
                            "cred_attack resume: fsync not honored for %s: %s",
                            tmp,
                            exc,
                        )
                os.replace(tmp, path)
                try:
                    os.chmod(path, 0o600)
                except OSError as exc:
                    log.warning(
                        "cred_attack resume: cannot set 0o600 on %s: %s",
                        path,
                        exc,
                    )
            finally:
                if fd >= 0:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
        except OSError as exc:
            log.warning("cred_attack resume: cannot write %s: %s", path, exc)
        finally:
            if tmp:
                try:
                    if os.path.exists(tmp):
                        os.unlink(tmp)
                except OSError:
                    pass


def _target_key(profile: ConnectionProfile) -> str:
    return f"{profile.protocol}://{profile.host}:{profile.port}"


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------


def _user_major(
    users: list[str],
    passwords: list[str],
) -> Iterator[tuple[str, str]]:
    """Iterate user × password — try every password for user 1, then
    user 2, etc. Classic brute-force order; very lockout-prone."""
    for u in users:
        for p in passwords:
            yield (u, p)


def _password_major(
    users: list[str],
    passwords: list[str],
) -> Iterator[tuple[str, str]]:
    """Iterate password × user — try password 1 against every user,
    then password 2, etc. Spray pattern; safer wrt per-user lockout."""
    for p in passwords:
        for u in users:
            yield (u, p)


# ---------------------------------------------------------------------------
# Authorisation gate
# ---------------------------------------------------------------------------


def _check_authorisation(authorized: bool, function_name: str) -> None:
    if not authorized:
        raise PermissionError(
            f"core.cred_attack.{function_name} requires authorized=True. "
            "This module performs intrusive credential testing — only call "
            "it against systems you own or have written permission to "
            "assess. See docs/CRED_ATTACK.md for the OPSEC checklist."
        )
    if current_policy().name == "paranoid":
        # Paranoid mode is for "I am on a sensitive endpoint and want
        # axross to refuse anything noisy". Credential attacks are
        # noisy by definition; refuse without a per-call override.
        raise PermissionError(
            f"core.cred_attack.{function_name} is blocked under "
            "AXROSS_SECURITY_MODE=paranoid. Switch to normal mode to run "
            "credential tests, or run from a separate, less-restricted "
            "instance."
        )


# ---------------------------------------------------------------------------
# Core loop
# ---------------------------------------------------------------------------


def _run_loop(
    template: ConnectionProfile,
    plan: Iterator[tuple[str, str]],
    *,
    rate_per_min: float,
    timeout_per_attempt: float,
    abort_on_lockout: bool,
    abort_after_n_lockouts: int,
    abort_after_n_failures: int | None,
    max_attempts: int | None,
    stop_on_first_success_per_user: bool,
    stop_on_first_success_total: bool,
    progress: Callable[[AttemptOutcome], None] | None,
    on_unknown_host: Callable[[object], bool] | None,
    state_file: Path | None,
    dry_run: bool,
    jitter_s: float,
) -> AttackReport:
    require_protocol_allowed(template.protocol)
    _validate_password_auth_profile(template)
    rate_per_min = _validate_positive_float("rate_per_min", rate_per_min)
    timeout_per_attempt = _validate_positive_float(
        "timeout_per_attempt",
        timeout_per_attempt,
    )
    abort_after_n_lockouts = _validate_positive_int(
        "abort_after_n_lockouts",
        abort_after_n_lockouts,
    )
    abort_after_n_failures = _validate_optional_positive_int(
        "abort_after_n_failures",
        abort_after_n_failures,
    )
    max_attempts = _validate_optional_positive_int("max_attempts", max_attempts)
    jitter_s = _validate_non_negative_float("jitter_s", jitter_s)
    target_key = _target_key(template)
    target_log = _redact_log_text(target_key)
    started_at = time.time()
    report = AttackReport(
        target_protocol=template.protocol,
        target_host=template.host,
        target_port=template.port or 0,
        started_at=started_at,
        finished_at=started_at,
    )

    if dry_run:
        # Walk the plan but don't connect — useful for verifying the
        # generator and logging the target without firing any packets.
        log.warning(
            "cred_attack DRY-RUN target=%s — no network attempts will be made",
            target_log,
        )
        for username, password in plan:
            outcome = AttemptOutcome(
                username=username,
                password_hash=_hash_password(password),
                result=AttemptResult.SKIPPED,
                elapsed_s=0.0,
                error_message="dry-run",
            )
            report.attempts.append(outcome)
            if progress is not None:
                try:
                    progress(outcome)
                except Exception as exc:  # noqa: BLE001
                    log.warning("cred_attack progress callback raised: %s", exc)
            if max_attempts is not None and len(report.attempts) >= max_attempts:
                break
        report.finished_at = time.time()
        return report

    bucket = _TokenBucket(rate_per_min)
    seen_keys: set[tuple[str, str]] = set()
    successful_users: set[str] = set()
    consecutive_failures = 0
    lockouts_seen = 0
    rng = random.Random()

    resume: _ResumeState | None = None
    if state_file is not None:
        resume = _ResumeState.load(state_file)
        if resume is not None and resume.target_key != target_key:
            log.warning(
                "cred_attack resume: state %s targets %s but current run is "
                "%s — ignoring and starting fresh",
                state_file,
                _redact_log_text(resume.target_key),
                target_log,
            )
            resume = None
        if resume is None:
            resume = _ResumeState(
                target_key=target_key,
                started_at=started_at,
                attempted=[],
                successes=[],
            )
        else:
            for entry in resume.attempted:
                if len(entry) >= 2:
                    seen_keys.add((entry[0], entry[1]))
            for entry in resume.successes:
                if len(entry) >= 2:
                    successful_users.add(entry[0])
                    report.successes.append(
                        Credential(
                            username=entry[0],
                            password="<resumed>",
                        )
                    )

    log.info(
        "cred_attack START target=%s rate=%g/min timeout=%.1fs abort_on_lockout=%s",
        target_log,
        rate_per_min,
        timeout_per_attempt,
        abort_on_lockout,
    )

    for username, password in plan:
        if max_attempts is not None and report.attempted_count >= max_attempts:
            report.aborted = True
            report.abort_reason = f"max_attempts={max_attempts} reached"
            break
        if stop_on_first_success_per_user and username in successful_users:
            outcome = AttemptOutcome(
                username=username,
                password_hash=_hash_password(password),
                result=AttemptResult.SKIPPED,
                elapsed_s=0.0,
                error_message="user already authenticated",
            )
            report.attempts.append(outcome)
            if progress is not None:
                try:
                    progress(outcome)
                except Exception as exc:  # noqa: BLE001
                    log.warning("cred_attack progress callback raised: %s", exc)
            continue

        pwd_hash = _hash_password(password)
        if (username, pwd_hash) in seen_keys:
            outcome = AttemptOutcome(
                username=username,
                password_hash=pwd_hash,
                result=AttemptResult.SKIPPED,
                elapsed_s=0.0,
                error_message="resumed: already attempted",
            )
            report.attempts.append(outcome)
            if progress is not None:
                try:
                    progress(outcome)
                except Exception as exc:  # noqa: BLE001
                    log.warning("cred_attack progress callback raised: %s", exc)
            continue

        bucket.take()
        if jitter_s > 0:
            time.sleep(rng.uniform(0, jitter_s))

        attempt_kwargs = {"timeout_s": timeout_per_attempt}
        if on_unknown_host is not None:
            attempt_kwargs["on_unknown_host"] = on_unknown_host
        outcome = _attempt_login(template, username, password, **attempt_kwargs)
        report.attempts.append(outcome)
        seen_keys.add((username, pwd_hash))

        if resume is not None:
            resume.attempted.append([username, pwd_hash])
            if outcome.result is AttemptResult.SUCCESS:
                resume.successes.append([username, pwd_hash])
            if state_file is not None:
                resume.save(state_file)

        if progress is not None:
            try:
                progress(outcome)
            except Exception as exc:  # noqa: BLE001
                log.warning("cred_attack progress callback raised: %s", exc)

        if outcome.result is AttemptResult.SUCCESS:
            report.successes.append(Credential(username=username, password=password))
            successful_users.add(username)
            consecutive_failures = 0
            if stop_on_first_success_total:
                report.aborted = True
                report.abort_reason = "first success"
                break
        elif outcome.result is AttemptResult.LOCKOUT:
            lockouts_seen += 1
            if abort_on_lockout or lockouts_seen >= abort_after_n_lockouts:
                report.aborted = True
                report.abort_reason = (
                    f"lockout after {report.attempted_count} attempts (user={username!r})"
                )
                log.error(
                    "cred_attack ABORT target=%s reason=%s",
                    target_log,
                    report.abort_reason,
                )
                break
        elif outcome.result is AttemptResult.FAILED:
            consecutive_failures += 1
            if (
                abort_after_n_failures is not None
                and consecutive_failures >= abort_after_n_failures
            ):
                report.aborted = True
                report.abort_reason = (
                    f"{consecutive_failures} consecutive failures — stopping to avoid noise"
                )
                break
        elif outcome.result is AttemptResult.ERROR:
            # Don't increment consecutive_failures on network errors;
            # those are not authoritative. Do log.
            log.warning(
                "cred_attack network error: %s",
                outcome.error_message[:200],
            )

    report.finished_at = time.time()
    log.info("cred_attack END %s", report.summary())
    return report


# ---------------------------------------------------------------------------
# Public API — bruteforce and spray
# ---------------------------------------------------------------------------


def bruteforce(
    profile: ConnectionProfile | str,
    *,
    users: Iterable[str],
    passwords: Iterable[str],
    rate_per_min: float = 30.0,
    timeout_per_attempt: float = 10.0,
    abort_on_lockout: bool = True,
    abort_after_n_lockouts: int = 1,
    abort_after_n_failures: int | None = None,
    max_attempts: int | None = None,
    stop_on_first_success_per_user: bool = True,
    progress: Callable[[AttemptOutcome], None] | None = None,
    on_unknown_host: Callable[[object], bool] | None = None,
    state_file: str | os.PathLike[str] | None = None,
    dry_run: bool = False,
    jitter_s: float = 0.0,
    authorized: bool = False,
) -> AttackReport:
    """Run a brute-force credential test in **user-major** order.

    For every ``user`` in ``users``, every ``password`` in ``passwords``
    is tried until either the user authenticates (default) or the
    list is exhausted.

    Lockout-aware by default: the first attempt that classifies as
    LOCKOUT stops the entire run, not just the offending user. This
    is intentionally conservative — operators with explicit
    permission to keep going should pass ``abort_on_lockout=False``
    and a higher ``abort_after_n_lockouts``.

    Args:
        profile: ``ConnectionProfile`` (or saved-profile name) used as
            a template. Username is overridden per attempt; password
            is supplied per attempt; everything else (host, port,
            proxy, TLS settings, …) is preserved.
        users, passwords: iterables of strings. Materialised into
            lists internally so generator-based wordlists work.
        rate_per_min: token-bucket rate. Default 30/min ≈ one attempt
            every two seconds.
        timeout_per_attempt: hint passed to the per-protocol session
            ctor where supported. Backends that hard-code a connect
            timeout ignore this.
        abort_on_lockout: True (default) → stop on first lockout.
        abort_after_n_lockouts: only consulted if ``abort_on_lockout``
            is False — abort once N lockouts have accumulated.
        abort_after_n_failures: optional safety net — stop after N
            consecutive plain-FAILED outcomes (suggests the wordlist
            isn't matching anything; cheap to bail).
        max_attempts: hard cap on total attempts.
        stop_on_first_success_per_user: skip remaining passwords for
            a user once one succeeds. Almost always what you want.
        progress: callback fired with every :class:`AttemptOutcome`.
        on_unknown_host: optional SSH/SCP host-key decision callback.
            Passed through to the SSH backend; leave as ``None`` unless
            the caller has an explicit trust policy for the target.
        state_file: path to a JSON resume file. Created on first
            attempt; updated atomically after every attempt; consulted
            on subsequent runs to skip already-tried (user, password)
            pairs against the same target.
        dry_run: walk the plan, log it, but never connect.
        jitter_s: random sleep [0, jitter_s) added on top of the
            rate-limit interval. Off by default — see the
            "blend, don't randomise" rule in docs/OPSEC.md.
        authorized: must be True. Hard gate.

    Returns:
        :class:`AttackReport`.
    """
    _check_authorisation(authorized, "bruteforce")
    template = _resolve_profile(profile)
    users_l = _materialize_usernames(users, field_name="users")
    passwords_l = _materialize_passwords(passwords, field_name="passwords")
    if not users_l:
        raise ValueError("bruteforce: users iterable is empty")
    if not passwords_l:
        raise ValueError("bruteforce: passwords iterable is empty")
    plan = _user_major(users_l, passwords_l)
    state_path = Path(state_file) if state_file is not None else None
    return _run_loop(
        template,
        plan,
        rate_per_min=rate_per_min,
        timeout_per_attempt=timeout_per_attempt,
        abort_on_lockout=abort_on_lockout,
        abort_after_n_lockouts=abort_after_n_lockouts,
        abort_after_n_failures=abort_after_n_failures,
        max_attempts=max_attempts,
        stop_on_first_success_per_user=stop_on_first_success_per_user,
        stop_on_first_success_total=False,
        progress=progress,
        on_unknown_host=on_unknown_host,
        state_file=state_path,
        dry_run=dry_run,
        jitter_s=jitter_s,
    )


def spray(
    profile: ConnectionProfile | str,
    *,
    users: Iterable[str],
    passwords: Iterable[str] | None = None,
    password: str | None = None,
    rate_per_min: float = 30.0,
    timeout_per_attempt: float = 10.0,
    abort_on_lockout: bool = True,
    abort_after_n_lockouts: int = 1,
    max_attempts: int | None = None,
    stop_on_first_success_per_user: bool = True,
    progress: Callable[[AttemptOutcome], None] | None = None,
    on_unknown_host: Callable[[object], bool] | None = None,
    state_file: str | os.PathLike[str] | None = None,
    dry_run: bool = False,
    jitter_s: float = 0.0,
    authorized: bool = False,
) -> AttackReport:
    """Run a **password spray** in password-major order.

    For every ``password`` (or single ``password=``), every user in
    ``users`` is tried before moving on to the next password. This
    spreads attempts across the user pool so per-user lockout windows
    rarely fill up — the standard pattern for AD/Microsoft-365-style
    environments where lockout policy is per-user-per-window.

    Pass either ``password=`` (single) or ``passwords=`` (list).
    Other arguments mirror :func:`bruteforce`.
    """
    _check_authorisation(authorized, "spray")
    template = _resolve_profile(profile)
    users_l = _materialize_usernames(users, field_name="users")
    if password is not None and passwords is not None:
        raise ValueError("spray: pass either password= or passwords=, not both")
    if password is not None:
        passwords_l = [_validate_password(password, field_name="password")]
    elif passwords is not None:
        passwords_l = _materialize_passwords(passwords, field_name="passwords")
    else:
        raise ValueError("spray: one of password= or passwords= is required")
    if not users_l:
        raise ValueError("spray: users iterable is empty")
    if not passwords_l:
        raise ValueError("spray: no passwords supplied")
    plan = _password_major(users_l, passwords_l)
    state_path = Path(state_file) if state_file is not None else None
    return _run_loop(
        template,
        plan,
        rate_per_min=rate_per_min,
        timeout_per_attempt=timeout_per_attempt,
        abort_on_lockout=abort_on_lockout,
        abort_after_n_lockouts=abort_after_n_lockouts,
        abort_after_n_failures=None,
        max_attempts=max_attempts,
        stop_on_first_success_per_user=stop_on_first_success_per_user,
        stop_on_first_success_total=False,
        progress=progress,
        on_unknown_host=on_unknown_host,
        state_file=state_path,
        dry_run=dry_run,
        jitter_s=jitter_s,
    )


# ---------------------------------------------------------------------------
# User enumeration
# ---------------------------------------------------------------------------


@dataclass
class EnumResult:
    """Per-candidate enumeration verdict."""

    username: str
    likely_exists: bool
    confidence: float  # 0.0..1.0 — 1.0 = strong oracle, 0.0 = unknown
    method: str  # "oracle:pop3" / "timing" / "skipped"
    notes: str = ""


@dataclass
class EnumReport:
    target_protocol: str
    target_host: str
    started_at: float
    finished_at: float
    results: list[EnumResult] = field(default_factory=list)

    def hits(self) -> list[str]:
        return [r.username for r in self.results if r.likely_exists]

    def summary(self) -> str:
        elapsed = max(0.0, self.finished_at - self.started_at)
        return (
            f"target={self.target_protocol}://{_redact_log_text(self.target_host)} "
            f"candidates={len(self.results)} hits={len(self.hits())} "
            f"elapsed={elapsed:.1f}s"
        )


# Registry of per-protocol oracle implementations. Each entry is a
# callable taking ``(profile, candidates, timeout_s)`` and returning a
# list of ``EnumResult`` aligned with ``candidates``. Backends register
# themselves in their own module via :func:`register_oracle`.
_ORACLES: dict[str, Callable[..., list[EnumResult]]] = {}


def register_oracle(
    protocol: str,
    oracle: Callable[[ConnectionProfile, list[str], float], list[EnumResult]],
) -> None:
    """Register a per-protocol user-enumeration oracle. Called from
    each backend that has a meaningful USER/PASS-style oracle."""
    if not isinstance(protocol, str) or not protocol.strip():
        raise ValueError("register_oracle: protocol must be a non-empty string")
    if not callable(oracle):
        raise TypeError("register_oracle: oracle must be callable")
    key = protocol.strip().lower()
    _ORACLES[key] = oracle
    log.debug("cred_attack registered enumeration oracle for %s", key)


def has_oracle(protocol: str) -> bool:
    return protocol.strip().lower() in _ORACLES


def supported_oracles() -> list[str]:
    return sorted(_ORACLES.keys())


def _validate_enum_results(
    results: Iterable[EnumResult],
    *,
    expected_count: int,
    source: str,
) -> list[EnumResult]:
    materialized = list(results)
    if len(materialized) != expected_count:
        raise ValueError(
            f"{source} returned {len(materialized)} results for {expected_count} candidates"
        )
    for idx, result in enumerate(materialized):
        if not isinstance(result, EnumResult):
            raise TypeError(
                f"{source} returned non-EnumResult at index {idx}: {type(result).__name__}"
            )
        if not 0.0 <= float(result.confidence) <= 1.0:
            raise ValueError(f"{source} returned confidence outside 0.0..1.0 at index {idx}")
    return materialized


def _oracle_pacing_kwargs(
    oracle: Callable[..., list[EnumResult]],
    *,
    protocol: str,
    rate_limiter: _TokenBucket,
    jitter_s: float,
) -> dict[str, object]:
    """Return pacing kwargs supported by a registered oracle.

    Custom oracles registered before the pacing contract existed are
    still valid. We warn because those callables must pace themselves;
    otherwise enumeration can run faster than the public OPSEC default.
    """
    try:
        signature = inspect.signature(oracle)
    except (TypeError, ValueError):
        log.warning(
            "enumerate_users oracle:%s has no introspectable signature; "
            "calling without rate_limiter, oracle is responsible for pacing",
            protocol,
        )
        return {}

    params = signature.parameters.values()
    accepts_kwargs = any(param.kind is inspect.Parameter.VAR_KEYWORD for param in params)
    parameter_names = set(signature.parameters)
    kwargs: dict[str, object] = {}
    if accepts_kwargs or "rate_limiter" in parameter_names:
        kwargs["rate_limiter"] = rate_limiter
    else:
        log.warning(
            "enumerate_users oracle:%s does not accept rate_limiter; "
            "oracle is responsible for pacing",
            protocol,
        )
    if accepts_kwargs or "jitter_s" in parameter_names:
        kwargs["jitter_s"] = jitter_s
    elif jitter_s > 0:
        log.warning(
            "enumerate_users oracle:%s does not accept jitter_s; "
            "configured jitter will not be applied inside this oracle",
            protocol,
        )
    return kwargs


# ---------------------------------------------------------------------------
# Built-in POP3 oracle
# ---------------------------------------------------------------------------
#
# Most POP3 servers respond differently to ``USER <known>`` /
# ``USER <unknown>`` — either at the USER stage (Dovecot, qpopper) or
# at the PASS stage (some commercial appliances). We probe both and
# look at the response wording. Fall back to "unknown" rather than
# guessing when neither path discriminates.


def _pop3_oracle(
    profile: ConnectionProfile,
    candidates: list[str],
    timeout_s: float,
    *,
    rate_limiter: _TokenBucket | None = None,
    jitter_s: float = 0.0,
) -> list[EnumResult]:
    import poplib

    results: list[EnumResult] = []
    rng = random.Random()
    use_ssl = bool(profile.pop3_ssl)
    host = profile.host
    port = profile.port or (995 if use_ssl else 110)
    enum_probe_value = "axross-enum-" + hashlib.sha256(str(time.time()).encode()).hexdigest()[:16]

    for candidate in candidates:
        _pace_probe(rate_limiter, jitter_s, rng)
        verdict_exists: bool | None = None
        notes = ""
        probe_pass = True
        try:
            if use_ssl:
                pop = poplib.POP3_SSL(host, port, timeout=timeout_s)
            else:
                pop = poplib.POP3(host, port, timeout=timeout_s)
            try:
                try:
                    pop.user(candidate)
                except poplib.error_proto as exc:
                    text = str(exc).lower()
                    if any(
                        m in text
                        for m in ("no such user", "user unknown", "unknown user", "user not found")
                    ):
                        verdict_exists = False
                        notes = "USER stage rejected"
                    elif any(m in text for m in ("locked", "disabled", "too many", "rate")):
                        notes = f"USER stage indicates lockout: {exc}"
                        probe_pass = False
                    else:
                        # Server accepted USER without comment — try PASS
                        verdict_exists = None
                        notes = f"USER stage error wording inconclusive: {exc}"
                if verdict_exists is None and probe_pass:
                    try:
                        pop.pass_(enum_probe_value)
                        log.warning(
                            "pop3 oracle candidate=%r authenticated with junk password",
                            candidate,
                        )
                        verdict_exists = True
                        notes = "PASS accepted junk password"
                    except poplib.error_proto as exc:
                        text = str(exc).lower()
                        if any(m in text for m in ("no such user", "user unknown", "unknown user")):
                            verdict_exists = False
                            notes = "PASS stage: user unknown"
                        elif any(
                            m in text
                            for m in (
                                "authentication failed",
                                "auth failed",
                                "invalid password",
                                "incorrect password",
                                "wrong password",
                            )
                        ):
                            verdict_exists = True
                            notes = "PASS stage: auth failed (user known)"
                        else:
                            notes = f"PASS stage inconclusive: {exc}"
            finally:
                try:
                    pop.quit()
                except Exception as exc:  # noqa: BLE001
                    log.debug("pop3 oracle quit raised: %s", exc)
                    try:
                        pop.close()
                    except Exception:
                        pass
        except Exception as exc:  # noqa: BLE001 - poplib/socket/ssl vary
            log.warning(
                "pop3 oracle candidate=%r failed: %s",
                candidate,
                _redact_log_text(str(exc)),
            )
            results.append(
                EnumResult(
                    username=candidate,
                    likely_exists=False,
                    confidence=0.0,
                    method="oracle:pop3",
                    notes=f"network/protocol error: {_redact_log_text(str(exc))}",
                )
            )
            continue

        if verdict_exists is None:
            results.append(
                EnumResult(
                    username=candidate,
                    likely_exists=False,
                    confidence=0.0,
                    method="oracle:pop3",
                    notes=notes or "no discriminator",
                )
            )
        else:
            results.append(
                EnumResult(
                    username=candidate,
                    likely_exists=verdict_exists,
                    confidence=0.9 if verdict_exists else 0.7,
                    method="oracle:pop3",
                    notes=notes,
                )
            )
    return results


register_oracle("pop3", _pop3_oracle)


# ---------------------------------------------------------------------------
# Built-in FTP oracle (USER/PASS response codes)
# ---------------------------------------------------------------------------
#
# Many FTP servers leak user existence between USER and PASS:
#   USER <known>   → 331 "Password required for X."
#   USER <unknown> → 530 "User cannot log in." (some servers — vsftpd,
#                                              proftpd default)
# Some servers always return 331 regardless; for those the oracle
# returns confidence=0 and the caller should fall back to timing.


def _ftp_oracle(
    profile: ConnectionProfile,
    candidates: list[str],
    timeout_s: float,
    *,
    rate_limiter: _TokenBucket | None = None,
    jitter_s: float = 0.0,
) -> list[EnumResult]:
    import ftplib

    results: list[EnumResult] = []
    rng = random.Random()
    host = profile.host
    port = profile.port or 21
    use_tls = profile.protocol == "ftps"
    enum_probe_value = "axross-enum-junk"

    for candidate in candidates:
        _pace_probe(rate_limiter, jitter_s, rng)
        try:
            if use_tls:
                ftp = ftplib.FTP_TLS()
            else:
                ftp = ftplib.FTP()
            ftp.connect(host, port, timeout=timeout_s)
            if use_tls:
                ftp.auth()
        except Exception as exc:  # noqa: BLE001 - ftplib/socket/ssl vary
            log.warning(
                "ftp oracle candidate=%r connect failed: %s",
                candidate,
                _redact_log_text(str(exc)),
            )
            results.append(
                EnumResult(
                    username=candidate,
                    likely_exists=False,
                    confidence=0.0,
                    method="oracle:ftp",
                    notes=f"connect error: {_redact_log_text(str(exc))}",
                )
            )
            continue

        try:
            try:
                resp = ftp.sendcmd("USER " + candidate)
            except ftplib.error_perm as exc:
                # 5xx straight off USER → user denied / unknown.
                code = str(exc).split()[0] if str(exc) else ""
                results.append(
                    EnumResult(
                        username=candidate,
                        likely_exists=False,
                        confidence=0.8 if code.startswith("530") else 0.4,
                        method="oracle:ftp",
                        notes=f"USER rejected ({code or 'no code'})",
                    )
                )
                continue
            code = (resp.split() or [""])[0]
            if code == "230":
                # Anonymous-style instant accept — no oracle.
                log.warning(
                    "ftp oracle candidate=%r USER returned 230 before PASS",
                    candidate,
                )
                results.append(
                    EnumResult(
                        username=candidate,
                        likely_exists=True,
                        confidence=0.5,
                        method="oracle:ftp",
                        notes="USER returned 230 (anonymous-style accept)",
                    )
                )
                continue
            if code != "331":
                results.append(
                    EnumResult(
                        username=candidate,
                        likely_exists=False,
                        confidence=0.0,
                        method="oracle:ftp",
                        notes=f"USER unexpected code {code}",
                    )
                )
                continue
            # 331 — server wants a password. Send junk to see whether
            # PASS distinguishes "wrong password for known user" from
            # "no such user".
            try:
                ftp.sendcmd("PASS " + enum_probe_value)
                # 230 here would mean the junk worked → user has no
                # password (treat as exists).
                log.warning(
                    "ftp oracle candidate=%r authenticated with junk password",
                    candidate,
                )
                results.append(
                    EnumResult(
                        username=candidate,
                        likely_exists=True,
                        confidence=0.5,
                        method="oracle:ftp",
                        notes="PASS accepted junk password",
                    )
                )
            except ftplib.error_perm as exc:
                text = str(exc).lower()
                if "user cannot log in" in text or "unknown user" in text:
                    results.append(
                        EnumResult(
                            username=candidate,
                            likely_exists=False,
                            confidence=0.7,
                            method="oracle:ftp",
                            notes=f"PASS rejected: {exc}",
                        )
                    )
                else:
                    results.append(
                        EnumResult(
                            username=candidate,
                            likely_exists=True,
                            confidence=0.6,
                            method="oracle:ftp",
                            notes=f"PASS rejected (likely wrong pw): {exc}",
                        )
                    )
        except Exception as exc:  # noqa: BLE001 - per-candidate robustness
            log.warning(
                "ftp oracle candidate=%r failed: %s",
                candidate,
                _redact_log_text(str(exc)),
            )
            results.append(
                EnumResult(
                    username=candidate,
                    likely_exists=False,
                    confidence=0.0,
                    method="oracle:ftp",
                    notes=f"network/protocol error: {_redact_log_text(str(exc))}",
                )
            )
        finally:
            try:
                ftp.quit()
            except Exception as exc:  # noqa: BLE001
                log.debug("ftp oracle quit raised: %s", exc)
                try:
                    ftp.close()
                except Exception:
                    pass
    return results


register_oracle("ftp", _ftp_oracle)
register_oracle("ftps", _ftp_oracle)


# ---------------------------------------------------------------------------
# Timing-based fallback
# ---------------------------------------------------------------------------


def _timing_enum(
    profile: ConnectionProfile,
    candidates: list[str],
    timeout_s: float,
    samples_per_candidate: int,
    enum_probe_value: str | None = None,
    on_unknown_host: Callable[[object], bool] | None = None,
    rate_limiter: _TokenBucket | None = None,
    jitter_s: float = 0.0,
) -> list[EnumResult]:
    """Generic timing-based user enumeration.

    Approach:
      * For each candidate, run ``samples_per_candidate`` login
        attempts with a junk password and record the wall-time.
      * Take the **median** per candidate (robust against outliers).
      * Compute the global median + median absolute deviation.
      * A candidate whose median is more than ``MAD * 3`` above the
        global median is flagged as "likely exists" (longer hash compare).
        Below: "likely doesn't exist" (server short-circuits).
    """
    junk = enum_probe_value or (
        "axross-enum-" + hashlib.sha256(str(time.time()).encode()).hexdigest()[:16]
    )

    medians: list[float] = []
    raw: dict[str, list[float]] = {}
    direct_hits: set[str] = set()
    rng = random.Random()

    for candidate in candidates:
        samples: list[float] = []
        for _ in range(max(1, samples_per_candidate)):
            _pace_probe(rate_limiter, jitter_s, rng)
            attempt_kwargs = {"timeout_s": timeout_s}
            if on_unknown_host is not None:
                attempt_kwargs["on_unknown_host"] = on_unknown_host
            outcome = _attempt_login(profile, candidate, junk, **attempt_kwargs)
            if outcome.result is AttemptResult.SUCCESS:
                log.warning(
                    "timing enum candidate=%r authenticated with junk password",
                    candidate,
                )
                direct_hits.add(candidate)
                break
            if outcome.result is AttemptResult.LOCKOUT:
                # We will not pump more lockout-triggering attempts at
                # the same user.
                break
            if outcome.result is AttemptResult.ERROR:
                log.debug(
                    "timing enum skipped error sample for %r: %s",
                    candidate,
                    outcome.error_message[:200],
                )
                continue
            samples.append(outcome.elapsed_s)
        if samples:
            raw[candidate] = samples
            medians.append(statistics.median(samples))

    results: list[EnumResult] = []
    if not medians:
        for candidate in candidates:
            if candidate in direct_hits:
                results.append(
                    EnumResult(
                        username=candidate,
                        likely_exists=True,
                        confidence=1.0,
                        method="timing",
                        notes="junk password authenticated",
                    )
                )
            else:
                results.append(
                    EnumResult(
                        username=candidate,
                        likely_exists=False,
                        confidence=0.0,
                        method="timing",
                        notes="no samples collected",
                    )
                )
        return results

    global_median = statistics.median(medians)
    abs_dev = [abs(m - global_median) for m in medians]
    mad = statistics.median(abs_dev) if abs_dev else 0.0
    # Floor on MAD so a perfectly-uniform server doesn't make every
    # candidate look anomalous.
    mad = max(mad, 0.005)
    threshold_high = global_median + mad * 3.0
    threshold_low = global_median - mad * 3.0

    for candidate in candidates:
        if candidate in direct_hits:
            results.append(
                EnumResult(
                    username=candidate,
                    likely_exists=True,
                    confidence=1.0,
                    method="timing",
                    notes="junk password authenticated",
                )
            )
            continue
        samples = raw.get(candidate, [])
        if not samples:
            results.append(
                EnumResult(
                    username=candidate,
                    likely_exists=False,
                    confidence=0.0,
                    method="timing",
                    notes="no samples (lockout or all errors)",
                )
            )
            continue
        med = statistics.median(samples)
        if med >= threshold_high:
            confidence = min(1.0, (med - global_median) / max(mad, 0.001) / 6.0)
            results.append(
                EnumResult(
                    username=candidate,
                    likely_exists=True,
                    confidence=confidence,
                    method="timing",
                    notes=(
                        f"median {med * 1000:.0f}ms vs global {global_median * 1000:.0f}ms "
                        f"(mad={mad * 1000:.0f}ms)"
                    ),
                )
            )
        elif med <= threshold_low:
            results.append(
                EnumResult(
                    username=candidate,
                    likely_exists=False,
                    confidence=min(1.0, (global_median - med) / max(mad, 0.001) / 6.0),
                    method="timing",
                    notes=(f"median {med * 1000:.0f}ms below global {global_median * 1000:.0f}ms"),
                )
            )
        else:
            results.append(
                EnumResult(
                    username=candidate,
                    likely_exists=False,
                    confidence=0.0,
                    method="timing",
                    notes=(
                        f"median {med * 1000:.0f}ms — within noise of global "
                        f"{global_median * 1000:.0f}ms"
                    ),
                )
            )
    return results


# ---------------------------------------------------------------------------
# Public API — enumerate_users
# ---------------------------------------------------------------------------


def enumerate_users(
    profile: ConnectionProfile | str,
    candidates: Iterable[str],
    *,
    method: str = "auto",
    timeout_per_probe: float = 10.0,
    timing_samples: int = 5,
    rate_per_min: float = 30.0,
    jitter_s: float = 0.0,
    progress: Callable[[EnumResult], None] | None = None,
    on_unknown_host: Callable[[object], bool] | None = None,
    authorized: bool = False,
) -> EnumReport:
    """Probe whether each candidate username exists on the target.

    Args:
        profile: target template (``ConnectionProfile`` or saved-name).
        candidates: iterable of usernames to test.
        method: one of:
            ``"auto"`` (default) — use the registered oracle if one
                exists for the protocol, otherwise fall back to timing.
            ``"oracle"`` — refuse to run if no oracle is registered.
            ``"timing"`` — always use timing, even when an oracle exists.
        timeout_per_probe: connect/read timeout per candidate probe.
        timing_samples: number of samples to take per candidate when
            timing is in use. 5 is the minimum for a stable median;
            10–20 gives a much cleaner signal at the cost of more
            attempts per candidate (and more noise on the wire).
        rate_per_min: token-bucket rate for oracle probes and timing
            attempts. Default 30/min ≈ one probe every two seconds.
        jitter_s: random sleep [0, jitter_s) added on top of the
            rate-limit interval.
        progress: callback fired with each :class:`EnumResult`.
        on_unknown_host: optional SSH/SCP host-key decision callback,
            used only by timing fallback through :func:`_attempt_login`.
        authorized: must be True. Hard gate.

    Returns:
        :class:`EnumReport` with one :class:`EnumResult` per candidate.
    """
    _check_authorisation(authorized, "enumerate_users")
    template = _resolve_profile(profile)
    require_protocol_allowed(template.protocol)
    candidates_l = _materialize_usernames(candidates, field_name="candidates")
    if not candidates_l:
        raise ValueError("enumerate_users: candidates iterable is empty")
    if not isinstance(method, str):
        raise TypeError("enumerate_users: method must be a string")
    method = method.strip().lower()
    if method not in {"auto", "oracle", "timing"}:
        raise ValueError(
            f"enumerate_users: method must be 'auto', 'oracle' or 'timing'; got {method!r}"
        )
    if method == "timing" or (method == "auto" and not has_oracle(template.protocol)):
        _validate_password_auth_profile(template)
    timeout_per_probe = _validate_positive_float(
        "timeout_per_probe",
        timeout_per_probe,
    )
    timing_samples = _validate_positive_int("timing_samples", timing_samples)
    rate_per_min = _validate_positive_float("rate_per_min", rate_per_min)
    jitter_s = _validate_non_negative_float("jitter_s", jitter_s)
    rate_limiter = _TokenBucket(rate_per_min)

    started_at = time.time()
    report = EnumReport(
        target_protocol=template.protocol,
        target_host=template.host,
        started_at=started_at,
        finished_at=started_at,
    )

    use_oracle = method == "oracle" or (method == "auto" and has_oracle(template.protocol))
    if method == "oracle" and not has_oracle(template.protocol):
        raise ValueError(
            f"enumerate_users(method='oracle'): no oracle registered for "
            f"protocol {template.protocol!r}. Available: "
            f"{', '.join(supported_oracles()) or '(none)'}"
        )

    if use_oracle:
        log.info(
            "enumerate_users START target=%s candidates=%d method=oracle:%s rate=%g/min",
            _redact_log_text(_target_key(template)),
            len(candidates_l),
            template.protocol.strip().lower(),
            rate_per_min,
        )
        protocol_key = template.protocol.strip().lower()
        oracle = _ORACLES[protocol_key]
        pacing_kwargs = _oracle_pacing_kwargs(
            oracle,
            protocol=protocol_key,
            rate_limiter=rate_limiter,
            jitter_s=jitter_s,
        )
        try:
            results = _validate_enum_results(
                oracle(template, candidates_l, timeout_per_probe, **pacing_kwargs),
                expected_count=len(candidates_l),
                source=f"oracle:{protocol_key}",
            )
        except Exception:
            log.exception(
                "enumerate_users oracle failed target=%s protocol=%s",
                _redact_log_text(_target_key(template)),
                template.protocol,
            )
            raise
    else:
        log.info(
            "enumerate_users START target=%s candidates=%d method=timing samples=%d rate=%g/min",
            _redact_log_text(_target_key(template)),
            len(candidates_l),
            timing_samples,
            rate_per_min,
        )
        results = _validate_enum_results(
            _timing_enum(
                template,
                candidates_l,
                timeout_per_probe,
                timing_samples,
                on_unknown_host=on_unknown_host,
                rate_limiter=rate_limiter,
                jitter_s=jitter_s,
            ),
            expected_count=len(candidates_l),
            source="timing",
        )

    for r in results:
        report.results.append(r)
        if progress is not None:
            try:
                progress(r)
            except Exception as exc:  # noqa: BLE001
                log.warning("enumerate_users progress callback raised: %s", exc)

    report.finished_at = time.time()
    log.info("enumerate_users END %s", report.summary())
    return report


__all__ = [
    "AttackReport",
    "AttemptOutcome",
    "AttemptResult",
    "Credential",
    "EnumReport",
    "EnumResult",
    "bruteforce",
    "classify_error",
    "enumerate_users",
    "has_oracle",
    "register_marker",
    "register_oracle",
    "spray",
    "supported_oracles",
]
