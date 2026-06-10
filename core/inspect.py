"""Directory inspection — ``summarize`` and ``explain``.

Both verbs are designed for the LLM-first workflow: an agent driving
axross via MCP needs a *short* description of "what is this place"
and "what's in it" without paying for an N-thousand-entry
``list_dir`` round-trip.

* :func:`summarize` walks a directory (one level by default), counts
  files / directories / total bytes, builds a histogram of file
  extensions and a coarse age histogram (now / day / week / month /
  older), grabs the newest and oldest items by mtime, and renders a
  one-paragraph synopsis. Returns both the structured
  :class:`Summary` for callers that want to inspect, and a text
  string when asked.

* :func:`explain` runs a small library of pattern matchers against
  the contents of a directory and returns a best-guess label
  ("PostgreSQL data directory", "systemd unit drop-in", "git
  repository", "web-server log directory", "Linux ``/etc``-style
  config tree", "Kubernetes manifests"). The matchers look for
  *signature filenames* and *characteristic shapes*; they're
  heuristic, not authoritative. The output includes a confidence
  score, the matching evidence, and a short hint sentence.

Both verbs only call ``backend.list_dir`` + ``backend.stat`` — they
do not read file contents. That keeps the cost low and predictable on
remote backends, and means an agent can run summarize/explain against
a path on every backend axross speaks.
"""

from __future__ import annotations

import logging
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------


@dataclass
class Summary:
    """Structured directory snapshot."""

    backend_label: str
    path: str
    file_count: int = 0
    dir_count: int = 0
    link_count: int = 0
    total_bytes: int = 0
    extensions: dict[str, int] = field(default_factory=dict)  # ".log" → count
    age_buckets: dict[str, int] = field(default_factory=dict)  # "1h"/"1d"/...
    largest: list[tuple[str, int]] = field(default_factory=list)  # top-5 by size
    newest: tuple[str, float] | None = None  # (name, epoch)
    oldest: tuple[str, float] | None = None
    truncated: bool = False
    error: str = ""

    def render(self) -> str:
        """One-paragraph human render. Defensive against missing data."""
        if self.error:
            return f"summary({self.path}): {self.error}"
        parts: list[str] = []
        parts.append(
            f"{self.backend_label}:{self.path} — "
            f"{self.file_count} files, {self.dir_count} dirs"
            + (f", {self.link_count} links" if self.link_count else "")
            + f", {_human_bytes(self.total_bytes)} total."
        )
        if self.extensions:
            top_ext = ", ".join(
                f"{ext}={n}"
                for ext, n in sorted(
                    self.extensions.items(),
                    key=lambda kv: kv[1],
                    reverse=True,
                )[:5]
            )
            parts.append(f"Top types: {top_ext}.")
        if self.newest:
            name, ts = self.newest
            parts.append(f"Newest: {name} ({_human_age(ts)}).")
        if self.oldest and self.oldest != self.newest:
            name, ts = self.oldest
            parts.append(f"Oldest: {name} ({_human_age(ts)}).")
        if self.age_buckets:
            buckets = ", ".join(f"{label}={n}" for label, n in self.age_buckets.items() if n)
            if buckets:
                parts.append(f"Age: {buckets}.")
        if self.truncated:
            parts.append("(listing truncated.)")
        return " ".join(parts)


# ---------------------------------------------------------------------------
# Explain
# ---------------------------------------------------------------------------


@dataclass
class ExplainResult:
    """Heuristic verdict on what a directory IS."""

    label: str
    confidence: float  # 0.0..1.0
    evidence: list[str] = field(default_factory=list)
    hint: str = ""

    def render(self) -> str:
        if not self.label:
            return "explain: no pattern matched."
        line = f"{self.label} (confidence {self.confidence:.2f})"
        if self.hint:
            line += f" — {self.hint}"
        if self.evidence:
            line += f"  [evidence: {', '.join(self.evidence[:5])}]"
        return line


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _human_bytes(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    units = ["KiB", "MiB", "GiB", "TiB", "PiB"]
    val = float(n)
    for u in units:
        val /= 1024
        if val < 1024:
            return f"{val:.1f} {u}"
    return f"{val:.1f} EiB"


def _human_age(ts: float) -> str:
    if not ts:
        return "no mtime"
    now = time.time()
    delta = max(0.0, now - ts)
    if delta < 60:
        return "moments ago"
    if delta < 3600:
        return f"{int(delta / 60)} min ago"
    if delta < 86400:
        return f"{int(delta / 3600)} h ago"
    if delta < 86400 * 30:
        return f"{int(delta / 86400)} d ago"
    if delta < 86400 * 365:
        return f"{int(delta / 86400 / 30)} mo ago"
    return f"{int(delta / 86400 / 365)} y ago"


def _ext_of(name: str) -> str:
    """Last dotted suffix, lowercased. ``"foo.tar.gz"`` → ``".gz"`` —
    that's enough for histogram intent; double-suffix files are rare
    enough that we don't bother resolving them."""
    if name.startswith("."):
        # dotfile: ".bashrc" → "(no-ext)" rather than ".bashrc"
        if "." not in name[1:]:
            return "(no-ext)"
        name = name[1:]
    if "." not in name:
        return "(no-ext)"
    return "." + name.rsplit(".", 1)[-1].lower()


def _bucket_for_age(seconds: float) -> str:
    if seconds < 3600:
        return "<1h"
    if seconds < 86400:
        return "<1d"
    if seconds < 86400 * 7:
        return "<1w"
    if seconds < 86400 * 30:
        return "<1mo"
    if seconds < 86400 * 365:
        return "<1y"
    return ">1y"


def _label(backend) -> str:
    return getattr(backend, "name", type(backend).__name__)


# ---------------------------------------------------------------------------
# summarize
# ---------------------------------------------------------------------------

DEFAULT_MAX_ENTRIES = 2000


def summarize(
    backend,
    path: str = "",
    *,
    max_entries: int = DEFAULT_MAX_ENTRIES,
) -> Summary:
    """Walk one directory level and produce a coarse, fast snapshot.

    Args:
        backend: any object satisfying :class:`core.backend.FileBackend`.
        path: directory to summarise. Empty → ``backend.home()``.
        max_entries: hard cap on items considered. Defaults to 2000;
            larger directories are sampled (the first ``max_entries``)
            and the result is marked ``truncated``.

    Never raises for a normal "permission denied" / "no such path";
    those become :class:`Summary` instances with a populated ``error``
    field.
    """
    label = _label(backend)
    if not path:
        path = backend.home() if hasattr(backend, "home") else "/"
    summary = Summary(backend_label=label, path=path)
    try:
        entries = backend.list_dir(path)
    except OSError as exc:
        summary.error = f"{type(exc).__name__}: {exc}"
        return summary

    if len(entries) > max_entries:
        summary.truncated = True
        entries = entries[:max_entries]

    ext_counter: Counter[str] = Counter()
    age_counter: Counter[str] = Counter()
    sizes: list[tuple[str, int]] = []
    now = time.time()
    newest_ts = -1.0
    oldest_ts = float("inf")
    newest_name = oldest_name = ""

    for item in entries:
        if getattr(item, "is_link", False):
            summary.link_count += 1
            continue
        if getattr(item, "is_dir", False):
            summary.dir_count += 1
            continue
        summary.file_count += 1
        size = int(getattr(item, "size", 0) or 0)
        summary.total_bytes += size
        ext_counter[_ext_of(item.name)] += 1
        sizes.append((item.name, size))
        ts = _entry_mtime(item)
        if ts:
            delta = max(0.0, now - ts)
            age_counter[_bucket_for_age(delta)] += 1
            if ts > newest_ts:
                newest_ts = ts
                newest_name = item.name
            if ts < oldest_ts:
                oldest_ts = ts
                oldest_name = item.name

    summary.extensions = dict(ext_counter)
    summary.age_buckets = dict(age_counter)
    summary.largest = sorted(sizes, key=lambda kv: kv[1], reverse=True)[:5]
    if newest_ts > 0:
        summary.newest = (newest_name, newest_ts)
    if oldest_ts != float("inf"):
        summary.oldest = (oldest_name, oldest_ts)
    return summary


def _entry_mtime(item: Any) -> float:
    """Pull a usable epoch-seconds mtime off a FileItem-shaped object.

    ``FileItem.modified`` is typically a datetime; some backends fill
    in raw floats; some leave it None. Be liberal in what we accept.
    """
    raw = getattr(item, "modified", None)
    if raw is None:
        return 0.0
    if hasattr(raw, "timestamp"):
        try:
            return float(raw.timestamp())
        except (OSError, OverflowError, ValueError):
            return 0.0
    try:
        return float(raw)
    except (TypeError, ValueError):
        return 0.0


# ---------------------------------------------------------------------------
# Pattern library for `explain`
# ---------------------------------------------------------------------------
#
# Each pattern declares a list of "expected" signature names. The
# matcher checks how many are present (case-insensitive) and computes
# a confidence as
#     hits / max(1, len(expected_min))
# clamped to [0, 1].
#
# ``expected_strict`` lists names that MUST be present; if any is
# missing the pattern's confidence is multiplied by 0.4 (it's a hint,
# not a match). ``negative`` lists names whose presence rules the
# pattern out entirely.


@dataclass(frozen=True)
class _Pattern:
    label: str
    hint: str
    expected: tuple[str, ...] = ()
    expected_strict: tuple[str, ...] = ()
    negative: tuple[str, ...] = ()
    min_hits: int = 1


_PATTERNS: tuple[_Pattern, ...] = (
    _Pattern(
        label="Git repository",
        hint="A git repo — packed-refs / objects / config indicate a working repo.",
        expected=(
            "config",
            "HEAD",
            "refs",
            "objects",
            "packed-refs",
            "info",
            "hooks",
            "description",
        ),
        expected_strict=("HEAD",),
    ),
    _Pattern(
        label="PostgreSQL data directory",
        hint="A pg_data dir; ``pg_hba.conf`` and the ``base/`` subtree are signature.",
        expected=(
            "PG_VERSION",
            "postgresql.conf",
            "pg_hba.conf",
            "pg_ident.conf",
            "base",
            "global",
            "pg_wal",
            "pg_xlog",
            "pg_subtrans",
            "postmaster.pid",
        ),
        expected_strict=("PG_VERSION",),
    ),
    _Pattern(
        label="MySQL / MariaDB data directory",
        hint="A datadir; ``ibdata1`` and ``mysql/`` are signature.",
        expected=(
            "ibdata1",
            "ib_logfile0",
            "ib_logfile1",
            "mysql",
            "performance_schema",
            "ibtmp1",
            "auto.cnf",
        ),
        expected_strict=("ibdata1",),
    ),
    _Pattern(
        label="MongoDB data directory",
        hint="A WiredTiger / MMAPv1 data dir; ``WiredTiger`` files identify it.",
        expected=(
            "WiredTiger",
            "WiredTigerLAS.wt",
            "WiredTiger.lock",
            "WiredTiger.wt",
            "_mdb_catalog.wt",
            "storage.bson",
            "mongod.lock",
        ),
        expected_strict=("WiredTiger",),
    ),
    _Pattern(
        label="Linux /etc-style config tree",
        hint="Top-level system config — typical /etc shape.",
        expected=(
            "hostname",
            "hosts",
            "resolv.conf",
            "nsswitch.conf",
            "passwd",
            "shadow",
            "group",
            "fstab",
            "ssh",
            "systemd",
            "cron.d",
            "sysctl.d",
            "ld.so.conf",
        ),
        min_hits=4,
    ),
    _Pattern(
        label="systemd unit drop-in directory",
        hint="A path holding ``*.service`` / ``*.timer`` / ``*.socket`` units.",
        expected=(),
    ),
    _Pattern(
        label="nginx config tree",
        hint="``nginx.conf`` plus ``conf.d/`` / ``sites-available/`` reveal an nginx layout.",
        expected=(
            "nginx.conf",
            "conf.d",
            "sites-available",
            "sites-enabled",
            "modules-enabled",
            "fastcgi_params",
            "mime.types",
        ),
        expected_strict=("nginx.conf",),
    ),
    _Pattern(
        label="Apache HTTPD config tree",
        hint="``httpd.conf`` / ``apache2.conf`` plus ``mods-enabled`` / ``sites-enabled``.",
        expected=(
            "httpd.conf",
            "apache2.conf",
            "mods-available",
            "mods-enabled",
            "sites-available",
            "sites-enabled",
            "envvars",
            "ports.conf",
        ),
    ),
    _Pattern(
        label="Web-server log directory",
        hint="Files named ``*.log``, ``access.log*``, ``error.log*``.",
        expected=(),
    ),
    _Pattern(
        label="Kubernetes manifests directory",
        hint="``*.yaml`` files starting with ``apiVersion:`` / ``kind:`` (heuristic by name).",
        expected=(
            "kustomization.yaml",
            "kustomization.yml",
            "values.yaml",
            "Chart.yaml",
            "deployment.yaml",
            "service.yaml",
            "ingress.yaml",
        ),
        min_hits=2,
    ),
    _Pattern(
        label="Python project root",
        hint="A python package source tree.",
        expected=(
            "pyproject.toml",
            "setup.py",
            "setup.cfg",
            "requirements.txt",
            "Pipfile",
            "tox.ini",
            "conftest.py",
            ".python-version",
            "MANIFEST.in",
        ),
        min_hits=2,
    ),
    _Pattern(
        label="Node.js project root",
        hint="A node package root.",
        expected=(
            "package.json",
            "package-lock.json",
            "yarn.lock",
            "pnpm-lock.yaml",
            "node_modules",
            ".nvmrc",
            "tsconfig.json",
        ),
        expected_strict=("package.json",),
    ),
    _Pattern(
        label="Docker image / Compose project",
        hint="``Dockerfile`` / ``docker-compose.yml`` mark a Docker workspace.",
        expected=(
            "Dockerfile",
            "docker-compose.yml",
            "docker-compose.yaml",
            ".dockerignore",
            "compose.yml",
            "compose.yaml",
        ),
    ),
    _Pattern(
        label="Mail spool (Maildir)",
        hint="Maildir layout — ``cur`` / ``new`` / ``tmp`` subdirs.",
        expected=("cur", "new", "tmp"),
        expected_strict=("cur", "new", "tmp"),
        min_hits=3,
    ),
    _Pattern(
        label="WordPress installation",
        hint="WordPress files; ``wp-config.php`` is signature.",
        expected=(
            "wp-config.php",
            "wp-content",
            "wp-includes",
            "wp-admin",
            "index.php",
            "wp-login.php",
        ),
        expected_strict=("wp-config.php",),
    ),
)


def explain(backend, path: str = "") -> ExplainResult:
    """Best-guess label for what kind of directory this is.

    Returns the highest-confidence pattern match, or an empty
    :class:`ExplainResult` if nothing scores above 0.2.
    """
    if not path:
        path = backend.home() if hasattr(backend, "home") else "/"
    try:
        entries = backend.list_dir(path)
    except OSError as exc:
        return ExplainResult(
            label="",
            confidence=0.0,
            hint=f"explain: {type(exc).__name__}: {exc}",
        )
    names = {item.name.lower() for item in entries}
    name_set = names  # alias for clarity below

    # Pre-compute helpful aggregates that some patterns lean on without
    # their own pattern entry.
    log_files = sum(1 for n in names if n.endswith(".log") or ".log." in n)
    yaml_files = sum(1 for n in names if n.endswith(".yaml") or n.endswith(".yml"))
    systemd_units = sum(
        1
        for n in names
        if n.endswith(".service")
        or n.endswith(".timer")
        or n.endswith(".socket")
        or n.endswith(".target")
    )
    total_files = len(names)

    candidates: list[ExplainResult] = []
    for pat in _PATTERNS:
        evidence: list[str] = []
        for sig in pat.expected:
            if sig.lower() in name_set:
                evidence.append(sig)
        # Strict signatures — every one is required for full confidence.
        strict_missing = [s for s in pat.expected_strict if s.lower() not in name_set]
        # Negative — kill the match outright.
        if any(n.lower() in name_set for n in pat.negative):
            continue

        # Special-case heuristics — patterns that are content-shape,
        # not signature-name.
        if pat.label == "Web-server log directory":
            if total_files >= 3 and log_files / max(1, total_files) >= 0.5:
                evidence.append(f"{log_files} *.log files")
            else:
                continue
        elif pat.label == "systemd unit drop-in directory":
            if systemd_units >= 2:
                evidence.append(f"{systemd_units} *.service/*.timer/*.socket")
            else:
                continue
        elif pat.label == "Kubernetes manifests directory":
            if yaml_files >= 2:
                evidence.append(f"{yaml_files} yaml files")

        if not evidence and not pat.expected:
            continue

        denom = max(1, pat.min_hits, len(pat.expected_strict))
        confidence = min(1.0, len(evidence) / denom)
        if strict_missing:
            confidence *= 0.4

        if confidence >= 0.2:
            candidates.append(
                ExplainResult(
                    label=pat.label,
                    confidence=confidence,
                    evidence=evidence,
                    hint=pat.hint,
                )
            )

    if not candidates:
        return ExplainResult(label="", confidence=0.0)
    candidates.sort(key=lambda r: r.confidence, reverse=True)
    return candidates[0]


__all__ = [
    "ExplainResult",
    "Summary",
    "explain",
    "summarize",
]
