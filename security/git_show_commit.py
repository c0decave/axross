"""Defense-in-depth helper for the quoted-diff-header contract: scanners that
parse ``git show --format= REV`` output MUST handle the C-quoted
form of ``+++ b/<path>`` diff headers, since git's default
``core.quotePath=true`` emits non-ASCII paths as
``+++ "b/\\303\\251vil-leak.txt"``. The bare
``line.startswith("+++ b/")`` check in ``scan_diff_lines`` then
silently skips quoted headers, ``current_file`` inherits its
previous value, and if that was a SCAN_EXCLUDE_PREFIX every ``+``
line in the trailing non-ASCII hunk is wrongly excluded — a
forbidden substring in a non-ASCII filename slips past
--check-pushed and --scan-history as ``rc=0, clean``.

The helper combines two layers:

* :func:`commit_diff` invokes git with ``-c core.quotePath=false``
  so high-bit bytes pass through unquoted at the source (closes the
  common-case vector; mirrors the tracked-files ``ls-files -z``).
  ``--end-of-options`` blocks dash-prefixed rev smuggling.
* :func:`parse_new_side_path` ALSO accepts the quoted form
  (decoding ``\\\\``, ``\\"``, ``\\a..\\r``, 3-digit octals; UTF-8
  with surrogateescape). Even with ``-c core.quotePath=false`` git
  still quotes paths containing ``"``, ``\\``, ``\\n``, ``\\t`` or
  other ASCII control bytes — the long tail of legal-but-unusual
  names. So any caller that forgets the config flag still parses
  the header correctly instead of inheriting an excluded prefix.

Lifting the contract into ``security/`` mirrors the tracked-files /
merge-aware precedent: the policy lives outside ``scripts/`` so any
other caller (replacement hook, CI gate, audit tool) inherits it.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Optional

# Single-char escapes git emits in quoted paths.
_SIMPLE_ESCAPES: dict[str, int] = {
    "a": 0x07, "b": 0x08, "t": 0x09, "n": 0x0A,
    "v": 0x0B, "f": 0x0C, "r": 0x0D,
    "\\": 0x5C, '"': 0x22,
}


def _unquote_c(body: str) -> str:
    """Decode the body of a git-quoted path (text between the
    surrounding ``"..."``). Bytes are accumulated and decoded as
    UTF-8 with surrogateescape so non-UTF-8 byte sequences (legal
    on POSIX, surfaced as e.g. ``\\200`` octals) round-trip safely.
    Unknown escapes pass through literally — strictly safer than
    raising mid-scan since the caller treats the path as opaque."""
    out = bytearray()
    i = 0
    n = len(body)
    while i < n:
        c = body[i]
        if c != "\\":
            out.extend(c.encode("utf-8"))
            i += 1
            continue
        if i + 1 >= n:
            out.append(0x5C)
            i += 1
            continue
        nxt = body[i + 1]
        simple = _SIMPLE_ESCAPES.get(nxt)
        if simple is not None:
            out.append(simple)
            i += 2
            continue
        if (
            i + 3 < n
            and body[i + 1] in "0123"
            and body[i + 2] in "01234567"
            and body[i + 3] in "01234567"
        ):
            out.append(int(body[i + 1:i + 4], 8))
            i += 4
            continue
        out.extend(body[i:i + 2].encode("utf-8"))
        i += 2
    return out.decode("utf-8", errors="surrogateescape")


def is_added_side_header(line: str) -> bool:
    """Return True iff ``line`` is a genuine ``+++`` diff header.

    A real unified-diff header always carries a trailing space:
    ``+++ b/<path>``, ``+++ "b/<escaped>"`` (quoted form), or
    ``+++ /dev/null`` (file deletion). The leading-3-pluses prefix
    alone is NOT a sufficient discriminator: an added content line
    whose payload starts with ``++`` appears in the unified diff as
    ``+`` (added-marker) + ``++<rest>`` = ``+++<rest>`` — same
    prefix, different meaning. Callers MUST gate the
    "skip as header" branch on this helper, not on
    ``startswith("+++")``, otherwise such a content line is
    silently swallowed and a forbidden substring on it slips past
    the content scan.

    Tab and other whitespace are NOT accepted in place of the
    space: git's emitter always uses a single ASCII space, and
    accepting tabs would re-open the bypass for lines whose
    content starts with ``++\\t``.
    """
    if not line.startswith("+++ "):
        return False
    suffix = line[4:]
    if suffix == "/dev/null":
        return True
    if suffix.startswith("b/"):
        return True
    if suffix.startswith('"b/') and suffix.endswith('"') and len(suffix) >= 4:
        return True
    return False


PER_FILE_SEPARATOR_PREFIXES: tuple[str, ...] = (
    "diff --git ",
    "diff --cc ",
    "diff --combined ",
)
"""Per-file separator prefixes the :class:`DiffHeaderTracker` resets
state on. Trailing space is significant: it disambiguates the marker
from an added content line whose payload happens to begin with the
same bytes (e.g. ``+diff --combine`` inside a hunk body). Each entry
corresponds to a real git emit shape:

* ``diff --git `` — single-parent commits (and the default form for
  every non-merge commit).
* ``diff --cc `` — compact-combined diff for merge commits
  (default ``git show MERGE``).
* ``diff --combined `` — long form of ``--cc``, emitted when the
  caller passes ``--combined`` explicitly.

This tuple is the authoritative contract surface for "is this line a
per-file boundary?". Adding a new git variant must:

1. extend this tuple, *and*
2. extend the reset-state test set so the new variant is
   pinned as a state-resetting marker.

The tuple-with-``any()`` pattern in :meth:`DiffHeaderTracker.feed`
preserves the original ``or``-chain's short-circuit semantics — the
average diff-stream line is content and matches none of the prefixes,
so the loop exits after one comparison per entry in the common case.
"""


class DiffHeaderTracker:
    """Stateful gate for "is this line a genuine new-side diff header?"
    over a single ``git show --format=`` (or ``git diff``) output.

    Note: ``is_added_side_header`` alone is shape-only. It cannot
    distinguish a real ``+++ b/<path>`` header from an *added content
    line* whose payload begins with ``++ b/`` (rendered in the unified
    diff as ``+`` (added marker) + ``++ b/<rest>`` = ``+++ b/<rest>``).
    Both lines have an identical byte sequence; only the surrounding
    diff structure tells them apart:

    * A real ``+++ b/<path>`` header appears in the file-header section
      that begins with ``diff --git a/X b/Y`` and ends at the first
      ``@@`` hunk delimiter. After ``@@``, the section is the hunk
      body — every ``+``/``-``/`` `` prefixed line is content, not a
      header. The next ``diff --git`` starts the next file's header.

    Feed every line of the diff stream into :meth:`feed` in order; the
    return value tells the caller whether to treat the line as a
    header (skip + record :func:`parse_new_side_path` result as
    ``current_file``) or fall through to the content scanner. The
    tracker is single-use per diff stream — re-use on a second stream
    requires a fresh instance (cheaper than reset given the typical
    one-shot caller pattern).

    Combined-diff handling (merge-commit ``--cc`` output): hunk
    delimiters are ``@@@ -X,Y -X,Y +X,Y @@@`` (three ats); the
    ``line.startswith("@@")`` discriminator catches both 2- and
    3-at variants. New-side header lines in combined diff are
    ``++ b/<path>`` (two pluses) — DIFFERENT shape from ``+++ b/<path>``
    — so :func:`is_added_side_header` does not match them, and the
    tracker stays in pre-hunk state until the first ``@@@`` which is
    fine for the scan_diff_lines use case (it only scans single-parent
    diffs; merge commits are reached via the underlying parent commit
    in rev-list).

    Fail-safe default: an empty stream leaves ``in_hunk_body`` False;
    any ``+++ b/<path>`` line in such a stream is correctly classified
    as a header (matching the prior behaviour for the case where no
    structural cue is available).
    """

    __slots__ = ("in_hunk_body",)

    def __init__(self) -> None:
        self.in_hunk_body = False

    def feed(self, line: str) -> bool:
        """Feed one diff-stream line; return True iff it is a genuine
        new-side ``+++ b/...`` header. Returns False for hunk and file
        delimiters, for any line inside a hunk body (even one whose
        shape matches a header), and for content lines.

        Mutation contract: the tracker advances state on any per-file
        separator listed in :data:`PER_FILE_SEPARATOR_PREFIXES` by
        resetting in_hunk_body to False, and on any ``@@`` hunk
        delimiter (``@@`` and the combined-diff ``@@@`` form) by
        setting in_hunk_body to True, regardless of whether the caller
        chooses to act on the return value. Order of state transitions
        is exactly the order of lines fed, so the caller's loop need
        not pre-classify.

        Combined-diff merge commits use ``diff --cc <path>``
        (compact combined) or ``diff --combined <path>`` (long form)
        as the per-file separator instead of ``diff --git``. Without
        resetting in_hunk_body on these markers, the second-and-
        subsequent file's genuine ``+++ b/<path>`` header would be
        misclassified as content (because in_hunk_body stays True
        from the first file's ``@@@`` delimiter), pinning the
        caller's current_file to the first file and causing
        misattributed hits — or silent skips if the first file is
        in SCAN_EXCLUDE_PREFIXES.
        """
        if any(line.startswith(sep) for sep in PER_FILE_SEPARATOR_PREFIXES):
            self.in_hunk_body = False
            return False
        if line.startswith("@@"):
            self.in_hunk_body = True
            return False
        if self.in_hunk_body:
            return False
        return is_added_side_header(line)


def parse_new_side_path(line: str) -> Optional[str]:
    """Parse a unified-diff ``+++`` header.

    Returns the new-side path (``b/`` prefix stripped) for an added
    or modified file, or ``None`` for ``+++ /dev/null`` (file
    deletion) and for any header the parser cannot interpret with
    confidence (non-``+++``, missing trailing space, missing
    ``b/`` prefix, malformed quoted form).

    Callers MUST treat ``None`` as "do not trust the previous
    ``current_file``" — scan_diff_lines resets to ``"<unknown>"``
    so a stale excluded prefix from a prior hunk is not silently
    inherited. That reset is the root-cause fix: previously
    the bare ``startswith("+++ b/")`` check left ``current_file``
    unchanged for any unrecognised header (the quoted form in
    particular), and ``is_excluded(current_file)`` then skipped
    every following ``+`` line in the hunk.

    The leading-``+++`` test requires a trailing space.
    Without it, an added content line whose payload starts with
    ``++`` (rendered in the diff as ``+++<rest>``) is mistaken for
    a header. Callers that route every ``startswith("+++")`` line
    here would silently swallow such content; the trailing-space
    guard rejects those lines as not-a-header so the caller can
    fall through to the normal ``+``-content scanning path.
    Pair this with :func:`is_added_side_header` at the call site —
    that helper is the canonical "should I treat this as a
    header?" decision.

    Handles both forms git emits:

    * unquoted: ``+++ b/path/to/file.py`` → ``"path/to/file.py"``
    * quoted:   ``+++ "b/\\303\\251vil.txt"`` → ``"évil.txt"``
    """
    if not line.startswith("+++ "):
        return None
    rest = line[3:].lstrip()
    if rest == "/dev/null":
        return None
    if rest.startswith('"'):
        if len(rest) < 2 or not rest.endswith('"'):
            return None
        inner = _unquote_c(rest[1:-1])
        if inner.startswith("b/"):
            return inner[2:]
        return None
    if rest.startswith("b/"):
        return rest[2:]
    return None


def commit_diff(root: Path, rev: str) -> str:
    """Run ``git -c core.quotePath=false -C root show --format= REV``
    and return stdout decoded as UTF-8 with surrogateescape.

    ``-c core.quotePath=false`` is the canonical fix: high-
    bit bytes in path headers are emitted unquoted, so
    scan_diff_lines updates ``current_file`` for non-ASCII names
    via the same fast path it uses for ASCII names. The 2nd-layer
    :func:`parse_new_side_path` covers the long tail of paths git
    quotes regardless of the flag (``"``, ``\\``, ``\\n``, ``\\t``).

    ``--end-of-options`` blocks dash-prefixed rev smuggling so a
    caller cannot accidentally pass a ``git show`` option (e.g.
    ``--patch``, ``--src-prefix``) as the rev (merge-aware mirror).

    Fail-closed: any git failure — non-zero exit (corrupt
    object, invalid rev, non-git dir), or ``FileNotFoundError``
    (missing binary) — propagates via ``subprocess.CalledProcessError``
    / ``FileNotFoundError``. For a pre-push security scanner the
    correct response to "I cannot read this commit" is to abort the
    push, not to silently report ``clean (0 hits)``. Mirrors the
    ``check=True`` convention used by every other helper in
    ``security/`` (git_rev_changes, git_tracked_files, staged_blob).
    """
    proc = subprocess.run(
        [
            "git", "-c", "core.quotePath=false",
            "-C", str(root),
            "show", "--format=",
            "--end-of-options", rev,
        ],
        capture_output=True,
        check=True,
    )
    return proc.stdout.decode("utf-8", errors="surrogateescape")
