"""Defense-in-depth helpers for PATTERN-001 (Line-Delimiter Pluralism
Injection). Scanners and protocol parsers that process text emitted
by a source with ONE delimiter must split on that delimiter only —
never via :py:meth:`str.splitlines`.

This module is the protocol-side companion to
:mod:`security.diff_line_split` (which covers git diff streams). It
provides named, contract-pinned splitters for each emitter family
encountered in axross:

``split_lf_only_stream``
    For sources whose RFC pins ``\\n`` as the sole line terminator:
    git output, syslog RFC 5424, NDJSON / JSONL, container stdout,
    Python ``logging`` records, most Unix subprocess output that
    feeds line-oriented utilities. Equivalent to ``text.split("\\n")``
    but named so a regression is code-review-visible.

``split_crlf_stream``
    For sources whose RFC pins ``\\r\\n`` as the line terminator:
    FTP control channel (RFC 959), NNTP (RFC 3977), SMTP (RFC 5321),
    POP3 (RFC 1939), IMAP (RFC 3501), HTTP/1.x message framing
    (RFC 7230). The splitter accepts a bare trailing ``\\r`` as a
    CRLF artefact, but **rejects** bare ``\\r`` mid-line as the
    PATTERN-001 injection vector.

``split_text_safe``
    For arbitrary text where the caller deliberately wants Python's
    full Unicode line-boundary semantics (e.g. a code editor pane
    rendering arbitrary user text). This is the same behaviour as
    :py:meth:`str.splitlines` but the call site documents *why*
    splitlines is the right thing here.

``validate_no_internal_cr_payload``
    Predicate that returns False if a line carries an internal
    carriage return (a CR that is neither the last byte nor part
    of a trailing CRLF pair). Useful as a 2nd-layer guard at any
    site where the upstream contract says LF-only — even if a
    future regression at the splitter re-introduces ``splitlines()``,
    this guard keeps the bypass closed by rejecting the obviously
    malformed line.

``has_only_safe_line_boundaries``
    Paranoid check for text that must contain *only* ``\\n`` or
    ``\\r\\n`` line boundaries — no bare ``\\r``, ``\\v``, ``\\f``,
    ``\\x1c``-``\\x1e``, ``U+0085``, ``U+2028``, ``U+2029``. Use
    for top-level fail-closed input validation when the caller
    wants to reject malformed input outright rather than recover.

All functions are stdlib-only, side-effect-free, and safe to
import from any production scanner, test, or future security
helper.

See:

* :doc:`docs/patterns/PATTERN-001-splitlines-boundary-trust-mismatch`
* axross SPEC §A9 (Pre-push secret-scanner bypass attack family).
* axross commit ``8fad9cf`` / ``d16f829`` (reproduce + fix).
"""

from __future__ import annotations

# Characters that ``str.splitlines`` recognises as line boundaries.
# Order is documented in CPython's stringobject.c. Kept here as a
# public constant so callers can express "the set of bytes the
# attacker exploits" without re-deriving it.
SPLITLINES_BOUNDARIES: tuple[str, ...] = (
    "\r",       # CR
    "\v",       # VT
    "\f",       # FF
    "\x1c",     # FS (file separator)
    "\x1d",     # GS (group separator)
    "\x1e",     # RS (record separator)
    "\x85",     # NEL (next line)
    " ",   # LS (line separator)
    " ",   # PS (paragraph separator)
)

# Subset that an attacker can plausibly embed in payload bytes
# without the framing tool noticing — \v, \f, \x1c-\x1e, U+0085 are
# rarely stripped by intermediate libraries; U+2028 / U+2029 survive
# many JSON encoders. Used by :func:`has_only_safe_line_boundaries`.
_INJECTION_VECTORS: tuple[str, ...] = SPLITLINES_BOUNDARIES


def split_lf_only_stream(text: str) -> list[str]:
    """Split ``text`` on LF (``\\n``) only.

    The trailing empty string from a final ``\\n`` is preserved so
    callers can skip it with a ``not line.startswith(...)`` short-
    circuit (the existing pattern at every LF-split call site).

    Use for sources whose contract is LF-only:

    * git ``show`` / ``diff`` / ``log -p`` output
    * Unix subprocess stdout for line-oriented utilities
    * syslog RFC 5424 (LF only)
    * NDJSON / JSONL records
    * container stdout (Docker, k8s; both emit LF per record)
    * Python ``logging`` formatter output

    Equivalent to ``text.split("\\n")``. The value of the helper is
    in the *contract* it documents (callers must not reach for
    ``str.splitlines`` even when "it works"); the implementation is
    intentionally a thin wrapper. A regression that swaps in
    ``splitlines()`` reopens PATTERN-001; one that imports
    this helper cannot.
    """
    return text.split("\n")


def split_crlf_stream(text: str) -> list[str]:
    """Split ``text`` on CRLF (``\\r\\n``).

    Use for sources whose RFC pins CRLF as the line terminator:

    * FTP control channel (RFC 959)
    * NNTP (RFC 3977) — control + article headers
    * SMTP (RFC 5321)
    * POP3 (RFC 1939)
    * IMAP (RFC 3501) command-response framing
    * HTTP/1.x message framing (RFC 7230)

    The splitter is strict: a bare ``\\r`` or bare ``\\n`` mid-line
    is **kept inside that line** rather than treated as a boundary.
    This is the PATTERN-001 mitigation — an attacker who controls
    bytes between CRLF boundaries cannot inject a fake line by
    embedding bare ``\\r`` or bare ``\\n``.

    A trailing CRLF on the last line produces a trailing empty
    string element (consistent with :func:`split_lf_only_stream`).
    """
    return text.split("\r\n")


def split_text_safe(text: str) -> list[str]:
    """Split ``text`` using Python's full Unicode line-boundary
    semantics.

    Use for arbitrary text where the caller *deliberately* wants
    the same behaviour as :py:meth:`str.splitlines` — for example,
    a code editor pane that has to render multi-line text the way
    the user typed it, including odd boundary characters.

    The call site documents *why* the looser semantics is the
    correct contract for that specific surface; everyone else
    should reach for :func:`split_lf_only_stream` or
    :func:`split_crlf_stream`.
    """
    return text.splitlines()


def validate_no_internal_cr_payload(line: str) -> bool:
    """Return True iff ``line`` carries no internal CR.

    An "internal CR" is a ``\\r`` that is neither the last byte of
    the line nor part of a trailing CRLF artefact. Implementation:
    strip one trailing ``\\r`` first (the legitimate CRLF-source
    artefact a CRLF-source file produces on a unified diff), then
    look for any remaining ``\\r``.

    Use as a 2nd-layer guard at any LF-only call site: even if a
    future regression at the splitter re-introduces ``splitlines()``,
    this predicate rejects the obviously malformed line at the
    inner loop. Returning False means *the line is malformed* —
    callers typically force their metadata state machine into a
    safe state (e.g. ``current_file := "<unknown>"``) so any
    exclusion based on tracked metadata cannot apply to that line.

    The trailing-CRLF exemption is explicit (and documented here)
    because flagging it would break every diff over a CRLF-source
    file on a Windows checkout.
    """
    return "\r" not in line.removesuffix("\r")


def has_only_safe_line_boundaries(text: str) -> bool:
    """Return True iff ``text`` contains no character that
    :py:meth:`str.splitlines` would treat as a line boundary
    *other than* ``\\n`` and ``\\r\\n``.

    Stricter than :func:`validate_no_internal_cr_payload` — this
    catches the full ``\\v`` / ``\\f`` / ``\\x1c-\\x1e`` / NEL /
    U+2028 / U+2029 set, not just CR. Use for top-level fail-closed
    input validation at a trust boundary (e.g. a HTTP middleware,
    a log ingester, an MCP tool argument validator) when the
    caller wants to reject malformed input outright rather than
    recover.

    Worth noting that bare ``\\r`` is *not* in the rejected set
    here — it is covered by :func:`validate_no_internal_cr_payload`
    with its trailing-CRLF exemption. If you want to reject bare CR
    too, AND the input is not expected to be CRLF-terminated,
    chain the two predicates: ``has_only_safe_line_boundaries(t)
    and "\\r" not in t``.
    """
    # \r is intentionally absent — it appears legitimately in CRLF
    # framing and the caller can decide separately whether bare CR
    # is acceptable (see docstring).
    return not any(b in text for b in (
        "\v", "\f", "\x1c", "\x1d", "\x1e", "\x85", " ", " ",
    ))


__all__ = [
    "SPLITLINES_BOUNDARIES",
    "split_lf_only_stream",
    "split_crlf_stream",
    "split_text_safe",
    "validate_no_internal_cr_payload",
    "has_only_safe_line_boundaries",
]
