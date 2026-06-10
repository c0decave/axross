"""Defense-in-depth helper for the LF-only diff-split contract:
scanners that process a unified-diff stream emitted by git MUST split
on ``\\n`` only, never via ``str.splitlines()``.

Before this fix, ``scripts/export-public.py:scan_diff_lines`` iterated
``diff_text.splitlines()``. Python's ``str.splitlines`` also breaks
at bare ``\\r``, ``\\v``, ``\\f``, ``\\x1c``-``\\x1e``, U+0085,
U+2028, U+2029 — none of which git ever emits as a structural diff
element terminator. A single ``+``-content line whose payload
contained an embedded ``\\r`` was therefore shattered by the scanner
into multiple "logical" lines that the per-file-separator /
``+++ b/<path>`` header / ``@@`` hunk-marker recognisers would match
in textual order. An attacker who committed a file whose content
began with ``OK\\rdiff --git a/.secrets-allowlist
b/.secrets-allowlist\\r--- a/.secrets-allowlist\\r+++
b/.secrets-allowlist\\r@@ -1,1 +1,1 @@\\r+<FORBIDDEN>`` produced a
unified diff in which the scanner saw a fake per-file separator
(resetting current_file), a fake ``+++ b/.secrets-allowlist``
header (setting current_file to a SCAN_EXCLUDE_PREFIXES entry), a
fake ``@@`` (in_hunk_body=True), and finally the ``+<FORBIDDEN>``
line — which was then SKIPPED via ``is_excluded(current_file)`` as
a scanner self-reference. ``--check-pushed`` and ``--scan-history``
reported ``clean`` while the forbidden substring rode through
unscanned. Same attack class as the other diff-shape bypasses:
matching diff *shape* without using the authoritative
line-boundary source (git's actual LF-terminated stream).

The 1st-layer fix in 7d82943 replaced ``splitlines()`` with
``split('\\n')`` and added an inline 2nd-layer ``current_file :=
"<unknown>"`` pin for any ``+``-content line carrying internal
``\\r``. Both defenses lived in the SAME module (a single file in
``scripts/``), so a future scanner — a CI gate, a secondary
pre-receive hook, an audit tool — that wrote ``diff_text
.splitlines()`` from scratch would silently re-introduce the bypass.

This module lifts the contract OUT of ``scripts/`` so:

* the LF-only split rule is a named import that any future caller
  reuses (the CR-injection bypass cannot regress in code that goes
  through the helper),
* the CR-laced-content-line detector
  (:func:`added_line_has_internal_cr`) is a named predicate every
  scanner can apply for the inline ``current_file := "<unknown>"``
  pin without re-deriving the trailing-CRLF-artifact exclusion,
* the contract has a focused test suite
  (``tests/test_diff_line_split.py``) that exercises happy / edge /
  sad cases independently of the end-to-end script tests, so a
  regression at the line-splitting boundary surfaces at a unit-test
  failure rather than waiting for an integration scenario.

The module is stdlib-only and has no side effects at import time —
it is safe to import from any production scanner, any test, and any
future security helper.
"""

from __future__ import annotations


def split_diff_stream(diff_text: str) -> list[str]:
    """Split a unified-diff stream into per-LF elements.

    Splits ONLY on ``\\n`` (the line terminator git emits). Bare
    ``\\r``, ``\\v``, ``\\f``, ``\\x1c``-``\\x1e``, U+0085, U+2028,
    U+2029 in the middle of a line stay PART of that line — they are
    content bytes, not structural diff elements. The trailing empty
    string from a final ``\\n`` is preserved so callers can skip it
    with a ``not line.startswith("+")`` short-circuit (the existing
    pattern in :func:`scripts.export-public.scan_diff_lines`).

    This is intentionally a thin wrapper over ``str.split('\\n')`` —
    the value is in the *contract* the helper documents (callers must
    not reach for ``str.splitlines`` even when "it works"), not in
    the implementation. A future regression that re-introduces
    ``splitlines()`` reopens the splitlines bypass; one that goes
    through this helper cannot.
    """
    return diff_text.split("\n")


def added_line_has_internal_cr(line: str) -> bool:
    """True iff ``line`` is a ``+``-prefixed unified-diff content line
    whose payload (the bytes after the leading ``+``) carries an
    embedded ``\\r`` that is NOT a single trailing CRLF artifact.

    A ``+``-content line with such an internal ``\\r`` is by
    definition attacker-crafted: git itself never emits a structural
    diff element inside a single LF-delimited line. Callers should
    pin ``current_file := "<unknown>"`` for any line where this
    returns True, taking any scanner-self-reference allowlist off
    the table for that specific line — even if a hypothetical future
    regression at the header-tracker layer accepted a CR-injected
    ``+++ b/<excluded>`` fragment as a header.

    The trailing-CRLF artifact (one ``\\r`` at the end of a line
    whose source file uses CRLF endings) is explicitly EXEMPTED —
    flagging it would cause every diff over a CRLF-source file to
    lose its scanner-self-reference exclusion semantics on Windows
    checkouts (a legitimate ``.secrets-allowlist`` line ending in
    CRLF would otherwise be misclassified as injection). Non-``+``
    lines (``-`` removed, ``space`` context, empty) return False:
    they are not scanned for forbidden substrings on the added
    side, so internal ``\\r`` in them is not a bypass vector and
    pinning current_file for them would add no defensive value
    while costing scan accuracy on legitimate diffs.
    """
    if not line.startswith("+"):
        return False
    return "\r" in line[1:].removesuffix("\r")
