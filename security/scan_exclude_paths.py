"""Path-boundary-anchored exclusion matcher for SCAN_EXCLUDE_PREFIXES.

Defense-in-depth helper for the exclusion-anchoring contract: every scan mode in
:mod:`scripts.export-public` (worktree, staged, commit-range, history)
calls :func:`scripts.export-public.is_excluded` to decide whether to
SKIP the content scan for a given path — the path is treated as a
"scanner self-reference" (legitimate definitions of forbidden patterns
or the policy sidecar). Skipping a real file's content scan is a
security-relevant decision: a false positive here means a forbidden
substring rides through unscanned.

Before this fix, :func:`is_excluded` was

    any(path.startswith(p) for p in SCAN_EXCLUDE_PREFIXES)

The tuple mixes directory-shaped entries (``scripts/git-hooks/`` —
self-anchored by the trailing slash) with FILE-shaped entries
(``scripts/export-public.py``, ``scripts/build_release.sh``,
``.public-export-rules.toml``, ``.secrets-allowlist``) which are NOT
path-boundary anchored. ``startswith`` lets any path that merely
*begins with* a file entry's bytes inherit the skip — e.g.
``scripts/export-public.py-evil.txt`` or ``.secrets-allowlistEVIL.py``.
That bypasses every content-scan mode. Same attack class as the
root-level slash-bearing block bypass and the A9 family in SPEC.md:
a prefix matcher without path-boundary anchoring matches more than
it intends.

Lifting the matcher here gives it:

* A single canonical home outside ``scripts/`` (defense in depth — the
  script is one of two layers enforcing the rule).
* A focused test surface (:mod:`tests.test_scan_exclude_paths`)
  covering the four file-shaped entries individually plus the
  directory-shaped entry, plus edge cases (empty path, exact match,
  slash-suffix variants, unicode).
* Re-use for future callers (CI gate, secondary hook, audit tool)
  without re-implementing the anchoring logic.

Behaviour is a security tightening, not a pure refactor: any path that
the pre-fix matcher would have excluded but that does NOT match the
new path-boundary semantics will now be scanned. That's the entire
point of the fix.
"""

from __future__ import annotations

from dataclasses import dataclass


class PolicyError(ValueError):
    """Raised when a :class:`ScanExcludePolicy` carries a malformed entry.

    Subclasses :class:`ValueError` so callers with a broad
    ``except ValueError`` clause still catch it; the dedicated subclass
    lets policy-aware callers discriminate via ``except PolicyError``.
    """


def _validate_prefixes(prefixes: tuple[str, ...]) -> None:
    """Inner check: raise :class:`PolicyError` on the first malformed entry.

    Split from :func:`validate_policy` so :meth:`ScanExcludePolicy.__post_init__`
    can call it without needing the wrapped policy object — frozen-dataclass
    __post_init__ runs during ``__init__`` and can't yet rely on the public
    callable signature taking ``policy: ScanExcludePolicy`` (forward reference
    would re-validate, harmless but redundant).
    """
    for entry in prefixes:
        if entry == "":
            raise PolicyError(
                "ScanExcludePolicy: empty entry in prefixes tuple — would "
                "silently exclude every path; remove the empty string"
            )
        if entry != entry.strip():
            raise PolicyError(
                f"ScanExcludePolicy: whitespace in entry {entry!r} — would "
                "break the trailing-slash directory discriminator; trim"
            )
        # Internal-whitespace check parity with the boundary check above:
        # str.strip() catches \r / \v / \f at the boundary, but a paste
        # of Windows-CRLF source could embed a bare \r in the middle of
        # an entry (the boundary check would not fire). Cover the same
        # six ASCII whitespace characters \s recognises so the typo
        # defense is symmetric.
        if any(ch in entry for ch in " \t\n\r\v\f"):
            raise PolicyError(
                f"ScanExcludePolicy: whitespace inside entry {entry!r} — "
                "scan-exclude entries are path strings; remove the "
                "whitespace or escape the path before adding it"
            )
        if "//" in entry:
            raise PolicyError(
                f"ScanExcludePolicy: double-slash in entry {entry!r} — "
                "almost certainly a typo; collapse to a single `/`"
            )


@dataclass(frozen=True)
class ScanExcludePolicy:
    """Effective scanner-self-reference exclusion ruleset.

    A tuple (not list) of relative paths that callers should skip
    when content-scanning. Frozen + tuple-typed so the dataclass
    remains hashable and immutable — callers can safely cache it
    across requests.

    Entry semantics:

    * If an entry ends with ``"/"`` it is a DIRECTORY entry. Any path
      under that directory is excluded (``path.startswith(entry)``
      with the trailing slash supplying the path boundary).
    * Otherwise the entry is a FILE entry. A path is excluded iff
      it equals the entry exactly OR starts with ``entry + "/"``
      (the latter only matters if the excluded path is ever
      repurposed as a directory; in practice today's entries have
      no nested form, but the anchoring is what closes the bypass).

    2nd-layer tightening: ``__post_init__`` calls
    :func:`_validate_prefixes` so EVERY constructed policy carries the
    well-formedness check, not just those whose caller remembers to
    invoke :func:`validate_policy` afterwards. The matcher
    (:func:`is_excluded_path`) still defensively skips empty entries
    so a policy constructed via ``object.__setattr__`` (deserialization,
    test fixtures, ...) cannot silently exclude the whole worktree
    even if __post_init__ is bypassed.
    """

    prefixes: tuple[str, ...]

    def __post_init__(self) -> None:
        _validate_prefixes(self.prefixes)


def validate_policy(policy: ScanExcludePolicy) -> None:
    """Raise :class:`PolicyError` on the first malformed entry in ``policy``.

    Belt-and-suspenders public entry point. As of the
    ``__post_init__`` tightening, every freshly constructed
    :class:`ScanExcludePolicy` is already validated; callers that still
    invoke this function get a no-op fast-path on well-formed input,
    or a re-raise on a policy that was constructed via a __post_init__
    bypass and later patched into a malformed shape.

    Defense-in-depth: the matcher (:func:`is_excluded_path`)
    is path-boundary-anchored and immune to the original bypass. The
    POLICY DATA (the ``SCAN_EXCLUDE_PREFIXES`` tuple in
    :mod:`scripts.export-public`) is still hand-curated, and a future
    typo can re-introduce a silent-corruption bypass:

    * empty entry → ``startswith`` matches every path; the whole worktree
      is silently excluded from content scanning.
    * leading or trailing whitespace → the trailing-slash discriminator
      misfires (``"foo/ ".endswith("/")`` is ``False``) and the entry
      classifies as a file entry. The matcher then refuses every
      legitimate child path of the intended directory.
    * double-slash typo (``"foo//bar"``) → almost always an unintended
      character; reject so the contributor sees the mistake.

    The validator does NOT enforce relative-path semantics, ASCII-only
    bytes, or absence of ``..`` traversal — those are caller-side
    concerns and over-constraining here would block legitimate future
    use (e.g. a directory entry under ``./foo``). Only the shape
    invariants the exclusion-anchoring contract depends on are checked.
    """
    _validate_prefixes(policy.prefixes)


def is_excluded_path(policy: ScanExcludePolicy, path: str) -> bool:
    """Return True iff ``path`` is a scanner self-reference under
    ``policy`` — i.e. the content scan should be skipped for it.

    Matching is path-boundary anchored:

    * Empty path → False (no entry can match an empty string under
      these semantics, and the caller should not skip "nothing").
    * Directory entry (trailing ``"/"``) → ``path.startswith(entry)``.
      The trailing slash IS the boundary, so this is safe.
    * File entry (no trailing ``"/"``) → ``path == entry`` OR
      ``path.startswith(entry + "/")``. No bare-prefix match.

    >>> p = ScanExcludePolicy(prefixes=(
    ...     "scripts/export-public.py",
    ...     "scripts/git-hooks/",
    ...     ".secrets-allowlist",
    ... ))
    >>> is_excluded_path(p, "scripts/export-public.py")
    True
    >>> is_excluded_path(p, "scripts/git-hooks/pre-push")
    True
    >>> is_excluded_path(p, ".secrets-allowlist")
    True
    >>> is_excluded_path(p, "scripts/export-public.py-evil.txt")
    False
    >>> is_excluded_path(p, ".secrets-allowlistEVIL.py")
    False
    >>> is_excluded_path(p, "")
    False
    """
    if not path:
        return False
    for entry in policy.prefixes:
        if not entry:
            continue
        if entry.endswith("/"):
            if path.startswith(entry):
                return True
        elif path == entry or path.startswith(entry + "/"):
            return True
    return False
