"""Hard-coded canonical-credential blocklist — defense-in-depth companion
to :mod:`security.export_filename_policy`.

Experience showed that the policy matcher in
:func:`security.export_filename_policy.is_blocked_filename` can miss a
path because the matching arms are tied to basename equality and
path-suffix-with-slash semantics. The fix at b4747aee landed inside the
helper, but a single-layer fix is fragile: any future refactor of the
matcher (a broader regex, basename-case-folding, a different
normalisation step) can re-introduce the same class of regression for
a different file with no second-line check to catch it.

This module is a separate, hard-coded SECOND layer: a tuple of
canonical credential paths that callers reject by EXACT EQUALITY
against the path relative to repo root. No basename, no suffix, no
globbing, no policy/overlay — the simplest possible matcher with the
narrowest possible attack surface. Two layers, two code paths, two
semantics; a regression in the primary helper now has to be matched by
a parallel regression here to leak a canonical credential.

The list is intentionally short and high-confidence. Adding entries is
a policy decision, not an aesthetic one — every entry is a path that
should NEVER appear inside a tracked tree, regardless of context. Use
:mod:`security.export_filename_policy` for the broader (overlay-able)
ruleset.
"""

from __future__ import annotations

# Canonical credential paths. Exact-equality match only — entries here
# MUST be the literal relative path as `git ls-files` would emit it.
# Order is documentation-only (callers don't depend on iteration order).
CANONICAL_CREDENTIAL_PATHS: tuple[str, ...] = (
    ".kube/config",           # Kubernetes — canonical case
    ".aws/credentials",       # AWS CLI
    ".aws/config",            # AWS CLI (region/profile, can carry session secrets)
    ".docker/config.json",    # Docker — registry auth tokens
    ".npmrc",                 # npm registry auth token
    ".pypirc",                # PyPI API token
    ".ssh/id_rsa",            # OpenSSH private keys
    ".ssh/id_dsa",
    ".ssh/id_ecdsa",
    ".ssh/id_ed25519",
    # GPG: the legacy pre-2.1 monolithic secret keyring file. Modern
    # GPG (≥2.1) stores private keys as `~/.gnupg/private-keys-v1.d/
    # <keyid>.key`; those are caught by the `.key` extension rule in
    # DEFAULT_BLOCKED_EXTENSIONS, so we don't list the directory path
    # here (a bare directory never appears in `git ls-files` output).
    ".gnupg/secring.gpg",
    ".netrc",                 # curl/wget HTTP basic-auth creds
)


def is_canonical_credential_path(rel: str) -> str | None:
    """Return ``"canonical-credential:<path>"`` if ``rel`` is on the
    canonical-credential list, else ``None``. Empty paths return
    ``None``.

    Match semantics: **exact equality only**. ``rel`` must equal one
    of :data:`CANONICAL_CREDENTIAL_PATHS` byte-for-byte. No basename,
    no suffix, no normalisation. This is deliberately the simplest
    matcher possible — its job is to catch a regression in the primary
    helper's more-flexible matching logic.

    >>> is_canonical_credential_path(".kube/config")
    'canonical-credential:.kube/config'
    >>> is_canonical_credential_path("README.md") is None
    True
    >>> is_canonical_credential_path("") is None
    True
    """
    if not rel:
        return None
    if rel in CANONICAL_CREDENTIAL_PATHS:
        return f"canonical-credential:{rel}"
    return None
