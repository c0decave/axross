"""redact.py — encrypt every file under PATH whose name matches a
regex, leaving other files untouched.

Use case: pre-flight redaction before sharing a directory with a
support engineer — wrap every ``*.sql.dump``, ``*.kdbx``,
``*.env`` etc. in axross's encrypted-overlay format with a
passphrase only you hold.

Dry-run by default; pass ``commit=True`` to actually encrypt.

Usage::

    backend = axross.open("share-target")
    plan = redact(backend, "/exports", r"\\.(env|sql\\.dump|kdbx)$",
                  passphrase="support-2026", commit=False)
"""

from __future__ import annotations

import re

MAX_REGEX_CHARS = 512
MAX_WALK_ENTRIES = 100_000
_DANGEROUS_REGEX_RE = re.compile(
    r"\((?:[^()\\]|\\.){0,256}[+*](?:[^()\\]|\\.){0,256}\)"
    r"\s*(?:[+*]|\{\d*,?\d*\})"
)


def redact(
    backend,
    root: str,
    pattern: str,
    passphrase: str,
    commit: bool = False,
    *,
    max_entries: int = MAX_WALK_ENTRIES,
) -> list[str]:
    rx = _compile_safe_regex(pattern)
    affected: list[str] = []
    for entry, is_dir in _walk(backend, root, max_entries=max_entries):
        if is_dir:
            continue
        if not rx.search(entry):
            continue
        affected.append(entry)
        if commit:
            axross.encrypt(backend, entry, passphrase, keep_original=False)
    return affected


def _compile_safe_regex(pattern: str):
    if not isinstance(pattern, str):
        raise TypeError("pattern must be a string")
    if len(pattern) > MAX_REGEX_CHARS:
        raise ValueError(f"regex is too long; limit is {MAX_REGEX_CHARS} chars")
    if _DANGEROUS_REGEX_RE.search(pattern):
        raise ValueError("regex rejected: nested quantified groups are unsafe")
    return re.compile(pattern)


def _walk(backend, root: str, *, max_entries: int):
    if max_entries < 1:
        raise ValueError("max_entries must be >= 1")
    stack = [root]
    seen: set[str] = set()
    yielded = 0
    while stack:
        current = stack.pop()
        if current in seen:
            continue
        seen.add(current)
        yielded += 1
        if yielded > max_entries:
            raise RuntimeError(f"walk exceeded max_entries={max_entries}")
        try:
            kids = backend.list_dir(current)
        except OSError:
            continue
        yield current, True
        for it in kids:
            child = backend.join(current, it.name)
            yielded += 1
            if yielded > max_entries:
                raise RuntimeError(f"walk exceeded max_entries={max_entries}")
            if it.is_dir:
                stack.append(child)
            else:
                yield child, False
