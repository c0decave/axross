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


def redact(backend, root: str, pattern: str, passphrase: str,
           commit: bool = False) -> list[str]:
    rx = re.compile(pattern)
    affected: list[str] = []
    for entry, is_dir in _walk(backend, root):
        if is_dir:
            continue
        if not rx.search(entry):
            continue
        affected.append(entry)
        if commit:
            axross.encrypt(backend, entry, passphrase)
    return affected


def _walk(backend, root: str):
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            kids = backend.list_dir(current)
        except OSError:
            continue
        yield current, True
        for it in kids:
            child = backend.join(current, it.name)
            if it.is_dir:
                stack.append(child)
            else:
                yield child, False
