"""find_secrets.py — scan a backend for files containing leaked secrets.

Walks PATH on BACKEND and matches each file's contents against a
small library of regexes that catch the usual culprits (private
keys, AWS access-key IDs, JWTs, .env-style assignments, slack
webhooks, GitHub tokens). Prints a one-line hit per match.

Usage::

    backend = axross.open("audit-target")
    hits = scan(backend, "/var/www")
    for h in hits:
        print(h)

The scanner caps per-file reads at 4 MiB so a giant log doesn't
swallow the audit.
"""
from __future__ import annotations

import re

MAX_BYTES_PER_FILE = 4 * 1024 * 1024
MAX_FILES = 5000  # short-circuit before drowning in noise

PATTERNS = [
    ("aws_access_key", re.compile(rb"AKIA[0-9A-Z]{16}")),
    ("aws_secret_in_env", re.compile(
        rb"aws_secret_access_key\s*=\s*['\"]?[A-Za-z0-9/+=]{30,}",
        re.IGNORECASE,
    )),
    ("private_key_block", re.compile(
        rb"-----BEGIN (?:RSA |OPENSSH |EC |DSA |ENCRYPTED )?PRIVATE KEY-----",
    )),
    ("jwt_token", re.compile(rb"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    ("slack_webhook", re.compile(rb"https://hooks\.slack\.com/services/[A-Z0-9/]+")),
    ("github_pat", re.compile(rb"ghp_[A-Za-z0-9]{30,}")),
    ("dotenv_assignment", re.compile(rb"^[A-Z_]{3,}=['\"]?[^\s'\"]{16,}", re.MULTILINE)),
]


def scan(backend, path: str) -> list[dict]:
    """Walk PATH and return a list of hits — each hit is a dict
    with ``path``, ``rule``, and ``snippet`` (the matching bytes)."""
    hits: list[dict] = []
    files_seen = 0
    for entry, is_dir in _walk(backend, path):
        if is_dir or files_seen >= MAX_FILES:
            continue
        files_seen += 1
        try:
            with backend.open_read(entry) as fh:
                data = fh.read(MAX_BYTES_PER_FILE)
        except OSError:
            continue
        for rule_name, rx in PATTERNS:
            # Cap per-rule matches at 3 so a file with hundreds of hits
            # doesn't drown the report.
            for m in list(rx.finditer(data))[:3]:
                hits.append({
                    "path": entry,
                    "rule": rule_name,
                    "snippet": m.group(0)[:120].decode("utf-8", "replace"),
                })
    return hits


def _walk(backend, root: str):
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            items = backend.list_dir(current)
        except OSError:
            continue
        yield current, True
        for it in items:
            child = backend.join(current, it.name)
            if it.is_dir:
                stack.append(child)
            else:
                yield child, False
