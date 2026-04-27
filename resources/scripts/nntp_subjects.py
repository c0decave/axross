"""nntp_subjects.py — collect subject lines for the most recent N
articles in a Usenet group.

Useful for keyword-monitoring a niche group, or for sampling content
shape before deciding whether to mirror.

Usage::

    sess = axross.open("usenet-server")
    subjects = collect(sess, "alt.test", limit=200)
    print("\\n".join(subjects))
"""
from __future__ import annotations


def collect(backend, group: str, limit: int = 100) -> list[str]:
    """Return the last ``limit`` article subjects in ``group``.
    Backend must be an :class:`NntpSession`."""
    items = backend.list_dir(f"/{group}")
    # The NNTP backend's name shape is ``<msgno>_<subject>.eml``;
    # parse the subject back out.
    subjects: list[str] = []
    for it in items[-limit:]:
        name = it.name
        if not name.endswith(".eml"):
            continue
        first_us = name.find("_")
        if first_us == -1:
            continue
        subjects.append(name[first_us + 1: -len(".eml")])
    return subjects
