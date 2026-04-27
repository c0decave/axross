"""git_changelog.py — extract a flat changelog from a Git-FS branch.

Reads the most recent commits on a branch via the dulwich object
store the Git-FS backend already opened, and emits one
``<sha>  <subject>`` line per commit.

Useful for quick deploy notes, or for automating a "what changed
since last cut" report.

Usage::

    repo = axross.open_url("git+local:///srv/repos/foo.git")
    print(changelog(repo, "main", limit=50))
"""
from __future__ import annotations


def changelog(backend, branch: str = "main", limit: int = 50) -> list[str]:
    """Return ``[<short-sha> <subject>]`` for the last ``limit``
    commits on ``branch``. Backend must be a :class:`GitFsSession`."""
    repo = backend._repo  # noqa: SLF001 — read-only walk
    tip = backend._branch_tips.get(branch)  # noqa: SLF001
    if tip is None:
        raise OSError(f"unknown branch: {branch}")
    out: list[str] = []
    walker = repo.get_walker(include=[tip], max_entries=limit)
    for entry in walker:
        commit = entry.commit
        subject = commit.message.decode("utf-8", "replace").splitlines()
        first = subject[0] if subject else "(empty)"
        out.append(f"{commit.id.decode()[:8]}  {first}")
    return out
