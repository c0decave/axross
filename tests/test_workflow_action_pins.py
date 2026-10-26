"""Every GitHub Action the workflows run is pinned to a full commit SHA.

A tag (``actions/checkout@v4``) is mutable: whoever controls the action's
repository can point it at other code, and the next CI run - which builds
and uploads the macOS and Windows bundles - executes it. A 40-hex commit
SHA cannot be moved. The ``# vX.Y.Z`` comment names the release the SHA was
resolved from, so an update is a reviewed diff of both.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.y*ml"))
_USES = re.compile(r"^\s*(?:-\s+)?uses:\s*(.*)$")
_PINNED = re.compile(r'^"?([A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+)@([0-9a-f]{40})"?\s+#\s+v\d+\.\d+\.\d+\s*$')


def uses_lines(text: str) -> list[str]:
    """The values of every ``uses:`` key in *text*, commented-out lines skipped."""
    return [m.group(1).strip() for line in text.splitlines()
            if not line.lstrip().startswith("#") and (m := _USES.match(line))]


def unpinned(text: str) -> list[str]:
    """``uses:`` values that are neither a local action nor pinned by SHA
    with a release comment."""
    return [u for u in uses_lines(text) if not u.startswith("./") and not _PINNED.match(u)]


# --- happy -----------------------------------------------------------------


def test_happy_there_are_workflows_with_actions():
    assert WORKFLOWS
    assert sum(len(uses_lines(p.read_text(encoding="utf-8"))) for p in WORKFLOWS) >= 10


@pytest.mark.parametrize("path", WORKFLOWS, ids=[p.name for p in WORKFLOWS])
def test_happy_every_action_is_pinned_by_commit_sha(path):
    assert unpinned(path.read_text(encoding="utf-8")) == []


def test_happy_one_action_one_sha():
    """Two SHAs for one action across the workflows means one was updated
    and the other forgotten."""
    seen: dict[str, set] = {}
    for path in WORKFLOWS:
        for value in uses_lines(path.read_text(encoding="utf-8")):
            match = _PINNED.match(value)
            if match:
                repo = "/".join(match.group(1).split("/")[:2])
                seen.setdefault(repo, set()).add(match.group(2))
    assert {repo: shas for repo, shas in seen.items() if len(shas) > 1} == {}


# --- sad -------------------------------------------------------------------


@pytest.mark.parametrize("value", [
    "    - uses: actions/checkout@v4",
    "      uses: actions/checkout@v4.2.2",
    "      uses: actions/checkout@main",
    "      uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",  # no release comment
    "      uses: actions/checkout@3d3c42e5aac5ba80 # v7.0.1",  # short SHA
    '    uses: "google/osv-scanner-action/.github/workflows/x.yml@v2.7.0" # v2.7.0',
])
def test_sad_a_tag_branch_short_sha_or_missing_comment_is_refused(value):
    assert unpinned(value) != []


# --- edge ------------------------------------------------------------------


def test_edge_comments_and_local_actions_are_not_actions_to_pin():
    text = ("    #   uses: actions/setup-example@v1\n"
            "      - uses: ./.github/actions/local\n"
            '    uses: "google/osv-scanner-action/.github/workflows/osv-scanner-reusable.yml@'
            'b1d267aea5211fa648d9d442fa64b90dbdcbdd36" # v2.7.0\n')
    assert unpinned(text) == []
    assert len(uses_lines(text)) == 2
