"""Every tracked file name checks out on Windows and macOS.

Release 0.15.176 carried ``resources/chat_servers/*.json`` (a glob written
as a file name). ``*`` is not allowed in a Windows file name: the checkout
of the cross-platform workflow failed on Windows, the bundle job was
skipped, and the release went out without its macOS and Windows binaries.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
#: Characters Windows refuses in a name, and its reserved device names.
_BAD_CHARS = re.compile(r'[<>:"|?*\\\x00-\x1f]')
_RESERVED = re.compile(r"^(con|prn|aux|nul|com[0-9]|lpt[0-9])(\..*)?$", re.IGNORECASE)
#: The checkout path of the Windows runner, plus margin, under MAX_PATH.
_RUNNER_PREFIX = "D:/a/axross/axross/"


def _tracked() -> list[str]:
    if shutil.which("git") is None or not (ROOT / ".git").exists():
        pytest.skip("not a git checkout")
    out = subprocess.run(["git", "-C", str(ROOT), "ls-files", "-z"], capture_output=True,
                         check=True).stdout
    return [p for p in out.decode("utf-8", "surrogateescape").split("\0") if p]


def windows_problems(path: str) -> list[str]:
    problems = []
    for part in path.split("/"):
        if _BAD_CHARS.search(part):
            problems.append(f"{part!r}: a character Windows refuses")
        if part.endswith((".", " ")):
            problems.append(f"{part!r}: ends in a dot or a space")
        if _RESERVED.match(part):
            problems.append(f"{part!r}: a reserved device name")
    if len(_RUNNER_PREFIX + path) > 259:
        problems.append("longer than Windows' MAX_PATH on the CI runner")
    return problems


def test_sad_no_tracked_name_breaks_a_windows_checkout():
    bad = {p: windows_problems(p) for p in _tracked() if windows_problems(p)}
    assert bad == {}


def test_sad_no_two_tracked_paths_differ_only_in_case():
    """macOS and Windows file systems fold case: one of two such files is lost."""
    seen: dict[str, str] = {}
    clashes = []
    for path in _tracked():
        key = path.casefold()
        if key in seen:
            clashes.append((seen[key], path))
        seen[key] = path
    assert clashes == []


@pytest.mark.parametrize("name", ["resources/chat_servers/*.json", "docs/a:b.md", "aux.txt",
                                  "notes.", "x/CON/y.py"])
def test_edge_the_check_catches_names_windows_refuses(name):
    assert windows_problems(name)
