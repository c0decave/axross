"""rsync remove(): the filter rules that name the one entry to delete
(review round 2).

* ``--include`` takes a leading ``"- "`` / ``"+ "`` as a rule prefix
  (rsync's old-style prefixes), so the folder ``- old`` became the rule
  "exclude old/": nothing was deleted and remove() still returned.
  The folder's rule is anchored with a leading ``/`` now, like the file's.
* A backslash is an escape in a pattern only when the pattern holds a
  wildcard: ``back\\slash`` escaped to ``back\\\\slash`` named no file,
  and the delete removed nothing (remove() then said "rsync did not
  remove", so it failed, but always).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import rsync_client as RC  # noqa: E402


def _session(monkeypatch, is_dir: bool):
    calls: list[list[str]] = []

    def run(cmd, **_kw):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(RC.subprocess, "run", run)
    monkeypatch.setattr(RC.shutil, "which", lambda name: "/usr/bin/rsync")
    s = RC.RsyncSession("h", module="m")
    monkeypatch.setattr(s, "is_dir", lambda p: is_dir, raising=False)
    monkeypatch.setattr(s, "list_dir", lambda p: [], raising=False)
    return s, calls


def _rules(cmd: list[str]) -> list[tuple[str, str]]:
    return [(cmd[i], cmd[i + 1]) for i, a in enumerate(cmd) if a in ("--include", "--exclude")]


def test_sad_folder_with_rule_prefix_name_is_anchored(monkeypatch) -> None:
    s, calls = _session(monkeypatch, is_dir=True)
    s._remove_entry("/d/- old", True, True)
    rules = _rules(calls[-1])
    assert rules[0] == ("--include", "/- old/")
    for _flag, pattern in rules[:-1]:
        assert not pattern.startswith(("- ", "+ ", "!")), pattern


def test_sad_file_with_backslash_is_named_literally(monkeypatch) -> None:
    s, calls = _session(monkeypatch, is_dir=False)
    s._remove_entry("/d/back\\slash", False, False)
    assert ("--include", "/back\\slash") in _rules(calls[-1])


def test_happy_wildcards_are_still_escaped(monkeypatch) -> None:
    s, calls = _session(monkeypatch, is_dir=False)
    s._remove_entry("/d/a\\*[1]", False, False)
    assert ("--include", "/a\\\\\\*\\[1]") in _rules(calls[-1])
