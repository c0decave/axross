"""rsync: a source argument names exactly one path, never a pattern.

rsync expands wildcards in a source (the daemon, and the remote rsync
under protect-args), one path component at a time, with backslash
escapes. ``rename("/a[1].txt", ...)`` sent ``a[1].txt`` as the source:
it matched ``a1.txt``, which was copied to the destination - and then
the original ``a[1].txt`` was deleted. Every source (list_dir,
open_read, rename, the dry run) is now sent with such a component
escaped.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import rsync_client as RC  # noqa: E402


def _rsync_component_matches(pattern: str, name: str) -> bool:
    """rsync's glob of one source component (util1.c glob_match): a
    component without * ? [ is literal, else wildmatch with \\ escapes."""
    if not any(c in pattern for c in "*?["):
        return pattern == name
    rx, i = "", 0
    while i < len(pattern):
        c = pattern[i]
        if c == "\\" and i + 1 < len(pattern):
            rx += re.escape(pattern[i + 1])
            i += 2
            continue
        if c == "*":
            rx += "[^/]*"
        elif c == "?":
            rx += "[^/]"
        elif c == "[":
            end = pattern.find("]", i + 1)
            rx += pattern[i : end + 1] if end > 0 else re.escape(c)
            i = end if end > 0 else i
        else:
            rx += re.escape(c)
        i += 1
    return re.fullmatch(rx, name) is not None


def test_sad_rename_source_matches_only_the_named_file(monkeypatch) -> None:
    sent: list[list[str]] = []

    def run(cmd, **_kw):
        sent.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(RC.subprocess, "run", run)
    monkeypatch.setattr(RC.shutil, "which", lambda name: "/usr/bin/rsync")
    s = RC.RsyncSession("h", module="m")
    monkeypatch.setattr(s, "is_dir", lambda p: False)
    monkeypatch.setattr(s, "stat", lambda p: (_ for _ in ()).throw(FileNotFoundError(p)))
    monkeypatch.setattr(s, "remove", lambda p, recursive=False: None)
    try:
        s.rename("/a[1].txt", "/b.txt")
    except OSError:
        pass  # the download into the temp folder finds nothing: no matter here
    source = next(c for c in sent if any("a" in a and "1" in a for a in c))
    url = next(a for a in source if a.startswith("rsync://"))
    component = url.rsplit("/", 1)[1]
    on_server = ["a1.txt", "a[1].txt"]
    assert [n for n in on_server if _rsync_component_matches(component, n)] == ["a[1].txt"]


def test_edge_literal_source_escapes_only_wildcard_components() -> None:
    """A component without a wildcard is literal to rsync: escaping its
    backslash would name another file."""
    lit = RC._literal_source
    assert lit("/dir/plain.txt") == "/dir/plain.txt"
    assert lit("/dir/back\\slash") == "/dir/back\\slash"
    assert lit("/d[x]/a*?.txt") == "/d\\[x]/a\\*\\?.txt"
    assert lit("/x/w\\[1]") == "/x/w\\\\\\[1]"
    for name in ("a[1].txt", "*", "?", "w\\[1]", "plain"):
        assert _rsync_component_matches(lit(name), name)
    assert not _rsync_component_matches(lit("a[1].txt"), "a1.txt")
