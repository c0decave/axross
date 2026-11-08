""".gitattributes: LF for every text file, binary for the rest.

Without it a Windows checkout with core.autocrlf writes CRLF into the shell
scripts, the Dockerfiles and the DKIM-signed mail fixtures (the signature
covers the exact line ends), and git may diff or convert an image or an
archive as text.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _git(*args: str) -> str:
    try:
        done = subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True, timeout=60)
    except OSError:
        pytest.skip("no git")
    if done.returncode != 0:
        pytest.skip("not a git checkout (an sdist)")
    return done.stdout.decode("utf-8", errors="replace")


def test_happy_every_text_file_is_lf():
    _git("rev-parse", "--git-dir")  # .gitattributes is not in an sdist
    lines = (ROOT / ".gitattributes").read_text(encoding="utf-8").splitlines()
    assert "* text=auto eol=lf" in lines


def test_happy_every_file_that_is_not_text_is_binary():
    names = [n for n in _git("ls-files", "-z").split("\0") if n]
    not_text = []
    for name in names:
        path = ROOT / name
        if path.is_file():
            try:
                path.read_bytes().decode("utf-8")
            except UnicodeDecodeError:
                not_text.append(name)
    assert not_text, "the tree has images, archives and audio: the scan found none"
    attrs = _git("check-attr", "binary", "--", *not_text)
    unset = [line.split(":")[0] for line in attrs.splitlines() if not line.endswith(": set")]
    assert unset == [], f"not marked binary in .gitattributes: {unset}"


def test_happy_no_tracked_text_file_has_crlf_in_the_index():
    eol = _git("ls-files", "--eol")
    assert [line for line in eol.splitlines() if line.startswith(("i/crlf", "i/mixed"))] == []
