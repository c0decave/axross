"""Third security review: axross's own code, run from a source folder (a
checkout, ``pip install -e``), could still be changed through new files.

The second review protected its packages, ``resources`` and the top-level
``*.py`` that existed when axross started. A *new* top-level module was
not: ``json.py`` or ``socks.py`` beside ``main.py`` (``python main.py``
puts that folder first on sys.path, before the standard library), a new
``PyQt6/__init__.py``, a module of a missing optional dependency as a
namespace package (``smbprotocol/connection.py``), or a crafted ``.pyc`` in
the folder's ``__pycache__`` (stamped with the source's mtime and size, it
is loaded instead of the source) - and the next start of axross ran it with
the user's rights. Now no Python code (``.py``, ``.pyc``, extension
modules) is written anywhere below that folder, and in the agent's sandbox
nothing new can be made at its top level.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core import protected_places as P  # noqa: E402


@pytest.mark.parametrize("rel", [
    "json.py", "socks.py", "PyQt6/__init__.py", "smbprotocol/connection.py",
    "__pycache__/main.cpython-311.pyc", "__pycache__/x", "fast.cpython-311-x86_64-linux-gnu.so",
    "docs/__init__.py", "Paramiko.PY",
])
def test_sad_new_code_in_the_source_folder_is_refused(rel):
    assert P.refusal(str(ROOT / rel)) is not None, rel


def test_happy_other_files_stay_writable():
    for rel in ("docs/some-notes.md", "notes.txt", "data/x.json"):
        assert P.refusal(str(ROOT / rel)) is None, rel


def test_happy_an_installed_axross_has_no_source_folder(monkeypatch):
    monkeypatch.setattr(P, "_own_base", lambda: os.path.join(os.sep, "x", "site-packages"))
    P.own_source_folder.cache_clear()
    try:
        assert P.own_source_folder() is None
    finally:
        monkeypatch.undo()
        P.own_source_folder.cache_clear()


def test_sad_the_sandbox_makes_nothing_new_at_the_source_folder_s_top(tmp_path, monkeypatch):
    """The source folder inside a writable mount is a frame: its entries are
    there, nothing new can be made beside them."""
    from core import agent_sandbox as S

    src = tmp_path / "axross-src"
    (src / "docs").mkdir(parents=True)
    (src / "main.py").write_text("")
    monkeypatch.setattr(P, "own_source_folder", lambda: str(src))
    profile = S.SandboxProfile(level="normal")
    mounts = {path: (rw, kind) for path, rw, kind in S._mount_plan(profile, str(tmp_path), True)}
    assert mounts[str(src)] == (False, "frame")
    assert mounts[str(src / "docs")][0] is True
