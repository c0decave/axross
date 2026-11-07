"""core.archive imports py7zr at its first 7z use, not with the module.

py7zr pulls in Cryptodome, cffi and pycparser: about 70 % of core.archive's
import time (-X importtime: py7zr 1.36 s of 1.95 s on a loaded host). The
file pane imports core.archive at the first double-click on any file and
Find Files imports it through core.file_search - both on the GUI thread,
so the first double-click on a text file held the window for py7zr.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path
from unittest import mock

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core import archive as A  # noqa: E402


def _run(code: str) -> str:
    env = dict(os.environ, PYTHONPATH=str(ROOT), QT_QPA_PLATFORM="offscreen")
    out = subprocess.run([sys.executable, "-c", textwrap.dedent(code)], capture_output=True,
                         text=True, env=env, cwd=str(ROOT), timeout=120)
    assert out.returncode == 0, out.stderr
    return out.stdout.strip().splitlines()[-1]


def test_happy_importing_the_archive_module_leaves_py7zr_alone():
    """Neither core.archive nor core.file_search (Find Files) imports
    py7zr; the module still knows whether 7z archives can be read."""
    got = _run(
        """
        import importlib.util, sys
        import core.archive, core.file_search
        print("py7zr" in sys.modules,
              core.archive.SEVEN_Z_AVAILABLE == (importlib.util.find_spec("py7zr") is not None))
        """
    )
    assert got == "False True"


def test_happy_a_7z_archive_is_listed_and_extracted_after_the_lazy_import(tmp_path):
    py7zr = pytest.importorskip("py7zr")
    payload = tmp_path / "payload"
    payload.mkdir()
    (payload / "a.txt").write_bytes(b"seven")
    src = tmp_path / "pkg.7z"
    with py7zr.SevenZipFile(src, "w") as sz:
        sz.write(payload / "a.txt", "a.txt")
    with mock.patch.object(A, "py7zr", None):
        names = {e.name.rstrip("/") for e in A.list_archive(str(src))}
        assert "a.txt" in names
        target = tmp_path / "out"
        A.extract(str(src), str(target))
        assert (target / "a.txt").read_bytes() == b"seven"
    assert A.is_supported_archive("pkg.7z")


def test_sad_a_py7zr_that_cannot_be_imported_is_a_sentence(tmp_path, monkeypatch):
    """Installed (find_spec) but broken: the listing says what is missing
    instead of an ImportError traceback, and 7z is no longer offered."""
    import builtins

    real_import = builtins.__import__

    def failing(name, *args, **kwargs):
        if name == "py7zr":
            raise ImportError("No module named 'Cryptodome'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(A, "py7zr", None)
    monkeypatch.setattr(A, "SEVEN_Z_AVAILABLE", True)
    monkeypatch.setattr(builtins, "__import__", failing)
    dummy = tmp_path / "x.7z"
    dummy.write_bytes(b"7z\xbc\xaf\x27\x1c")
    with pytest.raises(A.UnsafeArchive, match="requires py7zr"):
        A.list_archive(str(dummy))
    assert A.SEVEN_Z_AVAILABLE is False


def test_edge_the_module_is_imported_once():
    """A second use takes the module already imported."""
    pytest.importorskip("py7zr")
    first = A._seven_zip("7z listing")
    assert A._seven_zip("7z listing") is first
