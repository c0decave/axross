"""Checksum Manifest reads and writes names exactly as GNU sha256sum does.

The review found intact files reported as missing (OK 1 / Missing 3 on
four unchanged files): names were written unescaped, and reading stripped
the line (a name's trailing spaces went), stripped a leading ``*`` from the
name and turned every ``\\`` into ``/``. GNU's escaped lines
(``\\<hash>  a\\\\b`` for a name with a backslash or newline) were dropped
silently, as was every other line that did not parse - a damaged manifest
looked verified. Now the escaping is sha256sum's on both sides, a line is
split exactly at ``"  "`` (text) or ``" *"`` (binary), and lines that do not
parse are counted as errors.
"""

from __future__ import annotations

import hashlib
import importlib.util
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import extensions as EX  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

FS = LocalFS()
#: A backslash, trailing spaces, a leading star, a newline, a carriage return.
AWKWARD = ["plain.txt", "back\\slash.txt", "trailing space ", "*star.txt",
           "two\nlines", "cr\rname"]


def _load():
    path = EX.bundled_dir() / "checksum_manifest.py"
    spec = importlib.util.spec_from_file_location("checksum_manifest_names_ext", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CM = _load()


def _files(folder: Path, names) -> None:
    for name in names:
        (folder / name).write_text(f"content of {name!r}", encoding="utf-8")


def _sha(folder: Path, name: str) -> str:
    return hashlib.sha256((folder / name).read_bytes()).hexdigest()


def test_happy_awkward_names_verify_from_axross_own_manifest(tmp_path):
    _files(tmp_path, AWKWARD)
    text = CM.manifest_text(FS, str(tmp_path), AWKWARD)
    result = CM.verify(FS, str(tmp_path), text)
    assert sorted(result["ok"]) == sorted(AWKWARD)
    assert result["failed"] == result["missing"] == result["errors"] == []


def test_happy_written_lines_are_what_sha256sum_writes(tmp_path):
    _files(tmp_path, AWKWARD)
    text = CM.manifest_text(FS, str(tmp_path), AWKWARD)
    lines = text.split("\n")
    escaped = "\\" + _sha(tmp_path, "back\\slash.txt") + "  back\\\\slash.txt"
    assert escaped in lines
    assert "\\" + _sha(tmp_path, "two\nlines") + "  two\\nlines" in lines
    assert "\\" + _sha(tmp_path, "cr\rname") + "  cr\\rname" in lines
    assert _sha(tmp_path, "trailing space ") + "  trailing space " in lines
    assert _sha(tmp_path, "*star.txt") + "  *star.txt" in lines


@pytest.mark.skipif(shutil.which("sha256sum") is None, reason="no GNU sha256sum here")
def test_happy_a_manifest_written_by_gnu_sha256sum_verifies(tmp_path):
    _files(tmp_path, AWKWARD)
    gnu = subprocess.run(["sha256sum", "--", *AWKWARD], cwd=tmp_path, capture_output=True,
                         check=True).stdout.decode("utf-8")
    result = CM.verify(FS, str(tmp_path), gnu)
    assert sorted(result["ok"]) == sorted(AWKWARD)
    assert result["missing"] == result["errors"] == []


@pytest.mark.skipif(shutil.which("sha256sum") is None, reason="no GNU sha256sum here")
def test_happy_gnu_sha256sum_checks_the_manifest_axross_wrote(tmp_path):
    _files(tmp_path, AWKWARD)
    (tmp_path / "SHA256SUMS").write_text(CM.manifest_text(FS, str(tmp_path), AWKWARD),
                                         encoding="utf-8")
    check = subprocess.run(["sha256sum", "-c", "--strict", "SHA256SUMS"], cwd=tmp_path,
                           capture_output=True)
    assert check.returncode == 0, check.stdout + check.stderr


def test_sad_lines_that_do_not_parse_are_counted_not_dropped(tmp_path):
    _files(tmp_path, ["ok.txt"])
    good = _sha(tmp_path, "ok.txt")
    text = "\n".join([
        f"{good}  ok.txt",
        "garbage",
        f"{good} ok.txt",            # one space: neither text nor binary mode
        "zz" * 32 + "  nothex.txt",
        f"\\{good}  bad\\qescape",   # an escape sha256sum does not know
        f"{good}  ../outside.txt",   # leaves the folder
        "",
    ]) + "\n"
    result = CM.verify(FS, str(tmp_path), text)
    assert result["ok"] == ["ok.txt"]
    assert result["errors"] == ["line 2", "line 3", "line 4", "line 5", "line 6"]


def test_edge_binary_mode_and_crlf_line_ends_parse(tmp_path):
    good = "a" * 64
    assert CM.parse_line(f"{good} *bin.dat") == (good, "bin.dat")
    assert CM.parse_line(f"{good}  win.txt\r") == (good, "win.txt")
    assert CM.parse_line(f"{good.upper()}  upper.txt") == (good, "upper.txt")
    assert CM.parse_line(f"{good}  **two") == (good, "**two")


def test_edge_a_path_below_the_folder_is_verified_there(tmp_path):
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "x.txt").write_text("x")
    text = f"{_sha(tmp_path, 'sub/x.txt')}  sub/x.txt\n"
    assert CM.verify(FS, str(tmp_path), text) == {"ok": ["sub/x.txt"], "failed": [],
                                                  "missing": [], "errors": []}


def test_edge_an_empty_manifest_has_nothing_and_no_errors():
    assert CM.read_manifest("") == ([], [])
    assert CM.read_manifest("\n\n") == ([], [])
