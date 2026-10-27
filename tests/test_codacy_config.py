"""The Codacy scan never meets a file it cannot read as text, and cannot hang
for hours.

Codacy Analysis CLI 7.9.25 writes its SARIF report by reading every file a
tool reported on as UTF-8 (Sarif.scala:149, Files.readAllLines). On the
first push of 0.14.101 its main thread died there with
"MalformedInputException: Input length = 1" and the process never exited:
the step ran 77 minutes until it was cancelled (the green runs before took
13-17). The tree's only files that are not UTF-8 are images and audio
fixtures, so .codacy.yml leaves out every such file - derived from
``git ls-files`` here, never typed in twice - and the job has a timeout.
"""

from __future__ import annotations

import fnmatch
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
CONFIG = ROOT / ".codacy.yml"
WORKFLOW = ROOT / ".github" / "workflows" / "codacy.yml"
#: The longest a scan took while it worked was 17 minutes.
MAX_MINUTES = 45


def excluded(path: str, patterns: list[str]) -> bool:
    """Whether *path* matches one of *patterns* the way Codacy's globs do:
    ``**/`` stands for any folders, none included."""
    for pattern in patterns:
        if fnmatch.fnmatchcase(path, pattern):
            return True
        if pattern.startswith("**/") and fnmatch.fnmatchcase(path, pattern[3:]):
            return True
    return False


def not_text(root: Path = ROOT) -> list[str]:
    """Tracked files that do not decode as UTF-8."""
    names = subprocess.run(["git", "-C", str(root), "ls-files", "-z"], capture_output=True,
                           check=True).stdout.decode("utf-8").split("\0")
    out = []
    for name in filter(None, names):
        path = root / name
        if not path.is_file():
            continue
        try:
            path.read_bytes().decode("utf-8")
        except UnicodeDecodeError:
            out.append(name)
    return out


def exclude_paths() -> list[str]:
    yaml = pytest.importorskip("yaml")
    return list((yaml.safe_load(CONFIG.read_text(encoding="utf-8")) or {}).get("exclude_paths")
                or [])


def test_happy_codacy_leaves_out_every_file_that_is_not_text():
    found = not_text()
    assert found, "the tree has images and audio fixtures: the scan above found none"
    patterns = exclude_paths()
    assert [p for p in found if not excluded(p, patterns)] == []


def test_happy_source_files_are_still_scanned():
    patterns = exclude_paths()
    for path in ("core/self_update.py", "ui/main_window.py", "main.py", "scripts/sign_release.py"):
        assert not excluded(path, patterns), path


def test_happy_the_scan_job_has_a_timeout():
    yaml = pytest.importorskip("yaml")
    job = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]["codacy-security-scan"]
    assert 0 < int(job["timeout-minutes"]) <= MAX_MINUTES


def test_sad_a_binary_file_outside_the_patterns_is_reported(tmp_path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / "a.py").write_text("x = 1\n")
    (tmp_path / "beep.aiff").write_bytes(b"FORM\xff\xfe\x00AIFF")
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    found = not_text(tmp_path)
    assert found == ["beep.aiff"]
    assert [p for p in found if not excluded(p, ["**/*.wav"])] == ["beep.aiff"]


def test_edge_double_star_matches_at_the_top_and_deep_down():
    assert excluded("x.png", ["**/*.png"])
    assert excluded("docs/screenshots/a/b.png", ["**/*.png"])
    assert not excluded("x.png.py", ["**/*.png"])
