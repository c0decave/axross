"""axross-headless-mcp is axross's export and nothing else (scripts/headless_release.py).

Before: the repository c0decave/axross-headless-mcp was written by hand-run
exports; nothing told an export from a hand edit, the release step did not
commit and tag it with the PyPI package, and nothing checked that its GitHub
release carries what PyPI carries. Now ``sync`` commits the very tree the
package was built from with a trailer naming its public axross ref (and tags
it), the repository's workflow ``drift.yml`` exports again from that ref and
fails on any difference, and ``compare-dists`` holds the GitHub release's
sdist and wheel against PyPI's by content."""

from __future__ import annotations

import ast
import io
import os
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import headless_release as HR  # noqa: E402

STUB = '''\
import sys
from pathlib import Path
out = Path(sys.argv[2])
(out / "src").mkdir(parents=True)
(out / "pyproject.toml").write_text('[project]\\nname = "axross-headless-mcp"\\nversion = "1.2.3"\\n')
(out / "README.md").write_text("exported\\n")
(out / "src" / "tool.py").write_text(Path(__file__).with_name("payload.txt").read_text())
'''


@pytest.fixture(autouse=True)
def _identity(monkeypatch):
    for key, value in (("GIT_AUTHOR_NAME", "t"), ("GIT_AUTHOR_EMAIL", "t@example.invalid"),
                       ("GIT_COMMITTER_NAME", "t"), ("GIT_COMMITTER_EMAIL", "t@example.invalid")):
        monkeypatch.setenv(key, value)


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True,
                          text=True).stdout


def _axross(tmp_path: Path, payload: str = "print('v1')\n") -> Path:
    repo = tmp_path / "axross"
    (repo / "scripts").mkdir(parents=True)
    (repo / "scripts" / "export_standalone.py").write_text(STUB)
    (repo / "scripts" / "payload.txt").write_text(payload)
    _git(repo.parent, "init", "-q", str(repo))
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "axross")
    _git(repo, "tag", "v1.2.3")
    return repo


def _headless(tmp_path: Path) -> Path:
    repo = tmp_path / "headless"
    repo.mkdir()
    _git(tmp_path, "init", "-q", str(repo))
    (repo / "old.txt").write_text("from before\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "first")
    return repo


def _synced(tmp_path: Path, tag: bool = True):
    axross = _axross(tmp_path)
    headless = _headless(tmp_path)
    tree = HR.export(axross, tmp_path / "export")
    commit = HR.sync(headless, tree, "v1.2.3", tag=tag)
    return axross, headless, commit


def test_happy_sync_commits_the_exported_tree_with_its_source_and_tags_it(tmp_path):
    _axross_repo, headless, commit = _synced(tmp_path)
    assert sorted(_git(headless, "ls-files").split()) == ["README.md", "pyproject.toml",
                                                          "src/tool.py"]
    assert HR.source_of(headless) == "v1.2.3"
    assert "Exported-From: c0decave/axross@v1.2.3" in _git(headless, "log", "-1", "--format=%B")
    assert _git(headless, "rev-parse", "v1.2.3^{commit}").strip() == commit


def test_happy_check_finds_the_commit_identical_to_a_fresh_export(tmp_path):
    axross, headless, _commit = _synced(tmp_path)
    assert HR.check(headless, axross) == []


def test_sad_a_hand_edit_is_found_even_with_a_copied_trailer(tmp_path):
    axross, headless, _commit = _synced(tmp_path)
    (headless / "README.md").write_text("edited by hand\n")
    (headless / "extra.txt").write_text("x\n")
    _git(headless, "add", "-A")
    _git(headless, "commit", "-q", "-m", "hand", "-m", "Exported-From: c0decave/axross@v1.2.3")
    assert HR.check(headless, axross) == ["not in the export: extra.txt", "differs: README.md"]


def test_sad_a_commit_without_a_source_is_refused(tmp_path):
    axross = _axross(tmp_path)
    headless = _headless(tmp_path)
    with pytest.raises(HR.ReleaseError, match="by hand"):
        HR.check(headless, axross)


def test_sad_a_checkout_of_another_ref_is_refused_unless_the_guard_made_it(tmp_path):
    axross, headless, _commit = _synced(tmp_path)
    (axross / "scripts" / "payload.txt").write_text("print('v2')\n")
    _git(axross, "commit", "-q", "-am", "later")
    with pytest.raises(HR.ReleaseError, match="names v1.2.3"):
        HR.check(headless, axross)
    # The guard's checkout is the named ref by construction; a later tree
    # then shows as a difference, not as a refusal.
    assert HR.check(headless, axross, checked_out=True) == ["differs: src/tool.py"]


def test_sad_sync_refuses_a_repository_with_changes_of_its_own(tmp_path):
    axross = _axross(tmp_path)
    headless = _headless(tmp_path)
    (headless / "old.txt").write_text("changed\n")
    with pytest.raises(HR.ReleaseError, match="uncommitted"):
        HR.sync(headless, HR.export(axross, tmp_path / "export"), "v1.2.3", tag=False)


def _wheel(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buf.getvalue()


def _sdist(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in files.items():
            info = tarfile.TarInfo(f"axross_headless_mcp-1.2.3/{name}")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def test_happy_two_builds_of_one_tree_have_the_same_content():
    a = {"pkg/x.py": b"x", "pkg-1.2.3.dist-info/WHEEL": b"Wheel-Version: 1.0\nGenerator: setuptools (80.1)\n"}
    b = {"pkg/x.py": b"x", "pkg-1.2.3.dist-info/WHEEL": b"Wheel-Version: 1.0\nGenerator: setuptools (80.9)\n"}
    assert HR.differences(HR._archive_files("p.whl", _wheel(a)),
                          HR._archive_files("p.whl", _wheel(b))) == []
    assert HR.differences(HR._archive_files("p.tar.gz", _sdist({"a.py": b"1"})),
                          HR._archive_files("p.tar.gz", _sdist({"a.py": b"1"}))) == []


def test_sad_another_file_content_is_a_difference():
    found = HR.differences(HR._archive_files("p.tar.gz", _sdist({"a.py": b"1", "b.py": b"2"})),
                           HR._archive_files("p.tar.gz", _sdist({"a.py": b"changed"})))
    assert found == ["missing: b.py", "differs: a.py"]


def test_happy_the_export_carries_the_drift_guard_and_the_script_needs_no_packages(tmp_path):
    sys.path.insert(0, str(ROOT))
    import export_standalone as EXP

    out = EXP.export("mcp", tmp_path / "mcp")
    guard = (out / ".github" / "workflows" / "drift.yml").read_text(encoding="utf-8")
    assert "scripts/headless_release.py check --repo . --axross .axross-source --checked-out" in guard
    assert "Exported-From" in guard and "repository: c0decave/axross" in guard
    for line in guard.splitlines():
        if line.strip().startswith("- uses:") or line.strip().startswith("uses:"):
            assert "@" in line and len(line.split("@", 1)[1].split()[0]) == 40, line
    tree = ast.parse((ROOT / "scripts" / "headless_release.py").read_text(encoding="utf-8"))
    imported = {(n.module or "").split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    imported |= {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import)
                 for a in n.names}
    assert imported <= set(sys.stdlib_module_names) | {"__future__"}, imported
    assert os.access(ROOT / "scripts" / "headless_release.py", os.R_OK)
