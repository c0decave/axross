"""scripts/build_release.sh packages the committed public tree, nothing else.

It used to collect ``git ls-files -co``: every untracked file of the work
tree (an operator's notes among them) was a candidate, and in the private
repo it re-scrubbed the unscrubbed tree with a deny list of its own, so a
tracked internal document or the scrub tooling failed every run. Now:

* in the public mirror checkout the tree is ``git archive HEAD``;
* in the private repo (``scripts/export-public.py`` present) it is what
  ``export-public.py --mirror --apply`` writes into a temp dir, and the
  exclude list is that script's ``MIRROR_EXCLUDE_PREFIXES``;
* the identity terms come from a file outside the repository.

Each test builds a small git repository and runs the real script in it.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "build_release.sh"

pytestmark = pytest.mark.skipif(
    shutil.which("bash") is None or shutil.which("git") is None,
    reason="needs bash and git",
)

REQUIRED = (
    "LICENSE", "NOTICE", "THIRD_PARTY_LICENSES.md", "README.md", "README_de.md",
    "README_es.md", "CONTRIBUTING.md", "SECURITY.md", "INSTALL.md", "OAUTH_SETUP.md",
    "main.py", "core/__init__.py", "core/client_identity.py", "docs/USAGE.md",
    "docs/USAGE_de.md", "docs/USAGE_es.md", "docs/DEVELOPMENT.md", "docs/OPSEC.md",
)

PYPROJECT = (
    '[project]\nname = "axross"\ndynamic = ["version"]\n'
    '[tool.setuptools.dynamic]\nversion = { attr = "axross._version.__version__" }\n'
)

#: A stand-in for scripts/export-public.py: writes HEAD's tracked files minus
#: MIRROR_EXCLUDE_PREFIXES (or, with LEAK, all of them) to --target.
STUB_EXPORT = textwrap.dedent('''\
    import subprocess, sys
    from pathlib import Path

    MIRROR_EXCLUDE_PREFIXES = (
        "docs/BACKLOG.md",
        "scripts/export-public.py",
        "tools/internal_",
    )
    LEAK = False

    def main():
        target = Path(sys.argv[sys.argv.index("--target") + 1])
        names = subprocess.run(["git", "ls-tree", "-r", "-z", "--name-only", "HEAD"],
                               capture_output=True, check=True).stdout.decode().split("\\0")
        for rel in filter(None, names):
            if not LEAK and any(rel.startswith(e) for e in MIRROR_EXCLUDE_PREFIXES):
                continue
            data = subprocess.run(["git", "show", "HEAD:" + rel],
                                  capture_output=True, check=True).stdout
            (target / rel).parent.mkdir(parents=True, exist_ok=True)
            (target / rel).write_bytes(data)
        (target / ".gitignore").write_text("__pycache__/\\n")
        return 0

    if __name__ == "__main__":
        sys.exit(main())
''')


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@localhost", "-c",
         "commit.gpgsign=false", *args],
        cwd=repo, check=True, capture_output=True,
    )


def _repo(tmp_path: Path, extra: dict[str, str] | None = None) -> Path:
    repo = tmp_path / "repo"
    files = {name: f"{name}\n" for name in REQUIRED}
    files["pyproject.toml"] = PYPROJECT
    files["axross/_version.py"] = '__version__ = "9.8.7"\n'
    files.update(extra or {})
    for rel, text in files.items():
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_text(text, encoding="utf-8")
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "init")
    return repo


def _terms(tmp_path: Path, *terms: str) -> Path:
    path = tmp_path / "config" / "identity-terms"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("# private\n" + "".join(t + "\n" for t in terms), encoding="utf-8")
    return path


def _run(repo: Path, tmp_path: Path, *args: str, terms: Path | None = None,
         env_extra: dict[str, str] | None = None) -> tuple[subprocess.CompletedProcess, list[str]]:
    listing = tmp_path / "list.txt"
    env = {k: v for k, v in os.environ.items() if not k.startswith("AXROSS_")}
    env["XDG_CONFIG_HOME"] = str(tmp_path / "xdg")
    env["AXROSS_RELEASE_LIST"] = str(listing)
    if terms is not None:
        env["AXROSS_IDENTITY_TERMS_FILE"] = str(terms)
    env.update(env_extra or {})
    done = subprocess.run(
        ["bash", str(SCRIPT), *args, str(tmp_path / "out")],
        cwd=repo, env=env, capture_output=True, text=True, timeout=300, check=False,
    )
    files = listing.read_text(encoding="utf-8").splitlines() if listing.exists() else []
    return done, files


def _untracked_and_dirty(repo: Path) -> None:
    (repo / "neue-dinge.txt").write_text("operator note\n", encoding="utf-8")
    (repo / "docs" / "HANDOFF.md").write_text("handoff\n", encoding="utf-8")
    (repo / "README.md").write_text("uncommitted edit\n", encoding="utf-8")


def test_happy_the_mirror_dry_run_lists_the_committed_files_only(tmp_path) -> None:
    repo = _repo(tmp_path)
    _untracked_and_dirty(repo)
    done, files = _run(repo, tmp_path, "--dry-run", terms=_terms(tmp_path, "zzqq-term"))
    assert done.returncode == 0, done.stdout + done.stderr
    assert "git archive HEAD" in done.stdout
    assert sorted(files) == sorted([*REQUIRED, "pyproject.toml", "axross/_version.py"])
    assert not (tmp_path / "out").exists()


def test_happy_a_live_run_ships_head_not_the_work_tree(tmp_path) -> None:
    repo = _repo(tmp_path)
    _untracked_and_dirty(repo)
    done, _ = _run(repo, tmp_path, terms=_terms(tmp_path, "zzqq-term"))
    assert done.returncode == 0, done.stdout + done.stderr
    out = tmp_path / "out"
    assert not (out / "neue-dinge.txt").exists()
    assert not (out / "docs" / "HANDOFF.md").exists()
    assert (out / "README.md").read_text(encoding="utf-8") == "README.md\n"
    assert "version:   9.8.7" in (out / ".release-info").read_text(encoding="utf-8")


def test_happy_the_private_tree_is_packaged_through_export_public(tmp_path) -> None:
    repo = _repo(tmp_path, {
        "scripts/export-public.py": STUB_EXPORT,
        "docs/BACKLOG.md": "internal\n",
        "tools/internal_x.py": "internal\n",
    })
    _untracked_and_dirty(repo)
    done, files = _run(repo, tmp_path, "--dry-run", terms=_terms(tmp_path, "zzqq-term"))
    assert done.returncode == 0, done.stdout + done.stderr
    assert "export-public.py --mirror" in done.stdout
    assert "3 MIRROR_EXCLUDE_PREFIXES entries" in done.stdout
    assert ".gitignore" in files
    for private in ("docs/BACKLOG.md", "scripts/export-public.py", "tools/internal_x.py",
                    "neue-dinge.txt", "docs/HANDOFF.md"):
        assert private not in files


def test_sad_an_excluded_file_the_export_lets_through_is_refused(tmp_path) -> None:
    repo = _repo(tmp_path, {
        "scripts/export-public.py": STUB_EXPORT.replace("LEAK = False", "LEAK = True"),
        "docs/BACKLOG.md": "internal\n",
    })
    done, _ = _run(repo, tmp_path, "--dry-run", terms=_terms(tmp_path, "zzqq-term"))
    assert done.returncode == 3, done.stdout + done.stderr
    assert "mirror-excluded path in candidate set: docs/BACKLOG.md" in done.stdout + done.stderr


def test_sad_an_identity_term_in_a_committed_file_is_refused(tmp_path) -> None:
    repo = _repo(tmp_path, {"docs/notes.md": "written by Zzqq Person\n"})
    done, _ = _run(repo, tmp_path, "--dry-run", terms=_terms(tmp_path, "Zzqq Person"))
    assert done.returncode == 3, done.stdout + done.stderr
    assert "docs/notes.md:1:" in done.stdout + done.stderr


def test_sad_without_a_terms_file_the_build_refuses(tmp_path) -> None:
    repo = _repo(tmp_path)
    done, _ = _run(repo, tmp_path, "--dry-run")
    assert done.returncode == 2, done.stdout + done.stderr
    assert str(tmp_path / "xdg" / "axross" / "release-identity-terms") in done.stdout + done.stderr


def test_happy_the_default_terms_file_lies_outside_the_repo(tmp_path) -> None:
    repo = _repo(tmp_path)
    default = tmp_path / "xdg" / "axross" / "release-identity-terms"
    default.parent.mkdir(parents=True)
    default.write_text("zzqq-term\n", encoding="utf-8")
    done, _ = _run(repo, tmp_path, "--dry-run")
    assert done.returncode == 0, done.stdout + done.stderr


def test_sad_a_terms_file_inside_the_repo_is_refused(tmp_path) -> None:
    repo = _repo(tmp_path)
    inside = repo / ".release-identity-terms"
    inside.write_text("zzqq-term\n", encoding="utf-8")
    done, _ = _run(repo, tmp_path, "--dry-run", terms=inside)
    assert done.returncode == 2, done.stdout + done.stderr
    assert "inside the repository" in done.stdout + done.stderr


def test_happy_the_script_keeps_no_copy_of_the_exclude_list() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert "DENY_PATHS" not in text
    assert "docs/BACKLOG.md" not in text
    assert "ls-files -z -co" not in text
