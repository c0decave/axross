"""The Backup Repositories extension against REAL borg and duplicity (opt-in).

tests/test_backup_repos_extension.py checks the Borg and duplicity unlock
paths with stub binaries, because neither tool is on the development host.
This file makes small encrypted repositories with the real tools (a known
passphrase each), then runs the extension's own code - detect, basic_info
(through LocalFS, as the pane does) and unlock (the real command lines:
``borg list --json --bypass-lock``, ``duplicity collection-status``) - and
compares the answers with what the tools themselves report.

Skipped unless ``AXROSS_BACKUP_LIVE=1`` and the binaries are installed.
``scripts/backup_repos_live.sh`` runs it in a disposable podman container
(packages fetched at build time; the test itself with --network=none and the
tree mounted read-only).
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.local_fs import LocalFS  # noqa: E402

LIVE = os.environ.get("AXROSS_BACKUP_LIVE") == "1"
BORG = shutil.which("borg")
DUPLICITY = shutil.which("duplicity")

pytestmark = pytest.mark.skipif(
    not LIVE, reason="opt-in: AXROSS_BACKUP_LIVE=1 (scripts/backup_repos_live.sh)"
)
needs_borg = pytest.mark.skipif(BORG is None, reason="borg is not installed")
needs_duplicity = pytest.mark.skipif(DUPLICITY is None, reason="duplicity is not installed")

FS = LocalFS()


def _load():
    path = Path(__file__).resolve().parents[1] / "resources" / "extensions" / "backup_repos.py"
    spec = importlib.util.spec_from_file_location("live_backup_repos", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


BR = _load()


def _sh(argv, env) -> str:
    proc = subprocess.run(argv, env={**os.environ, **env}, capture_output=True, text=True,
                          stdin=subprocess.DEVNULL, timeout=300, check=False)
    assert proc.returncode == 0, (argv, proc.stderr[-800:])
    return proc.stdout


@pytest.fixture
def src(tmp_path) -> Path:
    folder = tmp_path / "src"
    folder.mkdir()
    (folder / "a.txt").write_text("hello")
    return folder


@pytest.fixture
def own_home(tmp_path, monkeypatch) -> Path:
    # borg keeps its security dir and cache under HOME / BORG_BASE_DIR;
    # unlock() runs with this process's environment.
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("BORG_BASE_DIR", str(home / "borg-base"))
    monkeypatch.delenv("BORG_KEYS_DIR", raising=False)
    return home


def _borg_repo(tmp_path, src, encryption: str, passphrase: str, names, keys_dir=None):
    repo = tmp_path / f"borg-{encryption}"
    env = {"BORG_PASSPHRASE": passphrase, "BORG_BASE_DIR": str(tmp_path / f"base-{encryption}")}
    if keys_dir is not None:
        env["BORG_KEYS_DIR"] = str(keys_dir)
    _sh([BORG, "init", f"--encryption={encryption}", str(repo)], env)
    for name in names:
        _sh([BORG, "create", f"{repo}::{name}", str(src)], env)
    truth = json.loads(_sh([BORG, "list", "--json", str(repo)], env))["archives"]
    return repo, truth


def _dup_repo(tmp_path, src, passphrase: str):
    target = tmp_path / "dup"
    home = tmp_path / "dup-home"  # gpg keeps its ~/.gnupg here
    home.mkdir()
    env = {"PASSPHRASE": passphrase, "HOME": str(home)}
    common = ["--volsize", "1", "--archive-dir", str(tmp_path / "dup-cache")]
    _sh([DUPLICITY, "full", *common, str(src), f"file://{target}"], env)
    (src / "b.txt").write_text("more")
    _sh([DUPLICITY, "incremental", *common, str(src), f"file://{target}"], env)
    return target


# -- happy ------------------------------------------------------------------------------


@needs_borg
def test_happy_real_borg_repokey_basic_info_and_unlock(tmp_path, src, own_home):
    repo, truth = _borg_repo(tmp_path, src, "repokey", "borg pass 1", ("monday", "tuesday"))
    print("borg", _sh([BORG, "--version"], {}).strip())
    assert BR.detect(FS, str(repo)) == "borg"
    info = BR.basic_info(FS, str(repo))
    facts = dict(info.facts)
    print("borg facts", facts)
    assert facts["Version"] == "1"
    assert facts["Key"] == "in the repository (repokey)" and not info.needs_keyfile
    assert int(facts["Segments"]) >= 1
    snaps = BR.unlock("borg", str(repo), "borg pass 1")
    print("borg archives", [(s.id, s.time, s.note) for s in snaps])
    assert [s.id for s in snaps] == [a["name"] for a in truth] == ["monday", "tuesday"]
    assert all(s.time and s.note for s in snaps)
    assert [s.note for s in snaps] == [a["id"][:16] for a in truth]


@needs_duplicity
def test_happy_real_duplicity_chain_and_collection_status(tmp_path, src, own_home):
    target = _dup_repo(tmp_path, src, "dup pass 3")
    print("duplicity", _sh([DUPLICITY, "--version"], {}).strip())
    assert BR.detect(FS, str(target)) == "duplicity"
    info = BR.basic_info(FS, str(target))
    facts = dict(info.facts)
    print("duplicity facts", facts, [(s.id, s.note) for s in info.snapshots])
    assert facts["Backup chains"] == "1"
    assert facts["Encryption"] == "GnuPG"
    assert [s.id.split()[0] for s in info.snapshots] == ["full", "inc"]
    snaps = BR.unlock("duplicity", str(target), "dup pass 3")
    print("duplicity status", [(s.id, s.time, s.note) for s in snaps])
    assert [s.id for s in snaps] == ["Full", "Incremental"]
    assert all(s.time and s.note.endswith("volume(s)") for s in snaps)


# -- sad --------------------------------------------------------------------------------


@needs_borg
def test_sad_real_borg_wrong_passphrase_is_a_repo_error(tmp_path, src, own_home):
    repo, _truth = _borg_repo(tmp_path, src, "repokey", "right", ("one",))
    with pytest.raises(BR.RepoError) as caught:
        BR.unlock("borg", str(repo), "wrong")
    print("borg wrong passphrase ->", caught.value)
    assert str(caught.value)


@needs_duplicity
def test_sad_real_duplicity_wrong_passphrase_is_a_repo_error(tmp_path, src, own_home):
    target = _dup_repo(tmp_path, src, "right")
    # collection-status alone exits 0 with a wrong passphrase (it reads only
    # the file names); the extension decrypts the newest manifest first.
    with pytest.raises(BR.RepoError, match="password does not open") as caught:
        BR.unlock("duplicity", str(target), "wrong")
    print("duplicity wrong passphrase ->", caught.value)


@needs_duplicity
def test_edge_real_duplicity_a_cached_right_passphrase_does_not_hide_a_wrong_one(
    tmp_path, src, own_home
):
    target = _dup_repo(tmp_path, src, "right")
    assert [s.id for s in BR.unlock("duplicity", str(target), "right")] == ["Full", "Incremental"]
    with pytest.raises(BR.RepoError, match="password does not open"):
        BR.unlock("duplicity", str(target), "wrong")


# -- edge -------------------------------------------------------------------------------


@needs_borg
def test_edge_real_borg_keyfile_mode_needs_and_takes_the_key(tmp_path, src, own_home):
    keys = tmp_path / "keys"
    repo, truth = _borg_repo(tmp_path, src, "keyfile", "borg pass 2", ("only",), keys_dir=keys)
    info = BR.basic_info(FS, str(repo))
    assert info.needs_keyfile
    (keyfile,) = list(keys.iterdir())
    snaps = BR.unlock("borg", str(repo), "borg pass 2", str(keyfile))
    assert [s.id for s in snaps] == [a["name"] for a in truth] == ["only"]


@needs_borg
def test_edge_real_borg_unencrypted_repo_lists_without_a_prompt(tmp_path, src, own_home):
    repo, truth = _borg_repo(tmp_path, src, "none", "", ("plain",))
    snaps = BR.unlock("borg", str(repo), "")
    assert [s.id for s in snaps] == [a["name"] for a in truth] == ["plain"]
