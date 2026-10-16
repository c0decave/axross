"""Fuzz: the Git backend against a corrupt object store.

A remote's objects land in the local cache repository as they were sent,
so a hostile remote controls the bytes dulwich decodes. A small repository
is built, then copies of it get one loose object (commit, tree or blob)
mutated - flipped bits, truncation, garbage, a wrong header - and the
read surface runs on each copy. Every call returns sane data or raises
OSError (dulwich's own errors and zlib.error are neither).
"""

from __future__ import annotations

import random
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

pytest.importorskip("dulwich")
from dulwich import porcelain  # noqa: E402
from fuzz_testkit import check_contract, iterations, mutate  # noqa: E402

from core.git_fs_client import GitFsSession  # noqa: E402


@pytest.fixture(scope="module")
def pristine():
    tmp = Path(tempfile.mkdtemp())
    repo_dir = tmp / "repo"
    repo = porcelain.init(str(repo_dir))
    repo.refs.set_symbolic_ref(b"HEAD", b"refs/heads/main")
    (repo_dir / "a.txt").write_bytes(b"hello\n")
    (repo_dir / "sub").mkdir()
    (repo_dir / "sub" / "b.bin").write_bytes(bytes(range(256)))
    porcelain.add(str(repo_dir), paths=[str(repo_dir / "a.txt"), str(repo_dir / "sub" / "b.bin")])
    # Fixed times: the same objects (and so the same mutants) every run.
    porcelain.commit(
        str(repo_dir),
        message=b"init",
        author=b"t <t@t>",
        committer=b"t <t@t>",
        author_timestamp=1_700_000_000,
        author_timezone=0,
        commit_timestamp=1_700_000_000,
        commit_timezone=0,
    )
    repo.close()
    try:
        yield repo_dir
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _objects(repo_dir: Path) -> list[Path]:
    return sorted(p for p in (repo_dir / ".git" / "objects").glob("??/*") if p.is_file())


def _ops(s):
    return {
        "list_root": lambda: s.list_dir("/"),
        "list_branch": lambda: s.list_dir("/main"),
        "list_sub": lambda: s.list_dir("/main/sub"),
        "stat": lambda: s.stat("/main/a.txt"),
        "is_dir": lambda: s.is_dir("/main/sub"),
        "exists": lambda: s.exists("/main/a.txt"),
        "open_read": lambda: s.open_read("/main/a.txt").read(),
    }


def test_happy_repository_reads(pristine):
    s = GitFsSession(path=str(pristine), default_branch="main")
    assert "main" in {i.name for i in s.list_dir("/")}
    assert {i.name for i in s.list_dir("/main")} == {"a.txt", "sub"}
    assert s.open_read("/main/a.txt").read() == b"hello\n"


def test_sad_corrupt_objects(pristine):
    rng = random.Random(0x474954)
    objects = _objects(pristine)
    assert len(objects) >= 4  # commit, two trees, two blobs
    work = Path(tempfile.mkdtemp())
    try:
        for n in range(iterations(40)):
            copy = work / f"r{n}"
            shutil.copytree(pristine, copy)
            target = _objects(copy)[rng.randrange(len(objects))]
            data = target.read_bytes()
            target.chmod(0o644)
            target.write_bytes(
                rng.choice([mutate(data, rng), b"", b"garbage", data[: len(data) // 2]])
            )

            def run(copy=copy, n=n, target=target):
                s = GitFsSession(path=str(copy), default_branch="main")
                for name, op in _ops(s).items():
                    check_contract(
                        op, (OSError,), timeout=20.0, context=f"{n} {target.name} {name}"
                    )

            check_contract(run, (OSError,), timeout=60.0, context=f"case {n}")
            shutil.rmtree(copy, ignore_errors=True)
    finally:
        shutil.rmtree(work, ignore_errors=True)
