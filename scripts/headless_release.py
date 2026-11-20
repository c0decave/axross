#!/usr/bin/env python3
"""The repository c0decave/axross-headless-mcp is axross's export, nothing else.

Every commit there is the tree ``scripts/export_standalone.py mcp`` wrote from a
public axross ref, and names that ref in a trailer
``Exported-From: c0decave/axross@<tag or commit>``. Nothing is committed there
by hand: a fix or a feature goes into axross and reaches the repository with
the next export.

``sync``   - in the release step that builds the PyPI package (docs/PACKAGING.md,
             release flow step 10): replace the repository's files by the
             exported tree the package was built from, commit with the trailer
             and tag ``vVERSION`` - so the tag's tree is the PyPI package's source.
             Pushing stays with the maintainer.
``check``  - the drift guard (the repository's workflow ``drift.yml``, and any
             maintainer): export again from the named axross ref and compare
             with the commit, file by file.
``compare-dists`` - the sdist and wheel of the repository's GitHub release
             against PyPI's: the same files with the same content (built
             separately, so not byte-identical archives).

Standard library only: the drift guard runs it on a bare runner.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import urllib.request
import zipfile
from pathlib import Path

TRAILER = "Exported-From"
SOURCE_REPO = "c0decave/axross"
HEADLESS_REPO = "c0decave/axross-headless-mcp"
DIST = "axross-headless-mcp"
#: Lines of a wheel's or sdist's metadata that name the build tool, not the
#: content: they may differ between two builds of the same tree.
_TOOL_LINES = ("Generator:",)


class ReleaseError(RuntimeError):
    """What went wrong, in one sentence for the maintainer or the CI log."""


def _git(repo: Path, *args: str, text: bool = True):
    out = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, check=False)
    if out.returncode:
        raise ReleaseError(f"git {' '.join(args)} in {repo}: "
                           f"{out.stderr.decode('utf-8', 'replace').strip()}")
    return out.stdout.decode("utf-8") if text else out.stdout


def _version(tree: Path) -> str:
    return tomllib.loads((tree / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]


def source_of(repo: Path, ref: str = "HEAD") -> str:
    """The axross ref the commit *ref* of the repository was exported from."""
    values = _git(repo, "log", "-1", f"--format=%(trailers:key={TRAILER},valueonly)", ref)
    for line in values.splitlines():
        line = line.strip()
        if line.startswith(f"{SOURCE_REPO}@") and len(line) > len(SOURCE_REPO) + 1:
            return line[len(SOURCE_REPO) + 1:]
    raise ReleaseError(
        f"commit {ref} of the repository names no axross source ({TRAILER}: "
        f"{SOURCE_REPO}@<ref>): it was not made by scripts/headless_release.py sync - "
        "nothing is committed there by hand")


def export(axross: Path, out: Path) -> Path:
    """``scripts/export_standalone.py mcp`` of the axross checkout *axross*.
    Both paths are made absolute first: the export runs inside *axross*, so a
    relative one (the drift workflow's ``.axross-source``) was taken twice."""
    axross, out = Path(axross).resolve(), Path(out).resolve()
    run = subprocess.run([sys.executable, str(axross / "scripts" / "export_standalone.py"),
                          "mcp", str(out)], cwd=axross, capture_output=True, check=False)
    if run.returncode:
        raise ReleaseError("the export failed: "
                           + run.stderr.decode("utf-8", "replace").strip().splitlines()[-1:][0]
                           if run.stderr.strip() else "the export failed")
    return out


def _tree_files(tree: Path) -> dict[str, bytes]:
    return {p.relative_to(tree).as_posix(): p.read_bytes()
            for p in sorted(tree.rglob("*")) if p.is_file() and ".git" not in p.relative_to(tree).parts}


def _commit_files(repo: Path, ref: str) -> dict[str, bytes]:
    names = _git(repo, "ls-tree", "-r", "--name-only", "-z", ref).split("\0")
    return {n: _git(repo, "show", f"{ref}:{n}", text=False) for n in names if n}


def differences(expected: dict[str, bytes], actual: dict[str, bytes]) -> list[str]:
    """Each path that is missing, extra or different, as one line."""
    out = [f"missing: {p}" for p in sorted(expected.keys() - actual.keys())]
    out += [f"not in the export: {p}" for p in sorted(actual.keys() - expected.keys())]
    out += [f"differs: {p}" for p in sorted(expected.keys() & actual.keys())
            if expected[p] != actual[p]]
    return out


def check(repo: Path, axross: Path, ref: str = "HEAD", *,
          checked_out: bool = False) -> list[str]:
    """[] when commit *ref* of the repository is exactly the export of the
    axross ref it names; the differences otherwise. *axross* is a checkout of
    that ref: verified by git there, or - *checked_out*, the guard's shallow
    checkout of exactly that ref, which may hold no tag to resolve - taken
    as it is."""
    source = source_of(repo, ref)
    if not checked_out:
        head = _git(axross, "rev-parse", "HEAD").strip()
        want = _git(axross, "rev-parse", f"{source}^{{commit}}").strip()
        if head != want:
            raise ReleaseError(f"the axross checkout is at {head[:12]}, the commit names "
                               f"{source} ({want[:12]})")
    with tempfile.TemporaryDirectory(prefix="headless-check-") as tmp:
        fresh = export(axross, Path(tmp) / "export")
        return differences(_tree_files(fresh), _commit_files(repo, ref))


def sync(repo: Path, tree: Path, source: str, *, tag: bool, message: str = "") -> str:
    """Make the repository's working tree the exported *tree* and commit it
    with the trailer naming the public axross *source* (a tag such as
    v0.15.180, or a commit); with *tag*, tag the commit vVERSION. Returns the
    commit. Refuses a repository with changes of its own."""
    if _git(repo, "status", "--porcelain").strip():
        raise ReleaseError(f"{repo} has uncommitted changes")
    version = _version(tree)
    for entry in repo.iterdir():
        if entry.name == ".git":
            continue
        shutil.rmtree(entry) if entry.is_dir() and not entry.is_symlink() else entry.unlink()
    for name, data in _tree_files(tree).items():
        target = repo / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        mode = (tree / name).stat().st_mode & 0o777
        target.chmod(mode)
    _git(repo, "add", "-A")
    title = message or f"axross-headless-mcp {version}: exported from axross {source}"
    body = f"{title}\n\n{TRAILER}: {SOURCE_REPO}@{source}\n"
    run = subprocess.run(["git", "-C", str(repo), "commit", "-q", "--allow-empty", "-F", "-"],
                         input=body.encode("utf-8"), capture_output=True, check=False)
    if run.returncode:
        raise ReleaseError("git commit: " + run.stderr.decode("utf-8", "replace").strip())
    commit = _git(repo, "rev-parse", "HEAD").strip()
    if tag:
        _git(repo, "tag", "-a", f"v{version}", "-m", f"axross-headless-mcp {version}", commit)
    return commit


# -- sdist / wheel content ------------------------------------------------------------

def _archive_files(name: str, data: bytes) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    if name.endswith(".whl"):
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for info in zf.infolist():
                if not info.is_dir():
                    files[info.filename] = zf.read(info)
    else:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
            for member in tf.getmembers():
                if member.isfile():
                    # the top folder (name-version/) is the same on both sides
                    files[member.name.split("/", 1)[-1]] = tf.extractfile(member).read()
    for path, content in list(files.items()):
        if path.endswith((".dist-info/WHEEL", "PKG-INFO", ".dist-info/METADATA")):
            files[path] = b"\n".join(line for line in content.split(b"\n")
                                     if not line.startswith(tuple(t.encode() for t in _TOOL_LINES)))
        if path.endswith(".dist-info/RECORD"):
            # Hashes of the files compared one by one above; WHEEL's own line
            # may differ with the build tool.
            files[path] = b"\n".join(sorted(line for line in content.split(b"\n")
                                            if b".dist-info/WHEEL," not in line))
    return files


def _fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "axross-headless-release-check"})
    with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310 - fixed https hosts
        return resp.read()


def compare_dists(version: str) -> list[str]:
    """The sdist and wheel of the repository's GitHub release vVERSION
    against PyPI's, by content."""
    pypi = json.loads(_fetch(f"https://pypi.org/pypi/{DIST}/{version}/json"))
    release = json.loads(_fetch(
        f"https://api.github.com/repos/{HEADLESS_REPO}/releases/tags/v{version}"))
    on_github = {a["name"]: a["browser_download_url"] for a in release.get("assets", [])}
    out: list[str] = []
    for item in pypi["urls"]:
        name = item["filename"]
        if name not in on_github:
            out.append(f"{name}: not in the GitHub release v{version}")
            continue
        theirs = _fetch(item["url"])
        if hashlib.sha256(theirs).hexdigest() != item["digests"]["sha256"]:
            out.append(f"{name}: PyPI's download does not match PyPI's digest")
            continue
        ours = _fetch(on_github[name])
        out += [f"{name}: {line}" for line in
                differences(_archive_files(name, theirs), _archive_files(name, ours))]
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="command", required=True)
    s = sub.add_parser("sync", help="commit an exported tree to the repository (and tag it)")
    s.add_argument("--repo", type=Path, required=True, help="a clone of axross-headless-mcp")
    s.add_argument("--tree", type=Path, required=True, help="the exported tree (the package's source)")
    s.add_argument("--source", required=True, help="the public axross tag or commit it came from")
    s.add_argument("--tag", action="store_true", help="tag the commit vVERSION")
    c = sub.add_parser("check", help="the commit is exactly the export of its axross source")
    c.add_argument("--repo", type=Path, required=True)
    c.add_argument("--axross", type=Path, required=True, help="a checkout of the named source")
    c.add_argument("--ref", default="HEAD")
    c.add_argument("--checked-out", action="store_true",
                   help="the axross checkout was made at the named ref (the CI guard)")
    d = sub.add_parser("compare-dists", help="GitHub release files against PyPI's, by content")
    d.add_argument("version")
    args = ap.parse_args(argv)
    try:
        if args.command == "sync":
            print(sync(args.repo, args.tree, args.source, tag=args.tag))
            return 0
        found = (check(args.repo, args.axross, args.ref, checked_out=args.checked_out)
                 if args.command == "check"
                 else compare_dists(args.version))
    except ReleaseError as exc:
        print(f"::error::{exc}" if args.command == "check" else f"error: {exc}", file=sys.stderr)
        return 1
    for line in found:
        print(line)
    if found:
        print(f"::error::{len(found)} difference(s)" if args.command == "check"
              else f"{len(found)} difference(s)", file=sys.stderr)
        return 1
    print("identical" if args.command == "check" else "same content")
    return 0


if __name__ == "__main__":
    sys.exit(main())
