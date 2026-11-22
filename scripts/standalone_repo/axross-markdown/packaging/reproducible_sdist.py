#!/usr/bin/env python3
"""The sdist the same bytes for the same commit, and holding what THIRD_PARTY_LICENSES.txt says it holds.

``reproducible_sdist.py SDIST...`` writes each .tar.gz again: its members in name order, each file's time
``$SOURCE_DATE_EPOCH`` (the commit's: release.yml), owner root, modes 0644 / 0755, the gzip header without a
time or a name - setuptools wrote the build's own times and order (two builds of one commit differed).
``reproducible_sdist.py --check SDIST...`` fails unless each holds the build's scripts and locks
(.github/workflows/, packaging/, requirements.lock.txt, ...): the complete corresponding source of the one-file
programs. Python's standard library only.
"""

from __future__ import annotations

import gzip
import io
import os
import sys
import tarfile

#: What the sdist must hold (below its top folder): the programs' complete corresponding source.
REQUIRED = ("PKG-INFO", "pyproject.toml", "LICENSE", "NOTICE", "THIRD_PARTY_LICENSES.txt", "CHANGELOG.md",
            "requirements.lock.txt", "packaging/axross-markdown.spec", "packaging/requirements-pyinstaller.txt",
            "packaging/requirements-build.txt", "packaging/requirements-test.txt",
            "packaging/system_libraries.py", ".github/workflows/release.yml", ".github/workflows/tests.yml",
            "tests/conftest.py")


def rewritten(data: bytes, epoch: int) -> bytes:
    """The sdist *data* (a .tar.gz) written again as described above."""
    members = []
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as source:
        for member in source.getmembers():
            content = source.extractfile(member).read() if member.isfile() else None
            members.append((member, content))
    out = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=out, mtime=0, compresslevel=9) as packed, \
            tarfile.open(fileobj=packed, mode="w", format=tarfile.PAX_FORMAT) as target:
        for member, content in sorted(members, key=lambda pair: pair[0].name):
            member.mtime = epoch
            member.uid = member.gid = 0
            member.uname = member.gname = ""
            member.pax_headers = {}
            if member.isdir():
                member.mode = 0o755
            elif member.isfile():
                member.mode = 0o755 if member.mode & 0o111 else 0o644
            target.addfile(member, io.BytesIO(content) if content is not None else None)
    return out.getvalue()


def missing(data: bytes) -> list[str]:
    """What of REQUIRED the sdist *data* lacks."""
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as source:
        names = {name.split("/", 1)[1] for name in source.getnames() if "/" in name}
    return [name for name in REQUIRED if name not in names]


def main(argv: list[str]) -> int:
    check = "--check" in argv
    paths = [arg for arg in argv[1:] if arg != "--check"]
    if not paths:
        print(__doc__, file=sys.stderr)
        return 2
    failed = 0
    for path in paths:
        with open(path, "rb") as handle:
            data = handle.read()
        if check:
            lacking = missing(data)
            if lacking:
                print(f"::error::{os.path.basename(path)} lacks {', '.join(lacking)}")
                failed = 1
            continue
        epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "315532800"))  # (1980: no build's own time)
        with open(path, "wb") as handle:
            handle.write(rewritten(data, epoch))
        print(f"{os.path.basename(path)}: written again (time {epoch})")
    return failed


if __name__ == "__main__":
    sys.exit(main(sys.argv))
