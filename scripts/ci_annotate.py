"""Standard input as GitHub Actions error annotations, in pieces.

The API serves a job's annotations (``gh api
repos/OWNER/REPO/check-runs/JOB/annotations``) where the log storage is out
of reach, a sandboxed maintainer's machine for one. One annotation holds a
few KB, so a longer text - a build log's end, a diff - becomes numbered
pieces. A step gets at most ten error annotations: ``--pieces`` stays below.

    tail -n 80 build.log | python3 -I scripts/ci_annotate.py "build_dist.sh"
    git diff -U0 THIRD_PARTY_LICENSES.md | python3 -I scripts/ci_annotate.py \\
        "THIRD_PARTY_LICENSES.md wants" --pieces 9 --head
"""

from __future__ import annotations

import argparse
import re
import sys
from typing import Sequence

#: What one annotation carries before the runner shortens it.
PIECE = 3800
#: GitHub keeps ten error annotations of a step.
MAX_PIECES = 10
_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def escape(text: str) -> str:
    """A workflow command's data: %, CR and LF are the ones it encodes."""
    return text.replace("%", "%25").replace("\r", "").replace("\n", "%0A")


def _escape_property(text: str) -> str:
    return escape(text).replace(":", "%3A").replace(",", "%2C")


def pieces(text: str, *, size: int = PIECE, count: int = MAX_PIECES, head: bool = False) -> list[str]:
    """*text* without colour codes, cut at line ends into at most *count*
    pieces of about *size* characters: its end (a log), or with *head* its
    start (a diff, read from the top)."""
    text = _ANSI.sub("", text)
    chunks: list[str] = []
    current = ""
    for line in text.splitlines(keepends=True):
        while len(line) > size:  # one overlong line: hard cuts
            if current:
                chunks.append(current)
                current = ""
            chunks.append(line[:size])
            line = line[size:]
        if len(current) + len(line) > size:
            chunks.append(current)
            current = ""
        current += line
    if current:
        chunks.append(current)
    if len(chunks) <= count:
        return chunks
    return chunks[:count] if head else chunks[-count:]


def commands(title: str, text: str, *, count: int = MAX_PIECES, head: bool = False) -> list[str]:
    parts = pieces(text, count=min(count, MAX_PIECES), head=head)
    total = len(parts)
    return [f"::error title={_escape_property(f'{title} ({n}/{total})')}::{escape(part)}"
            for n, part in enumerate(parts, 1)]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="scripts/ci_annotate.py", description=__doc__.split("\n")[0])
    parser.add_argument("title")
    parser.add_argument("--pieces", type=int, default=MAX_PIECES)
    parser.add_argument("--head", action="store_true", help="keep the start, not the end")
    args = parser.parse_args(argv)
    text = sys.stdin.read()
    if not text.strip():
        return 0
    for line in commands(args.title, text, count=max(1, args.pieces), head=args.head):
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
