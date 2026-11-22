#!/usr/bin/env python3
"""The end of a CI step's log as error annotations: ``ci_log_tail.py [--warning] LOG [TITLE [LINES]]``.

The release workflow tees its heavy steps into LOG; when a job fails, this
prints the last LINES (60) lines as ``::error::`` annotations (in pieces
of 20 lines), so the cause can be read through the API's annotations where the
log storage is out of reach - with ``--warning`` as ``::warning::`` ones (a job
that blocks nothing: the timing tests). GitHub's escaping: % -> %25, CR -> %0D,
LF -> %0A.
"""

from __future__ import annotations

import sys
from pathlib import Path

LINES = 60
PIECE = 20


def escape(text: str) -> str:
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def main(argv: list[str]) -> int:
    level = "error"
    if argv[:1] == ["--warning"]:
        level, argv = "warning", argv[1:]
    if not argv:
        print(__doc__, file=sys.stderr)
        return 2
    log = Path(argv[0])
    title = argv[1] if len(argv) > 1 else "last lines of the log"
    count = int(argv[2]) if len(argv) > 2 else LINES
    if not log.is_file():
        print(f"::{level} title={escape(title)}::no log at {escape(str(log))}")
        return 0
    lines = log.read_text(encoding="utf-8", errors="replace").splitlines()[-count:]
    pieces = [lines[i:i + PIECE] for i in range(0, len(lines), PIECE)] or [["(empty log)"]]
    for number, piece in enumerate(pieces, 1):
        head = escape(f"{title} ({number}/{len(pieces)})").replace(",", "%2C").replace(":", "%3A")
        print(f"::{level} title={head}::{escape(chr(10).join(piece))}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
