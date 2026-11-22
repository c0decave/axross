#!/usr/bin/env python3
"""The GitHub release's notes: ``release_notes.py VERSION ASSETS_DIR > notes.md``.

The section ``## VERSION - <date>`` of CHANGELOG.md (refused when there is
none: a release without notes is a mistake), then the assets with their
SHA-256 from ASSETS_DIR/SHA256SUMS and how to check them.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def section(text: str, version: str) -> str:
    lines = text.splitlines()
    head = re.compile(rf"## \[?{re.escape(version)}\]?(?![0-9.])")
    start = next((i for i, line in enumerate(lines) if head.match(line)), None)
    if start is None:
        raise SystemExit(f"release_notes: CHANGELOG.md has no section '## {version} - <date>'")
    end = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("## ")),
               len(lines))
    body = "\n".join(lines[start + 1:end]).strip()
    if not body:
        raise SystemExit(f"release_notes: the section of {version} in CHANGELOG.md is empty")
    return body


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    version, assets = argv[1].removeprefix("v"), Path(argv[2])
    body = section((ROOT / "CHANGELOG.md").read_text(encoding="utf-8"), version)
    sums = (assets / "SHA256SUMS").read_text(encoding="utf-8").strip()
    names = [line.split(maxsplit=1)[-1] for line in sums.splitlines() if line.strip()]
    texts = ("LICENSE", "NOTICE", "THIRD_PARTY_LICENSES.txt")
    # (a text - the system libraries' notices of a binary, SYSTEM-LIBRARIES-*.txt - is no binary either)
    binaries = [n for n in names if not n.endswith((".whl", ".tar.gz", ".txt", ".json", ".md")) and n not in texts]
    note = (" The binaries are not notarized or code-signed: macOS asks for a right-click > "
            "Open at the first start, Windows SmartScreen for \"Run anyway\"."
            if binaries else "")
    if binaries and "THIRD_PARTY_LICENSES.txt" in names:  # (one-file programs with PyQt6 and Qt in them)
        note += (" They contain PyQt6 (GPL-3.0) and Qt (LGPL-3.0) and are distributed under the GPL-3.0: "
                 "THIRD_PARTY_LICENSES.txt lists what they contain, the licence texts and where the "
                 "source code is.")
    if any(n.startswith("SYSTEM-LIBRARIES-") for n in names):
        note += (" The Linux programs also carry libraries of the system they were built on: "
                 "SYSTEM-LIBRARIES-linux-x86_64.txt names each, its package's licence and its source package.")
    print(f"{body}\n\n## Assets and checksums\n\n```\n{sums}\n```\n\n"
          "Check a download with `sha256sum --check --ignore-missing SHA256SUMS` "
          f"(macOS: `shasum -a 256 -c --ignore-missing SHA256SUMS`).{note}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
