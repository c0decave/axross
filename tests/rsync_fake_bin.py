"""A stand-in for the ``rsync`` binary: the receiving side of a download.

Called as ``rsync [options] SOURCE DEST_DIR/``. The base name of SOURCE
says what happens:

* ``big-<size>-<slices>.bin``: writes <size> bytes (the pattern
  ``bytes(range(256))`` repeated) into DEST_DIR in <slices> slices with a
  pause of 0.1 s between them - the way rsync --inplace fills the file;
* ``broken-<size>.bin``: writes half of it, then fails with code 12;
* ``gone.txt``: what rsync says for a missing source (code 23);
* ``folder``: "skipping directory", nothing written, code 0.

Without ``-L`` (follow links) or ``--inplace`` it refuses (code 1), so a
test notices when the backend stops passing them.
"""

from __future__ import annotations

import os
import sys
import time


def pattern(size: int) -> bytes:
    return (bytes(range(256)) * (size // 256 + 1))[:size]


def main(argv: list[str]) -> int:
    if "-L" not in argv or "--inplace" not in argv:
        sys.stderr.write("fake rsync: -L and --inplace expected\n")
        return 1
    source, dest = argv[-2], argv[-1]
    name = source.rstrip("/").rsplit("/", 1)[-1]
    target = os.path.join(dest, name)
    if name == "gone.txt":
        sys.stderr.write(
            f'rsync: [sender] link_stat "/{name}" (in m) failed: No such file or directory (2)\n'
            "rsync error: some files/attrs were not transferred (see previous errors) "
            "(code 23) at main.c(1338) [Receiver=3.2.7]\n"
        )
        return 23
    if name == "folder":
        sys.stdout.write("skipping directory folder\n")
        return 0
    if name.startswith("broken-"):
        size = int(name.split("-")[1].split(".")[0])
        with open(target, "wb") as fh:
            fh.write(pattern(size)[: size // 2])
        sys.stderr.write("rsync error: error in rsync protocol data stream (code 12)\n")
        return 12
    if name.startswith("big-"):
        _, size, slices = name.split(".")[0].split("-")
        size, slices = int(size), int(slices)
        data = pattern(size)
        step = -(-size // slices)
        with open(target, "wb") as fh:
            for off in range(0, size, step):
                fh.write(data[off : off + step])
                fh.flush()
                time.sleep(0.1)
        return 0
    sys.stderr.write(f"fake rsync: unknown source {source}\n")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
