"""ldd and ldconfig as the target system would answer (scripts/build_dist.sh).

PyInstaller finds the libraries it bundles with ``ldd`` and ``ldconfig -p``.
On the build machine both also see the machine's own library folders, so a
library the target system does not have would be taken from the build
machine (GTK, cairo of a newer distribution). Set up by build_dist.sh:

* ``AXROSS_TARGET_LIBS`` - the folder of the target's libraries (glibc's
  left out: the running loader's);
* ``AXROSS_TARGET_KEEP`` - paths under it count (the target's libraries,
  the Python and venv of the build);
* ``AXROSS_GLIBC_RE`` - glibc's own libraries, always the loader's.

``ldd FILE``: the real ldd's lines, with every library that resolved
elsewhere turned into ``not found``. ``ldconfig -p``: the target's
libraries only. Anything else: nothing, successfully.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys


def filter_ldd(output: str, keep: str, glibc: re.Pattern) -> str:
    lines = []
    for line in output.splitlines():
        if " => " not in line:
            lines.append(line)
            continue
        name, _sep, rest = line.partition(" => ")
        name = name.strip()
        path = rest.rsplit(" (0x", 1)[0].strip() if " (0x" in rest else rest.strip()
        if path == "not found" or (keep and path.startswith(keep)) \
                or glibc.match(os.path.basename(name)):
            lines.append(line)
        else:
            lines.append(f"\t{name} => not found")
    return "\n".join(lines) + ("\n" if lines else "")


def ldconfig_cache(libs: str) -> str:
    names = sorted(n for n in os.listdir(libs) if ".so" in n) if libs and os.path.isdir(libs) \
        else []
    out = [f"{len(names)} libs found in cache `/etc/ld.so.cache'"]
    out += [f"\t{n} (libc6,x86-64) => {os.path.join(libs, n)}" for n in names]
    return "\n".join(out) + "\n"


def main(argv: list[str]) -> int:
    mode, args = (argv[1] if len(argv) > 1 else ""), argv[2:]
    glibc = re.compile(os.environ.get("AXROSS_GLIBC_RE") or r"^(ld-linux.*|libc)\.so")
    if mode == "ldd":
        result = subprocess.run(["/usr/bin/ldd", *args], capture_output=True, text=True)
        sys.stdout.write(filter_ldd(result.stdout, os.environ.get("AXROSS_TARGET_KEEP", ""),
                                    glibc))
        sys.stderr.write(result.stderr)
        return result.returncode
    if mode == "ldconfig":
        if "-p" in args or "--print-cache" in args:
            sys.stdout.write(ldconfig_cache(os.environ.get("AXROSS_TARGET_LIBS", "")))
        return 0
    print("usage: target_ldd.py ldd|ldconfig ARGS", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
