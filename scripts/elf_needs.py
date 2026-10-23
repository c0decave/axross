"""Which system libraries do the ELF files of a bundle need?

PyInstaller bundles a library only when it finds it on the build machine;
whatever it cannot find is left for the target system, silently. This
reads the DT_NEEDED entries of every ELF file under a folder (an extracted
bundle) with the standard library only - no readelf, no ldd, nothing that
loads the libraries - and reports the sonames that are neither bundled nor
on the list of what the target system provides.

Usage: python scripts/elf_needs.py FOLDER
"""

from __future__ import annotations

import os
import struct
import sys
from typing import Callable

_PT_LOAD, _PT_DYNAMIC = 1, 2
_DT_NULL, _DT_NEEDED, _DT_STRTAB, _DT_STRSZ = 0, 1, 5, 10


_DT_VERDEF, _DT_VERDEFNUM, _DT_VERNEED, _DT_VERNEEDNUM = (0x6FFFFFFC, 0x6FFFFFFD,
                                                           0x6FFFFFFE, 0x6FFFFFFF)
_VER_FLG_BASE = 1


def _read(path: str) -> bytes | None:
    with open(path, "rb") as fh:
        data = fh.read()
    return data if data[:4] == b"\x7fELF" else None


class _Dynamic:
    """The dynamic section of one ELF file: its entries, and the file
    offset of a virtual address (through the PT_LOAD segments)."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        bits = {1: 32, 2: 64}.get(data[4])
        self.order = {1: "<", 2: ">"}.get(data[5])
        if bits is None or self.order is None:
            raise ValueError(f"unknown ELF class/data {data[4]}/{data[5]}")
        o = self.order
        if bits == 64:
            phoff, = struct.unpack_from(o + "Q", data, 32)
            phentsize, phnum = struct.unpack_from(o + "HH", data, 54)
        else:
            phoff, = struct.unpack_from(o + "I", data, 28)
            phentsize, phnum = struct.unpack_from(o + "HH", data, 42)
        self.loads, dynamic = [], None
        for i in range(phnum):
            at = phoff + i * phentsize
            if bits == 64:
                p_type, _f, off, vaddr, _pa, filesz = struct.unpack_from(o + "IIQQQQ", data, at)
            else:
                p_type, off, vaddr, _pa, filesz = struct.unpack_from(o + "IIIII", data, at)
            if p_type == _PT_LOAD:
                self.loads.append((vaddr, off, filesz))
            elif p_type == _PT_DYNAMIC:
                dynamic = (off, filesz)
        self.entries: list[tuple[int, int]] = []
        if dynamic is None:
            return
        entry = o + ("qQ" if bits == 64 else "iI")
        size = struct.calcsize(entry)
        off, filesz = dynamic
        if off + filesz > len(data):
            raise ValueError("dynamic segment past the end of the file")
        for at in range(off, off + filesz - size + 1, size):
            tag, val = struct.unpack_from(entry, data, at)
            if tag == _DT_NULL:
                break
            self.entries.append((tag, val))
        tags = dict(self.entries)
        self._strtab = None
        if _DT_STRTAB in tags:
            self._strtab = self.offset(tags[_DT_STRTAB])
            strsz = tags.get(_DT_STRSZ)
            self._strend = self._strtab + strsz if strsz else len(data)
            if self._strend > len(data):
                raise ValueError("string table past the end of the file")

    def get(self, tag: int) -> int | None:
        return next((v for t, v in self.entries if t == tag), None)

    def offset(self, vaddr: int) -> int:
        off = next((o + vaddr - v for v, o, n in self.loads if v <= vaddr < v + n), None)
        if off is None:
            raise ValueError(f"address {vaddr:#x} outside every PT_LOAD segment")
        return off

    def string(self, index: int) -> str:
        if self._strtab is None:
            raise ValueError("a string reference without DT_STRTAB")
        start = self._strtab + index
        return self.data[start:self.data.index(b"\0", start, self._strend)].decode("ascii")

    def u(self, fmt: str, at: int) -> tuple:
        return struct.unpack_from(self.order + fmt, self.data, at)


def _parsed(path: str) -> _Dynamic | None:
    data = _read(path)
    if data is None:
        return None
    try:
        return _Dynamic(data)
    except (struct.error, IndexError, UnicodeDecodeError) as exc:
        raise ValueError(f"{path}: damaged ELF ({exc})") from exc


def _guard(path: str, fn):
    try:
        return fn()
    except (struct.error, IndexError, UnicodeDecodeError) as exc:
        raise ValueError(f"{path}: damaged ELF ({exc})") from exc


def needed(path: str) -> list[str] | None:
    """The DT_NEEDED sonames of the ELF file *path*, in file order; ``[]``
    for a static ELF, ``None`` when *path* is not an ELF file. A damaged
    ELF raises ``ValueError``: a gate must not read it as having no needs."""
    d = _parsed(path)
    if d is None:
        return None
    return _guard(path, lambda: [d.string(v) for t, v in d.entries if t == _DT_NEEDED])


def version_needs(path: str) -> dict[str, set[str]] | None:
    """The symbol versions *path* needs per library (DT_VERNEED: soname ->
    {"GLIBCXX_3.4.29", ...}); ``{}`` without any, ``None`` for a non-ELF."""
    d = _parsed(path)
    if d is None:
        return None

    def read() -> dict[str, set[str]]:
        out: dict[str, set[str]] = {}
        addr, count = d.get(_DT_VERNEED), d.get(_DT_VERNEEDNUM) or 0
        if addr is None:
            return out
        at = d.offset(addr)
        for _ in range(count):
            _ver, cnt, file_, aux, nxt = d.u("HHIII", at)
            names = out.setdefault(d.string(file_), set())
            a = at + aux
            for _ in range(cnt):
                _hash, _flags, _other, name, anext = d.u("IHHII", a)
                names.add(d.string(name))
                if not anext:
                    break
                a += anext
            if not nxt:
                break
            at += nxt
        return out

    return _guard(path, read)


def version_defs(path: str) -> set[str]:
    """The symbol versions the library *path* defines (DT_VERDEF), without
    its base entry (the soname itself)."""
    d = _parsed(path)
    if d is None:
        return set()

    def read() -> set[str]:
        out: set[str] = set()
        addr, count = d.get(_DT_VERDEF), d.get(_DT_VERDEFNUM) or 0
        if addr is None:
            return out
        at = d.offset(addr)
        for _ in range(count):
            _ver, flags, _ndx, cnt, _hash, aux, nxt = d.u("HHHHIII", at)
            if cnt and not flags & _VER_FLG_BASE:
                out.add(d.string(d.u("II", at + aux)[0]))
            if not nxt:
                break
            at += nxt
        return out

    return _guard(path, read)


_LIB_DIRS = ("/lib64", "/usr/lib64", "/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu",
             "/lib", "/usr/lib")


def host_library(soname: str) -> str | None:
    """The file this machine's loader uses for *soname* (ldconfig's cache,
    x86-64 entries first, then the usual directories); ``None`` if none."""
    import subprocess

    try:
        out = subprocess.run(["ldconfig", "-p"], capture_output=True, text=True, timeout=30,
                             env={"PATH": "/usr/sbin:/sbin:/usr/bin:/bin", "LC_ALL": "C"}).stdout
    except (OSError, subprocess.SubprocessError):
        out = ""
    found = [line.split(" => ", 1)[1].strip() for line in out.splitlines()
             if line.strip().startswith(soname + " ") and " => " in line
             and ("x86-64" in line or "64bit" in line)]
    if found:
        return found[0]
    for d in _LIB_DIRS:
        p = os.path.join(d, soname)
        if os.path.isfile(p):
            return p
    return None


def version_floor_problems(folder: str, host_lib: Callable[[str], str | None] = host_library,
                           skip: Callable[[str], bool] | None = None,
                           known: dict | None = None) -> list[str]:
    """Every symbol version an ELF under *folder* needs from a library the
    bundle does NOT carry must be defined by that library on this machine
    (*host_lib*: soname -> path). In the builder image this machine is the
    oldest supported system, so a need it cannot meet breaks there. One
    line per ELF and library. *known* (soname -> versions) stands in for a
    host library this machine deliberately lacks
    (bundle_options.HOST_VERSION_FLOOR)."""
    bundled, per_file = set(), {}
    for root, _dirs, files in os.walk(folder):
        for name in files:
            path = os.path.join(root, name)
            bundled.add(name)
            rel = os.path.relpath(path, folder).replace(os.sep, "/")
            if os.path.islink(path) or not os.path.isfile(path) or (skip and skip(rel)):
                continue
            needs = version_needs(path)
            if needs:
                per_file[rel] = needs
    defs_of: dict[str, set[str] | None] = {}
    problems = []
    for rel, needs in sorted(per_file.items()):
        for soname, versions in sorted(needs.items()):
            if soname in bundled:
                continue
            if soname not in defs_of:
                path = host_lib(soname)
                defs_of[soname] = (version_defs(path) if path
                                   else set((known or {}).get(soname, ())) or None)
            defs = defs_of[soname]
            if defs is None:
                problems.append(f"{rel}: {soname} not found on this machine - "
                                f"cannot check {', '.join(sorted(versions))}")
                continue
            missing = sorted(versions - defs)
            if missing:
                problems.append(f"{rel}: needs {', '.join(missing)} from {soname}, which the "
                                "oldest supported system (this build machine) does not define")
    return problems


def system_needs(folder: str, provided: Callable[[str], bool] | tuple,
                 skip: Callable[[str], bool] | None = None) -> dict:
    """Scan every regular ELF file under *folder* (symlinks are the same
    file again). Returns ``needs`` (soname -> files that need it, relative
    to *folder*) for sonames neither bundled under *folder* nor
    *provided*; ``elf_files``, the number of ELF files read; and
    ``unreadable``, the ones that could not be parsed. *provided* is a
    predicate on a soname, or a tuple of prefixes. *skip* is a predicate on
    the relative path for files the build removes anyway."""
    if isinstance(provided, tuple):
        prefixes = provided
        provided = lambda name: name.startswith(prefixes)  # noqa: E731
    bundled, per_file, unreadable = set(), {}, []
    for root, _dirs, files in os.walk(folder):
        for name in files:
            path = os.path.join(root, name)
            bundled.add(name)
            rel = os.path.relpath(path, folder).replace(os.sep, "/")
            if os.path.islink(path) or not os.path.isfile(path) or (skip and skip(rel)):
                continue
            try:
                found = needed(path)
            except (OSError, ValueError) as exc:
                unreadable.append(f"{rel}: {exc}")
                continue
            if found is not None:
                per_file[rel] = found
    needs: dict[str, list[str]] = {}
    for rel, sonames in sorted(per_file.items()):
        for soname in sonames:
            if soname not in bundled and not provided(soname):
                needs.setdefault(soname, []).append(rel)
    return {"needs": needs, "elf_files": len(per_file), "unreadable": sorted(unreadable)}


def problems(scan: dict) -> list[str]:
    """One line per problem in a :func:`system_needs` result."""
    out = [f"needs {soname} from the system (not bundled): {', '.join(users[:3])}"
           + (f" and {len(users) - 3} more" if len(users) > 3 else "")
           for soname, users in sorted(scan["needs"].items())]
    out += [f"unreadable ELF {u}" for u in scan["unreadable"]]
    if not scan["elf_files"]:
        out.append("no ELF file found: nothing was checked")
    return out


def main(argv: list[str]) -> int:
    if len(argv) != 2 or not os.path.isdir(argv[1]):
        print(__doc__, file=sys.stderr)
        return 2
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from bundle_options import dropped, host_provided

    scan = system_needs(argv[1], host_provided, skip=dropped)
    print(f"{scan['elf_files']} ELF files read")
    for p in problems(scan):
        print(p)
    return 1 if problems(scan) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
