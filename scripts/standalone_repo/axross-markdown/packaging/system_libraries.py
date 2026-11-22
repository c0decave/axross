"""The build machine's own libraries in the Linux one-file program (packaging/axross-markdown.spec): only those
something left in the program loads, each with its licence and where its source is.

PyInstaller puts in every system library a collected binary needs - those of the Qt plugins the spec then
drops too (the GTK theme's libgtk-3, gnutls, avahi; the CUPS print plugin's libcups.so.2): 94 libraries in
0.17.2's program, 48 of them loaded by nothing that stays in it, and none with a licence text or a source
pointer. :func:`pruned` keeps a system library only when it is in the DT_NEEDED closure of what stays (Qt,
PyQt6, Python's extension modules, libpython); :func:`notices` writes, for each one kept, the Debian/Ubuntu
package's copyright file (/usr/share/doc/PACKAGE/copyright: its licence texts) and an index with the package,
its version and its source package - the source pointer (``apt-get source SOURCE=VERSION``, the archive's
page). The build stops when a kept library's package or copyright cannot be found.

Pure Python (an ELF reader of its own: no binutils needed), run by PyInstaller in the spec; also a command:
``python packaging/system_libraries.py FILE...`` lists the closure of the files' DT_NEEDED.
"""

from __future__ import annotations

import os
import struct
import subprocess
import sys
from pathlib import Path

#: Where a library counts as the build machine's own (not a wheel's, not the interpreter's).
SYSTEM_DIRS = ("/lib/", "/lib64/", "/usr/lib/", "/usr/lib64/", "/usr/local/lib/")
#: The index the notices go in (licenses/system/ inside the program).
INDEX = "INDEX.txt"


def needed(path: str | os.PathLike) -> list[str]:
    """The DT_NEEDED names of the ELF file *path* ([] for a file that is no dynamic ELF object)."""
    try:
        with open(path, "rb") as handle:
            data = handle.read()
    except OSError:
        return []
    if data[:4] != b"\x7fELF" or len(data) < 64:
        return []
    wide, order = data[4] == 2, "<" if data[5] == 1 else ">"
    if wide:
        phoff, = struct.unpack_from(order + "Q", data, 32)
        phentsize, phnum = struct.unpack_from(order + "HH", data, 54)
    else:
        phoff, = struct.unpack_from(order + "I", data, 28)
        phentsize, phnum = struct.unpack_from(order + "HH", data, 42)
    loads, dynamic = [], None
    for number in range(phnum):
        at = phoff + number * phentsize
        if wide:
            kind, _flags, offset, vaddr, _paddr, filesz = struct.unpack_from(order + "IIQQQQ", data, at)
        else:
            kind, offset, vaddr, _paddr, filesz = struct.unpack_from(order + "IIIII", data, at)
        if kind == 1:  # PT_LOAD
            loads.append((vaddr, offset, filesz))
        elif kind == 2:  # PT_DYNAMIC
            dynamic = (offset, filesz)
    if dynamic is None:
        return []
    entry = struct.Struct(order + ("qQ" if wide else "iI"))
    names, strtab = [], None
    for at in range(dynamic[0], dynamic[0] + dynamic[1] - entry.size + 1, entry.size):
        tag, value = entry.unpack_from(data, at)
        if tag == 0:  # DT_NULL
            break
        if tag == 1:  # DT_NEEDED
            names.append(value)
        elif tag == 5:  # DT_STRTAB (an address: its offset in the file through the load segments)
            strtab = next((offset + value - vaddr for vaddr, offset, size in loads if vaddr <= value < vaddr + size),
                          None)
    if strtab is None:
        return []
    out = []
    for value in names:
        end = data.find(b"\0", strtab + value)
        out.append(data[strtab + value:end].decode("utf-8", "replace"))
    return out


def is_system(source: str) -> bool:
    """Whether *source* (a collected binary's file) is the build machine's own library."""
    real = os.path.realpath(source)
    return real.startswith(SYSTEM_DIRS) and not real.startswith(_python_prefixes())


def _python_prefixes() -> tuple[str, ...]:
    prefixes = {os.path.realpath(p) + os.sep for p in (sys.prefix, sys.base_prefix, sys.exec_prefix)}
    return tuple(p for p in prefixes if not p.startswith(("/usr/", "/lib")) or "site-packages" in p)


def pruned(binaries) -> tuple[list, list]:
    """(*binaries* - a PyInstaller TOC of (name, source, kind) - with only the system libraries something kept
    in it needs (the DT_NEEDED closure of the rest), the system libraries left out)."""
    entries = list(binaries)
    system = {os.path.basename(name): (name, source, kind) for name, source, kind in entries if is_system(source)}
    roots = [source for name, source, kind in entries if os.path.basename(name) not in system]
    wanted, queue = set(), [needed(source) for source in roots]
    while queue:
        for name in queue.pop():
            if name in system and name not in wanted:
                wanted.add(name)
                queue.append(needed(system[name][1]))
    kept = [entry for entry in entries if os.path.basename(entry[0]) not in system
            or os.path.basename(entry[0]) in wanted]
    gone = [entry for entry in entries if os.path.basename(entry[0]) in system
            and os.path.basename(entry[0]) not in wanted]
    return kept, gone


def _run(*args: str) -> str:
    return subprocess.run(args, capture_output=True, text=True, check=True, timeout=120).stdout


def package_of(source: str) -> str:
    """The Debian/Ubuntu package (dpkg -S) that installed the library *source* ("" when none did)."""
    for path in dict.fromkeys((source, os.path.realpath(source))):
        candidates = [path]
        if path.startswith("/usr/lib/"):  # (merged /usr: dpkg may know it as /lib/…)
            candidates.append(path[4:])
        elif path.startswith("/lib/"):
            candidates.append("/usr" + path)
        for candidate in candidates:
            try:
                out = _run("dpkg", "-S", candidate)
            except (OSError, subprocess.SubprocessError):
                continue
            for line in out.splitlines():
                package, _sep, _file = line.partition(": ")
                if package and "diversion" not in line:
                    return package.split(",")[0].strip()
    return ""


def _source_url(distribution: str, source: str, version: str) -> str:
    if distribution == "ubuntu":
        return f"https://launchpad.net/ubuntu/+source/{source}/{version}"
    return f"https://snapshot.debian.org/package/{source}/{version}/"


def _distribution() -> tuple[str, str]:
    try:
        fields = dict(line.split("=", 1) for line in Path("/etc/os-release").read_text().splitlines() if "=" in line)
    except OSError:
        return "", ""
    return fields.get("ID", "").strip('"'), fields.get("PRETTY_NAME", "").strip('"')


def notices(binaries, folder: str | os.PathLike) -> list[tuple[str, str, str]]:
    """The licence notices of the system libraries among *binaries* (a TOC), written into *folder*: each
    package's copyright file and INDEX.txt (library, package, version, source package and where its source is)
    - a TOC of DATA entries under licenses/system/ to add to the program. SystemExit when a library's package
    or its copyright file is not found (a library without its licence is not shipped)."""
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    system = sorted({(os.path.basename(name), source) for name, source, _kind in binaries if is_system(source)})
    distribution, pretty = _distribution()
    rows, packages, missing = [], {}, []
    for name, source in system:
        package = package_of(source)
        if not package:
            missing.append(f"{name} ({source}): no package")
            continue
        if package not in packages:
            fields = _run("dpkg-query", "-W", "-f", "${Version}\t${source:Package}\t${source:Version}",
                          package).split("\t")
            copyright = Path("/usr/share/doc") / package.split(":")[0] / "copyright"
            if not copyright.is_file():
                missing.append(f"{name}: {package} has no {copyright}")
                continue
            target = folder / f"{package.split(':')[0]}.copyright"
            target.write_bytes(copyright.read_bytes())
            packages[package] = (fields[0], fields[1] or package, fields[2] or fields[0], target.name)
        version, source_package, source_version, text = packages[package]
        rows.append((name, package, version, source_package, source_version, text))
    if missing:
        raise SystemExit("system_libraries: a bundled library without its licence:\n  " + "\n  ".join(missing))
    lines = [
        "The build machine's libraries in this program",
        "=" * 46,
        "",
        f"Built on {pretty or 'Linux'}. Each library below comes from that system's package named beside it,",
        "under the licence in licenses/system/PACKAGE.copyright (the package's own copyright file). Its",
        "complete source code is the package's source package at the version given: apt-get source",
        "SOURCE=VERSION, or the archive page given. Should one no longer be available there, ask at",
        "https://github.com/c0decave/axross-markdown/issues and it is provided.",
        "",
    ]
    for name, package, version, source_package, source_version, text in rows:
        lines += [f"{name}", f"    package {package} {version} - licences: licenses/system/{text}",
                  f"    source  {source_package} {source_version}: "
                  f"{_source_url(distribution, source_package, source_version)}"]
    (folder / INDEX).write_text("\n".join(lines) + "\n", encoding="utf-8")
    files = sorted(folder.iterdir())
    return [(f"licenses/system/{path.name}", str(path), "DATA") for path in files]


def _main(argv: list[str]) -> int:
    for path in argv[1:]:
        print(path, needed(path))
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv))
