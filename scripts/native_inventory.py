"""Every native file inside a Linux one-file binary, with its version and
where it comes from.

THIRD_PARTY_LICENSES.md lists them between the ``native-files`` markers and
every release's notes name the components (``--notes``). Both are generated
from the built binaries, never typed: ``python scripts/native_inventory.py
--write dist/axross-full dist/axross-slim``. tests/test_native_inventory.py
fails at release time when the document drifts from the binaries or when a
version typed in resources/credits/third_party.json disagrees with them.

A version is read, in this order, and each row says from where:

``rpm``      the builder image's package (licenses/system/LIBRARIES.txt,
             written by scripts/bundle_licenses.py)
``wheel``    the library is the wheel's own (Qt in PyQt6-Qt6): the wheel version
``sbom``     the wheel's SBOM (licenses/python/<wheel>/sboms/)
``file``     a version string inside the file
``sibling``  that string in the library of the same build next to it
             (libssl takes libcrypto's)
``soname``   only the ABI number in the file name

A component an SBOM names that matches no file of its wheel is linked into
the wheel's own modules (cryptography's OpenSSL) and gets a row of its own.
Rust crates (``pkg:cargo``) stay in the wheel's SBOM inside the bundle.
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping, Protocol, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import third_party as T  # noqa: E402

BLOCK = "native-files"
#: The release notes section starts with these two lines; the release script
#: refuses notes without the marker.
NOTES_MARKER = "<!-- native-components -->"
NOTES_HEADING = "## Native components in the Linux binaries"
LINUX_BINARIES = ("axross-full", "axross-slim")
ELF_MAGIC = b"\x7fELF"
#: Above this a JSON SBOM is not read (a wheel's are a few hundred KiB).
MAX_SBOM_BYTES = 8 * 1024 * 1024

#: The wheel that owns a folder whose first part names no wheel.
OWNER_PREFIXES = (("PyQt6/Qt6/", "pyqt6-qt6"),)
_FFMPEG = re.compile(rb"FFmpeg version (\d+\.\d+(?:\.\d+)?)")
#: Library family -> the version string its build embeds.
EMBEDDED = {
    "libavcodec": _FFMPEG, "libavdevice": _FFMPEG, "libavfilter": _FFMPEG,
    "libavformat": _FFMPEG, "libavutil": _FFMPEG, "libswresample": _FFMPEG,
    "libcrypto": re.compile(rb"OpenSSL (\d+\.\d+\.\d+[a-z]?) "),
    "libgnutls": re.compile(rb"GnuTLS (\d+\.\d+\.\d+)"),
    "libopus": re.compile(rb"libopus (\d+\.\d+(?:\.\d+)?)"),
    "libvpx": re.compile(rb"\0v(\d+\.\d+\.\d+)\0"),
    "libSvtAv1Enc": re.compile(rb"\0v(\d+\.\d+\.\d+)\0"),
    "libx265": re.compile(rb"\0(\d+\.\d+\+\d+-[0-9a-f]{7,})\0"),
    "libscipy_openblas64_": re.compile(rb"OpenBLAS (\d+\.\d+\.\d+)"),
}
#: Bundled programs -> the version string next to their ``--version`` text.
PROGRAMS = {
    "bin/rg": re.compile(rb"\(JIT is available\)\n(\d+\.\d+\.\d+)"),
    "bin/fd": re.compile(rb"gen-completions(\d+\.\d+\.\d+)"),
}
#: A library without a version string of its own -> the one of its build.
SIBLINGS = {"libssl": "libcrypto", "libswscale": "libavutil"}
_EXTENSION = re.compile(r"\.(cpython-[^/]*|abi3)\.so$")
_SONAME = re.compile(r"\.so\.([0-9][0-9.]*)$")
_WHEEL_DIR = re.compile(r"^licenses/python/(?P<dist>.+)-(?P<version>[^-/]+)/")
_DIST_INFO = re.compile(r"^(?P<dist>[^/]+)-(?P<version>[^-/]+)\.dist-info/")


class Archive(Protocol):
    toc: list[tuple[str, str]]

    def read(self, name: str) -> bytes: ...


@dataclass(frozen=True)
class NativeFile:
    #: Name inside the bundle; ``<folder>/`` for a group of extension modules,
    #: empty for a library linked into a wheel's modules.
    path: str
    #: The third_party.json entry id, or empty when no entry claims it.
    component: str
    #: Shown when there is no entry (an SBOM name).
    label: str
    version: str
    evidence: str
    shipped_by: str
    #: ``library``, ``program``, ``extension`` or ``static``.
    kind: str
    count: int = 1


# --------------------------------------------------------------------------
# Reading the parts
# --------------------------------------------------------------------------

def is_extension(name: str) -> bool:
    return bool(_EXTENSION.search(name)) or name.endswith(".pyd")


def family(name: str) -> str:
    return T.normalise_library(name)


def soname_version(name: str) -> str | None:
    m = _SONAME.search(name.rsplit("/", 1)[-1])
    return m.group(1) if m else None


def embedded_version(fam: str, data: bytes) -> str | None:
    """The version string *fam*'s build embeds, or None (unknown family, no
    string, or two different ones)."""
    pattern = EMBEDDED.get(fam)
    return _one(pattern, data) if pattern else None


def _one(pattern: re.Pattern, data: bytes) -> str | None:
    found = {m.group(1).decode("ascii", "replace") for m in pattern.finditer(data)}
    return found.pop() if len(found) == 1 else None


def system_packages(text: str) -> dict[str, tuple[str, str]]:
    """LIBRARIES.txt -> library: (rpm package, version-release or "")."""
    out: dict[str, tuple[str, str]] = {}
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) < 2 or parts[1] in ("", "-"):
            continue
        version = parts[2].strip() if len(parts) > 2 and parts[2].strip() != "-" else ""
        out[parts[0]] = (parts[1].strip(), version)
    return out


def wheel_versions(names: Iterable[str]) -> dict[str, str]:
    """Normalised distribution name -> version, from the licence folders
    and ``*.dist-info`` folders of the bundle."""
    out: dict[str, str] = {}
    for name in names:
        m = _WHEEL_DIR.match(name) or _DIST_INFO.match(name)
        if m:
            out.setdefault(T.normalise_name(m.group("dist")), m.group("version"))
    return out


def _key(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", text.lower())


def sbom_components(data: bytes) -> list[tuple[str, str, str]]:
    """(name, version, purl) of an SBOM's components that are someone
    else's code with a version: not the wheel itself (``pkg:pypi``), not
    Rust crates (``pkg:cargo``). Unreadable SBOMs give nothing."""
    if len(data) > MAX_SBOM_BYTES:
        return []
    try:
        doc = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return []
    out: list[tuple[str, str, str]] = []
    for comp in doc.get("components", []) if isinstance(doc, dict) else []:
        if not isinstance(comp, dict):
            continue
        name, version, purl = comp.get("name"), comp.get("version"), comp.get("purl") or ""
        if not isinstance(name, str) or not isinstance(version, str) or not version:
            continue
        if not isinstance(purl, str) or purl.startswith(("pkg:pypi/", "pkg:cargo/")):
            continue
        if (name, version, purl) not in out:
            out.append((name, version, purl))
    return out


def _sbom_match(comp: str, fam: str, entry: T.Entry | None, *, exact: bool) -> bool:
    """Whether the SBOM component *comp* describes a library of family *fam*
    (claimed by *entry*): the family itself (with or without ``lib``) or one
    of its names in the SBOM's spelling (``libjpeg / libjpeg-turbo``);
    otherwise - not *exact* - the entry's id or name as a prefix either way
    (``krb5`` / ``krb5-libs``, ``Little CMS`` / ``Little CMS 2``)."""
    names = [_key(part) for part in comp.split("/") if _key(part)]
    fams = {_key(fam), _key(fam.removeprefix("lib"))}
    if any(n in fams for n in names):
        return True
    if exact or entry is None:
        return False
    keys = [k for k in (_key(entry.id), _key(entry.name)) if len(k) >= 4]
    return any(n.startswith(k) or k.startswith(n) for n in names for k in keys if len(n) >= 4)


# --------------------------------------------------------------------------
# The inventory
# --------------------------------------------------------------------------

def _owner_wheel(name: str, wheels: Mapping[str, str], entries: Sequence[T.Entry]) -> str | None:
    for prefix, dist in OWNER_PREFIXES:
        if name.startswith(prefix) and dist in wheels:
            return dist
    if "/" not in name:
        return None
    top = name.split("/", 1)[0]
    dist = T.normalise_name(top.removesuffix(".libs"))
    if dist in wheels:
        return dist
    for entry in entries:
        if top in entry.modules:
            for pypi in entry.pypi:
                if T.normalise_name(pypi) in wheels:
                    return T.normalise_name(pypi)
    return None


def _claim(entries: Sequence[T.Entry], name: str, library: bool) -> T.Entry | None:
    owners = T.entries_by_path(entries, name)
    if not owners and library:
        owners = T.entries_by_library(entries, name)
    if not owners and not library:
        first = name.split("/", 1)[0]
        top = first.split(".", 1)[0] if "/" not in name else first
        owners = [e for e in entries if top in e.modules]
    return owners[0] if owners else None


def _own_wheel(entry: T.Entry | None, dist: str | None) -> bool:
    return bool(entry and dist and dist in {T.normalise_name(p) for p in entry.pypi})


def inventory(archive: Archive, entries: Sequence[T.Entry]) -> list[NativeFile]:
    """The native files of *archive*: one row per shared library and
    program, one per folder of extension modules, one per library an SBOM
    names that no file matches."""
    names = [name for _, name in archive.toc]
    wheels = wheel_versions(names)
    try:
        listing = archive.read("licenses/system/LIBRARIES.txt").decode("utf-8")
    except (KeyError, UnicodeDecodeError):
        listing = ""
    system = system_packages(listing)
    sboms: dict[str, list[tuple[str, str, str]]] = {}
    for name in names:
        m = _WHEEL_DIR.match(name)
        if m and "/sboms/" in name and name.endswith(".json"):
            dist = T.normalise_name(m.group("dist"))
            for comp in sbom_components(archive.read(name)):
                if comp not in sboms.setdefault(dist, []):
                    sboms[dist].append(comp)

    natives: dict[str, bytes] = {}
    for kind, name in archive.toc:
        if kind not in ("b", "x") or name.startswith("licenses/"):
            continue
        data = archive.read(name)
        if data[:4] == ELF_MAGIC:
            natives[name] = data

    rows: list[NativeFile] = []
    used: set[tuple[str, tuple[str, str, str]]] = set()
    groups: dict[tuple[str, str], list[str]] = {}
    found: dict[str, str] = {}  # path -> version from the file (for siblings)
    pending: list[tuple[str, T.Entry | None, str, str | None]] = []
    for name, data in sorted(natives.items()):
        if is_extension(name):
            folder = name.rsplit("/", 1)[0] + "/" if "/" in name else name
            if folder.startswith("python3.") and "/lib-dynload/" in folder:
                folder = folder.split("/lib-dynload/", 1)[0] + "/lib-dynload/"
            else:
                folder = folder.split("/", 1)[0] + "/" if "/" in folder else folder
            groups.setdefault((folder, name), [])
            continue
        if name in PROGRAMS:
            entry = _claim(entries, name, library=False)
            version = _one(PROGRAMS[name], data) or ""
            rows.append(NativeFile(name, entry.id if entry else "", "", version,
                                   "file" if version else "", "build", "program"))
            continue
        entry = _claim(entries, name, library=True)
        fam = family(name)
        if "/" not in name:
            package, version = system.get(name, ("", ""))
            evidence = "rpm" if version else ""
            shipped = f"rpm {package}" if package else "builder image"
            if not version:
                version = soname_version(name) or ""
                evidence = "soname" if version else ""
            rows.append(NativeFile(name, entry.id if entry else "", "", version, evidence,
                                   shipped, "library"))
            continue
        dist = _owner_wheel(name, wheels, entries)
        shipped = f"wheel {dist} {wheels[dist]}" if dist else "bundle"
        if _own_wheel(entry, dist):
            rows.append(NativeFile(name, entry.id, "", wheels[dist], "wheel", shipped,
                                   "library"))
            continue
        comp = None
        for exact in (True, False):
            comp = next((c for c in sboms.get(dist or "", [])
                         if _sbom_match(c[0], fam, entry, exact=exact)), None)
            if comp:
                break
        if comp:
            used.add((dist or "", comp))
            rows.append(NativeFile(name, entry.id if entry else "", "", comp[1], "sbom",
                                   shipped, "library"))
            continue
        version = embedded_version(fam, data)
        if version:
            found[name] = version
            rows.append(NativeFile(name, entry.id if entry else "", "", version, "file",
                                   shipped, "library"))
            continue
        pending.append((name, entry, shipped, fam))

    for name, entry, shipped, fam in pending:
        folder = name.rsplit("/", 1)[0]
        sibling = SIBLINGS.get(fam or "")
        version = next((v for p, v in found.items()
                        if sibling and p.rsplit("/", 1)[0] == folder and family(p) == sibling),
                       None)
        evidence = "sibling" if version else ""
        if not version:
            version = soname_version(name)
            evidence = "soname" if version else ""
        rows.append(NativeFile(name, entry.id if entry else "", "", version or "", evidence,
                               shipped, "library"))

    by_group: dict[str, list[str]] = {}
    for folder, name in groups:
        by_group.setdefault(folder, []).append(name)
    for folder, members in sorted(by_group.items()):
        entry = _claim(entries, members[0], library=False)
        if folder.startswith("python3."):
            lib = next((n for n in system if n.startswith("libpython")), "")
            package, version = system.get(lib, ("", ""))
            cpython = next((e for e in entries if e.id == "cpython"), None)
            rows.append(NativeFile(folder, cpython.id if cpython else "", "", version,
                                   "rpm" if version else "",
                                   f"rpm {package}" if package else "builder image",
                                   "extension", len(members)))
            continue
        dist = _owner_wheel(members[0], wheels, entries)
        own = _own_wheel(entry, dist)
        rows.append(NativeFile(folder, entry.id if entry else "", "",
                               wheels[dist] if own else "", "wheel" if own else "",
                               f"wheel {dist} {wheels[dist]}" if dist else "bundle",
                               "extension", len(members)))

    for dist, comps in sorted(sboms.items()):
        for comp in comps:
            if (dist, comp) in used:
                continue
            entry = next((e for e in entries if _key(comp[0]) in (_key(e.id), _key(e.name))),
                         None)
            rows.append(NativeFile("", entry.id if entry else "", comp[0], comp[1], "sbom",
                                   f"wheel {dist} {wheels.get(dist, '')}".rstrip(), "static"))
    return rows


def version_conflicts(inventories: Mapping[str, Sequence[NativeFile]],
                      entries: Sequence[T.Entry]) -> list[str]:
    """Entries whose typed ``version`` matches none of the versions the
    binaries show for them (the soname does not count)."""
    seen: dict[str, list[str]] = {}
    for rows in inventories.values():
        for row in rows:
            if row.component and row.version and row.evidence not in ("soname", ""):
                version = row.version.split("-", 1)[0] if row.evidence in ("rpm", "sbom") \
                    else row.version
                seen.setdefault(row.component, []).append(version)
    out = []
    for entry in entries:
        versions = seen.get(entry.id)
        if not entry.version or not versions:
            continue
        typed = entry.version.split(" ", 1)[0]
        if not any(v == typed or v.startswith(typed + ".") or typed.startswith(v + ".")
                   for v in versions):
            out.append(f"{entry.id}: typed {entry.version}, the binary has "
                       f"{', '.join(sorted(set(versions)))}")
    return out


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------

def _short(flavor: str) -> str:
    return flavor.split("-", 1)[1] if "-" in flavor else flavor


def _component(row: NativeFile, by_id: Mapping[str, T.Entry]) -> str:
    entry = by_id.get(row.component)
    if entry:
        return T._link(entry)
    return T._cell(row.label).replace("[", "\\[").replace("]", "\\]")


def shown(row: NativeFile, by_id: Mapping[str, T.Entry]) -> tuple[str, str]:
    """(version, read from) as shown: a file the binaries tell no version of
    shows the one its entry types in third_party.json (``credits``)."""
    if row.version:
        return row.version, row.evidence
    entry = by_id.get(row.component)
    if entry and entry.version:
        return entry.version, "credits"
    return "", ""


def _file_cell(row: NativeFile, count: str) -> str:
    if row.kind == "static":
        return "linked into the wheel's modules"
    if row.kind == "extension":
        return f"`{T._cell(row.path)}` ({count} extension modules)"
    return f"`{T._cell(row.path)}`"


_ORDER = {"library": 0, "program": 2, "extension": 3, "static": 4}


def _sort_key(row: NativeFile):
    rank = _ORDER[row.kind] + (0 if row.shipped_by.startswith("rpm") or
                               row.shipped_by == "builder image" else 1) * (row.kind == "library")
    return (rank, row.shipped_by.casefold(), row.path.casefold(), row.label.casefold())


def _per_binary(values: Mapping[str, str]) -> str:
    distinct = set(values.values())
    if len(distinct) == 1:
        return T._cell(distinct.pop())
    return ", ".join(f"{T._cell(v)} ({_short(f)})" for f, v in values.items())


def render_files(inventories: Mapping[str, Sequence[NativeFile]],
                 entries: Sequence[T.Entry]) -> str:
    """The ``native-files`` block of THIRD_PARTY_LICENSES.md."""
    by_id = {e.id: e for e in entries}
    merged: dict[tuple, dict[str, NativeFile]] = {}
    for flavor, rows in inventories.items():
        for row in rows:
            key = (row.kind, row.path, row.component, row.label, row.shipped_by)
            merged.setdefault(key, {})[flavor] = row
    counts = []
    for flavor, rows in inventories.items():
        files = sum(r.count for r in rows if r.kind != "static")
        ext = sum(r.count for r in rows if r.kind == "extension")
        counts.append(f"`{flavor}` {files} ELF files ({ext} of them Python extension modules)")
    lines = [
        "<!-- Generated from the built binaries by `python scripts/native_inventory.py --write "
        "dist/axross-full dist/axross-slim`; tests/test_native_inventory.py fails at release "
        "time when it drifts. -->",
        "",
        "; ".join(counts) + ". *Read from*: `rpm` the builder image's package, `wheel` the "
        "library is the wheel's own, `sbom` the wheel's SBOM, `file` a version string in the "
        "file, `sibling` that string in the library of the same build next to it, `soname` "
        "only the ABI number of the file name, `credits` not in the binary: the version "
        "resources/credits/third_party.json names.",
        "",
    ]
    table = []
    for key, per in sorted(merged.items(), key=lambda kv: _sort_key(next(iter(kv[1].values())))):
        row = next(iter(per.values()))
        count = _per_binary({f: str(r.count) for f, r in per.items()})
        version = _per_binary({f: shown(r, by_id)[0] or "-" for f, r in per.items()})
        evidence = _per_binary({f: shown(r, by_id)[1] or "-" for f, r in per.items()})
        flavors = ", ".join(_short(f) for f in inventories if f in per)
        table.append((_file_cell(row, count), _component(row, by_id), version, evidence,
                      T._cell(row.shipped_by), flavors))
    lines.append(T._table(("File", "Component", "Version", "Read from", "Shipped by", "In"),
                          table))
    return "\n".join(lines)


def render_components(inventories: Mapping[str, Sequence[NativeFile]],
                      entries: Sequence[T.Entry]) -> str:
    """One row per native component with every version the binaries carry:
    the section of the release notes."""
    by_id = {e.id: e for e in entries}
    rows: dict[str, dict] = {}
    for flavor, inv in inventories.items():
        for row in inv:
            if row.kind == "extension":
                continue
            key = row.component or f"label:{row.label or row.path}"
            item = rows.setdefault(key, {"row": row, "versions": [], "in": []})
            version, evidence = shown(row, by_id)
            prefix = {"soname": "soname ", "credits": "credits "}.get(evidence, "")
            label = f"{prefix}{version or '-'} ({row.shipped_by})"
            if label not in item["versions"]:
                item["versions"].append(label)
            if flavor not in item["in"]:
                item["in"].append(flavor)
    table = []
    for key, item in sorted(rows.items(), key=lambda kv: _name(kv[1]["row"], by_id).casefold()):
        row = item["row"]
        name = _component(row, by_id) if (row.component or row.label) else \
            f"`{T._cell(row.path)}`"
        table.append((name, "; ".join(T._cell(v) for v in sorted(item["versions"])),
                      ", ".join(_short(f) for f in item["in"])))
    total = {f: sum(r.count for r in inv if r.kind != "static") for f, inv in inventories.items()}
    head = ", ".join(f"`{f}` {n} ELF files" for f, n in total.items())
    return (f"{NOTES_MARKER}\n{NOTES_HEADING}\n\n"
            f"{head}. A version marked *soname* is only the ABI number of the file name. "
            f"Every file with its version: THIRD_PARTY_LICENSES.md, "
            f"\"Native files inside the Linux binaries\".\n\n" +
            T._table(("Component", "Versions (shipped by)", "In"), table))


def _name(row: NativeFile, by_id: Mapping[str, T.Entry]) -> str:
    entry = by_id.get(row.component)
    return entry.name if entry else (row.label or row.path)


# --------------------------------------------------------------------------
# Built binaries and the command line
# --------------------------------------------------------------------------

class _BundleArchive:
    def __init__(self, path: Path):
        from PyInstaller.archive.readers import CArchiveReader

        self._reader = CArchiveReader(str(path))
        self.toc = [(entry[4] if len(entry) > 4 else "?", name)
                    for name, entry in self._reader.toc.items()]

    def read(self, name: str) -> bytes:
        if name not in self._reader.toc:
            raise KeyError(name)
        return self._reader.extract(name) or b""


def open_bundle(path: Path | str) -> Archive:
    return _BundleArchive(Path(path))


def _flavor(path: Path) -> str:
    return "axross-slim" if "slim" in path.name else "axross-full"


def main(argv: Sequence[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="scripts/native_inventory.py",
        description="List the native files of the Linux one-file binaries with their versions: "
                    "the native-files block of THIRD_PARTY_LICENSES.md and the release notes "
                    "section.")
    parser.add_argument("binaries", nargs="+", type=Path, help="dist/axross-full dist/axross-slim")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="exit 1 when the document drifted")
    mode.add_argument("--write", action="store_true", help="regenerate the block")
    mode.add_argument("--notes", type=Path, metavar="FILE",
                      help="write the release notes section to FILE")
    parser.add_argument("--root", type=Path, default=T.DATA_FILE.parent.parent.parent)
    args = parser.parse_args(argv)
    try:
        entries = T.load()
        inventories = {_flavor(p): inventory(open_bundle(p), entries) for p in args.binaries}
    except (T.DataError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    conflicts = version_conflicts(inventories, entries)
    for line in conflicts:
        print(f"version in third_party.json disagrees: {line}", file=sys.stderr)
    if args.notes:
        args.notes.write_text(render_components(inventories, entries) + "\n", encoding="utf-8")
        print(f"written: {args.notes}")
        return 1 if conflicts else 0
    doc = args.root / T.LICENSES_FILE
    current = doc.read_text(encoding="utf-8")
    wanted = T.replace_block(current, BLOCK, render_files(inventories, entries))
    if wanted is None:
        print(f"error: missing {T.block_begin(BLOCK)} markers in {doc}", file=sys.stderr)
        return 2
    if args.check:
        if wanted != current:
            print(f"out of date: {T.LICENSES_FILE} (run python scripts/native_inventory.py --write)")
            return 1
        return 1 if conflicts else 0
    if wanted != current:
        doc.write_text(wanted, encoding="utf-8")
        print(f"written: {doc}")
    return 1 if conflicts else 0


if __name__ == "__main__":
    raise SystemExit(main())
