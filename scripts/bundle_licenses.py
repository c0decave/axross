"""Licence texts for everything a one-file bundle carries (build/axross.spec).

Two sources, both read at build time inside the builder image:

* every Python distribution in the bundle brings its own licence files
  (``*.dist-info/licenses/``, ``LICENSE*``/``COPYING*``/``NOTICE*`` files of
  the package, and the wheel's SBOMs); they go to
  ``licenses/python/<name>-<version>/``. A wheel that vendors native
  libraries (Pillow, PyAV, numpy, ...) lists their licences there too.
* every shared library the builder system contributes (a top-level library
  copied from /usr/lib64 and friends) brings the licence files of its rpm
  package: ``licenses/system/<package>/``, and a line in
  ``licenses/system/LIBRARIES.txt`` names the package and its
  version-release for each library (scripts/native_inventory.py reads it).

tests/test_third_party_bundle.py checks a built binary for both.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path, PurePosixPath
from typing import Callable, Iterable, Mapping

#: File names that are licence material wherever they sit in a distribution.
LICENCE_NAME = re.compile(
    r"^(LICEN[CS]E|COPYING|NOTICE|COPYRIGHT|AUTHORS|THIRD[-_]?PARTY[-_]?NOTICES)([-._].*)?$",
    re.IGNORECASE)
SYSTEM_LIBRARY_DIRS = ("/usr/lib64/", "/lib64/", "/usr/lib/", "/lib/")


def _normalise(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _licence_dest(path: PurePosixPath) -> str | None:
    """Folder below the distribution's licence folder for a file of it, or
    None when the file is no licence material."""
    parts = path.parts
    if path.suffix in (".py", ".pyc") or "__pycache__" in parts:
        return None
    for i, part in enumerate(parts[:-1]):
        if part.endswith(".dist-info"):
            rest = parts[i + 1:]
            if len(rest) >= 2 and rest[0] == "licenses":
                return "/".join(rest[1:-1])
            if len(rest) >= 2 and rest[0] == "sboms":
                return "/".join(rest[:-1])
            break
    if not LICENCE_NAME.match(path.name):
        return None
    if ".." in parts or any(p.endswith(".dist-info") for p in parts):
        return ""
    return "/".join(parts[:-1])


def python_licence_datas(distributions: Iterable) -> list[tuple[str, str]]:
    """(source file, bundle folder) for the licence files of *distributions*
    (``importlib.metadata.Distribution`` objects). Files that are listed but
    missing on disk are skipped."""
    datas: list[tuple[str, str]] = []
    for dist in distributions:
        name = _normalise(dist.metadata["Name"])
        base = f"licenses/python/{name}-{dist.version}"
        for path in dist.files or ():
            sub = _licence_dest(PurePosixPath(str(path)))
            if sub is None:
                continue
            source = Path(path.locate())
            if not source.is_file():
                continue
            datas.append((str(source), f"{base}/{sub}" if sub else base))
    return sorted(set(datas))


def distribution_names(top_names: Iterable[str],
                       mapping: Mapping[str, list[str]] | None = None) -> list[str]:
    """The distributions that provide *top_names* (import names, top level),
    per ``importlib.metadata.packages_distributions()``."""
    if mapping is None:
        import importlib.metadata as metadata

        mapping = metadata.packages_distributions()
    names = {dist for top in top_names for dist in mapping.get(top, ())}
    return sorted(names)


def _rpm(args: list[str]) -> str | None:
    """stdout of ``rpm <args>``, or None when rpm is missing or fails."""
    try:
        result = subprocess.run(["rpm", *args], capture_output=True, text=True, timeout=60,
                                check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout if result.returncode == 0 else None


def rpm_package(path: str, run: Callable[[list[str]], str | None] = _rpm) -> str | None:
    """The rpm package that owns *path*, or None (not owned, no rpm)."""
    out = (run(["-qf", "--qf", "%{NAME}\n", path]) or "").strip().splitlines()
    name = out[0].strip() if out else ""
    return name if name and " " not in name else None


def rpm_version(package: str, run: Callable[[list[str]], str | None] = _rpm) -> str | None:
    """``VERSION-RELEASE`` of the installed *package*, or None."""
    out = (run(["-q", "--qf", "%{VERSION}-%{RELEASE}\n", package]) or "").strip().splitlines()
    value = out[0].strip() if out else ""
    return value if value and " " not in value else None


def rpm_licence_files(package: str, run: Callable[[list[str]], str | None] = _rpm) -> list[str]:
    """The licence files of *package* that exist: what ``rpm -qL`` marks as
    licence, else the documentation files (``rpm -qd``) named like a licence
    (COPYING, LICENSE, ...). A package without either - a library
    sub-package often leaves the licence to a sibling - gets those of the
    installed packages built from the same source rpm."""

    def listed(name: str, flag: str) -> list[str]:
        out = run([flag, name]) or ""
        return [line for line in out.splitlines() if line.startswith("/")
                and (flag == "-qL" or LICENCE_NAME.match(os.path.basename(line)))
                and os.path.isfile(line)]

    source = None
    for flag in ("-qL", "-qd"):
        files = listed(package, flag)
        if files:
            return files
        if source is None:
            source = (run(["-q", "--qf", "%{SOURCERPM}", package]) or "").strip()
            siblings = []
            if source:
                for line in (run(["-qa", "--qf", "%{NAME} %{SOURCERPM}\n"]) or "").splitlines():
                    name, _, src = line.partition(" ")
                    if src.strip() == source and name != package:
                        siblings.append(name)
        files = []
        for sibling in sorted(siblings):
            files += [f for f in listed(sibling, flag) if f not in files]
        if files:
            return files
    return []


def system_licence_datas(binaries: Iterable[tuple],
                         query: Callable[[str], str | None] = rpm_package,
                         licence_files: Callable[[str], list[str]] = rpm_licence_files,
                         version: Callable[[str], str | None] = rpm_version,
                         ) -> tuple[list[tuple[str, str]], list[str]]:
    """Licence files for the top-level shared libraries in *binaries* (the
    PyInstaller TOC: dest, source, typecode) that come from the system, and
    the LIBRARIES.txt lines (``<library>\\t<package or ->\\t<version or ->``)."""
    datas: list[tuple[str, str]] = []
    manifest: list[str] = []
    done: set[str] = set()
    versions: dict[str, str] = {}
    for dest, source, *_ in binaries:
        if "/" in dest or not os.path.basename(dest).startswith("lib"):
            continue
        if not str(source).startswith(SYSTEM_LIBRARY_DIRS):
            continue
        package = query(str(source))
        if package and package not in versions:
            versions[package] = version(package) or "-"
        manifest.append(f"{dest}\t{package or '-'}\t{versions.get(package or '', '-')}")
        if not package or package in done:
            continue
        done.add(package)
        used: set[str] = set()
        for file in licence_files(package):
            name = os.path.basename(file)
            target = f"licenses/system/{package}"
            if name in used:  # two LICENSE files: keep them apart by their folder
                target += "/" + os.path.basename(os.path.dirname(file))
            used.add(name)
            datas.append((file, target))
    return datas, sorted(manifest)


def licence_datas(analysis, workdir: str) -> list[tuple[str, str, str]]:
    """TOC entries (dest, source, "DATA") with every licence text for the
    contents of *analysis* (a PyInstaller Analysis after its filters), plus
    ``licenses/system/LIBRARIES.txt`` written into *workdir*."""
    tops: set[str] = set()
    for name, *_ in analysis.pure:
        tops.add(name.split(".", 1)[0])
    for dest, *_ in list(analysis.binaries) + list(analysis.datas):
        first = dest.replace("\\", "/").split("/", 1)[0]
        tops.add(first.split(".", 1)[0] if "/" not in dest.replace("\\", "/") else first)
    import importlib.metadata as metadata

    dists = []
    for name in distribution_names(tops):
        try:
            dists.append(metadata.distribution(name))
        except metadata.PackageNotFoundError:
            continue
    pairs = python_licence_datas(dists)
    system, manifest = system_licence_datas(analysis.binaries)
    pairs += system
    os.makedirs(workdir, exist_ok=True)
    listing = os.path.join(workdir, "LIBRARIES.txt")
    with open(listing, "w", encoding="utf-8") as fh:
        fh.write("".join(f"{line}\n" for line in manifest))
    toc = [(f"{folder}/{os.path.basename(src)}", src, "DATA") for src, folder in pairs]
    toc.append(("licenses/system/LIBRARIES.txt", listing, "DATA"))
    return toc
