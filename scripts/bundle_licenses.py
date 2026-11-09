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
  A build against a sysroot (scripts/build_dist.sh: ``AXROSS_TARGET_ROOT``
  is the root scripts/sysroot_fetch.py unpacked) has no package database:
  the root's FILES.json, written while unpacking, names the package of each
  file and the target's package format, which ``licenses/system/SYSTEM.txt``
  records (``rpm`` or ``deb``).
* a top-level library a wheel ships (libusb-package's libusb-1.0.so) is
  ``wheel:<distribution>`` in LIBRARIES.txt: its licence files are the
  wheel's, under ``licenses/python/``.
* the building interpreter's own libpython (python-build-standalone in a
  sysroot build; no package owns it) brings that interpreter's LICENSE.txt
  (and the notices of what is linked into it, where the installation has
  them): ``licenses/system/python/``, package ``python`` in LIBRARIES.txt.

tests/test_third_party_bundle.py checks a built binary for both.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath
from typing import Callable, Iterable, Mapping

#: File names that are licence material wherever they sit in a distribution.
LICENCE_NAME = re.compile(
    r"^(LICEN[CS]E|COPYING|NOTICE|COPYRIGHT|AUTHORS|THIRD[-_]?PARTY[-_]?NOTICES)([-._].*)?\Z",
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


#: Where a package keeps its licence texts, by package format: first what
#: rpm marks as licence (``%license``: /usr/share/licenses/<package>/) or
#: Debian's copyright file, then documentation named like a licence.
_DEB_COPYRIGHT = re.compile(r"^usr/share/doc/[^/]+/copyright\Z")


class TargetPackages:
    """The packages of a sysroot (scripts/sysroot_fetch.py), from its
    FILES.json: ``{"system", "files": {path: package}, "packages":
    {package: {"version", "source"}}}`` with paths relative to *root*."""

    def __init__(self, root: str | os.PathLike, manifest: Mapping):
        self.root = os.path.abspath(root)
        self.system = str(manifest.get("system") or "")
        self.files: dict[str, str] = dict(manifest.get("files") or {})
        self.packages: dict[str, dict] = dict(manifest.get("packages") or {})
        self.format = "deb" if self.system.startswith("debian") else "rpm"
        self._owned: dict[str, list[str]] = {}
        for path, package in sorted(self.files.items()):
            self._owned.setdefault(package, []).append(path)

    @classmethod
    def load(cls, root: str | os.PathLike) -> "TargetPackages":
        """The packages of *root*; its FILES.json is next to it."""
        import json

        path = os.path.join(os.path.dirname(os.path.abspath(root)), "FILES.json")
        with open(path, encoding="utf-8") as fh:
            return cls(root, json.load(fh))

    @classmethod
    def from_environment(cls) -> "TargetPackages | None":
        """The packages of ``AXROSS_TARGET_ROOT``, None without it. A root
        without FILES.json stops the build: its libraries would go out
        without their licence texts."""
        root = os.environ.get("AXROSS_TARGET_ROOT", "")
        if not root:
            return None
        manifest = os.path.join(os.path.dirname(os.path.abspath(root)), "FILES.json")
        if not os.path.isfile(manifest):
            raise SystemExit(f"AXROSS_TARGET_ROOT={root}: no {manifest} - unpack the root "
                             "with scripts/sysroot_fetch.py, which writes it")
        return cls.load(root)

    # -- paths ----------------------------------------------------------------------------

    def _inside(self, rel: str, links: list[str] | None = None, depth: int = 0) -> str | None:
        """*rel* (relative to the root) with every symlink resolved as in a
        chroot of the root; None when it leaves the root or loops. The
        symlinks met as the last part go to *links*, in order."""
        done: list[str] = []
        parts = [p for p in rel.split("/") if p not in ("", ".")]
        for n, part in enumerate(parts):
            if part == "..":
                if not done:
                    return None
                done.pop()
                continue
            here = "/".join(done + [part])
            full = os.path.join(self.root, here)
            if not os.path.islink(full):
                done.append(part)
                continue
            if depth > 40:
                return None
            last = n == len(parts) - 1
            if last and links is not None:
                links.append(here)
            link = os.readlink(full)
            base = "" if link.startswith("/") else "/".join(done)
            resolved = self._inside(f"{base}/{link}", links if last else None, depth + 1)
            if resolved is None:
                return None
            done = resolved.split("/") if resolved else []
        return "/".join(done)

    def relative(self, source: str) -> tuple[str, list[str]] | None:
        """(*source* resolved inside the root, the symlinks on the way) for
        a file of the root - also one reached through a symlink from outside
        (build_dist.sh's library folder) - or None."""
        path = os.path.abspath(str(source))
        roots = {self.root, os.path.realpath(self.root)}
        for _hop in range(41):
            for root in roots:
                if path == root or path.startswith(root + os.sep):
                    links: list[str] = []
                    rel = os.path.relpath(path, root).replace(os.sep, "/")
                    found = self._inside(rel, links)
                    return (found, links) if found else None
            if not os.path.islink(path):
                break
            path = os.path.normpath(os.path.join(os.path.dirname(path), os.readlink(path)))
        return None

    def contains(self, source: str) -> bool:
        return self.relative(source) is not None

    # -- packages -------------------------------------------------------------------------

    def package(self, source: str) -> str | None:
        """The package that installed *source* (the file it resolves to,
        else the first symlink on the way that a package installed)."""
        found = self.relative(source)
        if not found:
            return None
        final, links = found
        for rel in [final, *links]:
            if rel in self.files:
                return self.files[rel]
        return None

    def version(self, package: str) -> str | None:
        value = str((self.packages.get(package) or {}).get("version") or "")
        return value if value and " " not in value else None

    def _licences(self, package: str, kind: int) -> list[str]:
        out: list[str] = []
        for rel in self._owned.get(package, ()):
            if kind == 0:
                wanted = _DEB_COPYRIGHT.match(rel) if self.format == "deb" else \
                    rel.startswith("usr/share/licenses/")
            else:
                wanted = rel.startswith("usr/share/doc/") and \
                    LICENCE_NAME.match(rel.rsplit("/", 1)[-1])
            if not wanted:
                continue
            real = self._inside(rel)
            path = os.path.join(self.root, real) if real else ""
            if path and os.path.isfile(path) and path not in out:
                out.append(path)
        return out

    def licence_files(self, package: str) -> list[str]:
        """As :func:`rpm_licence_files` for an installed package: *package*'s
        own licence files (rpm: /usr/share/licenses/, deb: its copyright
        file), else those of the root's packages built from the same source
        package, else documentation named like a licence the same way."""
        source = (self.packages.get(package) or {}).get("source") or ""
        siblings = sorted(name for name, meta in self.packages.items()
                          if name != package and source and (meta or {}).get("source") == source)
        for kind in (0, 1):
            files = self._licences(package, kind)
            if files:
                return files
            for sibling in siblings:
                files += [f for f in self._licences(sibling, kind) if f not in files]
            if files:
                return files
        return []


#: LIBRARIES.txt's package and the licences/system/ folder of a libpython
#: that is the building interpreter's own (python-build-standalone, which
#: scripts/build_dist.sh builds with through uv), not a system package's.
BUILD_PYTHON = "python"


class BuildPython:
    """The interpreter that runs the build: its installation folder, its
    standard library folder (CPython's LICENSE.txt is there) and version."""

    def __init__(self, prefix: str, stdlib: str, version: str, notices: str = ""):
        self.prefix, self.stdlib, self.version = prefix, stdlib, version
        #: PYTHON.json and licenses/ of the full python-build-standalone
        #: archive of this build (scripts/python_licences.py), or ""
        self.notices = notices

    @classmethod
    def current(cls) -> "BuildPython":
        import platform
        import sysconfig

        return cls(sys.base_prefix, sysconfig.get_path("stdlib"), platform.python_version(),
                   os.environ.get("AXROSS_PYTHON_LICENSES", ""))

    def owns(self, dest: str, source: str) -> bool:
        """*source* is this interpreter's libpython (also through a symlink;
        uv's cpython-3.12-... folder is a link to cpython-3.12.8-...)."""
        if not os.path.basename(dest).startswith("libpython"):
            return False
        prefixes = {os.path.abspath(self.prefix), os.path.realpath(self.prefix)}
        for path in {os.path.abspath(source), os.path.realpath(source)}:
            if any(path.startswith(p.rstrip(os.sep) + os.sep) for p in prefixes):
                return True
        return False

    def licence_files(self) -> list[tuple[str, str]]:
        """(file, bundle folder): CPython's LICENSE.txt, and the notices of
        the parts linked into it: PYTHON.json (its "licenses" and
        "license_paths" fields name them) and licenses/ - from *notices*
        (build_dist.sh: the full archive of the build, which
        scripts/python_licences.py fetched) or from next to the
        installation (a full archive's python/install/); uv's installation
        has neither. *notices* of another CPython version stop the build."""
        out: list[tuple[str, str]] = []
        folder = f"licenses/system/{BUILD_PYTHON}"
        licence = os.path.join(self.stdlib, "LICENSE.txt")
        if os.path.isfile(licence):
            out.append((licence, folder))
        if self.notices:
            import json

            meta = os.path.join(self.notices, "PYTHON.json")
            try:
                with open(meta, encoding="utf-8") as fh:
                    built = json.load(fh).get("python_version")
            except (OSError, ValueError):
                raise SystemExit(f"AXROSS_PYTHON_LICENSES={self.notices}: no readable "
                                 "PYTHON.json (scripts/python_licences.py writes it)") from None
            if built != self.version:
                raise SystemExit(f"AXROSS_PYTHON_LICENSES={self.notices} is of CPython {built}, "
                                 f"the build runs {self.version}")
        bases = [self.notices] if self.notices else []
        for base in bases + [self.prefix, os.path.dirname(os.path.abspath(self.prefix))]:
            meta = os.path.join(base, "PYTHON.json")
            if not os.path.isfile(meta):
                continue
            out.append((meta, folder))  # the first one only: one build, one set of notices
            notices = os.path.join(base, "licenses")
            if os.path.isdir(notices):
                for name in sorted(os.listdir(notices)):
                    path = os.path.join(notices, name)
                    if os.path.isfile(path):
                        out.append((path, f"{folder}/licenses"))
            break
        return out


#: LIBRARIES.txt's package of a top-level library a wheel ships
#: (``wheel:<distribution>``, the wheel's version): its licence files are the
#: wheel's, under licenses/python/<distribution>-<version>/.
WHEEL_PREFIX = "wheel:"
#: Wheels that ship someone else's library without that library's licence:
#: distribution -> (folder below its licence folder, tracked texts). The
#: libusb-package wheel carries only its own Apache-2.0 text, not libusb's
#: LGPL-2.1 (build/licenses/libusb/: COPYING and AUTHORS of libusb v1.0.26,
#: the version its libusb-1.0.so is built from).
WHEEL_LIBRARY_NOTICES = {
    "libusb-package": ("libusb", ("build/licenses/libusb/COPYING",
                                  "build/licenses/libusb/AUTHORS")),
}
PROJECT_ROOT = Path(__file__).resolve().parent.parent


def wheel_library_owner(distributions: Iterable | None = None
                        ) -> Callable[[str], tuple[str, str] | None]:
    """A lookup: shared library file -> (distribution, version) of the
    installed distribution whose files hold it (``importlib.metadata``
    objects; default: every installed one, read on the first question)."""
    index: dict[str, tuple[str, str]] | None = None

    def owner(source: str) -> tuple[str, str] | None:
        nonlocal index
        if index is None:
            import importlib.metadata as metadata

            index = {}
            for dist in (metadata.distributions() if distributions is None else distributions):
                name = dist.metadata["Name"] if dist.metadata else None
                if not name:
                    continue
                for path in dist.files or ():
                    if path.name.endswith(".so") or ".so." in path.name:
                        index[os.path.realpath(str(path.locate()))] = (_normalise(name),
                                                                       dist.version)
        return index.get(os.path.realpath(str(source)))
    return owner


def wheel_library_notices(dist: str, version: str) -> list[tuple[str, str]]:
    """The tracked licence texts of the library *dist*'s wheel ships
    without them (:data:`WHEEL_LIBRARY_NOTICES`); a missing one stops the
    build."""
    if dist not in WHEEL_LIBRARY_NOTICES:
        return []
    folder, files = WHEEL_LIBRARY_NOTICES[dist]
    out = []
    for rel in files:
        path = PROJECT_ROOT / rel
        if not path.is_file():
            raise SystemExit(f"{rel} is missing: the licence of the library {dist} ships")
        out.append((str(path), f"licenses/python/{dist}-{version}/{folder}"))
    return out


def system_licence_datas(binaries: Iterable[tuple],
                         query: Callable[[str], str | None] = rpm_package,
                         licence_files: Callable[[str], list[str]] = rpm_licence_files,
                         version: Callable[[str], str | None] = rpm_version,
                         target: TargetPackages | None = None,
                         python: BuildPython | None = None,
                         wheels: Callable[[str], tuple[str, str] | None] | None = None,
                         ) -> tuple[list[tuple[str, str]], list[str]]:
    """Licence files for the top-level shared libraries in *binaries* (the
    PyInstaller TOC: dest, source, typecode) that come from the system, and
    the LIBRARIES.txt lines (``<library>\\t<package or ->\\t<version or ->``).
    With *target* (a sysroot build) the system is that root: a library
    counts when its source resolves into the root, and the root's FILES.json
    answers instead of rpm. A libpython no package owns that is the
    building interpreter's (*python*, default: this one) is listed as
    package ``python`` with that interpreter's version and licence files.
    A top-level library a wheel ships (*wheels*: its owner lookup, default
    :func:`wheel_library_owner`) is ``wheel:<distribution>`` with the
    wheel's version; its licence files are the wheel's (plus
    :data:`WHEEL_LIBRARY_NOTICES`)."""
    if target is not None:
        query, licence_files, version = target.package, target.licence_files, target.version
    datas: list[tuple[str, str]] = []
    manifest: list[str] = []
    done: set[str] = set()
    versions: dict[str, str] = {}
    for dest, source, *_ in binaries:
        if "/" in dest or not os.path.basename(dest).startswith("lib"):
            continue
        in_system = target.contains(str(source)) if target is not None else \
            str(source).startswith(SYSTEM_LIBRARY_DIRS)
        package = query(str(source)) if in_system else None
        if not package and os.path.basename(dest).startswith("libpython"):
            python = python or BuildPython.current()
            if python.owns(dest, str(source)):
                manifest.append(f"{dest}\t{BUILD_PYTHON}\t{python.version}")
                if BUILD_PYTHON not in done:
                    done.add(BUILD_PYTHON)
                    datas += python.licence_files()
                continue
        if not in_system:
            wheels = wheels or wheel_library_owner()
            owner = wheels(str(source))
            if owner:
                dist, wheel_version = owner
                manifest.append(f"{dest}\t{WHEEL_PREFIX}{dist}\t{wheel_version or '-'}")
                if WHEEL_PREFIX + dist not in done:
                    done.add(WHEEL_PREFIX + dist)
                    datas += wheel_library_notices(dist, wheel_version)
            continue
        if package and package not in versions:
            versions[package] = version(package) or "-"
        manifest.append(f"{dest}\t{package or '-'}\t{versions.get(package or '', '-')}")
        if not package or package in done:
            continue
        done.add(package)
        used: set[str] = set()
        for file in licence_files(package):
            name = os.path.basename(file)
            folder = f"licenses/system/{package}"
            if name in used:  # two LICENSE files: keep them apart by their folder
                folder += "/" + os.path.basename(os.path.dirname(file))
            used.add(name)
            datas.append((file, folder))
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
    target = TargetPackages.from_environment()
    system, manifest = system_licence_datas(analysis.binaries, target=target)
    # the wheels whose libraries the bundle carries at its top level bring
    # their licence files too, also when no module of theirs is bundled
    have = {_normalise(d.metadata["Name"]) for d in dists}
    for line in manifest:
        package = line.split("\t")[1]
        if package.startswith(WHEEL_PREFIX) and package[len(WHEEL_PREFIX):] not in have:
            try:
                dists.append(metadata.distribution(package[len(WHEEL_PREFIX):]))
            except metadata.PackageNotFoundError:
                continue
            have.add(package[len(WHEEL_PREFIX):])
    pairs = python_licence_datas(dists) + system
    os.makedirs(workdir, exist_ok=True)
    listing = os.path.join(workdir, "LIBRARIES.txt")
    with open(listing, "w", encoding="utf-8") as fh:
        fh.write("".join(f"{line}\n" for line in manifest))
    toc = [(f"{folder}/{os.path.basename(src)}", src, "DATA") for src, folder in pairs]
    toc.append(("licenses/system/LIBRARIES.txt", listing, "DATA"))
    if target is not None:  # the package format: scripts/native_inventory.py
        kind = os.path.join(workdir, "SYSTEM.txt")
        with open(kind, "w", encoding="utf-8") as fh:
            fh.write(f"{target.format}\t{target.system}\n")
        toc.append(("licenses/system/SYSTEM.txt", kind, "DATA"))
    return toc
