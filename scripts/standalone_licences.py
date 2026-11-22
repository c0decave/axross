#!/usr/bin/env python3
"""The licences of what an exported tool's one-file programs contain: ``standalone_licences.py APP --refresh``.

The release workflow of an exported tool (scripts/export_standalone.py APP, its repo's
.github/workflows/release.yml) builds one-file programs with PyInstaller from the tool's hashed lock
(build/requirements-standalone-APP.txt, written into the export as requirements.lock.txt): they carry
every package of that lock but the build backend (BUILD_ONLY). axross-markdown's carry PyQt6 (GPL-3.0)
and Qt (LGPL-3.0), so each is a combined work under the GPL-3.0 and must come with the licence texts,
the notices and where the source code is.

``--refresh`` takes the licence files of each pin - as scripts/bundle_licenses.py takes them for
axross's own binaries: the dist-info's licenses/ folder, LICENSE* / COPYING* / NOTICE* - out of one of
the very files the lock pins (a wheel from PyPI, its SHA-256 checked against the lock before it is
opened) into build/licenses/standalone-APP/<name>-<version>/, and records the package's name, licence
(axross's resources/credits/third_party.json where it has the package, else the wheel's metadata) and
upstream in packages.json there. The export (render) writes them into the tool's
THIRD_PARTY_LICENSES.txt - inside its package, so the program shows it (Help > About) and the
binaries carry it - and refuses a pin of the lock that has no texts of its own version: after
scripts/lock_standalone_deps.sh APP, run this again and review the new texts.
"""

from __future__ import annotations

import argparse
import email.parser
import hashlib
import io
import json
import re
import sys
import textwrap
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]

#: Pins of a lock that build the sdist and wheel and are not inside the programs (export_standalone.BUILD_REQUIRES).
BUILD_ONLY = frozenset({"setuptools"})
#: Texts a program with PyQt6 and Qt must carry: (pin, what its texts must hold).
REQUIRED = (("pyqt6", "GNU GENERAL PUBLIC LICENSE"), ("pyqt6-qt6", "GNU LESSER GENERAL PUBLIC LICENSE"))
#: Largest file downloaded (PyQt6-Qt6's wheels are ~90 MB).
MAX_DOWNLOAD = 400 * 1024 * 1024
#: Licence classifiers as SPDX identifiers (a wheel without License-Expression).
CLASSIFIERS = {"MIT License": "MIT", "Apache Software License": "Apache-2.0", "ISC License (ISCL)": "ISC",
               "Python Software Foundation License": "PSF-2.0"}
#: Largest licence file kept.
MAX_TEXT = 1024 * 1024


class LicenceError(SystemExit):
    """The texts are missing or do not match the lock."""


def texts_dir(name: str) -> Path:
    return ROOT / "build" / "licenses" / f"standalone-{name}"


def normalise(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def pins(lock: str) -> list[tuple[str, str, list[str]]]:
    """(name, version, sha256s) of each pin of *lock* (a uv lock: ``name==version [; marker] \\`` and
    its ``--hash=sha256:`` lines)."""
    found: list[tuple[str, str, list[str]]] = []
    for line in lock.splitlines():
        pin = re.match(r"^([A-Za-z0-9][A-Za-z0-9_.-]*)==([^\s;\\]+)", line)
        if pin:
            found.append((normalise(pin.group(1)), pin.group(2), []))
            continue
        digest = re.match(r"^\s+--hash=sha256:([0-9a-f]{64})", line)
        if digest and found:
            found[-1][2].append(digest.group(1))
    return found


def _get(url: str, limit: int) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "axross-standalone-licences/1"})
    with urllib.request.urlopen(request, timeout=120) as response:  # noqa: S310 - https://pypi.org only
        data = response.read(limit + 1)
    if len(data) > limit:
        raise LicenceError(f"standalone_licences: {url} is larger than {limit} bytes")
    return data


def _choose(files: list[dict], hashes: list[str]) -> dict:
    """The file of a release to read the texts from: a wheel the lock pins - pure, else Linux x86_64,
    else any."""
    wheels = [f for f in files if f.get("packagetype") == "bdist_wheel"
              and f.get("digests", {}).get("sha256") in hashes]
    if not wheels:
        raise LicenceError("standalone_licences: no wheel of the lock's hashes on PyPI")

    def rank(f: dict) -> tuple[int, int, str]:
        name = f["filename"]
        return ("-none-any." not in name, not ("manylinux" in name and "x86_64" in name), name)

    return sorted(wheels, key=rank)[0]


def _axross_imports():
    """scripts/bundle_licenses.py's choice of licence files (the same as axross's binaries') and
    core.third_party - only for --refresh (the export imports nothing of axross's through this module)."""
    for folder in (str(ROOT), str(ROOT / "scripts")):
        if folder not in sys.path:
            sys.path.insert(0, folder)
    from bundle_licenses import _licence_dest
    from core import third_party

    return _licence_dest, third_party


def _credits() -> dict[str, tuple[str, str]]:
    """axross's third-party data: normalised PyPI name -> (licence, upstream)."""
    _dest, third_party = _axross_imports()

    found: dict[str, tuple[str, str]] = {}
    for entry in third_party.load():
        for pypi in entry.pypi:
            found.setdefault(normalise(pypi), (entry.license, entry.url))
    return found


def _metadata_licence(meta) -> str:
    expression = (meta.get("License-Expression") or "").strip()
    if expression:
        return expression
    licence = (meta.get("License") or "").strip()
    if licence and "\n" not in licence and len(licence) < 80:
        return licence
    classifiers = [CLASSIFIERS.get(c.split("::")[-1].strip(), c.split("::")[-1].strip())
                   for c in meta.get_all("Classifier") or [] if c.startswith("License ::")]
    return " / ".join(classifiers) or "see its licence text"


def _metadata_url(meta, name: str) -> str:
    for value in meta.get_all("Project-URL") or []:
        label, _, url = value.partition(",")
        if label.strip().lower() in ("homepage", "source", "repository", "source code", "code"):
            return url.strip()
    return (meta.get("Home-page") or "").strip() or f"https://pypi.org/project/{name}/"


def refresh(name: str, lock: str, get=_get) -> list[str]:
    """Write build/licenses/standalone-NAME/ for the pins of *lock*; the folders written."""
    out = texts_dir(name)
    _licence_dest, _third_party = _axross_imports()
    credits = _credits()
    packages, written = [], []
    for pin, version, hashes in pins(lock):
        if pin in BUILD_ONLY:
            continue
        release = json.loads(get(f"https://pypi.org/pypi/{pin}/{version}/json", 16 * 1024 * 1024))
        chosen = _choose(release.get("urls", []), hashes)
        data = get(chosen["url"], MAX_DOWNLOAD)
        if hashlib.sha256(data).hexdigest() not in hashes:  # (before anything of it is read)
            raise LicenceError(f"standalone_licences: {chosen['filename']} is not a file the lock pins")
        folder = out / f"{pin}-{version}"
        texts, meta = [], None
        with zipfile.ZipFile(io.BytesIO(data)) as wheel:
            for info in wheel.infolist():
                member = PurePosixPath(info.filename)
                if info.is_dir() or ".." in member.parts or member.is_absolute():
                    continue
                if member.name == "METADATA" and len(member.parts) == 2 and member.parts[0].endswith(".dist-info"):
                    meta = email.parser.Parser().parsestr(wheel.read(info).decode("utf-8", "replace"))
                    continue
                sub = _licence_dest(member)
                if sub is None or sub.split("/")[0] == "sboms" or info.file_size > MAX_TEXT:
                    continue  # (a wheel's SBOMs are data, not licence texts)
                target = PurePosixPath(sub) / member.name if sub else PurePosixPath(member.name)
                texts.append((target.as_posix(), wheel.read(info)))
        if meta is None:
            raise LicenceError(f"standalone_licences: {chosen['filename']} has no METADATA")
        if not texts:
            raise LicenceError(f"standalone_licences: {chosen['filename']} carries no licence file")
        if folder.exists():
            for old in sorted(folder.rglob("*"), reverse=True):
                old.unlink() if old.is_file() else old.rmdir()
        for rel, content in texts:
            (folder / rel).parent.mkdir(parents=True, exist_ok=True)
            (folder / rel).write_bytes(content)
        licence, url = credits.get(pin, ("", ""))
        packages.append({"pin": pin, "name": meta.get("Name", pin), "version": version,
                         "license": licence or _metadata_licence(meta),
                         "url": url or _metadata_url(meta, pin),
                         "from": chosen["filename"], "sha256": hashlib.sha256(data).hexdigest(),
                         "texts": sorted(rel for rel, _ in texts)})
        written.append(folder.name)
    out.mkdir(parents=True, exist_ok=True)
    keep = {p["pin"] + "-" + p["version"] for p in packages}
    for old in out.iterdir():  # (the texts of versions the lock no longer pins)
        if old.is_dir() and old.name not in keep:
            for item in sorted(old.rglob("*"), reverse=True):
                item.unlink() if item.is_file() else item.rmdir()
            old.rmdir()
    (out / "packages.json").write_text(json.dumps({"packages": packages}, indent=1) + "\n", encoding="utf-8")
    return written


def bundled(name: str, lock: str) -> list[dict]:
    """The packages of the programs (the pins of *lock* but BUILD_ONLY) with their texts' folder, as
    --refresh recorded them; a LicenceError when one is missing or of another version."""
    out = texts_dir(name)
    try:
        recorded = {p["pin"]: p for p in json.loads((out / "packages.json").read_text(encoding="utf-8"))["packages"]}
    except (OSError, ValueError, KeyError) as exc:
        raise LicenceError(f"export: no licence texts for {name} ({exc}) - run "
                           f"scripts/standalone_licences.py {name} --refresh") from None
    found = []
    for pin, version, _hashes in pins(lock):
        if pin in BUILD_ONLY:
            continue
        package = recorded.get(pin)
        if package is None or package["version"] != version or not (out / f"{pin}-{version}").is_dir():
            raise LicenceError(f"export: no licence texts of {pin} {version} (the lock's pin) - run "
                               f"scripts/standalone_licences.py {name} --refresh and review them")
        found.append(dict(package, folder=out / f"{pin}-{version}"))
    for pin, needle in REQUIRED:
        package = next((p for p in found if p["pin"] == pin), None)
        if package is not None and not any(needle in (package["folder"] / rel).read_text("utf-8", "replace")
                                           for rel in package["texts"]):
            raise LicenceError(f"export: the licence texts of {pin} hold no {needle}")
    return found


def _pin_of(lock: str, name: str) -> str:
    return next((version for pin, version, _h in pins(lock) if pin == name), "")


def _wrap(text: str, bullet: bool = False) -> list[str]:
    """*text* as lines of at most 78 columns (addresses never broken); a bullet's go on indented."""
    return textwrap.wrap(text, 78, break_long_words=False, break_on_hyphens=False,
                         initial_indent="* " if bullet else "", subsequent_indent="  " if bullet else "")


def render(name: str, *, title: str, version: str, repo: str, axross: str, lock: str,
           pyinstaller_lock: str = "", licence: str = "", notice: str = "") -> str:
    """The tool's THIRD_PARTY_LICENSES.txt: what its programs contain, under which licence, where the
    source code is, the licence texts; *licence* and *notice* - the tool's own LICENSE and NOTICE -
    at the end."""
    packages = bundled(name, lock)
    qt, pyqt = _pin_of(lock, "pyqt6-qt6"), _pin_of(lock, "pyqt6")
    pyinstaller = _pin_of(pyinstaller_lock, "pyinstaller")
    minor = ".".join(qt.split(".")[:2])
    sdist = f"{re.sub(r'[-.]+', '_', title)}-{version}.tar.gz"
    rule = "=" * 78
    lines = [f"{title} {version}: licences and source code", rule, ""]

    def paragraph(text: str) -> None:
        lines.extend(_wrap(text) + [""])

    def bullets(*items: str) -> None:
        for item in items:
            lines.extend(_wrap(item, bullet=True))
        lines.append("")

    def heading(text: str) -> None:
        lines.extend([text, "-" * len(text), ""])

    paragraph(f"{title} - its own code and the code of axross ({axross}) it is written out from - is "
              "licensed under the Apache License, Version 2.0 (its LICENSE and NOTICE are at the end of "
              "this file).")
    paragraph("The pip packages (the wheel and the sdist) hold only that code: pip installs the packages it "
              "needs beside it, each under its own licence.")
    heading("The one-file programs")
    paragraph(f"The programs of the releases ({repo}/releases) - for Linux (also as an AppImage), macOS "
              "(also as a disk image) and Windows - contain a Python interpreter, PyInstaller's bootloader "
              "and the packages listed below. They contain PyQt6, licensed under the GNU General Public "
              "License version 3 (GPL-3.0-only), and Qt, licensed under the GNU Lesser General Public "
              "License version 3 (LGPL-3.0-only): each such program is a combined work and is distributed "
              "under the terms of the GPL-3.0. The Apache-2.0 code in it may be distributed under the "
              "GPL-3.0 and keeps its own licence when taken on its own; every package in it keeps its own "
              "licence, whose text is below. (axross-mdcat-windows-x64.exe, the terminal view, contains "
              "neither PyQt6 nor Qt.)")
    paragraph("Qt's libraries are separate shared libraries inside a program, unpacked into a temporary "
              "folder at each start and loaded from there. To run the program with another or a modified "
              "Qt, build it again from its source with that Qt - as .github/workflows/release.yml does: "
              "install requirements.lock.txt with your Qt in place of the PyQt6-Qt6 package, install the "
              "project (pip install --no-deps .) and run python -m PyInstaller "
              f"packaging/{title}.spec - or install the pip package (pip install {title}), which runs with "
              "the Qt installed beside it.")
    heading("Source code")
    paragraph("The complete corresponding source code of each program:")
    items = [f"{title} {version}: {repo} (git tag v{version}) and the sdist {sdist} on the release page "
             f"({repo}/releases/tag/v{version}). It holds the scripts that build the programs "
             "(.github/workflows/release.yml, packaging/), the tests and the exact versions and SHA-256 of "
             "everything they contain (requirements.lock.txt, packaging/requirements-pyinstaller.txt); the "
             "release checks that it does (packaging/reproducible_sdist.py --check). (PyPI has some of the "
             "versions, not this one necessarily: the release page has every one.)",
             f"axross, the code it is written out from: {axross}",
             "the Linux programs: the libraries of the system they are built on (Ubuntu's) - each named in "
             "licenses/system/INDEX.txt inside the program and in SYSTEM-LIBRARIES-linux-x86_64.txt on the "
             "release page, with its package's copyright file (its licence) and its source package and "
             "version (apt-get source SOURCE=VERSION; https://launchpad.net/ubuntu/+source/SOURCE/VERSION)"]
    if pyqt:
        items.append(f"PyQt6 {pyqt} (Riverbank Computing): its sdist, https://pypi.org/project/PyQt6/{pyqt}/#files"
                     " - https://www.riverbankcomputing.com/software/pyqt/")
    if qt:
        items.append(f"Qt {qt} (the PyQt6-Qt6 {qt} wheels are a build of it by The Qt Company): "
                     f"https://download.qt.io/official_releases/qt/{minor}/{qt}/src/ (later: "
                     f"https://download.qt.io/archive/qt/{minor}/{qt}/src/) - https://code.qt.io/")
    items += ["every other package listed below: its sdist, https://pypi.org/project/NAME/VERSION/#files, "
              "and its upstream repository below",
              "Python, the interpreter in the programs: https://www.python.org/downloads/source/"]
    if pyinstaller:
        items.append(f"PyInstaller {pyinstaller} (its bootloader starts the programs): "
                     f"https://pypi.org/project/pyinstaller/{pyinstaller}/#files")
    bullets(*items)
    paragraph("The third-party sources are kept at those places by their projects; should one of them not "
              f"be available there any more, ask at {repo}/issues and it is provided.")
    heading("What the programs contain")
    width = max(len(f"{p['name']} {p['version']}") for p in packages)
    for p in packages:
        lines.append(f"{(p['name'] + ' ' + p['version']).ljust(width)}  {p['license']}")
        lines.append(f"{' ' * width}  {p['url']}")
    lines.append("")
    bullets("Python: PSF-2.0. The interpreter's own LICENSE.txt is inside the programs as well "
            "(licenses/python/LICENSE.txt); the licences of what a Python build incorporates (OpenSSL, "
            "libffi, expat, zlib, ...) are listed at https://docs.python.org/3/license.html.",
            "PyInstaller's bootloader and loader: GPL-2.0-or-later WITH Bootloader-exception, and "
            "Apache-2.0 (https://github.com/pyinstaller/pyinstaller/blob/develop/COPYING.txt).",
            "Qt includes third-party code of its own (FreeType, HarfBuzz, PCRE2, libpng, zlib, md4c, "
            "double-conversion, Unicode data, on Linux ICU, ...): each is listed with its licence and "
            f"notice at https://doc.qt.io/qt-{qt.split('.')[0] or '6'}/licenses-used-in-qt.html.",
            "Pillow's wheels include libjpeg-turbo, libpng, libtiff, libwebp, FreeType, HarfBuzz, zlib "
            "and others: their licences are part of Pillow's licence text below.",
            "The Linux programs: the build machine's libraries in them (glibc's excepted: the system's own are "
            "used) - licenses/system/INDEX.txt inside the program and "
            "SYSTEM-LIBRARIES-linux-x86_64.txt on the release page list each, with its package's copyright "
            "file (its licence texts, LGPL-2.1 and LGPL-3.0 among them) and its source package.",
            "The AppImage: its runtime is AppImage's type2-runtime (MIT, https://github.com/AppImage/type2-runtime"
            "), which contains libfuse3 (LGPL-2.1-or-later, https://github.com/libfuse/libfuse), squashfuse "
            "(BSD-2-Clause, https://github.com/vasi/squashfuse) and zstd (BSD-3-Clause, "
            "https://github.com/facebook/zstd): their licence texts and sources are at those places; the "
            "runtime's exact build is named by packaging/fetch_appimagetool.sh.",
            "The Windows programs: Microsoft's Visual C++ runtime (vcruntime140.dll, msvcp140.dll, ...), "
            "redistributable under the Visual Studio licence's distributable code terms "
            "(https://visualstudio.microsoft.com/license-terms/), and Qt's opengl32sw.dll, a build of Mesa's "
            "llvmpipe (MIT, https://docs.mesa3d.org/license.html), listed with Qt's third-party code above.")
    heading("Licence texts")
    for p in packages:
        for rel in p["texts"]:
            text = (p["folder"] / rel).read_text(encoding="utf-8", errors="replace").replace("\r\n", "\n")
            lines += [rule, f"{p['name']} {p['version']}: {rel}", rule, "", text.strip("\n"), ""]
    for head, text in ((f"{title}: LICENSE (Apache-2.0)", licence), (f"{title}: NOTICE", notice)):
        if text:
            lines += [rule, head, rule, "", text.strip("\n"), ""]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("app")
    ap.add_argument("--refresh", action="store_true", help="take the texts out of the lock's wheels (PyPI)")
    args = ap.parse_args(argv)
    lock_file = ROOT / "build" / f"requirements-standalone-{args.app}.txt"
    lock = lock_file.read_text(encoding="utf-8")
    if args.refresh:
        for folder in refresh(args.app, lock):
            print(f"{texts_dir(args.app).relative_to(ROOT)}/{folder}")
        return 0
    for package in bundled(args.app, lock):
        print(f"{package['pin']} {package['version']}: {', '.join(package['texts'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
