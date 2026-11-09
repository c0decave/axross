"""Release gate: everything third-party inside a built one-file binary has an
entry in resources/credits/third_party.json, every entry that claims to be
inside a binary is found there, and the binary carries the licence texts.

The release part reads dist/axross-full and dist/axross-slim (or the one
binary AXROSS_FROZEN_BINARY names) with PyInstaller's archive readers and
skips without them. The classifier itself is tested on made-up tables of
contents, so it runs everywhere.
"""

from __future__ import annotations

import os
import re
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core import third_party as T  # noqa: E402

#: Bundled distributions whose wheel carries no licence file at all (checked
#: in the builder image: importlib.metadata lists none). Their licence is
#: named in THIRD_PARTY_LICENSES.md; the text cannot come from the wheel.
NO_LICENCE_FILE_IN_WHEEL = {"ctranslate2", "dnspython", "fusepy", "manuf", "tokenizers"}
#: rpm packages of the builder image (AlmaLinux 9) that carry no licence text:
#: neither ``rpm -qL`` nor ``rpm -qd`` of the package or of the other packages
#: built from its source rpm lists one (checked in the builder image).
NO_LICENCE_TEXT_IN_RPM = {"libxcb", "lz4-libs", "sqlite-libs", "xcb-util-keysyms"}


#: LIBRARIES.txt's package of a libpython that is the building interpreter's
#: own (scripts/bundle_licenses.BUILD_PYTHON: python-build-standalone in a
#: sysroot build); its licence is CPython's LICENSE.txt.
BUILD_PYTHON = "python"
#: LIBRARIES.txt's package of a top-level library a wheel ships
#: (scripts/bundle_licenses.WHEEL_PREFIX): its licences are the wheel's.
WHEEL_PREFIX = "wheel:"
#: Wheels that ship another project's library without its licence: the
#: file the build adds below the wheel's licence folder
#: (scripts/bundle_licenses.WHEEL_LIBRARY_NOTICES).
WHEEL_LIBRARY_NOTICE = {"libusb-package": "libusb/COPYING", "xeddsa": "libsodium/LICENSE",
                        "pycares": "c-ares/LICENSE.md"}


def wheel_notice_problems(names, dists) -> list[str]:
    """The bundled wheels of *dists* (normalised names) whose licence folder
    lacks the notice of the library they ship without its licence
    (:data:`WHEEL_LIBRARY_NOTICE`: xeddsa's libsodium, pycares' c-ares)."""
    missing = []
    for dist in sorted(set(dists) & set(WHEEL_LIBRARY_NOTICE)):
        folder = re.compile(rf"^licenses/python/{re.escape(dist)}-[^-/]+/")
        notice = WHEEL_LIBRARY_NOTICE[dist]
        if not any(folder.match(n) and n.endswith("/" + notice) for n in names):
            missing.append(f"python {dist}: no licenses/python/{dist}-*/{notice}")
    return missing


def system_licence_problems(toc, listed: dict[str, str]) -> list[str]:
    """What a binary lacks for its top-level libraries: each needs a
    package in LIBRARIES.txt (*listed*: library -> package) and that
    package's licence files under licenses/system/<package>/; the building
    interpreter's libpython needs CPython's LICENSE.txt there, a library a
    wheel ships (``wheel:<name>``) the wheel's licence files under
    licenses/python/<name>-<version>/."""
    names = {name for _, name in toc}
    missing = []
    for kind, name in toc:
        if kind != "b" or "/" in name or not name.startswith("lib"):
            continue
        package = listed.get(name)
        if not package or package == "-":
            missing.append(f"system {name}: no package")
        elif package.startswith(WHEEL_PREFIX):
            dist = package[len(WHEEL_PREFIX):]
            folder = re.compile(rf"^licenses/python/({re.escape(dist)}-[^-/]+)/")
            folders = {m.group(1) for m in map(folder.match, names) if m}
            notice = WHEEL_LIBRARY_NOTICE.get(dist)
            if not folders and dist not in NO_LICENCE_FILE_IN_WHEEL:
                missing.append(f"system {name}: no licence files of the wheel {dist}")
            elif notice and not any(f"licenses/python/{f}/{notice}" in names for f in folders):
                missing.append(f"system {name}: no licenses/python/{dist}-*/{notice}")
        elif package == BUILD_PYTHON:
            if f"licenses/system/{BUILD_PYTHON}/LICENSE.txt" not in names:
                missing.append(f"system {name}: no licenses/system/{BUILD_PYTHON}/LICENSE.txt")
        elif package in NO_LICENCE_TEXT_IN_RPM:
            continue
        elif not any(n.startswith(f"licenses/system/{package}/") for n in names):
            missing.append(f"system {name}: no licence files of {package}")
    return missing


def _entries(*raw: dict) -> list[T.Entry]:
    base = {"kind": "library", "purpose": "p", "license": "MIT", "url": "https://x.org"}
    return T.parse({"schema": T.SCHEMA, "entries": [{**base, **r} for r in raw]})


STDLIB = T.stdlib_modules()


# --- classifier: happy -----------------------------------------------------


def test_happy_libraries_modules_and_paths_are_claimed():
    entries = _entries(
        {"id": "qt", "name": "Qt", "ships": ["axross-full"],
         "match": {"libraries": ["libQt6*"], "paths": ["PyQt6/Qt6/plugins/*"]}},
        {"id": "jpeg", "name": "jpeg", "ships": ["axross-full"],
         "match": {"libraries": ["libjpeg"]}},
        {"id": "pil", "name": "Pillow", "kind": "python", "ships": ["axross-full"],
         "match": {"modules": ["PIL"]}},
        {"id": "rg", "name": "rg", "kind": "program", "ships": ["axross-full"],
         "match": {"paths": ["bin/rg"]}},
    )
    toc = [("b", "PyQt6/Qt6/lib/libQt6Core.so.6"), ("b", "PyQt6/Qt6/plugins/platforms/libqxcb.so"),
           ("b", "pillow.libs/libjpeg-6dc8d115.so.62.4.0"), ("b", "libjpeg.so.62"),
           ("b", "PIL/_imaging.cpython-312-x86_64-linux-gnu.so"), ("b", "bin/rg"),
           ("x", "pillow-13.0.0.dist-info/METADATA"), ("n", "libQt6Core.so.6"),
           ("b", "python3.12/lib-dynload/_ssl.cpython-312-x86_64-linux-gnu.so"),
           ("x", "base_library.zip"), ("x", "resources/i18n/de.json"),
           ("x", "licenses/voice/COPYING")]
    report = T.classify_bundle(entries, "axross-full", toc, ["PIL", "json", "core", "ui"], STDLIB,
                               pypi_names={"pillow": "pil"})
    assert report.unclaimed == []
    assert report.stale == []
    assert set(report.claimed) == {"qt", "jpeg", "pil", "rg"}


def test_happy_library_names_lose_version_and_wheel_hash():
    assert T.normalise_library("pillow.libs/libjpeg-6dc8d115.so.62.4.0") == "libjpeg"
    assert T.normalise_library("numpy.libs/libgfortran-83c28eba-468e71e5.so.5.0.0") == "libgfortran"
    assert T.normalise_library("libpython3.12.so.1.0") == "libpython3.12"
    assert T.normalise_library("PyQt6/Qt6/lib/libQt6FFmpegStub-crypto.so.3") == \
        "libQt6FFmpegStub-crypto"
    assert T.normalise_library("libscipy_openblas64_-f48b354e.so") == "libscipy_openblas64_"


def test_happy_the_data_claims_what_the_ci_inventory_found_without_an_entry():
    # 0.15.177's CI inventory: native parts of the Matrix / XMPP stack and
    # libusb's libatomic that resources/credits/third_party.json did not name.
    toc = [("b", "Crypto/Cipher/_raw_aes.abi3.so"), ("b", "_libxeddsa.abi3.so"),
           ("b", "xeddsa.libs/libsodium-f5304dcb.so.23.3.0"), ("b", "libatomic.so.1"),
           ("b", "aiohttp/_http_parser.cpython-312-x86_64-linux-gnu.so"),
           ("b", "yarl/_quoting_c.cpython-312-x86_64-linux-gnu.so"),
           ("b", "multidict/_multidict.cpython-312-x86_64-linux-gnu.so"),
           ("b", "frozenlist/_frozenlist.cpython-312-x86_64-linux-gnu.so"),
           ("b", "propcache/_helpers_c.cpython-312-x86_64-linux-gnu.so"),
           ("b", "pycares/_cares.abi3.so"),
           ("b", "pydantic_core/_pydantic_core.cpython-312-x86_64-linux-gnu.so")]
    modules = ["Crypto.Cipher.AES", "xeddsa.bindings", "h2.connection", "peewee", "pydantic",
               "aiohttp_socks", "python_socks", "elementpath", "xmlschema", "x3dh",
               "doubleratchet", "unpaddedbase64", "atomicwrites", "cachetools", "aiofiles",
               "aiodns", "aiosignal", "aiohappyeyeballs", "annotated_types",
               "typing_inspection", "hpack", "hyperframe"]
    report = T.classify_bundle(T.load(), "axross-full", toc, modules, STDLIB)
    assert report.unclaimed == []
    assert report.unlisted == []
    owners = {what: owner for owner, parts in report.claimed.items() for what in parts}
    assert owners["xeddsa.libs/libsodium-f5304dcb.so.23.3.0"] == "libsodium"
    assert owners["_libxeddsa.abi3.so"] == "xeddsa"
    assert owners["libatomic.so.1"] == "gcc-runtime"
    assert owners["Crypto/Cipher/_raw_aes.abi3.so"] == "pycryptodome"


# --- classifier: sad -------------------------------------------------------


def test_sad_an_unknown_library_module_and_dist_info_are_unclaimed():
    entries = _entries({"id": "qt", "name": "Qt", "ships": ["axross-full"],
                        "match": {"libraries": ["libQt6*"]}})
    toc = [("b", "libQt6Core.so.6"), ("b", "libmystery.so.1"),
           ("x", "mystery_pkg-1.0.dist-info/METADATA"), ("b", "bin/strange-tool")]
    report = T.classify_bundle(entries, "axross-full", toc, ["mysterymod", "json"], STDLIB)
    assert report.unclaimed == ["bin/strange-tool", "libmystery.so.1",
                                "module mysterymod", "mystery_pkg-1.0.dist-info"]


def test_sad_an_entry_that_says_it_is_inside_but_matches_nothing_is_stale():
    entries = _entries({"id": "gone", "name": "Gone", "ships": ["axross-full", "axross-slim"],
                        "match": {"libraries": ["libgone"]}})
    report = T.classify_bundle(entries, "axross-slim", [], [], STDLIB)
    assert report.stale == ["gone"]
    report = T.classify_bundle(entries, "axross-full", [("b", "libgone.so.1")], [], STDLIB)
    assert report.stale == []


def test_sad_an_entry_found_in_a_binary_it_does_not_list_is_reported():
    entries = _entries({"id": "full-only", "name": "F", "ships": ["axross-full"],
                        "match": {"libraries": ["libf"]}})
    report = T.classify_bundle(entries, "axross-slim", [("b", "libf.so.1")], [], STDLIB)
    assert report.unlisted == ["full-only"]


# --- classifier: edge ------------------------------------------------------


def test_happy_the_build_python_s_libpython_passes_with_cpython_s_licence():
    toc = [("b", "libpython3.12.so.1.0"), ("b", "libkrb5.so.3"),
           ("x", "licenses/system/python/LICENSE.txt"),
           ("x", "licenses/system/krb5-libs/LICENSE")]
    listed = {"libpython3.12.so.1.0": "python", "libkrb5.so.3": "krb5-libs"}
    assert system_licence_problems(toc, listed) == []


def test_sad_the_build_python_s_libpython_without_its_licence_is_reported():
    toc = [("b", "libpython3.12.so.1.0"), ("x", "licenses/system/python/PYTHON.json"),
           ("b", "libstray.so.1")]
    assert system_licence_problems(toc, {"libpython3.12.so.1.0": "python",
                                         "libstray.so.1": "-"}) == [
        "system libpython3.12.so.1.0: no licenses/system/python/LICENSE.txt",
        "system libstray.so.1: no package"]


def test_happy_a_library_a_wheel_ships_passes_with_the_wheel_s_licences():
    toc = [("b", "libusb-1.0.so"), ("b", "libthing.so.2"),
           ("x", "licenses/python/libusb-package-1.0.26.4/LICENSE"),
           ("x", "licenses/python/libusb-package-1.0.26.4/libusb/COPYING"),
           ("x", "licenses/python/some-wheel-2.0/LICENSE.txt")]
    listed = {"libusb-1.0.so": "wheel:libusb-package", "libthing.so.2": "wheel:some-wheel"}
    assert system_licence_problems(toc, listed) == []


def test_sad_a_wheel_library_without_its_licences_is_reported():
    toc = [("b", "libusb-1.0.so"), ("b", "libthing.so.2"),
           ("x", "licenses/python/libusb-package-1.0.26.4/LICENSE"),
           ("x", "licenses/python/some-wheel-old-1.0/LICENSE")]
    listed = {"libusb-1.0.so": "wheel:libusb-package", "libthing.so.2": "wheel:some-wheel"}
    assert system_licence_problems(toc, listed) == [
        "system libusb-1.0.so: no licenses/python/libusb-package-*/libusb/COPYING",
        "system libthing.so.2: no licence files of the wheel some-wheel"]


def test_happy_a_bundled_wheel_s_inner_library_notice_passes():
    names = ["licenses/python/xeddsa-1.2.0/LICENSE",
             "licenses/python/xeddsa-1.2.0/libsodium/LICENSE",
             "licenses/python/pycares-5.2.1/c-ares/LICENSE.md",
             "licenses/python/numpy-2.5.4/LICENSE.txt"]
    assert wheel_notice_problems(names, {"xeddsa", "pycares", "numpy"}) == []
    # a flavour without the wheels (slim) needs none of them
    assert wheel_notice_problems([], {"numpy"}) == []


def test_sad_a_bundled_wheel_without_its_inner_library_notice_is_reported():
    names = ["licenses/python/xeddsa-1.2.0/LICENSE",
             "licenses/python/pycares-5.2.1/LICENSE",
             "licenses/python/pycares-old-1.0/c-ares/LICENSE.md"]
    assert wheel_notice_problems(names, {"xeddsa", "pycares"}) == [
        "python pycares: no licenses/python/pycares-*/c-ares/LICENSE.md",
        "python xeddsa: no licenses/python/xeddsa-*/libsodium/LICENSE"]


def test_edge_bootstrap_and_symlink_entries_are_ignored():
    toc = [("m", "pyimod01_archive"), ("s", "pyiboot01_bootstrap"), ("z", "PYZ.pyz"),
           ("n", "libwhatever.so.1"), ("x", "base_library.zip")]
    report = T.classify_bundle([], "axross-full", toc, ["_pyi_rth_utils", "pyimod02_importers"],
                               STDLIB)
    assert report.unclaimed == []


def test_edge_modules_removed_from_newer_pythons_count_as_stdlib():
    report = T.classify_bundle([], "axross-full", [], ["cgi", "_compression", "imghdr"], STDLIB)
    assert report.unclaimed == []


# --- release: the real binaries --------------------------------------------


def _binaries() -> list[tuple[str, Path]]:
    named = os.environ.get("AXROSS_FROZEN_BINARY", "")
    if named:
        path = Path(named)
        flavor = "axross-slim" if "slim" in path.name else "axross-full"
        return [(flavor, path)]
    return [(f, ROOT / "dist" / f) for f in ("axross-full", "axross-slim")
            if (ROOT / "dist" / f).is_file()]


def _read(path: Path):
    readers = pytest.importorskip("PyInstaller.archive.readers")
    archive = readers.CArchiveReader(str(path))
    toc = [(entry[4] if len(entry) > 4 else "?", name) for name, entry in archive.toc.items()]
    pyz_name = next(n for n in archive.toc if n.endswith(".pyz"))
    with tempfile.NamedTemporaryFile(suffix=".pyz", delete=False) as tmp:
        tmp.write(archive.extract(pyz_name))
    try:
        modules = list(readers.ZlibArchiveReader(tmp.name).toc)
    finally:
        os.unlink(tmp.name)
    return archive, toc, modules


BINARIES = _binaries()
needs_binaries = pytest.mark.skipif(not BINARIES, reason="no built binary in dist/ and "
                                                         "AXROSS_FROZEN_BINARY unset")


@needs_binaries
@pytest.mark.parametrize("flavor,path", BINARIES, ids=[f for f, _ in BINARIES])
def test_release_everything_in_the_binary_has_an_entry(flavor, path):
    _, toc, modules = _read(path)
    report = T.classify_bundle(T.load(), flavor, toc, modules, STDLIB)
    assert report.unclaimed == [], "\n".join(report.unclaimed)
    assert report.stale == [], report.stale
    assert report.unlisted == [], report.unlisted


@needs_binaries
@pytest.mark.parametrize("flavor,path", BINARIES, ids=[f for f, _ in BINARIES])
def test_release_the_binary_carries_the_licence_texts(flavor, path):
    archive, toc, modules = _read(path)
    names = [name for _, name in toc]
    report = T.classify_bundle(T.load(), flavor, toc, modules, STDLIB)
    missing = []
    bundled = set()
    for entry in T.load():
        if entry.id not in report.claimed:
            continue
        for pypi in entry.pypi:
            key = T.normalise_name(pypi)
            bundled.add(key)
            if key in NO_LICENCE_FILE_IN_WHEEL:
                continue
            if not any(n.startswith(f"licenses/python/{key}-") for n in names):
                missing.append(f"python {pypi}")
    missing += wheel_notice_problems(names, bundled)
    if "licenses/system/LIBRARIES.txt" in names:
        manifest = archive.extract("licenses/system/LIBRARIES.txt").decode("utf-8")
        listed = {line.split("\t")[0]: line.split("\t")[1]
                  for line in manifest.splitlines() if line.strip()}
    else:
        missing.append("licenses/system/LIBRARIES.txt")
        listed = {}
    missing += system_licence_problems(toc, listed)
    for required in ("licenses/voice/COPYING", "licenses/voice/SOURCE-OFFER.txt",
                     "licenses/search-tools/ripgrep-LICENSE-MIT"):
        if flavor == "axross-full" and required not in names:
            missing.append(required)
    assert missing == [], "\n".join(missing)
