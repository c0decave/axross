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
    for entry in T.load():
        if entry.id not in report.claimed:
            continue
        for pypi in entry.pypi:
            key = T.normalise_name(pypi)
            if key in NO_LICENCE_FILE_IN_WHEEL:
                continue
            if not any(n.startswith(f"licenses/python/{key}-") for n in names):
                missing.append(f"python {pypi}")
    if "licenses/system/LIBRARIES.txt" in names:
        manifest = archive.extract("licenses/system/LIBRARIES.txt").decode("utf-8")
        listed = {line.split("\t")[0]: line.split("\t")[1]
                  for line in manifest.splitlines() if line.strip()}
    else:
        missing.append("licenses/system/LIBRARIES.txt")
        listed = {}
    for kind, name in toc:
        if kind == "b" and "/" not in name and name.startswith("lib"):
            package = listed.get(name)
            if not package or package == "-":
                missing.append(f"system {name}: no rpm package")
            elif package in NO_LICENCE_TEXT_IN_RPM:
                continue
            elif not any(n.startswith(f"licenses/system/{package}/") for n in names):
                missing.append(f"system {name}: no licence files of {package}")
    for required in ("licenses/voice/COPYING", "licenses/voice/SOURCE-OFFER.txt",
                     "licenses/search-tools/ripgrep-LICENSE-MIT"):
        if flavor == "axross-full" and required not in names:
            missing.append(required)
    assert missing == [], "\n".join(missing)
