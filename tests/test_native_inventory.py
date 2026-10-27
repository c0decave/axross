"""Every ELF inside a Linux one-file binary, with its version and where it
comes from - listed in THIRD_PARTY_LICENSES.md and in every release's notes.

Asked for: the native files and libraries of the deliveries are linked in
the third-party licences document with their versions, and every release
names them.

The inventory reads a bundle through its archive (made-up archives here, the
built binaries in the release part). A version is taken, in this order, from
the rpm package of the builder image (licenses/system/LIBRARIES.txt), from the
wheel the file belongs to when the library is that wheel's own, from the
wheel's SBOM, from a version string inside the file, from its sibling library
of the same build, and only then from the soname. Each row says which.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

sys.path.insert(0, str(ROOT / "scripts"))

import native_inventory as N  # noqa: E402
from core import third_party as T  # noqa: E402

ELF = b"\x7fELF\x02\x01\x01" + b"\0" * 9


class FakeArchive:
    def __init__(self, files: dict[str, bytes], kinds: dict[str, str] | None = None):
        self.files = files
        self.kinds = kinds or {}

    @property
    def toc(self):
        return [(self.kinds.get(n, "b" if n.endswith((".so",)) or ".so." in n or
                                n.startswith("bin/") else "x"), n) for n in self.files]

    def read(self, name: str) -> bytes:
        return self.files[name]


def _entries(*raw: dict) -> list[T.Entry]:
    base = {"kind": "library", "purpose": "p", "license": "MIT", "url": "https://x.org",
            "ships": ["axross-full"]}
    return T.parse({"schema": T.SCHEMA, "entries": [{**base, **r} for r in raw]})


ENTRIES = _entries(
    {"id": "openssl", "name": "OpenSSL", "url": "https://www.openssl.org",
     "match": {"libraries": ["libssl", "libcrypto"]}},
    {"id": "qt6", "name": "Qt 6", "pypi": ["PyQt6-Qt6"],
     "match": {"libraries": ["libQt6*"], "paths": ["PyQt6/Qt6/plugins/*"]}},
    {"id": "ffmpeg-pyav", "name": "FFmpeg (PyAV build)",
     "match": {"paths": ["av.libs/libav*", "av.libs/libsw*"]}},
    {"id": "libjpeg-turbo", "name": "libjpeg-turbo", "match": {"libraries": ["libjpeg"]}},
    {"id": "lcms2", "name": "Little CMS", "match": {"libraries": ["liblcms2"]}},
    {"id": "krb5", "name": "MIT Kerberos",
     "match": {"libraries": ["libkrb5", "libgssapi_krb5", "libcom_err"]}},
    {"id": "libpq", "name": "libpq", "match": {"libraries": ["libpq"]}},
    {"id": "pillow", "name": "Pillow", "kind": "python", "pypi": ["pillow"],
     "match": {"modules": ["PIL"]}},
    {"id": "cryptography", "name": "cryptography", "kind": "python", "pypi": ["cryptography"],
     "match": {"modules": ["cryptography"]}},
    {"id": "ripgrep", "name": "ripgrep", "kind": "program", "version": "15.2.0",
     "match": {"paths": ["bin/rg"]}},
    {"id": "cpython", "name": "Python", "version": "3.12",
     "match": {"libraries": ["libpython3*"]}},
    {"id": "zlib", "name": "zlib", "match": {"libraries": ["libz"]}},
)

LIBRARIES_TXT = ("libssl.so.3\topenssl-libs\t3.5.8-2.el9_8\n"
                 "libcrypto.so.3\topenssl-libs\t3.5.8-2.el9_8\n"
                 "libpython3.12.so.1.0\tpython3.12-libs\t3.12.15-1.el9_8\n"
                 "libz.so.1\tzlib\t-\n")

PILLOW_SBOM = {"bomFormat": "CycloneDX", "components": [
    {"name": "PIL._imaging", "version": "13.0.0", "purl": "pkg:pypi/pillow@13.0.0#c-ext"},
    {"name": "libjpeg / libjpeg-turbo", "version": "3.2.0"},
    {"name": "Little CMS 2", "version": "2.19.1"},
    {"name": "raqm", "version": "0.11.0"},
    {"name": "pybind11", "version": None},
]}
PSYCOPG_SBOM = {"bomFormat": "CycloneDX", "components": [
    {"name": "psycopg_binary", "version": "3.3.6", "purl": "pkg:pypi/psycopg_binary@3.3.6"},
    {"name": "krb5-libs", "version": "1.15.1-55.el7_9",
     "purl": "pkg:rpm/centos/krb5-libs@1.15.1-55.el7_9"},
    {"name": "krb5-libs", "version": "1.15.1-55.el7_9",
     "purl": "pkg:rpm/centos/krb5-libs@1.15.1-55.el7_9"},
    {"name": "libcom_err", "version": "1.42.9-19.el7",
     "purl": "pkg:rpm/centos/libcom_err@1.42.9-19.el7"},
]}
CRYPTO_SBOM = {"bomFormat": "CycloneDX", "components": [
    {"name": "openssl", "version": "4.0.3", "purl": "pkg:generic/openssl@4.0.3"}]}
CRYPTO_RUST_SBOM = {"bomFormat": "CycloneDX", "components": [
    {"name": "pyo3", "version": "0.26.0", "purl": "pkg:cargo/pyo3@0.26.0"}]}


def _bundle() -> FakeArchive:
    return FakeArchive({
        "libssl.so.3": ELF,
        "libcrypto.so.3": ELF + b"OpenSSL 3.5.8 25 Aug 2026\0",
        "libpython3.12.so.1.0": ELF,
        "libz.so.1": ELF,
        "python3.12/lib-dynload/_ssl.cpython-312-x86_64-linux-gnu.so": ELF,
        "python3.12/lib-dynload/_json.cpython-312-x86_64-linux-gnu.so": ELF,
        "PyQt6/Qt6/lib/libQt6Core.so.6": ELF,
        "PyQt6/Qt6/plugins/platforms/libqxcb.so": ELF,
        "av.libs/libavcodec-d61378e8.so.63.1.102": ELF + b"\0FFmpeg version 9.0.2\0",
        "av.libs/libavutil-8f0ab4ee.so.61.1.102": ELF + b"FFmpeg version 9.0.2\0",
        "av.libs/libswscale-cd7831fd.so.10.1.102": ELF,
        "pillow.libs/libjpeg-6dc8d115.so.62.4.0": ELF,
        "pillow.libs/liblcms2-88eaba2f.so.2.0.19": ELF,
        "PIL/_imaging.cpython-312-x86_64-linux-gnu.so": ELF,
        "PIL/_webp.cpython-312-x86_64-linux-gnu.so": ELF,
        "psycopg_binary.libs/libkrb5-fcafa220.so.3.3": ELF,
        "psycopg_binary.libs/libcom_err-2abe824b.so.2.1": ELF,
        "psycopg_binary.libs/libpq-e9b5c9ac.so.5.18": ELF,
        "psycopg_binary.libs/libssl-8bd944e8.so.3": ELF,
        "psycopg_binary.libs/libcrypto-2d1629ee.so.3": ELF + b"OpenSSL 3.5.8 25 Aug 2026\0",
        "cryptography/hazmat/bindings/_rust.abi3.so": ELF,
        "bin/rg": ELF + b" (JIT is available)\n15.2.0e89fff89ac",
        "licenses/system/LIBRARIES.txt": LIBRARIES_TXT.encode(),
        "licenses/python/pillow-13.0.0/LICENSE": b"text",
        "licenses/python/pillow-13.0.0/sboms/pillow-13.0.0.cdx.json":
            json.dumps(PILLOW_SBOM).encode(),
        "licenses/python/pyqt6-qt6-6.11.2/LICENSE": b"text",
        "licenses/python/av-19.0.2/LICENSE.txt": b"text",
        "licenses/python/psycopg-binary-3.3.6/sboms/auditwheel.cdx.json":
            json.dumps(PSYCOPG_SBOM).encode(),
        "licenses/python/cryptography-50.0.2/sboms/sbom.json": json.dumps(CRYPTO_SBOM).encode(),
        "licenses/python/cryptography-50.0.2/sboms/cryptography-rust.cyclonedx.json":
            json.dumps(CRYPTO_RUST_SBOM).encode(),
        "resources/icons/a.png": b"\x89PNG",
    })


def _by_path(rows):
    return {r.path: r for r in rows}


# --- happy -----------------------------------------------------------------


def test_happy_system_libraries_carry_their_rpm_package_and_version():
    rows = _by_path(N.inventory(_bundle(), ENTRIES))
    ssl = rows["libssl.so.3"]
    assert (ssl.component, ssl.version, ssl.evidence, ssl.shipped_by) == \
        ("openssl", "3.5.8-2.el9_8", "rpm", "rpm openssl-libs")
    assert rows["libpython3.12.so.1.0"].version == "3.12.15-1.el9_8"


def test_happy_a_wheels_own_library_has_the_wheel_version():
    rows = _by_path(N.inventory(_bundle(), ENTRIES))
    core = rows["PyQt6/Qt6/lib/libQt6Core.so.6"]
    assert (core.component, core.version, core.evidence, core.shipped_by) == \
        ("qt6", "6.11.2", "wheel", "wheel pyqt6-qt6 6.11.2")
    assert rows["PyQt6/Qt6/plugins/platforms/libqxcb.so"].version == "6.11.2"


def test_happy_sbom_versions_reach_the_files_they_describe():
    rows = _by_path(N.inventory(_bundle(), ENTRIES))
    jpeg = rows["pillow.libs/libjpeg-6dc8d115.so.62.4.0"]
    assert (jpeg.component, jpeg.version, jpeg.evidence, jpeg.shipped_by) == \
        ("libjpeg-turbo", "3.2.0", "sbom", "wheel pillow 13.0.0")
    assert rows["pillow.libs/liblcms2-88eaba2f.so.2.0.19"].version == "2.19.1"
    krb5 = rows["psycopg_binary.libs/libkrb5-fcafa220.so.3.3"]
    assert (krb5.version, krb5.evidence) == ("1.15.1-55.el7_9", "sbom")
    # the exact family wins over the entry's broader name
    assert rows["psycopg_binary.libs/libcom_err-2abe824b.so.2.1"].version == "1.42.9-19.el7"


def test_happy_a_version_string_inside_the_file_and_its_sibling_are_read():
    rows = _by_path(N.inventory(_bundle(), ENTRIES))
    codec = rows["av.libs/libavcodec-d61378e8.so.63.1.102"]
    assert (codec.component, codec.version, codec.evidence) == ("ffmpeg-pyav", "9.0.2", "file")
    scale = rows["av.libs/libswscale-cd7831fd.so.10.1.102"]
    assert (scale.version, scale.evidence) == ("9.0.2", "sibling")
    ssl = rows["psycopg_binary.libs/libssl-8bd944e8.so.3"]
    assert (ssl.component, ssl.version, ssl.evidence) == ("openssl", "3.5.8", "sibling")


def test_happy_programs_report_the_version_they_print():
    rows = _by_path(N.inventory(_bundle(), ENTRIES))
    rg = rows["bin/rg"]
    assert (rg.component, rg.version, rg.evidence, rg.shipped_by) == \
        ("ripgrep", "15.2.0", "file", "build")


def test_happy_extension_modules_are_counted_per_package():
    rows = _by_path(N.inventory(_bundle(), ENTRIES))
    pil = rows["PIL/"]
    assert (pil.component, pil.count, pil.version, pil.evidence, pil.kind) == \
        ("pillow", 2, "13.0.0", "wheel", "extension")
    stdlib = rows["python3.12/lib-dynload/"]
    assert (stdlib.component, stdlib.count, stdlib.version, stdlib.evidence) == \
        ("cpython", 2, "3.12.15-1.el9_8", "rpm")


def test_happy_libraries_linked_into_a_wheels_modules_are_listed_from_its_sbom():
    rows = N.inventory(_bundle(), ENTRIES)
    static = {(r.label, r.version, r.shipped_by) for r in rows if r.kind == "static"}
    assert ("openssl", "4.0.3", "wheel cryptography 50.0.2") in static
    assert ("raqm", "0.11.0", "wheel pillow 13.0.0") in static
    labels = {r.label for r in rows if r.kind == "static"}
    assert "pyo3" not in labels          # Rust crates stay in the wheel's own SBOM
    assert "PIL._imaging" not in labels   # the wheel's own modules
    assert "pybind11" not in labels       # no version
    openssl = next(r for r in rows if r.kind == "static" and r.label == "openssl")
    assert openssl.component == "openssl"


def test_happy_render_merges_the_binaries_and_links_each_component():
    rows = N.inventory(_bundle(), ENTRIES)
    text = N.render_files({"axross-full": rows, "axross-slim": rows}, ENTRIES)
    line = next(l for l in text.splitlines() if "`libssl.so.3`" in l)
    assert "[OpenSSL](https://www.openssl.org)" in line
    assert "3.5.8-2.el9_8" in line and "rpm openssl-libs" in line and "full, slim" in line
    assert "`PIL/` (2 extension modules)" in text


def test_happy_components_list_every_version_once():
    rows = N.inventory(_bundle(), ENTRIES)
    text = N.render_components({"axross-full": rows}, ENTRIES)
    line = next(l for l in text.splitlines() if "[OpenSSL]" in l)
    assert "3.5.8-2.el9_8 (rpm openssl-libs)" in line
    assert "3.5.8 (wheel psycopg-binary 3.3.6)" in line
    assert "4.0.3 (wheel cryptography 50.0.2)" in line
    assert line.count("3.5.8-2.el9_8") == 1


def test_happy_the_notes_start_with_the_marker_and_flag_soname_numbers():
    rows = N.inventory(_bundle(), ENTRIES)
    text = N.render_components({"axross-full": rows}, ENTRIES)
    assert text.splitlines()[:2] == [N.NOTES_MARKER, N.NOTES_HEADING]
    line = next(l for l in text.splitlines() if "[libpq]" in l)
    assert "soname 5.18 (wheel psycopg-binary 3.3.6)" in line


def test_edge_a_file_without_any_version_shows_the_credits_version():
    entries = _entries({"id": "espeak-ng", "name": "espeak-ng", "version": "1.52.0.1",
                        "match": {"paths": ["piper/espeakbridge*"]}})
    row = N.NativeFile(path="piper/", component="espeak-ng", label="", version="",
                       evidence="", shipped_by="wheel piper-tts 1.8.0", kind="extension", count=1)
    files = N.render_files({"axross-full": [row]}, entries)
    assert "| 1.52.0.1 | credits |" in files
    notes = N.render_components({"axross-full": [N.NativeFile(**{**row.__dict__,
                                                                  "kind": "static"})]}, entries)
    assert "credits 1.52.0.1 (wheel piper-tts 1.8.0)" in notes


def test_happy_the_licences_document_has_one_native_files_block():
    text = (ROOT / T.LICENSES_FILE).read_text(encoding="utf-8")
    assert text.count(T.block_begin(N.BLOCK)) == 1
    assert text.count(T.block_end(N.BLOCK)) == 1


# --- sad -------------------------------------------------------------------


def test_sad_a_library_no_source_dates_falls_back_to_its_soname():
    rows = _by_path(N.inventory(_bundle(), ENTRIES))
    pq = rows["psycopg_binary.libs/libpq-e9b5c9ac.so.5.18"]
    assert (pq.version, pq.evidence) == ("5.18", "soname")


def test_sad_an_rpm_without_version_falls_back_and_says_so():
    rows = _by_path(N.inventory(_bundle(), ENTRIES))
    z = rows["libz.so.1"]
    assert (z.shipped_by, z.version, z.evidence) == ("rpm zlib", "1", "soname")


def test_sad_two_different_version_strings_in_one_file_give_none():
    assert N.embedded_version("libcrypto", b"OpenSSL 3.5.8 x\0OpenSSL 3.0.1 y") is None
    assert N.embedded_version("libunknown", b"FFmpeg version 9.0.2") is None


def test_sad_a_broken_sbom_or_libraries_file_is_ignored_not_fatal():
    bundle = _bundle()
    bundle.files["licenses/python/pillow-13.0.0/sboms/pillow-13.0.0.cdx.json"] = b"{broken"
    bundle.files["licenses/system/LIBRARIES.txt"] = b"garbage line\n\xff\xfe\n"
    rows = _by_path(N.inventory(bundle, ENTRIES))
    assert rows["pillow.libs/libjpeg-6dc8d115.so.62.4.0"].evidence == "soname"
    assert rows["libssl.so.3"].shipped_by == "builder image"


def test_sad_an_unclaimed_file_is_listed_without_a_component():
    bundle = _bundle()
    bundle.files["mystery.libs/libmystery-0123abcd.so.4.1"] = ELF
    rows = _by_path(N.inventory(bundle, ENTRIES))
    row = rows["mystery.libs/libmystery-0123abcd.so.4.1"]
    assert (row.component, row.version) == ("", "4.1")
    text = N.render_files({"axross-full": [row]}, ENTRIES)
    assert "libmystery" in text


def test_sad_a_typed_version_that_disagrees_with_the_binary_is_reported():
    entries = _entries({"id": "ffmpeg-pyav", "name": "FFmpeg", "version": "7.1.2",
                        "match": {"paths": ["av.libs/libav*"]}},
                       {"id": "cpython", "name": "Python", "version": "3.12",
                        "match": {"libraries": ["libpython3*"]}},
                       {"id": "ripgrep", "name": "rg", "kind": "program", "version": "15.2.0",
                        "match": {"paths": ["bin/rg"]}})
    rows = N.inventory(_bundle(), entries)
    assert N.version_conflicts({"axross-full": rows}, entries) == \
        ["ffmpeg-pyav: typed 7.1.2, the binary has 9.0.2"]


# --- edge ------------------------------------------------------------------


def test_edge_data_files_and_non_elf_binaries_are_not_native():
    bundle = _bundle()
    bundle.files["PyQt6/Qt6/lib/libfake.so.1"] = b"not an elf"
    rows = _by_path(N.inventory(bundle, ENTRIES))
    assert "PyQt6/Qt6/lib/libfake.so.1" not in rows
    assert "resources/icons/a.png" not in rows
    assert "licenses/system/LIBRARIES.txt" not in rows


def test_edge_soname_versions_lose_the_wheel_hash():
    assert N.soname_version("pillow.libs/libjpeg-6dc8d115.so.62.4.0") == "62.4.0"
    assert N.soname_version("libscipy_openblas64_-f48b354e.so") is None
    assert N.soname_version("libpython3.12.so.1.0") == "1.0"


def test_edge_a_version_with_a_pipe_or_bracket_cannot_break_the_table():
    row = N.NativeFile(path="lib|x.so", component="", label="a|b]", version="1|2",
                       evidence="file", shipped_by="build", kind="library", count=1)
    text = N.render_files({"axross-full": [row]}, ENTRIES)
    body = [l for l in text.splitlines() if "lib" in l and l.startswith("|")][-1]
    assert body.count("|") - body.count("\\|") == 7


def test_edge_counts_that_differ_between_binaries_are_shown_per_binary():
    full = N.NativeFile(path="python3.12/lib-dynload/", component="cpython", label="",
                        version="3.12.15", evidence="rpm", shipped_by="rpm python3.12-libs",
                        kind="extension", count=50)
    slim = N.NativeFile(**{**full.__dict__, "count": 48})
    text = N.render_files({"axross-full": [full], "axross-slim": [slim]}, ENTRIES)
    assert "50 (full), 48 (slim)" in text


def test_edge_unmatched_auditwheel_components_still_appear():
    bundle = _bundle()
    del bundle.files["psycopg_binary.libs/libcom_err-2abe824b.so.2.1"]
    rows = N.inventory(bundle, ENTRIES)
    assert any(r.kind == "static" and r.label == "libcom_err" for r in rows)


# --- release: the built binaries -------------------------------------------


def _binaries() -> dict[str, Path]:
    named = os.environ.get("AXROSS_FROZEN_BINARY", "")
    if named:
        return {}
    return {f: ROOT / "dist" / f for f in N.LINUX_BINARIES if (ROOT / "dist" / f).is_file()}


BINARIES = _binaries()
needs_both = pytest.mark.skipif(set(BINARIES) != set(N.LINUX_BINARIES),
                                reason="needs dist/axross-full and dist/axross-slim")


@needs_both
def test_release_the_licences_document_lists_the_native_files_of_these_binaries():
    pytest.importorskip("PyInstaller.archive.readers")
    entries = T.load()
    inventories = {f: N.inventory(N.open_bundle(p), entries) for f, p in BINARIES.items()}
    text = (ROOT / T.LICENSES_FILE).read_text(encoding="utf-8")
    wanted = T.replace_block(text, N.BLOCK, N.render_files(inventories, entries))
    assert wanted == text, "run: python scripts/native_inventory.py --write dist/axross-full " \
                           "dist/axross-slim"
    assert N.version_conflicts(inventories, entries) == []
    by_id = {e.id: e for e in entries}
    unversioned = [r.path for rows in inventories.values() for r in rows
                   if r.kind in ("library", "program") and not N.shown(r, by_id)[0]]
    assert unversioned == []
