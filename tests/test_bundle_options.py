"""The PyInstaller EXE options per operating system.

build/axross.spec was written for Linux: strip=True and upx=True on every
platform. On Windows strip has no tool to run and UPX corrupts Qt DLLs;
on macOS stripping invalidates the code signatures of the bundled
libraries, and a windowed one-file build is deprecated there. On Linux the
builder's strip breaks numpy's OpenBLAS, so no platform strips.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import bundle_options as B  # noqa: E402

# --- happy ----------------------------------------------------------------


def test_happy_linux_keeps_upx_and_no_console_but_does_not_strip():
    # AlmaLinux 9's strip (binutils 2.35) rewrites numpy's vendored
    # libscipy_openblas64 into an ELF the loader refuses ("ELF load command
    # address/offset not page-aligned"): numpy, and with it voice output and
    # recognition, failed in axross-full 0.13.22. Nothing is stripped.
    o = B.exe_options("linux")
    assert (o["strip"], o["upx"], o["console"]) == (False, True, False)
    assert o["upx_exclude"] == ["libQt6*.so*", "libicu*.so*"]


def test_happy_windows_is_a_windowed_exe_without_strip_or_upx():
    o = B.exe_options("win32")
    assert (o["strip"], o["upx"], o["console"]) == (False, False, False)


def test_happy_macos_is_a_plain_unsigned_executable():
    o = B.exe_options("darwin")
    assert (o["strip"], o["upx"], o["console"]) == (False, False, True)


# --- sad ------------------------------------------------------------------


def test_sad_an_unknown_platform_is_refused():
    with pytest.raises(ValueError, match="sunos5"):
        B.exe_options("sunos5")


def test_sad_the_spec_takes_its_options_from_here():
    spec = (ROOT / "build" / "axross.spec").read_text(encoding="utf-8")
    assert "exe_options(sys.platform)" in spec
    assert not re.search(r"^\s*(strip|upx|console)=", spec, re.M), "spec still hard-codes them"


# --- edge -----------------------------------------------------------------


@pytest.mark.parametrize("name", ["linux", "linux2"])
def test_edge_every_linux_spelling_is_linux(name):
    assert B.exe_options(name) == B.exe_options("linux")


def test_edge_each_call_returns_a_fresh_dict():
    a = B.exe_options("linux")
    a["upx_exclude"].append("x")
    assert "x" not in B.exe_options("linux")["upx_exclude"]


# --- libraries the host must provide ------------------------------------------
#
# Reported on openSUSE Tumbleweed (glibc 2.44): axross-full's Media
# Player failed with "/tmp/_MEI.../libmvec.so.1: version `GLIBC_2.35' not found
# (required by /usr/lib64/libvorbis.so.0)". The bundle carried the builder's
# libmvec (glibc 2.34) and it shadowed the host's. Reproduced in a Tumbleweed
# container; Fedora 42 and Arch are not affected (their libvorbis does not use
# libmvec). No part of glibc may be bundled.


@pytest.mark.parametrize("name", [
    "libmvec.so.1", "libc.so.6", "libm.so.6", "ld-linux-x86-64.so.2", "libpthread.so.0",
    "libdl.so.2", "librt.so.1", "libutil.so.1", "libresolv.so.2", "libnss_files.so.2",
    "libanl.so.1", "libBrokenLocale.so.1", "libthread_db.so.1",
    "libfontconfig.so.1", "libfreetype.so.6",
    # The C++/GCC runtime too: the bundled libstdc++ made Mesa's GL driver
    # (GLIBCXX_3.4.30) fail in-process - see test_bundle_version_floor.
    "libstdc++.so.6", "libgcc_s.so.1",
])
def test_happy_glibc_and_the_font_stack_come_from_the_host(name):
    assert B.host_owned(name)
    assert B.host_owned(f"some/dir/{name}")  # a path: the file name counts


@pytest.mark.parametrize("name", [
    "libz.so.1", "libcrypt-bc2db45e.so.1", "libcrypto.so.3",
    "libmagic.so.1", "libscipy_openblas64_-f48b354e.so", "libavcodec.so.61",
    "libmvecx.so", "mylibc.so.6", "libmath.so",
])
def test_sad_other_libraries_stay_in_the_bundle(name):
    assert not B.host_owned(name)


def test_edge_the_spec_filters_with_this_rule():
    spec = (ROOT / "build" / "axross.spec").read_text(encoding="utf-8")
    assert "host_owned(" in spec
    assert "_HOST_OWNED_LIBS" not in spec  # one rule, kept here


# --- data the bundle does not need (unpacked at every start) ---------------
#
# A one-file binary unpacks its whole archive at every start - axross-full
# 0.13.85: 838 MB, about 28 s of zlib inflate on the build host, twice for a
# start from a terminal (it detaches by starting itself again). 112 MB of it
# were googleapiclient's 605 discovery documents (its PyInstaller hook takes
# them all); axross builds only drive v3 (core/gdrive_client.py).


@pytest.mark.parametrize("path", [
    "googleapiclient/discovery_cache/documents/gmail.v1.json",
    "googleapiclient/discovery_cache/documents/drive.v2.json",
    "googleapiclient/discovery_cache/documents/compute.alpha.json",
])
def test_happy_unused_discovery_documents_leave_the_bundle(path):
    assert B.dropped_data(path)


def test_happy_the_drive_v3_document_stays():
    assert not B.dropped_data("googleapiclient/discovery_cache/documents/drive.v3.json")


@pytest.mark.parametrize("path", [
    "puremagic/magic_data.json",
    "googleapiclient/discovery_cache/__init__.py",
    "googleapiclient/discovery_cache/base.py",
    "other/googleapiclient/discovery_cache/documents/gmail.v1.json",
    "resources/docs/drive.v3.json",
])
def test_sad_other_data_stays(path):
    assert not B.dropped_data(path)


def test_edge_windows_separators_and_the_spec_uses_the_rule():
    assert B.dropped_data("googleapiclient\\discovery_cache\\documents\\gmail.v1.json")
    assert not B.dropped_data("googleapiclient\\discovery_cache\\documents\\drive.v3.json")
    spec = (ROOT / "build" / "axross.spec").read_text(encoding="utf-8")
    assert "dropped_data(" in spec


def test_edge_the_kept_document_is_the_one_the_client_builds():
    source = (ROOT / "core" / "gdrive_client.py").read_text(encoding="utf-8")
    assert 'build("drive", "v3"' in source
    for name in B.KEPT_DISCOVERY_DOCUMENTS:
        api, version, _json = name.split(".")
        assert f'build("{api}", "{version}"' in source, name
