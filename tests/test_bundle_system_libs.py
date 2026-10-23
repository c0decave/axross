"""Every system library a bundled ELF needs is either bundled or one the
target system is known to provide.

PyInstaller bundles a dependency only when it finds it on the build
machine. The builder image (Dockerfile.build, AlmaLinux 9) had no libtiff
and no xcb-util libraries, so axross-full shipped Qt's TIFF plugin needing
``libtiff.so.5`` - which Arch and Fedora no longer have (they ship .so.6) -
and Qt's xcb platform plugin needing ``libxcb-cursor.so.0``, which Ubuntu
and Debian do not install by default: no window on X11 there.
scripts/elf_needs.py reads DT_NEEDED without any external tool, and
bundle_options.HOST_PROVIDED names what the target system must have.
"""

from __future__ import annotations

import os
import re
import struct
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import bundle_options as B  # noqa: E402
import elf_needs as E  # noqa: E402

_BASE = 0x400000


def _elf(needed: list[str], *, bits: int = 64, big: bool = False) -> bytes:
    """A minimal shared object: one PT_LOAD over the whole file, one
    PT_DYNAMIC with DT_NEEDED entries, DT_STRTAB and DT_STRSZ."""
    e = ">" if big else "<"
    word = "Q" if bits == 64 else "I"
    ehsize, phentsize = (64, 56) if bits == 64 else (52, 32)
    strtab = b"\0"
    offsets = []
    for name in needed:
        offsets.append(len(strtab))
        strtab += name.encode() + b"\0"
    strtab_off = ehsize + 2 * phentsize
    dyn_off = strtab_off + len(strtab)
    dyn_off += (-dyn_off) % 8
    entries = [(1, o) for o in offsets] + [(5, _BASE + strtab_off), (10, len(strtab)), (0, 0)]
    dyn = b"".join(struct.pack(e + ("qQ" if bits == 64 else "iI"), t, v) for t, v in entries)
    total = dyn_off + len(dyn)

    def phdr(p_type, off, size):
        if bits == 64:
            return struct.pack(e + "IIQQQQQQ", p_type, 6, off, _BASE + off, _BASE + off,
                               size, size, 8)
        return struct.pack(e + "IIIIIIII", p_type, off, _BASE + off, _BASE + off, size, size,
                           6, 4)

    ident = b"\x7fELF" + bytes([2 if bits == 64 else 1, 2 if big else 1, 1]) + b"\0" * 9
    header = ident + struct.pack(e + "HHI" + word * 3 + "IHHHHHH", 3, 62, 1, 0, ehsize, 0, 0,
                                 ehsize, phentsize, 2, 64, 0, 0)
    body = header + phdr(1, 0, total) + phdr(2, dyn_off, len(dyn)) + strtab
    body += b"\0" * (dyn_off - len(body))
    return body + dyn


def _write(path: Path, data: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


# --- happy ----------------------------------------------------------------


def test_happy_needed_reads_the_dt_needed_entries_in_order(tmp_path):
    f = _write(tmp_path / "libx.so", _elf(["libc.so.6", "libtiff.so.5"]))
    assert E.needed(str(f)) == ["libc.so.6", "libtiff.so.5"]


def test_happy_a_missing_system_library_is_reported_with_its_user(tmp_path):
    _write(tmp_path / "PyQt6/plugins/imageformats/libqtiff.so", _elf(["libtiff.so.5", "libc.so.6"]))
    scan = E.system_needs(str(tmp_path), B.HOST_PROVIDED)
    assert scan["needs"] == {"libtiff.so.5": ["PyQt6/plugins/imageformats/libqtiff.so"]}
    assert (scan["elf_files"], scan["unreadable"]) == (1, [])


def test_happy_a_bundled_library_is_not_a_system_need(tmp_path):
    _write(tmp_path / "PyQt6/plugins/imageformats/libqtiff.so", _elf(["libtiff.so.5"]))
    _write(tmp_path / "libtiff.so.5", _elf(["libc.so.6"]))
    assert E.system_needs(str(tmp_path), B.HOST_PROVIDED)["needs"] == {}


def test_happy_graphics_glibc_and_audio_come_from_the_system():
    for soname in ("libc.so.6", "libm.so.6", "ld-linux-x86-64.so.2", "libGL.so.1", "libEGL.so.1",
                   "libdrm.so.2", "libwayland-client.so.0", "libwayland-egl.so.1",
                   "libxcb.so.1", "libfontconfig.so.1", "libfreetype.so.6", "libpulse.so.0"):
        assert B.host_provided(soname), soname


def test_happy_the_gtk3_platform_theme_is_dropped_from_the_bundle():
    # libqgtk3 needs the whole GTK 3 stack; Qt falls back to its own theme
    # without it. Bundling GTK would load a second GTK next to the host's.
    assert B.dropped("PyQt6/Qt6/plugins/platformthemes/libqgtk3.so")
    assert not B.dropped("PyQt6/Qt6/plugins/platforms/libqxcb.so")


# --- sad ------------------------------------------------------------------


def test_sad_tiff_xcb_util_and_gtk_are_not_system_provided():
    # Each of these is missing on a distribution axross targets.
    for soname in ("libtiff.so.5", "libxcb-cursor.so.0", "libxcb-icccm.so.4",
                   "libxcb-image.so.0", "libxcb-keysyms.so.1", "libxcb-render-util.so.0",
                   "libxcb-util.so.1", "libXrandr.so.2", "libatomic.so.1", "libgtk-3.so.0"):
        assert not B.host_provided(soname), soname


def test_sad_a_non_elf_file_is_not_an_elf(tmp_path):
    f = _write(tmp_path / "notes.txt", b"hello world, not an ELF at all")
    assert E.needed(str(f)) is None


def test_sad_a_truncated_elf_raises_instead_of_reading_as_clean(tmp_path):
    f = _write(tmp_path / "libcut.so", _elf(["libtiff.so.5"])[:80])
    with pytest.raises(ValueError):
        E.needed(str(f))


def test_sad_an_unreadable_elf_is_counted_not_skipped(tmp_path):
    _write(tmp_path / "libcut.so", _elf(["libtiff.so.5"])[:80])
    scan = E.system_needs(str(tmp_path), B.HOST_PROVIDED)
    assert scan["unreadable"] and scan["unreadable"][0].startswith("libcut.so")
    assert E.problems(scan), "an unreadable ELF must fail the gate"


def test_sad_problems_name_the_soname_and_a_user(tmp_path):
    _write(tmp_path / "plugins/libqxcb.so", _elf(["libxcb-cursor.so.0"]))
    text = "\n".join(E.problems(E.system_needs(str(tmp_path), B.HOST_PROVIDED)))
    assert "libxcb-cursor.so.0" in text and "plugins/libqxcb.so" in text


def test_sad_a_folder_without_any_elf_fails_the_gate(tmp_path):
    # A scan that opened nothing would otherwise read as "no problems".
    _write(tmp_path / "readme.txt", b"no binaries here")
    assert E.problems(E.system_needs(str(tmp_path), B.HOST_PROVIDED))


# --- edge -----------------------------------------------------------------


def test_edge_32_bit_and_big_endian_elves_parse(tmp_path):
    a = _write(tmp_path / "a.so", _elf(["liba.so.1"], bits=32))
    b = _write(tmp_path / "b.so", _elf(["libb.so.2"], big=True))
    assert (E.needed(str(a)), E.needed(str(b))) == (["liba.so.1"], ["libb.so.2"])


def test_edge_a_static_elf_has_no_needs(tmp_path):
    f = _write(tmp_path / "rg", _elf([]))
    assert E.needed(str(f)) == []


def test_edge_symlinks_are_not_scanned_twice_and_dropped_plugins_are_ignored(tmp_path):
    lib = _write(tmp_path / "lib/libfoo.so.1", _elf(["libbar.so.3"]))
    os.symlink(lib.name, tmp_path / "lib/libfoo.so")
    _write(tmp_path / "PyQt6/Qt6/plugins/platformthemes/libqgtk3.so", _elf(["libgtk-3.so.0"]))
    scan = E.system_needs(str(tmp_path), B.HOST_PROVIDED, skip=B.dropped)
    assert scan["needs"] == {"libbar.so.3": ["lib/libfoo.so.1"]}
    assert scan["elf_files"] == 1


def test_edge_host_provided_matches_whole_sonames_not_prefixes():
    # "libxcb.so" is provided; libxcb-cursor.so is a different library.
    assert B.host_provided("libxcb.so.1")
    assert not B.host_provided("libxcb-cursor.so.0")
    assert not B.host_provided("libGLU.so.1")


def test_edge_the_real_qt_tiff_plugin_reads_like_the_builder_saw_it():
    try:
        import PyQt6
    except ImportError:
        pytest.skip("PyQt6 not installed")
    plugin = Path(PyQt6.__file__).parent / "Qt6/plugins/imageformats/libqtiff.so"
    if not plugin.is_file():
        pytest.skip("no Qt TIFF plugin in this PyQt6")
    assert any(n.startswith("libtiff.so.") for n in E.needed(str(plugin)))


def test_edge_the_spec_drops_what_bundle_options_drops():
    spec = (ROOT / "build" / "axross.spec").read_text(encoding="utf-8")
    assert "dropped(" in spec and "host_owned(" in spec


def test_happy_the_builder_installs_what_the_qt_plugins_need():
    # PyInstaller bundles only what it finds in the builder; the package
    # for each library the --system-libs gate found missing in 0.13.x.
    text = (ROOT / "Dockerfile.build").read_text(encoding="utf-8")
    for package in ("libtiff", "xcb-util-cursor", "xcb-util-wm", "xcb-util-image",
                    "xcb-util-keysyms", "xcb-util-renderutil", "xcb-util", "libXrandr",
                    "libatomic"):
        assert re.search(rf"(?m)^\s+.*\b{re.escape(package)}\b(?![-\w])", text), package


def test_happy_gio_leaves_the_bundle_with_the_qt_plugins_that_need_it():
    # The bundled glib (2.68) would load the HOST's GIO modules from its
    # compiled-in /usr/lib64/gio/modules (Arch: a symlink to /usr/lib) and
    # they need newer glib ("undefined symbol: g_free_sized", measured in
    # axross-full). Only Qt's GTK theme and GLib network-information plugin
    # link libgio; axross uses neither.
    for path in ("PyQt6/Qt6/plugins/networkinformation/libqglib.so", "libgio-2.0.so.0",
                 "libgmodule-2.0.so.0"):
        assert B.dropped(path), path


def test_sad_glib_itself_and_lookalikes_stay():
    for path in ("libglib-2.0.so.0", "libgobject-2.0.so.0", "PyQt6/Qt6/lib/libQt6Core.so.6",
                 "PyQt6/Qt6/plugins/networkinformation/libqnetworkmanager.so",
                 "xlibgio-2.0.so.0"):
        assert not B.dropped(path), path
