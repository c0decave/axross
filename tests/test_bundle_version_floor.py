"""libstdc++ and libgcc_s come from the host; a gate keeps that safe.

The bundles carried the builder's libstdc++ (AlmaLinux 9, GLIBCXX_3.4.29).
It shadowed the host's for everything loaded into the process: Mesa's
libgallium needs GLIBCXX_3.4.30, so in axross-full on Arch an OpenGL
context ended in "Could not initialize GLX" and an abort (with the host's
libstdc++ preloaded: created and current). The host's libstdc++ is never
older than the builder's (the builder is the oldest supported system), so
it goes into bundle_options.HOST_OWNED with libgcc_s.

That is only safe while no bundled ELF needs a symbol version the oldest
supported system lacks. elf_needs.version_floor_problems checks every
bundled ELF's version needs (DT_VERNEED) against the libraries of the
machine that builds it (DT_VERDEF) - in the builder image, that machine
IS the oldest supported system.
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import bundle_options as B  # noqa: E402
import elf_needs as E  # noqa: E402

_BASE = 0x400000
_DT = {"NEEDED": 1, "STRTAB": 5, "STRSZ": 10, "SONAME": 14, "VERDEF": 0x6FFFFFFC,
       "VERDEFNUM": 0x6FFFFFFD, "VERNEED": 0x6FFFFFFE, "VERNEEDNUM": 0x6FFFFFFF}


def _elf(needed=(), *, versions=None, defs=None, soname=None, bits=64) -> bytes:
    """A shared object with DT_NEEDED, optional DT_VERNEED (*versions*:
    soname -> version names), optional DT_VERDEF (*defs*, after the base
    entry for *soname*)."""
    e = "<"
    strtab = bytearray(b"\0")

    def s(text: str) -> int:
        off = len(strtab)
        strtab.extend(text.encode() + b"\0")
        return off

    needed_offs = [s(n) for n in needed]
    so_off = s(soname) if soname else None
    verneed = bytearray()
    if versions:
        items = list(versions.items())
        for i, (lib, vers) in enumerate(items):
            file_off = s(lib)
            nxt = 0 if i == len(items) - 1 else 16 + 16 * len(vers)
            verneed += struct.pack(e + "HHIII", 1, len(vers), file_off, 16, nxt)
            for j, v in enumerate(vers):
                verneed += struct.pack(e + "IHHII", 0, 0, 2 + j, s(v), 0 if j == len(vers) - 1 else 16)
    verdef = bytearray()
    if defs is not None:
        names = [soname or "lib.so"] + list(defs)
        for i, name in enumerate(names):
            nxt = 0 if i == len(names) - 1 else 28
            verdef += struct.pack(e + "HHHHIII", 1, 1 if i == 0 else 0, i + 1, 1, 0, 20, nxt)
            verdef += struct.pack(e + "II", s(name), 0)
    ehsize, phentsize = (64, 56) if bits == 64 else (52, 32)
    strtab_off = ehsize + 2 * phentsize
    vn_off = strtab_off + len(strtab)
    vn_off += (-vn_off) % 8
    vd_off = vn_off + len(verneed)
    vd_off += (-vd_off) % 8
    dyn_off = vd_off + len(verdef)
    dyn_off += (-dyn_off) % 8
    entries = [(_DT["NEEDED"], o) for o in needed_offs]
    if so_off is not None:
        entries.append((_DT["SONAME"], so_off))
    if versions:
        entries += [(_DT["VERNEED"], _BASE + vn_off), (_DT["VERNEEDNUM"], len(versions))]
    if defs is not None:
        entries += [(_DT["VERDEF"], _BASE + vd_off), (_DT["VERDEFNUM"], len(defs) + 1)]
    entries += [(_DT["STRTAB"], _BASE + strtab_off), (_DT["STRSZ"], len(strtab)), (0, 0)]
    dyn = b"".join(struct.pack(e + ("qQ" if bits == 64 else "iI"), t, v) for t, v in entries)
    total = dyn_off + len(dyn)

    def phdr(p_type, off, size):
        if bits == 64:
            return struct.pack(e + "IIQQQQQQ", p_type, 6, off, _BASE + off, _BASE + off, size, size, 8)
        return struct.pack(e + "IIIIIIII", p_type, off, _BASE + off, _BASE + off, size, size, 6, 4)

    word = "Q" if bits == 64 else "I"
    ident = b"\x7fELF" + bytes([2 if bits == 64 else 1, 1, 1]) + b"\0" * 9
    header = ident + struct.pack(e + "HHI" + word * 3 + "IHHHHHH", 3, 62, 1, 0, ehsize, 0, 0,
                                 ehsize, phentsize, 2, 64, 0, 0)
    body = bytearray(header + phdr(1, 0, total) + phdr(2, dyn_off, len(dyn)) + strtab)
    body += b"\0" * (vn_off - len(body))
    body += verneed
    body += b"\0" * (vd_off - len(body))
    body += verdef
    body += b"\0" * (dyn_off - len(body))
    return bytes(body + dyn)


def _w(path: Path, data: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def _host(tmp_path: Path, libs: dict[str, list[str]]):
    """A fake "this machine": soname -> path of a library defining *versions*."""
    paths = {so: _w(tmp_path / "host" / so, _elf(defs=v, soname=so)) for so, v in libs.items()}
    return lambda soname: str(paths[soname]) if soname in paths else None


OLDEST = {"libstdc++.so.6": [f"GLIBCXX_3.4.{i}" for i in range(30)] + ["CXXABI_1.3.13"],
          "libc.so.6": ["GLIBC_2.2.5", "GLIBC_2.17", "GLIBC_2.34"]}


# --- happy ----------------------------------------------------------------


def test_happy_version_needs_and_defs_are_read(tmp_path):
    f = _w(tmp_path / "libq.so", _elf(["libstdc++.so.6", "libc.so.6"],
                                      versions={"libstdc++.so.6": ["GLIBCXX_3.4.29", "CXXABI_1.3.9"],
                                                "libc.so.6": ["GLIBC_2.34"]}))
    assert E.version_needs(str(f)) == {"libstdc++.so.6": {"GLIBCXX_3.4.29", "CXXABI_1.3.9"},
                                       "libc.so.6": {"GLIBC_2.34"}}
    lib = _w(tmp_path / "libstdc++.so.6", _elf(defs=["GLIBCXX_3.4", "GLIBCXX_3.4.29"],
                                               soname="libstdc++.so.6"))
    assert E.version_defs(str(lib)) == {"GLIBCXX_3.4", "GLIBCXX_3.4.29"}  # not the soname entry


def test_happy_a_bundle_within_the_floor_passes(tmp_path):
    _w(tmp_path / "b" / "libQt6Core.so.6",
       _elf(["libstdc++.so.6"], versions={"libstdc++.so.6": ["GLIBCXX_3.4.29"]}))
    assert E.version_floor_problems(str(tmp_path / "b"), _host(tmp_path, OLDEST)) == []


def test_happy_libstdcxx_and_libgcc_come_from_the_host():
    for name in ("libstdc++.so.6", "libgcc_s.so.1", "PyQt6/Qt6/lib/libstdc++.so.6"):
        assert B.host_owned(name), name
    assert not B.host_owned("libstdc++fs.a") and not B.host_owned("libgcc_extra.so.1")


# --- sad ------------------------------------------------------------------


def test_sad_a_need_newer_than_the_oldest_system_is_named(tmp_path):
    _w(tmp_path / "b" / "plugins/libnew.so",
       _elf(["libstdc++.so.6"], versions={"libstdc++.so.6": ["GLIBCXX_3.4.30", "GLIBCXX_3.4.21"]}))
    problems = E.version_floor_problems(str(tmp_path / "b"), _host(tmp_path, OLDEST))
    assert len(problems) == 1
    assert "plugins/libnew.so" in problems[0] and "GLIBCXX_3.4.30" in problems[0]
    assert "GLIBCXX_3.4.21" not in problems[0]


def test_sad_glibc_newer_than_the_floor_is_named(tmp_path):
    _w(tmp_path / "b" / "x.so", _elf(["libc.so.6"], versions={"libc.so.6": ["GLIBC_2.35"]}))
    assert "GLIBC_2.35" in "\n".join(
        E.version_floor_problems(str(tmp_path / "b"), _host(tmp_path, OLDEST)))


def test_sad_a_host_library_that_cannot_be_found_is_a_problem(tmp_path):
    # Not silently "fine": the floor could not be checked.
    _w(tmp_path / "b" / "x.so", _elf(["libfoo.so.1"], versions={"libfoo.so.1": ["FOO_1"]}))
    problems = E.version_floor_problems(str(tmp_path / "b"), _host(tmp_path, OLDEST))
    assert problems and "libfoo.so.1" in problems[0] and "not found" in problems[0]


# --- edge -----------------------------------------------------------------


def test_edge_needs_satisfied_inside_the_bundle_are_not_checked_against_the_host(tmp_path):
    _w(tmp_path / "b" / "libz.so.1", _elf(defs=["ZLIB_1.2.13"], soname="libz.so.1"))
    _w(tmp_path / "b" / "x.so", _elf(["libz.so.1"], versions={"libz.so.1": ["ZLIB_1.2.13"]}))
    assert E.version_floor_problems(str(tmp_path / "b"), _host(tmp_path, OLDEST)) == []


def test_edge_an_elf_without_version_needs(tmp_path):
    f = _w(tmp_path / "plain.so", _elf(["libc.so.6"]))
    assert E.version_needs(str(f)) == {}
    assert E.version_defs(str(f)) == set()


def test_edge_32_bit_version_records(tmp_path):
    f = _w(tmp_path / "x32.so", _elf(["libc.so.6"], versions={"libc.so.6": ["GLIBC_2.0"]}, bits=32))
    assert E.version_needs(str(f)) == {"libc.so.6": {"GLIBC_2.0"}}


def test_edge_host_library_resolves_real_libc():
    path = E.host_library("libc.so.6")
    assert path and Path(path).is_file()
    assert {"GLIBC_2.2.5", "GLIBC_2.17"} <= E.version_defs(path)
    assert E.host_library("libno_such_library_xyz.so.9") is None


def test_edge_the_build_gate_runs_the_floor_check():
    smoke = (ROOT / "scripts" / "bundle_smoke.py").read_text(encoding="utf-8")
    assert "version_floor_problems" in smoke and "bundled_host_libraries" in smoke


def test_edge_dropped_plugins_are_not_checked(tmp_path):
    _w(tmp_path / "b" / "PyQt6/Qt6/plugins/platformthemes/libqgtk3.so",
       _elf(["libgtk-3.so.0"], versions={"libgtk-3.so.0": ["GTK_3"]}))
    assert E.version_floor_problems(str(tmp_path / "b"), _host(tmp_path, OLDEST),
                                    skip=B.dropped) == []


# --- host libraries the builder deliberately does not have -------------------------
#
# libpulse is the host's (bundle_options.HOST_PROVIDED) and NOT installed in
# the builder: PyInstaller would bundle its libsndfile/libvorbis chain, which
# then shadows the host's (the libmvec crash of 0.13.22). The floor for it
# comes from a short explicit table instead: libpulse has only ever defined
# PULSE_0. The first builder run of the gate stopped on exactly this need.


def test_happy_a_known_host_version_passes_without_the_library(tmp_path):
    _w(tmp_path / "b" / "libQt6Multimedia.so.6",
       _elf(["libpulse.so.0"], versions={"libpulse.so.0": ["PULSE_0"]}))
    assert E.version_floor_problems(str(tmp_path / "b"), _host(tmp_path, OLDEST),
                                    known=B.HOST_VERSION_FLOOR) == []


def test_sad_a_version_outside_the_known_table_is_named(tmp_path):
    _w(tmp_path / "b" / "x.so", _elf(["libpulse.so.0"], versions={"libpulse.so.0": ["PULSE_1"]}))
    problems = E.version_floor_problems(str(tmp_path / "b"), _host(tmp_path, OLDEST),
                                        known=B.HOST_VERSION_FLOOR)
    assert problems and "PULSE_1" in problems[0]


def test_edge_the_table_only_holds_host_provided_libraries_absent_from_the_builder():
    for soname in B.HOST_VERSION_FLOOR:
        assert B.host_provided(soname) and not B.host_owned(soname), soname
    assert B.HOST_VERSION_FLOOR["libpulse.so.0"] == frozenset({"PULSE_0"})
    docker = (ROOT / "Dockerfile.build").read_text(encoding="utf-8")
    assert "pulseaudio-libs" not in docker
