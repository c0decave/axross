"""PyInstaller EXE options per operating system, for build/axross.spec.

Windows has no strip tool and UPX corrupts Qt DLLs; macOS code signatures
break when a bundled library is stripped, and a windowed one-file build is
deprecated there, so the macOS binary is a plain console executable. Linux
does not strip either: the builder's strip (binutils 2.35, AlmaLinux 9)
turns numpy's vendored libscipy_openblas64 into an ELF the loader refuses
("ELF load command address/offset not page-aligned"), and numpy - with it
voice output and recognition - fails in axross-full.
"""

from __future__ import annotations


def exe_options(platform: str) -> dict:
    """``strip``, ``upx``, ``upx_exclude`` and ``console`` for ``EXE()``."""
    if platform.startswith("linux"):
        return {
            "strip": False,  # see the module docstring: strip breaks OpenBLAS
            "upx": True,  # shrinks the binary ~30-40 %, harmless on ELF
            "upx_exclude": ["libQt6*.so*", "libicu*.so*"],  # Qt plugins break under UPX
            "console": False,
        }
    if platform == "win32":
        return {"strip": False, "upx": False, "upx_exclude": [], "console": False}
    if platform == "darwin":
        return {"strip": False, "upx": False, "upx_exclude": [], "console": True}
    raise ValueError(f"no bundle options for platform {platform!r}")


#: Libraries the host provides, never the bundle. glibc in all its parts:
#: a bundled copy is the builder's (AlmaLinux 9, glibc 2.34) and shadows the
#: host's - 0.13.22 full carried libmvec, and on openSUSE Tumbleweed the
#: system libvorbis then failed with "libmvec.so.1: version GLIBC_2.35 not
#: found", taking the Media Player down. The host has every glibc part by
#: definition (the binary needs glibc 2.34 or later anyway). fontconfig and
#: freetype read the host's /etc/fonts, written for the host's version.
HOST_OWNED = (
    "ld-linux", "libc.so", "libm.so", "libmvec.so", "libpthread.so", "libdl.so", "librt.so",
    "libutil.so", "libresolv.so", "libnsl.so", "libanl.so", "libBrokenLocale.so",
    "libthread_db.so", "libnss_", "libcidn.so", "libmemusage.so", "libpcprofile.so",
    "libSegFault.so", "libc_malloc_debug.so",
    "libfontconfig.so", "libfreetype.so",
    # The C++ and GCC runtimes: everything loaded into the process uses ONE
    # libstdc++, and the bundled one (builder: GLIBCXX_3.4.29) is older than
    # the host's. Mesa's libgallium needs GLIBCXX_3.4.30: with ours, an
    # OpenGL context aborted with "Could not initialize GLX" (axross-full on
    # Arch). The host's is never older than the builder's, the oldest
    # supported system; elf_needs.version_floor_problems holds that.
    "libstdc++.so", "libgcc_s.so",
)


def host_owned(path: str) -> bool:
    """Whether the library *path* (a file name or a path to one) must come
    from the host rather than from the bundle."""
    name = path.replace("\\", "/").rsplit("/", 1)[-1]
    return name.startswith(HOST_OWNED)


#: Sonames a bundled ELF may need from the target system besides
#: HOST_OWNED: the graphics stack (it belongs to the GPU driver), the core
#: X11 and Wayland client libraries (part of every session that can show a
#: window) and the PulseAudio client (pipewire-pulse speaks through it).
#: Every other dependency must be in the bundle - PyInstaller only bundles
#: what it finds on the build machine, so a library missing there is left
#: to the target system without a word. That shipped Qt's TIFF plugin
#: needing libtiff.so.5 (Arch and Fedora have .so.6 only) and Qt's xcb
#: plugin needing libxcb-cursor.so.0 (not installed by default on Ubuntu or
#: Debian: no window on X11). scripts/elf_needs.py checks a built bundle.
HOST_PROVIDED_SONAMES = (
    "libGL.so.", "libEGL.so.", "libGLX.so.", "libOpenGL.so.", "libGLdispatch.so.",
    "libdrm.so.", "libgbm.so.", "libvulkan.so.",
    "libwayland-client.so.", "libwayland-cursor.so.", "libwayland-egl.so.",
    "libxcb.so.", "libX11.so.", "libX11-xcb.so.",
    "libpulse.so.", "libpulse-simple.so.",
)
HOST_PROVIDED = HOST_OWNED + HOST_PROVIDED_SONAMES

#: Symbol versions of host-provided libraries the builder deliberately does
#: not install, so elf_needs.version_floor_problems cannot read them there.
#: libpulse: installing it would make PyInstaller bundle its libsndfile /
#: libvorbis chain, which then shadows the host's; it has only ever defined
#: PULSE_0.
HOST_VERSION_FLOOR = {
    "libpulse.so.0": frozenset({"PULSE_0"}),
    "libpulse-simple.so.0": frozenset({"PULSE_0"}),
}


def host_provided(soname: str) -> bool:
    """Whether the target system provides *soname* (a bundled ELF may need
    it without the bundle carrying it). Matches on the full soname stem:
    ``libxcb.so.1`` is provided, ``libxcb-cursor.so.0`` is not."""
    return soname.startswith(HOST_PROVIDED)


#: Files the build removes from the bundle. Qt's GTK 3 platform theme
#: needs the whole GTK 3 stack, which axross does not bundle (a second GTK
#: next to the host's breaks on the host's themes and modules); without the
#: plugin Qt uses its own theme, as on any desktop that is not GTK.
#: libgio leaves with the two Qt plugins that link it (the GTK theme and
#: the GLib network-information backend; axross uses neither): the bundled
#: glib would load the HOST's GIO modules from its compiled-in
#: /usr/lib64/gio/modules (on Arch a symlink to /usr/lib), and those need a
#: newer glib ("undefined symbol: g_free_sized"). The --system-libs gate
#: fails if anything left in the bundle still needs libgio.
DROPPED = ("platformthemes/libqgtk3.so", "networkinformation/libqglib.so",
           "libgio-2.0.so.0", "libgmodule-2.0.so.0")


def dropped(path: str) -> bool:
    """Whether the build removes *path* (a destination path in the bundle):
    an entry of DROPPED is the whole path or its trailing components."""
    path = path.replace("\\", "/")
    return any(path == d or path.endswith("/" + d) for d in DROPPED)


#: googleapiclient's discovery documents: its PyInstaller hook bundles all
#: 605 (112 MB unpacked at every start of a one-file binary); axross builds
#: only these (core/gdrive_client.py).
DISCOVERY_DOCUMENTS = "googleapiclient/discovery_cache/documents/"
KEPT_DISCOVERY_DOCUMENTS = ("drive.v3.json",)


def dropped_data(path: str) -> bool:
    """Whether the build removes the data file *path* (a destination path
    in the bundle): a discovery document axross never builds a client for."""
    path = path.replace("\\", "/")
    if not path.startswith(DISCOVERY_DOCUMENTS):
        return False
    return path[len(DISCOVERY_DOCUMENTS):] not in KEPT_DISCOVERY_DOCUMENTS
