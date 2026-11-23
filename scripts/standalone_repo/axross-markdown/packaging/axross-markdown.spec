# -*- mode: python ; coding: utf-8 -*-
"""One-file binary of axross-markdown (PyInstaller): packaging/build in the
release workflow (.github/workflows/release.yml) runs

    python -m PyInstaller --clean --noconfirm packaging/axross-markdown.spec

after installing the hashed lock (requirements.lock.txt), this project
(--no-deps) and packaging/requirements-pyinstaller.txt.

Every module of the package goes in (the viewer imports parts of itself
late), with its data (the interface languages). The Qt plugins axross's own
binaries leave out are left out here too (axross scripts/bundle_options.py):
platforms nobody selects (VNC - CVE-2026-79680 - eglfs, linuxfb, minimal),
the GTK theme and glib network plugins (they need the host's newer glib)
and the CUPS print plugin (Qt prints to PDF). Here the minimal platform of
Windows and macOS goes too (DROPPED_HERE: qminimal.dll, libqminimal.dylib):
the window runs on windows or cocoa; the children, the self-test and the
CI's smoke tests on offscreen. On Linux the build machine's own libraries
those plugins pulled in go with them: a system library stays only when
something left in the program loads it (packaging/system_libraries.py:
the DT_NEEDED closure - 0.17.2's program carried 94, libcups.so.2, libgtk-3
and gnutls among them, 48 loaded by nothing), and each one that stays goes
in with its package's copyright file and an index of the source packages
(licenses/system/INDEX.txt). The build stops when libcups.so.2 is still in
or a kept library has no licence.

The licences go in too: THIRD_PARTY_LICENSES.txt (package data of
axross_markdown, written by axross's scripts/export_standalone.py: what the
binary contains, the licence texts - PyQt6's GPL-3.0, Qt's LGPL-3.0 - and
where the source code is; Help > About shows it) and the building
interpreter's LICENSE.txt (licenses/python/). The build stops without them.
"""

import os
import sys

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

HERE = os.path.dirname(os.path.abspath(SPEC))  # noqa: F821 - PyInstaller defines SPEC

DROPPED = ("platformthemes/libqgtk3.so", "networkinformation/libqglib.so",
           "libgio-2.0.so.0", "libgmodule-2.0.so.0",
           "platforms/libqvnc.so", "platforms/libqeglfs.so", "platforms/libqlinuxfb.so",
           "platforms/libqminimal.so", "platforms/libqminimalegl.so",
           "platforms/libqvkkhrdisplay.so", "libQt6EglFSDeviceIntegration.so.6",
           "printsupport/libcupsprintersupport.so")
DROPPED_FOLDERS = ("egldeviceintegrations", "sqldrivers")
# (beyond axross's DROPPED: the minimal platform of the Windows and macOS wheels, which nothing here selects)
DROPPED_HERE = ("platforms/qminimal.dll", "platforms/libqminimal.dylib")


def dropped(path):
    path = path.replace("\\", "/")
    if any(path == d or path.endswith("/" + d) for d in DROPPED + DROPPED_HERE):
        return True
    return any(f in DROPPED_FOLDERS for f in path.split("/")[:-1])


WINDOWS = sys.platform == "win32"
LICENCES = "THIRD_PARTY_LICENSES.txt"


def with_licences(datas):
    """*datas* (collect_data_files) with the interpreter's licence; the build stops when the package's
    THIRD_PARTY_LICENSES.txt is not among them or the interpreter has no LICENSE.txt."""
    if not any(os.path.basename(source) == LICENCES and target.replace("\\", "/") == "axross_markdown"
               for source, target in datas):
        raise SystemExit(f"axross-markdown.spec: axross_markdown/{LICENCES} is not installed with the package")
    for folder in (os.path.dirname(os.__file__), sys.base_prefix):  # (POSIX: lib/python3.X/; Windows: the prefix)
        python = os.path.join(folder, "LICENSE.txt")
        if os.path.isfile(python):
            return datas + [(python, "licenses/python")]
    raise SystemExit("axross-markdown.spec: the interpreter has no LICENSE.txt")


a = Analysis(  # noqa: F821
    [os.path.join(HERE, "entry.py")],
    hiddenimports=collect_submodules("axross_markdown"),
    datas=with_licences(collect_data_files("axross_markdown")),
    excludes=["tkinter"],
    noarchive=False,
)
a.binaries = [b for b in a.binaries if not dropped(b[0])]
a.datas = [d for d in a.datas if not dropped(d[0])]
if sys.platform.startswith("linux"):
    sys.path.insert(0, HERE)
    import system_libraries  # noqa: E402 - packaging/system_libraries.py

    a.binaries, left_out = system_libraries.pruned(a.binaries)
    print(f"axross-markdown.spec: {len(left_out)} system libraries no kept binary loads left out:",
          " ".join(sorted(os.path.basename(name) for name, _source, _kind in left_out)))
    if any(os.path.basename(name).startswith("libcups.so") for name, _source, _kind in a.binaries):
        raise SystemExit("axross-markdown.spec: libcups.so.2 is still in the program")
    a.datas += system_libraries.notices(a.binaries, os.path.join(os.path.dirname(HERE), "build", "system-licences"))
pyz = PYZ(a.pure)  # noqa: F821
# UTF-8 mode: --html and --term write UTF-8 into a pipe or file on every
# system (Windows would take its ANSI code page otherwise)
options = [("X utf8_mode=1", None, "OPTION")]
exe = EXE(  # noqa: F821
    pyz,
    a.scripts,
    options,
    a.binaries,
    a.datas,
    [],
    name="axross-markdown",
    debug=False,
    strip=False,
    upx=False,
    # On Windows a window program: a console program opened a console window beside the viewer.
    # Its --term / --html / --version write into the console it was started from (entry.py attaches
    # to it); axross-mdcat.exe below is the terminal view as a console program. Elsewhere a console
    # program as before (no window of its own there).
    console=not WINDOWS,
    icon=os.path.join(HERE, "icons", "axross-logo-256.png") if WINDOWS else None,
    codesign_identity=None,
    entitlements_file=None,
)

if WINDOWS:
    # axross-mdcat.exe: the terminal view (core.markdown_cli) on its own - a console program, no Qt
    terminal = Analysis(  # noqa: F821
        [os.path.join(HERE, "entry_mdcat.py")],
        hiddenimports=collect_submodules("axross_markdown._ax.core"),
        datas=with_licences(collect_data_files("axross_markdown")),
        excludes=["tkinter", "PyQt6"],
        noarchive=False,
    )
    EXE(  # noqa: F821
        PYZ(terminal.pure),  # noqa: F821
        terminal.scripts,
        options,
        terminal.binaries,
        terminal.datas,
        [],
        name="axross-mdcat",
        debug=False,
        strip=False,
        upx=False,
        console=True,
        icon=os.path.join(HERE, "icons", "axross-logo-256.png"),
        codesign_identity=None,
        entitlements_file=None,
    )
