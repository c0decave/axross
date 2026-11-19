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
the GTK theme and glib network plugins (they need the host's newer glib) and
the CUPS print plugin (libcups.so.2 is not bundled; Qt prints to PDF).
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


def dropped(path):
    path = path.replace("\\", "/")
    if any(path == d or path.endswith("/" + d) for d in DROPPED):
        return True
    return any(f in DROPPED_FOLDERS for f in path.split("/")[:-1])


WINDOWS = sys.platform == "win32"

a = Analysis(  # noqa: F821
    [os.path.join(HERE, "entry.py")],
    hiddenimports=collect_submodules("axross_markdown"),
    datas=collect_data_files("axross_markdown"),
    excludes=["tkinter"],
    noarchive=False,
)
a.binaries = [b for b in a.binaries if not dropped(b[0])]
a.datas = [d for d in a.datas if not dropped(d[0])]
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
        datas=collect_data_files("axross_markdown"),
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
