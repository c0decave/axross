# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec of axross's tools as programs of their own:
axross-media-player and axross-system-info.

Built by ``scripts/build_bundle.sh media-player|system-info`` from the
project scripts/export_standalone.py wrote (AXROSS_STANDALONE_SRC: its src/
folder) - not from the axross tree, where PyInstaller would follow every
import inside a function into the rest of axross. The rules of the axross
bundles apply: the host's glibc and font stack (bundle_options.host_owned),
the dropped files, the licence texts of everything bundled.
"""
from __future__ import annotations

import os
import sys

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

PROJECT_ROOT = os.path.abspath(os.path.join(SPECPATH, ".."))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "scripts"))
from bundle_licenses import licence_datas  # noqa: E402
from bundle_options import dropped, dropped_data, exe_options, host_owned  # noqa: E402

APPS = {"media-player": "axross_media_player", "system-info": "axross_system_info"}
APP = os.environ.get("AXROSS_STANDALONE_APP", "")
if APP not in APPS:
    raise SystemExit(f"AXROSS_STANDALONE_APP must be one of {sorted(APPS)}, got {APP!r}")
PACKAGE = APPS[APP]
SRC = os.environ.get("AXROSS_STANDALONE_SRC", "")
if not os.path.isfile(os.path.join(SRC, PACKAGE, "__main__.py")):
    raise SystemExit(f"AXROSS_STANDALONE_SRC={SRC!r} holds no exported {PACKAGE}")
sys.path.insert(0, SRC)

hiddenimports = collect_submodules(PACKAGE)
excludes = ["setuptools", "pip", "wheel", "pytest", "tkinter", "sphinx", "IPython"]
if APP == "media-player":
    hiddenimports += ["numpy", "PyQt6.QtMultimedia"]
else:
    # No sound: Qt Multimedia's FFmpeg libraries would add 100 MB for nothing.
    excludes += ["PyQt6.QtMultimedia", "PyQt6.QtMultimediaWidgets", "numpy"]
datas = collect_data_files(PACKAGE)

a = Analysis(
    [os.path.join(SRC, PACKAGE, "__main__.py")],
    pathex=[SRC],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=excludes,
    noarchive=False,
)
a.binaries = TOC(
    entry for entry in a.binaries if not host_owned(entry[0]) and not dropped(entry[0])
)
a.datas = TOC(entry for entry in a.datas if not dropped_data(entry[0]) and not dropped(entry[0]))
a.datas = TOC(list(a.datas) + licence_datas(a, os.path.join(workpath, "licenses")))

pyz = PYZ(a.pure, a.zipped_data, cipher=None)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name=f"axross-{APP}",
    debug=False,
    bootloader_ignore_signals=False,
    runtime_tmpdir=None,
    **exe_options(sys.platform),
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
