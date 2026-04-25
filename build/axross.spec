# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller build spec for axross.

Build via ``scripts/build_bundle.sh`` (wraps pyinstaller with the
right invocation). Two flavours, controlled by the
``AXROSS_BUNDLE_FLAVOR`` env var:

  * ``full``  (default) — every optional protocol bundled
  * ``slim``            — cloud OAuth + Windows backends stripped

The slim variant drops ~150 MB by excluding googleapiclient,
msal, dropbox, azure, exchangelib, pywinrm, and impacket. It
targets a "SSH + SMB + WebDAV + S3 + Android" user that doesn't
need cloud-OAuth or Windows-protocol access.

PyInstaller can't follow the dynamic imports through
``core.backend_registry.load_backend_class(proto)`` — every
backend module must be listed as a hidden import explicitly. We
collect them via ``collect_submodules`` so future core modules
are picked up automatically.
"""
from __future__ import annotations

import os
import sys

from PyInstaller.utils.hooks import (
    collect_data_files,
    collect_submodules,
)

# Spec files run with SPECPATH pointing at their own dir.
PROJECT_ROOT = os.path.abspath(os.path.join(SPECPATH, ".."))
sys.path.insert(0, PROJECT_ROOT)

FLAVOR = os.environ.get("AXROSS_BUNDLE_FLAVOR", "full")
if FLAVOR not in ("full", "slim"):
    raise SystemExit(
        f"AXROSS_BUNDLE_FLAVOR must be 'full' or 'slim', got {FLAVOR!r}"
    )

# --------------------------------------------------------------------------
# Hidden imports
# --------------------------------------------------------------------------
# Our own code — collect_submodules picks up every .py under each
# package so adding a new backend to core/ doesn't require a spec
# edit. Cheaper than enumerating + easier to keep in sync.
hiddenimports = []
hiddenimports += collect_submodules("core")
hiddenimports += collect_submodules("ui")
hiddenimports += collect_submodules("models")

# PyQt6 optional submodules — Qt6 is installed per-module, the
# bindings we touch outside PyQt6.QtWidgets need hints.
hiddenimports += [
    "PyQt6.QtCore",
    "PyQt6.QtGui",
    "PyQt6.QtWidgets",
    "PyQt6.QtSvg",          # icon_provider renders SVGs via QSvgRenderer
    "PyQt6.sip",
]

# Cryptography — dynamic backend load; PyInstaller's hook usually
# covers these but be explicit so a minor release bump doesn't
# break us silently.
hiddenimports += [
    "cryptography.hazmat.backends.openssl",
    "cryptography.hazmat.bindings.openssl",
    "cryptography.hazmat.bindings.openssl.binding",
]

# Keyring — credentials.py queries the OS-native backend via the
# keyring package. Without these hidden imports, PyInstaller
# bundles only the fallback "null" backend, and every profile
# password fails to load with the warning we've already seen in
# test output.
hiddenimports += [
    "keyring.backends.SecretService",  # GNOME Keyring / libsecret
    "keyring.backends.kwallet",        # KDE Wallet
    "keyring.backends.chainer",
    "keyring.backends.fail",
    "keyring.backends.null",
    "jeepney",                         # dbus dep of SecretService
    "secretstorage",
]

# Paramiko + cryptography are covered by their own hooks; named
# here just for documentation.
hiddenimports += [
    "paramiko",
]

# --------------------------------------------------------------------------
# Excludes (per flavor)
# --------------------------------------------------------------------------
# The slim bundle loses cloud OAuth + Windows protocols.
excludes: list[str] = []
if FLAVOR == "slim":
    excludes += [
        # Cloud OAuth SDKs — each brings ~20-90 MB
        "google",
        "googleapiclient",
        "google_auth_oauthlib",
        "google_auth_httplib2",
        "msal",
        "dropbox",
        "azure",
        "azure.storage",
        "azure.storage.blob",
        "azure.storage.fileshare",
        # Exchange / WinRM / WMI — large + niche
        "exchangelib",
        "winrm",
        "impacket",
        # Transitive dev-tool payloads — semgrep + bandit bring
        # opentelemetry + boltons + stevedore + ruamel.yaml. None
        # of these are runtime deps of axross; PyInstaller's
        # automatic collection still ropes them in if we don't
        # say no. Tighten the exclude list based on the
        # Supply-chain audit (docs/SUPPLY_CHAIN_AUDIT.md).
        "ruamel",
        "ruamel.yaml",
        "boltons",
        "stevedore",
        # Our matching backend modules — prevents load_backend_class
        # from trying to import them.
        "core.azure_client",
        "core.onedrive_client",
        "core.gdrive_client",
        "core.dropbox_client",
        "core.winrm_client",
        "core.wmi_client",
        "core.exchange_client",
    ]

# Unconditional excludes — stuff that slipped into the venv but
# should never land in the bundled binary. NOT listed here but
# deliberately NOT excluded: ``distutils``, ``unittest`` — PyInstaller
# hooks alias-import them internally and flagging them as excluded
# aborts the build with "already imported as ExcludedModule".
excludes += [
    "semgrep",              # dev-time security scanner, 305 MB
    "setuptools",
    "pip",
    "wheel",
    "pytest",
    "tkinter",              # we use PyQt6
    # Documentation / dev tooling that got pulled in via extras
    "sphinx",
    "jupyter",
    "IPython",
    "notebook",
]

# --------------------------------------------------------------------------
# Data files
# --------------------------------------------------------------------------
datas = []
# Anything under the project that isn't Python but the runtime
# needs at startup goes here. We currently embed all icons as SVG
# strings in ui/icon_provider.py, so there's nothing to ship as
# sidecar — left for future use.

# --------------------------------------------------------------------------
# Build graph
# --------------------------------------------------------------------------
a = Analysis(
    [os.path.join(PROJECT_ROOT, "main.py")],
    pathex=[PROJECT_ROOT],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=excludes,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=None)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name=f"axross-{FLAVOR}",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,           # shrink the binary ~30-40% — harmless on ELF
    upx_exclude=[       # Qt plugins break under UPX; exclude them
        "libQt6*.so*",
        "libicu*.so*",
    ],
    runtime_tmpdir=None,
    console=False,      # GUI app — no console window
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
