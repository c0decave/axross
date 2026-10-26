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
    collect_dynamic_libs,
    collect_submodules,
)

# Spec files run with SPECPATH pointing at their own dir.
PROJECT_ROOT = os.path.abspath(os.path.join(SPECPATH, ".."))
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "scripts"))
from bundle_licenses import licence_datas  # noqa: E402
from bundle_options import dropped, dropped_data, exe_options, host_owned  # noqa: E402

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
    # core.self_update verifies the release signature (Ed25519) with a
    # lazy import; without it every self-update is refused.
    "cryptography.hazmat.primitives.asymmetric.ed25519",
]

# Slice 6 helper deps — small pure-Python wrappers loaded lazily by
# core.net_helpers. PyInstaller doesn't always trace lazy imports
# inside try/except ImportError, so be explicit.
hiddenimports += [
    # NOTE: these are IMPORT names, not pip names. "dnspython" used to
    # be listed here and PyInstaller reported
    # `ERROR: Hidden import 'dnspython' not found` on every build —
    # the distribution installs under `dns`. The entry was inert (the
    # two `dns.*` lines below did the real work), but it trained the
    # eye to ignore a genuine error line. Same trap as PySocks/`socks`
    # and fusepy/`fuse`; see REQUIRED_MODS in scripts/build_bundle.sh.
    "dns.resolver",
    "dns.reversename",
    "dns.exception",
    "puremagic",
    "chardet",
    # API_GAPS round-2 / Tier-2 libs (also lazy-loaded inside
    # try/except ImportError; keep explicit so PyInstaller picks
    # them up).
    "ldap3",
    "ipwhois",
    "ntplib",
    "pysnmp",
    "pysnmp.hlapi.v3arch.asyncio",
    "manuf",
    # PDF metadata removal (core.metadata_formats imports it lazily).
    "pypdf",
]
# pysnmp loads MIBs and protocol dispatchers via dynamic imports
# (``importlib.import_module(f'pysnmp.smi.mibs.{name}')``), so the
# static analyser misses them. collect_submodules pulls every
# ``pysnmp.*`` and friends into the bundle.
try:
    hiddenimports += collect_submodules("pysnmp")
except Exception:
    # pysnmp absent in the build venv (uncommon but legal for slim
    # builds that drop the round-2 extras). Fail open.
    pass

# sift (Analysis dock, axross-full): its extractors are imported by name,
# so the static analyser misses some. Absent in a slim build venv: fail open.
if FLAVOR == "full":
    try:
        hiddenimports += collect_submodules("sift")
    except Exception:
        pass
    # numpy: the Media Player extension's equalizer and spectrum. The
    # extension is loaded from resources/ at run time, where the static
    # analyser never looks; PyInstaller's numpy hook does the rest.
    hiddenimports += ["numpy"]

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
        # sift (the Analysis dock's explainer) ships in full only; slim
        # offers to install it.
        "sift",
        # numpy (Media Player equalizer/spectrum) ships in full only; slim
        # plays without them.
        "numpy",
        # The Agent dock's voice (Piper, faster-whisper) ships in full only.
        "piper",
        "faster_whisper",
        "ctranslate2",
        "onnxruntime",
        "av",
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
# Bundled non-Python resources the runtime resolves relative to the
# project root (= ``sys._MEIPASS`` inside a PyInstaller one-file build,
# or ``dirname(dirname(__file__))`` otherwise). The (src, dest) tuple's
# dest is RELATIVE to the bundle root, mirroring the source layout so
# ``core.scripting._render_scripts_reference()`` etc. find them at
# the same relative path inside and outside the bundle.
datas = []
_RESOURCES = os.path.join(PROJECT_ROOT, "resources")
# Keep this in step with resources/ on disk — a subdirectory the code
# reads but the spec does not list works perfectly from source and
# silently returns nothing in the shipped binary. That has now happened
# three times; tests/test_packaging.py::BundledResourcesTests asserts the
# relationship rather than trusting this list.
for sub in ("scripts", "wordlists", "logo", "icons", "i18n", "extensions", "voice", "mcp",
            "credits"):
    src = os.path.join(_RESOURCES, sub)
    if os.path.isdir(src):
        datas.append((src, f"resources/{sub}"))

# The flavour, for the self-update (core.self_update.FLAVOR_PATH): which
# release asset replaces this binary does not depend on its file name.
_flavor_file = os.path.join(workpath, "axross-bundle-flavor.txt")
os.makedirs(workpath, exist_ok=True)
with open(_flavor_file, "w", encoding="ascii") as _fh:
    _fh.write(FLAVOR + "\n")
# In the first-party folder "axross": core.third_party claims the bundle
# root for nobody, so a file there fails the release's bundle gate.
datas.append((_flavor_file, "axross"))

# Some pure-Python deps ship a runtime data file alongside their .py
# code. PyInstaller's static analyser only follows ``import`` so any
# data the package opens via ``open(__file__/../foo)`` is invisible
# unless we pull it in explicitly. Common cases discovered during
# the live --script smoke against the bundled binary:
#
#   * manuf      — ``manuf/manuf`` (Wireshark OUI database, 3 MB).
#                  ``mac_lookup`` raises FileNotFoundError without it.
#   * puremagic  — ``puremagic/magic_data.json`` (file-magic table).
#                  ``magic_type`` returns ``application/octet-stream``
#                  for everything if missing — silently degraded.
#   * chardet    — five model files under ``chardet/models``. Without
#                  them ``text_encoding`` falls back to mbcs guessing
#                  and gets non-ASCII text wrong.
#   * pysnmp     — pysnmp's MIB tree + asyncio dispatcher modules.
for _data_dep in ("manuf", "puremagic", "chardet", "pysnmp"):
    try:
        datas += collect_data_files(_data_dep)
    except Exception as _exc:
        # collect_data_files raises if the package isn't installed in
        # the build venv. Slim builds skip the round-2 libs, so a
        # missing dep is expected there — fail open.
        pass

bundle_binaries = []
if FLAVOR == "full":
    # ripgrep + fd (Find Files, punch-list item 52): the static builds the
    # builder image fetched with pinned checksums (Dockerfile.build).
    # core.file_search.find_tool prefers bin/ of the bundle; without them
    # (a host build) Find Files falls back to PATH or its Python walker.
    _bin = os.environ.get("AXROSS_BUNDLE_BIN", "")
    for _tool in ("rg", "fd"):
        _path = os.path.join(_bin, _tool)
        if _bin and os.path.isfile(_path):
            bundle_binaries.append((_path, "bin"))
    _licenses = os.path.join(_bin, "licenses")
    if _bin and os.path.isdir(_licenses):
        datas.append((_licenses, "licenses/search-tools"))

# Voice (axross-full): the Agent dock's speech output (piper-tts, with its
# espeak-ng data) and local speech recognition (faster-whisper on
# CTranslate2). The voice child runs inside the binary (--voice-worker).
# piper-tts and espeak-ng are GPL-3.0-or-later: the bundle carries the GPL-3
# text from piper's own distribution and the written source offer
# (build/licenses/voice/SOURCE-OFFER.txt) under licenses/voice/. A full
# build that has piper but cannot find its COPYING stops - never a bundle
# without the licence. The voices and models themselves are downloaded at
# run time (core.voice_models), never bundled.
if FLAVOR == "full":
    try:
        import importlib.metadata as _metadata

        _piper = _metadata.distribution("piper-tts")
    except Exception:
        _piper = None
    if _piper is not None:
        hiddenimports += collect_submodules("piper")
        hiddenimports += collect_submodules("faster_whisper")
        # Hebrew and Arabic models of piper (26 MB) are never used here.
        datas += collect_data_files("piper", excludes=["**/hebrew/*.onnx", "**/tashkeel/*.onnx"])
        datas += collect_data_files("faster_whisper")
        bundle_binaries += collect_dynamic_libs("ctranslate2")
        _copying = [f for f in (_piper.files or []) if f.name == "COPYING"]
        if not _copying:
            raise SystemExit("piper-tts is installed but its COPYING (GPL-3.0) was not found")
        datas.append((str(_copying[0].locate()), "licenses/voice"))
        datas.append((os.path.join(PROJECT_ROOT, "build", "licenses", "voice", "SOURCE-OFFER.txt"),
                      "licenses/voice"))

# --------------------------------------------------------------------------
# Build graph
# --------------------------------------------------------------------------
a = Analysis(
    [os.path.join(PROJECT_ROOT, "main.py")],
    pathex=[PROJECT_ROOT],
    binaries=bundle_binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=excludes,
    noarchive=False,
)

# --------------------------------------------------------------------------
# Host-owned libraries (scripts/bundle_options.HOST_OWNED): every part of
# glibc - a bundled copy is the builder's and shadows the host's (0.13.22
# full: libmvec broke the system libvorbis on openSUSE Tumbleweed) - and the
# font stack below.
# --------------------------------------------------------------------------
# fontconfig reads the HOST's /etc/fonts/conf.d, and those files track the
# host's fontconfig version. Bundling the builder image's copy therefore
# pairs an old library with new configuration: AlmaLinux 9 ships
# fontconfig 2.14, while any current desktop writes configs using
# ``xsi:nil`` and the genericfamily constants introduced in 2.17. The
# result is a warning per unparsable element — measured at 90 lines on a
# fontconfig-2.18 host, on every single start of the GUI.
#
# Nothing breaks (fontconfig skips what it cannot parse and font matching
# still works), but an application that prints ninety warnings before it
# paints reads as broken and buries anything that matters.
#
# So fontconfig is left to the host, which by definition matches its own
# configuration. freetype goes with it: fontconfig links against freetype,
# and pairing the host's 2.18 fontconfig with a bundled 2.10 freetype
# would swap one mismatch for a subtler one.
#
# This is safe to rely on: both are hard requirements of any Qt GUI, so a
# machine that can run this binary at all already has them, and
# libfontconfig.so.1 / libfreetype.so.6 have been ABI-stable for well over
# a decade.
#
# Files in bundle_options.DROPPED leave too: Qt's GTK 3 platform theme needs
# a GTK 3 stack the bundle does not carry.
a.binaries = TOC(
    entry for entry in a.binaries if not host_owned(entry[0]) and not dropped(entry[0])
)
# Data the bundle never reads - unpacked at every start of the one-file
# binary all the same (scripts/bundle_options.dropped_data). The DROPPED rule
# applies here too: PyInstaller files its SYMLINK entries (the top-level
# libQt6EglFSDeviceIntegration.so.6 -> PyQt6/Qt6/lib/...) under a.datas, and
# a link to a dropped library would be left dangling.
a.datas = TOC(entry for entry in a.datas if not dropped_data(entry[0]) and not dropped(entry[0]))

# Licence texts of everything kept above (scripts/bundle_licenses.py): every
# bundled Python distribution's own licence files under licenses/python/, and
# for every library the builder system contributes the licence files of its
# rpm package under licenses/system/, with licenses/system/LIBRARIES.txt
# naming the package of each library. tests/test_third_party_bundle.py checks
# a built binary for them.
a.datas = TOC(list(a.datas) + licence_datas(a, os.path.join(workpath, "licenses")))

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
    runtime_tmpdir=None,
    # strip / upx / upx_exclude / console differ per OS: scripts/bundle_options.py
    **exe_options(sys.platform),
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
