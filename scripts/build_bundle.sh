#!/usr/bin/env bash
# Build a standalone axross binary via PyInstaller, optionally wrap
# it in an AppImage.
#
# Usage:
#   scripts/build_bundle.sh [slim|full] [--appimage]
#
# Examples:
#   scripts/build_bundle.sh                   # full, ELF only
#   scripts/build_bundle.sh slim              # slim, ELF only
#   scripts/build_bundle.sh full --appimage   # full, ELF + AppImage
#
# Outputs:
#   dist/axross-<flavor>                         standalone ELF
#   dist/axross-<flavor>-x86_64.AppImage         AppImage (if --appimage)
#
# Requires:
#   PyInstaller in .venv (auto-installed if missing)
#   appimagetool in PATH (for --appimage; auto-downloaded if absent)
#
# Temp build artifacts go to /tmp/axross-build-<flavor> because a
# full build needs ~3 GB of scratch space and /tmp is usually
# tmpfs-backed.

set -euo pipefail

FLAVOR="${1:-full}"
shift || true
BUILD_APPIMAGE=0

for arg in "$@"; do
    case "$arg" in
        --appimage) BUILD_APPIMAGE=1 ;;
        *) echo "Unknown arg: $arg" >&2; exit 1 ;;
    esac
done

if [[ "$FLAVOR" != "slim" && "$FLAVOR" != "full" ]]; then
    echo "Flavor must be 'slim' or 'full', got: $FLAVOR" >&2
    exit 1
fi

# Locate project root from the script's own dir.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

# Allow the caller to override which Python we build with — the
# Docker build (scripts/build_bundle_docker.sh) points this at
# /opt/python/cp312-cp312/bin/python inside the manylinux image,
# where deps are installed globally and there's no .venv.
VENV_PY="${AXROSS_PYTHON:-$PROJECT_ROOT/.venv/bin/python}"
if [[ ! -x "$VENV_PY" ]]; then
    echo "No Python found at $VENV_PY." >&2
    echo "Set AXROSS_PYTHON or create .venv first." >&2
    exit 1
fi

# PyInstaller auto-install (idempotent).
if ! "$VENV_PY" -c "import PyInstaller" 2>/dev/null; then
    echo ">>> Installing PyInstaller into .venv"
    "$VENV_PY" -m pip install pyinstaller >/dev/null
fi

# ----------------------------------------------------------------------
# Pre-flight: verify every dep needed for the chosen flavor is present
# in the build environment. PyInstaller will silently produce a binary
# missing those imports otherwise — the user only finds out when they
# launch the bundle and a backend errors at first use (or, worst case,
# the GUI itself fails to start because PyQt6 wasn't in the venv at
# build time).
# ----------------------------------------------------------------------

# Modules every flavor must have. Each entry is a (pyname, role) pair.
# Add to REQUIRED_MODS when a new must-ship dep is introduced.
# NOTE: each entry is the Python IMPORT name (what you'd put in
# ``import X``), NOT the pip package name. PySocks installs under
# ``socks``; fusepy under ``fuse``; google-api-python-client under
# ``googleapiclient``; etc. Getting this wrong gives the user a
# cryptic "missing module" error after they've actually installed
# the package — the real bug from when `PySocks` and `fusepy` were
# listed by their pip names.
REQUIRED_MODS=(
    "PyQt6:GUI toolkit (Widgets/Core/Gui)"
    "PyQt6.QtSvg:SVG icons in icon_provider"
    "paramiko:SSH/SFTP/SCP"
    "socks:SOCKS proxy support (pip: PySocks)"
    "keyring:OS-native credential store"
    "PIL.Image:image preview decode fallback (pip: Pillow)"
    "cryptography:TLS + key handling"
    "requests:WebDAV / OneDrive / OAuth flows"
    "defusedxml:XML hardening (WebDAV PROPFIND, etc.)"
    "dns.resolver:DNS records (axross.dns_records / dns_reverse)"
    "puremagic:file-type detection (axross.magic_type)"
    "chardet:text-encoding detection (axross.text_encoding)"
)

# Extra modules per flavor. Slim drops cloud OAuth + Windows-protocol
# extras; full needs them all. Keep in sync with the spec excludes.
FULL_MODS=(
    "smbprotocol:SMB"
    "boto3:S3"
    "azure.storage.blob:Azure Blob"
    "azure.storage.fileshare:Azure Files"
    "msal:OneDrive OAuth"
    "googleapiclient:Google Drive"
    "google_auth_oauthlib:Google Drive OAuth"
    "dropbox:Dropbox"
    "fuse:FUSE mount (pip: fusepy)"
    "winrm:WinRM"
    "impacket:WMI"
    "exchangelib:Exchange"
    "adb_shell:Android ADB"
    "py7zr:7z archive"
    "tftpy:TFTP backend"
    "psycopg:Postgres FS backend"
    "redis:Redis FS backend"
    "pymongo:MongoDB GridFS"
    "dulwich:Git FS backend"
    # API_GAPS round-2 / Tier-2 libs
    "ldap3:LDAP-as-FS backend"
    "ipwhois:axross.whois RIR/ASN lookup"
    "ntplib:axross.time_skew NTP source"
    "pysnmp:axross.snmp_get/walk/set"
    "manuf:axross.mac_lookup IEEE OUI database"
)

if [[ "$FLAVOR" == "full" ]]; then
    CHECK_MODS=("${REQUIRED_MODS[@]}" "${FULL_MODS[@]}")
else
    CHECK_MODS=("${REQUIRED_MODS[@]}")
fi

echo ">>> Verifying $VENV_PY has all libs needed for flavor=$FLAVOR"
missing=()
for entry in "${CHECK_MODS[@]}"; do
    pyname="${entry%%:*}"
    role="${entry#*:}"
    if ! "$VENV_PY" -c "import $pyname" 2>/dev/null; then
        missing+=("  - $pyname  ($role)")
    fi
done

if (( ${#missing[@]} > 0 )); then
    echo
    echo "ERROR: build environment is missing required modules for flavor=$FLAVOR:" >&2
    printf '%s\n' "${missing[@]}" >&2
    echo >&2
    echo "Install them into the venv first, e.g.:" >&2
    echo "  $VENV_PY -m pip install -e '.[all,smb,webdav,s3,azure,onedrive,gdrive,dropbox,fuse,winrm,wmi,exchange,adb,archive,tftp,postgres,redis,mongo,git]'" >&2
    echo >&2
    echo "(refusing to ship a bundle that's missing libs that the runtime" >&2
    echo " expects — PyInstaller would produce a binary that crashes at" >&2
    echo " first use of those backends, with cryptic ImportError pop-ups.)" >&2
    exit 2
fi
echo "    ✓ all ${#CHECK_MODS[@]} required modules importable"

# Pre-flight: is /tmp big enough?
TMP_AVAIL_MB=$(df -Pm /tmp | awk 'NR==2 {print $4}')
if (( TMP_AVAIL_MB < 3000 )); then
    echo "WARNING: /tmp has only ${TMP_AVAIL_MB} MB free — a full build"
    echo "wants ~3 GB of scratch. Symlinking /tmp/axross-build- into the"
    echo "project dir instead."
    WORK_DIR="$PROJECT_ROOT/build-tmp"
else
    WORK_DIR="/tmp/axross-build-${FLAVOR}"
fi

rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR/dist" "$WORK_DIR/work"

echo ">>> Building axross-${FLAVOR} (temp=${WORK_DIR})"
AXROSS_BUNDLE_FLAVOR="$FLAVOR" \
    "$VENV_PY" -m PyInstaller \
    --clean --noconfirm \
    --distpath "$WORK_DIR/dist" \
    --workpath "$WORK_DIR/work" \
    build/axross.spec

mkdir -p "$PROJECT_ROOT/dist"
cp "$WORK_DIR/dist/axross-${FLAVOR}" "$PROJECT_ROOT/dist/"
ELF_PATH="$PROJECT_ROOT/dist/axross-${FLAVOR}"
BINARY_SIZE=$(du -h "$ELF_PATH" | cut -f1)
echo ">>> Built $ELF_PATH ($BINARY_SIZE)"

# ----------------------------------------------------------------------
# Post-build smoke: --help must succeed. Catches the "PyInstaller hid
# a missing import in the spec" failure mode where the binary builds
# but every launch fails with ImportError before the GUI even paints.
# Run with QT_QPA_PLATFORM=offscreen so headless build hosts don't
# need a display server.
# ----------------------------------------------------------------------
echo ">>> Smoke-testing $ELF_PATH --help"
if ! QT_QPA_PLATFORM=offscreen timeout 30 "$ELF_PATH" --help >/dev/null 2>&1; then
    echo "ERROR: bundled binary failed --help smoke test" >&2
    echo "Re-run for diagnostics:" >&2
    echo "  QT_QPA_PLATFORM=offscreen $ELF_PATH --help" >&2
    exit 3
fi
echo "    ✓ --help works"

# Bundled scripts: they must exist inside the binary, otherwise the
# REPL .scripts list shows empty and `axross.docs('scripts')` says
# "(scripts directory not present in this install)". Verify by running
# a tiny Python expression that pokes at the bundled-resources path.
echo ">>> Smoke-testing bundled resources/scripts/ presence"
if ! QT_QPA_PLATFORM=offscreen timeout 30 "$ELF_PATH" --script - <<<'import core.scripting as s, os; r = s._render_scripts_reference(); assert "(scripts directory not present" not in r, "resources/scripts/ missing from bundle"; print("resources/scripts/ ok")' 2>/dev/null | grep -q "resources/scripts/ ok"; then
    echo "ERROR: bundled binary is missing resources/scripts/" >&2
    echo "Check that build/axross.spec datas includes resources/scripts/." >&2
    exit 4
fi
echo "    ✓ bundled scripts present"

# --------------------------------------------------------------------------
# AppImage wrap
# --------------------------------------------------------------------------
if (( BUILD_APPIMAGE == 1 )); then
    APPIMAGETOOL="${APPIMAGETOOL:-}"
    if [[ -z "$APPIMAGETOOL" ]]; then
        # Prefer a PATH entry; fall back to downloading into build/.
        if command -v appimagetool >/dev/null 2>&1; then
            APPIMAGETOOL=$(command -v appimagetool)
        else
            DL="$PROJECT_ROOT/build/appimagetool-x86_64.AppImage"
            if [[ ! -x "$DL" ]]; then
                echo ">>> Downloading appimagetool (one-time, ~70 MB)"
                curl -L -o "$DL" \
                    "https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage"
                chmod +x "$DL"
            fi
            APPIMAGETOOL="$DL"
        fi
    fi

    APPDIR="$WORK_DIR/AppDir"
    rm -rf "$APPDIR"
    mkdir -p "$APPDIR/usr/bin" "$APPDIR/usr/share/applications" \
             "$APPDIR/usr/share/icons/hicolor/scalable/apps"

    # Binary — renamed to 'axross' inside the AppImage so the
    # .desktop file's Exec= line matches regardless of flavor.
    cp "$ELF_PATH" "$APPDIR/usr/bin/axross"

    # AppRun is the entry point the AppImage runtime invokes. A
    # plain symlink to the binary works for single-file apps.
    ln -sf "usr/bin/axross" "$APPDIR/AppRun"

    # Desktop file + icon. Both need to sit at the AppDir root AND
    # under the standard hicolor path so the host can index them
    # when installed via appimaged or similar.
    cp "$PROJECT_ROOT/build/axross.desktop" \
       "$APPDIR/axross.desktop"
    cp "$PROJECT_ROOT/build/axross.desktop" \
       "$APPDIR/usr/share/applications/axross.desktop"
    cp "$PROJECT_ROOT/build/axross.svg" \
       "$APPDIR/axross.svg"
    cp "$PROJECT_ROOT/build/axross.svg" \
       "$APPDIR/usr/share/icons/hicolor/scalable/apps/axross.svg"

    APPIMAGE_OUT="$PROJECT_ROOT/dist/axross-${FLAVOR}-x86_64.AppImage"
    ARCH=x86_64 "$APPIMAGETOOL" --no-appstream "$APPDIR" "$APPIMAGE_OUT"
    APPIMAGE_SIZE=$(du -h "$APPIMAGE_OUT" | cut -f1)
    echo ">>> Built $APPIMAGE_OUT ($APPIMAGE_SIZE)"
fi

echo
echo "Cleaning up scratch dir $WORK_DIR"
rm -rf "$WORK_DIR"

echo
echo ">>> Bundle ready in $PROJECT_ROOT/dist/"
ls -lh "$PROJECT_ROOT/dist/"
