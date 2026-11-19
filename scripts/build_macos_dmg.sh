#!/usr/bin/env bash
# macOS: axross.app around a one-file binary, in a disk image.
#
# Usage (on macOS, after the bundle job built the binary):
#   scripts/build_macos_dmg.sh FLAVOR BINARY OUT.dmg
#
#   FLAVOR   slim or full (the volume and the app say which)
#   BINARY   the one-file binary PyInstaller wrote (dist/<flavor>/axross-<flavor>)
#   OUT.dmg  the disk image to write: axross-<flavor>-macos-arm64.dmg
#
# axross.app is made by hand: Contents/MacOS/axross is the very one-file
# binary, Contents/Info.plist names it (CFBundleIdentifier
# io.github.c0decave.axross, LSMinimumSystemVersion read from the binary's
# own build version), Contents/Resources/axross.icns comes from
# resources/logo/axross-logo-*.png (sips, iconutil). The app is ad-hoc signed
# (codesign -s -), like the binaries: not notarized, so the first start
# needs a right-click > Open (docs/PACKAGING.md, "macOS binary: the first
# start"). The image (UDZO) holds axross.app and a link to /Applications.
#
# Inside axross.app the binary does not replace itself (core.self_update:
# replacing Contents/MacOS/axross would break the app's seal); it shows
# the release page, where the next DMG is.
#
# Everything is built in a temporary folder and checked - the app's
# signature, `axross --version` from the app and from the mounted image -
# before OUT.dmg is written; a failure leaves no OUT.dmg behind.

set -euo pipefail

FLAVOR="${1:?usage: build_macos_dmg.sh FLAVOR BINARY OUT.dmg}"
BINARY="${2:?usage: build_macos_dmg.sh FLAVOR BINARY OUT.dmg}"
OUT="${3:?usage: build_macos_dmg.sh FLAVOR BINARY OUT.dmg}"
case "$FLAVOR" in slim|full) ;; *) echo "build_macos_dmg: flavour slim or full, not $FLAVOR" >&2; exit 2 ;; esac
[[ "$(uname -s)" == "Darwin" ]] || { echo "build_macos_dmg: runs on macOS only" >&2; exit 2; }
[[ -f "$BINARY" ]] || { echo "build_macos_dmg: no binary at $BINARY" >&2; exit 2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
VERSION="$(python3 -c 'import re,sys; print(re.search(r"__version__ = \"([^\"]+)\"", open(sys.argv[1]).read()).group(1))' "$PROJECT_ROOT/axross/_version.py")"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/axross-dmg.XXXXXX")"
MOUNT=""
cleanup() {
    [[ -n "$MOUNT" ]] && hdiutil detach "$MOUNT" -quiet -force >/dev/null 2>&1 || true
    rm -rf -- "$WORK"
}
trap cleanup EXIT

APP="$WORK/stage/axross.app"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BINARY" "$APP/Contents/MacOS/axross"
chmod 0755 "$APP/Contents/MacOS/axross"

# The lowest macOS the binary runs on, as its load command says (vtool, else otool)
MINOS="$( (vtool -show-build "$BINARY" 2>/dev/null || true) | awk '/minos/ {print $2; exit}')"
if [[ -z "$MINOS" ]]; then
    MINOS="$(otool -l "$BINARY" | awk '/LC_BUILD_VERSION/ {f=1} f && /minos/ {print $2; exit}')"
fi
[[ "$MINOS" =~ ^[0-9]+(\.[0-9]+)*$ ]] || MINOS="11.0"

# The icon: an iconset from the logo PNGs (16 ... 512, their @2x where there is one)
ICONSET="$WORK/axross.iconset"
mkdir -p "$ICONSET"
LOGO="$PROJECT_ROOT/resources/logo"
for size in 16 32 128 256 512; do
    cp "$LOGO/axross-logo-$size.png" "$ICONSET/icon_${size}x${size}.png"
    double=$((size * 2))
    if [[ -f "$LOGO/axross-logo-$double.png" ]]; then
        cp "$LOGO/axross-logo-$double.png" "$ICONSET/icon_${size}x${size}@2x.png"
    else
        sips -z "$double" "$double" "$LOGO/axross-logo-$size.png" \
            --out "$ICONSET/icon_${size}x${size}@2x.png" >/dev/null
    fi
done
iconutil -c icns "$ICONSET" -o "$APP/Contents/Resources/axross.icns"

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key><string>en</string>
    <key>CFBundleDisplayName</key><string>axross</string>
    <key>CFBundleExecutable</key><string>axross</string>
    <key>CFBundleIconFile</key><string>axross</string>
    <key>CFBundleIdentifier</key><string>io.github.c0decave.axross</string>
    <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
    <key>CFBundleName</key><string>axross</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleShortVersionString</key><string>$VERSION</string>
    <key>CFBundleVersion</key><string>$VERSION</string>
    <key>CFBundleGetInfoString</key><string>axross $VERSION ($FLAVOR)</string>
    <key>LSApplicationCategoryType</key><string>public.app-category.utilities</string>
    <key>LSMinimumSystemVersion</key><string>$MINOS</string>
    <key>NSHighResolutionCapable</key><true/>
    <key>NSHumanReadableCopyright</key><string>Apache-2.0 (the binary GPL-3.0 through PyQt6), see THIRD_PARTY_LICENSES.md</string>
</dict>
</plist>
PLIST
plutil -lint "$APP/Contents/Info.plist" >/dev/null

# ad-hoc, as the binaries; the app's seal covers Info.plist and the icon
codesign --force --sign - "$APP"
codesign --verify --strict --verbose=1 "$APP"
want="axross $VERSION"
got="$("$APP/Contents/MacOS/axross" --version | tail -n 1)"
[[ "$got" == "$want" ]] || { echo "build_macos_dmg: the app says '$got', not '$want'" >&2; exit 1; }

ln -s /Applications "$WORK/stage/Applications"
# hdiutil create fails now and then on CI runners ("Resource busy"): three tries
for try in 1 2 3; do
    if hdiutil create -volname "axross" -srcfolder "$WORK/stage" -ov -format UDZO "$WORK/axross.dmg" >/dev/null; then
        break
    fi
    [[ "$try" == 3 ]] && { echo "build_macos_dmg: hdiutil create failed" >&2; exit 1; }
    sleep 5
done
hdiutil verify "$WORK/axross.dmg" >/dev/null

# the image as a user gets it: mounted read-only, the app inside starts
MOUNT="$WORK/mnt"
mkdir -p "$MOUNT"
hdiutil attach "$WORK/axross.dmg" -nobrowse -readonly -mountpoint "$MOUNT" -quiet
[[ -L "$MOUNT/Applications" ]] || { echo "build_macos_dmg: no Applications link in the image" >&2; exit 1; }
got="$("$MOUNT/axross.app/Contents/MacOS/axross" --version | tail -n 1)"
[[ "$got" == "$want" ]] || { echo "build_macos_dmg: the mounted app says '$got'" >&2; exit 1; }
codesign --verify --strict "$MOUNT/axross.app"
hdiutil detach "$MOUNT" -quiet
MOUNT=""

mkdir -p "$(dirname -- "$OUT")"
mv -f "$WORK/axross.dmg" "$OUT"
echo ">>> Built $OUT ($(du -h "$OUT" | cut -f1)): axross.app $VERSION ($FLAVOR, macOS $MINOS+)"
