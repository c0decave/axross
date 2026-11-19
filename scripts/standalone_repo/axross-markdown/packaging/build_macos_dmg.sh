#!/usr/bin/env bash
# macOS: "axross Markdown.app" around the one-file binary, in a disk image
# (axross's scripts/build_macos_dmg.sh, for axross-markdown):
#
#   packaging/build_macos_dmg.sh BINARY OUT.dmg
#
# The app: Contents/MacOS/axross-markdown is the very one-file binary,
# Info.plist (io.github.c0decave.axross-markdown, LSMinimumSystemVersion from
# the binary's build version), the icon from packaging/icons (sips, iconutil);
# ad-hoc signed (codesign -s -), not notarized: the first start needs a
# right-click > Open. The image (UDZO) holds the app and a link to
# /Applications. `--version` runs from the app and from the mounted image
# before OUT.dmg is written.

set -euo pipefail

BINARY="${1:?usage: build_macos_dmg.sh BINARY OUT.dmg}"
OUT="${2:?usage: build_macos_dmg.sh BINARY OUT.dmg}"
[[ "$(uname -s)" == "Darwin" ]] || { echo "build_macos_dmg: runs on macOS only" >&2; exit 2; }
[[ -f "$BINARY" ]] || { echo "build_macos_dmg: no binary at $BINARY" >&2; exit 2; }
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION="$(python3 -c 'import re,sys; print(re.search(r"(?m)^version = \"([^\"]+)\"", open(sys.argv[1]).read()).group(1))' "$HERE/../pyproject.toml")"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/axross-markdown-dmg.XXXXXX")"
MOUNT=""
cleanup() {
    [[ -n "$MOUNT" ]] && hdiutil detach "$MOUNT" -quiet -force >/dev/null 2>&1 || true
    rm -rf -- "$WORK"
}
trap cleanup EXIT

APP="$WORK/stage/axross Markdown.app"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BINARY" "$APP/Contents/MacOS/axross-markdown"
chmod 0755 "$APP/Contents/MacOS/axross-markdown"

MINOS="$( (vtool -show-build "$BINARY" 2>/dev/null || true) | awk '/minos/ {print $2; exit}')"
if [[ -z "$MINOS" ]]; then
    MINOS="$(otool -l "$BINARY" | awk '/LC_BUILD_VERSION/ {f=1} f && /minos/ {print $2; exit}')"
fi
[[ "$MINOS" =~ ^[0-9]+(\.[0-9]+)*$ ]] || MINOS="11.0"

ICONSET="$WORK/axross-markdown.iconset"
mkdir -p "$ICONSET"
for size in 16 32 128 256 512; do
    cp "$HERE/icons/axross-logo-$size.png" "$ICONSET/icon_${size}x${size}.png"
    double=$((size * 2))
    if [[ -f "$HERE/icons/axross-logo-$double.png" ]]; then
        cp "$HERE/icons/axross-logo-$double.png" "$ICONSET/icon_${size}x${size}@2x.png"
    else
        sips -z "$double" "$double" "$HERE/icons/axross-logo-$size.png" \
            --out "$ICONSET/icon_${size}x${size}@2x.png" >/dev/null
    fi
done
iconutil -c icns "$ICONSET" -o "$APP/Contents/Resources/axross-markdown.icns"

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key><string>en</string>
    <key>CFBundleDisplayName</key><string>axross Markdown</string>
    <key>CFBundleExecutable</key><string>axross-markdown</string>
    <key>CFBundleIconFile</key><string>axross-markdown</string>
    <key>CFBundleIdentifier</key><string>io.github.c0decave.axross-markdown</string>
    <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
    <key>CFBundleName</key><string>axross Markdown</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleShortVersionString</key><string>$VERSION</string>
    <key>CFBundleVersion</key><string>$VERSION</string>
    <key>LSApplicationCategoryType</key><string>public.app-category.productivity</string>
    <key>LSMinimumSystemVersion</key><string>$MINOS</string>
    <key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
PLIST
plutil -lint "$APP/Contents/Info.plist" >/dev/null
codesign --force --sign - "$APP"
codesign --verify --strict --verbose=1 "$APP"
want="axross-markdown $VERSION"
got="$("$APP/Contents/MacOS/axross-markdown" --version | tail -n 1)"
[[ "$got" == "$want" ]] || { echo "build_macos_dmg: the app says '$got', not '$want'" >&2; exit 1; }

ln -s /Applications "$WORK/stage/Applications"
for try in 1 2 3; do
    if hdiutil create -volname "axross Markdown" -srcfolder "$WORK/stage" -ov -format UDZO "$WORK/out.dmg" >/dev/null; then
        break
    fi
    [[ "$try" == 3 ]] && { echo "build_macos_dmg: hdiutil create failed" >&2; exit 1; }
    sleep 5
done
hdiutil verify "$WORK/out.dmg" >/dev/null
MOUNT="$WORK/mnt"
mkdir -p "$MOUNT"
hdiutil attach "$WORK/out.dmg" -nobrowse -readonly -mountpoint "$MOUNT" -quiet
got="$("$MOUNT/axross Markdown.app/Contents/MacOS/axross-markdown" --version | tail -n 1)"
[[ "$got" == "$want" ]] || { echo "build_macos_dmg: the mounted app says '$got'" >&2; exit 1; }
hdiutil detach "$MOUNT" -quiet
MOUNT=""
mkdir -p "$(dirname -- "$OUT")"
mv -f "$WORK/out.dmg" "$OUT"
echo ">>> Built $OUT ($(du -h "$OUT" | cut -f1)), macOS $MINOS+"
