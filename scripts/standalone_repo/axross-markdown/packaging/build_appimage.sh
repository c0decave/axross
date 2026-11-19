#!/usr/bin/env bash
# The one-file Linux binary as an AppImage (axross's scripts/build_appimage.sh,
# for axross-markdown):
#
#   packaging/build_appimage.sh ELF OUT.AppImage
#
# appimagetool and the type-2 runtime are pinned releases, their SHA-256
# checked by packaging/fetch_appimagetool.sh (a mismatch stops the build).
# appimagetool is unpacked and run from there (no FUSE needed); it needs the
# program `file`. The binary is read back from the image and compared.

set -euo pipefail

ELF="${1:?usage: build_appimage.sh ELF OUT.AppImage}"
OUT="${2:?usage: build_appimage.sh ELF OUT.AppImage}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLS_DIR="${APPIMAGE_TOOLS_DIR:-$HERE/../build/appimage-tools}"

[[ -f "$ELF" ]] || { echo "build_appimage: no binary at $ELF" >&2; exit 2; }
# both absolute: the image is read back from inside another folder below
ELF="$(cd "$(dirname -- "$ELF")" && pwd)/$(basename -- "$ELF")"
mkdir -p "$(dirname -- "$OUT")"
OUT="$(cd "$(dirname -- "$OUT")" && pwd)/$(basename -- "$OUT")"
APPIMAGETOOL="$TOOLS_DIR/appimagetool-x86_64.AppImage"
RUNTIME="$TOOLS_DIR/appimage-runtime-x86_64"
bash "$HERE/fetch_appimagetool.sh" "$APPIMAGETOOL"
bash "$HERE/fetch_appimagetool.sh" "$RUNTIME" --runtime

WORK="$(mktemp -d "${TMPDIR:-/tmp}/axross-markdown-appimage.XXXXXX")"
trap 'rm -rf -- "$WORK"' EXIT
(cd "$WORK" && "$APPIMAGETOOL" --appimage-extract >/dev/null)
mv "$WORK/squashfs-root" "$WORK/appimagetool"

APPDIR="$WORK/AppDir"
mkdir -p "$APPDIR/usr/bin" "$APPDIR/usr/share/applications" \
         "$APPDIR/usr/share/icons/hicolor/256x256/apps"
cp "$ELF" "$APPDIR/usr/bin/axross-markdown"
chmod 0755 "$APPDIR/usr/bin/axross-markdown"
ln -s "usr/bin/axross-markdown" "$APPDIR/AppRun"
cp "$HERE/axross-markdown.desktop" "$APPDIR/axross-markdown.desktop"
cp "$HERE/axross-markdown.desktop" "$APPDIR/usr/share/applications/axross-markdown.desktop"
cp "$HERE/icons/axross-logo-256.png" "$APPDIR/axross-markdown.png"
cp "$HERE/icons/axross-logo-256.png" "$APPDIR/usr/share/icons/hicolor/256x256/apps/axross-markdown.png"

mkdir -p "$(dirname -- "$OUT")"
rm -f -- "$OUT"
ARCH=x86_64 "$WORK/appimagetool/AppRun" --no-appstream --runtime-file "$RUNTIME" "$APPDIR" "$OUT" \
    >"$WORK/appimagetool.log" 2>&1 \
    || { tail -30 "$WORK/appimagetool.log" >&2; echo "build_appimage: appimagetool failed" >&2; exit 1; }
[[ "$(head -c 11 "$OUT" | tail -c 3 | od -An -tx1 | tr -d ' \n')" == "414902" ]] \
    || { echo "build_appimage: $OUT is not a type-2 AppImage" >&2; exit 1; }
mkdir "$WORK/check"
(cd "$WORK/check" && "$OUT" --appimage-extract usr/bin/axross-markdown >/dev/null)
cmp -s -- "$ELF" "$WORK/check/squashfs-root/usr/bin/axross-markdown" \
    || { echo "build_appimage: $OUT does not hold $ELF" >&2; exit 1; }
chmod 0755 -- "$OUT"
echo ">>> Built $OUT ($(du -h "$OUT" | cut -f1))"
