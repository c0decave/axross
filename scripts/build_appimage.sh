#!/usr/bin/env bash
# Wrap a one-file axross binary into an AppImage.
#
# Usage:
#   scripts/build_appimage.sh ELF OUT.AppImage
#
#   ELF   a Linux x86-64 one-file binary (scripts/build_bundle.sh; in a release
#         the glibc-2.34 build, scripts/build_dist.sh)
#   OUT   the AppImage to write (replaced if it exists)
#
# The AppDir: usr/bin/axross (the binary, renamed so that the .desktop file's
# Exec= matches every flavour), AppRun (a link to it), axross.desktop and
# axross.svg at the root and under usr/share. The binary itself is unchanged:
# it still knows its flavour and glibc variant (build/axross.spec's marker
# files), and core.self_update recognises it inside the image ($APPIMAGE,
# $APPDIR) and updates the image file, never with the plain binary.
#
# Tools, both pinned and SHA-256 checked by scripts/fetch_appimagetool.sh
# (a mismatch stops the build; there is no switch to skip the check):
#   appimagetool 1.9.1  ($APPIMAGETOOL overrides it: a path to an appimagetool
#                        AppImage or program)
#   the type-2 runtime  that starts the image - it is part of every AppImage
#                        built, so it is pinned too and given with
#                        --runtime-file; appimagetool would otherwise fetch
#                        the "continuous" build ($APPIMAGE_RUNTIME overrides)
# Downloads go to $APPIMAGE_TOOLS_DIR (default build/). appimagetool is an
# AppImage itself; it is unpacked (--appimage-extract) and run from there,
# so no FUSE is needed (CI runners and sandboxes have none).

set -euo pipefail

ELF="${1:?usage: build_appimage.sh ELF OUT.AppImage}"
OUT="${2:?usage: build_appimage.sh ELF OUT.AppImage}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TOOLS_DIR="${APPIMAGE_TOOLS_DIR:-$PROJECT_ROOT/build}"

[[ -f "$ELF" ]] || { echo "build_appimage: no binary at $ELF" >&2; exit 2; }
[[ "$(head -c 4 "$ELF" | od -An -c | tr -d ' ')" == '177ELF' ]] \
    || { echo "build_appimage: $ELF is not an ELF file" >&2; exit 2; }

APPIMAGETOOL="${APPIMAGETOOL:-}"
if [[ -z "$APPIMAGETOOL" ]]; then
    APPIMAGETOOL="$TOOLS_DIR/appimagetool-x86_64.AppImage"
    bash "$SCRIPT_DIR/fetch_appimagetool.sh" "$APPIMAGETOOL"
fi
RUNTIME="${APPIMAGE_RUNTIME:-}"
if [[ -z "$RUNTIME" ]]; then
    RUNTIME="$TOOLS_DIR/appimage-runtime-x86_64"
    bash "$SCRIPT_DIR/fetch_appimagetool.sh" "$RUNTIME" --runtime
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/axross-appimage.XXXXXX")"
trap 'rm -rf -- "$WORK"' EXIT

# A type-2 AppImage carries "AI\x02" at offset 8: unpack it, run its AppRun.
is_appimage() { [[ "$(head -c 11 "$1" | tail -c 3 | od -An -tx1 | tr -d ' \n')" == "414902" ]]; }
TOOL="$APPIMAGETOOL"
if is_appimage "$APPIMAGETOOL"; then
    (cd "$WORK" && "$APPIMAGETOOL" --appimage-extract >/dev/null)
    mv "$WORK/squashfs-root" "$WORK/appimagetool"
    TOOL="$WORK/appimagetool/AppRun"
fi

APPDIR="$WORK/AppDir"
mkdir -p "$APPDIR/usr/bin" "$APPDIR/usr/share/applications" \
         "$APPDIR/usr/share/icons/hicolor/scalable/apps"
cp "$ELF" "$APPDIR/usr/bin/axross"
chmod 0755 "$APPDIR/usr/bin/axross"
# AppRun is the entry point the runtime starts; a link works for one binary
ln -s "usr/bin/axross" "$APPDIR/AppRun"
# the desktop entry and the icon at the root (appimagetool) and under the
# standard paths (appimaged and other integrations)
cp "$PROJECT_ROOT/build/axross.desktop" "$APPDIR/axross.desktop"
cp "$PROJECT_ROOT/build/axross.desktop" "$APPDIR/usr/share/applications/axross.desktop"
cp "$PROJECT_ROOT/build/axross.svg" "$APPDIR/axross.svg"
cp "$PROJECT_ROOT/build/axross.svg" "$APPDIR/usr/share/icons/hicolor/scalable/apps/axross.svg"

mkdir -p "$(dirname -- "$OUT")"
rm -f -- "$OUT"
# --no-appstream: no AppStream metadata; no -g/-u: no update information is
# embedded (axross updates itself), so no .zsync file either
ARCH=x86_64 "$TOOL" --no-appstream --runtime-file "$RUNTIME" "$APPDIR" "$OUT" \
    >"$WORK/appimagetool.log" 2>&1 \
    || { tail -30 "$WORK/appimagetool.log" >&2; echo "build_appimage: appimagetool failed" >&2; exit 1; }
is_appimage "$OUT" || { echo "build_appimage: $OUT is not a type-2 AppImage" >&2; exit 1; }
# the image holds the very binary it was given (read back through its own
# runtime, which also proves the runtime finds its file system)
mkdir "$WORK/check"
(cd "$WORK/check" && "$OUT" --appimage-extract usr/bin/axross >/dev/null) \
    || { echo "build_appimage: $OUT cannot be read back" >&2; exit 1; }
cmp -s -- "$ELF" "$WORK/check/squashfs-root/usr/bin/axross" \
    || { echo "build_appimage: $OUT does not hold $ELF" >&2; exit 1; }
chmod 0755 -- "$OUT"
echo ">>> Built $OUT ($(du -h "$OUT" | cut -f1)) from $(basename "$ELF")"
