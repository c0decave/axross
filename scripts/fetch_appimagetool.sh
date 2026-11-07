#!/usr/bin/env bash
# Fetch the pinned appimagetool release and verify its SHA-256.
#
# Usage:
#   scripts/fetch_appimagetool.sh DEST
#   scripts/fetch_appimagetool.sh DEST --url URL --sha256 HEX   (tests)
#
# DEST is reused when it exists and has the pinned digest; a DEST with any
# other content (an old "continuous" download, a truncated file) is
# replaced. A download whose digest differs is deleted and the script
# exits 1 - nothing unverified is ever left at DEST or run. There is no
# switch to skip the check.
#
# Updating the pin: pick a release on
# https://github.com/AppImage/appimagetool/releases (not "continuous" - its
# file changes under the same URL), set APPIMAGETOOL_VERSION, and set
# APPIMAGETOOL_SHA256 to the asset's digest. GitHub shows it on the
# release page and in the API:
#   curl -s https://api.github.com/repos/AppImage/appimagetool/releases/tags/<version> \
#     | python3 -c 'import json,sys; print([a["digest"] for a in json.load(sys.stdin)["assets"]
#                   if a["name"] == "appimagetool-x86_64.AppImage"])'
# Cross-check by downloading it and running sha256sum on the file.
# tests/test_appimagetool_pin.py holds the pin's form.

set -euo pipefail

APPIMAGETOOL_VERSION="1.9.1"
APPIMAGETOOL_SHA256="ed4ce84f0d9caff66f50bcca6ff6f35aae54ce8135408b3fa33abfc3cb384eb0"
APPIMAGETOOL_URL="https://github.com/AppImage/appimagetool/releases/download/${APPIMAGETOOL_VERSION}/appimagetool-x86_64.AppImage"

DEST="${1:?usage: fetch_appimagetool.sh DEST [--url URL --sha256 HEX]}"
shift
URL="$APPIMAGETOOL_URL"
SHA256="$APPIMAGETOOL_SHA256"
while [ "$#" -gt 0 ]; do
    case "$1" in
        --url) URL="$2"; shift 2 ;;
        --sha256) SHA256="$2"; shift 2 ;;
        *) echo "fetch_appimagetool: unknown argument $1" >&2; exit 2 ;;
    esac
done
[[ "$SHA256" =~ ^[0-9a-f]{64}$ ]] || { echo "fetch_appimagetool: not a SHA-256: $SHA256" >&2; exit 2; }

digest() { sha256sum -- "$1" | cut -d' ' -f1; }

if [ -f "$DEST" ] && [ "$(digest "$DEST")" = "$SHA256" ]; then
    chmod 0755 -- "$DEST"
    exit 0
fi

mkdir -p -- "$(dirname -- "$DEST")"
TMP="$(mktemp "$DEST.part.XXXXXX")"
trap 'rm -f -- "$TMP"' EXIT
echo ">>> Downloading appimagetool $APPIMAGETOOL_VERSION ($URL)"
curl -fL --proto '=https,file' -o "$TMP" -- "$URL"
GOT="$(digest "$TMP")"
if [ "$GOT" != "$SHA256" ]; then
    echo "fetch_appimagetool: SHA-256 mismatch for $URL" >&2
    echo "  expected $SHA256" >&2
    echo "  got      $GOT" >&2
    exit 1
fi
chmod 0755 -- "$TMP"
mv -f -- "$TMP" "$DEST"
trap - EXIT
echo ">>> appimagetool $APPIMAGETOOL_VERSION verified (sha256 $SHA256)"
