#!/usr/bin/env bash
# Lock the runtime dependencies of a tool axross exports as a program of its
# own (scripts/export_standalone.py APP): build/requirements-standalone-APP.txt,
# every pin with the sha256 of every file PyPI has for it.
#
#   scripts/lock_standalone_deps.sh markdown           # write the lock
#   scripts/lock_standalone_deps.sh markdown --check   # exit 1 when it is not current
#
# What is locked is the exported pyproject's dependencies and every extra
# (export_standalone.py --requirements APP), for Python 3.11 and newer on
# every platform (uv --universal). As the other locks: only releases at least
# MIN_AGE_DAYS old (the supply-chain gate's minimum age) unless
# build/young-release-exceptions.txt names a reviewed security fix, and only
# PyPI. axross's own locks seed the resolution, so a package both use keeps
# the version axross already reviewed.
#
# The lock is one of the supply-chain gate's locks (security/supply_chain_gate.py
# LOCKS): every pin needs a reviewed baseline (docs/SUPPLY_CHAIN_GATE.md),
# tests/test_supply_chain_gate_axross.py fails without one, and the exporter
# ships the lock with the program (requirements.lock.txt) - it refuses a lock
# whose input is not the exported pyproject's any more.
set -euo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP="${1:-}"
MODE="${2:-write}"
if [[ -z "$APP" || ( "$MODE" != "write" && "$MODE" != "--check" ) ]]; then
    echo "usage: $0 APP [--check]" >&2
    exit 2
fi
LOCK="build/requirements-standalone-$APP.txt"
MIN_AGE_DAYS=14
CUTOFF=$(date -u -d "-${MIN_AGE_DAYS} days" +%Y-%m-%dT%H:%M:%SZ)
EXCEPTIONS=()
while read -r pkg date _; do
    [[ -z "$pkg" || "$pkg" == \#* ]] && continue
    EXCEPTIONS+=(--exclude-newer-package "$pkg=$date")
done < build/young-release-exceptions.txt

OUT_DIR="$(mktemp -d)"
trap 'rm -rf "$OUT_DIR"' EXIT
python3 -I scripts/export_standalone.py --requirements "$APP" > "$OUT_DIR/requirements.in"
INPUT_SHA=$(sha256sum "$OUT_DIR/requirements.in" | cut -d' ' -f1)
if [[ "$MODE" == "--check" ]]; then
    # a fresh resolution may pick newer releases; what must hold is the input
    if grep -q "^# input sha256 $INPUT_SHA " "$LOCK" 2>/dev/null; then
        echo "$LOCK is current (input $INPUT_SHA)"
        exit 0
    fi
    echo "$LOCK is not current: run scripts/lock_standalone_deps.sh $APP" >&2
    exit 1
fi
# preferences: this lock's pins, else axross's (uv keeps the versions of the output file)
if [[ -f "$LOCK" ]]; then
    cp "$LOCK" "$OUT_DIR/lock.txt"
else
    cat build/requirements-bundle.txt build/requirements-scan-tools.txt > "$OUT_DIR/lock.txt"
fi
(cd "$OUT_DIR" && UV_NO_CONFIG=1 uv pip compile requirements.in --universal --python-version 3.11 \
    --generate-hashes --index-url https://pypi.org/simple --exclude-newer "$CUTOFF" "${EXCEPTIONS[@]}" \
    --custom-compile-command "scripts/lock_standalone_deps.sh $APP" --quiet --output-file lock.txt)
{
    echo "# The runtime dependencies of axross-$APP (scripts/export_standalone.py --requirements $APP),"
    echo "# input sha256 $INPUT_SHA - checked by the exporter and the tests."
    cat "$OUT_DIR/lock.txt"
} > "$OUT_DIR/final.txt"
cp "$OUT_DIR/final.txt" "$LOCK"
echo "locked (releases up to $CUTOFF): $(grep -c '==' "$LOCK") pins in $LOCK"
