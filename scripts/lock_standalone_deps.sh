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
# The tools that build the release's sdist and wheel - build (axross's reviewed pin, build/requirements-dist-tools.txt)
# and twine - hashed as the runtime's are, in the exported repo's packaging/requirements-build.txt: the release
# builds with --no-isolation, the backend (setuptools) from the lock above, nothing unpinned from PyPI.
REPO_PACKAGING="scripts/standalone_repo/axross-$APP/packaging"
BUILD_LOCK="$REPO_PACKAGING/requirements-build.txt"
BUILD_PIN=$(grep -o '^build==[^ ]*' build/requirements-dist-tools.txt)
printf '%s\ntwine\n' "$BUILD_PIN" > "$OUT_DIR/requirements-build.in"
BUILD_SHA=$(sha256sum "$OUT_DIR/requirements-build.in" | cut -d' ' -f1)
# The tests' tool (pytest and what it needs), hashed too, in packaging/requirements-test.txt: the tests run in the
# environment the sdist and wheel are then built in (--no-isolation) - an unpinned pytest from PyPI was in it.
TEST_LOCK="$REPO_PACKAGING/requirements-test.txt"
printf 'pytest\n' > "$OUT_DIR/requirements-test.in"
TEST_SHA=$(sha256sum "$OUT_DIR/requirements-test.in" | cut -d' ' -f1)
if [[ "$MODE" == "--check" ]]; then
    # a fresh resolution may pick newer releases; what must hold is the input
    status=0
    if grep -q "^# input sha256 $INPUT_SHA " "$LOCK" 2>/dev/null; then
        echo "$LOCK is current (input $INPUT_SHA)"
    else
        echo "$LOCK is not current: run scripts/lock_standalone_deps.sh $APP" >&2
        status=1
    fi
    if [[ -d "$REPO_PACKAGING" ]]; then
        if grep -q "^# input sha256 $BUILD_SHA " "$BUILD_LOCK" 2>/dev/null; then
            echo "$BUILD_LOCK is current (input $BUILD_SHA)"
        else
            echo "$BUILD_LOCK is not current: run scripts/lock_standalone_deps.sh $APP" >&2
            status=1
        fi
        if grep -q "^# input sha256 $TEST_SHA " "$TEST_LOCK" 2>/dev/null; then
            echo "$TEST_LOCK is current (input $TEST_SHA)"
        else
            echo "$TEST_LOCK is not current: run scripts/lock_standalone_deps.sh $APP" >&2
            status=1
        fi
    fi
    exit "$status"
fi
# preferences: this lock's pins, then axross's for what it has none of yet - a new requirement (the build
# backend) keeps the version axross reviewed (uv keeps the versions of the output file)
python3 -I - "$LOCK" build/requirements-bundle.txt build/requirements-scan-tools.txt > "$OUT_DIR/lock.txt" <<'PY'
import os, re, sys
seen, out = set(), []
for path in sys.argv[1:]:
    if not os.path.isfile(path):
        continue
    block = []
    for line in open(path, encoding="utf-8").read().splitlines() + [""]:
        pin = re.match(r"([A-Za-z0-9_.-]+)==", line)
        if pin or not line.startswith(" "):
            if block and block[0][1] not in seen:
                out += [text for text, _ in block]
            if block:
                seen.add(block[0][1])
            block = [(line, pin.group(1).lower().replace("_", "-"))] if pin else []
        elif block:
            block.append((line, block[0][1]))
print("\n".join(out))
PY
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
if [[ -d "$REPO_PACKAGING" ]]; then
    # (preferences: this lock's pins, then axross's reviewed ones - build's dependencies, requests and the rest)
    python3 -I - "$BUILD_LOCK" build/requirements-dist-tools.txt build/requirements-bundle.txt > "$OUT_DIR/build-lock.txt" <<'PY'
import os, re, sys
seen, out = set(), []
for path in sys.argv[1:]:
    if not os.path.isfile(path):
        continue
    block = []
    for line in open(path, encoding="utf-8").read().splitlines() + [""]:
        pin = re.match(r"([A-Za-z0-9_.-]+)==", line)
        if pin or not line.startswith(" "):
            if block and block[0][1] not in seen:
                out += [text for text, _ in block]
            if block:
                seen.add(block[0][1])
            block = [(line, pin.group(1).lower().replace("_", "-"))] if pin else []
        elif block:
            block.append((line, block[0][1]))
print("\n".join(out))
PY
    (cd "$OUT_DIR" && UV_NO_CONFIG=1 uv pip compile requirements-build.in --universal --python-version 3.11 \
        --generate-hashes --index-url https://pypi.org/simple --exclude-newer "$CUTOFF" "${EXCEPTIONS[@]}" \
        --custom-compile-command "scripts/lock_standalone_deps.sh $APP" --quiet --output-file build-lock.txt)
    {
        echo "# The tools that build axross-$APP's sdist and wheel ($BUILD_PIN, twine) - the release installs them"
        echo "# with --require-hashes and builds with --no-isolation (setuptools from requirements.lock.txt);"
        echo "# input sha256 $BUILD_SHA - written by scripts/lock_standalone_deps.sh $APP."
        cat "$OUT_DIR/build-lock.txt"
    } > "$BUILD_LOCK"
    echo "locked (releases up to $CUTOFF): $(grep -c '==' "$BUILD_LOCK") pins in $BUILD_LOCK"
    # (preferences: this lock's pins, then the runtime lock's - a package both have keeps the runtime's version, so
    # installing the tests' tool changes nothing the program runs with)
    python3 -I - "$TEST_LOCK" "$LOCK" > "$OUT_DIR/test-lock.txt" <<'PY'
import os, re, sys
seen, out = set(), []
for path in sys.argv[1:]:
    if not os.path.isfile(path):
        continue
    block = []
    for line in open(path, encoding="utf-8").read().splitlines() + [""]:
        pin = re.match(r"([A-Za-z0-9_.-]+)==", line)
        if pin or not line.startswith(" "):
            if block and block[0][1] not in seen:
                out += [text for text, _ in block]
            if block:
                seen.add(block[0][1])
            block = [(line, pin.group(1).lower().replace("_", "-"))] if pin else []
        elif block:
            block.append((line, block[0][1]))
print("\n".join(out))
PY
    (cd "$OUT_DIR" && UV_NO_CONFIG=1 uv pip compile requirements-test.in --universal --python-version 3.11 \
        --generate-hashes --index-url https://pypi.org/simple --exclude-newer "$CUTOFF" "${EXCEPTIONS[@]}" \
        --custom-compile-command "scripts/lock_standalone_deps.sh $APP" --quiet --output-file test-lock.txt)
    {
        echo "# The tests' tool of axross-$APP (pytest and its dependencies) - the CI and the release install it"
        echo "# with --require-hashes, in the environment the sdist and wheel are built in;"
        echo "# input sha256 $TEST_SHA - written by scripts/lock_standalone_deps.sh $APP."
        cat "$OUT_DIR/test-lock.txt"
    } > "$TEST_LOCK"
    echo "locked (releases up to $CUTOFF): $(grep -c '==' "$TEST_LOCK") pins in $TEST_LOCK"
fi
