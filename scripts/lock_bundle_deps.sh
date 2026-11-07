#!/usr/bin/env bash
# Refresh build/requirements-bundle.txt from build/requirements-bundle.in.
#
# The lock pins every Python package the one-file bundles are built from -
# Linux (Dockerfile.build) and the macOS / Windows CI builds
# (.github/workflows/cross-platform.yml) - to one exact version with the
# sha256 of every file PyPI has for it. Both install it with
# ``pip install --require-hashes``, so a file that differs from the one
# locked here stops the build.
#
# The resolver (uv, pinned by version and hash below) runs in a disposable
# container: resolving can build an sdist to read its metadata, and that runs
# the package's own code. Nothing of it reaches the host but the lock file.
#
# Usage:
#   scripts/lock_bundle_deps.sh            # write build/requirements-bundle.txt
#   scripts/lock_bundle_deps.sh --check    # exit 1 when the lock is not current
#   scripts/lock_bundle_deps.sh --here     # no container: where this already runs
#                                          # isolated (a sandbox); keeps the pins
#                                          # of the current lock, adds what is new
#
# After a refresh, audit the exact pins before committing:
#   python -m security.dep_floor_audit --lock build/requirements-bundle.txt

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
IN_FILE="$PROJECT_ROOT/build/requirements-bundle.in"
LOCK_FILE="$PROJECT_ROOT/build/requirements-bundle.txt"
BOOTSTRAP_FILE="$PROJECT_ROOT/build/requirements-bootstrap.txt"

MODE="write"
HERE=0
for arg in "$@"; do
    case "$arg" in
        --check) MODE="check" ;;
        --here) HERE=1 ;;
        *) echo "usage: $0 [--check] [--here]" >&2; exit 2 ;;
    esac
done

ENGINE="${CONTAINER_ENGINE:-}"
if [[ -z "$ENGINE" ]]; then
    for candidate in podman docker; do
        if command -v "$candidate" >/dev/null 2>&1; then
            ENGINE="$candidate"
            break
        fi
    done
fi
if [[ -z "$ENGINE" && "$HERE" == 0 ]]; then
    echo "No container engine on PATH (looked for podman, docker); in a sandbox: --here." >&2
    exit 2
fi

# The interpreter the bundles are built with (AlmaLinux 9: python3.12; CI:
# setup-python 3.12). Pinned by digest: a re-tagged image cannot slip in.
PYTHON_IMAGE="docker.io/library/python:3.12-slim@sha256:e8a38829209aea82774882e5157e1f7c3e8c8393ff53a697b3580896e57f345c"
UV_VERSION="0.13.5"
UV_SHA256_X86_64="fa8d26e08e34c29c0c4e820cf3181757086d547240b4f4d31ff1d8bd810ca946"
UV_SHA256_AARCH64="91e58e304b63b6c91bac5561459ab0c3ea24f17bc01ea9359d69fed72142978f"

# Only releases at least 14 days old (the supply-chain gate's minimum age,
# security/supply_chain_gate.py MIN_AGE_DAYS): most malicious uploads are
# found and removed within days.
CUTOFF="$(date -u -d '-14 days' +%Y-%m-%dT%H:%M:%SZ)"
# reviewed security fixes younger than that (build/young-release-exceptions.txt)
EXCEPTIONS=""
while read -r pkg date _; do
    [[ -z "$pkg" || "$pkg" == \#* ]] && continue
    EXCEPTIONS+=" --exclude-newer-package $pkg=$date"
done < "$(dirname "$0")/../build/young-release-exceptions.txt"

OUT_DIR="$(mktemp -d)"
trap 'rm -rf "$OUT_DIR"' EXIT
cp "$IN_FILE" "$OUT_DIR/requirements-bundle.in"
cat > "$OUT_DIR/uv-tool.txt" <<EOF
uv==${UV_VERSION} \\
    --hash=sha256:${UV_SHA256_X86_64} \\
    --hash=sha256:${UV_SHA256_AARCH64}
EOF

if [[ "$HERE" == 1 ]]; then
    # The same pinned uv, run here; the current lock is its starting point, so
    # only what the .in file adds or changes is resolved anew.
    PY312="$(uv python find 3.12 2>/dev/null || command -v python3.12 || true)"
    if [[ -z "$PY312" ]]; then
        echo "--here needs Python 3.12 (uv python install 3.12)" >&2
        exit 2
    fi
    # write: start from the current lock (only what is new resolves); check: from
    # nothing, as the container does, or the check would always find it current
    if [[ "$MODE" == "write" ]]; then
        cp "$LOCK_FILE" "$OUT_DIR/requirements-bundle.txt"
    fi
    "$PY312" -m pip install --quiet --no-cache-dir --require-hashes --only-binary=:all: \
        --target "$OUT_DIR/uv-tool" -r "$OUT_DIR/uv-tool.txt"
    # the hash-pinned uv just installed, not one the interpreter happens to have
    (cd "$OUT_DIR" && HOME="$OUT_DIR" UV_CACHE_DIR="$OUT_DIR/uv-cache" UV_NO_CONFIG=1 \
        "$OUT_DIR/uv-tool/bin/uv" pip compile requirements-bundle.in \
            --universal --python-version 3.12 --generate-hashes \
            --index-url https://pypi.org/simple \
            --exclude-newer "$CUTOFF" $EXCEPTIONS \
            --custom-compile-command "scripts/lock_bundle_deps.sh" \
            --quiet --output-file requirements-bundle.txt)
else
# --cap-drop=ALL and no-new-privileges: the resolver needs the network (PyPI)
# and a writable /work, nothing else.
"$ENGINE" run --rm --cap-drop=ALL --security-opt=no-new-privileges \
    --read-only --tmpfs /tmp:rw,exec,size=2g \
    -e HOME=/tmp -e UV_CACHE_DIR=/tmp/uv-cache -e PIP_DISABLE_PIP_VERSION_CHECK=1 \
    -e UV_NO_CONFIG=1 -e CUTOFF="$CUTOFF" -e EXCEPTIONS="$EXCEPTIONS" \
    -v "$OUT_DIR:/work:Z" -w /work \
    "$PYTHON_IMAGE" \
    sh -euc '
        python -m pip install --quiet --root-user-action=ignore --no-cache-dir --require-hashes --only-binary=:all: \
            --target /tmp/uv-tool -r uv-tool.txt
        PYTHONPATH=/tmp/uv-tool python -m uv pip compile requirements-bundle.in \
            --universal --python-version 3.12 --generate-hashes \
            --index-url https://pypi.org/simple --exclude-newer "$CUTOFF" $EXCEPTIONS \
            --custom-compile-command "scripts/lock_bundle_deps.sh" \
            --quiet --output-file requirements-bundle.txt
    '
fi

# The installer and the build backend, cut out of the lock: they go in first
# (the distro's pip is too old to read hashes from a constraints file, and
# the packages without a Python 3 wheel are built without build isolation,
# against this setuptools, so no unhashed build dependency is ever fetched).
{
    echo "# pip and setuptools of build/requirements-bundle.txt, installed before it."
    echo "# Written by scripts/lock_bundle_deps.sh - do not edit."
    awk '/^[^ #]/ { keep = ($0 ~ /^(pip|setuptools)==/) } keep' "$OUT_DIR/requirements-bundle.txt"
} > "$OUT_DIR/requirements-bootstrap.txt"

if [[ "$MODE" == "check" ]]; then
    if diff -u "$LOCK_FILE" "$OUT_DIR/requirements-bundle.txt" \
            && diff -u "$BOOTSTRAP_FILE" "$OUT_DIR/requirements-bootstrap.txt"; then
        echo "build/requirements-bundle.txt is current"
        exit 0
    fi
    echo "build/requirements-bundle.txt is not current: run scripts/lock_bundle_deps.sh" >&2
    exit 1
fi
cp "$OUT_DIR/requirements-bundle.txt" "$LOCK_FILE"
cp "$OUT_DIR/requirements-bootstrap.txt" "$BOOTSTRAP_FILE"
echo "wrote $LOCK_FILE ($(grep -c '^[A-Za-z0-9]' "$LOCK_FILE") packages)"
