#!/usr/bin/env bash
# Build axross one-file binaries inside a manylinux_2_34 Docker
# container so the resulting ELF runs on any glibc-2.34+ Linux
# (Ubuntu 22.04+, Debian 12+, RHEL 9+, Fedora 35+) — not just the
# host you built on.
#
# Without this wrapper, a build on Arch (glibc 2.43) produces a
# binary that crashes on Ubuntu 22.04 (glibc 2.35) with:
#   ImportError: version `GLIBC_2.43' not found
#
# The builder image is AlmaLinux 9 (glibc 2.34) with the distro
# python3.12 package. PyQt6 only ships manylinux_2_34 wheels on
# PyPI (2026-04); older bases (Debian 11, RHEL 8) would trigger a
# PyQt6 source build that requires the full Qt toolchain. See
# Dockerfile.build header for the trade-off rationale.
#
# Usage:
#   scripts/build_bundle_docker.sh [slim|full]
#
# Outputs:
#   dist/axross-<flavor>                         (portable ELF)
#
# Requires podman (preferred) or docker on the host — no Python,
# PyInstaller, or Qt needed locally; the container brings its own.
# Override the auto-detection with CONTAINER_ENGINE=<binary>. First
# run pulls ~1 GB base image; subsequent runs reuse it.

set -euo pipefail

FLAVOR="${1:-full}"
if [[ "$FLAVOR" != "slim" && "$FLAVOR" != "full" ]]; then
    echo "Flavor must be 'slim' or 'full', got: $FLAVOR" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

# Engine selection. podman is preferred: it runs rootless by default,
# so an untrusted `pip install` inside the build image never executes
# as host root. Override with CONTAINER_ENGINE=docker if you need it.
ENGINE="${CONTAINER_ENGINE:-}"
if [[ -z "$ENGINE" ]]; then
    for candidate in podman docker; do
        if command -v "$candidate" >/dev/null 2>&1; then
            ENGINE="$candidate"
            break
        fi
    done
fi
if [[ -z "$ENGINE" ]] || ! command -v "$ENGINE" >/dev/null 2>&1; then
    echo "No container engine on PATH (looked for podman, docker)." >&2
    echo "  Arch:   sudo pacman -S podman" >&2
    echo "  Ubuntu: sudo apt install podman" >&2
    echo "Or set CONTAINER_ENGINE to the binary you want to use." >&2
    exit 1
fi
echo ">>> Using container engine: $ENGINE"

IMAGE_TAG="axross-builder:alma9-glibc2.34"

echo ">>> Building builder image $IMAGE_TAG (one-time, ~1 GB)"
"$ENGINE" build -f Dockerfile.build -t "$IMAGE_TAG" .

mkdir -p "$PROJECT_ROOT/dist"

# Run the build inside the container. scripts/build_bundle.sh
# drops the ELF under /build/dist inside the container; we copy
# it out with `<engine> cp` so the host doesn't need write access
# to the container's working tree.
CONTAINER_ID=$("$ENGINE" create "$IMAGE_TAG" "$FLAVOR")

echo ">>> Running $FLAVOR build inside the container"
"$ENGINE" start -a "$CONTAINER_ID"

echo ">>> Copying axross-$FLAVOR out of the container"
"$ENGINE" cp "$CONTAINER_ID:/build/dist/axross-$FLAVOR" \
             "$PROJECT_ROOT/dist/axross-$FLAVOR"

"$ENGINE" rm -v "$CONTAINER_ID" >/dev/null

ELF_PATH="$PROJECT_ROOT/dist/axross-$FLAVOR"
BINARY_SIZE=$(du -h "$ELF_PATH" | cut -f1)
echo
echo ">>> Built $ELF_PATH ($BINARY_SIZE)"
echo ">>> Portable across glibc 2.34+ hosts (Ubuntu 22.04 / Debian 12 / RHEL 9+)"
ls -lh "$ELF_PATH"
