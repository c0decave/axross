#!/usr/bin/env bash
# Run tests/test_backup_repos_live.py against real borg and duplicity in a
# disposable podman container: the image is built from
# tests/docker/Dockerfile.backup-tools (network only while building), the test
# runs with --network=none, no capabilities and the tree mounted read-only.
# The image is removed afterwards unless AXROSS_KEEP_IMAGE=1.
set -euo pipefail

tree=$(cd "$(dirname "$0")/.." && pwd)
image=${AXROSS_BACKUP_IMAGE:-localhost/axross-backup-tools:live-test}
context=$(mktemp -d)
cleanup() {
    rm -rf "$context"
    if [ "${AXROSS_KEEP_IMAGE:-0}" != 1 ]; then
        podman rmi -f "$image" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

cp "$tree/tests/docker/Dockerfile.backup-tools" "$context/Containerfile"
podman build --pull=missing -t "$image" "$context"

podman run --rm --network=none --cap-drop=ALL --security-opt=no-new-privileges \
    --read-only --tmpfs /tmp:rw,size=512m --pids-limit=256 --memory=1g \
    -v "$tree:/src:ro" -w /src \
    -e AXROSS_BACKUP_LIVE=1 -e PYTHONDONTWRITEBYTECODE=1 -e HOME=/tmp \
    "$image" \
    sh -c 'borg --version; duplicity --version; python3 --version;
           exec python3 -m pytest -p no:cacheprovider -v -s -rs tests/test_backup_repos_live.py "$@"' \
    _ "$@"
