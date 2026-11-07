#!/usr/bin/env bash
# Lock the supply-chain gate's scanners (build/requirements-scan-tools.in)
# with hashes, for CPython 3.12 on Linux x86_64 - the build machine. Only
# releases at least MIN_AGE_DAYS old are considered (uv --exclude-newer),
# the gate's minimum age.
set -euo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MIN_AGE_DAYS=14
CUTOFF=$(date -u -d "-${MIN_AGE_DAYS} days" +%Y-%m-%dT%H:%M:%SZ)
# reviewed security fixes younger than that (build/young-release-exceptions.txt)
EXCEPTIONS=()
while read -r pkg date _; do
    [[ -z "$pkg" || "$pkg" == \#* ]] && continue
    EXCEPTIONS+=(--exclude-newer-package "$pkg=$date")
done < build/young-release-exceptions.txt
UV_NO_CONFIG=1 uv pip compile build/requirements-scan-tools.in --python-version 3.12 \
    --python-platform x86_64-manylinux_2_28 --generate-hashes --index-url https://pypi.org/simple \
    --exclude-newer "$CUTOFF" "${EXCEPTIONS[@]}" --custom-compile-command "scripts/lock_scan_tools.sh" --quiet \
    --output-file build/requirements-scan-tools.txt
echo "locked (releases up to $CUTOFF): $(grep -c '==' build/requirements-scan-tools.txt) pins"
