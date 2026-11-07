#!/usr/bin/env bash
# The supply-chain gate's night session: capa on every native binary of the
# locked dependencies, however large (security/supply_chain_gate.py deep-scan),
# within a time budget; resumable - the next night continues. Results go into
# security/supply_chain_baseline/; an alarming capability (anti-analysis,
# persistence, injection, credential access ...) fails the gate until it is
# reviewed (accept-deep). Run it from cron or a systemd timer, e.g.
#   30 0 * * *  cd /path/to/axross && scripts/supply_chain_nightly.sh >> ~/axross-nightly.log 2>&1
#
#   scripts/supply_chain_nightly.sh [BUDGET_MINUTES] [WORKERS]
set -euo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUDGET="${1:-420}"
WORKERS="${2:-2}"
WORK="${AXROSS_NIGHTLY_WORK:-$PWD/build/nightly}"
mkdir -p "$WORK"
export AXROSS_SUPPLY_CHAIN_CACHE="$WORK/supply-chain-cache"
PY=$(uv python find 3.12)
# the scanners from their vetted lock, checked before and after installing
python3 -I security/supply_chain_gate.py check --report "$WORK/gate"
rm -rf "$WORK/scan-venv"
"$PY" -m venv "$WORK/scan-venv"
"$WORK/scan-venv/bin/pip" install -q --require-hashes --only-binary=:all: -r build/requirements-scan-tools.txt
python3 -I security/supply_chain_gate.py verify-env --python "$WORK/scan-venv/bin/python" \
    --lock build/requirements-scan-tools.txt
echo ">>> $(date -u +%FT%TZ) deep scan, $BUDGET min, $WORKERS at a time"
python3 -I security/supply_chain_gate.py deep-scan --scan-python "$WORK/scan-venv/bin/python" \
    --budget-minutes "$BUDGET" --workers "$WORKERS"
git status --short security/supply_chain_baseline | head -20
