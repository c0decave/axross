#!/bin/bash
# Axross Security & Bug Analysis — adapted from OTI Dashboard security scanner.
# Allow individual tools to fail without aborting the full scan.
set -uo pipefail

export PATH="/opt/tools/bin:${PATH}"

REPORT_DIR="/src/security/reports"
mkdir -p "$REPORT_DIR"
TIMESTAMP=$(date +%Y-%m-%d_%H%M%S)
SCAN_REQUIREMENTS="/src/requirements.txt"

# Axross is a desktop app — no web target needed for most scans.
# Network scans (nmap, nikto, ffuf, katana, ZAP) are skipped by default.
RUN_NETWORK_SCANS="${RUN_NETWORK_SCANS:-0}"
TARGET_URL="${TARGET_URL:-}"

# Focus scans on app/runtime sources and skip security tooling/report trees.
CODE_SCAN_PATHS=(
    /src/core
    /src/ui
    /src/models
    /src/main.py
)
PYTHON_SCAN_PATHS=(
    /src/core
    /src/ui
    /src/models
    /src/main.py
)
SECRET_SCAN_PATHS=(
    "${CODE_SCAN_PATHS[@]}"
)

# Optional: include /src/security in source scans when explicitly requested.
INCLUDE_SECURITY_DIR="${INCLUDE_SECURITY_DIR:-0}"
SEMGREP_SCOPE_EXCLUDES=(--exclude="*/reports/*")
NL_EXCLUDE_ARGS=(
    --exclude "*/reports/*"
    --exclude "*/docs/*"
    --exclude "*/tests/*"
    --exclude "*/.venv/*"
)
NET_EXCLUDE_ARGS=(
    --exclude-dir reports
    --exclude-dir docs
    --exclude-dir tests
    --exclude-dir .venv
    --exclude-dir venv
)
ENT_EXCLUDE_ARGS=(
    --exclude-dir reports
    --exclude-dir docs
    --exclude-dir tests
    --exclude-dir .venv
    --exclude-dir venv
)
YARA_EXCLUDE_ARGS=(--exclude="/src/security/reports/*")
DODGY_IGNORE_PATHS="reports,docs,tests,.venv,venv,dist,build,*.egg-info"
SYFT_EXCLUDE_ARGS=(
    --exclude "./.venv/**"
    --exclude "./security/reports/**"
    --exclude "./docs/**"
    --exclude "./tests/**"
    --exclude "./dist/**"
    --exclude "./build/**"
)

if [ "$INCLUDE_SECURITY_DIR" = "1" ] || [ "$INCLUDE_SECURITY_DIR" = "true" ]; then
    CODE_SCAN_PATHS+=(/src/security)
    SECRET_SCAN_PATHS+=(/src/security)
else
    SEMGREP_SCOPE_EXCLUDES+=(--exclude="*/security/*")
    NL_EXCLUDE_ARGS+=(--exclude "*/security/*")
    NET_EXCLUDE_ARGS+=(--exclude-dir security)
    ENT_EXCLUDE_ARGS+=(--exclude-dir security)
    YARA_EXCLUDE_ARGS+=(--exclude="/src/security/*")
    DODGY_IGNORE_PATHS="${DODGY_IGNORE_PATHS},security"
fi

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

header() {
    echo ""
    echo -e "${CYAN}================================================================${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${CYAN}================================================================${NC}"
    echo ""
}

separator() {
    echo -e "${YELLOW}----------------------------------------------------------------${NC}"
}

SUMMARY_FILE="$REPORT_DIR/summary_${TIMESTAMP}.txt"
echo "Axross - Security & Bug Analysis Report" > "$SUMMARY_FILE"
echo "Generated: $(date)" >> "$SUMMARY_FILE"
echo "================================================" >> "$SUMMARY_FILE"

# ============================================================
# 0. Generate temporary requirements.txt from pyproject.toml for dep scanners
# ============================================================
header "0/18 - PREP: Generate dependency input"
if [ -f /src/pyproject.toml ]; then
    GENERATED_REQUIREMENTS="$REPORT_DIR/generated_requirements_${TIMESTAMP}.txt"
    python3 -c "
import tomllib, pathlib
data = tomllib.loads(pathlib.Path('/src/pyproject.toml').read_text())
deps = data.get('project', {}).get('dependencies', [])
extras = data.get('project', {}).get('optional-dependencies', {})
all_deps = list(deps)
for group_deps in extras.values():
    all_deps.extend(group_deps)
with open('$GENERATED_REQUIREMENTS', 'w', encoding='utf-8') as f:
    for d in sorted(set(all_deps)):
        f.write(d + '\n')
print(f'Generated requirements.txt with {len(set(all_deps))} dependencies')
" 2>/dev/null || echo "Could not generate dependency input"
    if [ -s "$GENERATED_REQUIREMENTS" ]; then
        SCAN_REQUIREMENTS="$GENERATED_REQUIREMENTS"
    fi
fi

# ============================================================
# 1. BANDIT - Python Security Linter
# ============================================================
header "1/18 - BANDIT: Python Security Analysis"
BANDIT_REPORT="$REPORT_DIR/bandit_${TIMESTAMP}.json"
BANDIT_TXT="$REPORT_DIR/bandit_${TIMESTAMP}.txt"

BANDIT_PATHS=()
for p in "${PYTHON_SCAN_PATHS[@]}"; do
    [ -e "$p" ] && BANDIT_PATHS+=("$p")
done

if [ ${#BANDIT_PATHS[@]} -gt 0 ]; then
    bandit -r "${BANDIT_PATHS[@]}" \
        -f json -o "$BANDIT_REPORT" \
        --severity-level medium \
        -x "**/tests/*,**/__pycache__/*" \
        2>/dev/null || true

    bandit -r "${BANDIT_PATHS[@]}" \
        -f txt -o "$BANDIT_TXT" \
        --severity-level medium \
        -x "**/tests/*,**/__pycache__/*" \
        2>/dev/null || true
fi

BANDIT_ISSUES=$(python3 -c "import json; d=json.load(open('$BANDIT_REPORT')); print(len(d.get('results',[])))" 2>/dev/null || echo "0")
echo -e "${GREEN}Bandit: ${BANDIT_ISSUES} issues found${NC}"
echo "Bandit: ${BANDIT_ISSUES} issues" >> "$SUMMARY_FILE"
cat "$BANDIT_TXT" 2>/dev/null || true

# ============================================================
# 2. SEMGREP - Multi-language SAST
# ============================================================
header "2/18 - SEMGREP: Multi-Language Static Analysis"
SEMGREP_REPORT="$REPORT_DIR/semgrep_${TIMESTAMP}.json"
SEMGREP_TXT="$REPORT_DIR/semgrep_${TIMESTAMP}.txt"
SEMGREP_CUSTOM="/src/security/semgrep/backdoor_rules.yml"
if [ ! -f "$SEMGREP_CUSTOM" ]; then
    SEMGREP_CUSTOM="/opt/semgrep/backdoor_rules.yml"
fi
SEMGREP_CUSTOM_ARG=""
if [ -f "$SEMGREP_CUSTOM" ]; then
    SEMGREP_CUSTOM_ARG="--config $SEMGREP_CUSTOM"
fi

semgrep scan \
    --config=auto \
    --config=p/python \
    --config=p/owasp-top-ten \
    --config=p/secrets \
    $SEMGREP_CUSTOM_ARG \
    --json -o "$SEMGREP_REPORT" \
    --exclude="*/tests/*" \
    --exclude="*/__pycache__/*" \
    --exclude="*/.venv/*" \
    --exclude="*/dist/*" \
    --exclude="*/build/*" \
    "${SEMGREP_SCOPE_EXCLUDES[@]}" \
    /src 2>/dev/null || true

python3 -c "
import json, sys
try:
    with open('$SEMGREP_REPORT') as f:
        data = json.load(f)
    results = data.get('results', [])
    print(f'Total findings: {len(results)}')
    by_severity = {}
    for r in results:
        sev = r.get('extra', {}).get('severity', 'UNKNOWN')
        by_severity[sev] = by_severity.get(sev, 0) + 1
    for sev, count in sorted(by_severity.items()):
        print(f'  {sev}: {count}')
    print()
    for r in results:
        path = r.get('path', '?')
        line = r.get('start', {}).get('line', '?')
        msg = r.get('extra', {}).get('message', 'No message')
        sev = r.get('extra', {}).get('severity', '?')
        rule = r.get('check_id', '?')
        print(f'[{sev}] {path}:{line}')
        print(f'  Rule: {rule}')
        print(f'  {msg[:200]}')
        print()
except Exception as e:
    print(f'Error parsing semgrep results: {e}')
" 2>/dev/null | tee "$SEMGREP_TXT"

SEMGREP_ISSUES=$(python3 -c "import json; d=json.load(open('$SEMGREP_REPORT')); print(len(d.get('results',[])))" 2>/dev/null || echo "0")
echo "Semgrep: ${SEMGREP_ISSUES} issues" >> "$SUMMARY_FILE"

# ============================================================
# 3. GITLEAKS - Secret Detection
# ============================================================
header "3/18 - GITLEAKS: Secret & Credential Detection"
GITLEAKS_REPORT="$REPORT_DIR/gitleaks_${TIMESTAMP}.json"

GITLEAKS_EXIT=0
if command -v gitleaks >/dev/null 2>&1; then
    GITLEAKS_TMP_DIR=$(mktemp -d)
    for scan_path in "${SECRET_SCAN_PATHS[@]}"; do
        [ -e "$scan_path" ] || continue
        scan_name=$(basename "$scan_path" | tr '.' '_')
        scan_report="${GITLEAKS_TMP_DIR}/${scan_name}.json"
        GITLEAKS_CMD_EXIT=0
        gitleaks detect --source="$scan_path" --report-format=json --report-path="$scan_report" --no-git 2>/dev/null || GITLEAKS_CMD_EXIT=$?
        if [ "$GITLEAKS_CMD_EXIT" -ne 0 ] && [ "$GITLEAKS_CMD_EXIT" -ne 1 ]; then
            GITLEAKS_EXIT=$GITLEAKS_CMD_EXIT
        fi
    done
    python3 - <<PY 2>/dev/null > "$GITLEAKS_REPORT" || echo "[]" > "$GITLEAKS_REPORT"
import json, glob
merged = []
for path in glob.glob("$GITLEAKS_TMP_DIR/*.json"):
    try:
        with open(path) as f:
            data = json.load(f)
        if isinstance(data, list):
            merged.extend(data)
    except Exception:
        continue
print(json.dumps(merged))
PY
    rm -rf "$GITLEAKS_TMP_DIR"
else
    GITLEAKS_EXIT=127
fi
if [ ! -s "$GITLEAKS_REPORT" ]; then
    echo "[]" > "$GITLEAKS_REPORT"
fi

GITLEAKS_ISSUES=$(python3 -c "import json; d=json.load(open('$GITLEAKS_REPORT')); print(len(d))" 2>/dev/null || echo "0")
echo -e "${GREEN}Gitleaks: ${GITLEAKS_ISSUES} potential secrets found${NC}"
echo "Gitleaks: ${GITLEAKS_ISSUES} secrets" >> "$SUMMARY_FILE"

if [ "$GITLEAKS_ISSUES" != "0" ]; then
    python3 -c "
import json
with open('$GITLEAKS_REPORT') as f:
    for item in json.load(f):
        print(f\"  [{item.get('RuleID','?')}] {item.get('File','?')}:{item.get('StartLine','?')}\")
        print(f\"    Match: {item.get('Match','?')[:80]}\")
        print()
" 2>/dev/null || true
fi

# ============================================================
# 4. TRUFFLEHOG - Deep Secret Scan
# ============================================================
header "4/18 - TRUFFLEHOG: Deep Secret Detection"
TRUFFLEHOG_JSON="$REPORT_DIR/trufflehog_${TIMESTAMP}.json"
TRUFFLEHOG_TXT="$REPORT_DIR/trufflehog_${TIMESTAMP}.txt"

: > "$TRUFFLEHOG_JSON"
for scan_path in "${SECRET_SCAN_PATHS[@]}"; do
    [ -e "$scan_path" ] || continue
    trufflehog filesystem "$scan_path" --json >> "$TRUFFLEHOG_JSON" 2>/dev/null || true
done
TRUFFLEHOG_ISSUES=$(wc -l < "$TRUFFLEHOG_JSON" 2>/dev/null || echo "0")

python3 -c "
import json, collections
counts = collections.Counter()
try:
    with open('$TRUFFLEHOG_JSON') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except Exception:
                continue
            name = data.get('DetectorName') or data.get('DetectorType') or 'unknown'
            counts[name] += 1
    print(f'Total findings: {sum(counts.values())}')
    for name, count in counts.most_common():
        print(f'  {name}: {count}')
except Exception as e:
    print(f'Error parsing trufflehog output: {e}')
" 2>/dev/null > "$TRUFFLEHOG_TXT" || true

echo -e "${GREEN}Trufflehog: ${TRUFFLEHOG_ISSUES} potential secrets found${NC}"
echo "Trufflehog: ${TRUFFLEHOG_ISSUES} secrets" >> "$SUMMARY_FILE"

# ============================================================
# 5. YARA - Backdoor/IOC Pattern Scan
# ============================================================
header "5/18 - YARA: Backdoor/IOC Pattern Scan"
YARA_RULES="/src/security/yara_rules/backdoor_rules.yar"
if [ ! -f "$YARA_RULES" ]; then
    YARA_RULES="/opt/yara_rules/backdoor_rules.yar"
fi
YARA_TXT="$REPORT_DIR/yara_${TIMESTAMP}.txt"
YARA_JSON="$REPORT_DIR/yara_${TIMESTAMP}.json"

if [ -f "$YARA_RULES" ]; then
    yara -r \
        "${YARA_EXCLUDE_ARGS[@]}" \
        "$YARA_RULES" /src > "$YARA_TXT" 2>/dev/null || true
    python3 -c "
import json, collections
matches = []
counts = collections.Counter()
try:
    with open('$YARA_TXT') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split(' ', 1)
            if len(parts) != 2:
                continue
            rule, path = parts
            matches.append({'rule': rule, 'file': path})
            counts[rule] += 1
    payload = {'statistics': {'matches': len(matches), 'by_rule': dict(counts)}, 'matches': matches}
    with open('$YARA_JSON', 'w') as out:
        json.dump(payload, out, indent=2)
except Exception:
    with open('$YARA_JSON', 'w') as out:
        json.dump({'statistics': {'matches': 0, 'by_rule': {}}, 'matches': []}, out, indent=2)
" 2>/dev/null || true
else
    echo "YARA rules not found: $YARA_RULES" > "$YARA_TXT"
    echo '{"statistics": {"matches": 0, "by_rule": {}}, "matches": []}' > "$YARA_JSON"
fi

YARA_MATCHES=$(python3 -c "import json; d=json.load(open('$YARA_JSON')); print(d.get('statistics',{}).get('matches',0))" 2>/dev/null || echo "0")
echo -e "${GREEN}YARA: ${YARA_MATCHES} matches${NC}"
echo "YARA: ${YARA_MATCHES} matches" >> "$SUMMARY_FILE"

# ============================================================
# 6. SAFETY - Python Dependency Vulnerability Check
# ============================================================
header "6/18 - SAFETY: Python Dependency Vulnerabilities"
SAFETY_REPORT="$REPORT_DIR/safety_${TIMESTAMP}.txt"

if [ -f "$SCAN_REQUIREMENTS" ]; then
    safety scan --target "$SCAN_REQUIREMENTS" --output text 2>/dev/null | tee "$SAFETY_REPORT" || \
    safety check -r "$SCAN_REQUIREMENTS" --output text 2>/dev/null | tee "$SAFETY_REPORT" || true
    echo "Safety: see report" >> "$SUMMARY_FILE"
else
    echo "No requirements.txt found, skipping safety check"
    echo "Safety: skipped (no requirements.txt)" >> "$SUMMARY_FILE"
fi

# ============================================================
# 7. PIP-AUDIT - Python Dependency Vulnerabilities
# ============================================================
header "7/18 - PIP-AUDIT: Python Dependency Vulnerabilities"
PIPAUDIT_REPORT="$REPORT_DIR/pip_audit_${TIMESTAMP}.json"
PIPAUDIT_TXT="$REPORT_DIR/pip_audit_${TIMESTAMP}.txt"

if [ -f "$SCAN_REQUIREMENTS" ]; then
    pip-audit -r "$SCAN_REQUIREMENTS" -f json > "$PIPAUDIT_REPORT" 2>/dev/null || true

    if [ -s "$PIPAUDIT_REPORT" ]; then
        python3 -c "
import json
from typing import Any, List, Dict

with open('$PIPAUDIT_REPORT') as f:
    data = json.load(f)

def deps_from(data: Any) -> List[Dict[str, Any]]:
    if isinstance(data, dict):
        deps = data.get('dependencies') or data.get('deps') or []
        return deps if isinstance(deps, list) else []
    if isinstance(data, list):
        return data
    return []

deps = deps_from(data)
total_vulns = 0
for item in deps:
    if not isinstance(item, dict):
        total_vulns += 1
        continue
    vulns = item.get('vulns')
    if isinstance(vulns, list):
        total_vulns += len(vulns)

print(f'Total findings: {total_vulns}')
for item in deps[:200]:
    if not isinstance(item, dict):
        continue
    dep = item.get('name', '?')
    ver = item.get('version', '?')
    vulns = item.get('vulns') or []
    if not isinstance(vulns, list):
        vulns = []
    print(f'- {dep} {ver}: {len(vulns)} vulns')
    for v in vulns[:3]:
        if isinstance(v, dict):
            print(f\"  - {v.get('id','?')}: {v.get('description','')[:120]}\")
" 2>/dev/null | tee "$PIPAUDIT_TXT"

        PIPAUDIT_ISSUES=$(python3 -c "
import json
from typing import Any
data = json.load(open('$PIPAUDIT_REPORT'))
def deps_from(d: Any):
    if isinstance(d, dict):
        deps = d.get('dependencies') or d.get('deps') or []
        return deps if isinstance(deps, list) else []
    if isinstance(d, list):
        return d
    return []
deps = deps_from(data)
total = 0
for item in deps:
    if isinstance(item, dict) and isinstance(item.get('vulns'), list):
        total += len(item.get('vulns') or [])
print(total)
" 2>/dev/null || echo "0")
        echo "pip-audit: ${PIPAUDIT_ISSUES} findings" >> "$SUMMARY_FILE"
    else
        echo "pip-audit: no report generated" >> "$SUMMARY_FILE"
    fi
else
    echo "pip-audit: skipped (no requirements.txt)" >> "$SUMMARY_FILE"
fi

# ============================================================
# 8. OSV-SCANNER - Dependency Vulnerabilities (Repo Scan)
# ============================================================
header "8/18 - OSV-SCANNER: Dependency Vulnerabilities"
OSV_REPORT="$REPORT_DIR/osv_scanner_${TIMESTAMP}.json"
OSV_TXT="$REPORT_DIR/osv_scanner_${TIMESTAMP}.txt"

OSV_EXIT=0
if command -v osv-scanner >/dev/null 2>&1; then
    osv-scanner --format json --output "$OSV_REPORT" --recursive /src 2>/dev/null || \
    osv-scanner scan --format json --output "$OSV_REPORT" --recursive /src 2>/dev/null || \
    osv-scanner -r /src --format json > "$OSV_REPORT" 2>/dev/null || OSV_EXIT=$?
else
    OSV_EXIT=127
fi
if [ ! -s "$OSV_REPORT" ]; then
    echo '{"results": []}' > "$OSV_REPORT"
fi

if [ -s "$OSV_REPORT" ]; then
    python3 -c "
import json
def count_vulns(data):
    if isinstance(data, dict):
        if 'results' in data:
            total = 0
            for r in data.get('results', []):
                total += len(r.get('vulnerabilities', []) or r.get('vulns', []))
            return total
        return len(data.get('vulnerabilities', []) or data.get('vulns', []))
    if isinstance(data, list):
        return sum(count_vulns(item) for item in data)
    return 0
with open('$OSV_REPORT') as f:
    data = json.load(f)
total = count_vulns(data)
print(f'Total vulnerabilities: {total}')
" 2>/dev/null | tee "$OSV_TXT"

    OSV_ISSUES=$(python3 -c "
import json
from pathlib import Path
data = json.load(Path('$OSV_REPORT').open())
def count_vulns(d):
    if isinstance(d, dict):
        if 'results' in d:
            return sum(len(r.get('vulnerabilities', []) or r.get('vulns', [])) for r in d.get('results', []))
        return len(d.get('vulnerabilities', []) or d.get('vulns', []))
    if isinstance(d, list):
        return sum(count_vulns(i) for i in d)
    return 0
print(count_vulns(data))
" 2>/dev/null || echo "0")
    echo "osv-scanner: ${OSV_ISSUES} findings" >> "$SUMMARY_FILE"
else
    echo "osv-scanner: no report generated" >> "$SUMMARY_FILE"
fi

# ============================================================
# 9. SYFT - SBOM Generation
# ============================================================
header "9/18 - SYFT: SBOM Generation"
SYFT_REPORT="$REPORT_DIR/syft_${TIMESTAMP}.json"

syft dir:/src -o json "${SYFT_EXCLUDE_ARGS[@]}" > "$SYFT_REPORT" 2>/dev/null || true
SYFT_PACKAGES=$(python3 -c "import json; d=json.load(open('$SYFT_REPORT')); print(len(d.get('artifacts',[])))" 2>/dev/null || echo "0")
echo "Syft: ${SYFT_PACKAGES} packages" >> "$SUMMARY_FILE"

# ============================================================
# 10. GRYPE - Vulnerability Scan (SBOM)
# ============================================================
header "10/18 - GRYPE: SBOM Vulnerability Scan"
GRYPE_REPORT="$REPORT_DIR/grype_${TIMESTAMP}.json"

if [ -s "$SYFT_REPORT" ]; then
    grype sbom:"$SYFT_REPORT" -o json > "$GRYPE_REPORT" 2>/dev/null || true
else
    grype dir:/src -o json > "$GRYPE_REPORT" 2>/dev/null || true
fi

GRYPE_ISSUES=$(python3 -c "import json; d=json.load(open('$GRYPE_REPORT')); print(len(d.get('matches',[])))" 2>/dev/null || echo "0")
echo "Grype: ${GRYPE_ISSUES} findings" >> "$SUMMARY_FILE"

# ============================================================
# 11. PYLINT - Python Code Quality & Bugs
# ============================================================
header "11/18 - PYLINT: Python Code Quality & Bug Detection"
PYLINT_REPORT="$REPORT_DIR/pylint_${TIMESTAMP}.txt"

find /src/core /src/ui /src/models -name "*.py" \
    ! -path "*/__pycache__/*" \
    2>/dev/null \
    | head -100 \
    | xargs pylint \
    --disable=C,R \
    --enable=E,W \
    --output-format=text \
    2>/dev/null | tee "$PYLINT_REPORT" || true

PYLINT_ERRORS=$(grep -c "^E:" "$PYLINT_REPORT" 2>/dev/null || echo "0")
PYLINT_WARNINGS=$(grep -c "^W:" "$PYLINT_REPORT" 2>/dev/null || echo "0")
echo "Pylint: ${PYLINT_ERRORS} errors, ${PYLINT_WARNINGS} warnings" >> "$SUMMARY_FILE"

# ============================================================
# 12. FLAKE8 - Python Lint (Bugs & Style)
# ============================================================
header "12/18 - FLAKE8: Python Lint"
FLAKE8_REPORT="$REPORT_DIR/flake8_${TIMESTAMP}.txt"

FLAKE8_DIRS=""
for p in /src/core /src/ui /src/models; do
    [ -d "$p" ] && FLAKE8_DIRS="$FLAKE8_DIRS $p"
done

if [ -n "$FLAKE8_DIRS" ]; then
    flake8 $FLAKE8_DIRS \
        --exclude="*/__pycache__/*" \
        --count --select=E9,F63,F7,F82 --show-source --statistics \
        2>/dev/null | tee "$FLAKE8_REPORT" || true
fi

FLAKE8_ERRORS=$(grep -E "^[0-9]+$" "$FLAKE8_REPORT" 2>/dev/null | tail -1 || echo "0")
echo "Flake8: ${FLAKE8_ERRORS} critical issues" >> "$SUMMARY_FILE"

# ============================================================
# 13. HADOLINT - Dockerfile Lint
# ============================================================
header "13/18 - HADOLINT: Dockerfile Lint"
HADOLINT_REPORT="$REPORT_DIR/hadolint_${TIMESTAMP}.txt"

HADOLINT_FILES=$(find /src -name "Dockerfile*" -type f 2>/dev/null || true)
if [ -n "$HADOLINT_FILES" ]; then
    : > "$HADOLINT_REPORT"
    for file in $HADOLINT_FILES; do
        echo "File: $file" >> "$HADOLINT_REPORT"
        hadolint "$file" >> "$HADOLINT_REPORT" 2>/dev/null || true
        echo "" >> "$HADOLINT_REPORT"
    done
    HADOLINT_ISSUES=$(grep -E "DL[0-9]+" "$HADOLINT_REPORT" 2>/dev/null | wc -l | tr -d ' ')
    echo "Hadolint: ${HADOLINT_ISSUES} issues" >> "$SUMMARY_FILE"
else
    echo "Hadolint: skipped (no Dockerfile)" >> "$SUMMARY_FILE"
fi

# ============================================================
# 14. DODGY - Hardcoded Secrets in Python
# ============================================================
header "14/18 - DODGY: Hardcoded Secret Detection (Python)"
DODGY_REPORT="$REPORT_DIR/dodgy_${TIMESTAMP}.txt"

DODGY_SCAN_PATHS=("${PYTHON_SCAN_PATHS[@]}")
if [ "$INCLUDE_SECURITY_DIR" = "1" ] || [ "$INCLUDE_SECURITY_DIR" = "true" ]; then
    DODGY_SCAN_PATHS+=(/src/security)
fi

DODGY_EXISTING_PATHS=()
for scan_path in "${DODGY_SCAN_PATHS[@]}"; do
    [ -e "$scan_path" ] || continue
    DODGY_EXISTING_PATHS+=("$scan_path")
done

if [ ${#DODGY_EXISTING_PATHS[@]} -gt 0 ]; then
    dodgy --ignore-paths "$DODGY_IGNORE_PATHS" "${DODGY_EXISTING_PATHS[@]}" 2>/dev/null | tee "$DODGY_REPORT" || true
else
    echo '{"warnings": []}' | tee "$DODGY_REPORT" >/dev/null
fi
echo "Dodgy: see report" >> "$SUMMARY_FILE"

# ============================================================
# 15. NATURAL LANGUAGE & SECRET SCANNER
# ============================================================
header "15/18 - NL SCANNER: Natural Language & Secret Detection"
NL_JSON="$REPORT_DIR/natural_language_${TIMESTAMP}.json"
NL_TXT="$REPORT_DIR/natural_language_${TIMESTAMP}.txt"

NL_SCRIPT="/src/security/scan_natural_language.py"
if [ ! -f "$NL_SCRIPT" ]; then
    NL_SCRIPT="/opt/scan_natural_language.py"
fi
python3 "$NL_SCRIPT" --root /src \
    --severity medium --no-color \
    "${NL_EXCLUDE_ARGS[@]}" \
    --json-output "$NL_JSON" --txt-output "$NL_TXT" \
    2>/dev/null || true

NL_ISSUES=$(python3 -c "import json; d=json.load(open('$NL_JSON')); print(d['statistics']['total_findings'])" 2>/dev/null || echo "0")
NL_SECRETS=$(python3 -c "import json; d=json.load(open('$NL_JSON')); print(d['statistics']['by_category'].get('secret',0))" 2>/dev/null || echo "0")
echo -e "${GREEN}NL Scanner: ${NL_ISSUES} findings (${NL_SECRETS} secrets)${NC}"
echo "NL Scanner: ${NL_ISSUES} findings (${NL_SECRETS} secrets)" >> "$SUMMARY_FILE"

# ============================================================
# 16. NETWORK EGRESS SURFACE SCAN
# ============================================================
header "16/18 - NETWORK EGRESS: Potential Outbound Call Sites"
NETSCAN_JSON="$REPORT_DIR/network_egress_${TIMESTAMP}.json"
NETSCAN_TXT="$REPORT_DIR/network_egress_${TIMESTAMP}.txt"
NET_SCRIPT="/src/security/scan_network_egress.py"
if [ ! -f "$NET_SCRIPT" ]; then
    NET_SCRIPT="/opt/scan_network_egress.py"
fi

python3 "$NET_SCRIPT" --root /src \
    "${NET_EXCLUDE_ARGS[@]}" \
    --json-output "$NETSCAN_JSON" \
    --txt-output "$NETSCAN_TXT" \
    2>/dev/null || true

NET_ISSUES=$(python3 -c "import json; d=json.load(open('$NETSCAN_JSON')); print(d['statistics']['total_findings'])" 2>/dev/null || echo "0")
echo -e "${GREEN}Network Egress: ${NET_ISSUES} call sites${NC}"
echo "Network Egress: ${NET_ISSUES} call sites" >> "$SUMMARY_FILE"

# ============================================================
# 17. ENTROPY SCAN
# ============================================================
header "17/18 - ENTROPY: High-Entropy File Detection"
ENTROPY_JSON="$REPORT_DIR/entropy_${TIMESTAMP}.json"
ENTROPY_TXT="$REPORT_DIR/entropy_${TIMESTAMP}.txt"
ENT_SCRIPT="/src/security/entropy_scan.py"
if [ ! -f "$ENT_SCRIPT" ]; then
    ENT_SCRIPT="/opt/entropy_scan.py"
fi

python3 "$ENT_SCRIPT" --root /src \
    "${ENT_EXCLUDE_ARGS[@]}" \
    --json-output "$ENTROPY_JSON" \
    --txt-output "$ENTROPY_TXT" \
    2>/dev/null || true

ENTROPY_HIGH=$(python3 -c "import json; d=json.load(open('$ENTROPY_JSON')); print(d['statistics']['high_entropy_files'])" 2>/dev/null || echo "0")
ENTROPY_FILES=$(python3 -c "import json; d=json.load(open('$ENTROPY_JSON')); print(d['statistics']['total_files'])" 2>/dev/null || echo "0")
echo -e "${GREEN}Entropy: ${ENTROPY_HIGH} high-entropy files (of ${ENTROPY_FILES})${NC}"
echo "Entropy: ${ENTROPY_HIGH} high-entropy files (of ${ENTROPY_FILES})" >> "$SUMMARY_FILE"

# ============================================================
# 18. NETWORK SCANS (Optional — only when RUN_NETWORK_SCANS=1)
# ============================================================
NMAP_REPORT="n/a"
NIKTO_REPORT="n/a"
ZAP_ALERTS="0"

if [ "$RUN_NETWORK_SCANS" = "1" ] || [ "$RUN_NETWORK_SCANS" = "true" ]; then
    if [ -n "$TARGET_URL" ]; then
        TARGET_HOST=$(echo "$TARGET_URL" | sed -E 's#^https?://##; s#/.*##')

        header "18a/18 - NMAP: Service Discovery"
        NMAP_REPORT="$REPORT_DIR/nmap_${TIMESTAMP}.txt"
        nmap -sV -Pn -p 22,21,445,443,873,2049,3260,993 "$TARGET_HOST" \
            -oN "$NMAP_REPORT" 2>/dev/null || true
        echo "Nmap: see report" >> "$SUMMARY_FILE"

        header "18b/18 - NIKTO: Web Server Scan"
        NIKTO_REPORT="$REPORT_DIR/nikto_${TIMESTAMP}.txt"
        nikto -h "$TARGET_URL" -output "$NIKTO_REPORT" -Format txt 2>/dev/null || true
        echo "Nikto: see report" >> "$SUMMARY_FILE"
    else
        echo "Network scans: skipped (no TARGET_URL)" >> "$SUMMARY_FILE"
    fi
else
    echo "Network scans: skipped (RUN_NETWORK_SCANS=0)" >> "$SUMMARY_FILE"
fi

# ============================================================
# FINAL SUMMARY
# ============================================================
header "ANALYSIS COMPLETE"
echo ""
echo -e "${CYAN}Summary:${NC}"
echo -e "  Bandit (Python Security):      ${BANDIT_ISSUES} issues"
echo -e "  Semgrep (Multi-lang SAST):      ${SEMGREP_ISSUES} issues"
echo -e "  Gitleaks (Secrets):             ${GITLEAKS_ISSUES} secrets"
echo -e "  Trufflehog (Secrets):           ${TRUFFLEHOG_ISSUES} findings"
echo -e "  YARA (IOC Patterns):            ${YARA_MATCHES} matches"
echo -e "  Safety (Deps):                  see report"
echo -e "  pip-audit (Deps):               ${PIPAUDIT_ISSUES:-0} findings"
echo -e "  osv-scanner (Deps):             ${OSV_ISSUES:-0} findings"
echo -e "  Syft (SBOM packages):           ${SYFT_PACKAGES:-0}"
echo -e "  Grype (SBOM vulns):             ${GRYPE_ISSUES:-0}"
echo -e "  Pylint (Errors/Warnings):       ${PYLINT_ERRORS}E / ${PYLINT_WARNINGS}W"
echo -e "  Flake8 (Critical):              ${FLAKE8_ERRORS} issues"
echo -e "  Hadolint (Dockerfile):          ${HADOLINT_ISSUES:-0} issues"
echo -e "  NL Scanner (Findings/Secrets):  ${NL_ISSUES} / ${NL_SECRETS}"
echo -e "  Network Egress (Call Sites):    ${NET_ISSUES:-0}"
echo -e "  Entropy (High/Total files):     ${ENTROPY_HIGH:-0} / ${ENTROPY_FILES:-0}"
echo ""
echo -e "${GREEN}Reports saved to: /src/security/reports/${NC}"
echo ""

# Final summary to file
echo "" >> "$SUMMARY_FILE"
echo "Reports:" >> "$SUMMARY_FILE"
echo "  $BANDIT_REPORT" >> "$SUMMARY_FILE"
echo "  $SEMGREP_REPORT" >> "$SUMMARY_FILE"
echo "  $GITLEAKS_REPORT" >> "$SUMMARY_FILE"
echo "  $TRUFFLEHOG_JSON" >> "$SUMMARY_FILE"
echo "  $YARA_JSON" >> "$SUMMARY_FILE"
echo "  $SAFETY_REPORT" >> "$SUMMARY_FILE"
echo "  $PIPAUDIT_REPORT" >> "$SUMMARY_FILE"
echo "  $OSV_REPORT" >> "$SUMMARY_FILE"
echo "  $SYFT_REPORT" >> "$SUMMARY_FILE"
echo "  $GRYPE_REPORT" >> "$SUMMARY_FILE"
echo "  $PYLINT_REPORT" >> "$SUMMARY_FILE"
echo "  $FLAKE8_REPORT" >> "$SUMMARY_FILE"
echo "  $HADOLINT_REPORT" >> "$SUMMARY_FILE"
echo "  $DODGY_REPORT" >> "$SUMMARY_FILE"
echo "  $NL_JSON" >> "$SUMMARY_FILE"
echo "  $NETSCAN_JSON" >> "$SUMMARY_FILE"
echo "  $ENTROPY_JSON" >> "$SUMMARY_FILE"

# ============================================================
# REPORT GENERATION (Markdown + PDF)
# ============================================================
header "REPORT GENERATION"
REPORT_MD="$REPORT_DIR/security_report_${TIMESTAMP}.md"
REPORT_PDF="$REPORT_DIR/security_report_${TIMESTAMP}.pdf"

python3 /opt/generate_report.py \
    --summary "$SUMMARY_FILE" \
    --report-dir "$REPORT_DIR" \
    --timestamp "$TIMESTAMP" \
    --output-md "$REPORT_MD" \
    --output-pdf "$REPORT_PDF" 2>/dev/null || true

if [ -f "$REPORT_MD" ]; then
    echo "  $REPORT_MD" >> "$SUMMARY_FILE"
fi
if [ -f "$REPORT_PDF" ]; then
    echo "  $REPORT_PDF" >> "$SUMMARY_FILE"
fi
