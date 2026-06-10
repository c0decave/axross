#!/usr/bin/env bash
# ----------------------------------------------------------------------
# build_release.sh — package the Axross public-release tree.
#
# Produces a clean output directory (and optionally a tarball + hashes)
# containing only files safe for public distribution. Internal notes
# (HANDOFF, BACKLOG), dev artefacts (.venv, dist/, build caches) and
# any stale project-identity strings are excluded. All scrub gates run
# BEFORE any file is written, so the script refuses to produce a
# contaminated bundle rather than ship one.
#
# Usage:
#   scripts/build_release.sh                    # default: ../axross-release
#   scripts/build_release.sh /path/to/outdir    # custom outdir
#   scripts/build_release.sh --tarball          # also emit tar.gz + hashes
#   scripts/build_release.sh --force            # wipe outdir without prompt
#   scripts/build_release.sh --dry-run          # checks only; no files written
#
# Exit codes:
#   0  success
#   1  argument error / usage
#   2  environment error (missing tool, not in repo, version missing…)
#   3  scrub failure (deny-listed path / secret / identity string)
#   4  outdir collision without --force
#   5  post-copy sanity check failed
#   6  safety-guard refusal (outdir too close to /, $HOME, $REPO_ROOT)
#
# GNU tools assumed: git, python3, tar (with --null + --transform), grep,
# sha256sum, sha512sum, du. On BSD/macOS systems swap in coreutils first.
# ----------------------------------------------------------------------
set -euo pipefail

# ==================================================================== #
# Helpers                                                              #
# ==================================================================== #

# Timestamped log line. All output goes here; see `exec > >(tee)` below.
log()  { printf '%s %s\n' "[$(date -u +%FT%TZ)]" "$*"; }
ok()   { log "  ✓ $*"; }
warn() { log "  ! $*"; }
err()  { log "  ✗ $*" >&2; }

usage() {
    cat <<'EOF'
Usage: build_release.sh [OPTIONS] [OUTDIR]

Package the Axross public-release tree into OUTDIR.
Default OUTDIR is ../axross-release (sibling of the repo).

Options:
  --force          Wipe OUTDIR if it already exists (with safety guards).
  --tarball        After copy, produce axross-<version>.tar.gz + .sha256 + .sha512.
  --dry-run        Run every check; report what would happen; write nothing.
  -h, --help       Show this help and exit.

Exit codes:
  0 success · 1 usage · 2 env · 3 scrub fail · 4 outdir exists · 5 sanity fail · 6 safety guard
EOF
}

# Die with a message + exit code, without relying on `err` when
# logging isn't set up yet.
die() {
    local code="$1"; shift
    printf '[%s] ERROR: %s\n' "$(date -u +%FT%TZ)" "$*" >&2
    exit "$code"
}

# ==================================================================== #
# 1. Argument parsing                                                  #
# ==================================================================== #

FORCE=0
MAKE_TARBALL=0
DRY_RUN=0
OUTDIR=""

while [ "$#" -gt 0 ]; do
    case "$1" in
        --force)    FORCE=1 ;;
        --tarball)  MAKE_TARBALL=1 ;;
        --dry-run)  DRY_RUN=1 ;;
        -h|--help)  usage; exit 0 ;;
        --)         shift; break ;;
        -*)         usage >&2; die 1 "unknown flag: $1" ;;
        *)
            if [ -n "$OUTDIR" ]; then
                usage >&2; die 1 "OUTDIR already set to $OUTDIR, second positional arg: $1"
            fi
            OUTDIR="$1"
            ;;
    esac
    shift
done

# Any remaining args after `--` are disallowed — tighten the surface.
if [ "$#" -gt 0 ]; then
    usage >&2
    die 1 "unexpected trailing arguments: $*"
fi

# ==================================================================== #
# 2. Tool availability                                                 #
# ==================================================================== #

REQUIRED_CMDS=(git python3 tar grep sha256sum sha512sum du find sed awk realpath)
for cmd in "${REQUIRED_CMDS[@]}"; do
    command -v "$cmd" >/dev/null 2>&1 \
        || die 2 "missing required command: $cmd"
done

# ==================================================================== #
# 3. Locate repo                                                       #
# ==================================================================== #

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || true)"
[ -n "$REPO_ROOT" ] || die 2 "not inside a git repository"
cd "$REPO_ROOT"

# ==================================================================== #
# 4. Resolve version                                                   #
# ==================================================================== #

VERSION="$(
    python3 - <<'PY' 2>/dev/null
import pathlib, sys, tomllib
try:
    d = tomllib.loads(pathlib.Path("pyproject.toml").read_text())
    v = d["project"]["version"]
    if not isinstance(v, str) or not v.strip():
        raise ValueError("empty")
    print(v.strip())
except Exception:
    sys.exit(1)
PY
)" || die 2 "pyproject.toml has no usable [project].version — fix before releasing"

GIT_SHA="$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")"
GIT_BRANCH="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")"

# ==================================================================== #
# 5. Resolve + guard OUTDIR                                            #
# ==================================================================== #

if [ -z "$OUTDIR" ]; then
    OUTDIR="$REPO_ROOT/../axross-release"
fi

# Normalise to a canonical absolute path BEFORE safety checks.
# ``realpath -m`` resolves .. and collapses // even for paths that
# don't exist yet. Without this, OUTDIR=/ would normalise to "//" via
# dirname/basename and bypass the equality check below.
OUTDIR="$(realpath -m -- "$OUTDIR")"

OUTDIR_PARENT="$(dirname -- "$OUTDIR")"
[ -d "$OUTDIR_PARENT" ] || die 2 "parent directory does not exist: $OUTDIR_PARENT"

# Safety guards — an accidental typo with --force could otherwise
# destroy the user's home or the repo itself. Compare absolute paths.
for forbidden in "/" "$HOME" "$REPO_ROOT" "$(dirname "$REPO_ROOT")"; do
    # Trim trailing slashes to compare cleanly.
    trimmed="${forbidden%/}"
    [ -n "$trimmed" ] || trimmed="/"
    if [ "$OUTDIR" = "$trimmed" ]; then
        die 6 "refusing to use OUTDIR=$OUTDIR — it equals $trimmed"
    fi
done

# ==================================================================== #
# 6. Set up logging                                                    #
# ==================================================================== #

LOGFILE="${OUTDIR}.build.log"
# Truncate prior log; keep one copy.
: > "$LOGFILE"

# Tee stdout+stderr through the logfile so the whole run is captured
# — including crashes that happen after this point.
exec > >(tee -a "$LOGFILE") 2>&1

log "=== Axross release build ==="
log "repo:      $REPO_ROOT"
log "outdir:    $OUTDIR"
log "logfile:   $LOGFILE"
log "version:   $VERSION"
log "git-sha:   $GIT_SHA"
log "git-branch:$GIT_BRANCH"
log "mode:      $([ $DRY_RUN -eq 1 ] && echo DRY-RUN || echo LIVE)"
log ""

# ==================================================================== #
# 7. Trap for clean exit state                                         #
# ==================================================================== #

# If we fail mid-copy (rare — pre-flight should catch everything),
# remove a half-populated OUTDIR so a subsequent run doesn't mistake
# it for a valid previous build.
cleanup_on_fail() {
    local rc=$?
    # Only act on failure, not on a clean exit 0.
    if [ $rc -ne 0 ] && [ $DRY_RUN -eq 0 ] && [ -d "$OUTDIR" ] && [ "${COPY_STARTED:-0}" = "1" ]; then
        warn "failure mid-build (rc=$rc) — removing partial $OUTDIR"
        rm -rf -- "$OUTDIR"
    fi
    exit $rc
}
trap cleanup_on_fail EXIT

# ==================================================================== #
# 8. Build candidate file list                                         #
# ==================================================================== #

log "=== Collecting file list ==="

# -c = cached (committed to index), -o = other (untracked),
# --exclude-standard honours .gitignore, -z emits NUL-terminated paths
# (so filenames with newlines/whitespace survive a cross-tool pipeline).
# Filter to paths that actually exist in the working tree — a staged
# deletion (git rm --cached without commit) otherwise lingers in -c
# output and would be fed to tar as a missing file.
mapfile -d '' -t FILES < <(
    git ls-files -z -co --exclude-standard \
        | while IFS= read -r -d '' f; do
              if [ -f "$f" ] || [ -L "$f" ]; then
                  printf '%s\0' "$f"
              fi
          done
)

FILE_COUNT=${#FILES[@]}
if [ "$FILE_COUNT" -eq 0 ]; then
    die 2 "git ls-files returned no candidate files — wrong working directory?"
fi
log "  candidates: $FILE_COUNT files"

# ==================================================================== #
# 9. Pre-flight scrub gates                                            #
# ==================================================================== #

log ""
log "=== Pre-flight scrub ==="

# The release-script itself references the identity terms in its
# scrub patterns below. Skip it in content scans so it doesn't match
# itself and create a false positive.
SELF_REL="scripts/build_release.sh"

# ---- 9a. Deny-listed path prefixes --------------------------------- #
# Literal string match, not regex. A path is denied if it EQUALS a
# deny entry or starts with "<deny>/".
DENY_PATHS=(
    "docs/HANDOFF.md"
    "docs/BACKLOG.md"
    ".claude"
    ".vscode"
    ".idea"
    "security/reports"
    "security/scanner_reports"
)

scrub_failed=0

for f in "${FILES[@]}"; do
    for deny in "${DENY_PATHS[@]}"; do
        if [ "$f" = "$deny" ] || [ "${f#"$deny"/}" != "$f" ]; then
            err "deny-listed path in candidate set: $f (matches $deny)"
            scrub_failed=1
        fi
    done
done

# ---- 9b. Secret-shaped filenames ----------------------------------- #
# Match on basename so directory names don't false-positive.
SECRET_BASENAME_GLOBS=(
    "*_token.json"
    "*.pem"
    "*.key"
    ".env"
    ".env.local"
    "credentials.json"
    "secrets.yaml"
    "id_rsa"
    "id_ed25519"
    "id_ecdsa"
    "*.p12"
    "*.pfx"
)

for f in "${FILES[@]}"; do
    base="$(basename -- "$f")"
    for pat in "${SECRET_BASENAME_GLOBS[@]}"; do
        # shellcheck disable=SC2053 — glob comparison is intentional
        if [[ "$base" == $pat ]]; then
            err "secret-shaped filename: $f (matches $pat)"
            scrub_failed=1
        fi
    done
done

# ---- 9c. Stale identity strings (file content) --------------------- #
# Fixed-string search (-F) so we don't accidentally match more than
# we mean. The scrub list is what the user asked to keep out of
# public artefacts.
IDENTITY_TERMS=(
    "mantodea"
    "mtdmarco"
    "marco"  # username prefix scrub target; constructed at scan-time
)

for f in "${FILES[@]}"; do
    # Don't scan binary files (grep -I) and skip the release script
    # itself (which lists these terms as scrub targets).
    [ "$f" = "$SELF_REL" ] && continue
    for term in "${IDENTITY_TERMS[@]}"; do
        if grep -FIHn -- "$term" "$f" 2>/dev/null; then
            err "stale identity string '$term' found in $f (see line above)"
            scrub_failed=1
        fi
    done
done

# ---- 9d. Private-key PEM blocks in non-test files ------------------ #
# Test fixtures can legitimately carry crafted key material; anything
# else is almost certainly an accident.
PEM_MARKER='-----BEGIN '
for f in "${FILES[@]}"; do
    [ "$f" = "$SELF_REL" ] && continue
    case "$f" in
        tests/*|*/tests/*) continue ;;
    esac
    # -Iq: binary skip + quiet; plus explicit pattern for any PEM
    # private-key header variant.
    if grep -IqE -- "${PEM_MARKER}(RSA |OPENSSH |EC |DSA |ENCRYPTED |)PRIVATE KEY-----" "$f" 2>/dev/null; then
        err "PEM private-key block in non-test file: $f"
        scrub_failed=1
    fi
done

if [ "$scrub_failed" -ne 0 ]; then
    die 3 "scrub gate failed — see findings above; nothing was written"
fi

ok "no deny-listed paths"
ok "no secret-shaped filenames"
ok "no stale identity strings (scanned $FILE_COUNT files)"
ok "no PEM private-key blocks outside tests/"

# ==================================================================== #
# 10. Working-tree hygiene (warnings only)                             #
# ==================================================================== #

log ""
log "=== Working tree ==="

if [ -n "$(git status --porcelain)" ]; then
    warn "working tree has uncommitted changes — bundling current state anyway"
    warn "(commit first if you want a reproducible release tag)"
else
    ok "working tree clean"
fi

if [ "$GIT_BRANCH" != "main" ]; then
    warn "on branch '$GIT_BRANCH' (not main) — continuing"
else
    ok "on main"
fi

# ==================================================================== #
# 11. Dry-run short-circuit                                            #
# ==================================================================== #

if [ "$DRY_RUN" -eq 1 ]; then
    log ""
    log "=== Dry run complete ==="
    ok "all gates passed; no files written"
    log "  would copy:  $FILE_COUNT files"
    log "  would write: $OUTDIR"
    [ "$MAKE_TARBALL" -eq 1 ] && log "  would pack:  $(dirname "$OUTDIR")/axross-${VERSION}.tar.gz"
    trap - EXIT
    exit 0
fi

# ==================================================================== #
# 12. Handle existing outdir                                           #
# ==================================================================== #

log ""
log "=== Output directory ==="

if [ -e "$OUTDIR" ]; then
    if [ "$FORCE" -eq 1 ]; then
        warn "removing existing $OUTDIR (--force)"
        rm -rf -- "$OUTDIR"
    else
        die 4 "output dir already exists: $OUTDIR (re-run with --force to wipe)"
    fi
fi

mkdir -p -- "$OUTDIR"
ok "created $OUTDIR"

# ==================================================================== #
# 13. Copy files                                                       #
# ==================================================================== #

log ""
log "=== Copying $FILE_COUNT files ==="
COPY_STARTED=1

# Feed the NUL-terminated list to a single tar | tar pipeline so
# permissions + symlinks + sparse regions round-trip cleanly.
# --null / --files-from=- reads NUL-separated filenames.
printf '%s\0' "${FILES[@]}" \
    | tar --create --null --files-from=- \
          --owner=0 --group=0 --numeric-owner \
    | tar --extract --directory="$OUTDIR"

ok "copy complete"

# ==================================================================== #
# 14. Post-copy sanity                                                 #
# ==================================================================== #

log ""
log "=== Post-copy sanity ==="

# 14a — no .git leaked.
if [ -d "$OUTDIR/.git" ]; then
    die 5 "$OUTDIR/.git exists (should never be copied)"
fi
ok "no .git in output"

# 14b — size cap. A source-release tree for axross is a few MB;
# anything over 50 MB means a binary almost certainly slipped through
# .gitignore. Use `du -sk` (POSIX) instead of the GNU-only `du -sb`.
SIZE_KB="$(du -sk -- "$OUTDIR" | awk '{print $1}')"
SIZE_HUMAN="$(du -sh -- "$OUTDIR" | awk '{print $1}')"
SIZE_CAP_KB=$((50 * 1024))
if [ "$SIZE_KB" -gt "$SIZE_CAP_KB" ]; then
    err "output tree is $SIZE_HUMAN (cap $((SIZE_CAP_KB / 1024)) MB) — top offenders:"
    du -sh -- "$OUTDIR"/* 2>/dev/null | sort -h | tail -10 >&2 || true
    die 5 "size cap exceeded"
fi
ok "size: $SIZE_HUMAN (within $((SIZE_CAP_KB / 1024)) MB cap)"

# 14c — re-scan output tree for identity terms as belt-and-braces.
out_hit=0
for term in "${IDENTITY_TERMS[@]}"; do
    # Exclude the release script itself (same rationale as pre-flight).
    if find "$OUTDIR" -type f \
        ! -path "*/scripts/build_release.sh" \
        -exec grep -FIln -- "$term" {} + 2>/dev/null | head -1 | grep -q .; then
        err "identity string '$term' appears in output tree:"
        find "$OUTDIR" -type f ! -path "*/scripts/build_release.sh" \
            -exec grep -FIHn -- "$term" {} + 2>/dev/null >&2 || true
        out_hit=1
    fi
done
if [ "$out_hit" -ne 0 ]; then
    die 5 "post-copy identity scan failed"
fi
ok "identity re-scan clean"

# 14d — required files present. If any of these are missing, the
# release is broken even if it passes the scrub.
REQUIRED=(
    "LICENSE"
    "NOTICE"
    "THIRD_PARTY_LICENSES.md"
    "README.md"
    "README_de.md"
    "README_es.md"
    "CONTRIBUTING.md"
    "SECURITY.md"
    "INSTALL.md"
    "OAUTH_SETUP.md"
    "pyproject.toml"
    "main.py"
    "core/__init__.py"
    "core/client_identity.py"
    "docs/USAGE.md"
    "docs/USAGE_de.md"
    "docs/USAGE_es.md"
    "docs/DEVELOPMENT.md"
    "docs/OPSEC.md"
)
missing=0
for f in "${REQUIRED[@]}"; do
    if [ ! -f "$OUTDIR/$f" ]; then
        err "required file missing from release: $f"
        missing=1
    fi
done
[ "$missing" -eq 0 ] || die 5 "required-files check failed"
ok "required files present (${#REQUIRED[@]} checked)"

# 14e — drop a provenance stamp inside the bundle so a reviewer can
# tell which commit it was built from, on which branch, when. Not
# secret-sensitive. Intentionally NOT part of the scrub (we want to
# tell users what they're getting).
cat > "$OUTDIR/.release-info" <<EOF
# Axross release provenance
version:   $VERSION
git-sha:   $GIT_SHA
git-branch:$GIT_BRANCH
built-at:  $(date -u +%FT%TZ)
files:     $FILE_COUNT
size-kb:   $SIZE_KB
EOF
ok "wrote $OUTDIR/.release-info"

# ==================================================================== #
# 15. Optional tarball                                                 #
# ==================================================================== #

if [ "$MAKE_TARBALL" -eq 1 ]; then
    log ""
    log "=== Tarball ==="
    PARENT="$(dirname -- "$OUTDIR")"
    BASE="$(basename -- "$OUTDIR")"
    STEM="axross-${VERSION}"
    TARBALL="${PARENT}/${STEM}.tar.gz"

    # Rename the top-level dir inside the tar so the extracted tree
    # is axross-<version>/ regardless of what the user called OUTDIR.
    tar --create --gzip \
        --owner=0 --group=0 --numeric-owner \
        --transform "s|^${BASE}|${STEM}|" \
        --file "$TARBALL" \
        --directory "$PARENT" \
        "$BASE"

    (cd "$PARENT" && sha256sum -- "${STEM}.tar.gz" > "${STEM}.tar.gz.sha256")
    (cd "$PARENT" && sha512sum -- "${STEM}.tar.gz" > "${STEM}.tar.gz.sha512")

    # Reproducibility check: unpack the tarball to a scratch dir and
    # diff against the source tree. Catches any tar quirk that would
    # otherwise be found by the first user to download.
    REPRO_DIR="$(mktemp -d)"
    trap 'rm -rf -- "$REPRO_DIR"' RETURN
    tar --extract --gzip --file "$TARBALL" --directory "$REPRO_DIR"
    if ! diff -rq "$OUTDIR" "$REPRO_DIR/${STEM}" >/dev/null; then
        err "tarball does NOT round-trip to source tree — diff:"
        diff -rq "$OUTDIR" "$REPRO_DIR/${STEM}" >&2 || true
        rm -rf -- "$REPRO_DIR"
        die 5 "tarball reproducibility failed"
    fi
    rm -rf -- "$REPRO_DIR"
    trap - RETURN

    TAR_SIZE="$(du -h -- "$TARBALL" | awk '{print $1}')"
    ok "$TARBALL ($TAR_SIZE)"
    ok "${TARBALL}.sha256"
    ok "${TARBALL}.sha512"
    ok "tarball round-trips cleanly against source tree"
fi

# ==================================================================== #
# 16. Done                                                             #
# ==================================================================== #

log ""
log "=== Release bundle ready ==="
log "  dir:     $OUTDIR"
log "  log:     $LOGFILE"
log "  files:   $FILE_COUNT"
log "  size:    $SIZE_HUMAN"
log "  version: $VERSION (git $GIT_SHA on $GIT_BRANCH)"
[ "$MAKE_TARBALL" -eq 1 ] && log "  tarball: $(dirname -- "$OUTDIR")/axross-${VERSION}.tar.gz"
log ""
log "Upload the contents (or the tarball) to github.com/c0decave/axross."

# Clean exit — disarm the EXIT trap so it doesn't think we failed.
trap - EXIT
exit 0
