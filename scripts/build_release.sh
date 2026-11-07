#!/usr/bin/env bash
# ----------------------------------------------------------------------
# build_release.sh — package the Axross public-release tree.
#
# Produces a clean output directory (and optionally a tarball + hashes)
# containing only files safe for public distribution: the committed
# files of HEAD, never untracked or uncommitted ones. In the private
# source repo the tree is the scrubbed public mirror, which
# scripts/export-public.py --mirror writes into a temp dir (its
# MIRROR_EXCLUDE_PREFIXES keep internal notes and tooling out); in the
# public mirror checkout it is `git archive HEAD`. All scrub gates run
# on that staged tree BEFORE anything is written to OUTDIR, so the
# script refuses to produce a contaminated bundle rather than ship one.
#
# The identity terms the gates look for are kept outside the repo:
# $AXROSS_IDENTITY_TERMS_FILE, default
# ${XDG_CONFIG_HOME:-~/.config}/axross/release-identity-terms.
# $AXROSS_RELEASE_LIST, when set, receives the candidate file list.
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
#   3  scrub failure (excluded path / secret / identity string / export refused)
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

REQUIRED_CMDS=(git python3 tar grep sha256sum sha512sum du find sed awk realpath mktemp sort diff)
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

# pyproject declares the version dynamic: tool.setuptools.dynamic reads
# it from axross/_version.py (attr = "axross._version.__version__").
# Resolve it the way setuptools does - a static [project].version if
# there is one, else the attr's module read as source (its AST, nothing
# imported) - so the tarball is named after the version a build gets.
# The snippet between the PY markers is run on its own by
# tests/test_build_release_version.py.
VERSION="$(
    python3 - <<'PY' 2>/dev/null
import ast, pathlib, sys, tomllib
try:
    project = tomllib.loads(pathlib.Path("pyproject.toml").read_text(encoding="utf-8"))
    v = project.get("project", {}).get("version")
    if v is None:
        attr = project["tool"]["setuptools"]["dynamic"]["version"]["attr"]
        module, _, name = attr.rpartition(".")
        source = pathlib.Path(*module.split(".")).with_suffix(".py")
        tree = ast.parse(source.read_text(encoding="utf-8"))
        for node in tree.body:
            targets = node.targets if isinstance(node, ast.Assign) else (
                [node.target] if isinstance(node, ast.AnnAssign) else [])
            if any(isinstance(t, ast.Name) and t.id == name for t in targets):
                v = ast.literal_eval(node.value)
    if not isinstance(v, str) or not v.strip():
        raise ValueError("empty")
    print(v.strip())
except Exception:
    sys.exit(1)
PY
)" || die 2 "no usable version (axross/_version.py __version__, as pyproject.toml's tool.setuptools.dynamic names it) — fix before releasing"

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

# The tree is staged in a private temp dir outside the repo; it goes
# away on every exit. If we fail mid-copy (rare — pre-flight should
# catch everything), also remove a half-populated OUTDIR so a later run
# doesn't mistake it for a valid previous build.
STAGE_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/axross-release-stage.XXXXXX")"
STAGE="$STAGE_ROOT/tree"
cleanup() {
    local rc=$?
    if [ $rc -ne 0 ] && [ $DRY_RUN -eq 0 ] && [ -d "$OUTDIR" ] && [ "${COPY_STARTED:-0}" = "1" ]; then
        warn "failure mid-build (rc=$rc) — removing partial $OUTDIR"
        rm -rf -- "$OUTDIR"
    fi
    rm -rf -- "$STAGE_ROOT"
    exit $rc
}
trap cleanup EXIT

# ==================================================================== #
# 8. Identity terms (read before anything is staged)                   #
# ==================================================================== #

# The terms themselves must not be published, so they live OUTSIDE the
# repository, one per line ('#' comments allowed):
# $AXROSS_IDENTITY_TERMS_FILE, default
# ${XDG_CONFIG_HOME:-~/.config}/axross/release-identity-terms.
# Without it the release refuses (fail closed); a terms file inside the
# work tree is refused too, so it can never be committed and shipped.
TERMS_DEFAULT="${XDG_CONFIG_HOME:-$HOME/.config}/axross/release-identity-terms"
IDENTITY_TERMS_FILE="${AXROSS_IDENTITY_TERMS_FILE:-$TERMS_DEFAULT}"
[ -f "$IDENTITY_TERMS_FILE" ] \
    || die 2 "identity terms file missing: $IDENTITY_TERMS_FILE (default $TERMS_DEFAULT, or set AXROSS_IDENTITY_TERMS_FILE)"
TERMS_REAL="$(realpath -- "$IDENTITY_TERMS_FILE")"
case "$TERMS_REAL" in
    "$REPO_ROOT"/*)
        die 2 "identity terms file is inside the repository ($TERMS_REAL) — move it out, e.g. to $TERMS_DEFAULT" ;;
esac
TERMS_CLEAN="$STAGE_ROOT/identity-terms"
: > "$TERMS_CLEAN"
term_count=0
while IFS= read -r term || [ -n "$term" ]; do
    term="${term%%#*}"
    term="${term#"${term%%[![:space:]]*}"}"
    term="${term%"${term##*[![:space:]]}"}"
    if [ -n "$term" ]; then
        printf '%s\n' "$term" >> "$TERMS_CLEAN"
        term_count=$((term_count + 1))
    fi
done < "$TERMS_REAL"
[ "$term_count" -gt 0 ] || die 2 "identity terms file is empty: $IDENTITY_TERMS_FILE"

# ==================================================================== #
# 9. Stage the public tree                                             #
# ==================================================================== #

# Only committed files of HEAD are packaged — never untracked or
# uncommitted ones (an operator's notes in the work tree stay out).
#
#   * In the private source repo (scripts/export-public.py present) the
#     public tree is what `export-public.py --mirror --apply` writes into
#     the stage: HEAD's tracked files minus its MIRROR_EXCLUDE_PREFIXES,
#     run through the scrub rules and its leak gate. The exclude list is
#     read from that script; this one keeps no copy of it.
#   * In the public mirror checkout (export-public.py is one of the
#     files the mirror leaves out) the tree is `git archive HEAD`.
EXPORT_SCRIPT="$REPO_ROOT/scripts/export-public.py"
EXCLUDES_FILE="$STAGE_ROOT/mirror-exclude-prefixes"
: > "$EXCLUDES_FILE"

log "=== Staging the public tree ==="
if [ -f "$EXPORT_SCRIPT" ]; then
    log "  source: private source repo, scrubbed by scripts/export-public.py --mirror"
    # The exclude list, read as source: nothing of the script is run.
    python3 - "$EXPORT_SCRIPT" > "$EXCLUDES_FILE" <<'PY' \
        || die 2 "cannot read MIRROR_EXCLUDE_PREFIXES from scripts/export-public.py"
import ast, sys
tree = ast.parse(open(sys.argv[1], encoding="utf-8").read())
for node in tree.body:
    if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "MIRROR_EXCLUDE_PREFIXES" for t in node.targets):
        values = ast.literal_eval(node.value)
        if not values or not all(isinstance(v, str) and v and "\n" not in v for v in values):
            sys.exit(1)
        for v in values:
            print(v)
        sys.exit(0)
sys.exit(1)
PY
    log "  excludes: $(wc -l < "$EXCLUDES_FILE") MIRROR_EXCLUDE_PREFIXES entries"
    set +e
    python3 "$EXPORT_SCRIPT" --mirror --apply --target "$STAGE"
    export_rc=$?
    set -e
    case "$export_rc" in
        0) ;;
        3|4|5) die 3 "export-public.py --mirror refused (rc=$export_rc) — see findings above; nothing was written" ;;
        *) die 2 "export-public.py --mirror failed (rc=$export_rc)" ;;
    esac
else
    log "  source: public mirror checkout, git archive HEAD"
    mkdir -p -- "$STAGE"
    git archive --format=tar HEAD | tar --extract --directory="$STAGE"
fi

mapfile -d '' -t FILES < <(cd "$STAGE" && find . \( -type f -o -type l \) -printf '%P\0' | sort -z)

FILE_COUNT=${#FILES[@]}
if [ "$FILE_COUNT" -eq 0 ]; then
    die 2 "the staged tree is empty — nothing committed at HEAD?"
fi
log "  candidates: $FILE_COUNT files"
if [ -n "${AXROSS_RELEASE_LIST:-}" ]; then
    # The candidate list, one path per line (tests and reviewers).
    printf '%s\n' "${FILES[@]}" > "$AXROSS_RELEASE_LIST"
    log "  list:       $AXROSS_RELEASE_LIST"
fi

# ==================================================================== #
# 10. Pre-flight scrub gates                                           #
# ==================================================================== #

log ""
log "=== Pre-flight scrub ==="

scrub_failed=0

# ---- 10a. Mirror-excluded paths ------------------------------------ #
# Belt and braces over export-public.py: no staged path is, or starts
# with, an entry of its MIRROR_EXCLUDE_PREFIXES (its own matching).
# The one exception is .gitignore: the source one is excluded and the
# export writes its curated PUBLIC_GITIGNORE in its place.
if [ -s "$EXCLUDES_FILE" ]; then
    mapfile -t EXCLUDES < "$EXCLUDES_FILE"
    for f in "${FILES[@]}"; do
        [ "$f" = ".gitignore" ] && continue
        for ex in "${EXCLUDES[@]}"; do
            if [ "${f#"$ex"}" != "$f" ]; then
                err "mirror-excluded path in candidate set: $f (matches $ex)"
                scrub_failed=1
            fi
        done
    done
fi

# ---- 10b. Secret-shaped filenames ---------------------------------- #
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

# ---- 10c. Stale identity strings (file content) -------------------- #
# Fixed strings (-F), text files only (-I), every staged file - this
# script included, as the terms are not in it.
if (cd "$STAGE" && grep -rFIHn -f "$TERMS_CLEAN" -- .); then
    err "stale identity string(s) in the staged tree (see lines above)"
    scrub_failed=1
fi

# ---- 10d. Private-key PEM blocks in non-test files ----------------- #
# Test fixtures can legitimately carry crafted key material; anything
# else is almost certainly an accident.
PEM_MARKER='-----BEGIN '
for f in "${FILES[@]}"; do
    case "$f" in
        tests/*|*/tests/*) continue ;;
    esac
    # -Iq: binary skip + quiet; plus explicit pattern for any PEM
    # private-key header variant.
    if grep -IqE -- "${PEM_MARKER}(RSA |OPENSSH |EC |DSA |ENCRYPTED |)PRIVATE KEY-----" "$STAGE/$f" 2>/dev/null; then
        err "PEM private-key block in non-test file: $f"
        scrub_failed=1
    fi
done

if [ "$scrub_failed" -ne 0 ]; then
    die 3 "scrub gate failed — see findings above; nothing was written"
fi

ok "no mirror-excluded paths"
ok "no secret-shaped filenames"
ok "no stale identity strings (scanned $FILE_COUNT files)"
ok "no PEM private-key blocks outside tests/"

# ==================================================================== #
# 10e. Working-tree hygiene (warnings only)                            #
# ==================================================================== #

log ""
log "=== Working tree ==="

if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
    warn "working tree has uncommitted changes — they are NOT packaged (HEAD is)"
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
    | tar --create --null --directory="$STAGE" --files-from=- \
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
if (cd "$OUTDIR" && grep -rFIHn -f "$TERMS_CLEAN" -- . >&2); then
    err "identity string(s) appear in the output tree (see lines above)"
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
    # (The scratch dir lies in STAGE_ROOT, which the EXIT trap removes.)
    REPRO_DIR="$STAGE_ROOT/repro"
    mkdir -p -- "$REPRO_DIR"
    tar --extract --gzip --file "$TARBALL" --directory "$REPRO_DIR"
    if ! diff -rq "$OUTDIR" "$REPRO_DIR/${STEM}" >/dev/null; then
        err "tarball does NOT round-trip to source tree — diff:"
        diff -rq "$OUTDIR" "$REPRO_DIR/${STEM}" >&2 || true
        die 5 "tarball reproducibility failed"
    fi

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

# Clean exit — the EXIT trap only removes the stage.
exit 0
