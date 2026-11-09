#!/usr/bin/env bash
# Build every release artifact from a clean `git archive` of HEAD, without
# Docker, root or a package manager (the sandbox, a CI runner, a laptop):
#
#   dist/<version>/axross-<version>.tar.gz, axross-<version>-py3-none-any.whl
#       PyPI (PyPA build, isolated)
#   dist/<version>/glibc-2.34/axross-{base,slim,full}   AlmaLinux 9 libraries: glibc 2.34+
#   dist/<version>/glibc-2.36/axross-{base,slim,full}   Debian 12 libraries:  glibc 2.36+
#       GitHub release binaries (scripts/build_bundle.sh, PyInstaller)
#   dist/<version>/packs/   the units an axross-base adds (core.packs): the
#       locked wheels and packs-<version>.json (scripts/build_packs.py)
#   dist/<version>/glibc-2.3x/axross-{media-player,system-info}   axross's tools as
#       programs of their own; dist/<version>/standalone/ their sdists and wheels
#       (scripts/export_standalone.py)
#   SHA256SUMS in each folder, BUILD-INFO.md
#
# Usage:
#   scripts/build_dist.sh [--out DIR] [--work DIR] [--only wheel|bundles|standalone]
#                         [--variants almalinux9,debian12] [--flavors slim,full]
#                         [--standalone media-player,system-info|none]
#   scripts/build_dist.sh --lock-tools   # refresh build/requirements-dist-tools.txt
#
# What it needs: git, curl, gpgv and dpkg-deb (Debian-based machine), uv
# (fetches CPython 3.12.8 from python-build-standalone, hash-checked by uv),
# and the network to pypi.org/files.pythonhosted.org, github.com,
# deb.debian.org, security.debian.org and repo.almalinux.org.
#
# How a variant is built: scripts/sysroot_fetch.py unpacks the target
# system's packages (build/sysroot/<system>.txt, signatures and hashes
# checked); PyInstaller then runs with only those libraries on the library
# path (glibc itself excepted: the running loader's), so it bundles the
# target's libraries; AXROSS_TARGET_ROOT makes the symbol-version gate
# (scripts/elf_needs.py) check against the target's glibc and libstdc++.
# The Python packages come from build/requirements-bundle.txt, the build's own
# tools (PyPA build, setuptools, wheel, zstandard) from
# build/requirements-dist-tools.txt, both with --require-hashes; sdist and
# wheel are built without isolation, so no unhashed backend is fetched.
# Not signed: scripts/sign_release.py needs the key.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PYTHON_VERSION=3.12.8

OUT=""
# on disk, not /tmp: /tmp is often a tmpfs, and its files are memory - the venv,
# the sysroot and PyInstaller's scratch together are more than a sandbox's or a
# CI runner's memory limit (an 8 GiB sandbox was killed by it in the full build)
WORK="$PROJECT_ROOT/build/dist-work"
ONLY=""
VARIANTS="almalinux9,debian12"
FLAVORS="base,slim,full"
STANDALONE="media-player,system-info"
while (( $# )); do
    case "$1" in
        --out) OUT="$2"; shift 2 ;;
        --work) WORK="$2"; shift 2 ;;
        --only) ONLY="$2"; shift 2 ;;
        --variants) VARIANTS="$2"; shift 2 ;;
        --flavors) FLAVORS="$2"; shift 2 ;;
        --standalone) STANDALONE="$2"; shift 2 ;;
        --lock-tools)
            cd "$PROJECT_ROOT"
            # releases at least 14 days old, as the supply-chain gate requires
            UV_NO_CONFIG=1 uv pip compile build/requirements-dist-tools.in --python-version 3.12 \
                --exclude-newer "$(date -u -d '-14 days' +%Y-%m-%dT%H:%M:%SZ)" \
                --universal --generate-hashes --index-url https://pypi.org/simple \
                --custom-compile-command "scripts/build_dist.sh --lock-tools" --quiet \
                --output-file build/requirements-dist-tools.txt
            exit 0 ;;
        -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

[[ "$STANDALONE" == "none" ]] && STANDALONE=""
# only the tools: no axross wheel, bundles or packs
[[ "$ONLY" == "standalone" ]] && FLAVORS=""
cd "$PROJECT_ROOT"
# the version of what is built: HEAD's, not the working tree's
VERSION=$(git show HEAD:axross/_version.py | python3 -c 'import re,sys; print(re.search(r"__version__ = \"([^\"]+)\"", sys.stdin.read()).group(1))')
COMMIT=$(git rev-parse --short=8 HEAD)
OUT="${OUT:-$PROJECT_ROOT/dist/$VERSION}"
if ! git diff --quiet HEAD -- . ':!dist'; then
    echo "note: the working tree has changes; the artifacts are built from HEAD ($COMMIT)"
fi
mkdir -p "$WORK/tmp" "$OUT"
WORK="$(cd "$WORK" && pwd)"
# PyInstaller's scratch (build_bundle.sh), uv, pip and the onefile smoke test's
# unpacking: on the work folder's disk too
export TMPDIR="$WORK/tmp"
OUT="$(cd "$OUT" && pwd)"

echo ">>> axross $VERSION from $COMMIT -> $OUT (work: $WORK)"
SRC="$WORK/src"
rm -rf "$SRC"
mkdir -p "$SRC"
git archive HEAD | tar -x -C "$SRC"

# -- the supply-chain gate (security/supply_chain_gate.py): mandatory, no switch ----------
# Every pin of every lock this build installs from is checked against PyPI,
# OSV (advisories and malicious packages), its minimum age, its provenance,
# the typosquatting list and the reviewed baseline committed with HEAD -
# before anything is installed. Then the vetted scanners (GuardDog's and
# axross's YARA rules, Sigstore verification of the attestations) run over
# every archive; the venvs are checked after installing, the system
# packages of each variant after fetching. Any problem stops the build.
export AXROSS_SUPPLY_CHAIN_CACHE="$WORK/supply-chain-cache"
# Run inside the HEAD export: the gate reads ./supply-chain-gate.toml of the
# folder it runs in, and an untracked one in the working tree must not point
# it at other locks or another baseline.
gate() { (cd "$SRC" && python3 -I "$SRC/security/supply_chain_gate.py" "$@"); }
# Every pip install below reads these: each lock cut down to the archives the
# gate inspected, so pip cannot take a sibling wheel of a release (a more
# specific platform tag) that was never looked at.
RL="$WORK/reviewed-locks"
rm -rf "$RL"
echo ">>> supply-chain gate: dependencies (standard-library stage)"
gate check --report "$WORK/gate-stdlib" --reduced-locks "$RL" \
    || { echo "supply-chain gate FAILED - no dist is built" >&2; exit 1; }

# -- Python: CPython $PYTHON_VERSION with libpython, the hash-pinned packages -----------
export UV_PYTHON_INSTALL_DIR="$WORK/python" UV_PYTHON_BIN_DIR="$WORK/python/bin"
export PIP_DISABLE_PIP_VERSION_CHECK=1
uv python install "$PYTHON_VERSION" >/dev/null
PY="$(uv python find "$PYTHON_VERSION")"
VENV="$WORK/venv"
# a venv is reused only for the very same lock files
fresh_venv() {  # fresh_venv DIR REQUIREMENTS...
    local dir="$1"; shift
    local key; key=$(cat "$@" | sha256sum | cut -d' ' -f1)
    if [[ -x "$dir/bin/python" && "$(cat "$dir/.requirements-sha256" 2>/dev/null)" == "$key" ]]; then
        return
    fi
    rm -rf "$dir"
    "$PY" -m venv "$dir"
    for req in "$@"; do
        "$dir/bin/pip" install -q --require-hashes -r "$req"
    done
    echo "$key" > "$dir/.requirements-sha256"
}
# the gate's scanners in a venv of their own, from their vetted, hashed lock
SVENV="$WORK/scan-venv"
rm -rf "$SVENV"
"$PY" -m venv "$SVENV"
"$SVENV/bin/pip" install -q --require-hashes --only-binary=:all: -r "$RL/requirements-scan-tools.txt"
gate verify-env --python "$SVENV/bin/python" --lock "$SRC/build/requirements-scan-tools.txt" \
    || { echo "supply-chain gate: the scanner venv is not what was locked" >&2; exit 1; }
echo ">>> supply-chain gate: scanners (YARA: GuardDog + axross rules, attestations)"
gate check --scan-python "$SVENV/bin/python" --report "$OUT" \
    || { echo "supply-chain gate FAILED - no dist is built (report: $OUT/SUPPLY-CHAIN.md)" >&2; exit 1; }

fresh_venv "$VENV" "$RL/requirements-bootstrap.txt" "$RL/requirements-bundle.txt"
gate verify-env --python "$VENV/bin/python" --lock "$SRC/build/requirements-bootstrap.txt" \
    --lock "$SRC/build/requirements-bundle.txt" \
    || { echo "supply-chain gate: the bundle venv is not what was locked" >&2; exit 1; }

# the tools of the build itself (PyPA build, setuptools, wheel, zstandard), hash-pinned
BVENV="$WORK/build-venv"
fresh_venv "$BVENV" "$RL/requirements-bootstrap.txt" "$RL/requirements-dist-tools.txt"
gate verify-env --python "$BVENV/bin/python" --lock "$SRC/build/requirements-bootstrap.txt" \
    --lock "$SRC/build/requirements-dist-tools.txt" \
    || { echo "supply-chain gate: the build-tools venv is not what was locked" >&2; exit 1; }
BUILD_VERSION=$("$BVENV/bin/python" -c 'import importlib.metadata as m; print(m.version("build"))')

# -- PyPI: sdist and wheel ----------------------------------------------------------------
if [[ "$ONLY" != "bundles" && "$ONLY" != "standalone" ]]; then
    echo ">>> sdist and wheel (build $BUILD_VERSION, against the pinned setuptools)"
    rm -f "$OUT"/axross-"$VERSION".tar.gz "$OUT"/axross-"$VERSION"-py3-none-any.whl
    (cd "$SRC" && "$BVENV/bin/python" -m build --no-isolation --outdir "$OUT" . >"$WORK/build-wheel.log" 2>&1) \
        || { tail -30 "$WORK/build-wheel.log"; exit 1; }
    (cd "$OUT" && sha256sum axross-"$VERSION".tar.gz axross-"$VERSION"-py3-none-any.whl > SHA256SUMS)
fi

# -- the tools as programs of their own: sdist and wheel ------------------------------------
IFS=, read -r -a STANDALONE_LIST <<<"$STANDALONE"
if [[ "$ONLY" != "bundles" && ${#STANDALONE_LIST[@]} -gt 0 ]]; then
    mkdir -p "$OUT/standalone"
    for app in "${STANDALONE_LIST[@]}"; do
        echo ">>> axross-$app: sdist and wheel"
        rm -rf "$WORK/standalone-src/$app"
        "$PY" -I "$SRC/scripts/export_standalone.py" "$app" "$WORK/standalone-src/$app"
        (cd "$WORK/standalone-src/$app" && "$BVENV/bin/python" -m build --no-isolation \
            --outdir "$OUT/standalone" . >"$WORK/build-$app.log" 2>&1) \
            || { tail -30 "$WORK/build-$app.log"; exit 1; }
    done
    (cd "$OUT/standalone" && sha256sum ./*.tar.gz ./*.whl | sed 's| \./| |' > SHA256SUMS)
fi

# -- GitHub: the bundles, one per glibc variant and flavour --------------------------------
glibc_of() { case "$1" in almalinux9) echo 2.34 ;; debian12) echo 2.36 ;; *) return 1 ;; esac; }
lib_dirs_of() {
    case "$1" in
        almalinux9) echo "usr/lib64 lib64" ;;
        debian12) echo "usr/lib/x86_64-linux-gnu lib/x86_64-linux-gnu" ;;
    esac
}
# glibc stays the running loader's: its libraries never come from the target root
GLIBC_RE='^(ld-linux.*|libc|libm|libmvec|libpthread|libdl|librt|libresolv|libutil|libanl|libnsl|libnss_[a-z]+|libBrokenLocale|libthread_db|libc_malloc_debug|libmemusage|libpcprofile|libSegFault)\.so'

# PyInstaller with its bootloader compiled here, from the hash-pinned sdist the
# supply-chain gate reviewed (security/build_from_source.txt): no prebuilt
# native starter from PyPI goes into a bundle. zig is the C compiler (glibc
# 2.34 as the floor, as the oldest variant), strip the target's own binutils.
# Once per build, inside the first variant (it needs that variant's strip).
build_bootloader() {
    [[ -n "${BOOTLOADER_SHA256:-}" ]] && return
    local pin sha sdist="" dir f tool
    pin=$(awk '/^pyinstaller==/{f=1} f{print} f&&!/\\$/{exit}' "$SRC/build/requirements-bundle.txt")
    for sha in $(grep -oE 'sha256:[0-9a-f]{64}' <<<"$pin" | cut -d: -f2); do
        for f in "$AXROSS_SUPPLY_CHAIN_CACHE/${sha:0:2}/$sha"/pyinstaller-*.tar.gz; do
            [[ -f "$f" ]] && sdist="$f"
        done
    done
    [[ -n "$sdist" ]] || { echo "the gate did not fetch PyInstaller's sdist" >&2; exit 1; }
    [[ "$(sha256sum "$sdist" | cut -d' ' -f1)" == "$(basename "$(dirname "$sdist")")" ]] \
        || { echo "PyInstaller's sdist is not the locked file" >&2; exit 1; }
    dir="$WORK/pyinstaller-src"
    rm -rf "$dir" "$WORK/pyinstaller-wheel" "$WORK/zigbin"
    mkdir -p "$dir" "$WORK/pyinstaller-wheel" "$WORK/zigbin"
    tar -xzf "$sdist" -C "$dir" --strip-components=1
    {
        echo '#!/bin/sh'
        echo '# zig cc as clang for waf; the glibc floor in the target, except for the'
        echo '# preprocessor-only calls (-E), where zig does not take it'
        echo 'target=x86_64-linux-gnu.2.34'
        echo 'for a in "$@"; do [ "$a" = "-E" ] && target=x86_64-linux-gnu; done'
        printf 'exec "%s" -m ziglang cc -target "$target" "$@"\n' "$BVENV/bin/python"
    } > "$WORK/zigbin/clang"
    for tool in ar ranlib; do
        printf '#!/bin/sh\nexec "%s" -m ziglang %s "$@"\n' "$BVENV/bin/python" "$tool" > "$WORK/zigbin/$tool"
    done
    chmod +x "$WORK/zigbin"/*
    echo ">>> PyInstaller bootloader from $(basename "$sdist") (zig cc, glibc 2.34)"
    (cd "$dir" && env PATH="$WORK/zigbin:$SYSROOT/bin:$PATH" LD_LIBRARY_PATH="$LIBS" CC=clang AR=ar \
        PYINSTALLER_COMPILE_BOOTLOADER=1 PYINSTALLER_BOOTLOADER_WAF_ARGS="--static-zlib --target-arch=64bit" \
        "$BVENV/bin/python" -m build --wheel --no-isolation --outdir "$WORK/pyinstaller-wheel" . \
        >"$WORK/bootloader.log" 2>&1) || { tail -30 "$WORK/bootloader.log"; exit 1; }
    "$VENV/bin/pip" install -q --no-deps --force-reinstall "$WORK/pyinstaller-wheel"/pyinstaller-*.whl
    gate verify-env --python "$VENV/bin/python" --lock "$SRC/build/requirements-bootstrap.txt" \
        --lock "$SRC/build/requirements-bundle.txt" \
        || { echo "supply-chain gate: the bundle venv is not what was locked" >&2; exit 1; }
    BOOTLOADER_SHA256=$("$VENV/bin/python" -I -c 'import PyInstaller, pathlib, hashlib; p = pathlib.Path(PyInstaller.__file__).parent / "bootloader" / "Linux-64bit-intel" / "run"; print(hashlib.sha256(p.read_bytes()).hexdigest())')
    echo "    bootloader run: sha256 $BOOTLOADER_SHA256"
}

if [[ "$ONLY" != "wheel" ]]; then
    # libpython is python-build-standalone's, and so are the libraries linked
    # into it (OpenSSL, libffi, SQLite, ...): their licence texts come from the
    # full archive of the same build, hash-pinned in build/python-standalone.txt;
    # scripts/bundle_licenses.py puts them into licenses/system/python/
    echo ">>> python-build-standalone licence texts (build/python-standalone.txt)"
    "$BVENV/bin/python" -I "$SRC/scripts/python_licences.py" "$SRC/build/python-standalone.txt" \
        "$WORK/python-licences" --python "$PY" \
        || { echo "the python-build-standalone licence texts could not be fetched" >&2; exit 1; }
    export AXROSS_PYTHON_LICENSES="$WORK/python-licences"
    IFS=, read -r -a VARIANT_LIST <<<"$VARIANTS"
    IFS=, read -r -a FLAVOR_LIST <<<"$FLAVORS"
    for variant in "${VARIANT_LIST[@]}"; do
        glibc=$(glibc_of "$variant") || { echo "unknown variant $variant" >&2; exit 2; }
        SYSROOT="$WORK/sysroot-$variant"
        echo ">>> $variant: fetching and checking its packages"
        "$BVENV/bin/python" -I "$SRC/scripts/sysroot_fetch.py" "$variant" "$SYSROOT" \
            --list "$SRC/build/sysroot/$variant.txt"
        echo ">>> supply-chain gate: $variant system packages"
        gate check-system "$SYSROOT/PACKAGES.json" | tee "$WORK/gate-system-$variant.txt" \
            || { echo "supply-chain gate FAILED for the $variant packages - no dist is built" >&2; exit 1; }
        LIBS="$SYSROOT/libs"
        rm -rf "$LIBS" "$SYSROOT/bin"
        mkdir -p "$LIBS" "$SYSROOT/bin"
        for d in $(lib_dirs_of "$variant"); do
            [[ -d "$SYSROOT/root/$d" ]] || continue
            for f in "$SYSROOT/root/$d"/*.so*; do
                name=$(basename "$f")
                [[ -e "$LIBS/$name" || -L "$LIBS/$name" ]] && continue
                [[ "$name" =~ $GLIBC_RE ]] && continue
                ln -s "$f" "$LIBS/$name"
            done
        done
        # PyInstaller's binutils (objdump: is it an ELF file; objcopy: the archive
        # into the binary; strip, readelf): the target's own
        for tool in objdump objcopy strip readelf; do
            real=""
            for candidate in "$SYSROOT/root/usr/bin/$tool" "$SYSROOT/root/usr/bin/x86_64-linux-gnu-$tool"; do
                if [[ -e "$candidate" ]]; then real="$candidate"; break; fi
            done
            [[ -n "$real" ]] || { echo "$variant: no $tool in its packages" >&2; exit 1; }
            ln -s "$real" "$SYSROOT/bin/$tool"
        done
        # ldd and ldconfig as on the target: the loader also searches this machine's
        # own library folders, and PyInstaller would bundle what it finds there
        # (GTK, cairo of the build machine, needing a newer glibc). Only the
        # target's libraries, ours (Python, the venv) and glibc's count; the rest is
        # "not found", as it would be on the target system itself.
        cp "$SRC/scripts/target_ldd.py" "$SYSROOT/bin/target_ldd.py"
        printf '#!/bin/bash\nexec %q -I %q ldd "$@"\n' "$PY" "$SYSROOT/bin/target_ldd.py" > "$SYSROOT/bin/ldd"
        printf '#!/bin/bash\nexec %q -I %q ldconfig "$@"\n' "$PY" "$SYSROOT/bin/target_ldd.py" > "$SYSROOT/bin/ldconfig"
        chmod +x "$SYSROOT/bin/ldd" "$SYSROOT/bin/ldconfig"
        dest="$OUT/glibc-$glibc"
        mkdir -p "$dest"
        cp "$SYSROOT/PACKAGES.txt" "$dest/BUILD-PACKAGES-$variant.txt"
        # fusepy looks for libfuse at import with /sbin/ldconfig (this machine's):
        # point it at the target's
        FUSE_LIB=""
        for candidate in "$LIBS"/libfuse.so.2*; do
            if [[ -e "$candidate" ]]; then FUSE_LIB="$candidate"; break; fi
        done
        build_bootloader
        for flavor in "${FLAVOR_LIST[@]}"; do
            echo ">>> $variant: axross-$flavor"
            rm -f "$SRC/dist/axross-$flavor"
            (cd "$SRC" && env PATH="$VENV/bin:$SYSROOT/bin:$PATH" AXROSS_PYTHON="$VENV/bin/python" \
                LD_LIBRARY_PATH="$LIBS" AXROSS_TARGET_ROOT="$SYSROOT/root" \
                AXROSS_TARGET_LIBS="$LIBS" AXROSS_TARGET_KEEP="$WORK/" AXROSS_GLIBC_RE="$GLIBC_RE" \
                FUSE_LIBRARY_PATH="$FUSE_LIB" AXROSS_BUNDLE_VARIANT="glibc-$glibc" \
                QT_QPA_PLATFORM=offscreen bash scripts/build_bundle.sh "$flavor" \
                >"$WORK/bundle-$variant-$flavor.log" 2>&1) \
                || { tail -40 "$WORK/bundle-$variant-$flavor.log"; exit 1; }
            mv "$SRC/dist/axross-$flavor" "$dest/axross-$flavor"
        done
        # The tools as programs of their own, from the same gate-checked venv
        # and the same target libraries.
        for app in "${STANDALONE_LIST[@]}"; do
            [[ -n "$app" ]] || continue
            echo ">>> $variant: axross-$app"
            rm -f "$SRC/dist/axross-$app"
            (cd "$SRC" && env PATH="$VENV/bin:$SYSROOT/bin:$PATH" AXROSS_PYTHON="$VENV/bin/python" \
                LD_LIBRARY_PATH="$LIBS" AXROSS_TARGET_ROOT="$SYSROOT/root" \
                AXROSS_TARGET_LIBS="$LIBS" AXROSS_TARGET_KEEP="$WORK/" AXROSS_GLIBC_RE="$GLIBC_RE" \
                AXROSS_BUNDLE_VARIANT="glibc-$glibc" \
                QT_QPA_PLATFORM=offscreen bash scripts/build_bundle.sh "$app" \
                >"$WORK/bundle-$variant-$app.log" 2>&1) \
                || { tail -40 "$WORK/bundle-$variant-$app.log"; exit 1; }
            mv "$SRC/dist/axross-$app" "$dest/axross-$app"
        done
        (cd "$dest" && sha256sum axross-* > SHA256SUMS)
    done
    if [[ -n "$FLAVORS" ]]; then
        # The packs: the units an axross-base adds from this release - the same
        # locked wheels the gate checked above.
        echo ">>> packs"
        "$PY" -I "$SRC/scripts/build_packs.py" "$OUT/packs" "$VERSION" --wheel-python "$BVENV/bin/python" \
            || { echo "the packs could not be built" >&2; exit 1; }
    fi
fi

# -- what was built ------------------------------------------------------------------------
{
    echo "# axross $VERSION - build of $(date -u +%Y-%m-%d)"
    echo
    echo "From commit $COMMIT, a clean \`git archive\` of HEAD, by scripts/build_dist.sh."
    echo
    if [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then
        # the linux job of .github/workflows/cross-platform.yml: which run built it
        echo "Built by GitHub Actions: ${GITHUB_SERVER_URL:-}/${GITHUB_REPOSITORY:-}/actions/runs/${GITHUB_RUN_ID:-} (attempt ${GITHUB_RUN_ATTEMPT:-1}, ${GITHUB_REF:-}, runner image ${ImageOS:-?} ${ImageVersion:-?})."
        echo
    fi
    echo "| Path | What |"
    echo "|---|---|"
    [[ -f "$OUT/axross-$VERSION.tar.gz" ]] && echo "| axross-$VERSION.tar.gz, axross-$VERSION-py3-none-any.whl | PyPA build $BUILD_VERSION, isolated; platform-independent (PyPI) |"
    [[ -d "$OUT/glibc-2.34" ]] && echo "| glibc-2.34/axross-* | AlmaLinux 9 libraries: run on glibc 2.34+ (RHEL / Alma / Rocky 9, Ubuntu 22.04, Debian 12, Fedora, Arch) |"
    [[ -d "$OUT/glibc-2.36" ]] && echo "| glibc-2.36/axross-* | Debian 12 libraries: run on glibc 2.36+ (Debian 12+, Ubuntu 22.10+, Fedora 37+, Arch) |"
    [[ -d "$OUT/packs" ]] && echo "| packs/ | the units an axross-base adds (core.packs): locked wheels and packs-$VERSION.json |"
    [[ -d "$OUT/standalone" ]] && echo "| standalone/, glibc-2.3x/axross-{media-player,system-info} | the Media Player and System Information as programs of their own (scripts/export_standalone.py): sdist, wheel and binaries |"
    echo
    echo "Bundles: PyInstaller from build/requirements-bundle.txt (--require-hashes), CPython"
    echo "$PYTHON_VERSION (python-build-standalone via uv), each variant with only its"
    echo "system's libraries (BUILD-PACKAGES-*.txt; signatures and hashes checked by"
    echo "scripts/sysroot_fetch.py); the build's gates (--help, bundled scripts, system"
    echo "libraries bundled or host-provided, symbol versions against the target's glibc)."
    echo
    if [[ -n "${BOOTLOADER_SHA256:-}" ]]; then
        echo "PyInstaller bootloader compiled from its pinned sdist (zig cc): run sha256 $BOOTLOADER_SHA256"
        echo
    fi
    echo "Supply-chain gate: passed before the build (SUPPLY-CHAIN.md, SUPPLY-CHAIN.json): every"
    echo "dependency reviewed in security/supply_chain_baseline/, OSV, minimum age, provenance, typosquatting,"
    echo "YARA (GuardDog + axross rules), the installed venvs against their locks, the system packages."
    echo
    echo "**Not signed**: SHA256SUMS.sig needs the release key (scripts/sign_release.py)."
} > "$OUT/BUILD-INFO.md"

echo ">>> done: $OUT"
find "$OUT" -maxdepth 2 -type f -name 'axross*' -exec ls -lh {} \;
