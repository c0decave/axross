# Packaging axross for distribution

axross ships four distribution formats, all built from the same
source tree:

1. **PyPI package** — source distribution + wheel for `pip install`.
2. **Standalone Linux ELF** — single binary, no system Python
   needed.
3. **AppImage** — ELF wrapped with desktop integration (menu
   entry, icon, `.desktop` file). For end-user Linux.
4. **Docker image** — headless MCP-server deployment. Trims the
   PyQt6 GUI entirely.

> **Portability note.** PyInstaller ELFs link against the glibc
> of the **build host**. Building on a rolling-release distro
> (Arch, glibc 2.43 as of 2026-04) produces a binary that crashes
> on Ubuntu 22.04 with `GLIBC_2.43 not found`. **For any binary
> you plan to share, build inside the container** —
> `scripts/build_bundle_docker.sh` pins the build to glibc 2.34,
> which runs everywhere from Ubuntu 22.04 / Debian 12 / RHEL 9
> upward. See the **Cross-distro builds** section below.

## Quick reference

| Output                                   | Size  | How to build                                       |
|------------------------------------------|-------|----------------------------------------------------|
| `dist/axross-<version>.tar.gz`           | varies | `python -m build`                                |
| `dist/axross-<version>-py3-none-any.whl` | varies | `python -m build`                                |
| `dist/axross-slim`                       | ~114 MB | `scripts/build_bundle.sh slim`                   |
| `dist/axross-full`                       | ~132 MB | `scripts/build_bundle.sh full`                   |
| `dist/axross-slim` (portable, glibc 2.34)| ~87 MB  | `scripts/build_bundle_docker.sh slim`            |
| `dist/axross-full` (portable, glibc 2.34)| ~109 MB | `scripts/build_bundle_docker.sh full`            |
| `dist/axross-slim-x86_64.AppImage`       | ~120 MB | `scripts/build_bundle.sh slim --appimage`        |
| `dist/axross-full-x86_64.AppImage`       | ~140 MB | `scripts/build_bundle.sh full --appimage`        |
| `axross-mcp:latest` (Docker)             | ~180 MB | `docker build -f Dockerfile.mcp -t axross-mcp:latest .` |

**Sizes are realistic measurements** from a clean rebuild in a
`/tmp` scratch dir, not hand-waves. UPX packs the slim ELF down
from a ~180 MB unpacked form.

## PyPI package

The PyPI artifact is the normal Python distribution: an sdist plus a
pure-Python wheel. It installs the GUI entry point, the MCP/headless
CLI modes, the public `axross` scripting facade, and the bundled
runtime resources:

* `resources/logo/` — window icons and generated logo assets.
* `resources/scripts/` — built-in REPL/CLI scripts listed by the
  scripting docs.
* `resources/wordlists/` — default TFTP discovery wordlist.

PyPI renders `README_PYPI.md` as the project start page. Keep it
short, install-focused, and based on absolute GitHub links; the
top-level `README.md` remains the full repository overview.

### Build locally

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r dev-requirements.txt
rm -rf dist
python -m build
python -m twine check dist/*
```

The source checkout should stay out of the smoke test so import-path
mistakes are caught:

```bash
tmpdir="$(mktemp -d)"
python3 -m venv "$tmpdir/venv"
"$tmpdir/venv/bin/pip" install --no-deps dist/axross-<version>-py3-none-any.whl
"$tmpdir/venv/bin/python" -c 'import axross; print(axross.__version__)'
"$tmpdir/venv/bin/python" -m axross --help
"$tmpdir/venv/bin/axross" --help
```

Use a dependency-resolving install for an actual GUI run:

```bash
"$tmpdir/venv/bin/pip" install "dist/axross-<version>-py3-none-any.whl[all]"
"$tmpdir/venv/bin/axross"
```

### Publish

Publish only from a clean, tagged checkout:

```bash
git status --short
git tag -s v0.4.1 -m "axross 0.4.1"
rm -rf dist
python -m build
python -m twine check dist/*
python -m twine upload --repository testpypi dist/*
python -m twine upload dist/*
```

Use API tokens for both PyPI and TestPyPI. Keep credentials in
`~/.pypirc` or pass them through `TWINE_USERNAME=__token__` and
`TWINE_PASSWORD=<token>`.

### Versioning

The PyPI version is read from `axross/_version.py` via
`tool.setuptools.dynamic`. Do not duplicate it in `pyproject.toml`.

Before a release, change only:

```python
__version__ = "0.4.1"
```

Then rebuild from scratch:

```bash
rm -rf dist
python -m build
python -m twine check dist/*
```

Use PEP 440-compliant versions (`0.4.1`, `0.5.0`, `1.0.0`,
`0.5.0rc1`, `0.4.1.post1`) and tag the exact commit as
`v<version>`.

## Flavours: slim vs full

| Feature                | slim        | full        |
|------------------------|-------------|-------------|
| SFTP / SCP             | ✓           | ✓           |
| FTP / FTPS             | ✓           | ✓           |
| SMB / CIFS             | ✓           | ✓           |
| WebDAV                 | ✓           | ✓           |
| S3 / S3-compatible     | ✓           | ✓           |
| Rsync                  | ✓           | ✓           |
| NFS                    | ✓           | ✓           |
| iSCSI                  | ✓           | ✓           |
| IMAP / Telnet          | ✓           | ✓           |
| ADB / MTP (Android)    | ✓           | ✓           |
| Archive extract        | ✓           | ✓           |
| Encrypted overlay      | ✓           | ✓           |
| FUSE mount             | ✓           | ✓           |
| MCP server (stdio+HTTP)| ✓           | ✓           |
| Azure Blob / Files     | ✗           | ✓           |
| OneDrive / SharePoint  | ✗           | ✓           |
| Google Drive           | ✗           | ✓           |
| Dropbox                | ✗           | ✓           |
| Exchange (EWS)         | ✗           | ✓           |
| WinRM / WMI / DCOM     | ✗           | ✓           |

The `slim` variant is **the right default** for most users. Cloud
OAuth + Windows-specific backends pull in the biggest third-party
dependencies (googleapiclient alone is 94 MB); users who need
them can pick `full` or install axross via `pip` with the
matching extras.

## How the bundling works

### PyInstaller spec (`build/axross.spec`)

One spec file handles both flavours via the
`AXROSS_BUNDLE_FLAVOR` env var. The flavour-specific bits are:

* **`hiddenimports`** — `collect_submodules("core")` +
  `collect_submodules("ui")` + `collect_submodules("models")`
  picks up every backend without needing a hand-maintained list.
  Additional explicit entries cover indirect deps PyInstaller
  can't statically follow: `PyQt6.QtSvg`, the cryptography
  OpenSSL backends, keyring backends (SecretService / kwallet /
  chainer — otherwise every keyring lookup falls back to the
  null backend and every stored password fails).
* **`excludes`** — slim drops `google`, `googleapiclient`, `msal`,
  `dropbox`, `azure`, `exchangelib`, `winrm`, `impacket`, plus
  the matching `core.*_client` modules. Both flavours drop
  `semgrep` (dev-only 305 MB), `setuptools`, `pip`, `wheel`,
  `pytest`, `tkinter`, `sphinx`, `jupyter`, `IPython`, `notebook`.
* **UPX** — on by default with `libQt6*.so*` and `libicu*.so*`
  excluded because Qt plugins break when packed.

### Dynamic backend imports

`core/connection_manager.py` dispatches via
`load_backend_class(protocol_id)`, which calls
`importlib.import_module` at runtime with a string from a
profile. PyInstaller's static analysis can't follow that — which
is why `collect_submodules("core")` is the trick: it grabs every
`.py` under `core/` regardless of whether anyone imports it
directly, so the dispatch finds its target module inside the
bundled archive.

### External binaries we DON'T bundle

| Binary       | Used by                         | Why unbundled                                                      |
|--------------|---------------------------------|--------------------------------------------------------------------|
| `rsync`      | `core.rsync_client`             | System package; no pure-Python rsync wire protocol exists          |
| `iscsiadm`   | `core.iscsi_client`             | Kernel iSCSI initiator; must be root-setuid                        |
| `mount.nfs`  | `core.nfs_client`               | Kernel NFS client; needs `CAP_SYS_ADMIN`                           |
| `fusermount` | `core.fuse_mount`               | Bundling libfuse is brittle across distros                         |
| `jmtpfs` / `simple-mtpfs` | `core.mtp_client`     | MTP-FUSE mounters — kernel + libusb deps                           |
| `adb`        | *(NOT used — adb-shell is pure Python)* | — |
| `pkexec`     | `core.elevated_io`              | Host polkit integration                                            |

The `core.backend_registry` flags unavailable backends as
`available=False`; the Connection Manager greys out their
entries with an "install the matching system package" hint.

### AppImage wrap

`scripts/build_bundle.sh <flavor> --appimage` runs the ELF
through [`appimagetool`](https://appimage.github.io/appimagetool/),
which:

1. Creates an `AppDir` layout (`usr/bin/axross`,
   `usr/share/applications/axross.desktop`,
   `usr/share/icons/hicolor/scalable/apps/axross.svg`).
2. Adds the standard AppRun entry point.
3. Packages everything into a single self-mounting ELF.

Fresh hosts without `appimagetool` in PATH get the tool
auto-downloaded to `build/appimagetool-x86_64.AppImage` on first
run; subsequent builds reuse the cached copy.

### Docker image (`Dockerfile.mcp`)

Pure-headless. No PyQt6. Installs only the subset of third-party
deps the MCP surface needs:

* `paramiko` — SFTP/SCP
* `cryptography` — encrypted overlay + TLS
* `jsonschema` — argument validation
* `smbprotocol` — SMB / DFS-N
* `boto3` — S3
* `requests` + `defusedxml` — WebDAV (pure-Python, no SDK)
* `adb-shell` — ADB
* `py7zr` — 7z extract

The resulting image is ~180 MB — much smaller than the GUI
bundle because Qt is the dominant dep in both. Default
`ENTRYPOINT` runs `main.py --mcp-server` on stdio; operators
override with `--mcp-http 0.0.0.0:7331` + cert args for a
network-facing deploy.

See the in-file comments for mTLS-protected example
`docker run` invocations.

## Cross-distro builds (glibc portability)

PyInstaller produces ELFs that dynamically link against libc.
"glibc is backwards-compatible, not forwards-compatible" — a
binary built on glibc 2.43 requires glibc 2.43 at runtime. The
practical consequence:

```text
# ./axross-full  (built on Arch, glibc 2.43)
ImportError: /lib/x86_64-linux-gnu/libc.so.6: version
  `GLIBC_2.43' not found (required by libglib-2.0.so.0)
# Ubuntu 22.04 only has glibc 2.35 → refuses to load.
```

Fix: build inside a pinned-glibc container via
`scripts/build_bundle_docker.sh`. It uses an `almalinux:9` image
(glibc 2.34, distro python3.12), producing binaries that run on:

| Distro                  | glibc   | Runs? |
|-------------------------|---------|-------|
| Ubuntu 22.04 LTS        | 2.35    | ✓    |
| Ubuntu 24.04 LTS        | 2.39    | ✓    |
| Debian 12 (Bookworm)    | 2.36    | ✓    |
| Debian 13 (Trixie)      | 2.41    | ✓    |
| RHEL 9 / Alma 9 / Rocky 9 | 2.34  | ✓    |
| Fedora 35+              | 2.34+   | ✓    |
| Arch, openSUSE TW       | rolling | ✓    |
| Ubuntu 20.04 LTS        | 2.31    | ✗ (too old) |
| RHEL 8 / Alma 8         | 2.28    | ✗ (too old) |

Usage:

```bash
# One command. Pulls the ~1 GB builder image on first run
# (cached afterwards), installs deps inside the container, runs
# PyInstaller, extracts the ELF to ./dist/.
scripts/build_bundle_docker.sh full
scripts/build_bundle_docker.sh slim
```

The resulting `dist/axross-{full,slim}` is the one to ship.
Verify with:

```bash
objdump -T dist/axross-full | awk '/GLIBC_/ {print $5}' \
    | sort -uV | tail -3
# Expected: GLIBC_2.34 (or lower) — nothing newer.
```

### Why AlmaLinux 9 and not older / newer bases?

* **RHEL 8 / Ubuntu 20.04 (glibc 2.28 / 2.31)** would reach more
  hosts, but PyQt6 doesn't publish wheels for those tags (only
  manylinux_2_34 and manylinux_2_39 — verified on PyPI 2026-04).
  Pinning to an older glibc triggers a source build that needs
  the full Qt toolchain + GL headers + ~45 min of compile time.
* **manylinux_2_34 (pypa image)** has the right glibc but ships
  a static-linked CPython; PyInstaller refuses to use it with
  *"Python was built without a shared library"*.
* **AlmaLinux 9** hits the sweet spot: glibc 2.34 matches PyQt6's
  wheel tag, its distro `python3.12` package is shared-library,
  and the resulting ELF runs on every glibc-2.34+ host.

If you specifically need RHEL 8 / Ubuntu 20.04 support, either:

* Distribute via the system's Python (`pip install` into a venv)
  and skip the ELF bundling; or
* Swap the base in `Dockerfile.build` to `debian:bullseye` or
  `ubuntu:20.04`, install Python 3.12 from deadsnakes / upstream,
  and accept that PyQt6 will build from source (slow, needs the
  Qt dev packages).

## Building on a machine with limited disk

PyInstaller needs ~3 GB of scratch during a full PyQt6 build.
The bundled `build_bundle.sh` detects low `/tmp` free space and
falls back to `build-tmp/` inside the project dir — which is
gitignored, so it doesn't pollute the tree.

If your host is under 5 GB free *anywhere*, build on a different
machine and copy the resulting `dist/axross-<flavor>` over. The
ELF has no runtime dependency on the build host beyond a
compatible glibc.

## Update the build

When a new backend lands in `core/`:

* `collect_submodules("core")` picks it up automatically — no
  spec edit.
* If the backend depends on a third-party package PyInstaller
  can't statically follow (unusual: most packages have their
  own PyInstaller hook), add the dep name to `hiddenimports` in
  `build/axross.spec`.

When a new optional extra lands:

* Add the matching module to the slim `excludes` list so slim
  stays lean.
* Add a row to the flavour table above.
* Rebuild both flavours and record the new binary sizes in the
  Quick-reference table.

## Release flow

Suggested sequence for a tagged release:

```bash
# 1. Clean venv + deps (catches accidental dev leftovers)
rm -rf .venv
uv venv
.venv/bin/pip install -e ".[all,adb,archive]"

# 2. Run the full regression
QT_QPA_PLATFORM=offscreen .venv/bin/pytest -q \
    tests/test_hardening_regressions.py \
    tests/test_regressions.py \
    tests/test_new_features.py \
    tests/test_backend_regressions.py \
    tests/test_pane_layout_regressions.py \
    tests/test_e2e.py

# 3. Build all three flavours
scripts/build_bundle.sh slim --appimage
scripts/build_bundle.sh full --appimage

# 4. Build the MCP Docker image (requires docker daemon)
docker build -f Dockerfile.mcp -t axross-mcp:$(git describe --tags) .
docker tag axross-mcp:$(git describe --tags) axross-mcp:latest

# 5. Sha256 everything
( cd dist && sha256sum axross-* ) | tee dist/SHA256SUMS
```

Checksums go into the release notes. Linux AppImage signing
(`gpg --detach-sign dist/axross-full-x86_64.AppImage`) is a
nice-to-have; for internal lab distribution SHA256 alone is
usually enough.
