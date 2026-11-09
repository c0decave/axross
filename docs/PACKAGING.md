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

| Output | How to build | Where |
|---|---|---|
| `axross-<version>.tar.gz`, `axross-<version>-py3-none-any.whl` | `python -m build` | anywhere |
| Linux `axross-base`, `axross-slim`, `axross-full` (+ `axross-media-player`, `axross-system-info`) for glibc 2.34 and 2.36, the packs, wheel and sdist - everything a release carries for Linux | `scripts/build_dist.sh` -> `dist/<version>/`; in CI the `linux` job of `cross-platform.yml` runs it (artifact `axross-linux-dist`) | CI, or a builder (see [Release flow](#release-flow)) |
| One Linux binary on this machine | `scripts/build_bundle.sh slim\|full\|base [--appimage]` | any Linux |
| One portable Linux binary (glibc 2.34) | `scripts/build_bundle_docker.sh slim\|full` | Linux with Docker or podman |
| macOS and Windows `axross-slim`, `axross-full` | the `bundle` job of `cross-platform.yml`, started by a tag push | CI |
| Optional packs (extras as wheels) | `scripts/build_packs.py` (part of `build_dist.sh`) | builder |
| Release folder in the updater's asset names, `SHA256SUMS` signed | `scripts/assemble_release.py`, then `scripts/sign_release.py` | maintainer |
| `axross-mcp:latest` (Docker) | `docker build -f Dockerfile.mcp -t axross-mcp:latest .` | Docker host |
| `localhost/axross-gui:latest` (podman) | `scripts/axross-podman.sh build` (`Dockerfile.gui`) | podman host |

Sizes depend on the flavour and the platform: slim is about 90-115 MB,
full about 110-135 MB (UPX packs the Linux ELF). The [Release
flow](#release-flow) below is the order in which a release is made; the
[Self-update](#self-update-what-a-release-must-carry) section lists what
it must carry for installed binaries to update.

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
python -m twine check --strict dist/*
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
python -m twine check --strict dist/*
python -m twine upload --repository testpypi dist/*
python -m twine upload dist/*
```

Use API tokens for both PyPI and TestPyPI. Keep credentials in
`~/.pypirc` or pass them through `TWINE_USERNAME=__token__` and
`TWINE_PASSWORD=<token>`.

### Versioning

The version is read from `axross/_version.py` via
`tool.setuptools.dynamic`: by the wheel and sdist, by `axross --version`,
and by `scripts/build_release.sh` for the tarball name. Do not duplicate
it in `pyproject.toml`.

Before a release, change only:

```python
__version__ = "0.4.1"
```

Then rebuild from scratch:

```bash
rm -rf dist
python -m build
python -m twine check --strict dist/*
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
* **Licence texts** — `scripts/bundle_licenses.py` copies each bundled
  system library's package licence files into `licenses/system/<package>/`
  and lists library, package and version in `licenses/system/LIBRARIES.txt`.
  In a container build, `rpm` names the package. A sysroot build
  (`scripts/build_dist.sh`) has no package database, so the package comes
  from the sysroot's `FILES.json`, which `scripts/sysroot_fetch.py` writes
  while unpacking: which package wrote each file and symlink, with each
  package's version and source package. The licence files are the
  package's own files under `/usr/share/licenses/` (AlmaLinux) or its
  `/usr/share/doc/<package>/copyright` (Debian). When the package has none,
  the files of the sysroot's other packages built from the same source
  package are taken. `licenses/system/SYSTEM.txt` names the format (`rpm`
  or `deb`), and `scripts/native_inventory.py` shows it in each row. An
  `AXROSS_TARGET_ROOT` without `FILES.json` stops the build. A
  `libpython` that no package owns and that belongs to the interpreter
  running the build (in `build_dist.sh`, uv's python-build-standalone
  CPython) gets the package `python` with that interpreter's version. Its
  `lib/python3.X/LICENSE.txt` goes to `licenses/system/python/`. uv's
  installation lacks the licences of what is linked into libpython
  (OpenSSL, libffi, SQLite, XZ, zlib, ...). So `build_dist.sh` runs
  `scripts/python_licences.py`, which fetches the *full* archive of the
  same python-build-standalone build. Its URL and SHA-256 are pinned in
  `build/python-standalone.txt`, and the hash is checked before the archive
  is read. The script refuses a pin of another CPython version, or of
  another release than the one uv recorded in its `BUILD` file. Only
  `python/PYTHON.json` (which names the licence of each linked library) and
  the files of `python/licenses/` are kept. They go to
  `licenses/system/python/` and `licenses/system/python/licenses/`
  (`AXROSS_PYTHON_LICENSES`). PYTHON.json carries no versions of those
  libraries, so LIBRARIES.txt and the inventory do not list them one by
  one. The inventory shows libpython as `cpython`, shipped by
  `python-build-standalone <version>`. A new `PYTHON_VERSION` needs a new
  pin (`uv python list <version> --show-urls` names the release).
  A top-level library that a wheel ships (libusb-package's
  `libusb-1.0.so`) is listed as `wheel:<distribution>` with the wheel's
  version. Its licence files are the wheel's, under `licenses/python/`,
  and the inventory reads it as `wheel`. When a wheel lacks the licence of
  the library it carries, a tracked text is added: libusb-package has only
  its own Apache-2.0 text, so libusb's LGPL-2.1 `COPYING` and `AUTHORS`
  (v1.0.26) come from `build/licenses/libusb/`
  (`WHEEL_LIBRARY_NOTICES` in `scripts/bundle_licenses.py`). The same goes
  for libraries inside a wheel: xeddsa's `xeddsa.libs/libsodium` (1.0.18,
  ISC, `build/licenses/libsodium/LICENSE`) and the c-ares that pycares
  links in (1.34.9, MIT, `build/licenses/c-ares/LICENSE.md`); both texts
  are upstream's at the matching tag. A new pin of xeddsa or pycares
  needs that version checked again (tests/test_bundle_licenses_sysroot.py
  holds the pins). ctranslate2's wheel has neither a licence file nor an
  SBOM, so the full build copies its dist-info (`copy_metadata`) for the
  inventory to tie `ctranslate2.libs/` to the wheel.

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

Fresh hosts without `appimagetool` in PATH (or `APPIMAGETOOL=<path>`)
get a pinned release of the tool - 1.9.1, not the `continuous` build,
whose file changes under the same URL - downloaded to
`build/appimagetool-x86_64.AppImage` by `scripts/fetch_appimagetool.sh`.
Its SHA-256 is checked after the download and again on every later
build for the cached copy; a mismatch deletes the download and stops
the build, and there is no switch to skip the check. To move to a
newer release, set `APPIMAGETOOL_VERSION` and `APPIMAGETOOL_SHA256` at
the top of that script (the comment there says where GitHub shows an
asset's digest) and cross-check the digest with `sha256sum` on the
downloaded file.

### macOS binary: the first start

The macOS binary (`axross-slim-macos-arm64`) is ad-hoc signed, not
notarized: there is no Apple Developer ID behind it. A browser marks
the download with `com.apple.quarantine`, and Gatekeeper refuses its
first start ("Apple could not verify … is free of malware") before any
axross code runs. Measured on macOS 27.0.1: syspolicyd logs "Prompt
shown" and then "Adding Gatekeeper denial breadcrumb". Two ways to
start it anyway:

- After the refused start, open **System Settings → Privacy & Security**
  and click **Open Anyway**.
- Or in Terminal, remove only the quarantine attribute:

  ```bash
  xattr -d com.apple.quarantine ./axross-slim-macos-arm64
  chmod +x ./axross-slim-macos-arm64
  ./axross-slim-macos-arm64
  ```

The window needs the desktop session. Over SSH only the user who is
logged in at the screen gets it (the window then opens on that screen);
for any other user there is no screen: axross then says so and exits 1,
where Qt used to abort with crash reports. Without a window, `--mcp-server` and `--script FILE` work
anywhere.

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

Each with pyproject.toml's floor. Of the source tree it carries
`main.py` and what its MCP path imports or reads: `axross/`, `core/`,
`models/`, `security/` and `resources/` (no `ui/`).
`tests/test_docker_images.py` follows the imports of the entry point
and fails when one of them is not copied, or a floor falls below
pyproject's.

The resulting image is ~180 MB — much smaller than the GUI
bundle because Qt is the dominant dep in both. Default
`ENTRYPOINT` runs `main.py --mcp-server` on stdio; operators
override with `--mcp-http 0.0.0.0:7331` + cert args for a
network-facing deploy.

See the in-file comments for mTLS-protected example
`docker run` invocations.

### GUI image for podman (`Dockerfile.gui`, `scripts/axross-podman.sh`)

The desktop app, the MCP server and the Agent dock in one image
(`axross[all]`), shown on the host's Wayland or X11 display; a local
LLM can run beside it.

```bash
scripts/axross-podman.sh build                       # localhost/axross-gui:latest
scripts/axross-podman.sh gui                         # the window, on your display
scripts/axross-podman.sh gui --data ~/work           # + ~/work at /data
scripts/axross-podman.sh gui --llm-model ~/models/qwen2.5-7b-instruct-q4_k_m.gguf
scripts/axross-podman.sh gui --llm-url http://host.containers.internal:11434/v1 --llm-name qwen2.5:7b
scripts/axross-podman.sh mcp --llm-model M.gguf -- --mcp-tools agent --mcp-root /data
```

* **Display.** `gui` takes Wayland when `$WAYLAND_DISPLAY` names a
  socket, else X11 (`$DISPLAY`, the socket from `/tmp/.X11-unix`); `--display
  wayland|x11` chooses. For X11 the script writes a cookie of its own
  (`xauth`, family "any host") into `$XDG_RUNTIME_DIR/axross-podman/`, so
  the host's `~/.Xauthority` stays outside. `--gpu` passes `/dev/dri`;
  without it Qt draws in software.
* **The image.** Only the wheel built from the tree enters the final
  stage, never the source. The build fails when a library of the Qt
  `xcb` or `wayland` platform plugins is missing (an `ldd` check), so the
  image cannot ship half a desktop.
* **Isolation.** The container runs as your user (`--userns=keep-id`)
  with every capability dropped, and sees the display socket, its home
  (`--home`, default `~/.local/share/axross-podman/home`, mode 0700, kept
  between runs) and `--data`. `--dbus` passes the session bus, which
  the Secret Service keyring needs to store passwords (not part of the
  live checks below: they never touch a real keyring).
* **A local LLM.** `--llm-model FILE.gguf` starts llama.cpp
  (`ghcr.io/ggml-org/llama.cpp:server`, `--jinja` for tool calling;
  `--llm-image` for another) with the model mounted read-only, waits
  until it has loaded the model and listens, and runs axross in that
  container's user and network namespaces: the Agent dock and
  `agent_run` reach it at `http://127.0.0.1:8080/v1`. Not a pod: on
  podman 6.1 with runc 1.5.2 a pod's infra container did not start. The
  first start adds the LLM profile `pod-llm` (or, with `--llm-url`, a
  profile for a server that already runs) - only when the home has no
  `llm.json` yet. The model container is removed when axross exits.
* **MCP.** `mcp` runs `axross --mcp-server` on stdio (`podman run -i`),
  for an MCP client on the host; arguments after `--` go to axross.
* **The Agent dock's sandbox inside.** The image brings bubblewrap.
  `--agent-sandbox` adds `--security-opt unmask=/proc/*`: podman masks
  paths under `/proc` and mounts `/proc/sys` read-only, and bubblewrap
  then fails to mount its own `/proc` ("Can't mount proc on
  /newroot/proc") and, on high and paranoid, to switch off user
  namespaces. Capabilities stay dropped and `no-new-privileges` stays
  on; `/sys/firmware` stays masked. Measured 2026-10-17 with podman
  6.1.3: with the option every test of `tests/test_agent_sandbox.py`
  passes inside the container; without it the tab's error names the
  option. podman inside the container cannot start the agent image (the
  container's user namespace maps no further ids for `newuidmap`):
  choose a bubblewrap sandbox profile there.

Verified with podman 6.1.3: the window on X11 (Xvfb) and on Wayland
(headless weston), the Agent's MCP tools answering with a local
Qwen2.5-1.5B through llama.cpp, and `agent_run` from an MCP client on
stdio.

### Agent sandbox image (`Dockerfile.agent`)

The image a tab's agent runs in when its sandbox profile uses podman or
docker (Tools > Agent Settings > Sandboxes): only `core.agent_worker`,
the agent loop and the MCP tools it calls, on `python:3.12-slim`; it
runs as your own uid (`--user`, with podman also `--userns=keep-id`),
so it can enter the tab's folder. No GUI, no protocol backends,
no credentials: the model's requests, remote connections, MCP servers
and extension tools stay in axross, which talks to the worker over
stdin/stdout.

```bash
scripts/axross-podman.sh agent-image          # localhost/axross-agent:<version>
docker build -f Dockerfile.agent -t localhost/axross-agent:<version> .
```

axross starts it with `--network=none --cap-drop=ALL --read-only
--security-opt=no-new-privileges`, a size-limited `/tmp`, memory, pids
and (high, paranoid) CPU limits, `--ipc=none` (high, paranoid) and only
the tab's folder and the sandbox's extra folders mounted. bubblewrap
needs no image: it runs the worker from the installed axross with the
system and Python directories read-only.

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

### Pinned, hashed dependencies

The builder installs nothing by name: every Python package comes from
`build/requirements-bundle.txt`, one exact version per package with the
sha256 of each of its files, installed with `--require-hashes
--only-binary=:all:`. The macOS and Windows CI bundles install the same
file. Its input is `build/requirements-bundle.in` (every pyproject
requirement with its floor, plus PyInstaller); refresh it with

```bash
scripts/lock_bundle_deps.sh          # resolver (uv) runs in a container
python -m security.dep_floor_audit --lock build/requirements-bundle.txt
```

and commit both files with `build/requirements-bootstrap.txt` (`git add
-f`: a global `build/` ignore hides them). The image also runs `dnf
upgrade`; `scripts/build_bundle_docker.sh` refuses an image that still
lists a security update (`AXROSS_BUILDER_NO_CACHE=1` rebuilds every
layer). What each gate covers: `docs/SUPPLY_CHAIN_AUDIT.md`.

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
machine and copy the resulting `dist/axross-<flavor>` over. What the
ELF needs from the machine it runs on is listed below.

## What comes from the host, and how the build checks it

A one-file binary runs host code in two ways: host programs it starts
(a shell, ffprobe, a file manager behind xdg-open) and host libraries
loaded into its own process (the GPU's OpenGL driver, audio plugins).
Both met the bundle's own libraries once: `bash -c` died with "symbol
lookup error ... rl_trim_arg_from_keyseq" (the bundle's readline), an
OpenGL context aborted with "Could not initialize GLX" (Mesa needs a newer
libstdc++ than the bundled one), Qt's TIFF and xcb plugins needed
libraries that were never bundled. The rules, in `scripts/bundle_options.py`:

| Comes from the host | Why |
|---|---|
| glibc in all its parts, libstdc++, libgcc_s (`HOST_OWNED`, never bundled) | one copy per process; the host's is never older than the builder's |
| fontconfig, freetype (`HOST_OWNED`) | they read the host's `/etc/fonts` |
| GL/EGL/GLX/DRM/GBM/Vulkan, Wayland client, libxcb, libX11, libpulse (`HOST_PROVIDED`) | the graphics and sound stack belongs to the host's drivers and session |
| everything else | bundled; a build fails when it is not |

`scripts/build_bundle.sh` runs `scripts/bundle_smoke.py --system-libs` on
every built binary; inside it, the build fails when

* a bundled ELF needs a system library that is neither bundled nor in the
  table (`scripts/elf_needs.py` reads DT_NEEDED);
* a library the host must own is bundled;
* a bundled ELF needs a symbol version (GLIBC_, GLIBCXX_, CXXABI_ ...) that
  the build machine does not define - in the AlmaLinux 9 builder that is the
  oldest supported system;
* a child process started via `subprocess` without `env=`, `os.system` or
  QProcess sees a variable pointing into the unpacked folder
  (`LD_LIBRARY_PATH`, `QT_PLUGIN_PATH`, `QML2_IMPORT_PATH`, `_PYI_*`;
  `core.subprocess_env.restore_loader_env` clears them at start).

The builder runs on the oldest system, so it cannot see what breaks on a
current one. Before every release, run against the built binaries on a
current distribution (Arch, Fedora, openSUSE Tumbleweed):

```bash
AXROSS_FROZEN_BINARY=dist/axross-full .venv/bin/python -m pytest tests/test_frozen_binary_host_e2e.py
AXROSS_FROZEN_BINARY=dist/axross-slim .venv/bin/python -m pytest tests/test_frozen_binary_host_e2e.py
```

It starts host programs from the binary, loads the host's C++ plugin
libraries (Mesa, JACK, ALSA, Vulkan drivers) into it and creates an
OpenGL context under Xvfb, each against a control without axross.

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

Every step names where it runs. **CI** is GitHub Actions; **builder** is
the machine or container that runs `scripts/build_dist.sh` (Debian-based,
with git, curl, gpgv, dpkg-deb, uv and the network that script names - no
Docker, no root); **maintainer** is the machine that holds the release key
and the PyPI tokens, and never builds. Nothing on the builder or in CI
ever sees the key.

CI is the builder: the `linux` job of `cross-platform.yml`
runs `scripts/build_dist.sh` unchanged on a GitHub runner (Ubuntu 24.04,
the supply-chain gate first, both glibc variants against their own
packages - no container), so a release needs no builder machine, only the
maintainer's key. A builder machine stays the alternative (step 5). What
CI cannot do, and stays with the maintainer: signing `SHA256SUMS` (the key
never leaves the maintainer's machine; the workflow references no secret),
the uploads to GitHub and PyPI, the update check of an installed 0.14.136
binary, the tour videos, and the optional source tarball of
`scripts/build_release.sh --tarball` (it needs the maintainer's private
`~/.config/axross/release-identity-terms`; `build_dist.sh` never reads
it).

```bash
export GH_HOST=github.com   # gh must talk to github.com, whatever its default host is
VERSION=0.15.177
```

1. **maintainer** - prepare the commit. `axross/_version.py` says
   `$VERSION`; `CHANGELOG.md` turns "Unreleased" into `## $VERSION -
   <date>` (the release notes start from it: `assemble_release.py
   --require-all` refuses a section still called "Unreleased"). Run the
   **full** test suite locally - the "Python application" workflow
   (`python-app.yml`) runs only five test files, not the suite:

   ```bash
   .venv/bin/pip install -e ".[all]" -r dev-requirements.txt
   QT_QPA_PLATFORM=offscreen .venv/bin/pytest -q -p no:cacheprovider -rfE -n auto tests
   ```

   (`-n auto` needs pytest-xdist; single-process the run takes about half an
   hour.) Merge to `main`; `python-app.yml` must be green on that commit.

   **Tour videos, in the same commit.** The app pins each video's SHA-256
   in `resources/tours/tour_videos.json` and plays only those files, so the
   videos are rendered from this commit (its tour texts, its window, its
   version in the status bar) and their pins committed *before* the tag -
   rendered after it, every video would be refused; published from an older
   render, they would narrate old texts. A new set of videos takes a new
   tag (`tour-videos-2`, ...): an axross that pinned the old files keeps
   fetching them from the old release.

   ```bash
   TOURS=tour-videos-1          # a new tag when the videos change
   python scripts/tour_videos.py frames --out F --lang en de          # PyQt6
   python scripts/tour_videos.py render --frames F --out V --voices VOICES   # piper, ffmpeg
   python scripts/tour_videos.py manifest --videos V --tag "$TOURS"   # -> V/release/*.mp4
   git add resources/tours/tour_videos.json && git commit -m "Tour videos for $VERSION"
   ```

   Step 7 publishes `V/release/*.mp4` as that tag.

2. **maintainer** - before the tag, a green **cross-platform build** of that
   commit: the macOS and Windows binaries have not been built since
   0.14.136, and `bundle` runs only after `smoke` passed on all three
   systems. A push to a `ci/` branch starts `cross-platform.yml` without a
   tag:

   ```bash
   git push origin "HEAD:refs/heads/ci/$VERSION"
   RUN=$(gh run list --workflow cross-platform.yml --branch "ci/$VERSION" --limit 1 \
         --json databaseId --jq '.[0].databaseId')
   gh run watch "$RUN" --exit-status    # smoke on Linux, macOS, Windows, then bundle
   gh run view "$RUN" --json jobs --jq '.jobs[] | "\(.name) \(.conclusion)"'
   ```

   Every job must say `success`: `smoke` (three), `bundle` (four: slim
   and full on macOS and Windows), `linux` (the whole Linux dist, a few
   hours) and `linux-host-check` (three: full, slim, base). Fix and push
   again until it is; tag only a commit with a green run.

3. **maintainer** - tag that commit and push the tag:

   ```bash
   git tag -a "v$VERSION" -m "axross $VERSION" && git push origin "v$VERSION"
   ```

4. **CI** - the tag starts `cross-platform.yml` again: the smoke tests on
   Linux, macOS and Windows, then the `bundle` job builds the macOS and
   Windows one-file binaries, slim and full, and the `linux` job the Linux
   dist (step 5). The `bundle` artifacts are
   `axross-<flavor>-<runner.os>-<runner.arch>` - `axross-slim-macOS-ARM64`,
   `axross-full-macOS-ARM64`, `axross-slim-Windows-X64`,
   `axross-full-Windows-X64` - each with `axross-<flavor>[.exe]` and its
   `.sha256`; the `linux` artifact is `axross-linux-dist`. Fetch them all
   once the run is green:

   ```bash
   RUN=$(gh run list --workflow cross-platform.yml --branch "v$VERSION" --limit 1 \
         --json databaseId --jq '.[0].databaseId')
   gh run watch "$RUN" --exit-status
   gh run download "$RUN" -D "dist/$VERSION-ci"
   ```

5. **CI** - the `linux` job builds the Linux binaries, the packs, wheel
   and sdist from the tag with `scripts/build_dist.sh` (`HEAD`, a clean
   `git archive`, after the supply-chain gate passed; `BUILD-INFO.md` names
   the run), writes `NATIVE-COMPONENTS.md` (`scripts/native_inventory.py
   --notes`), checks THIRD_PARTY_LICENSES.md against the binaries
   (`--check`) and that `assemble_release.py` takes the folder, then
   uploads it as `axross-linux-dist`; `linux-host-check` runs step 6's host
   test on the downloaded artifact. Step 4's download put it at
   `dist/$VERSION-ci/axross-linux-dist/`, which `assemble_release.py --ci`
   takes in place of `--dist` (step 8). To have it where a builder writes
   it (an artifact keeps no file mode):

   ```bash
   gh run download "$RUN" -n axross-linux-dist -D "dist/$VERSION"
   chmod +x dist/$VERSION/glibc-2.3*/axross-*
   ```

   The folder holds `glibc-2.34/` and `glibc-2.36/` (each with
   `axross-base`, `axross-slim`, `axross-full` and the tools
   `axross-media-player`, `axross-system-info`), `packs/` (the wheels and
   `packs-$VERSION.json`), `standalone/`, the wheel
   `axross-$VERSION-py3-none-any.whl`, the sdist `axross-$VERSION.tar.gz`,
   `SUPPLY-CHAIN.md`, `BUILD-INFO.md` and `NATIVE-COMPONENTS.md`. When
   `--check` fails (a newer system package changed a native file), the run
   uploads `axross-linux-third-party-licenses`, the THIRD_PARTY_LICENSES.md
   these binaries want: review it, commit it, and run again.

   **Alternative: a builder machine** (no CI run, or to rebuild one
   locally) - the same script from the tag:

   ```bash
   git checkout "v$VERSION"
   scripts/build_dist.sh            # -> dist/$VERSION/
   ```

6. **builder, or any current distribution** - only when the Linux dist
   comes from a builder (in CI the `linux` and `linux-host-check`
   jobs run both, step 5): the Linux binaries against a current host (see
   "What comes from the host"), and the native components for
   THIRD_PARTY_LICENSES.md and the release notes (fails when a typed
   credits version disagrees):

   ```bash
   for f in full slim base; do
       AXROSS_FROZEN_BINARY=dist/$VERSION/glibc-2.34/axross-$f \
           .venv/bin/python -m pytest tests/test_frozen_binary_host_e2e.py
   done
   .venv/bin/python scripts/native_inventory.py dist/$VERSION/glibc-2.34/axross-full \
       dist/$VERSION/glibc-2.34/axross-slim --check
   .venv/bin/python scripts/native_inventory.py dist/$VERSION/glibc-2.34/axross-full \
       dist/$VERSION/glibc-2.34/axross-slim --notes "dist/$VERSION/NATIVE-COMPONENTS.md"
   ```

   Copy `dist/$VERSION/` (with `NATIVE-COMPONENTS.md`) to the
   maintainer's machine.

7. **maintainer** - the **tour videos**, before the app release and only
   when `resources/tours/tour_videos.json` names a tag that has no release
   yet (a new set of videos gets a new tag, see `scripts/tour_videos.py`).
   They go into a release of their own that must **never become
   "Latest"**: the updater reads `releases/latest`, and a tag such as
   `tour-videos-1` is no version - every installed binary's check would
   fail until the next app release. So: a prerelease, and `--latest=false`:

   ```bash
   TOURS=$(python3 -c 'import json; print(json.load(open("resources/tours/tour_videos.json"))["tag"])')
   gh release create "$TOURS" --prerelease --latest=false \
       --title "axross tour videos ($TOURS)" \
       --notes "The narrated videos of Help > Tours; axross downloads them on demand." \
       V/release/*.mp4
   gh api repos/c0decave/axross/releases/latest --jq .tag_name   # still a vX.Y.Z tag
   ```

   (`VIDEOS` is the folder `scripts/tour_videos.py manifest --videos`
   wrote.) If the last command prints anything but a version tag, fix it at
   once: `gh release edit "$TOURS" --prerelease --latest=false` and
   `gh release edit v<the previous version> --latest`.

8. **maintainer** - assemble, sign and check the release, with the
   **field key**: a key of `FIELD_KEYS` in `scripts/sign_release.py`, the
   key the binaries in use pin (for 0.15.177 that is the first key,
   `rJX0yymA5/...`; see "Key rotation" below):

   ```bash
   .venv/bin/python scripts/assemble_release.py --version "$VERSION" \
       --ci "dist/$VERSION-ci" --out "dist/release-$VERSION" \
       --key /path/to/release-key.pem --require-all
   ```

   `--ci` alone takes the Linux dist from its `axross-linux-dist` (a
   folder, or the `.zip` the web page hands out); with a builder's
   folder add `--dist "dist/$VERSION"` - it is used instead, and the
   summary says so.

   `scripts/assemble_release.py` renames everything to the asset names of
   the contract below, checks every input against the checksum its build
   wrote and drops those files (the per-folder `SHA256SUMS`, the CI's
   `.sha256`), writes one `SHA256SUMS` (first line `# axross-release
   $VERSION`, a line for every binary, attached pack wheel, the manifest,
   wheel and sdist), signs it through `scripts/sign_release.py`, writes
   `dist/release-$VERSION/notes.md` (the `CHANGELOG.md` section,
   `NATIVE-COMPONENTS.md`, the assets, how to verify them with their
   checksums) and then checks the result through `core.self_update` and
   `core.packs` themselves: every kind of installed binary (platform,
   machine, flavour, glibc variant, with and without the marker files of
   older bundles) finds its asset and its line, the signature verifies with
   the field keys alone, the pack manifest is what a base accepts, the
   API's answer stays within the updater's 1 MiB, and everything an
   updater needs is among the **first 100 assets** of the API's answer.
   GitHub lists a release's assets **sorted by name, ignoring case** - not
   in upload order (measured 2026-11-08: `releases/latest` returns every
   asset in one answer, in that order) - and the updater of 0.14.136, in
   every installed binary, reads only the first 100. `SHA256SUMS` sorts
   after every `axross-*`, `dep*` and `packs-*` name: with all ~160 pack
   wheels attached it would be asset 151 of 180, and every installed
   binary would refuse the update. So the pack wheels are attached only
   when PyPI does not have them (`--pack-wheels unhosted`, the default:
   those built from an sdist, whose manifest entry names no PyPI address);
   a base fetches every other wheel from `files.pythonhosted.org` and
   checks it against the SHA-256 and size of the signed manifest
   (`core.packs`). The release then has well under 100 assets (about 25).
   `--pack-wheels all` attaches every wheel and is refused while it pushes
   anything the updater needs past the first 100 (checked in GitHub's
   order, folded to upper case, in byte order and in upload order).
   It refuses on any problem; `--require-all` also refuses when an input
   is missing (without it, a partial release - Linux only, no packs - is
   assembled and the summary names what is missing). The Linux dist
   must be the tag's build: a `BUILD-INFO.md` naming another commit
   ("From commit ...") than this repository's tag `v$VERSION` is refused
   (the `linux` job also builds `ci/` branches and runs by hand); without
   the tag, or without that line, the check is named as missing. A
   re-issue of the pack manifest under the same version adds
   `--packs-issue N` (see below).

9. **maintainer** - a **draft** release with the assets. The updater asks
   for `releases/latest`, which never returns a draft, so nothing installed
   sees it yet. Then the draft as GitHub holds it is checked against the
   assembled folder - GitHub's own order, names, sizes and digests:

   ```bash
   (cd "dist/release-$VERSION" &&
    gh release create "v$VERSION" --draft --verify-tag --title "axross $VERSION" \
        --notes-file notes.md $(cat upload-1.txt) &&
    gh release upload "v$VERSION" $(cat upload-2.txt))
   gh release download "v$VERSION" -D "dist/draft-$VERSION"
   ID=$(gh release view "v$VERSION" --json databaseId --jq .databaseId)
   gh api "repos/c0decave/axross/releases/$ID" > "dist/draft-$VERSION.json"
   .venv/bin/python scripts/assemble_release.py --version "$VERSION" \
       --check "dist/draft-$VERSION" --api-json "dist/draft-$VERSION.json" --require-all
   ```

   (`--release-id "$ID"` instead of `--api-json` runs that `gh api`
   itself, on github.com.) The check refuses an asset that is not
   uploaded, one left over on GitHub, a size or digest that differs, and
   anything an updater needs past the first 100 in GitHub's order.

10. **maintainer** - TestPyPI, then a clean install from it:

   ```bash
   A="dist/release-$VERSION/assets"
   .venv/bin/twine check --strict "$A/axross-$VERSION.tar.gz" "$A/axross-$VERSION-py3-none-any.whl"
   .venv/bin/twine upload --repository testpypi \
       "$A/axross-$VERSION.tar.gz" "$A/axross-$VERSION-py3-none-any.whl"
   python3 -m venv /tmp/axross-testpypi
   /tmp/axross-testpypi/bin/pip install --index-url https://test.pypi.org/simple/ \
       --extra-index-url https://pypi.org/simple/ "axross==$VERSION"
   /tmp/axross-testpypi/bin/axross --version
   ```

11. **maintainer** - publish the GitHub release
   (`gh release edit "v$VERSION" --draft=false --latest`), then check
   that an **installed 0.14.136 binary updates**: on a machine that is not
   the builder, take `axross-full` (and `axross-slim`) of the v0.14.136
   release, start it, *Help > Check for Updates...*, *Download*, *Restart
   Now*; it must offer `$VERSION`, accept the signature and start as
   `$VERSION` (`./axross-full --version`). The same for an axross-slim on
   macOS and on Windows where one is at hand. If it refuses, turn the
   release back into a draft at once (`gh release edit "v$VERSION"
   --draft=true`): installed binaries then see the previous release again.
   Before that, the release GitHub now calls the latest must be this one:

   ```bash
   gh api repos/c0decave/axross/releases/latest --jq .tag_name     # v$VERSION
   ID=$(gh release view "v$VERSION" --json databaseId --jq .databaseId)
   .venv/bin/python scripts/assemble_release.py --version "$VERSION" \
       --check "dist/draft-$VERSION" --release-id "$ID" --require-all
   ```

12. **maintainer** - PyPI, last: an upload there cannot be replaced.

    ```bash
    .venv/bin/twine upload "$A/axross-$VERSION.tar.gz" "$A/axross-$VERSION-py3-none-any.whl"
    ```

    Then open a new "Unreleased" section in `CHANGELOG.md`.

Optional, **maintainer**: the MCP Docker image (`docker build -f
Dockerfile.mcp -t axross-mcp:$VERSION .`), and the source tarball
(`axross-<version>.tar.gz` + `.sha256` + `.sha512`) from
`scripts/build_release.sh --tarball`: the committed files of `HEAD`, never
untracked ones, and in a private tree the scrubbed mirror that
`scripts/export-public.py --mirror` writes; see
[DEVELOPMENT.md](DEVELOPMENT.md#building-a-release-tarball) for its
identity-terms file. `--write` instead of `--check` of
`native_inventory.py` regenerates the "Native files inside the Linux
binaries" table of THIRD_PARTY_LICENSES.md when the lock or the builder
image changed. Without `SHA256SUMS.sig` no installed binary updates (see
below).

## Self-update: what a release must carry

The one-file binaries update themselves (`core/self_update.py`,
*Help → Check for Updates…*, *Settings → Updates*; user side in
[USAGE.md](USAGE.md#updates)). They find the release through
`https://api.github.com/repos/c0decave/axross/releases/latest` (drafts and
prereleases are ignored) and rely on this contract - a release that breaks
it is refused by every installed binary, nothing is replaced:

* **Tag** `vX.Y.Z` (numeric, no suffix). Only a higher `X.Y.Z` than the
  running one is offered. The release GitHub marks "Latest" must be such
  a release: one under another tag (the tour videos' `tour-videos-N`)
  stops every check ("... is not an axross version") - it is created as a
  prerelease with `--latest=false` (step 7).
* **Asset names**, exactly: `axross-full`, `axross-slim`, `axross-base`
  (Linux x86-64, glibc 2.34 - the AlmaLinux 9 build), `axross-full-glibc2.36`,
  `axross-slim-glibc2.36`, `axross-base-glibc2.36` (the Debian 12 build),
  `axross-slim-macos-arm64`, `axross-slim-windows-x64.exe`. A binary picks
  its own: `build/axross.spec` writes the flavour into the bundle as
  `axross/axross-bundle-flavor.txt` (`full` / `slim` / `base`) and the
  variant as `axross/axross-bundle-variant.txt` (`glibc-2.34` / `glibc-2.36`;
  in the first-party folder, so the bundle gate claims them); a bundle
  without the variant file is a glibc-2.34 one (every binary before
  0.15.166), one without the flavour file is recognised by a file name
  starting with `axross-full` / `axross-slim`.
* **Packs** (`core/packs.py`, docs/PACKS.md): `packs-<version>.json`
  from `dist/<version>/packs/` as an asset of the same release, with a
  line in the release's `SHA256SUMS`. The manifest names every unit (a pip
  extra, a bundled extension, a feature group) with its wheels, their
  sizes, SHA-256 and PyPI addresses. A wheel the manifest gives no PyPI
  address (built from an sdist) is an asset as well, with its line in
  `SHA256SUMS`; the others are fetched from `files.pythonhosted.org` (an
  asset of the same name would be taken first). A base checks the
  signature of `SHA256SUMS`, the manifest against it and every wheel
  against the manifest (and an attached one against `SHA256SUMS` too)
  before it unpacks anything; an update of a binary brings its installed
  units along (the new release's) before the new binary is fetched.
  Platforms without an asset (Linux aarch64, an axross-full on macOS) only
  get the notice with the release page.
* **At most 100 assets that matter**: GitHub lists the assets sorted by
  name, ignoring case; the updater of 0.14.136 reads only the first 100 of
  the answer, so `SHA256SUMS`, `SHA256SUMS.sig` and every binary asset
  above must sort into them (`scripts/assemble_release.py` refuses
  otherwise). The updater from 0.15.177 on reads every asset of the answer
  (and the asset pages, should an answer end at exactly 100).
* **`SHA256SUMS`** among the assets of the same release, in `sha256sum`
  format, with one line per binary (`scripts/assemble_release.py`, step 8
  of the release flow). No line for the
  binary, or a different hash: refused. GitHub's own `digest` of an asset,
  where the API gives one, must agree with it as well.
* **`SHA256SUMS.sig`**, the detached signature of `SHA256SUMS` (step 8):
  the **raw 64-byte Ed25519 signature** of the exact bytes of
  `SHA256SUMS` (not base64, nothing normalised - CRLF or a missing final
  newline are signed as they are). The binaries pin the public release
  key, raw 32 bytes in base64, in `core/self_update.py` `TRUSTED_KEYS`
  (`rJX0yymA5/Mbw24qIpuLNaLqC/FbvugEREz1p0pSz68=`, and from 0.15.176 on also the next key
  `INHsCyIzJ305W1+SvRkrEMuaO7puYtlgnhP72N6+mcw=`). The signature is
  checked after `SHA256SUMS` and the signature are fetched and before any
  entry of `SHA256SUMS` is read or the binary is fetched. Refused: no
  `SHA256SUMS.sig` asset, one that is larger than 64 bytes (not even
  downloaded), one of any other size, one that differs from GitHub's
  digest of it, or one that does not verify with a pinned key (a
  `SHA256SUMS` changed after signing, another key). The checksums and
  GitHub's digests come from the release itself and only catch a broken
  download; the signature is what someone who can change the release
  cannot make.
  `scripts/sign_release.py <key.pem> <SHA256SUMS>` writes it next to
  `SHA256SUMS`: the key is a PEM private Ed25519 key (`openssl genpkey
  -algorithm ed25519 -out release-key.pem`; an encrypted one asks for its
  passphrase), refused when group or others can read the file or when it
  is a symlink; no key material is printed, only the derived public key;
  a key not pinned in `TRUSTED_KEYS` is refused unless `--allow-unpinned`
  is given, a pinned key outside `FIELD_KEYS` unless `--allow-new-key` is
  (see "Key rotation"); the new signature is verified with the derived public key,
  through the updater's own check, before the file is written.
  **The signature names the version:** `SHA256SUMS` starts with
  `# axross-release X.Y.Z` (`--version` adds it), and the updater refuses
  a release whose signed line names no version or another one than its
  tag - an old release's signed checksums published under a new tag
  would otherwise install that old, perhaps vulnerable, build. The
  updater also refuses a release that is not newer than the running
  version (`core.self_update.update` / `download`, not only the check).
  **The signature numbers a pack re-issue:** `--packs-issue N` adds
  `# axross-packs-issue N` right after the release line (signed with it).
  The first publication of a release may leave it out (issue 0); each
  re-issue of `packs-<version>.json` under the same version takes the
  next number. `core.packs` keeps the highest issue installed in
  `installed.json` and refuses a lower one - an earlier signed issue
  uploaded again would otherwise roll a fixed pack back - and another
  manifest under the installed number (a re-issue without
  `--packs-issue` is refused by the binaries that have it). Installed
  binaries of 0.14.50 and later read only the checksum lines
  (`parse_sums`) and the `# axross-release` line: they ignore it.
  **Key rotation:** `TRUSTED_KEYS` is a tuple and any one key verifying
  is enough. An installed binary checks only the latest release and only
  with the keys it was built with, so a rotation takes three releases:
  (1) a release adds the new public key to `TRUSTED_KEYS` and is still
  signed with the old key; (2) **the new key may sign only once a release
  that is signed with the old key and pins both keys has been published
  *with its binaries*** (every asset of the contract above, so that each
  installed binary that updates lands on one that trusts both keys) **and
  the binaries in use have updated to it** - a binary older than that
  release which has not updated by then refuses every release signed with
  the new key and must be replaced by hand from the release page; (3) a
  later release drops the old key. A release without binaries (0.15.176)
  does not count for (2): nothing installed carries its keys.
  `scripts/sign_release.py` holds the keys the binaries in use pin in
  `FIELD_KEYS` and refuses any other key - a pinned key outside it too;
  `--allow-new-key` signs anyway, with a warning, and is right only once
  (2) holds; with it, the new key moves into `FIELD_KEYS` (and
  `tests/test_sign_release_field_keys.py`, which holds `FIELD_KEYS` to
  the keys of the newest release with binaries).
  **Rotation under way:** 0.15.176 pins both keys and is signed with the
  first one, but it shipped no binaries; every installed binary (0.14.136
  and older) pins only the first key. So **0.15.177 is signed with the
  first key** (`rJX0yymA5/...`, the only entry of `FIELD_KEYS`), pins both
  and carries every binary: it is the release of step (2). The second key
  signs at the earliest the release after it, once the 0.15.177 binaries
  are in use; a later release then drops the first key.
  **Migration:** binaries of 0.14.50 and older do not check signatures;
  they pick their assets by exact name (`axross-full`, `SHA256SUMS`, ...)
  and ignore `SHA256SUMS.sig`, so they keep updating - into a binary
  that checks it from then on.
* **Hosts**: the API on `api.github.com`; the download URL
  `https://github.com/c0decave/axross/releases/download/vX.Y.Z/<name>`
  answers 302 to `release-assets.githubusercontent.com` (measured
  2026-10-25; `objects.githubusercontent.com` before). Only these four
  hosts, only https, at most five redirects; bounds: 1 MiB for the API
  answer, 64 KiB for `SHA256SUMS`, 64 bytes for `SHA256SUMS.sig`, 1 GiB
  for a binary, which must have exactly the size the API states. A base
  fetches a pack wheel that is not an asset from `files.pythonhosted.org`.

A distribution package (deb, rpm, a container image) must not replace
itself: start it with `AXROSS_NO_UPDATE_CHECK=1` in the environment (no
check at start; *Check Now* still asks), and install the binary in a
folder the user cannot write to - the update then saves the verified file
in `~/.cache/axross/update/` and leaves the installed one alone. A Python
install (wheel, sdist, source tree) is never replaced; it is told
`pip install -U axross`. The smoke start (`AXROSS_SMOKE_GUI_MS`) never
checks.
