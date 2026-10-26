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
| `localhost/axross-gui:latest` (podman)   | ~990 MB | `scripts/axross-podman.sh build` (`Dockerfile.gui`) |

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

Suggested sequence for a tagged release:

```bash
# 1. Clean venv + deps (catches accidental dev leftovers)
rm -rf .venv
uv venv
.venv/bin/pip install -e ".[all,adb,archive]"

# 2. Run the full regression
QT_QPA_PLATFORM=offscreen .venv/bin/pytest -q \
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

# 5. The binaries against a current host (see "What comes from the host")
AXROSS_FROZEN_BINARY=dist/axross-full .venv/bin/python -m pytest tests/test_frozen_binary_host_e2e.py
AXROSS_FROZEN_BINARY=dist/axross-slim .venv/bin/python -m pytest tests/test_frozen_binary_host_e2e.py

# 6. Sha256 everything
( cd dist && sha256sum axross-* ) | tee dist/SHA256SUMS

# 7. Sign SHA256SUMS with the release key (writes dist/SHA256SUMS.sig)
.venv/bin/python scripts/sign_release.py /path/to/release-key.pem dist/SHA256SUMS
```

Checksums go into the release notes. `SHA256SUMS` and `SHA256SUMS.sig`
are both release assets; without the signature no installed binary
updates (see below). Linux AppImage signing
(`gpg --detach-sign dist/axross-full-x86_64.AppImage`) is a
nice-to-have on top.

## Self-update: what a release must carry

The one-file binaries update themselves (`core/self_update.py`,
*Help → Check for Updates…*, *Settings → Updates*; user side in
[USAGE.md](USAGE.md#updates)). They find the release through
`https://api.github.com/repos/c0decave/axross/releases/latest` (drafts and
prereleases are ignored) and rely on this contract - a release that breaks
it is refused by every installed binary, nothing is replaced:

* **Tag** `vX.Y.Z` (numeric, no suffix). Only a higher `X.Y.Z` than the
  running one is offered.
* **Asset names**, exactly: `axross-full`, `axross-slim` (Linux x86-64),
  `axross-slim-macos-arm64`, `axross-slim-windows-x64.exe`. A binary picks
  its own: `build/axross.spec` writes the flavour into the bundle as
  `axross/axross-bundle-flavor.txt` (`full` / `slim`; in the first-party
  folder, so the bundle gate claims it); a bundle without it is
  recognised by a file name starting with `axross-full` / `axross-slim`.
  Platforms without an asset (Linux aarch64, an axross-full on macOS) only
  get the notice with the release page.
* **`SHA256SUMS`** among the assets of the same release, in `sha256sum`
  format, with one line per binary (step 6 above). No line for the
  binary, or a different hash: refused. GitHub's own `digest` of an asset,
  where the API gives one, must agree with it as well.
* **`SHA256SUMS.sig`**, the detached signature of `SHA256SUMS` (step 7):
  the **raw 64-byte Ed25519 signature** of the exact bytes of
  `SHA256SUMS` (not base64, nothing normalised - CRLF or a missing final
  newline are signed as they are). The binaries pin the public release
  key, raw 32 bytes in base64, in `core/self_update.py` `TRUSTED_KEYS`
  (`rJX0yymA5/Mbw24qIpuLNaLqC/FbvugEREz1p0pSz68=`). The signature is
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
  is given; the new signature is verified with the derived public key,
  through the updater's own check, before the file is written.
  **Key rotation:** `TRUSTED_KEYS` is a tuple and any one key verifying
  is enough. Add the new public key in a release signed with the old key,
  sign with the new key only once the binaries in use carry it, then
  drop the old one.
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
  for a binary, which must have exactly the size the API states.

A distribution package (deb, rpm, a container image) must not replace
itself: start it with `AXROSS_NO_UPDATE_CHECK=1` in the environment (no
check at start; *Check Now* still asks), and install the binary in a
folder the user cannot write to - the update then saves the verified file
in `~/.cache/axross/update/` and leaves the installed one alone. A Python
install (wheel, sdist, source tree) is never replaced; it is told
`pip install -U axross`. The smoke start (`AXROSS_SMOKE_GUI_MS`) never
checks.
