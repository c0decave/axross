<p align="center">
  <img src="https://raw.githubusercontent.com/c0decave/axross/main/resources/logo/axross-logo-256.png" alt="Axross" width="160"/>
</p>

# Axross

**One UI for 30+ file, cloud, network, legacy, database, scripting,
and MCP workflows.**

- **30+ protocols in one window** — SFTP, SMB, S3, WebDAV, cloud drives, IMAP, Git, databases and more.
- **Copy between any two backends** — S3 → SFTP, WebDAV → SMB, directly, no detour via local disk.
- **Commander-style multi-pane layout** — as many split panes as you like, layout presets, drag & drop.
- **Workspaces** — named pane layouts as tabs, detachable into their own window, restored on the next start, any dock shown only on one workspace.
- **An LLM agent built in** — Agent dock with tabs and sandboxes for LM Studio, Ollama, vLLM or llama.cpp, read-only by default.
- **Talk to the agent** — push-to-talk, spoken answers in German and English, speech recognition locally or on the LLM server.
- **MCP server and client** — LLMs drive axross over stdio or HTTP, and the agent uses the tools of further MCP servers.
- **Built-in Python scripting** — REPL, Scripts dock and 32 ready-made scripts on one `axross.*` API.
- **Tabbed text editor** — syntax highlighting, find/replace, encodings and line endings, for local and remote files.
- **Find Files** — by name, type, content, size or tag, inside archives too, kept as a Smart Folder.
- **Coloured tags** — on any file, following renames and moves, a filter in Find Files.
- **Disk images and forensics** — partitions and file systems, read-only loop mount, hashes, The Sleuth Kit, PhotoRec.
- **Media Player and Audio Mixer** — eighteen visualizations, a sleep timer; per-source volume and output, one equalizer, PipeWire/PulseAudio.
- **Find duplicates, strip metadata** — content-hash duplicate finder, EXIF/GPS removal before sharing.
- **Encryption without plaintext on disk** — `.axenc` overlay on any backend, decrypted into RAM only.
- **Safe by default** — preview before delete/move, operation journal, `paranoid` mode, SSRF-guarded proxies.
- **Resumable transfers** — survive Ctrl-C and VPN drops, resume from the last verified segment.
- **Archives as folders** — browse ZIP, TAR and 7z, nested ones too, extract only what you pick, zip-bomb-safe.
- **Extensions** — Bluetooth (Classic, BLE map, add a headset in one go), System Information, Forensic Tools, Treemap and more, each off until you switch it on.
- **Install in one line** — `pip install axross`, or a single-file binary for Linux, macOS and Windows.

> **Checked for malicious code.** Every dependency a release is built from - 254 pinned
> packages: the application's, the binaries', the build tools' - passes axross's own
> supply-chain gate before anything is built: OSV (advisories and the malicious-packages
> feed), YARA (GuardDog's and axross's rules), an inspection of every file without running
> it, native binaries profiled and analysed with capa, Sigstore provenance, typosquatting,
> a 14-day minimum age. **Result of the review of 2026-11-05: no malicious code found.**
> Every YARA hit was read in the code and is benign; two findings were handled -
> onnxruntime's telemetry (switched off by axross) and a process-wide TLS bypass in
> `impacket.examples` (never imported). Still running: capa's full analysis of 200 large
> native binaries (mostly Qt's libraries) in night sessions. The tool, its method and every
> finding: [docs/SUPPLY_CHAIN_GATE.md](https://github.com/c0decave/axross/blob/main/docs/SUPPLY_CHAIN_GATE.md) (`security/supply_chain_gate.py`); each
> dist carries its report as `SUPPLY-CHAIN.md`.

Axross is a multi-protocol file manager and security toolkit built
with Python and PyQt6. It gives you a split-pane desktop UI, a
headless MCP server mode for LLM agents, and a public `axross.*`
Python scripting API from the same package.

The project is currently beta: useful, broad, and actively hardened,
but still moving quickly.

## Binaries: which axross?

Every [release](https://github.com/c0decave/axross/releases/latest) carries single-file programs - download, `chmod +x`,
start; no Python needed - and the Python package:

| File | What is in it | Runs on |
|---|---|---|
| `axross-full` | everything: every backend (with Google Drive, OneDrive, Dropbox, Azure, Exchange, WinRM/WMI), every extension, Matrix/XMPP chat, the Media Player's equalizer and spectrum, the Bluetooth stick mode, voice and analysis | Linux x86-64 with glibc 2.34 or newer (RHEL / Alma / Rocky 9, Ubuntu 22.04, Debian 12, Fedora 35 and later) |
| `axross-slim` | the same without the cloud SDKs, the Windows protocols, Matrix/XMPP, voice, analysis and numpy - SFTP, SMB, WebDAV, S3, FTP, Android and the rest are in it; about half the size | the same |
| `axross-base` | the core only: local files, SFTP / SCP / FTP, the panes, the editor, the terminal, the settings. Everything else - each backend, each extension - is a *pack* you add from *Help → Features… → Packs…*: fetched from the same release, signature and SHA-256 checked before anything is unpacked | the same |
| `axross-full-glibc2.36`, `axross-slim-glibc2.36`, `axross-base-glibc2.36` | the same three, built with Debian 12's (newer) libraries | Linux x86-64 with glibc 2.36 or newer (Debian 12+, Ubuntu 22.10+, Fedora 37+) |
| `axross-slim-macos-arm64` | slim | macOS on Apple silicon (not notarized: [first start](https://github.com/c0decave/axross/blob/main/docs/PACKAGING.md#macos-binary-the-first-start)) |
| `axross-slim-windows-x64.exe` | slim | Windows 10 / 11, x64 |
| `axross-media-player`, `axross-system-info` (and `-glibc2.36`) | the Media Player and System Information as programs of their own ([docs/STANDALONE.md](https://github.com/c0decave/axross/blob/main/docs/STANDALONE.md)) | Linux x86-64 |
| `axross-X.Y.Z.tar.gz`, `axross-X.Y.Z-py3-none-any.whl` | the Python package, the same as on PyPI (this page) | every system with Python 3.11+ |
| `packs-X.Y.Z.json` and the wheels beside it | the packs an `axross-base` adds | - |
| `SHA256SUMS`, `SHA256SUMS.sig` | the checksums of every file, signed with the axross release key (Ed25519) | - |

Which glibc you have: `ldd --version`. The glibc 2.34 build runs on newer systems
too; the glibc 2.36 one brings newer libraries along. Every binary updates
itself to the next release of exactly its own kind (*Help → Check for
Updates…*, signature checked), an `axross-base` with the packs it has.

## Install

Base install:

```bash
python -m venv .venv
source .venv/bin/activate
pip install axross
axross
```

Install the common light protocol extras:

```bash
pip install "axross[all]"
```

Pick individual extras when you only need selected backends:

```bash
pip install "axross[smb]"       # SMB / CIFS + DFS-N
pip install "axross[s3]"        # S3-compatible storage
pip install "axross[webdav]"    # WebDAV
pip install "axross[gdrive]"    # Google Drive
pip install "axross[dropbox]"   # Dropbox
pip install "axross[postgres]"  # PostgreSQL-as-FS
pip install "axross[redis]"     # Redis-as-FS
pip install "axross[mongo]"     # MongoDB GridFS
pip install "axross[git]"       # Git-as-FS via dulwich
```

Heavy or platform-sensitive extras stay explicit:

```bash
pip install "axross[winrm]"
pip install "axross[wmi]"
pip install "axross[exchange]"
pip install "axross[fuse]"
```

On minimal Debian/Ubuntu containers, install Qt loader libraries before
launching the GUI:

```bash
apt-get update
apt-get install -y --no-install-recommends \
    libglib2.0-0 libgl1 libegl1 libfontconfig1 libxkbcommon0 libdbus-1-3
```

Headless modes (`--help`, `--script`, `--mcp-server`) work without
those GUI libraries.

## First Checks

```bash
axross --version
axross --help
python -m axross --help
python - <<'PY'
import axross
print(axross.__version__)
print(axross.localfs().list_dir(".")[:3])
PY
```

Launch modes:

```bash
axross                         # desktop GUI
axross --script script.py      # run an axross automation script
axross --mcp-server            # stdio MCP server for local agents
axross --mcp-server --mcp-http 127.0.0.1:7331
```

## What It Can Talk To

Core backends include SFTP/SCP, FTP/FTPS, SMB/CIFS, WebDAV,
S3-compatible storage, Rsync, NFS, Azure Blob/Files, OneDrive,
SharePoint, Google Drive, Dropbox, iSCSI, IMAP, POP3, TFTP,
Telnet, WinRM, WMI/DCOM, Exchange, DFS-N, ADB, MTP, Gopher,
NNTP/Usenet, SQLite-FS, PostgreSQL-FS, Redis-FS, MongoDB GridFS,
Git-as-FS, PJL printer-FS, SLP discovery, rsh/rcp, Cisco IOS
Telnet, and a RAM-only volatile workspace.

## Scripting API

The package exposes the same curated API used by the embedded REPL:

```python
import axross

local = axross.localfs()
for item in local.list_dir(".")[:5]:
    print(item.name, item.size)
```

In the GUI, the bottom Console dock adds persistent history, docs,
slash commands, and bundled scripts such as mirror, dedupe,
find-secrets, port-scan, SLP inventory, Cisco IOS collection,
IMAP archive, checksum diff, and TFTP audit.

Runnable scripting examples ship with the package under
`examples/scripting_api/`. The local examples are tested without
network access, and the Docker-lab examples exercise protocol-backed
recipes against `tests/docker/docker-compose.yml`.

## Multi-System Workflows

Recent releases add operational workflow verbs on top of the core
backends:

- `axross.where_was_i()` recalls recently touched hosts and paths.
- `axross.health_pulse()` reports live latency / stale-session state.
- `axross.compare_file()` and `axross.inspect_targets()` compare files
  across hosts and protocols.
- `axross.federated_search()` fans one query out across many backends.
- `axross.resumable_copy()` adds checkpoint-resume for cross-backend
  transfers.
- `axross.dashboard()` renders one-screen federation status.
- `axross.snapshot_now()` / `axross.start_trail()` keep SQLite
  time-lapse metadata for directory trees.
- `axross.serve_s3()` and `axross.serve_webdav()` expose any opened
  backend through local S3-compatible or WebDAV endpoints.

Credential-testing helpers (`axross.bruteforce`, `axross.spray`,
`axross.enumerate_users`) are available for authorised assessments
only and require an explicit `authorized=True` gate.

## Safety Defaults

Axross is designed for operational work:

- mutating operations can be previewed
- destructive actions write redacted structured logs
- an append-only operation journal records high-risk actions
- plaintext legacy protocols show credential warnings
- SSRF guards protect proxy hops by default
- paranoid mode can disable scripts, previews, external viewers,
  legacy protocols, and private proxy overrides

## Documentation

- Full README: https://github.com/c0decave/axross
- Installation and extras: https://github.com/c0decave/axross/blob/main/INSTALL.md
- User guide: https://github.com/c0decave/axross/blob/main/docs/USAGE.md
- Scripting: https://github.com/c0decave/axross/blob/main/docs/SCRIPTING.md
- Scripting reference: https://github.com/c0decave/axross/blob/main/docs/SCRIPTING_REFERENCE.md
- Scripting examples: https://github.com/c0decave/axross/tree/main/examples/scripting_api
- Multi-system workflows: https://github.com/c0decave/axross/blob/main/docs/MULTI_SYSTEM.md
- Daily-driver primitives: https://github.com/c0decave/axross/blob/main/docs/DAILY_DRIVER.md
- Reverse-serve: https://github.com/c0decave/axross/blob/main/docs/REVERSE_SERVE.md
- Trail / time-lapse: https://github.com/c0decave/axross/blob/main/docs/TRAIL.md
- Authorised credential testing: https://github.com/c0decave/axross/blob/main/docs/CRED_ATTACK.md
- MCP server: https://github.com/c0decave/axross/blob/main/docs/MCP.md
- OPSEC notes: https://github.com/c0decave/axross/blob/main/docs/OPSEC.md

## License

Axross is released under the Apache License 2.0. See the source
repository for the full license, notice, and third-party attribution
files.
