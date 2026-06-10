<p align="center">
  <img src="https://raw.githubusercontent.com/c0decave/axross/main/resources/logo/axross-logo-256.png" alt="Axross" width="160"/>
</p>

# Axross

**One UI for 30+ file, cloud, network, legacy, database, scripting,
and MCP workflows.**

Axross is a multi-protocol file manager and security toolkit built
with Python and PyQt6. It gives you a split-pane desktop UI, a
headless MCP server mode for LLM agents, and a public `axross.*`
Python scripting API from the same package.

The project is currently beta: useful, broad, and actively hardened,
but still moving quickly.

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
