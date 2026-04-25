# Using Axross

This guide covers what you can do once Axross is running. For
installation see [INSTALL.md](../INSTALL.md); for the full German
manual see [HANDBUCH.md](HANDBUCH.md).

Languages: **English** · [Deutsch](USAGE_de.md) · [Español](USAGE_es.md)

## At a glance

Axross is a Total-Commander-style file manager for 22 protocols,
built around three ideas:

- **Multi-pane layout.** Split horizontally / vertically into as many
  panes as you like; each pane connects to its own backend (local,
  SFTP, S3, IMAP, anything).
- **Backend-agnostic primitives.** Trash, atomic writes, encrypted
  overlays, version timeline, content-addressable storage — all of
  these work on every protocol, even the ones whose native API
  doesn't support them.
- **MCP server mode.** Axross can run headless and expose any
  configured backend as MCP tools, so an LLM client can drive it.
  Read-only by default; opt-in `--mcp-write` for mutations.

## Connections

The Connection Manager (Ctrl+N) is where you create profiles. Each
profile selects a protocol and stores host / username / auth /
proxy / per-protocol options. Sensitive fields (passwords, OAuth
secrets, Azure connection strings) go to the OS keyring; profile
JSON itself never carries plaintext credentials.

- **Host-key verification.** First-time SSH targets show a SHA-256
  fingerprint dialog before the connection completes; trusted keys
  persist to `~/.ssh/known_hosts`.
- **OAuth flows.** OneDrive / SharePoint / Google Drive / Dropbox
  open a browser for the consent step. Tokens are cached at
  `~/.config/axross/<provider>_token.json` with `0o600` from birth.
  See [OAUTH_SETUP.md](../OAUTH_SETUP.md) for the per-provider app
  registration recipe.
- **Proxy support.** Per-profile SOCKS5 / SOCKS4 / HTTP-CONNECT.
  SOCKS5 resolves hostnames server-side (no DNS leak); SOCKS4 falls
  back to local DNS by protocol design.
- **OpSec overrides.** Profile fields control SSH keepalive, SMB
  workstation name, Telnet NAWS, rsync metadata stripping. See
  [OPSEC.md](OPSEC.md) for the threat model.

## Multi-pane layout

- Add panes with **Ctrl+T**, split with **Ctrl+Shift+H** /
  **Ctrl+Shift+V**, close with **Ctrl+W**.
- Active pane gets a blue border; the **target** pane (where copies
  land) gets a green border. Last-focused pane becomes target.
- **Alt+Left / Alt+Right** walk through pane history; **Ctrl+Tab**
  cycles.
- Drag-and-drop between panes initiates a transfer (works for
  local↔remote, remote↔remote, cross-protocol).

## Transfers

Every cross-pane copy or move enters the transfer queue. The dock
at the bottom shows progress, throughput, and ETA. Transfers run on
worker threads and survive a refused dialog or a closed pane.

- **Atomic semantics.** Every write goes to a sibling temp file
  (`.tmp-<hex>.tmp`) and is renamed into place at the end. On
  S3 / Azure / Dropbox / GDrive / OneDrive / IMAP / Rsync the
  underlying upload is already atomic; on the rest the rename is
  the commit point.
- **Resume.** Failed transfers can be resumed; partial bytes on the
  destination are picked up where they left off.
- **Retry.** "Retry Failed" replays every error-state transfer in
  the queue.
- **Verify.** A per-job `verify_checksum` flag re-hashes the
  destination after the upload and rejects on mismatch.

## Filesystem feature layer

These primitives work on **any** backend, even the ones whose
native protocol doesn't support them.

| Module | What it gives you |
|---|---|
| `core.atomic_io` | `atomic_write(backend, path, data)` — native-atomic on S3 / Azure / Dropbox / GDrive / OneDrive / IMAP / Rsync; tmp-then-rename elsewhere. |
| `core.atomic_recovery` | Crash-recovery sweep for orphaned `.tmp-*.tmp` files. Per-pane navigate hook removes >1 h-old leftovers. Legacy `.axross-atomic-*.tmp` prefix still recognised. |
| `core.server_ops` | `server_side_copy` / `server_side_move` with automatic fallback to `open_read` + `open_write` when the backend has no native copy. |
| `core.watch` | File-watching API. Native inotify on LocalFS (with watchdog); polling everywhere else. Toggle in the path bar. |
| `core.trash` | Universal recycle bin: `trash` / `list_trash` / `restore` / `empty_trash`. Per-entry sidecar metadata, no central manifest. |
| `core.xlink` | Cross-protocol symlinks via `.axlink` JSON pointer files. |
| `core.encrypted_overlay` | AES-256-GCM at-rest encryption with PBKDF2-HMAC-SHA256 (200 k iterations). |
| `core.cas` | Content-addressable layer: SQLite index of `(backend, path) → checksum`, duplicate detection, `ax-cas://<algo>:<hex>` URLs. |
| `core.snapshot_browser` | Uniform timeline view across S3, Dropbox, GDrive, OneDrive, Azure Blob. |
| `core.metadata_index` | Offline SQLite search by name / ext / size / mtime. |
| `core.previews` | Local image thumbnailer with strict MIME allow-list, size caps, and a Qt-allocation gate. F3 / double-click. |
| `core.archive` | Safe extraction of zip / tar / 7z (`.zip .xpi .jar .war .apk .epub .docx .xlsx .odt .tar .tar.gz .tgz .tar.bz2 .tbz2 .tar.xz .txz .7z`). Zip-slip / bomb / lying-metadata guards; `.7z` needs the `[archive]` extra. |
| `core.elevated_io` | `pkexec`-gated local read for `/etc/shadow` etc. — Axross never holds the privilege itself. "Open as root…" context-menu entry. |
| `core.fuse_mount` | FUSE mount any FileBackend. Read-only by default; `writeable=True` enables create / write / unlink / mkdir / rename. Optional `[fuse]` extra. |
| `core.mcp_server` | Stdio-framed JSON-RPC MCP server exposing the configured backend as tools. `--mcp-write` adds mutating tools, capped to a path-traversal-safe root. |

## Right-click actions

| Action | Trigger | What it does |
|---|---|---|
| New Folder | Right-click | `backend.mkdir(path)` on every writeable backend. |
| New File… | Right-click | Zero-byte file via `backend.open_write(path).write(b"")`. |
| New Symlink… | Right-click | Two prompts. Visible only on `supports_symlinks=True` backends. |
| New Hardlink… | Right-click | Same shape; cross-device hardlinks surface as `OSError(EXDEV)`. |
| Find in Index | `Ctrl+Shift+F` | Search the offline metadata index by name / ext / size. |
| CAS Duplicate Finder | View menu | Group rows by content hash, copy `ax-cas://…` URLs. |
| Move to Trash | Right-click | Universal recycle bin. |
| Show Trash… | Right-click | Restore / permanently-delete dialog. |
| Show Versions… | Right-click | Snapshot browser — Save Version As, Restore as Current. |
| Show Checksum… | Right-click | Native checksum (S3 ETag, Drive md5, ssh sha256sum…) with stream-hash fallback. |
| Extract to folder… | Right-click on a supported archive | Same-named sibling folder, cancellable, with the `core.archive` safety guards. Local backends only. |
| Encrypt / Decrypt with passphrase | Right-click | AES-256-GCM. |
| Open as root… | Right-click | Local-only; routes through `pkexec`. Hidden when polkit/pkexec are missing. |
| Create XLink… | Right-click | Cross-protocol pointer file. |
| Mount as FUSE (read-only / read-write)… | Right-click | Two menu entries so the mount mode is upfront. Toggles to "Unmount FUSE" while mounted. |
| Batch Rename… | Right-click (multi-select) | Find/Replace or regex with live preview + atomic rename. |
| Permissions… | Right-click | chmod dialog with checkbox grid + octal input. |

## Path bar

- **Auto-refresh ◉** subscribes the pane to `core.watch`; debounced
  refresh on backend changes.
- **Live filter** types into the path bar to filter the listing in
  real time.
- **Bookmarks** bar (left dock) for one-click navigation; F8
  bookmarks the current path, F12 toggles the dock.

## Editors and viewers

- **Text editor** (built-in) — for files < 1 MB, with conflict
  detection on save.
- **Hex editor** — read-only; useful for triage on remote files.
- **Image viewer** — F3 / double-click, MIME-allow-listed, size-
  capped to keep Qt's allocator happy.
- **SSH terminal** — tabbed dock next to the transfer queue. Local
  PTY (`pty.fork()`) and remote SSH-over-paramiko are both
  available; the SSH variant reuses the existing connection rather
  than dialling a new one.

## Transfers, terminal, log dock

- The bottom strip has three tabs: **Transfers**, **Terminal**,
  **Log**. Each flashes amber when something happens off-screen
  (new transfer state, shell output, log line). Click clears the
  indicator.
- Right-click a transfer for **Cancel**, **Retry**, **Open
  destination folder**.

## MCP server

Axross can run as a Model Context Protocol server so an LLM client
(Claude Desktop, Cline, a custom agent) can drive any configured
backend through a JSON-RPC tool surface.

```bash
axross --mcp-server                                  # read-only, stdio
axross --mcp-server --mcp-write                      # add write tools (capped to a root)
axross --mcp-server --mcp-http 127.0.0.1:7331        # HTTP, loopback
```

17 tools (`list_dir`, `stat`, `read_file`, `checksum`, `search`,
`walk`, `grep`, `list_versions`, `open_version_read`, `preview` +
7 write tools when `--mcp-write` is set), `resources/*` endpoints,
`notifications/message` log forwarding, per-tool timeouts,
per-session token-bucket rate limits, HTTP sessions with SSE
progress streaming, optional multi-backend routing.

Full reference: **[docs/MCP.md](MCP.md)** (EN) · [MCP_de.md](MCP_de.md) (DE) · [MCP_es.md](MCP_es.md) (ES).

## Configuration files

- `~/.config/axross/profiles.json` — connection profiles (`0o600`).
- `~/.config/axross/bookmarks.json` — bookmark bar contents.
- `~/.config/axross/session.json` — pane layout at last close.
- `~/.config/axross/column_prefs.json` — per-pane column widths.
- `~/.config/axross/<provider>_token.json` — OAuth refresh tokens (`0o600`).
- `~/.local/state/axross/logs/axross.log` — rotating log file (5 MB, 3 backups).

## Where to go next

- **Just want to connect?** [OAUTH_SETUP.md](../OAUTH_SETUP.md) walks
  you through the cloud-storage app registrations.
- **Running on hostile networks?** [OPSEC.md](OPSEC.md) lists every
  client-to-server fingerprint Axross emits and how to suppress it.
- **Driving Axross from an LLM?** [MCP.md](MCP.md) is the canonical
  protocol reference.
- **Building or contributing?** [DEVELOPMENT.md](DEVELOPMENT.md)
  has the test suite, lab compose, and coverage matrix.
- **Full German manual?** [HANDBUCH.md](HANDBUCH.md).
