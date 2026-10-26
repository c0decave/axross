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

The Connection Manager (Ctrl+Shift+N) is where you create profiles;
Quick Connect (Ctrl+N) opens a saved one. Each
profile selects a protocol and stores host / username / auth /
proxy / per-protocol options. Sensitive fields (passwords, OAuth
secrets, Azure connection strings) go to the OS keyring; profile
JSON itself never carries plaintext credentials. A right click on a
profile in Quick Connect (or on the profile list of the Connection
Manager) offers *Delete Connection Config…*: after a question the
profile goes, with its stored password.

- **Missing features.** *Help > Features…* lists every optional
  feature - connections, file analysis and archives, external tools
  such as ripgrep, rsync or the forensic and VirtualBox extensions'
  qemu-img, Sleuth Kit, TestDisk / PhotoRec and VBoxManage - as
  installed or missing, with how to get
  it. *Install Selected* runs `python -m pip install …` in the Python
  that runs axross after a question naming the command (the output in
  the log, no restart needed for most); a frozen build links the
  axross-full download of the same release; a tool shows this system's
  package command to copy. Choosing a backend whose dependencies are
  missing, or analysing a file without sift, offers the same window.
- **Host-key verification.** First-time SSH targets show a SHA-256
  fingerprint dialog before the connection completes; trusted keys
  persist to `~/.ssh/known_hosts`.
- **OAuth flows.** OneDrive / SharePoint / Google Drive / Dropbox
  open a browser for the consent step (Dropbox then asks for the code it
  shows in a window). The connection dialog names, per service, what to
  create where; Google's client file fills both fields (Import Client JSON…).
  Tokens are cached at
  `~/.config/axross/<provider>_token.json` with `0o600` from birth.
  Profile proxies cover Axross-owned API/token traffic; the external
  browser consent page may use browser or system proxy settings.
  See [OAUTH_SETUP.md](../OAUTH_SETUP.md) for the per-provider app
  registration recipe.
- **Proxy support.** SOCKS4/4a, SOCKS5, HTTP CONNECT and HTTPS proxies
  (TLS to the proxy), with Basic, NTLM and Negotiate authentication,
  per profile or as one global default (*Edit → Settings… → Network &
  Proxy*, also *Tools → Network & Proxy…*) with
  a bypass list and a PAC script. SOCKS5 resolves hostnames at the proxy
  (no DNS leak); SOCKS4 sends host names as SOCKS4a. A "Test proxy"
  button reports which stage fails, and each pane shows its route.
  Backends that cannot be proxied fail closed instead of going direct.
  See [PROXY_SUPPORT.md](PROXY_SUPPORT.md).
- **OpSec overrides.** Profile fields control SSH keepalive, SMB
  workstation name, Telnet NAWS, rsync metadata stripping. See
  [OPSEC.md](OPSEC.md) for the threat model.

## Multi-pane layout

- Add panes by splitting with **Ctrl+Shift+H** /
  **Ctrl+Shift+V**, close with **Ctrl+W**.
- Active pane gets a blue border; the **target** pane (where copies
  land) gets a green border. Last-focused pane becomes target.
- A pane becomes the active one when the mouse rests in it for 0.5 s.
  **Edit → Settings… → General → Activate a pane** sets 0.5, 1, 2 or 3 s,
  or **On Click**. Keyboard
  focus follows only from another pane's file list, never out of a text
  field.
- **Alt+Left / Alt+Right** walk through pane history; **Tab** /
  **Shift+Tab** in a file list cycle the panes.
- Drag-and-drop between panes initiates a transfer (works for
  local↔remote, remote↔remote, cross-protocol). **Ctrl+X** / **Ctrl+V**
  cut and paste entries between any two folders (see Transfers).

### Workspaces — several layouts, on several screens

A workspace is a named pane layout of its own. **Workspace → New
Workspace → With File List** (**Ctrl+Alt+N**) opens one with a local pane,
**With Terminal** (**Ctrl+Alt+Shift+N**) one with a local shell; from the
second on, the workspaces show as tabs above the panes. **Ctrl+Alt+PgDown /
PgUp** switch them, and each one keeps its own source and target pane.

- **Several shells:** **Workspace → Add Terminal Pane** (also in the
  tab's right-click menu) puts another local shell into the workspace,
  side by side with the panes already there.
- **Rename:** double-click the tab, its right-click menu, or **Workspace
  → Rename Workspace…**.
- **Detach to Window** (Workspace menu or the tab's right-click menu)
  puts the workspace on a window of its own — move it to another
  screen. Closing that window brings the workspace back as a tab.
- **Move a pane:** **Workspace → Move Pane to Workspace** sends the
  active pane to another workspace (or a new one), or drag a pane's
  header onto a pane of another workspace or window. File panes and
  terminal panes drag alike (a terminal pane's ⇄ button moves it too);
  hold a dragged pane over a workspace tab for half a second and that
  tab opens, so a pane reaches a workspace in the background.
- **Extension panels** (Media Player, Drives Overview, Markdown Preview,
  …) are on all workspaces until you put one on a workspace: the ⇄
  button in its title bar (or a right click on the title bar) offers
  every workspace, **New Workspace** and **All Workspaces**, and
  **Workspace → Add Extension Panel** (also in the tab's right-click
  menu) brings a panel into a workspace. There it is a pane: it shows
  only with its workspace, goes along when the workspace is detached,
  drags by its title bar onto another pane and takes dragged panes, is
  resized by the splitter and evened out by **Equalize Pane Sizes**.
  Its [x] takes it out of the workspace; showing it again from the
  **Extensions** menu puts it back. Closing the workspace parks its
  panels on All Workspaces (hidden, with their state); switching the
  extension off takes its panels out and switching it on puts them back.
- **Close Workspace** closes it with its panes (it asks first); the
  last pane of a workspace closing closes the workspace. One workspace
  always stays.
- **Equalize Pane Sizes** (**Ctrl+Shift+E**) evens out the workspace on
  screen — also one that holds only terminals or extension panels.
- A layout preset (**View → Layout Preset**) replaces the panes of the
  current workspace only.
- All workspaces — names, order, the current one, layouts with their
  terminals, folders and extension panels, which are detached and where
  their windows are — come back on the next start (see below).

### The layout comes back on start

Closing axross saves the layout to `session.json`; the next start
rebuilds it automatically:

- the splitter tree with its sizes, the window geometry, the dock
  layout (which docks are open and where) and the theme;
- local panes on their folders — a folder deleted since then opens
  the home folder instead, without a dialog;
- local terminal panes as a fresh shell in the same place, in the
  folder the old shell was in (home when that folder is gone).

**A start never connects.** A pane or terminal of a saved connection
profile comes back as a placeholder, *Not connected — &lt;profile&gt;*,
with a **Reconnect** button. For a file pane, Reconnect connects
exactly like opening the profile from Quick Connect (password prompt,
host-key check) and puts the pane where the placeholder was, on its
saved folder. For a terminal it opens the profile's terminal the way a
layout preset does (stored password, no prompt). The restore runs no
scripts and no extensions, and Paranoid Security Mode is unchanged by
it.

*Restore the layout of the last session on start* (**Edit → Settings… →
General**, on by default) switches this off; the choice is stored in
`session.json` at once and a start then shows
the default single pane. A missing, unreadable or invalid
`session.json` also starts with the default layout; the reason is in
the log. **File > Restore Last Session** (**Ctrl+Shift+R**) still
rebuilds the saved layout on demand, and there remote file panes do
connect.

## Transfers

Before a copy or move (F5, F6, drag & drop) is queued, axross checks
the destination in the background and asks about every name that is
already there: Overwrite, Overwrite if Newer, Skip, Rename
(`name (1).ext`), each optionally for all remaining conflicts, or
Cancel (nothing is copied). Folders merge; the names inside them are
asked about. A skipped move keeps its source, and a file that appears
at the destination after the prompt fails its job instead of being
overwritten. A move removes its source only when the source still has
the size it had before it was copied; one that changed meanwhile (a log
still being written) fails its job and is kept.

**Cut and Paste.** *Cut* (Ctrl+X, or right-click > Cut) only remembers
the selected entries - nothing is removed, they are drawn dimmed while
the cut waits. *Paste* (Ctrl+V, or right-click > Paste, also on empty
space) in any pane - another folder, another connection - moves them
into that pane's folder as a move through the transfer queue: the same
name check as above, and each source is removed only after its own copy
completed and was checked, so a failed, cancelled or partial transfer
leaves it where it was. A cut that is never pasted removes nothing: a
new Cut replaces it, Esc in its pane drops it, closing the pane or
changing its connection drops it. Pasting into the folder the entries
came from does nothing; a folder pasted into itself is refused. The
cut is cleared once its move is queued.

Every cross-pane copy or move enters the transfer queue. The dock
at the bottom shows progress, throughput, and ETA. Transfers run on
worker threads and survive a refused dialog or a closed pane.

- **Atomic semantics.** Every write goes to a hidden sibling temp
  file (`.<name>.part-<job>-<fingerprint>`) and is renamed into place
  at the end. On
  S3 / Azure / Dropbox / GDrive / OneDrive / IMAP / Rsync the
  underlying upload is already atomic; on the rest the rename is
  the commit point.
- **Resume.** Failed transfers can be resumed; partial bytes on the
  destination are picked up where they left off. A transfer that
  failed because the destination is full removes its partial file.
- **Retry.** "Retry Failed" replays every error-state transfer in
  the queue, each failed transfer once.
- **Cancel All** also stops a copy or move whose folder walk is
  still running: none of its files is queued.
- **Verify.** A per-job `verify_checksum` flag re-hashes the
  destination after the upload and rejects on mismatch.
- **Parallel transfers.** *Edit → Settings… → Files & Panes →
  Parallel transfers* (1–8, default 1) lets several jobs run side by
  side, started in queue order; that hides the round trips of many
  small files on a slow link. A connection that cannot carry two jobs
  at once (SCP and every other protocol except local files, RAM
  workspaces, SFTP, SMB, FTP, WebDAV and S3) still runs its jobs one
  by one, and two jobs never write the same destination at once. A
  change applies to the jobs that start after it. Each SFTP job runs on
  an SSH channel of its own, and servers limit the channels per
  connection (OpenSSH `MaxSessions`, 10 by default). Each FTP transfer
  runs on a control connection of its own; servers often limit the
  connections per user or address, and an FTP connection whose server
  refuses a second login runs its jobs one by one.

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
| `core.metadata_index` | Offline SQLite search by name / ext / size / mtime. One file: `$AXROSS_METADATA_DB`, else `$XDG_DATA_HOME/axross/metadata.sqlite`, else `~/.local/share/axross/metadata.sqlite` (an index already at that old place stays in use). Filled only by *Index Active Folder…* (not by browsing) — see *The offline index* under *Find Files*. |
| `core.file_search` | The Find Files engine: name / type / content / size / date over folders of any backend, inside archives, streaming and cancellable; `fd` / `rg` locally when installed. |
| `core.file_categories` | The type presets of Find Files (Images, Disk & VM images, Crypto wallets, Keys & certificates, …) by name, folder and content markers. |
| `core.previews` | Local image thumbnailer with strict MIME allow-list, size caps, and a Qt-allocation gate. F3 / double-click. |
| `core.archive` | Safe extraction of zip / tar / 7z and single compressed files (`.zip .xpi .jar .war .apk .epub .docx .xlsx .odt .tar .tar.gz .tgz .tar.bz2 .tbz2 .tar.xz .txz .tar.zst .tzst .7z .gz .bz2 .xz .zst`). Zip-slip / bomb / lying-metadata guards; `.7z` needs the `[archive]` extra, zstd Python 3.14 or that extra. |
| `core.packer` | Right-click → **Pack**: zip, tar.gz / .zst / .xz / .bz2, 7z (optionally AES-256 with encrypted file names), or one file as .gz / .zst / .xz / .bz2 — from any backend, never overwriting (`name (2).zip`), never leaving a half-written archive. |
| `core.elevated_io` | `pkexec`-gated local read for `/etc/shadow` etc. — Axross never holds the privilege itself. "Open as root…" context-menu entry. |
| `core.fuse_mount` | FUSE mount any FileBackend. Read-only by default; `writeable=True` enables create / write / unlink / mkdir / rename. Optional `[fuse]` extra. |
| `core.mcp_server` | Stdio-framed JSON-RPC MCP server exposing the configured backend as tools. `--mcp-write` adds mutating tools, capped to a path-traversal-safe root. |

## Right-click actions

| Action | Trigger | What it does |
|---|---|---|
| Disk Image… | Right-click (one `.img .raw .dd .iso .qcow2 .vdi .vmdk .vhd(x) .e01 …` file) | The container (qcow2, VDI, VMDK, VHD/VHDX, E01), the partition table (MBR with logical partitions, GPT) and each volume's file system and label, read in plain Python through any backend. A local image mounts one volume through a loop device over exactly its bytes: `udisksctl` without a prompt first (where polkit allows it), then `sudo`, then `pkexec`, then `udisksctl` letting polkit ask. The sudo password is asked once and kept in memory while axross runs (never on disk, never on a command line); *Remember the sudo password* (*Edit → Settings… → Security*) switches that off, which restores the order `udisksctl` (polkit asks), `pkexec`, `sudo` asked every time. Paranoid Security Mode never remembers it. sudo, pkexec and udisksctl are run only from root-owned system folders, never from `$PATH`. **Read-only** unless *Allow writing* is ticked and confirmed. The mounted folder opens in a new pane; *Unmount* gives the loop device back. Mounts made by axross are remembered across restarts (`~/.config/axross/mounts.json`, only those still mounted come back). *Identify File Type…* recognises disk images by content too (GPT, MBR, virtual disks) and offers *Disk Image…* for such a row, whatever its name. qcow2 / dynamic VDI / VMDK need converting (`qemu-img convert -O raw`) first; a fixed VDI mounts directly. |
| New Folder | Right-click | `backend.mkdir(path)` on every writeable backend. |
| Tags ▸ | Right-click a selection | Tick a coloured tag (Important and Review later exist; New Tag… adds one) for every selected file on any backend; dots in the Name column, the tags in its tooltip; `tag:<name>` in the filter field shows only those files; *View > Tagged Files…* lists every tag's files and goes there. Stored in `~/.config/axross/tags.json`. |
| New File… | Right-click | Zero-byte file via `backend.open_write(path).write(b"")`. |
| New Symlink… | Right-click | Two prompts. Visible only on `supports_symlinks=True` backends. |
| New Hardlink… | Right-click | Same shape; cross-device hardlinks surface as `OSError(EXDEV)`. |
| Find in Index | `Ctrl+Shift+F` | Search the offline metadata index by name / ext / size. |
| Find in This Folder… | Right-click (also on empty space) | Find Files with this folder (or the selected one) ticked — see *Find Files*. |
| Duplicate Finder | View menu | Group rows by content hash, copy `ax-cas://…` URLs; move selected copies to the axross trash after a live re-check that a genuine other copy survives. |
| View Media… / View Selected Media… | Right-click, View menu | Images, PDFs and videos of the folder (optionally recursive) or the selection as overview grid, click-through viewer or slideshow — see *Editors and viewers*. |
| Show / Remove / Export Metadata… | Right-click | EXIF / GPS / XMP / IPTC, Office properties, PDF info, audio / video tags of the selection — or of the whole folder when nothing is selected (subfolders optional) — see *File metadata*. |
| Calculate Size (N dirs) | Right-click on folders | Total size, file and folder count of each selected folder, walked in the background through the connection (*Cancel* in the status line); the result table sorts, and the sizes show in the pane's Size column until the folder is reloaded. **Hidden files count**: dotfiles, hidden folders and entries a backend flags hidden are summed like every other entry — as `du` does — whether or not the pane shows them. A link counts with its own size and is never followed; a folder that cannot be read is named in the result and skipped. |
| Identify Files in This Folder… | Right-click (also on empty space); the button of the *Identify File Type* window | Every file directly in the folder (a selected folder, else the folder shown; subfolders are counted, not entered; hidden files included) identified like *Identify File Type…*, in the background and through the connection, so remote panes work too. Bounded: at most 2000 files, 64 KiB read per file, a 15 s timeout per read, *Cancel*; `file(1)` is not asked. The columns sort: name, detected type, MIME type, the *mismatch* verdict, size, a note — for a disk image its container, partition table and partition count (`Raw disk image, MBR, 2 partitions, 4.0 MiB`; at most 4 MiB read for it) — and, for local files when the `sift` extra is installed, sift's kind. A row opens *Disk Image…* (disk images) or *Properties…*; a double-click picks the one that fits. |
| Analyse with sift / Analyse Folder with sift | Right-click (the folder entry also on empty space), the Actions menu, *Tools → Analyse with sift* | Opens the *Analysis (sift)* dock (sift's sieve icon, `Ctrl+Shift+I`) and explains the file there without a model. Several selected files, or a folder (the selected one, else the folder shown), are offered as one batch for the active LLM profile; *Tools → Analyse with sift* takes the selection, or the folder shown when nothing is selected. sift's own directory summary (`sift --dir-summary`, sift 0.1.96 and later) is not part of the dock: a folder is analysed file by file. Without sift (axross-slim, or a source install without the `sift` extra) every entry says that sift comes with axross-full or the `axross[sift]` extra and links *Help → Features…*. |
| Identify File Type… | Right-click (selection) | One row per entry: the real type from the content (magic bytes via Qt's MIME database, puremagic, a built-in signature table), the MIME type, what the extension claims and a highlighted *mismatch* when they disagree, size, and for text the encoding and line endings. Reads at most 64 KiB per file through the backend, off the GUI thread, with a 15 s timeout per file — a dead remote gives a "timed out" row. Local files also show `file(1)`'s description when it is installed. Scripting: `axross.file_type(b, path)`. |
| Open Terminal Here | Right-click (also on empty space) | Opens a shell in the terminal dock in the folder: a selected folder, otherwise the folder shown. Local panes get a local shell started in that folder; SFTP / SCP panes get a shell on the same SSH connection followed by `cd -- '<folder>'` (quoted with `shlex.quote`). Disabled, with the reason as tooltip, on protocols without a shell. |
| Open External Terminal Here | Right-click (local panes) | Starts `$TERMINAL`, else the first installed of x-terminal-emulator, gnome-terminal, konsole, xfce4-terminal, alacritty, kitty, foot, wezterm, xterm — with the folder as working directory, detached, no shell involved. |
| Cut / Paste | Right-click (Paste also on empty space), `Ctrl+X` / `Ctrl+V` | Cut remembers the selection and removes nothing (the entries are dimmed); Paste in any pane moves them into its folder through the transfer queue - see *Transfers*. A cut never pasted leaves everything in place. |
| Move to Trash | Right-click | Universal recycle bin. Runs like Delete Permanently: in the background, with the same second question for hidden entries. |
| Delete Permanently | Right-click, `Del` | First counts what will go (folders, files, bytes, hidden entries) off the GUI thread, then asks. A selected folder that holds hidden entries (dotfiles, or a backend's hidden flag) - or one the check could not fully read - needs a second OK whose default is No. The removal runs in the background: the status line shows the progress, Cancel stops at the next entry - also inside a folder being deleted on a local path, SMB, SFTP or FTP (SFTP removes a folder's files in batches of 16 requests at once and stops after the running batch), and the status line then says how much of that folder went (removed entries stay removed; a server that deletes a whole folder in one request, such as WebDAV or S3, finishes that folder first) - failures are listed per entry, and the folder is reloaded at the end. A path that is already being deleted is refused, also from the other pane. |
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

## Find Files

**Edit → Find Files…** (`Alt+F7` or `Ctrl+Alt+F`; a pane's right-click
*Find in This Folder…*) searches folders on every open connection at once
— local, SFTP, SMB, S3, … — and optionally the offline index. `Ctrl+F`
stays the pane's live filter.

| Field | What it does |
|---|---|
| Name | Text without `* ? [ ]` matches anywhere in the name (`report` finds `Q3-report.pdf`); a pattern (`*.jpg`, `IMG_????.*`) the whole name. Case is ignored. *Regex* takes a regular expression instead. |
| Contains | Text inside the file, line by line, in the first 32 MiB of each file; *Regex* and *Case-sensitive* as usual. |
| Types | Any of the ticked presets: Images, Videos, Audio, Documents, Archives, Disk & VM images (dd / raw / img, ISO, qcow2, VDI, VMDK, VHD(X), E01 / AFF, DMG, LUKS…), Crypto wallets (Bitcoin Core / Litecoin `wallet.dat`, Electrum, Ethereum `UTC--…` keystores, Exodus, Monero, MultiBit / Armory, Wasabi, Atomic, Ledger Live, MetaMask / Phantom / … browser wallets), Keys & certificates (PEM / DER, `.p12` / `.pfx`, Java key stores, SSH and PuTTY keys, KeePass), Source code, Email, Databases. Decided by name and folder; for local files whose extension says nothing (`blob`, `wallet.dat`, `UTC--…`) also by the first bytes, and by `sift` when the `sift` extra is installed (`axross[sift]`). Types name file *kinds* — nothing looks for passwords or keys inside files. |
| Size / Modified | `10K`, `1.5M`, `2G`; a date range. |
| Inside archives | Also look into zip, tar, tar.gz / .bz2 / .xz / .zst, single .gz / .bz2 / .xz / .zst files and archives nested in them (3 levels); 7z and rar by member name. A hit reads `archive.zip!/folder/file.txt`. Bounded: 10 000 members and 1 GiB decompressed per archive, 64 MiB per nested archive, the extraction's 100:1 zip-bomb ratio; a remote archive is copied (at most 256 MiB) to a private temporary file first. |
| Tag | Only files that carry the chosen tag (right-click → *Tags*); a tagged archive counts for its members. A Smart Folder keeps the tag. Offline-index hits are filtered too. |
| Hidden files, Skip .git / node_modules / caches, depth | What the walk includes. Symlinked folders are never followed. |
| Look in | Every open pane's folder (the active one ticked), *Add Folder…*, and *Also search the offline index* (names, sizes, dates; no content). |

Results stream in while the search runs; *Stop* or closing the window
cancels it. The columns sort; double-click or `Enter` shows the file
selected in a pane (an archive member opens the archive view), and the
right-click menu has *Open*, *Reveal in Pane*, *Copy Path* and *Send to
Agent*.

On a local folder the search uses [`fd`](https://github.com/sharkdp/fd)
to list files and [`ripgrep`](https://github.com/BurntSushi/ripgrep)
(`rg`) to search their content when they are installed (on `PATH`, `fdfind`
on Debian / Ubuntu, or `bin/` next to a frozen build); without them a
built-in walker gives the same results, more slowly. Remote folders are
walked through the connection.

**Save as Smart Folder…** keeps the search in the bookmarks (sidebar and
Bookmarks menu, with a magnifier icon); a click runs it again on the
folders whose connection is open. It is stored in `bookmarks.json` with
the other bookmarks.

**Edit → Index Active Folder…** records names, sizes and dates below the
active pane's folder in the offline index — the only way it is filled.
*View → Find in Index…* (`Ctrl+Shift+F`) searches it; the window shows the
index file.

### The offline index

- **What it stores.** One SQLite file with one row per file and folder:
  the connection, the full path, name, size, folder or not, extension,
  modification time and when it was indexed. No file content and no
  checksums — those are the duplicate index (`cas.sqlite`, next to it).
- **Where.** `$AXROSS_METADATA_DB`; else `$XDG_DATA_HOME/axross/metadata.sqlite`
  when `XDG_DATA_HOME` is an absolute path; else
  `~/.local/share/axross/metadata.sqlite`. An index made at that old place
  stays in use as long as there is none at the new one, so setting
  `XDG_DATA_HOME` orphans nothing. `cas.sqlite` follows the same rules
  (`$AXROSS_CAS_DB`). *Edit → Settings… → Search* shows both paths.
- **How it is filled and updated.** *Edit → Index Active Folder…* (or
  *Index Current Pane…* in *Find in Index*) walks the active pane's folder
  recursively through its connection — any backend, hidden entries
  included, at most 50 levels and 1 000 000 entries per run, written in
  batches of 500, cancellable (what was indexed is kept). Browsing never
  indexes. Indexing the same folder again updates its rows in place; rows of
  files deleted since are **not** removed by the GUI (the MCP tool
  `index_build` with `prune` drops them).
- **How it is searched.** Name substring (case-insensitive), extension,
  size range, date range, one connection. Extension, size and date use
  SQLite indexes; a name substring (`LIKE '%…%'`) cannot use one and reads
  every row.
- **How fast — measured** on the development machine with `/usr` (290 872
  entries, local disk, the machine under other load): first run 125 s
  (about 2 300 entries/s), second run over the same tree 53 s, index file
  98 MiB; a name search 0.4–1.2 s (every row is read; many hits take
  longer), an extension search 37 ms. Good for "where was that file" across
  connections that are offline now; it is no content search (that is
  *Find Files → Contains*, live).

### Find Files and sift

sift (the optional `sift` extra) is a file *analyser*, not a
search engine: it builds no index and has no search — its command line
and API summarise files, and its only store is a cache of summaries keyed
by the file's content hash. Searching folders, by type and inside
archives, is axross' own Find Files (`core.file_search`,
`core.file_categories`, `core.archive`).

- **What Find Files uses sift for.** With the `sift` extra installed, the
  *Types* filter asks `sift.detect` about local files whose name says
  nothing (no extension a preset claims) and maps its kind — image, pdf,
  docx, archive, sqlite, email, source code, … — to a preset. Remote
  files and archive members are typed by name and folder only. There is
  no switch: Find Files uses sift when it is there.
- **Inside archives.** sift lists an archive's members in its summary
  (the Analysis dock) but does not search them. *Find Files → Inside
  archives* does: zip, tar.*, single-file compressors and archives nested
  in them (3 levels), 7z and rar by member name.
- **Where sift's options and features are.** *View → Panels → Analysis (sift)*
  (`Ctrl+Shift+I`; right-click → *Analyse with sift*) explains the selected file: without a model
  automatically, with the active LLM profile on *Analyse with LLM*. The
  dock's *LLM…* button opens *Edit → Settings… → LLM Profiles*, where the
  model servers are set; *Edit → Settings… → Analysis (sift)* holds sift's
  own options (automatic analysis, read limit, time budget, vision,
  context, tags, categories, the cache) and the profile analysis uses. *Help → Features…* shows whether the sift extra
  is installed and offers to install it (`pip install axross[sift]`; a
  frozen build offers the axross-full download instead).
  *Identify Files in This Folder…* shows sift's kind of local files as a
  column of its own.

## Path bar

- **Auto-refresh ◉** subscribes the pane to `core.watch`; debounced
  refresh on backend changes. On by default for local folders (inotify
  through watchdog, or a cheap local poll when the inotify limit is
  reached); off for remote ones, where it would list the
  folder again every 2 seconds - one click turns it on for that pane.
- **Live filter** types into the path bar to filter the listing in
  real time. **Ctrl+F** jumps to the filter field; **Esc** there clears
  the filter and goes back to the list. Esc in the list stops a running
  load first, then clears an active filter, then the selection, then
  drops a pending Cut of that pane.
- **Bookmarks** (left dock, or the toolbar's bookmark button) for
  one-click navigation; F8 bookmarks the current path (name, icon,
  colour and group are chosen in the dialog), F12 toggles the dock.
  Bookmarks can be grouped (groups nest and fold on click; the
  Bookmarks menu shows them as hover submenus), reordered by drag &
  drop or Move Up / Down in the right-click menu, and given an icon
  from the built-in SVG set plus a colour. Folders dragged from a pane
  onto the dock (empty space, a group, or between entries) become
  bookmarks there, remote ones with their connection profile. Files
  and folders dropped *onto* a bookmark are moved into its folder (Ctrl
  copies), through the same existing-name check as F5 / F6; a folder
  that is gone or a remote that does not answer is reported and nothing
  is queued, and a remote bookmark without an open connection connects
  first, then transfers. Ctrl+click and Shift+click select several
  entries: they drag together, and the right-click menu moves them
  (*Move to Group*) or deletes them after one question. A group's
  right-click menu sorts it (*Sort* by name, path, name + path or age,
  each also reversed; groups stay first, the order is saved; bookmarks
  from before the creation time was recorded sort last).
  **Bookmarks > Manage Bookmarks…** shows the same tree with each
  entry's location and connection and does the same with buttons:
  Edit…, Rename… (F2), New Group…, New Terminal Bookmark…, Move Up /
  Down / to Top, Move to Group, Sort, Delete… (Del, for a selection).
  It works on the same store, so the sidebar and the menu change at once.
- **Terminal bookmarks** open a shell instead of a folder: a local
  shell, one on an SSH (SFTP/SCP) profile, or one on a bare host —
  *SSH Host (no profile)*: host or IP address, port (22), user, an
  optional key file — optionally changing into a working folder. Make one
  with the ☆ button of a terminal pane (*Bookmark this Terminal*) or
  *New Terminal Bookmark…* in the sidebar's right-click menu; a click
  opens a terminal pane beside the active pane. A bookmark never holds a
  credential: a profile bookmark names the profile; a host bookmark
  connects like Quick Connect — in the background, asking whether to
  trust an unknown host key (known_hosts, never accepted silently), using
  the key file or else a running ssh-agent, asking the password when
  neither gets in and the key's passphrase when the key is encrypted;
  nothing typed is stored, and the proxy of *Settings → Network & Proxy*
  applies. A profile that is gone or has no shell, or a host that is no
  host name, is reported and nothing opens. A host bookmark's shell is
  not part of the saved layout.
- **Folders load in the background**: opening a folder, going up /
  back / forward, refreshing or typing a path keeps the current
  listing usable; the status line shows *Loading …* with a Cancel
  button (Esc works too), and a new click replaces a load that is
  still running. A failed or cancelled load leaves you where you
  were. Auto-refresh updates quietly and never interrupts you.
- **File list**: hovering a name shows it in full; dragging from
  empty space draws a selection box (Ctrl adds); the divider right of
  *Name* moves space between *Name* and the next column, double-click
  on a divider fits the column; the back / forward mouse buttons walk
  the folder history and a wheel click opens the row under the pointer.

## Editors and viewers

Every viewer, editor and dialog has two buttons in its top-right corner:
[x] closes it, the one left of it maximizes it over the whole screen and
restores the size it had before. `Ctrl+M` does the same, and so does
the title bar's Maximize button. In a dialog, a left drag on the rest of
that top row moves the dialog, and a left drag on a floating panel's
title bar moves the panel - also where the window manager draws no title
bar (spectrwm, other tiling setups) or keeps the window maximized
(spectrwm's `fullscreen` layout), and on Wayland: axross then asks the
window manager to move it. A double-click on a floating panel's title
bar docks it again.

- **Text editor** (built-in) — every file opened for editing is a tab
  of one editor window (*Edit* / F4 in a pane, local or remote): syntax
  highlighting (Pygments; the language by name or `#!` line, changeable
  in the status bar), line numbers, find and replace with regex, case
  and whole word (Ctrl+F / Ctrl+H, F3), go to line (Ctrl+G), wrap, zoom,
  line endings (LF / CRLF / CR) and encoding (UTF-8, UTF-8 BOM, Latin-1,
  UTF-16) under *Format*, Save / Save All. *File → New* (Ctrl+N) starts
  an untitled tab, *Open…* (Ctrl+O) picks local files (remote files open
  from their pane), *Save As…* (Ctrl+Shift+S) writes a local tab to a
  local file and a remote tab to a path on its own backend, asking
  before it replaces a file; Save All is Ctrl+L. Enter keeps the line's
  indentation, one level more after `:` (Python, YAML) or `{` (brace
  languages). *Tools → Text Editor* opens the window without a file.
  A save keeps every untouched
  line's own ending, a BOM and no-break spaces, writes atomically and
  asks first when the file changed since it was opened; the pane showing
  the folder refreshes. Closing a tab or the window with unsaved
  changes asks Save / Discard / Cancel; closing the last tab closes the
  window, and its menu bar carries the maximize and [x] buttons.
- **Hex editor** — useful for triage on remote files.
- **Open size limit** — the text / hex viewers read the whole file,
  so there is a cap: 32 MB by default, changeable under
  *Edit → Settings… → Files & Panes* (1–4096 MB, stored in `settings.json`).
- **Image viewer** — F3 / double-click, MIME-allow-listed, size-
  capped to keep Qt's allocator happy.
- **PDF** — F3 / double-click opens the PDF on its own in the media
  viewer below (needs QtPdf; without it, or in the `paranoid` security
  mode, the hex editor opens instead and the log says why).
- **Media viewer** — *View → View Media…* or right-click → *View
  Media…* on the folder (*View Selected Media…* for a selection of
  files and folders). Choose the types (images incl. SVG, PDFs,
  videos via QtMultimedia), whether to include subfolders (depth
  1–32; at most 5000 files, symlinked folders are not followed,
  unreadable folders are skipped and counted) and how to start:
  **Overview first** (thumbnail grid with filter, sort by name /
  date / folder and a size slider; Enter or double-click opens an
  item), **Start slideshow** or **Click through**. In the viewer:
  Left / Right / PageUp / PageDown / Space go to the previous / next
  file (stopping at the first and last item; also inside a PDF, and
  the slideshow only turns pages of a PDF opened on its own). A PDF with more than one
  page gets a page control `← n / m →` in the button bar; Up / Down
  turn its pages. Home / End, F11 fullscreen, Ctrl+M
  maximize / restore (the window remembers its last size, position
  and maximized state for the next open), wheel or
  `+` / `-` zoom, `F` fit, `1` 100 %, `R` rotate, `S` slideshow
  (interval in seconds; the slideshow loops, a video plays to its
  end), Esc back to the overview, Esc again closes. **Delete**
  deletes the shown file (or the selected tile) after a question;
  dragging the image or a tile onto a pane moves it there, Ctrl
  copies - the same as a drag out of the pane the viewer came from
  (a zoomed-in image pans instead). The image viewer does both too.
  Works on every
  backend: remote files are copied to a private temp directory up
  to the *Open Size Limit* and removed afterwards; an item that is
  too large, encrypted or broken shows the reason instead. SVG is
  rendered only when it has no DOCTYPE/entities, scripts or
  references outside the file. `paranoid` mode blocks the viewer.
  `I` (or the *Info* button) shows the current item's metadata in a
  side panel, with *Remove metadata* — in the image viewer too.
- **Media Player** (bundled extension, *Extensions → Manage
  Extensions…*) — a dock that plays MP3, WAV, Ogg Vorbis, FLAC, Opus,
  AAC and more. Add tracks with right-click → *Play in Media Player*,
  *Add…*, or by dropping files and folders from a file pane or the
  desktop onto the playlist (folders add their audio files sorted, at
  most 2000, 6 levels deep, links to folders followed once; .m4b,
  .wv, .webm and other formats the engine plays count; what gives no
  track - not audio, unreadable, nested too deep - is counted in the
  note, files beside found tracks such as covers are no news; remote files are copied to a temporary folder off the
  GUI thread, at most 512 MB each and 2 GB per drop). Drag rows to
  reorder; the playing track (bold, play icon, named in the dock
  title) keeps playing. Seek with the position slider (click or drag,
  `1:23 / 4:56`). ⏮ restarts the track after 3 s, else goes back;
  shuffle plays every track once per round, repeat is off / all /
  one. An unplayable track is marked and skipped. *Load…* / *Save…*
  read and write M3U / M3U8 playlists (UTF-8, relative paths for
  tracks under the playlist's folder, `#EXTINF` titles and lengths;
  URLs, missing or non-audio entries are skipped, files over 1 MiB
  or with NUL bytes are refused; temporary copies of remote tracks
  are not saved). The list, the current track and position, volume,
  mute, shuffle and repeat come back on the next start
  (`~/.config/axross/media_player.json`, mode 0600). Volume follows a
  perceptual (cubic) curve; mute button. The output device and the
  output volume of *Edit → Settings… → Audio* apply on top (a change
  there reaches a playing track at once). When audio does not start,
  the panel says why: *Try Again* checks once more and starts the
  player when audio answers, *Audio Settings…* opens the Audio page
  (another backend or device). Keys while the player has
  the focus: Space play/pause, Enter play the selected row, Delete
  remove the selected rows, Left / Right seek 5 s (with Shift 30 s),
  Ctrl+Left / Ctrl+Right previous / next, M mute, + / - volume. With
  numpy: 10-band equalizer with presets (the arrow left of *Equalizer*
  folds the band sliders away and gives the playlist the room) and an
  animated visualization: spectrum, mirrored spectrum, radial spectrum,
  oscilloscope, stereo VU meter, line spectrum (log frequency axis),
  waterfall (spectrogram), polar spectrum, stereo scope (goniometer: L
  against R) or a starfield that speeds up with the bass - a click on it
  switches to the next. Its right-click menu lists every visualization
  and colour scheme (Classic, Fire, Ice, Neon, Mono, *Follow the theme*,
  *Custom*), the bar count and the frame rate cap; *Visualizer
  Settings…* (also *Extensions → Media Player Visualizer…*) adds the
  custom colours (background, quiet and loud bars, peaks - a peak colour
  without 3:1 contrast on the background is adjusted), peak fall speed
  and smoothing. *Fullscreen* (menu, double-click or F11 on the
  visualization) shows it alone on the screen like a screensaver - Esc,
  F11 or a double-click leaves, the mouse pointer hides after 2.5 s
  without a move (can be switched off); *Detach into a Window* puts it
  into a window of its own of any size that keeps playing, *Attach to
  the Panel* or closing that window brings it back. The arrow left of
  *Playlist* (or *Show Playlist* in the menu) folds the playlist away:
  the panel is then the controls and the visualization, the keys work
  and files dropped onto the panel still land in the playlist. The
  visualization, its colours and options and the folded equalizer and
  playlist come back on the next start.
- **SSH terminal** — tabbed dock next to the transfer queue. Local
  PTY (`pty.fork()`) and remote SSH-over-paramiko are both
  available; the SSH variant reuses the existing connection rather
  than dialling a new one.

## File metadata

Right-click → **Show Metadata…**, **Remove Metadata…** or **Export
Metadata…** acts on the selected files and folders, or on the folder
itself when nothing is selected. The metadata window shows one row per
file with its fields one after another as `key: value`; a double-click
or right-click → *Properties…* opens every field of that file, grouped
and one per line, and right-click → *Remove Metadata* cleans only the
selected files. It has a filter, *Copy* (the fields of the selected
files as text), *Export…* (JSON or CSV) and *Remove Metadata* for every
file listed. Folders are read flat;
tick *Include subfolders* to go deeper (at most 5000 files, depth 8,
symlinked folders not followed). Reading and removing run in the
background with progress and *Cancel*. In the image and media viewers
`I` opens the same information as a side panel.

| Kind | Read | Removed | Kept |
|---|---|---|---|
| JPEG, PNG, WebP, GIF | built in | EXIF (GPS, camera, serial numbers, times, author, software), embedded thumbnails, XMP, IPTC, comments, PNG text chunks, data after the image | EXIF orientation, ICC colour profile; the pixels are never re-encoded and are checked to be identical |
| TIFF | built in | the same, through a lossless re-save | orientation, ICC profile; JPEG-compressed TIFF is refused |
| docx / xlsx / pptx, odt / ods / odp | built in | `docProps/core.xml`, `app.xml`, `custom.xml`, ODF `meta.xml`, the zip comment | every other part, decompressing to the same bytes |
| PDF | pypdf, else QtPdf | Info dictionary, XMP streams, PieceInfo, earlier revisions (full rewrite) | — needs the `[metadata]` extra (`pip install 'axross[metadata]'`) |
| Audio / video | `ffprobe` | all tags and chapters, data streams (camera GPS tracks), the cover picture of audio files (`ffmpeg -c copy`, no re-encoding) | the streams |

**How removal writes** — *Edit → Settings… → Metadata* (*Tools →
Metadata Settings…* opens it):

- **In place** (default): the file is replaced atomically and its
  original is kept in the axross trash. One run — a single file or a
  whole folder — is one entry for *Edit → Undo Last Operation*
  (`Ctrl+Z`), which puts every original back byte for byte, but only
  while the file still holds what the removal wrote.
- **Cleaned copy**: `name.clean.ext` next to the original
  (`name.clean (1).ext` if that exists); nothing is overwritten.

No confirmation is asked unless *Ask before removing metadata* is
ticked there. Remote files go through a private temp copy bounded by
the *Open Size Limit* and back through the backend's atomic write; a
connection whose trash cannot be written gets a cleaned copy instead,
and the result says so. A file that changes while it is being cleaned is
left alone. In `paranoid` mode reading and removing work, except for
audio / video: that would run ffprobe / ffmpeg on the file's contents.
Scripts: `axross.metadata`, `axross.remove_metadata`,
`axross.export_metadata` (see [SCRIPTING.md](SCRIPTING.md)).

## Transfers, terminal, log dock

- The bottom strip has three tabs: **Transfers**, **Terminal**,
  **Log**. Each flashes amber when something happens off-screen
  (new transfer state, shell output, log line). Click clears the
  indicator.
- Right-click a transfer for **Cancel**, **Retry**, **Open
  destination folder**.
- The terminal (dock and terminal pane) is a VT100 / xterm screen:
  carriage return, cursor moves, erase, scroll regions and the
  alternate screen work, so zsh prompts, line editing, `less`, `top`
  and editors draw where they should. The shell's terminal size is the
  size of the terminal area and follows every resize (`stty size`
  shows it). Colours are not shown.
- Keys typed in the terminal go to the shell: Ctrl+letter (on macOS
  the Control key), function keys, arrows and editing keys — so Ctrl+W,
  Ctrl+Q or F6 there never close a pane, quit or move files. Paste with
  Ctrl+Shift+V (macOS: Command+V), a middle click or the context menu;
  the text goes to the shell. Command shortcuts on macOS and the zoom
  keys stay with axross.
- While a file drag is over a pane, the row the drop goes into gets a
  frame and a note beside the cursor names the folder: *Move to …* or,
  with Ctrl, *Copy to …*. The `..` row means the folder above.

## Scripting & embedded REPL

Axross ships a curated Python surface (``axross.*``) covering every
backend, plus 9 result-type classes for network helpers. Same
source of truth across all three entry points:

- **Console dock** (View menu) — embedded REPL with multi-line
  input, history, tab completion, and a side panel listing every
  function with its docstring.
- **Headless** — ``axross --script myscript.py`` runs your Python
  in the same namespace; ideal for cron / CI / one-shot batching.
- **MCP** — when ``--mcp-allow-scripts`` is set, the REPL surface
  is also reachable via MCP tool calls.

Quick examples (drop into the Console or a ``.py`` file for
``--script``):

```python
b = axross.localfs()
items = b.list_dir("/var/log")[:10]
hits = axross.grep(b, "/var/log", r"kernel:.*panic")

src = axross.open("my-sftp")           # named profile from Connection Manager
dst = axross.localfs()
axross.copy(src, "/etc/hosts", dst, "/tmp/hosts.bak")

probe = axross.http_probe("https://example.com")
print(probe.status_code, probe.redirect_chain)
ips = axross.dns_resolve("example.com")
```

### Browsing the API

- ``axross.help()`` — printed cheat-sheet, grouped by category.
- ``axross.docs("backend")`` / ``axross.docs("scripts")`` /
  ``axross.docs("slash")`` — per-topic Markdown reference.
- Tab-complete on ``axross.<TAB>`` in the REPL.
- ``docs/SCRIPTING_REFERENCE.md`` — every verb and result class
  with full signature + docstring.

### REPL slash commands

| Command | Effect |
|---|---|
| ``.help`` | List slash-commands |
| ``.scripts`` | Saved scripts in ``~/.config/axross/scripts/`` |
| ``.save <name>`` | Save THIS session's submitted source; an existing script of that name is never replaced (``.delete`` it first) |
| ``.load <name>`` | Print the source of a saved script |
| ``.run <name>`` | Execute a saved script in the live namespace |
| ``.delete <name>`` | Remove a saved script |
| ``.open`` | Print the script directory path |

### UI helpers — message / confirm / toast

Scripts and REPL sessions can show modal dialogs and toasts that
**fall back gracefully to stdout/stdin** when there's no Qt event
loop (so the same script runs in cron / CI):

```python
# Modal info dialog (Qt) → stdout one-liner (headless)
axross.message("Backup completed (123 files copied)",
               level="success")

# Yes/No (Qt) → y/n stdin prompt (headless)
if axross.confirm("Delete 47 files? Cannot be undone.",
                  default_yes=False):
    for p in doomed:
        backend.remove(p)

# Non-modal toast in the bottom-right (Qt) → stdout (headless)
axross.toast("Connection lost — retrying", level="error")
axross.toast("Saved 1.2 MB to /tmp/dump.json",
             level="success", timeout=2)
```

Levels: ``"info"`` (blue), ``"success"`` (green), ``"warning"``
(yellow), ``"error"`` (red). Each renders with a coloured SVG state
icon; the bundled axross glyph is the dialog's window-icon.

The headless ``confirm()`` prompt only asks when stdin is a terminal.
Without a human — cron, a pipe, the Scripts dock's child process, an
MCP ``script_run``, or ``AXROSS_NONINTERACTIVE=1`` — it raises
``axross.NonInteractiveError`` instead of answering its default; pass
``assume_yes=True`` to answer yes without asking there.

### Proxy support in scripts

Both ``axross.open(profile_name)`` and ``axross.open_url(url, **kw)``
now thread proxy configuration through the same ConnectionManager
plumbing the GUI uses. ``open()`` reads the proxy fields from the
saved profile; ``open_url()`` accepts them as kwargs:

```python
b = axross.open_url(
    "sftp://alice@gateway.example.com/",
    password="hunter2",
    proxy_type="socks5",          # "socks5" / "socks4" / "http" / "https" (+ "+ntlm" ...)
    proxy_host="proxy.example.com",
    proxy_port=1080,
    proxy_username="puser",       # optional
    proxy_password="ppass",       # optional
)
```

When `proxy_type` is not `"none"`, `proxy_host` and a non-zero
`proxy_port` are required. Half-configured proxies fail closed instead
of falling back to direct traffic. Without any `proxy_*` keyword,
`open_url` uses the default proxy from *Tools → Network & Proxy…* (its
bypass list and PAC script apply); a PAC script that cannot be evaluated
raises `ProxyResolutionError` rather than connecting directly.

Supported for: sftp, scp, ftp/ftps, smb/dfsn, webdav, rsync,
telnet, cisco-telnet, imap, pop3, nntp, gopher, pjl, adb-tcp,
azure_blob/files, onedrive, sharepoint, gdrive, dropbox, winrm, s3,
svn, postgres, redis, mongodb, ldap, git, and (NFSv4 / iSCSI through a
loopback tunnel). HTTP-only libraries (botocore, svn) are fronted by a
loopback shim, so SOCKS, HTTPS and NTLM work for them too. Rsync uses
OpenBSD `nc`; `proxy_username` can be passed, but `proxy_password`
is rejected because `nc` has no safe non-interactive password flag.
Requests-based SDK sessions controlled by Axross ignore process-level
`HTTP_PROXY` / `HTTPS_PROXY`; the profile proxy is the route source of
truth. OAuth browser consent pages are external to Axross and may follow
browser/system proxy settings.
Unsupported backends warn: ramfs/sqlite (local/in-process),
nfs/iscsi/mtp (kernel/USB transports), tftp/slp (UDP),
rsh/svn/git/wmi and the DB drivers without a clean socket hook.

`open_url()` also accepts a few practical aliases: `http://` /
`https://` are treated as WebDAV endpoints, `gophers://` and
`nntps://` select TLS variants, `git+local://` opens a local Git
repository path, and `sftp+key://` / `sftp+agent://` select SSH auth
mode.

### Categories (every public name: `axross.api_schema()`)

| Group | Verbs |
|---|---|
| Connect / backend | ``open``, ``open_url``, ``localfs``, ``ramfs``, ``list_backends``, ``available_backends`` |
| Profiles | ``list_profiles``, ``get_profile``, ``save_profile``, ``delete_profile`` |
| File I/O | ``copy``, ``move``, ``checksum``, ``read_bytes`` / ``write_bytes`` / ``read_text`` / ``write_text``, ``hash_bytes`` / ``hash_file`` |
| Crypto / archives | ``encrypt``, ``decrypt``, ``extract_archive``, ``is_archive``, ``archive_inspect`` |
| Bookmarks | ``list_bookmarks``, ``add_bookmark``, ``remove_bookmark`` |
| Scripts | ``script_dir``, ``list_scripts``, ``save_script``, ``load_script``, ``delete_script``, ``run_script`` |
| Per-protocol | ``find_tftp_files``, ``slp_discover``, ``nntp_post``, ``git_push``, ``exec``, ``interactive_shell``, ``query``, ``tables``, ``imap_search`` / ``imap_move`` / ``imap_set_flags``, ``share``, ``ldap_search`` |
| DNS / Net | ``dns_resolve`` / ``dns_records`` / ``dns_reverse``, ``port_open``, ``port_scan``, ``subnet_hosts`` |
| Network helpers | ``ping`` / ``PingResult``, ``mac_lookup`` / ``OuiInfo``, ``whois`` / ``WhoisInfo``, ``time_skew`` / ``TimeSkew``, ``tcp_banner``, ``tls_cert`` / ``TlsCert``, ``ssh_hostkey`` / ``SshHostKey``, ``http_probe`` / ``HttpProbe`` |
| SNMP | ``snmp_get``, ``snmp_walk``, ``snmp_set``, ``SnmpVar`` |
| Cross-backend search | ``find_files``, ``grep`` / ``GrepHit``, ``diff_files`` |
| File metadata | ``metadata``, ``remove_metadata``, ``export_metadata`` |
| UI helpers | ``message``, ``confirm``, ``toast`` (modal + toast with SVG state icons; stdout/stdin fallback when headless), ``is_interactive``, ``NonInteractiveError`` |
| Reference | ``help``, ``docs``, ``api_schema`` (the API as JSON, for machines) |

## SSH / SCP terminal multiplexing

When you connect via SSH or SCP, axross opens **one** TCP connection
+ paramiko Transport. Subsequent operations multiplex onto that
transport:

- **SFTP / file ops** ride a dedicated channel.
- **Open Terminal** (terminal dock) allocates an additional channel
  with a PTY — full interactive shell, no second login prompt, no
  second key challenge. Works the same for SSH and SCP backends.
- The transport is exposed as ``session.transport`` on both
  ``SSHSession`` and ``SCPSession`` so the terminal dock can wire
  itself up automatically.

This means an SCP pane gets the same "open a remote shell here"
right-click as an SSH pane, on the same connection.

## Keyring auto-detect & re-detect

Saved passwords go to the OS keyring (Secret-Service / KWallet /
Windows Credential Locker / macOS Keychain / KeePassXC's Secret-
Service plug-in). Axross probes for a working backend on first
use. Any other keyring backend works as well, as long as it needs
no terminal input (for example keyring-pass or keyrings.cryptfile set
up through ``keyringrc.cfg``); when several are installed, the one
keyring itself ranks first is used. Clear-text files
(``PlaintextKeyring``) and keyrings.alt's ``EncryptedKeyring``, which
asks for its master password on the terminal, are not used. On
systems with no usable backend, "Save in keyring" is disabled with an
actionable hint:

- **Arch:** ``sudo pacman -S gnome-keyring`` (or kwallet, or keepassxc)
- **Debian:** ``sudo apt install gnome-keyring``
- **Fedora:** ``sudo dnf install gnome-keyring``

If you start a daemon **after** axross is already running, use
**File → Re-detect System Keyring** (or just try Save again — the
next ``store_password`` auto-rechecks).

## MCP server

Axross can run as a Model Context Protocol server so an LLM client
(Claude Desktop, Cline, a custom agent) can drive any configured
backend through a JSON-RPC tool surface.

```bash
axross --mcp-server                                  # read-only, stdio
axross --mcp-server --mcp-write                      # add write tools (capped to a root)
axross --mcp-server --mcp-http 127.0.0.1:7331        # HTTP, loopback
```

The read-only file tools (`list_dir`, `stat`, `read_file`, `checksum`,
`search`, `walk`, `grep`, …), the write tools when `--mcp-write` is
set, the capability groups of `--mcp-tools` (`axross --mcp-list-tools`
prints every tool a set of flags serves), `resources/*` endpoints,
`notifications/message` log forwarding, per-tool timeouts,
per-session token-bucket rate limits, HTTP sessions with SSE
progress streaming, optional multi-backend routing.

Full reference: **[docs/MCP.md](MCP.md)** (EN) · [MCP_de.md](MCP_de.md) (DE) · [MCP_es.md](MCP_es.md) (ES).
For LLM clients: [LLM_GUIDE.md](LLM_GUIDE.md).

## Agent dock — a local LLM works with axross

Tools > Start Agent, *New Agent Tab Here* in a pane's right-click menu
(a new tab for that folder) or View > Panels > Agent (Ctrl+Shift+A)
open a chat with an LLM profile
(the profiles of the Analysis dock: LM Studio, Ollama, vLLM, llama.cpp
or any OpenAI-compatible server; LLM… manages them). The model works
with the same tools as the MCP server, in the folder shown at the top
(the active pane's, when it shows local files).

**Ollama** runs a model with a context of 4096 tokens unless told
otherwise, and the agent's instructions and tools alone take 2,000 to
5,000 tokens (5,259 with *Allow changes to files*). Start the server
with `OLLAMA_CONTEXT_LENGTH=16384`, or set `PARAMETER num_ctx 16384` in
a Modelfile: Ollama cuts a request that does not fit without a word,
and its OpenAI-compatible API takes no context size. When an answer
filled the context, the tab says so.

**Tabs.** Every tab is a conversation of its own with its own model,
protection mode, sandbox, folder and tools: "+" or Ctrl+T opens one,
a double-click renames it. With *Keep tabs* on (Tools > Agent
Settings…) each tab is one JSON file in `~/.config/axross/agent/sessions/`
(`0o600`) and comes back at the next start. Ctrl+Enter sends, Esc
or Stop ends the task at once - also while the model is still writing
its answer (the request is cut, the server stops generating) - and
Up/Down bring back earlier tasks. A reasoning model that writes its
whole answer only into its reasoning (Qwen3 on LM Studio does at times)
gets that shown, marked as such; a model that ends without any answer
is said so.

**Conversations in panels of their own.** Right-click a tab and choose
**Detach as Panel** - or drag the tab well away from the tab bar - and
the conversation becomes a panel of its own; **Tools → New Agent
Window** (or ⧉ beside "+") opens a new conversation directly as one.
The same conversation moves: a running task keeps going and its
questions still come, nothing restarts. Such a panel is placed like an
extension panel: on **All Workspaces** (the window's dock area) or, from
the ⇄ button or a right click on its title bar (*Move to Workspace*) or
**Workspace → Add Extension Panel**, on one workspace, where it is a
pane - dragged by its title bar, resized, taken along when the workspace
is detached. ⇲ (or *Attach to Agent Dock* in the right-click menu) puts
it back as a tab. Its [x] closes the conversation as closing its tab
does: when there is a conversation it asks first, then it is deleted.
Closing its workspace leaves it on All Workspaces; *close all panels in
this area* puts it back into the Agent dock. Each panel has its own
lamp; the voice works for the conversation it was started in, else the
one you were last typing in; settings, profiles and extensions reach
every conversation. With *Keep tabs* on, detached conversations come
back after a restart on their workspace or All Workspaces; one whose
workspace does not come back (the layout is not restored) is a tab
again.

**Thinking.** What a reasoning model thinks before it answers or calls a
tool (`reasoning_content` or `reasoning` beside the answer, or
`<think>…</think>` at the start of it) is shown apart from the answer: a
grey, italic **▸ Thinking** line with its first sentence. Click
*Thinking* to open the whole text, click again to close it. Only the
answer is read aloud. Kept tabs keep the thinking, closed.

**The lamp** in the dock's title bar says whether the tab's LLM answers:
**green** - the last request to its endpoint (a model listing, or a
request of a task) succeeded; **orange** - one is on its way; **red** -
it failed, no profile is set up, or the endpoint is remote and has no
consent yet (it is not asked before the first task). Its tooltip names
the endpoint, the model and the reason; a click checks again. The check
lists the server's models in the background, only while the dock is
shown.

**Protection modes** (per tab):

- **Ask** — every change and every remote command waits for Yes in a
  dialog that shows the tool and its arguments (passphrases masked).
- **Plan** — the agent only reads and writes a plan; *Run this plan*
  then runs it in Ask mode.
- **Auto** — changes run without asking; remote commands
  and tools of an MCP server set to "always" still ask.
- **Bypass** — nothing asks. Only offered when switched on in Agent
  Settings, never in the paranoid security mode, and marked red.

**Giving it files.** The "+" menu attaches the active pane's selection
or folder, files from a dialog or a path from the clipboard; drag files
from a pane onto the tab, or use *Send to Agent* in the pane's
right-click menu. A local file outside the tab's folder makes its
folder readable (read-only) for that tab.

**Tools** (Tools ▸ in the tab): the file tools, the ticked groups
(metadata, file types, archives, …), *Allow changes to files*, *Allow
remote commands*, one line `mcp:<name>` per MCP server and `ext:<id>`
per extension with agent tools. Always there: `ask_user` (the agent
asks you something) and `update_plan` (a checklist above the task
field).

**Files read-only** (in the tab's top row, and for every tab in Agent
Settings > Access): the agent reads files but changes none - no
writing, deleting or moving, no remote commands (a command can change
files), extra folders read-only, no writing tools of MCP servers or
extensions, and a sandbox mounts nothing writable. It is enforced where
the agent's tools are built and again at every call, not only in the
dialog. One exact exception: an MCP server that cannot change your
files keeps its tools — a container server on axross's own podman line
(installed from a catalog) with `--network=none` and only read-only
folders (`:ro`). Its *Asks* still applies: with "Every call asks" each
call waits for your Yes. Any other server (network, a writable folder, a
program on this machine, an HTTP server, a hand-written podman line)
offers only the tools it marks read-only, and none when it asks before
every call.

**Topics ▸** fills the task field with a prepared task — System
inventory, Install or update software (in Plan mode), Service status,
Collect logs, Disk usage, Summarise a folder, Read data out, Review a
config folder, Free disk space (with the Duplicate Finder tools) — for
you to complete and send. Extensions can add their own.

**Your own topics** ("work prompts"): Topics ▸ *+ New Topic…* opens an
empty form, *Save This Task as Topic…* starts from the task field, and
*Edit or Delete My Topics…* changes or removes them. A topic stores a
title, a slash command,
the prompt (`{folder}` and `{backend}` are filled in), the mode it
suggests, what it needs and the tool groups it ticks, in
`~/.config/axross/agent/work_prompts.json`. Every topic has a command:
type `/` in the task field to pick one (`/free-space`, `/review-config`,
your own); text after the command is kept below the prompt. A command
fills the field — you read it and send it.

**Prompts** (*Edit → Settings… → Agent → Prompts*): the system prompt
(the rules the model gets first) and the user prompt (a template for
every task: `{task}` becomes what you typed, text without `{task}` goes
in front of it, empty sends the task as typed) as named profiles.
*Default* is axross's own prompt and cannot be changed or deleted —
*Duplicate* it to change a copy. *Prompt profile of new requests* picks
the one the next request of every tab uses; the tab still adds its
folder, Plan mode and read-aloud rules. Stored in
`~/.config/axross/agent/settings.json`.

**axross functions** are the tools axross runs itself on the agent's
behalf — outside the agent's sandbox, with axross's own rights: *Remote
files* (the connections open in the panes, backend `pane:<name>`),
*Saved connections* (saved profiles the agent opens itself), *Remote
commands* (SSH/WinRM/… hosts), *MCP servers* and *extension tools*.
They are a way out of a sandbox, so a master switch guards them and is
**off by default**. A production profile refuses every change.

**What a tab may reach** — two layers, both must allow it:

- *Agent Settings > Access* is the ceiling of every tab: the master
  switch *Let agents use axross functions* and each function. Off there
  means off in every tab.
- *Access…* in the tab (or *Agent Settings > Sessions* for all tabs at
  once) is the tab's own choice within it: its master switch and
  functions, its **network** and its **folders**. A new tab starts with
  the master switch as Agent Settings has it.

| Network of a tab | Meaning |
|---|---|
| As the sandbox profile says | the profile's level and allowed hosts (no sandbox: no limit) |
| None | no host at all |
| Only these hosts | the tab's own `host:port` list |
| All hosts | lax sandbox or no sandbox only |

The sandbox level stays the ceiling: a tab only narrows what its level
can do (paranoid offers only *None*, normal and high no *All*). The
network gates the sandbox's own connections, remote work in axross and
http MCP servers alike, and is checked at every connection. A tab's
**folders** are read-only or read-write; read-write only where the
level lets extra folders be (lax, normal) and with *Allow changes to
files*. The tab's *Access…* tooltip sums it up.

**Agent profiles** set up a tab in one go: the LLM profile, the prompt
profile, the protection mode, the sandbox, the tool groups, the axross
functions (master switch, functions, network), *Files read-only*,
*Allow changes to files* / *Allow remote commands* and the MCP servers
it offers — chosen **by category** (the catalog category a server was
installed from, e.g. *Security: Reverse Engineering*; *Category* in
Agent Settings > MCP Servers sets one by hand) and/or **by name** (or by
the catalog entry it came from, so a renamed server still matches).
The arrow beside "+" in the Agent dock offers **New Tab from Profile**,
**Apply Profile…** (also in a tab's right-click menu) and **Edit Agent
Profiles…**; Tools > New Agent Tab from Profile opens one for the active
pane's folder. *Apply Profile…* shows first what the tab would get; it
changes the tab's settings, the folder and the conversation stay, and a
tab with a running task refuses it (stop the task first — the running
task keeps the settings it started with). The tab names its profile
(*Profile: …*) and lists what the ceiling cut or what is missing, with
**Install from Catalog…** (the catalog opens on that category, or
searches the server's name).

A profile **never widens Agent Settings > Access**: with axross
functions off there, a profile's MCP servers are not offered and the tab
says so; Bypass only where it may be chosen; a sandbox profile that does
not exist is kept and refused, never quietly "no sandbox". Under *Files
read-only* a server whose *Asks* is "Every call asks" offers no tool at
all unless it is a container without network and with read-only folders
(see *Files read-only* above) — the tab names each such server and why.

Built-in **presets** (read-only, marked *(preset)*; *Copy* makes an
editable profile of one):

| Preset | What it sets up |
|---|---|
| Files Assistant | axross's file tools, the open remote connections; changes ask; no MCP servers |
| Reverse Engineering | categories *Security: Reverse Engineering* and *Security: Firmware & Forensics*; sandbox *High* |
| Forensics read-only | category *Security: Firmware & Forensics*; files read-only |
| Network & Web Recon | categories *Security: Network Recon*, *Security: Web*, *Security: OSINT*; mode Ask |
| Code & Secrets | servers *git* and *filesystem*, category *Security: Code & Secrets* |
| Remote Ops | remote files, saved connections, remote commands (each one asks); mode Ask |
| Research | servers *fetch*, *memory*, *sequentialthinking*; not files read-only (fetch needs network), *Allow changes to files* off |

A preset whose servers are not installed still sets up the rest of the
tab. Agent Settings > **Profiles** edits your own profiles (New, Copy,
Delete), previews what a tab gets within the Access page and picks the
**profile of new tabs**. Stored in `~/.config/axross/agent/settings.json`
(`agent_profiles`, `agent_profile`); a hand-edited entry is checked like
the rest of the file (unknown keys dropped, wrong types take their
default, a taken name — also a preset's — drops the entry).

**Sandboxes** (Agent Settings > Sandboxes): a tab can run its agent in
bubblewrap, podman or docker. A sandbox profile has a level:

| Level | Network | Folder | Extra folders |
|---|---|---|---|
| lax | the host's | as set | as set |
| normal | allowed hosts only | as set | as set |
| high | allowed hosts only | as set | read-only |
| paranoid | only the LLM | read-only | read-only |

The model's requests, the API key and the consent stay outside: the
sandbox has no network of its own, axross sends for it. Allowed hosts
(`host:port`) are reached through axross and checked on every
connection — a change applies at once. Remote connections, saved
profiles, MCP servers and extension tools also run in axross, outside
the sandbox, so their credentials never enter it; the sandbox's level
and allowed hosts decide whether the agent may use them (paranoid:
none), and so do the axross functions of the tab (above). The level's memory, task and CPU limits hold for podman and
docker; bubblewrap gets them from a systemd user scope (without one only
the memory, through `prlimit`). podman and docker need the image:
`scripts/axross-podman.sh agent-image` ([PACKAGING.md](PACKAGING.md)).

**MCP servers** (Agent Settings > MCP Servers): further MCP servers —
a program (stdio) or an http endpoint — whose tools a tab may offer as
`<server>__<tool>`. *Test* lists their tools. A server set to "always"
asks for every call; "writes" lets tools the server marks read-only run
without asking. A program can run in a sandbox profile; one without
says *runs on this machine, not in a container*. An http server's token
is kept in the keyring. A typed command that downloads code (`npx …`,
`uvx …`, `docker run …`) is never saved as a program on this machine:
*Install in a Container* builds it in rootless podman (no network), or
the reason it cannot be is shown. A hand-edited settings file with such
a command does not start it either (the server is left out, with a log
line), and a container line with widening flags (`--privileged`,
`--cap-add`, host namespaces, other mounts) is refused.

*Tools → MCP Servers…* opens this page (Edit → Settings… → Agent → MCP
Servers). **Add from Catalog…** searches the *MCP sources* and installs a
server into **rootless podman**; nothing of it runs on the host:

- **Sources** (Agent Settings → MCP Sources, each switchable): the
  built-in catalog (official reference servers from Docker's curated
  `mcp/*` namespace plus two security servers, pinned by digest, works
  offline), Docker Hub's `mcp` namespace, the official MCP Registry
  (`registry.modelcontextprotocol.io`), and catalog files or `https://`
  URLs of your own. *Check* reads one and names what it holds or why it
  is refused (wrong schema, larger than 1 MiB, not JSON, an entry
  without a pinned digest …). What a source says is shown as plain text.
- **c0decave MCP Hub** (on by default): a catalog of the same schema at
  `https://raw.githubusercontent.com/c0decave/axross-mcp-hub/main/catalog.json`.
  Only images under `ghcr.io/c0decave/` pinned by a real `sha256` digest
  are taken from it; any other entry (another registry, npm, pypi,
  remote, no digest) is refused with its reason. While the hub does not
  answer, the status line says *not reachable or not published yet* and
  the other sources work as before.
- **Discover** (on by default): curated awesome-lists to browse -
  [R00T-Kim/awesome-offensive-mcp](https://github.com/R00T-Kim/awesome-offensive-mcp)
  (CC0; a snapshot ships with axross, so Discover works offline) and
  [wong2/awesome-mcp-servers](https://github.com/wong2/awesome-mcp-servers)
  (MIT; read live only). Their README is read as untrusted text: category,
  name, description and the GitHub repository link, nothing else - no
  markup, no other link. An entry is **installable via MCP Registry** or
  **installable via Docker Hub** only when that source names the same
  repository (checked in the background, at most 300 requests a run,
  cached for 24 h); otherwise it is **link only**: *Open Repository*, no
  install - axross never builds from a bare GitHub repository.
  *Refresh* reads the lists and checks again.
- **Install**: an image is pulled by digest (Docker Hub's tag digest is
  looked up first; others are pinned to the digest podman reports). An
  npm or pypi package is installed in a container of a pinned
  `node:22-slim` / `python:3.13-slim` image (`npm --ignore-scripts`,
  `pip --only-binary=:all:`) whose only network is the package registry,
  then committed as `localhost/axross-mcp:<name>-<version>` - never npx,
  uvx, npm or pip on the host. A remote (Streamable HTTP, https) server
  becomes an http server. Progress is shown, *Cancel Install* stops it;
  the server is then tested (initialize, tools/list) and switched on if
  the test passed. **Save** keeps it.
- **How it runs**: `podman run --rm -i --init --pull=never` without
  capabilities, with no new privileges, a read-only root, a small
  noexec `/tmp`, process and memory limits. Network **None** by default;
  **Allowlist** reaches only the `host:port` entries given, through a
  proxy in axross (for programs that honour `HTTPS_PROXY`; others get no
  route at all); **Full** any host. Folders only as you choose them,
  read-only unless *Writable* is ticked. Environment values and secrets
  (kept in the keyring) reach the container through a pipe, never on
  the command line or in a file.
- **Uninstall** removes the server and, on Save, its image by ID
  (`podman rmi`, never forced: an image in use, tagged otherwise or there
  before the install stays). **Check for Update** shows a newer digest
  or version; nothing is updated by itself.

**Detected on this machine** (Agent Settings → MCP Servers, and the
Tools list of every Agent tab): MCP servers that are already set up here
are offered with one checkbox, no command to type - the servers of
Claude Desktop (`claude_desktop_config.json`), Claude Code
(`~/.claude.json`, also per project, and `.mcp.json` of the tab's
folder), VS Code (`settings.json` →
`mcp.servers`, `mcp.json`, `.vscode/mcp.json`) and Cursor
(`~/.cursor/mcp.json`, `.cursor/mcp.json`), plus podman images axross
installed (also when the settings lost the server). A tick in Agent
Settings adds the server switched on (Save keeps it), an untick removes
it; a tick on a `detected:<name>` line of a tab adds it, saves the
settings and ticks `mcp:<name>` in that tab, so the model gets its tools
right away. It is then a server like any other (the same confirm modes,
"always" by default). **What is downloaded runs in a container, never on
this machine:** a command that fetches code at start (`npx`, `bunx`,
`pnpm dlx`, `yarn dlx`, `npm exec`, `uvx`, `uv tool run`, `pipx run`,
`docker`/`podman run` …) is installed the contained way on the tick - the
npm or pypi package built in the pinned `node`/`python` container (the
latest exact version when the command names none), an image pulled and
run with axross's hardened podman line, no network; the flags of a
`docker run` line (`--privileged`, `--network=host`, volumes,
`--cap-add`, `--device`, host namespaces, `--security-opt` …) are not
taken over, and the details name what was dropped. What cannot be
converted (a git URL, `--package`, `uv run`, an unknown option …) is
shown but cannot be ticked, with the reason. A program already on disk
runs as it is, in the sandbox profile of new tabs (Agent Settings) or of
the tab where it was ticked, and says so: *runs on this machine, not in
a container*; one that is not on this machine cannot be ticked. The
files are read only, as untrusted data (regular files up to 8 MiB, JSON
or TOML, nothing run). Environment values that look like secrets (by
name - TOKEN, PASSWORD, API_KEY … - or shape) and Bearer tokens are
never written to a log or `agent.json`: switching the server on asks
first and stores them in the keyring. Programs on PATH are not detected:
nothing identifies an MCP server there without running it or guessing
from its name.

A catalog file of your own (schema `axross-mcp-catalog`, version 1):

```json
{"schema": "axross-mcp-catalog", "version": 1, "title": "My servers",
 "entries": [{"id": "nvd", "name": "nvd", "title": "NVD lookups",
   "description": "CVE lookups", "category": "Security", "tags": ["cve"],
   "repository": "https://github.com/...", "license": "MIT",
   "kind": "oci", "image": "docker.io/mcp/vuln-nist-mcp-server", "tag": "latest",
   "digest": "sha256:<64 hex digits>",
   "network": "allowlist", "hosts": ["services.nvd.nist.gov:443"],
   "env": [{"name": "API_KEY", "secret": true, "required": false}],
   "mounts": [{"target": "/data", "description": "a folder", "required": false}],
   "args": []}]}
```

`kind` is `oci` (pinned by `digest`), `npm` or `pypi` (`package` and an
exact `version`) or `remote` (`url`, `bearer`).

**Extensions** can start the agent (`api.run_agent`,
`api.open_agent_tab`), give it tools (`api.add_agent_tool`), add topics
(`api.add_agent_topic`) and follow its events (`api.on_agent_event`).
The bundled *Agent Stats* extension shows a small window above the main
window (a normal window: move, resize, close; it floats on tiling
window managers too) with tasks, answers, tool calls, errors, tokens and time.

A profile whose server is not on this machine or its network asks
first, as what the tools read is sent there.

In a container: `scripts/axross-podman.sh gui --llm-model FILE.gguf`
runs axross on your display with llama.cpp beside it and the profile
already set up ([PACKAGING.md](PACKAGING.md)). Add `--agent-sandbox`
for the bubblewrap sandbox in there: podman masks `/proc`, which
bubblewrap needs to mount its own; without the option the tab says so.
Inside a container use bubblewrap - podman cannot start containers of
its own there.

An MCP client can hand a task to the same local model with
`--mcp-tools agent` (`agent_run`); that model can only read
([MCP.md](MCP.md) §9.9).

### Talking with the agent

The tab's **🎤** button talks to the agent, **🔊** reads its answers
aloud. Speech is recognised by the tab's LLM profile (LLM Profiles,
*Advanced*): locally with Whisper — nothing leaves the machine — or by an
OpenAI-compatible server (`/audio/transcriptions`; a remote one asks
before it hears a recording). Answers are spoken by a local Piper voice.

- **Microphone modes** (Settings > Voice): *push-to-talk* (hold the button,
  or the hold key, default **F9**, while the Agent dock has the focus),
  *toggle* (click to start, click again or pause to end) and
  *conversation* (after each spoken answer it listens again; click the
  button to end it).
- **Recognised text** goes into the task field to read and send, or is
  sent at once (a conversation always sends).
- **What is spoken:** only the answer - no tool calls, no code (a short
  note says that code is shown), no URLs or long paths. Stop, Esc, typing
  or a new task end it. When axross refuses a tool call (Files read-only,
  not allowed, no permission) the voice says so briefly; the first voice
  use of a session greets.
- **Language:** German or English, or *follow the answer*. In German
  speech English IT terms (Server, Backup, Pull Request, …) are spoken in
  English; a term the answer writes in `{braces}` is one too (the braces
  are not shown).
- **Voices** (a tab per language): the voice that speaks the language
  (German: Thorsten or Kerstin, English: Ryan or Lessac), whether it is
  downloaded, **Download** (a second click cancels) and **Listen** - it
  speaks two sample sentences with the values of the tab, saved or not,
  through the output of *Settings > Audio*; a second click stops. Every
  voice keeps its own values of how it speaks: *Speed* (0.5-2×), *Pitch*
  (±6 semitones; Piper has no pitch of its own, so the speech is made that
  much slower and then resampled that much higher - its length stays),
  *Expressiveness* and *Rhythm variation* (how much the tone and the
  length of the sounds vary, 0-200 %), *Volume* (a share of the output
  volume, 10-100 %) and *Pause between sentences* (0-2 s); *Reset* takes
  one value back, *Reset All* the voice's every value. Every spoken answer
  uses them.
- **Setup:** `pip install axross[voice]` (piper-tts, faster-whisper; part
  of axross-full), then **Download** beside a voice on the Voice page, or
  *Help > Features…*, group **Voice**, for the voices and a Whisper model
  (pinned checksums, into `~/.local/share/axross/voice/`).
- **Safety:** confirmations are always clicked, never spoken; the
  microphone is off in the paranoid security mode; audio and transcripts
  stay in memory.

## Settings

**Edit → Settings…** (**Ctrl+,**; on macOS in the application menu) holds
every setting of axross in one window: the categories on the left, the
page of the selected one on the right, and above the list a field that
finds a setting by its name (type *sudo*, *proxy* or *zoom*).

| Category | Settings |
|---|---|
| General | Language (applies at the next start), restore the layout of the last session on start, when a pane becomes the active one (on click, or after resting the mouse 0.5–3 s in it) |
| Appearance | Theme, compact mode, monochrome icons, icon colours (Theme default; Own colours in every theme - also in Hacker and Amber, which draw every icon in one colour; One colour of your choice), font size (zoom), highlight hidden files and their colour (a colour that is hard to read on the theme is used only after a question) |
| Toolbar | Group the buttons by category, show each category's colour behind its buttons, the colour of each category (Connections, Windows & Panes, Files & Search, Media, LLM & Agent, Tools & System, Extensions), *Reset to Defaults* |
| Files & Panes | Show hidden files, open size limit, parallel transfers, RAM workspaces (on / off, size limit, memory kept free) and temporary files in RAM (applies at the next start) |
| Network & Proxy | The default proxy, bypass list, PAC script, a test |
| LLM Profiles | The LLM servers of the Agent and Analysis docks; *Fetch models* opens a list with each model's size, parameters, quantisation and which one is loaded, as far as the server reports them |
| Analysis (sift) | Automatic analysis of the selected file (off: a selection only names the file, *Analyse* explains it), the LLM profile of *Analyse with LLM* (the active one, or one of its own - the Agent keeps its choice), max bytes read per file (it caps a remote file's copy too), time budget per file, vision, context tokens (0 = what the server says), tags per file, categories (one per line), keep sift's results in the cache, *Clear Cache*; sift's version, or a link to *Help → Features…* when this build has no sift |
| Agent | General, Prompts, Access, Sandboxes, MCP Servers, MCP Sources, Sessions |
| Voice | Read answers aloud, spoken language, the voice of each language (Download, Listen) and how it speaks (speed, pitch, expressiveness, rhythm variation, volume, pause between sentences), microphone mode, hold key, recognised text inserted or sent, the pause that ends speaking |
| Audio | Audio backend (Automatic, PipeWire, PulseAudio; the one this run plays through is shown, a change applies at the next start), output device and volume (it scales everything axross plays) with *Play Test Tone*, input device and volume (gain) with *Test Microphone* (a level meter) and *Record 3 s and Play Back*, the result of the audio check and *Check Audio Again* |
| Metadata | How Remove Metadata writes, asking first |
| Search | Hosts searched at once by *Find on Network Hosts*; where the offline and duplicate indexes are |
| Security | Paranoid security mode (kept for the next start; `AXROSS_SECURITY_MODE` in the environment wins), remember the sudo password |
| Extensions | Which extensions are switched on |
| Updates | Check for updates at start, download updates automatically, *Check Now*, the last check (see [Updates](#updates)) |

The **Analysis (sift)** page writes `~/.config/axross/analysis.json`; the
open Analysis dock uses a saved change at once and explains the file on
screen again. Its ranges are sift's own - a value sift would refuse (a
context of 100 tokens, a category named twice) is named above the page and
nothing is saved. sift's results are kept in `~/.cache/axross/sift`
(`$XDG_CACHE_HOME/axross/sift`, readable only by you); *Clear Cache*
removes sift's entries there and nothing else. A broken `analysis.json`
reads as the defaults and is kept beside it as
`analysis.json.unreadable-…` before the next save replaces it.

The **Audio** page touches Qt Multimedia only after the audio check (a
separate process) has answered; when the check fails, the page names the
reason, the tests stay off and the backend can still be chosen and saved.
A saved device that is not plugged in stays in its list as
*(not connected)* - until it is back, the system default plays. A device
plugged in while the page is open appears at once.

**OK, Apply, Cancel** work the same on every page: only pages whose values
were changed are written; OK and Apply check every changed page first and
save nothing at all while one has a problem (that page is shown, the
problem is named above it); then each changed page is saved and takes
effect at once. Cancel, Esc and the [x] discard what was not applied.

*Tools → Network & Proxy…, LLM Profiles…, Agent Settings…, MCP Servers…,
Metadata Settings…* and *Extensions → Manage Extensions…* open the Settings window
on their page. *View → Show Hidden Files* (**Ctrl+H**), *View → Theme* and
*View → Zoom* stay quick switches; they are stored at once, like the page.

## Updates

The one-file binaries (`axross-full`, `axross-slim`, the macOS and Windows
`axross-slim`) update themselves from the GitHub releases of
`c0decave/axross`:

- **Check at start.** Once per start, about two seconds after the window
  is shown, axross asks GitHub's API for the latest release - one https
  request, in the background; the start never waits for it. A newer
  version appears as **Update to X.Y.Z…** at the right of the status bar
  and in the *Help* menu. A failed check (no network, GitHub's rate limit)
  is a line in the log and the status on *Settings → Updates*, never a
  dialog. Releases marked draft or prerelease are ignored.
- **Help → Check for Updates…** checks now and shows the answer, also
  when axross is up to date.
- **The update window** shows this and the new version, the release notes
  (rendered as Markdown; images and other resources in them are never
  loaded, HTML in them is shown as text, and only http and https links
  open, in the browser) and a link to the release page, and offers **Download and Install**,
  **Skip This Version** (no notice for that version again; asked by hand,
  it is still offered) and **Remind Me Later** (no notice until the next
  start).
- **Download and Install** fetches the binary of this build (axross-full
  gets axross-full, a slim build gets its slim one), checks its SHA-256
  against the `SHA256SUMS` of the same release (and against GitHub's own
  digest of the file) and refuses anything that does not match - nothing
  is replaced then, and the partial file is removed. Before any of that,
  the `SHA256SUMS` itself must carry a valid signature: `SHA256SUMS.sig`
  is an Ed25519 signature made with the axross release key, whose public
  half is built into axross. A release without it, or with one that does
  not verify, is refused with "The update is refused: release X.Y.Z is not
  signed with the axross release key" - someone who could change the
  release could change its checksums, but not make that signature. A verified file
  replaces the running binary in one atomic rename, with the old file's
  permissions; the old one stays next to it as `<name>.previous`. It takes
  effect at the next start; **Restart Now** closes axross (it asks about
  unsaved work as on any close) and starts the new version.
- **A folder you cannot write to** (a binary installed by root) is not
  touched: the verified file goes to `~/.cache/axross/update/` and **Save
  to…** puts a copy where you choose.
- **Windows** cannot replace a running program: the new version is saved
  next to the old one as `axross-slim-windows-x64-X.Y.Z.exe`; close axross
  and replace the old file with it (or start the new one).
- **A Python install** (pip or a source checkout) is never replaced; the
  window says `pip install -U axross`.

*Settings → Updates*: **Check for updates at start** (on), **Download
updates automatically** (off: the notice offers the download; on: a new
version found at start is downloaded, verified and installed in the
background and waits for the next start), **Check Now** and the time and
result of the last check. Only `github.com`, `api.github.com` and
`release-assets.githubusercontent.com` are contacted, over https; every
redirect is checked against that list. The default proxy (*Network &
Proxy*) is used; without one, `https_proxy` from the environment. The
check at start does not run with `AXROSS_NO_UPDATE_CHECK=1` in the
environment or in the paranoid security mode; *Check Now* still works.

## Configuration files

- `~/.config/axross/profiles.json` — connection profiles (`0o600`).
- `~/.config/axross/bookmarks.json` — bookmark bar contents.
- `~/.config/axross/session.json` — pane layout, window geometry and
  dock layout at last close; restored on start unless *Restore the layout
  of the last session on start* (Settings > General) is off. Its `window`
  object also holds the look (theme, compact, monochrome icons, font size,
  hidden files) and the language.
- `~/.config/axross/column_prefs.json` — column widths and hidden
  columns, one file shared by all panes.
- `~/.config/axross/settings.json` — small preferences: open size limit,
  pane activation, metadata write mode and confirmation, remember the sudo
  password, hosts searched at once, the security mode, the update settings
  (`update_check_at_start`, `update_auto_download`, a skipped version, the
  last check).
- `~/.config/axross/proxy.json`, `llm.json`, `extensions.json` — the
  default proxy, the LLM profiles, the switched-on extensions (secrets in
  the keyring).
- `~/.config/axross/agent/voice.json` — the Voice settings (`0o600`).
- `~/.config/axross/audio.json` — the Audio settings: backend, output and
  input device, volumes (`0o600`).
- `~/.config/axross/agent/settings.json` — Agent Settings (modes, access,
  sandbox profiles, MCP servers; `0o600`).
- `~/.config/axross/agent/sessions/` — one JSON file per kept Agent tab (`0o600`).
- `~/.config/axross/<provider>_token.json` — OAuth refresh tokens (`0o600`).
- `~/.config/axross/ramfs.json` — RAM workspace settings. `"tmpfs_enabled": true`
  sends every temp file of the process (download/upload buffers past
  8 MiB, archive extraction, FUSE write buffers) to a RAM disk
  (`/run/user/$UID`, else `/dev/shm`) instead of the disk: nothing lands
  on disk, but it takes RAM, so it is off by default. A `TMPDIR` set in
  the environment always wins.
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
