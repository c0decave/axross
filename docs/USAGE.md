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
  Profile proxies cover Axross-owned API/token traffic; the external
  browser consent page may use browser or system proxy settings.
  See [OAUTH_SETUP.md](../OAUTH_SETUP.md) for the per-provider app
  registration recipe.
- **Proxy support.** SOCKS4/4a, SOCKS5, HTTP CONNECT and HTTPS proxies
  (TLS to the proxy), with Basic, NTLM and Negotiate authentication,
  per profile or as one global default (*Tools → Network & Proxy…*) with
  a bypass list and a PAC script. SOCKS5 resolves hostnames at the proxy
  (no DNS leak); SOCKS4 sends host names as SOCKS4a. A "Test proxy"
  button reports which stage fails, and each pane shows its route.
  Backends that cannot be proxied fail closed instead of going direct.
  See [PROXY_SUPPORT.md](PROXY_SUPPORT.md).
- **OpSec overrides.** Profile fields control SSH keepalive, SMB
  workstation name, Telnet NAWS, rsync metadata stripping. See
  [OPSEC.md](OPSEC.md) for the threat model.

## Multi-pane layout

- Add panes with **Ctrl+T**, split with **Ctrl+Shift+H** /
  **Ctrl+Shift+V**, close with **Ctrl+W**.
- Active pane gets a blue border; the **target** pane (where copies
  land) gets a green border. Last-focused pane becomes target.
- A pane becomes the active one when the mouse rests in it for 1 s.
  **View → Activate Pane** sets 1, 2 or 3 s, or **On Click**. Keyboard
  focus follows only from another pane's file list, never out of a text
  field.
- **Alt+Left / Alt+Right** walk through pane history; **Ctrl+Tab**
  cycles.
- Drag-and-drop between panes initiates a transfer (works for
  local↔remote, remote↔remote, cross-protocol).

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

**File > Restore Layout on Start** (on by default) switches this off;
the choice is stored in `session.json` at once and a start then shows
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
overwritten.

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
| `core.archive` | Safe extraction of zip / tar / 7z and single compressed files (`.zip .xpi .jar .war .apk .epub .docx .xlsx .odt .tar .tar.gz .tgz .tar.bz2 .tbz2 .tar.xz .txz .tar.zst .tzst .7z .gz .bz2 .xz .zst`). Zip-slip / bomb / lying-metadata guards; `.7z` needs the `[archive]` extra, zstd Python 3.14 or that extra. |
| `core.packer` | Right-click → **Pack**: zip, tar.gz / .zst / .xz / .bz2, 7z (optionally AES-256 with encrypted file names), or one file as .gz / .zst / .xz / .bz2 — from any backend, never overwriting (`name (2).zip`), never leaving a half-written archive. |
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
| Duplicate Finder | View menu | Group rows by content hash, copy `ax-cas://…` URLs; move selected copies to the axross trash after a live re-check that a genuine other copy survives. |
| View Media… / View Selected Media… | Right-click, View menu | Images, PDFs and videos of the folder (optionally recursive) or the selection as overview grid, click-through viewer or slideshow — see *Editors and viewers*. |
| Show / Remove / Export Metadata… | Right-click | EXIF / GPS / XMP / IPTC, Office properties, PDF info, audio / video tags of the selection — or of the whole folder when nothing is selected (subfolders optional) — see *File metadata*. |
| Identify File Type… | Right-click (selection) | One row per entry: the real type from the content (magic bytes via Qt's MIME database, puremagic, a built-in signature table), the MIME type, what the extension claims and a highlighted *mismatch* when they disagree, size, and for text the encoding and line endings. Reads at most 64 KiB per file through the backend, off the GUI thread, with a 15 s timeout per file — a dead remote gives a "timed out" row. Local files also show `file(1)`'s description when it is installed. Scripting: `axross.file_type(b, path)`. |
| Open Terminal Here | Right-click (also on empty space) | Opens a shell in the terminal dock in the folder: a selected folder, otherwise the folder shown. Local panes get a local shell started in that folder; SFTP / SCP panes get a shell on the same SSH connection followed by `cd -- '<folder>'` (quoted with `shlex.quote`). Disabled, with the reason as tooltip, on protocols without a shell. |
| Open External Terminal Here | Right-click (local panes) | Starts `$TERMINAL`, else the first installed of x-terminal-emulator, gnome-terminal, konsole, xfce4-terminal, alacritty, kitty, foot, wezterm, xterm — with the folder as working directory, detached, no shell involved. |
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
  first, then transfers.
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

- **Text editor** (built-in) — with conflict detection on save and
  a close button in the top-right corner.
- **Hex editor** — useful for triage on remote files.
- **Open size limit** — the text / hex viewers read the whole file,
  so there is a cap: 32 MB by default, changeable under
  *View → Open Size Limit…* (1–4096 MB, stored in `settings.json`).
- **Image viewer** — F3 / double-click, MIME-allow-listed, size-
  capped to keep Qt's allocator happy.
- **Media viewer** — *View → View Media…* or right-click → *View
  Media…* on the folder (*View Selected Media…* for a selection of
  files and folders). Choose the types (images incl. SVG, PDFs,
  videos via QtMultimedia), whether to include subfolders (depth
  1–32; at most 5000 files, symlinked folders are not followed,
  unreadable folders are skipped and counted) and how to start:
  **Overview first** (thumbnail grid with filter, sort by name /
  date / folder and a size slider; Enter or double-click opens an
  item), **Start slideshow** or **Click through**. In the viewer:
  Left / Right / PageUp / PageDown / Space step (stopping at the
  first and last item; inside a PDF they turn pages, past the last
  page to the next item), Home / End, F11 fullscreen, Ctrl+M
  maximize / restore (the window remembers its last size, position
  and maximized state for the next open), wheel or
  `+` / `-` zoom, `F` fit, `1` 100 %, `R` rotate, `S` slideshow
  (interval in seconds; the slideshow loops, a video plays to its
  end), Esc back to the overview, Esc again closes. Works on every
  backend: remote files are copied to a private temp directory up
  to the *Open Size Limit* and removed afterwards; an item that is
  too large, encrypted or broken shows the reason instead. SVG is
  rendered only when it has no DOCTYPE/entities, scripts or
  references outside the file. `paranoid` mode blocks the viewer.
  `I` (or the *Info* button) shows the current item's metadata in a
  side panel, with *Remove metadata* — in the image viewer too.
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

**How removal writes** — *Tools → Metadata Settings…*:

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
| ``.save <name>`` | Save THIS session's submitted source |
| ``.load <name>`` | Paste a saved script into the prompt |
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
- `~/.config/axross/session.json` — pane layout, window geometry and
  dock layout at last close; restored on start unless File > Restore
  Layout on Start is off.
- `~/.config/axross/column_prefs.json` — per-pane column widths.
- `~/.config/axross/settings.json` — small preferences (open size limit).
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
