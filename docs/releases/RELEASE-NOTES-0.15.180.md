# axross 0.15.180 - release notes

The notes of the GitHub release of axross 0.15.180 (the asset
`RELEASE-NOTES-0.15.180.md`). `scripts/assemble_release.py --changelog`
takes the section below; the short entry is in [CHANGELOG.md](../../CHANGELOG.md).

## 0.15.180 - 2026-11-20

0.15.180 closes three complete review rounds of every area of axross:
files and transfers, the protocols, the terminal and scripting, the
viewers and the Media Player, security with the agent and the MCP server,
and the window with search and translations - after the reviews of
search, of every file operation and of every connection type that came
just before. Every fix comes with tests that fail on the old code. The
downloads are the same as for 0.15.179 (Linux, AppImages, macOS, Windows,
packs, wheel and sdist, signed `SHA256SUMS`); installed binaries update to
it. axross-headless-mcp 0.15.180 carries the same MCP server fixes.

**In short** (the update dialog shows the start of these notes):

- **Security:** IMAP, POP3 and LDAP encrypt with STARTTLS before the
  login on their plain ports - a profile on 143, 110 or 389 sent the
  password in clear text. The agent's approval shows where a write really
  goes; neither the agent nor the MCP server can change the code of the
  axross that runs; an MCP server run on this machine has its whole folder
  pinned. The mail docks' leak check catches a code however it is written.
  PDFs, pictures, SVGs, code highlighting and video probing run in
  separate processes that a hostile file can only hang or crash
  themselves. A host name with shell syntax in an rsync profile behind a
  proxy no longer runs a command on this computer; a WinRM folder delete
  or copy never goes into a junction's target.
- **Your data:** a move keeps a source written to meanwhile, a copy onto
  a hard link of itself does nothing, a resume checks what it continues,
  temp files are private from their first byte, a file trashed with other
  hard links comes back, Pack and Extract keep modes, dates and folders.
- **Flash-safe:** no Media Player visualization and no arcade game flashes
  more than three times a second or in saturated red, at any size and
  frame rate.
- **New:** archive passwords (7z, ZipCrypto ZIP); the right-click menu
  from the keyboard; warnings when a share's trash is shared; Find Files
  finds folders and names in any Unicode form; a light or dark theme in
  axross-markdown; bracketed paste and Alt as Meta in the terminal; SSH
  config import with `Include`, `Match` and `ProxyJump`.

### Compatibility

- **STARTTLS for IMAP, POP3 and LDAP.** Without SSL/TLS, a profile now
  upgrades the connection with STARTTLS (STLS for POP3, StartTLS for LDAP)
  before the login and checks the certificate as IMAPS does. This holds
  for profiles saved before as well. A server that does not offer
  STARTTLS, a network that strips it, a refusal or a failed handshake end
  the connect before the user name or password is sent, and the message
  says that STARTTLS was refused. For a server without any TLS, untick
  *STARTTLS before the login* in the profile: the password then travels
  in clear text. In scripts `imap://`, `pop3://` and `ldap://` upgrade,
  `imap+plain://`, `pop3+plain://` and `ldap+plain://` stay plain,
  `ldaps://` is TLS on 636.
- **A new profile cannot be named `local`.** `local` is the local shell's
  name in terminal bookmarks and saved layouts; renaming a profile of that
  name turned every local terminal bookmark into a shell on that host. A
  profile called `local` saved by an older version stays usable, and
  renaming it leaves the local shells alone.
- **Qt's SQL driver plugins are no longer in the binaries.** axross does
  not use QtSql, and the macOS drivers linked library paths a user could
  write to. A script or extension that needs QtSql uses a PyPI install
  with the host's Qt.
- **The macOS and Windows binaries go through the supply-chain gate**, as
  the Linux ones did: the release CI checks every wheel for those
  platforms against the reviewed baseline and builds from the reduced,
  hash-pinned locks only.
- **Printing in the one-file Linux binaries** writes a PDF (they carry no
  CUPS print plugin), as noted for 0.15.179; the PyPI install prints
  through the host's Qt plugins.
- **With a proxy, a pinned IP version needs the server's IP address**:
  SFTP and SCP refuse a host name then, because the proxy resolves names.
- **MCP:** `walk` takes at most 100 000 entries, `recursive_checksum`
  50 000 files and `bulk_copy` 100 000 files, each at most 64 levels deep;
  a call above a cap is refused. `search` returns at most `limit` results
  (default 1000, at most 10 000). An MCP server run on this machine whose
  folder holds more than 10 000 entries, 256 MB or 32 levels does not
  start - move its script into a folder of its own. Python MCP servers
  keep their byte code in a private folder of axross's state, so their
  start compiles the modules once more.
- **Updates** also contact `objects.githubusercontent.com` (GitHub serves
  release files from there), over https like the other update hosts.
- **Telnet uploads** without base64, uuencode or xxd on the server take
  only text without control characters (tabs included).

### Security

**Mail over IMAP, POP3 and LDAP**

- STARTTLS before the login on the plain ports, with the certificate
  checked (see *Compatibility*). The security badge says STARTTLS,
  configured and negotiated.
- The untagged IMAP answers read in clear text before the upgrade are
  dropped: a `* LIST` put in front of the OK by a man in the middle was
  read after the login as the server's own.
- POP3's capability answer before STLS is capped - a never-ending answer
  was read into memory.
- Only ASCII digits name an IMAP message's UID.

**The agent and the MCP server**

- **Approvals show where a write really goes.** Approving `proj/NOTES.md`
  overwrote the file its symlink pointed to; the question showed the
  model's path only. A local write's paths are resolved before the
  question, a path that leads elsewhere is shown as "path → real target",
  and the targets are checked again after the yes: if one changed,
  nothing is written. A `*_b64` twin of a write tool names the path it
  writes, and a sandboxed agent's question is shown uncut.
- **axross's own code is a protected place.** Run from a source folder (a
  checkout, `pip install -e`) inside the MCP root or an agent's folder,
  the write tools could rewrite axross's modules, and the next start ran
  them with your rights. Its packages, resources and top-level scripts, a
  one-file build's binary and AppImage, and a venv's settings and programs
  are protected now; no Python code (`.py`, `.pyc`, a compiled module, a
  `__init__.py` that would shadow a package) is written anywhere below
  the source folder; in the sandbox nothing new can be made at its top
  level.
- **An MCP server run on this machine has its whole folder pinned.** The
  pin covered only the module files beside a Python script: a `.pyc` in
  `__pycache__`, a sub-package or the files a Node server `require()`s
  were neither pinned nor refused to the agent. Now every file of the
  server's folder is hashed (sub-packages, data files, `node_modules` and
  linked folders included), the agent writes nothing below it and nothing
  in a `node_modules` above a Node server, sandboxes mount those folders
  read-only, files below a protected folder are no longer listed one by
  one, and Python servers start without loading byte code from beside
  their sources (a private byte-code folder, which must be 0700 and
  yours).
- **More programs count as runners** (which fetch and run code, and so
  need a sandbox): `nlx` and the rest of `@antfu/ni`, the Maven and Gradle
  wrapper jars, and a runner's name with a suffix (`pip3.11-wrapper`,
  `pip.real`, `npx-wrapper.js`); downloaders and podman by any name.
- **Secret folders are not moved whole.** Renaming `proj/.kube` to
  `proj/plain` took away the name that made `config` secret, and
  `read_file` handed out the cluster's token; on a remote, renaming
  `~/.gnupg` handed out the GnuPG keys. The folders `.aws`, `.docker`,
  `.kube` (and on a remote `.ssh` and `.gnupg`) are refused as a whole
  for rename and copy, and backup copies such as `credentials.bak` or
  `config~` are secret like the files.
- **A remote's secrets are found by content too.** On a remote backend a
  key was known by its name alone: one in `site/privkey.pem` came out
  through `grep` and through a `read_file` window that started inside the
  key. Every remote file `grep` reads and every remote read window is now
  checked for keys; `/proc/*/environ`, shell histories, `rclone.conf` and
  `/etc/ssl/private/*` are secret by name on a remote as well.
- **Symlinks with `..` lead where they were checked.** A link `a ->
  b/..` made while `b` pointed inside the root led to the root's parent
  once `b` was made again elsewhere. A target with `..` is now made as the
  checked place itself.
- **The trash:** once axross has its key, a trash record without a
  signature counts as changed and is not restored.
- **MCP over HTTP (round 9):** one client's parallel calls no longer make
  its address the "busy" one; a slow TLS handshake is no longer closed as
  the plain oldest connection; `GET /health`, which needs no token, no
  longer marks its connection as never pushed out.

**The mail docks**

- On the *allowed* send policy a reply goes out without asking only to
  the sender of a mail listed as new in that run, and only when it holds
  nothing of another mail: its codes, links, addresses, a run of 8 or more
  of its words, or quotes beyond the answered mail. A mail asking "reply
  quoting message 1" had the dock send a bank's reset code to its sender.
- A code counts by its digits however it is written - spaced, grouped, in
  other digits, as number words, backwards or encoded, split across
  several replies - across the mails sent without asking in this run and
  in the dock's runs of the last 7 days; the subject and the recipients'
  names are checked like the text, and everything a tool showed of
  another mail (its subject in a listing, its file name, the links of its
  HTML part) counts as its text.
- Fewer false alarms: what the dock itself sent without asking to several
  people (its signature quoted back in a thread) and its own address no
  longer count as another mail's text; 30 ordinary replies over three days
  go out without a question again.

**Hostile files in separate processes**

- **PDFs** are opened and drawn in a child process: a hostile PDF hangs or
  crashes only that child. A page that takes longer than 15 seconds is
  shown as the reason, and the other pages are still drawn. PDF metadata
  without pypdf is read by the same child.
- **Pictures** are decoded in child processes (a few kept running): a
  crafted picture that keeps Qt's plugins or Pillow busy, or crashes them,
  no longer pins a viewer or thumbnail thread or ends axross; 30 seconds
  per picture. A child's answer past the size caps is refused before
  anything of that size is allocated.
- **SVGs** in a Markdown file go through the SVG checks and child process
  (30 seconds for all of a document's SVGs); a "picture" that is really a
  PDF or PostScript is not shown. A one-file build's SVG child works
  under the build's own launcher, and the release smoke test draws an SVG,
  a PDF page, a PNG and a highlighted line through the binary's own
  children.
- **Code highlighting** (Pygments) runs in a child process in the editor
  and the Markdown reader: a lexer stuck in backtracking froze the whole
  window. The editor waits at most a second, a file that cannot be
  coloured within 60 seconds stays plain; Markdown code blocks have 5
  seconds.
- **Video and Media Player tracks** are probed by ffprobe (when installed)
  in a child before Qt Multimedia opens them: a file whose probe crashes or
  hangs (10 seconds) is not played, and a crashing track in the restored
  playlist no longer ends axross at every start.

**Hostile names and text**

- Invisible characters in names (zero width space, line separators, tag
  characters) are shown as �; right-to-left marks stay. Names with a bidi
  override or a control character are shown as � in viewers and editors,
  status lines and message boxes, window titles, Tagged Files, bookmarks,
  tags and workspace tabs, Properties, File Already Exists and System
  Information (a USB product string, a monitor's name) - `inv<RLO>fdp.exe`
  read `invexe.pdf` there.
- The path bar keeps such a path as typed and flags it with an orange
  mark and a tooltip that names it as the list shows it.
- The log escapes control characters, escape sequences and bidi marks (log
  file, terminal, Log dock and the MCP audit log); remote names with CR, LF
  or C1 characters are refused.
- An archive whose member names hold control or direction characters is
  refused.

**Credentials stay where they belong**

- Speech to text no longer follows a redirect with the API key.
- OneDrive refuses a paging link off Microsoft Graph - the bearer token
  never goes to another host or over http.
- WebDAV follows a redirect for an upload, delete, rename or new folder
  only to the same address; any other redirect is an error naming where
  it pointed, and nothing is done there.
- The Git cache keeps no password or token of the remote URL and is
  private (0700); Git and SVN over a proxied SSH check the host key of the
  server's port.
- iSCSI's CHAP secret never goes on a command line; a node record that
  cannot be written refuses the connect.
- Exchange sends its first request through the profile's proxy too.

**Commands on this computer**

- **rsync behind a proxy:** a host name with shell syntax (`x;touch
  /tmp/p`, `x$(id)`) from an imported profile or a URL ran that command
  on this computer, through `RSYNC_CONNECT_PROG` or ssh's ProxyCommand.
  The host is checked as OpenSSH checks it (CVE-2023-51385) before rsync
  starts.
- **SSH config import:** an imported ProxyCommand (also one made from
  `ProxyJump`) is asked for on Connect; *Deploy SSH Key* asks before it
  runs one, and the SFTP and SCP sessions refuse an unconfirmed one
  themselves. The ProxyJump destination is matched whole.
- **Local terminal:** a failed shell start ends the forked child instead
  of running a second axross.

**Other**

- **WinRM:** a folder delete never goes into a junction's or symlink's
  target, and a folder copy copies a link as the link; a command has a
  deadline; names ending in `.` or a blank are refused. WinRM over HTTP
  (5985) or with an unchecked certificate shows TLS with a weakness.
- **Telnet raw upload:** a file holding terminal control characters is
  refused (the terminal would have acted on them).
- **SCP:** a header size that is not ASCII digits is refused.
- **Private files:** the thumbnail cache is private (0700, each file 0600);
  Decrypt writes the clear text 0600; a file of a RAM disk (`/run/user`,
  `/dev/shm`) is not copied into a trash on another disk; a copy or move
  gives a folder no group or other right its source folder lacked (a 0700
  folder arrived as 0755); a copy never keeps setuid, setgid or sticky.
- **Extensions:** `sys.exit()` in an extension no longer quits axross at
  every start, and no other failure of an extension takes axross down.
- **Build context:** the release signing keys and every key file stay out
  of the container build context.

### Data safety

**Transfers**

- A move keeps a local source that was written to or replaced while it was
  copied, also at the same size (transfers, the server-side fallback and
  scripts).
- A copy or move onto a hard link of its source does nothing and says so;
  both names stay.
- Before a partial is continued, its first and last 64 KiB and windows
  spread through it are compared with the source; a partial that matches
  but may not be continued restarts from byte 0 under a fresh name (only
  the tail was copied before).
- A resumable copy into a local folder makes its partial `O_EXCL` with the
  source's mode, never through a link, and appends only to your own
  partial.
- Names that differ only in case are asked about on destinations that do
  not tell case apart (SMB, Windows, macOS, FAT and exFAT).
- A folder copied or moved into a symlink to itself no longer nests ~975
  levels deep; a folder into itself is refused up front; a link to the
  same folder is the same folder.
- A second source tree merged into a folder this batch made no longer
  removes the file the first one wrote.
- Two jobs on the same local path no longer run side by side because
  they came from different panes.
- A full disk's failure no longer says its partial file is kept.
- A copy across file systems (Move, Move to Trash, a restore) is 0600 /
  0700 while it is written; a folder's named pipes and sockets are made
  again at the destination, as `mv` does; a device, pipe or socket as a
  source file is refused (a character device was read for ever).
- Temp files over SFTP, SCP and on an NFS mount are created with the
  source's mode; an SFTP save keeps the file's owner and group from the
  empty temp file on; an in-place save's backup is `O_EXCL` and no more
  readable than the file.
- An rsh upload goes to a temp file and replaces the target only once all
  data has arrived.
- New File never empties a file that appears meanwhile.
- Checksum Manifest's Replace and Update write over an existing
  `SHA256SUMS` where a rename does not replace (SMB, Windows).
- Encrypt, Decrypt and the text and hex editors read a file to its end
  across short reads - a network reader showed only the first part as the
  whole file, and a save wrote that part back over it.

**The trash**

- A file trashed with other hard links and edited through one of them is
  the same file and comes back; data put in its place is refused, and the
  message says whether the record or the data changed.
- Cancel during Empty Trash stops it.
- Where the trash of a share lives is said before anything goes there (see
  *New*).

**Archives**

- Pack: a `.gz` names the packed file in its header; a socket, pipe or
  device in a folder is left out and named; 7z refuses a name it cannot
  store; tar and 7z keep dates before 1980; 7z keeps the times and modes
  of remote files and every folder, and no setuid bits of a local file.
- Pack writes the archive with a new file's mode (0666 less the umask),
  private only when it holds something private, into the temp file made
  for it; a killed pack's temp file is removed by the folder's cleanup; a
  name below a packed folder that cannot be an archive member is left out
  and counted; a local source is read as the walk saw it.
- Extract: each folder gets the mode the archive stores for it, less the
  umask; a 7z whose folders are read-only or closed is extracted whole; a
  7z with too many members is refused before it is listed; Extract
  Selected on a folder takes everything in it.
- ZIP names without the UTF-8 flag are read as unzip and 7-Zip read them
  (UTF-8, the code page found across all names, else cp437), and the
  Unicode Path field is taken; a ZIP folder entry ending in a backslash is
  a folder; a tar holding a file twice extracts the last copy.
- Cancel stops a 7z, a RAR or a single compressed file while its data is
  written; damage is told from a wrong password; names Windows does not
  allow are refused on Windows and on Windows shares, NTFS and FAT disks.
- The ZIP ratio guard applies from 64 MiB per member - axross could not
  extract its own ZIP of a megabyte of zeros.
- An encrypted 7z says it is encrypted instead of showing its header;
  only a member recognised by its content goes to the system application.

**Metadata**

- Remove Metadata on a folder cleans hidden files too and says what a run
  left out: unreadable or too deep folders, the file cap, folder links,
  and types it cannot clean (HEIC, AVIF, RAW, SVG, `.doc` ...).
- PDFs lose XMP and PieceInfo wherever they are and objects nothing uses;
  a PDF listing more objects than are checked is not read as empty; Office
  files lose every property part (found by their relationships, Strict
  OOXML and embedded ODF objects too) and the zip entries' comments.
- A hard-linked file is cleaned in the file itself, the trash keeps its
  own copy, and the cleaned copy is made beside the file, not in `/tmp`.
- Ctrl+Z passes over a removal it can no longer reverse (the file edited
  since, the trash emptied) and says why; a partly failed undo puts back
  the rest next time.

**Compare, size and names**

- Compare Panes' *Delete…* removes only rows known to be on one side; a
  tree deeper than the walk goes is not reported as matching; Cancel and
  Close stop the hashing too.
- Calculate Size names the folders it could not read, and an entry whose
  size cannot be read makes the total a lower bound.
- A name no folder can hold (`../x`, `a/b`, a NUL) that an SFTP, SCP or
  SVN server lists is an unusable row - shown, never acted on, listed as
  not usable by a folder copy; S3 and Azure keys with an empty, `.` or
  `..` part are listed the same way.
- Batch Rename takes the tags along, also in a chain, and a
  case-insensitive replace takes the replacement as written.

**Settings and state**

- `settings.json` saves have a temp file each and are merged across
  processes; `session.json` keeps the preferences another axross stored,
  every writer takes its file lock, and the window's state files are
  synced to disk before they replace the old ones (a crash right after
  left an empty `session.json`).
- Bookmarks: two windows no longer undo each other's group changes; a
  newer axross's bookmarks survive an older one's edit (an unknown kind is
  kept as it is); entries that cannot be kept are copied aside as
  `bookmarks.json.unreadable-*` before a save; groups nest up to 16 levels.
- A profile rename takes its bookmarks, terminal bookmarks, Smart Folders
  and saved panes along, and is not undone when another axross quits.
- Scheduled jobs: one run at a time across processes (a lease); a broken
  `jobs.json` is set aside only while it is still the file that could not
  be read, and a job row that cannot be read is kept in
  `jobs.json.unreadable-*`; Run Now records the run's start.
- A layout of more than 256 entries comes back as far as it fits; a layout
  axross saved itself is no longer refused as too large; one bad splitter
  size no longer loses the whole layout; a dock bound to a workspace comes
  back on it.
- The Scripts dock: a case-only rename (`Backup` → `backup`) no longer
  deletes the script; `save_script` and the console history write every
  byte or fail; `extensions.json` keeps the switch another axross made.

**Connections**

- iSCSI matches the profile's target by its whole IQN - never the device
  of `…:disk10` for `…:disk1`.
- A connection released while it reconnects no longer closes another
  pane's live session.
- rsync deletes a folder named `- x` or `+ x`; database file systems
  rename only the rows truly under a folder; Git commits no `.git` path
  and no invalid branch name; a cancelled OneDrive or Google Drive
  overwrite whose last part may have reached the server is rolled back.

### Photosensitivity

The Media Player's visualizations and the arcade are flash-safe (WCAG
2.3.1 / 2.3.2): whatever the sound does - a gated synth, radio static,
noise that differs left and right, short bursts - no area of the picture
flashes more than three times a second, and none flashes in saturated red.
This holds at any size and frame rate.

- The bars turn together at most five times a second and otherwise hold
  where they turned; level colours either side of the red cap are
  neighbours.
- The oscilloscope keeps its points 3 px apart and no longer flashes with
  noise in a small face; the stereo scope draws dots; a small window shows
  fewer, wider bell curves and fewer terrain rows.
- The kaleidoscope has a flash guard of its own (a synth gated at 8 Hz
  flashed it 7 to 9 times a second in a dock-sized face at 60 fps).
- No face flashes at 60 fps, in a small face or in a red scheme.
- Arcade: no red flash when Byte is caught (the screen dims); frightened
  daemons and fleeing drones blink twice a second. Every game is tested
  under a flash meter, from the title to its worst moments.

### New

- **Archive passwords.** An encrypted 7z and ZIP members encrypted with
  ZipCrypto open with their password: the pane and the archive view ask
  for it and keep it in memory only while the archive is open; a wrong one
  is said and asked again; an AES-encrypted ZIP member is named (open it
  with 7-Zip).
- **The right-click menu from the keyboard.** F10, Shift+F10 and the Menu
  key open it at the current row.
- **Shared-trash warnings.** On S3, SMB, WebDAV, FTP and the cloud backends
  the axross trash is the folder `.axross-trash` at the top of the share,
  where a trashed file has that folder's permissions; only this machine's
  disk and SFTP have a private (0700) trash. Move to Trash names the trash
  folder and offers *Delete Permanently*; Remove Metadata in place says the
  originals go there and offers *Cleaned Copies Instead*; the Duplicate
  Finder adds the same note; a viewer's Del on a share asks the pane's
  question.
- **axross-markdown's theme.** It follows the desktop's light or dark
  scheme; *View → Theme* (Alt+V) chooses another, kept in its own settings.
- **Find Files** finds folders by name (category *Folder*), names in any
  Unicode form and case (`strasse` finds `Straße`, a Mac-written `Ärger`
  is found), brackets as part of a name (`Song [Remix]`), text in Latin-1,
  Windows-1252 and UTF-16 files; sizes take a decimal comma (`1,5M`); a
  file below two ticked folders is one hit; the window opens with the
  focus in Name.
- **The pane filter** takes name patterns (`*.pdf`, `*.jpg *.png`), finds
  decomposed umlauts and no longer goes along into the next folder.
- **Find in Index** stays open beside the window and follows the active
  pane, searches sizes above 2 GB and by date, opens a hit in the pane on
  its connection with the file selected. *Index Active Folder* says when a
  folder cannot be read and no longer walks into folder links.
- **Find on Network Hosts** stays responsive with many hits, matches a
  name anywhere and in any case, opens a result on Enter.
- **Terminal:** keys as xterm sends them (Enter is CR, Alt+key is Meta,
  Shift+Tab); bracketed paste - a pasted command list no longer runs line
  by line; a large paste into a busy shell (local, SSH, Windows) waits in
  a queue and never freezes the window; a pinned terminal pane takes every
  key typed in its window.
- **SSH config import** reads `Include` (16 deep), `Match` blocks,
  `ProxyJump`, negated hosts and `Port=2222` as OpenSSH reads them, takes
  the first value of a setting and expands `%h` in HostName.
- **The path bar** takes `~` and paths relative to the folder shown;
  **going up** selects the folder just left; a renamed or new entry is
  the selected one afterwards.
- **Show Checksum** hashes a local file with progress and Cancel, and
  offers SHA-256 by reading where the server's checksum fails;
  *Permissions…* works on one entry.
- **Viewers:** every picture opens fitted to the window and stays fitted
  until you zoom; Del moves the shown file to the trash, Shift+Del
  deletes after its own question; F3 shows `.pgm`, `.pbm` and `.pnm`.
- **Tagged Files:** *Go to File* selects the file in a pane.
- **The Console** runs a pasted block of several statements and keeps it
  as one history entry.
- **setuid, setgid and sticky** show as `ls -l` shows them
  (`-rwsr-xr-x  (4755)`).

### Fixed

**Protocols**

- WebDAV: a redirect never makes a write a success or sends a file
  elsewhere; user names and passwords go as UTF-8.
- Azure Blob: a blob with snapshots can be deleted and renamed; a SAS URL
  quotes the blob name. Google Drive writes reach shared drives.
- FTP: a streamed download's 426 is an error that stays; listings stop at
  300 000 entries.
- Telnet: a timed-out command ends the connection (the next action logs
  in again); a name holding the prompt marker is listed as it is. Cisco
  Telnet: a line that is the device's own prompt no longer ends an answer;
  `clear counters` answers `[confirm]`.
- SCP: folders and links are known on a server in any language. Shell
  listings (SCP, Telnet, rsh, ADB, rsync) keep a name holding ` -> `.
  `normalize('')` is the root on every backend.
- NFS: a READDIR cookie that comes back is a protocol error at once,
  NFSv4 caps the whole folder; an NFSv3 kernel mount finds mountd through
  rpcbind.
- SVN: a listing is read in steps under a 64 MiB cap. ADB: a command's
  answer is at most 64 MiB, and exec stops at its time-out. PST and CFB
  (`.msg`) files are read with bounded work.
- Git: a `git://` remote has a timeout (15 s to connect, 60 s per answer).
- Exchange: every attachment gets a name of its own.
- SNMP: a GET of a missing object raises `FileNotFoundError`; SNMPv3 knows
  SHA-2 and AES-192/256, and unknown protocol names are refused.
- Proxies: rsync over SOCKS4 resolves through the proxy (SOCKS4a) and
  takes a proxy password.
- SFTP lets go of the channels of threads that have ended. *Deploy SSH
  Key* reads a remote `authorized_keys` of up to 4 MiB.

**Terminal and scripting**

- A long OSC or DCS payload (imgcat, sixel, a large OSC 52 copy) is no
  longer printed; ESC inside a CSI starts a new sequence; erase, insert,
  delete and resize take a wide character whole.
- A terminal dock tab keeps its output once; a local shell that cannot
  start says so in the dock.
- `axross.toast()` and `axross.message()` from a worker thread build their
  widgets on the GUI thread; a toast closed before its timeout, or with a
  timeout out of range, no longer raises.
- A Scripts dock run ends with the axross that started it, also when
  axross is killed or crashes, with what it started.
- Scheduled jobs: no failure for a refusal, short details, a clock set
  back makes a job due at once; every run reports through one relay entry.
- `axross.remove_bookmark` with an index outside the list raises
  `IndexError`; bookmark functions raise `OSError` when the file could not
  be written; `bookmarks_export` keeps terminal bookmarks and Smart
  Folders apart.
- Extensions: an exception from `activate()` of any kind, a dock deleted by
  the extension itself, `add_dock` of something that is no widget, a stale
  start marker - none of them stops axross or keeps the extension
  suspended; an extension's agent tool that calls `sys.exit()` is an error
  for the model, not a stuck Agent tab.
- Start: a `session.json` whose workspace list holds a non-object no
  longer stops axross; Restore Last Session shows a terminal of a missing
  profile as a placeholder, never as a local shell.
- The update check finishes when `settings.json` cannot be written.
- Asking whether pip is there no longer switches setuptools' distutils
  off.

**Viewers and media**

- Image viewer: zoom is a view transform - zooming far in no longer builds
  huge pixmaps (it crashed at about 14.5x); a fitted picture uses the whole
  view; Del and a drag take the picture on screen; a held arrow key turns
  at most three pictures a second.
- Media viewer: a PDF page that could not be drawn is tried again on the
  next visit; the drawn pages kept are bounded at 256 MB.
- Thumbnails: the pane's Thumbnail View draws SVGs and the first page of a
  PDF the safe way; the cache holds at most 20 000 thumbnails.
- Editor: saving no longer hangs for minutes over line endings; CR or
  U+2029 line ends are not one long line; a line longer than 200 000
  characters opens wrapped, past 1 000 000 also read-only (with *Edit
  Anyway*); the text editor dialog reads and saves UTF-16 and works off
  the GUI thread.
- Viewers keep their title bar on the screen and open even with a stored
  position past the screen's range.
- The Media Player fits a narrow dock again with its -15 s / +15 s
  buttons.
- Markdown reader (reviews 17 to 19, axross-markdown 0.16.1 to 0.16.3): a
  text the parser cannot read, or a formula nested more than 64 deep, is
  shown as written with a note; Export and Print take the whole page with
  progress and Cancel; Find reaches folded `<details>`; wide tables scroll
  sideways; a table copies as tab-separated rows; Latin-1 files; boxes
  across a PDF page break stay in the margins; the zoom button shows the
  level; long lines, inline footnotes and many links no longer hold the
  window; `axross-mdcat` handles `--watch` of a missing file, closed pipes
  and full disks.

**Window, search and translations**

- Every window the menus open fits a 1024x600 screen, also in German
  (Mail Docks, Mail Project, System Information); dialogs wrap a long name
  or path instead of growing past the screen or cutting it; the pane
  footer no longer asks for the width of a 5000-character status.
- Split, close and extract keep the keyboard in a file list; a split or
  pane drop is refused when the panes would no longer fit.
- Pane sort: descending keeps `.` and `..` on top and folders before files.
- "Find a setting" shows the tab of a hit.
- Counts read as counts: "1 file", "3 files" in some fifty texts, with
  German for both forms; the busy strip's Cancel is disabled while
  cancelling in every language; more messages speak the interface
  language.
- Themes: a muted wrapped value is muted in every theme.
- Tagged Files fills its table once (twice as fast on large tags).

### Known limitations

- **Binaries:** the macOS binaries are only ad-hoc signed, not notarized,
  and the Windows ones are not signed (Gatekeeper and SmartScreen warn at
  the first start); there is no macOS build for Intel Macs and no Linux
  build for arm64. The AppImages need FUSE to mount themselves; without
  it, start them with `--appimage-extract-and-run`.
- **Printing on Linux (binaries):** *Print* writes a PDF (no CUPS plugin).
- **MCP server over HTTP:** from the client's own address (or its IPv6
  /64), connections that trickle a byte every few milliseconds look more
  alive than a slow TLS handshake and can push it out of a full server -
  an attacker needs that very address (docs/MCP.md).
