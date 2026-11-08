# Changelog

What changed in each axross release, for the people who use it. The full
notes of a release, with every fix, are on its
[GitHub release page](https://github.com/c0decave/axross/releases).

## Unreleased (0.15.177)

0.15.177 is the first release since 0.14.136 with one-file binaries for
Linux, macOS and Windows: installed binaries update to it. Three rounds of
reviews of the whole code (backends and transfers, security, the windows,
the extensions, the entry points, concurrency, the docs against the code)
found and fixed more than 140 bugs; every fix comes with tests that fail on the
old code.

### Fixed

- **Right-click menus are freed once they close.** Each right click in a
  file pane left its menu (four menus, ~70 actions) on the pane - 500 right
  clicks grew the process by ~130 MB - and kept switched-off extensions'
  modules alive. The archive pane, Find Files, CAS, metadata, bookmark,
  chat, network search and column menus did the same.
- **POP3 mail reaches the mail docks and the Mail Project.** A dock on a
  POP3 mailbox read "INBOX", which POP3 does not have, and a message path
  was "//1_x.eml", which was refused: no dock saw mail, and the Mail
  Project imported nothing. Import from Mailbox suggests "/" for POP3 and
  closes its connection when done.
- **A mail dock's settings never swap a gone sandbox for "(no sandbox)".**
  A mailbox, LLM or sandbox profile renamed or deleted since is shown as
  "<name> (missing)" and OK refuses until one is chosen; before, OK saved
  the first entry of the list without a word.
- **The SMTP password of a mail dock goes through the keyring check of the
  profiles**, and a password no keyring took is reported instead of being
  dropped silently.
- **One damaged .pst / .ost no longer ends a Mail Project import.** A block
  that does not inflate or a broken table costs that folder or message,
  counted in the import log; the other files are imported, and the log and
  index.csv are always written.
- **Mail Project imports are ~25 times faster**: the index is committed in
  batches (every 200 messages or second, and at the end) instead of once
  per message, and each DNS name is asked once per import.
- **The bundled extensions speak German**: menu, right-click and panel
  labels go through the catalogue (Agent Stats, Markdown Preview, Entropy
  Heatmap, the Forensic Tools and VirtualBox entries, the Drives panel).
- **The Agent tab names the switch a refused tool needs** (a tool group,
  Allow changes to files, an extension's line under Tools, or Agent
  Settings > Access) with a link to it, and tells the model the full name
  of a tool it shortened; a profile's note about axross functions links to
  Agent Settings > Access, and a tab from a profile shows the profile's
  name until its first task.
- **Smaller fixes from the features review:** Scheduled Jobs refuses a
  script that does not exist (with the saved scripts to pick from), says
  so in a sentence for a deleted one and has Run Now; metadata_read gives
  the real size of a file it does not read; Create SHA256SUMS offers
  Update / Replace for an existing manifest and checksums a selected
  folder's files; the Media Player says "No audio device"; Forensic Tools
  and VirtualBox offer "Show in Features…" for a missing program; narrow
  dock titles end in "…"; mail_list_new and the handbook describe how a
  dock marks mail as handled.

- **Enter in "File Already Exists" skips the file.** With one conflict the
  focus sat on Overwrite, and Qt made the focused button the default:
  Enter replaced the existing file. Skip is now the default and has the
  focus; no Overwrite button is ever the default. Cancelling the question
  now says in the status bar that nothing was copied.
- **F5 with both panes on the same folder copies nothing onto itself.** At
  the first start both panes show the home folder; F5 asked to overwrite
  each file with itself and ended "0 copied, 1 failed". The status bar now
  says the source and the destination are the same folder.
- **Connection errors are one sentence, in your language.** SFTP said
  "Cannot resolve host 'x': [Errno -2] Name or service not known",
  "Cannot connect to 127.0.0.1:1: [Errno 111] Connection refused" or, after
  10 s, "No existing session" - in English in the German window too. The
  message now names the cause and the host ("The host name x could not be
  resolved…", "127.0.0.1 refused the connection…", "did not finish the SSH
  handshake in time…"). A failed transfer shows the same kind of sentence
  in the Transfers panel; the raw text stays in its tooltip and the log.
- **Watch Video explains a failure.** "github.com answered HTTP 404"
  became "This tour video is not published yet", a network failure gets a
  plain sentence, and the box offers Start Tour instead.
- **The German window is German.** Find Files' type boxes, Help > Features
  (columns, groups, names and notes), the OAuth set-up steps of Connect to
  Server, its key and share labels, the Pack submenu, the tab bar's scroll
  buttons, "Local" in the pane header and "bytes" now follow the language;
  sizes use the decimal comma ("1,1 MB"), and the shortcuts in the menus say
  Strg / Umschalt / Entf like the rest of the window. A new test walks the
  German window and fails on any text without a German entry.
- **The German tours and handbook name the buttons the German window
  shows** ("Überschreiben", "Fehlgeschlagene wiederholen", "In den Trash
  verschieben", "Im Keyring speichern" ...), in the narration of the tour
  videos as well.
- **Small screens.** Settings, the Handbook and Features opened taller than
  a 1024x600 screen, and Connect to Server widened itself off its edge; they
  now fit and stay on the screen. The handbook's contents no longer squeeze
  their rows together from the twelfth entry on.
- **Smaller things.** Zoom Out has a minus icon (it showed the close
  cross), the "left" and "previous" entries point left, the Workspace menu
  has mnemonics and icons, F1 works in Keyboard Shortcuts, the Compare Panes
  summary wraps instead of being cut off, the duplicate finder has one name
  in both menus, About lost a double full stop, and "axross" is written one
  way.

- **FTP copies and deletes dot files on servers without MLSD** (vsftpd,
  pure-ftpd). Those servers leave .htaccess, .env, .git and every other
  name starting with a dot out of a plain listing: a folder copy left them
  behind without a word, and a recursive delete removed the rest and then
  failed on a folder that was not empty. Listings now ask with ``-a`` (and
  fall back to the plain command on a server that refuses it). A file's
  listing is no longer shown as a folder holding the file itself, and a
  folder's date no longer sits hours off its files when the server prints
  its listing on its own clock.
- **FTP through a proxy no longer connects where the server tells it to.**
  The data connection went to whatever address the server's PASV answer
  named: a server behind NAT that announces its private address failed, and
  a hostile server (or anyone on a cleartext connection) could make the
  proxy fetch an internal address as the "download". The data connection
  now goes to the server you connected to, as without a proxy.
- **An append on a mounted cloud, SMB or FTP folder no longer replaces the
  file after one failed request.** A stat that failed with a 429, a 503 or
  a dropped connection was reported to the kernel as "no such file", so
  ``echo line >> log.txt`` created the file anew and the old content was
  lost. Such a failure is now an I/O error; only a definite "not found"
  lets a new file be created.
- **SMB says what went wrong.** A missing path, an existing name, a file
  where a folder was expected and a refused permission all came back as the
  same plain error; they now keep their kind, so copies, conflict checks and
  mounts react correctly. Writing or renaming a file to a name ending in "/"
  is refused instead of creating a file of that name.
- **SFTP: files whose names are not UTF-8 can be opened, renamed and
  deleted.** A latin-1 name showed in the listing but every action on it
  failed with "No such file", and deleting its folder stopped there. Names
  now round-trip byte for byte, as on the local disk. A rename that must not
  replace an existing file now says "exists" when it is refused.
- **Nextcloud / ownCloud checksums are read correctly.** All checksums of a
  file arrive in one field; SHA-1 compared as different from every other
  backend and MD5 was never found.
- **Clearer errors on S3, FTP, SCP, Telnet, RSH and ADB.** Reading a file
  that is not there now says "not found" (was a generic failure), listing a
  file says "not a folder", creating a folder over a file says "exists",
  and a file renamed to a name ending in "/" (SCP, WebDAV) is refused
  instead of creating a file of that name.
- **S3-compatible stores that leave out KeyCount** (older Ceph RGW and some
  gateways) no longer show every folder as missing; deleting such a folder
  works again.
- **Google Drive, OneDrive, SharePoint and Git show as available only when
  all their packages are installed**, instead of failing at connect.
- **Rsync: renaming a file onto itself no longer deletes it.**

- **The selection stays on the entries you selected** (a slip of the faster
  pane filter in this release). With a whole long list selected (Shift+click
  from the first row to the last), Show Hidden Files selected the hidden
  entries too, a filter change to as many other entries selected all of
  them, and a narrowing filter dropped the whole selection. A filter change
  keeps exactly the selected entries still shown again, as 0.15.176 did; a
  sort keeps them as well.
- **Undo of a large move or Move to Trash is whole or refused.** Ctrl+Z
  read only the newest part of the operation journal: after a move of
  8,000 files it offered to move about 3,000 back and then counted the
  whole move as undone, so the rest could never be undone. Ctrl+Z now
  reads every entry of the operation, from the current journal and the
  rotated one, and undoes all of it; when its first entries are no longer
  in the journal, it says that the operation is too large to undo and
  changes nothing.
- **Google Drive no longer makes a second file of a name.** A name lookup
  read only the first page of Drive's answer, which may be empty while more
  follow: saving report.txt then created a second report.txt (and a second
  folder for a New Folder), and from then on the name could not be opened.
  Every page is read now; a name two items share is refused as ambiguous.
- **Cloud drives retry when the service says "try again".** OneDrive and
  Google Drive retry a throttled (429) or failed (5xx) request a few times
  with growing pauses, waiting as long as the service asks (at most 30 s);
  a OneDrive upload continues where it stopped instead of failing after one
  bad chunk. Dropbox no longer waits without end on a throttled account.
- **Saving to a cloud drive shows "Cannot save file" when it fails.** A
  full Google Drive, Dropbox or Azure share, or a refused upload, showed
  "Unexpected Error" instead. Every cloud error now says what happened
  (not found, exists, no permission, no space, try again), also to a FUSE
  mount: a throttled request no longer looked like a missing file there,
  which could replace a file by an empty one. Reading a missing Azure file
  says "not found".
- **Dropbox: Copy with "overwrite" onto an existing file works**, and a
  taken name is reported as such.
- **Cloud drives: a name ending in "/" is a folder.** Saving, renaming or
  copying a file to such a name wrote a file on Google Drive, OneDrive,
  Dropbox and Azure Files; it is refused now. Moving a Google Drive folder
  into itself is refused, as is a name with control characters that the
  listing would hide.
- **Moves and copies keep your data.** A move onto a destination that is
  the same file under another name, a move whose integrity check fails after
  the rename, read-only (0400) sources, and the order in which Empty Trash
  works no longer lose or duplicate files. A failed overwrite of an S3 or
  Azure Blob object keeps the old object until the new one is checked.
  Copying an S3 object larger than 5 GiB works (multipart copy).
- **Backends.** Cloud profiles no longer share one session; stale Google
  Drive ids, Git lost updates, dropped SFTP names, NFS and iSCSI
  disconnects, and empty FTP and ADB listings are handled. IMAP, Exchange,
  Azure Files and Google Drive edge cases are fixed. A typo in an S3 path no
  longer lists as an empty folder. WebDAV no longer shows a file as an empty
  folder, and a name it cannot carry is refused instead of breaking the
  folder's listing. SCP shows the server's dates correctly. Creating a
  folder over an existing SFTP path says that the name is taken, and a
  WinRM move refuses to overwrite an existing file.
- **Window.** Every move asks the production countdown (undo too). Closing
  the window waits for background work; quit asks about running transfers
  first and no longer crashes during a stuck transfer. Session restore and
  archive members work again. Connection Manager keeps typed secrets per
  profile, and Deploy SSH Key uses the proxy.
- **Extensions and devices.** A broken extension manifest no longer stops
  the start; unloading an extension frees its actions, threads and
  submodules. Bluetooth dialogs clean up and show passkeys; the voice and
  the Arcade follow a new output device; an equalizer change is saved on
  close; game difficulty, rock collisions and pause are fixed.
- **Mail and NFS.** SPF, DKIM and DMARC give the right verdicts; the safe
  HTML view, PST walks and the link scan are bounded; NFSv4.1 sessions
  recover. The mail dock no longer brings back a mail the agent already
  handled.
- A tooltip set by keyword (`setData(..., role=ToolTipRole)`) was shown as
  rich text; remote names in such tooltips are now defused like all others.
- **WebDAV** showed as available when `requests` was missing; boto3
  uploads to reverse-serve over HTTPS failed; the NFS check missed a
  missing `umount`.
- **Scripts and FTP.** `axross.save_profile` and `delete_profile` raise
  `OSError` when the profiles file could not be written (a full disk),
  instead of going on as if saved. An FTP file renamed to a path ending in
  `/` is refused, as on every other backend; it used to become a file of
  that name without the slash.
- **Updates of releases with many files.** The update check uses every
  file GitHub lists for a release, not only the first 100. GitHub sends
  them all in one answer, sorted by name; further pages are asked for only
  when an answer ends at exactly 100, and a file listed twice counts once.
  The pack wheels that PyPI has are no longer attached to the release: an
  axross-base fetches them from PyPI and checks each against the signed
  pack manifest. That keeps the release well under 100 files, so the binaries
  of 0.14.136, which look at the first 100 only, find the checksums, the
  signature and their binary. When GitHub's latest release is not an
  axross version, the check now says so and names the releases page.
- **FUSE mounts** report when the mount could not be made (no `/dev/fuse`,
  a busy mount point) instead of looking mounted.
- **Windows checkout.** A file named `*.json` in 0.15.176 made the
  repository impossible to check out on Windows, so 0.15.176 had no macOS
  or Windows binaries. It is gone, and a test keeps every file name valid
  on Windows and macOS.
- **IMAP keeps mail that other programs only marked as deleted.**
  Disconnecting, or renaming or deleting the open mailbox, after a refused
  delete, a flag change or a move no longer purges every message flagged
  as deleted in it - also ones Outlook or Thunderbird had only marked.
  Moving a message (drag and drop, `imap_move`) checks that it is the
  message listed and that it is still there, uses the server's MOVE, and
  never reports a move that left the message in both mailboxes; a server
  without MOVE or UIDPLUS refuses it while other messages there are marked
  as deleted. A mailbox of more than about 125,000 messages can be opened.
  Deleting a missing mailbox or a name that is no message says so.
- **Exchange** deletes a message into Deleted Items, as Outlook does,
  instead of deleting it for good.
- **WinRM** copies a folder with everything in it (it made an empty folder
  and reported success) and refuses to copy into an existing folder. Names
  with umlauts and other characters beyond ASCII are listed correctly and
  can be opened. A missing path is reported as not found, and listing a
  file is refused.
- **Git** sessions opened from a URL see what was pushed upstream since
  the first clone; they showed the files as they were then, and a change
  was committed on top of that old state.

### Security

- The agent's protected home places hold inside the sandbox, through
  symlinks and in Windows and macOS spellings, and are mounted read-only;
  more places are protected.
- Reverse-serve refuses S3 subresources and CopyObject instead of
  overwriting or deleting, decodes chunked bodies and speaks HTTPS.
- Closed: wrapped downloaders, DNS rebinding in the host relay, secret
  reads over MCP (also through group tools), the proxy peer check on
  macOS and Windows. Downloader detection fails closed.
- Tar, PNG and image-cleaning bombs are bounded and can be cancelled;
  bidirectional text in links and archive names is defused.
- The mail dock reads only its own folder, and its send approval shows the
  whole message.
- Updates: an update is refused unless the release is newer than the
  running version, and a re-issued pack manifest is numbered in the signed
  checksums so an older one cannot be put back.
- 0.15.177 is signed with the release key that installed binaries trust
  (the first of the two keys 0.15.176 pins); the second key signs only
  once binaries that carry it are in use.
- MCP file tools open every local path beneath their root without
  following a symlink, so two calls of one client can no longer swap a
  folder for a link between the check and the write (or read) and reach
  `~/.config/autostart`, `~/.bash_profile` or `~/.ssh`. The `symlink` tool
  refuses targets outside the write roots and at protected places, and the
  mutating tools run one at a time. `grep` matches in a child process that
  is stopped after 5 s per file, so a backtracking pattern no longer ties
  up the server.
- The compiled-extension cache (`~/.cache/axross`, also under
  `$XDG_CACHE_HOME`) is a protected place, read-only in the agent sandbox,
  and its entries carry an HMAC with a private key, so planted byte code is
  never run. The cache also hits in the one-file binaries now.
- In the agent sandbox, protected files that do not exist yet
  (`~/.bash_profile`, `~/.zshenv`, `~/.gitconfig`, ...) cannot be created:
  the home folder is a read-only frame with its existing entries mounted
  in it. Nothing is created on the host for this.
- Message boxes show remote file names as written: a name can no longer
  add styled text or a clickable link to the Checksum, Overwrite or other
  prompts.
- Reverse-serve sends at most the announced length of a file (and closes
  the connection if the file changed size), answers byte ranges with 206,
  sends no body with a HEAD error, and refuses `Depth: infinity`.
- The operation journal rotates under a lock, so the GUI and the MCP
  server no longer lose each other's history. `ssh -o ProxyCommand`,
  `git ext::`, `gdb -ex` and `php -d` count as running code for the MCP
  runner check.

### New

- **Help > Handbook** (F1, opened at the part of the window in use, in every
  window) and **Help > Tours** with six guided tours in English and German.
- **Help > Tours > Watch Video**: a narrated video of each tour, in English
  and German (IT terms spoken in English). Downloaded once from its own
  GitHub release and played only when it matches the checksum axross
  carries for it.
- Pure-Python packs work at once, without a restart; **Update packs** fetches
  a re-issued pack manifest; the updater offers no install for a release
  that has no build for this binary.
- A right-click menu on transfer jobs.
- `--script` takes arguments and wins over `AXROSS_MCP`; `--mcp-http` starts
  the server.

### Changed

- **German: "Profil", not "Profile".** The English word kept in about 120
  German texts broke the grammar ("ein Profile", "das aktive LLM-Profile");
  they now say Profil / Profile / Profilen. New German users also start
  with the tags "Wichtig" and "Später ansehen".
- The guided tours dim the rest of the window; narrated tour videos are
  rendered from the real window (`scripts/tour_videos.py`).
- The German interface is translated further, and key names follow the
  keyboard of the language ("Strg+Umschalt+A").
- The release is put together and checked by
  `scripts/assemble_release.py` (docs/PACKAGING.md, "Release flow").
- **Faster.** With all bundled extensions on, the window shows in about
  1.5 s instead of 3-4.7 s and uses 60 MB less: Matrix, XMPP and the
  mixer load their libraries when first used, and compiled extension code
  is cached by the SHA-256 of its source. Switching extensions off and on
  no longer leaks memory. The terminal draws at most every 16 ms (`cat` of
  4 MB: 3 s -> 0.7 s). The connection dialog opens in about 30 ms. Script
  calls no longer rewrite the visit history each time.
- **Many small files.** Uploads of small files need about one request per
  file instead of three to six: 500 files over SFTP at 20 ms latency take
  36 s instead of 96 s (WebDAV 13 s instead of 39 s, S3 26 s instead of
  67 s); with Parallel transfers set to 4, SFTP takes 10 s. Local copies of
  small files are about twice as fast, and the window no longer stalls
  while thousands are queued. Integrity checks, the journal and "never
  overwrite without asking" work as before.
- **Big folders.** In a folder of 100,000 entries, typing in the filter takes
  about 40 ms per key instead of 400 ms, Select All 4 ms instead of 300 ms,
  and opening it no longer freezes the window. A 50,000-member archive
  opens in about 0.1 s instead of 2 s; Compare's "All" view and the Find
  Files result list fill without freezing; content search with ripgrep
  runs one ripgrep over the folder (30,000 files: 3.4 s -> 0.6 s); a search
  of the metadata index is 3-4x faster. The filter ignores case the
  Unicode way ("strasse" finds "straße").
- The operations journal starts a new file above 16 MB instead of growing
  without end.
- **Every menu entry has an icon**; the Agent's robot is visible on dark
  themes; IRC, Matrix and XMPP have their own icons; F1 opens the handbook
  in every tool window, and the handbook covers the tools and bundled
  extensions.
- **Mail docks**: switching the timer off pauses at once and Pause is kept;
  a Stop button, the agent's tool calls in the log, Open Drafts Folder, an
  Edit button, every mail dock under View > Panels; a dock without a
  mailbox is refused.
- Help > Features offers the chat (Matrix/XMPP) and raw Bluetooth extras
  instead of telling you to run pip.
- Reverse-serve speaks HTTP/1.1, answers `100-continue` after its checks
  (boto3 and aws-cli no longer wait 1 s per upload) and takes multipart
  uploads, within the same limits as a single upload.

## 0.15.176 - 2026-11-07

The release notes are on its
[release page](https://github.com/c0decave/axross/releases/tag/v0.15.176):
`axross-base` with signed packs, builds for glibc 2.34 and 2.36, mail docks
and mail projects, IRC, Matrix and XMPP chat, the Bluetooth panel, the Audio
Mixer, System Information, the NFSv4 client and more.

**It shipped without binaries:** the release page has only the wheel and
the sdist - no `axross-*` binaries, no `SHA256SUMS`, no `SHA256SUMS.sig` -
and it was not uploaded to PyPI. Installed binaries therefore stayed on
0.14.136 and update straight to 0.15.177.

## Earlier releases

See the [GitHub releases](https://github.com/c0decave/axross/releases).
