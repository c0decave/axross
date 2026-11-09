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

- Create SHA256SUMS with every file selected no longer lists the manifest itself (Verify then failed on it); an open Scheduled Jobs window shows the result of Run Now.
- **Space marks files again instead of moving one mark down.** "Mark the
  file and move down" moved the cursor with a call that cleared every
  other mark, so three presses left one wrong file marked; the marks now
  stay (details and thumbnail view). A refresh (the folder watcher, a
  transfer writing into the folder) also keeps the cursor row when it is
  not marked itself, so the next arrow key no longer starts at the top.
- **Undo of a large move is no longer done in part after the journal
  rotated.** Every move, copy and Move to Trash now opens its entries in
  the operation journal with a begin marker; Ctrl+Z undoes a batch whole
  only when that marker is still there. A move whose first files had been
  rotated out of the journal was undone in part and recorded as undone,
  and a move that began at the top of the rotated journal was refused.
- **"Overwrite?" and "Delete?" questions default to No.** Encrypt and
  Decrypt onto an existing name, Delete Permanently and Empty Trash in the
  trash window, discarding unsaved changes in the text and hex editors,
  deleting bookmarks, profiles or a chat account and other destructive
  questions answered Enter with Yes.
- **A file removed while a local folder is listed no longer shows as a "?"
  row.** It is left out (a folder copy no longer fails a job for it); an
  entry that cannot be read for another reason is still listed.
- **A move, an undo or a "skip existing" copy does not replace a file that
  appears at the last moment.** Local folders and SFTP now refuse the
  rename when the target appeared after the check, instead of overwriting
  it.

- **A folder that cannot be created or read is reported in the interface
  language.** When a copy into a read-only place failed, the Transfers
  panel showed raw English, "cannot create the folder, its contents were
  not copied: [Errno 30] Read-only file system: …", while the file next to
  it got a German sentence. The refused folder row now keeps its exception
  and shows the same kind of sentence; the raw text stays in the tooltip
  and the log.

- **Cancel works during the real upload and download of spooling
  backends, and the bar shows the network bytes.** The OneDrive, Google
  Drive, Dropbox, S3, Azure, WebDAV, FTP, SCP, Telnet and IMAP writers
  upload in close() and several readers download the whole file inside
  open_read(): the bar reached 100 % at disk speed, then the real transfer
  ran to its end whatever Cancel said (OneDrive: three chunks sent and the
  file committed after Cancel). The transfer engine now hands the backends
  its Cancel and progress for the job (core/transfer_hooks.py): uploads and
  downloads check Cancel between chunks and report what is on the server,
  retry pauses wake on Cancel, and a cancelled upload commits nothing (the
  OneDrive session is deleted, the S3 multipart upload aborted, the
  Dropbox session never finished, the Azure blocks never committed, the
  Drive resumable session left unfinished). A job with two network legs
  (cloud to cloud, SFTP to cloud) shows each as half of the bar.
- **Dropbox no longer sleeps a server's Retry-After whole.** The SDK slept
  int(Retry-After) itself (an hour, four times); its own retries are off
  and 429 / 5xx are retried with the capped, cancellable pause.
- **A Dropbox upload over 150 MiB resumes after a lost answer** from the
  session's correct_offset instead of failing.
- **S3 errors are typed.** The writer's close() let botocore's ClientError
  out (an editor Save of a write-protected key ended in the error hook),
  other verbs raised errno-less errors and the folder-rename listing was
  not wrapped; every S3 failure is now an OSError of its errno (403
  PermissionError, SlowDown EAGAIN, quota ENOSPC ...). A multipart copy
  over 5 GiB pins the source version (CopySourceIfMatch), and a custom
  endpoint gets checksums only where S3 requires them (S3-compatible
  stores refuse botocore's new default trailers).
- **OneDrive: an upload whose last answer was lost is no failure** when
  the item is there with the new content; **a DELETE retried after a lost
  answer** (OneDrive, Google Drive) is no "not found" any more.
- **Git URL sessions follow the remote and push what is saved.** After an
  upstream force-push a session kept the old content and refused every
  write; saves were committed into the local cache only and never pushed;
  an unreachable remote opened the stale cache as if all was well. Now a
  branch with nothing unpushed follows origin (force-push, deleted branch),
  every save is pushed at once (fast-forward only; a failed push keeps the
  commit and the save says so), commits origin does not have are kept and
  counted in the pane's status line ("not pushed to origin: main (1)"), and
  an unreachable remote opens the cache read-only, marked "offline".
- **Removing an IMAP message's attachments folder no longer deletes the
  message.** `remove("/INBOX/1")` - the folder that lists message 1's
  attachments - deleted the whole message, with or without recursive. It
  is refused now; deleting the `.eml` deletes the message.
- **Mail file names fit a local file system.** IMAP, POP3 and Exchange
  capped a message's name in characters: a CJK or emoji subject, or any
  long subject behind an Exchange ItemId, gave names over 255 bytes, and
  copying the message to a local folder failed with "File name too long".
  Names are at most 200 UTF-8 bytes now (the id and extension whole); the
  old names still resolve and a mail dock does not see renamed mail as new.
- **POP3 reconnects, and says when deletions were lost.** After a dropped
  connection every call failed until the profile was reopened; a failed
  QUIT after deletions was swallowed, so the messages stayed on the server
  while the user saw them deleted. POP3 now reconnects, and the deletions a
  lost connection or a failed QUIT did not commit are reported. On a server
  without UIDL, two messages with the same subject could swap after a
  reconnect and the wrong one was deleted; messages are found by their
  headers and size now, and identical ones are not deleted.
- **Google Docs, Sheets and Slides can be read.** They were refused with
  "Permission denied" (Drive has no binary content for them). They are
  listed as `.docx` / `.xlsx` / `.pptx` (a drawing `.pdf`) and read as that
  export, read-only; a Form says it has no file form. Requests now support
  items of shared drives; the shared drives themselves are not listed yet.
- **Typed errors:** IMAP mkdir or rename onto an existing mailbox is
  FileExistsError, a missing mailbox in a listing or as a move target
  FileNotFoundError; Git open_read / list_dir of a missing path is
  FileNotFoundError, list_dir of a file NotADirectoryError, mkdir over a
  file FileExistsError, and a file path ending in "/" is refused.

- **Retry after a reconnect uses the new connection.** When an SFTP pane
  reconnected by itself, its failed and queued transfers kept the dropped
  session, so Retry failed again with "Not connected". They now move to the
  new session, and Retry takes the pane's current connection when the job's
  own one is closed.
- **SFTP copy, hard link, checksum, commands and disk usage work on names
  that are not UTF-8.** They failed with an encoding error (and left an SSH
  channel open), and disk usage showed an empty disk; a failing disk usage
  query is now an error, not 0 bytes.
- **FTP listings on servers that answer "-a" with "450 No files found"**
  work again, and a file whose name starts with "-a" no longer hides the
  dot files of its folder.
- **WebDAV and Exchange retry when the server is busy.** WebDAV sends a
  request again after 429 or 503 (bounded, honouring Retry-After; MOVE and
  COPY only after 429); Exchange retries throttled requests
  (ErrorServerBusy) for up to 60 seconds.
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

- Trust Host Key? defaults to No: Enter no longer trusts an SSH host key nobody compared.
- **SMB reconnects with the same identity, proxy and workstation name.**
  After the connection dropped, the next operation dialled again without
  credentials (or as the local Kerberos ticket holder), past the
  SOCKS/HTTP proxy and with the real host name in NTLM; servers a DFS
  referral named were dialled the same way. Every SMB connection of a
  session is now made through the profile's proxy, with the masked name and
  the session's credentials; a closed session never dials again.
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
- **Reverse-serve stays in its folder when paths change under it.** The
  served path was checked as a string and then opened by name: a token
  holder who swapped a folder of the path for a symlink to a folder
  outside (MOVE renames links) between the two read, overwrote or deleted
  files outside the served folder. Every request on the local file system
  now opens its path beneath the served folder without following any
  symlink (links that stay inside still work).
- **Reverse-serve: clients without the token cannot lock token holders
  out.** 64 idle or keep-alive connections without the token made every
  token holder wait for a 503, and stalled header lines grew the server to
  over 400 MB. A 401 now ends its connection, a connection that has not
  shown the token gives its slot up to a new one (at most 8 per address),
  the request headers are capped at 64 KiB (431) and must arrive within
  10 s.
- **Reverse-serve answers name no local paths and no other host.** Error
  answers and the folder index no longer show the served folder's local
  path; a Range number of thousands of digits is answered (416) instead of
  dropping the connection; a COPY/MOVE Destination on another host is
  refused with 502 instead of being taken as a path of this server.
- **A file name can no longer crash or freeze axross through a progress or
  input dialog.** Their label is made by Qt itself, past the markup guard:
  an archive member or remote file named `<img src="&#47;dev&#47;zero">x`
  in "Opening …", "Extracting …" or the Encrypt/Decrypt passphrase prompt
  made Qt read /dev/zero until the process aborted (a FIFO froze it). The
  guard now covers QProgressDialog and QInputDialog labels, including
  `QInputDialog.getText()` and friends, and these dialogs show names as
  written.
- **A mail can no longer freeze the window.** Tables nested 21 deep (a
  467-byte mail) kept the window busy for 25 s, a long word or 4 MB of
  `&#` for minutes. The safe view keeps at most 6 nested tables and 16
  nested lists or quotes, ends the tables of a mail whose tables would
  take too long to lay out (the rest shows as text), gives long words a
  break opportunity, and caps the HTML after escaping.
- The Delete question shows names once and as they are: "Tom & Jerry" no
  longer reads "Tom &amp; Jerry", and bidi overrides and line breaks in a
  name show as their codes (`\u202e`) instead of hiding the names after it.
- Protected places cover macOS (LaunchAgents/LaunchDaemons, login items,
  Application Support/axross, Library/Python) and Windows (Startup folder,
  PowerShell profiles, %APPDATA%/%LOCALAPPDATA%\axross), the home's
  folders on PATH (~/bin, ~/.cargo/bin, pipx/uv tool venvs) and its
  site-packages, `*.pth`/sitecustomize files anywhere, ~/.tmux.conf,
  ~/.config/mimeapps.list, Emacs and more window-manager start files; XDG
  folders count even for an MCP server started without the variables
  (recorded by the GUI, read from the shell/session files).
- Agent sandbox: a protected place reached through a symlink (GNU stow,
  chezmoi) is read-only at its real path too; SSH/GnuPG private keys, the
  ADB key, axross's tokens and keys, keyrings, ~/.netrc and
  ~/.git-credentials are empty in the sandbox unless their folder is
  mounted on purpose.
- MCP: chmod no longer makes a folder holding protected places
  (~/.config, ~/.local) writable for group or others; a rename or
  transfer_move that re-points a relative symlink out of the root or at a
  protected place is refused.
- Archive extraction (MCP archive_extract, the GUI) creates every folder
  and file beneath a descriptor of the new target folder, never through a
  symlink and never over a file that appeared meanwhile; MCP's new-file
  writers and the packer create their files the same way, beneath the MCP
  root.
- The MCP grep tool's regex child has a CPU limit per text and ends with
  the server (PR_SET_PDEATHSIG on Linux, a kill-on-close job object on
  Windows); a killed server no longer leaves it backtracking.
- Packs: the signed SHA256SUMS must name the release and match GitHub's
  digests; a pack-manifest issue older than the one shipped or ever seen
  is refused, also on a fresh install and when a self-update brings the
  packs along; a wheel member with a drive or stream colon is refused.
- A relative XDG_DATA_HOME / XDG_CACHE_HOME / XDG_STATE_HOME /
  XDG_RUNTIME_DIR is ignored (XDG spec); packs, the update cache and
  tokens no longer land under the current directory.

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

- **Del moves to the trash, Shift+Del deletes permanently.** Del used to
  delete for good. Now it moves the selection to the trash wherever the
  connection has one; read-only protocols and those without rename (Gopher,
  LDAP, NNTP, PJL, POP3, SLP, SVN, TFTP, WMI) have none, and there Del asks
  for a permanent delete instead. The permanent-delete question now
  defaults to **No**, so a reflexive Enter keeps the files. Its text is in
  the interface language, with plural forms and readable sizes ("Delete 2
  items permanently? … In total: 2 files, 1.1 MB"), and so are the
  progress, result and error lines.
- **The right-click menu is one short column with Open first.** It had about
  47 entries in two columns, and on a folder the first was "View Selected
  Media…". Now it has about 20: Open (a folder in the pane, a file in its
  viewer) and Open With ▸; Copy Path, Cut, Paste, Rename; Copy / Move to
  Target Pane and Pack ▸; Move to Trash and Delete Permanently; New Folder
  and New File…; Properties… with Metadata ▸, Analyse ▸, Links ▸ and Tags ▸;
  Refresh and More ▸; Send to Workspace ▸ at the end. More than three
  extension entries go into Extensions ▸. Every former entry is still there.
- **Small screens: the file list gets the room.** A window shorter than
  700 px keeps the toolbars in one row. An empty Transfers panel is a
  single line, without an empty table or an idle "0%" bar; it grows back
  when a transfer starts. On 1024x600 the panes show seven rows instead of
  four.
- **German handbook (docs/USAGE_de.md, F1): every UI label it names is the
  one the German window shows.** Some 280 English labels were replaced, and
  tests/test_german_handbook_labels.py checks them. The opening section is
  now written for users, without developer jargon.
- **German: no English left behind tr().** Now translated: the password and
  passphrase prompts of Quick Connect, session restore and host terminals;
  the archive messages; Quick Connect ("Zuletzt verwendet", "Alle Profile",
  "Connection Manager…" with its shortcut shown the normal way); the local
  shell entries; the Pack and Extract status lines; the production-countdown
  texts; and the "Stimme" settings page. A new AST check,
  tests/test_german_no_untranslated_literals.py, reads ui/ and the
  user-facing core/ modules. It fails on any text given to a dialog, menu or
  status line without tr(), including tr(f"…"). The catalogue now uses
  informal "du" throughout and "…" instead of "...".
- One action, one name: Copy / Move to Target Pane is "Ins Ziel-Pane
  kopieren / verschieben" in the Actions menu, the right-click menu, the
  toolbar and the shortcut list. The Actions menu and Help > Features… have
  underlined letters. The View menu no longer lists a second "Bookmarks"
  entry; the sidebar toggle is under Panels. The pane header says "Local",
  not "Local [LOCAL]". The shortcut list is wider so that the descriptions
  fit. F2 selects the name without its extension. A tour video that is not
  available is reported with an information icon, not a warning.

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
