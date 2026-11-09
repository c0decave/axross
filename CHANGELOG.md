# Changelog

What changed in each axross release, for the people who use it. The full
notes of a release, with every fix, are on its
[GitHub release page](https://github.com/c0decave/axross/releases).

## Unreleased (0.15.177)

0.15.177 is the first release since 0.14.136 with one-file binaries for
Linux, macOS and Windows: installed binaries update to it. Six rounds of
reviews of the whole code (backends and transfers, security, the windows,
the extensions, the entry points, concurrency, the docs against the code)
found and fixed several hundred bugs; every fix comes with tests that fail on
the old code.

**In short** (the update dialog shows the start of these notes):

- **New since 0.14.136:** Help > Handbook (F1 everywhere) and guided
  Tours with narrated videos in English and German; packs (optional
  features added to a small binary), an axross-base binary and a glibc 2.36
  build; mail projects and mail docks, chat, Bluetooth; a German interface.
- **Safer:** the agent's sandbox and the MCP server keep to their folders
  even against racing symlinks; protected places on Linux, macOS and
  Windows; reverse-serve confined to its folder; hostile file names are
  shown as text everywhere; updates are signed and never roll back.
- **Faster:** small files transfer in about a third of the time, big
  folders filter in milliseconds, the start with all extensions takes half
  as long.
- **More careful with your data:** Cancel works during uploads and
  downloads and leaves nothing half-written; undo checks it moves the file
  it moved; Del moves to the trash (Shift+Del deletes); questions that
  destroy default to No.

### Fixed

- **Every entry of the right-click menus has an underlined letter.** The
  pane's right-click menu (Paste, Pack, Analyse, More and its Links,
  Metadata and Tags submenus), Quick Connect and the toolbar's right-click
  menu had about thirty entries the keyboard could not pick; a free letter
  is now given to each when the menu opens, in English and German. View >
  Show Trash… got one too.
- **A second connection keeps your local pane.** It replaced the last local
  pane, leaving two servers and no local folder on screen; the last local
  pane is never taken now, and the second server opens beside the first.
- **"Save in keyring" is the answer.** After every connection from the
  Connection Manager axross asked "Save password in the system keyring?",
  ticked or not; unticked it now asks nothing, ticked it saves without a
  second question, and a missing or refusing keyring is explained (in
  German too) instead of "Could not save password to system keyring.".
- **Checked menu entries with an icon look checked.** View > Panels
  (Transfers on, Agent off), Thumbnail View and the toolbar's right-click
  list showed no on/off state; a checked one now has a frame in the
  theme's check colour around its icon, in every theme.
- **The settings search marks the setting, not the whole box.** "proxy"
  turned the Default Proxy and No Proxy For boxes blue with every field
  in them; a group box now gets its title marked, other matches only
  themselves.
- **Smaller fixes to the windows.** A profile or tag named "Web & Mail"
  showed as "Web _Mail" in Quick Connect and the Tags menu; the toolbars
  are called Main Toolbar and Tools Toolbar (Hauptleiste, Tools-Leiste in
  German) in their right-click menu; German shortcut descriptions wrap
  instead of ending in "…"; a sandbox shows as "Locker", not "Lax (Lax)",
  and stays translated after an edit; a declined host key is a neutral
  "Not Connected" note ("check the fingerprint with the administrator"),
  not a red "Connection Failed"; German says "Eingabe" for the Enter key
  everywhere and writes percentages as "87 %" with a narrow space; the MCP
  Servers page shows "1,00 s" in German and says what to do while it has
  no server; the tour offer's buttons keep their own width; the
  Connection Manager's main button says Connect; an unticked Proxy box is
  its title alone and hidden where no proxy applies; the German handbook
  uses one dash.
- **Two copies of one file no longer write into one partial file.** A
  second copy of a file queued while the first ran (a second F5, a second
  axross) took over the first one's unfinished hidden partial and appended
  to it: the first copy reported done with a 4.9 MB file for a 4 MB
  source, and a move then deleted the source. A partial is now resumed
  only when no transfer of this axross writes it and nothing wrote to it
  for 30 seconds, it is first renamed to the new job's own name, a copy is
  committed only when the partial holds exactly what the job wrote, and a
  move deletes its source only when the destination is as long as the
  source.
- **Your file named like a partial is left alone.** A file such as
  `.video.mp4.part-1-notes` next to `video.mp4` was taken for an
  unfinished copy and removed by the copy or by Clear Finished; only names
  of the exact shape axross gives its partials count now.
- **Ctrl+Z no longer gets stuck on a move it cannot undo.** When the moved
  file was edited, replaced or deleted since (or the places of trashed
  entries were taken by new files), every Ctrl+Z offered it again and
  refused it, and older operations could never be undone; a deleted file
  showed "[Errno 2] No such file or d…". Such an operation is now skipped
  once with a note ("… could not be undone and was skipped: …") and Ctrl+Z
  goes on to the one before it.
- **A trash folder that is a file is named as the problem.** With a file
  called `.axross-trash` in the home folder, Del said "x.txt is not a
  folder"; it now says the trash folder is not a folder.
- **Symbolic links in a copied local folder get a clear reason.** A link
  to a folder ended with "[Errno 21] Is a directory" and a dangling link
  with "No such file or directory"; they are skipped now as "symbolic link
  to a folder: not followed" and "dangling symbolic link … skipped", as on
  SMB.
- **A move whose local source came out short keeps the destination
  clean.** The move failed and kept the source, but left the short copy
  under the destination's name; the copy is no longer committed.
- **A connection opens where there is room.** The first connection at the
  first start made a third, narrow pane; now a connection takes the place
  of the target pane while that is unused (a local pane still at the home
  folder, not navigated, nothing selected). Shift on the click, *Open in a
  new pane* in the Connection Manager or Quick Connect's *Connect in New
  Pane* still add a pane.
- **The pane footer cuts with "…" and keeps the message first.** A long
  message (after Ctrl+C at 1024x600: "2 Pfade in die Zwische") is cut with
  an ellipsis, whole in its tooltip and in the window's status bar; the
  free space shrinks to "Free: 249.0 MB", then away, before the message is
  cut. The item count counts the entries shown: "7 items (3 hidden)",
  "3 of 7 items" with a filter.
- **Column headers stay whole.** A column that had stepped aside for a long
  name came back below its label (the German "Eigentümer" drawn as
  "igentüme") and the columns jumped on a refresh; the label is now
  measured in the header's real font.
- **Smaller UX fixes.** A declined host key says so; "Host-Key" in German
  throughout. German for "not supported", "timed out", the sandbox names
  (Locker, Normal, Hoch, Paranoid) and Quick Connect's right-click menu.
  One name for bookmarking a folder (*Bookmark This Folder*, F8; Ctrl+D in
  the list), "folder" for "directory", menu paths written with "→" and
  dashes as "–" in English as in German. Settings: room beside the list,
  the matching setting is marked, a search without a hit says so, the
  hidden-files check box sits in the form's column. Light Mode: a readable
  selection and secondary text; disabled buttons in the dark themes look
  disabled. On a small screen the empty Bookmarks sidebar folds away (F12
  shows it). Every entry of the menu bar's submenus has an underlined
  letter, in English and German; Thumbnail View is one action with one
  name.
- **SFTP: the checksum after an upload no longer hangs, and Cancel stops
  it.** The integrity check runs `sha256sum` on the server over an SSH
  exec channel that had no time-out and no Cancel watch: a slow hash
  ignored Cancel, a network gone silent kept the job (and its temp file)
  for ever. Exec channels (checksum, server-side copy, df, hard links,
  `exec()`) now close on Cancel, and when they hear nothing for the SFTP
  time-out axross asks the connection whether it is alive
  (keepalive@openssh.com): no answer fails the command, an answer waits
  on - a long hash or copy is not cut off.
- **SFTP: a slow server that is alive is waited for.** A tape/HSM recall
  or a cloud-tiered file no longer fails after 60 s with "check the
  network": the request asks the connection first and waits on while it
  answers (up to 30 minutes). The time-out is per profile
  (**Connect → SFTP time-out**, default 60 s).
- **Cancel no longer closes terminals on the same SSH connection.** A
  transfer stuck after Cancel closed the whole shared connection after
  10 s; now that happens only when nothing else uses it, or when it no
  longer answers.
- **ADB over a proxy no longer routes other connections through it.**
  The ADB connect swapped `socket.create_connection` for the whole
  process while it waited for the phone's "Allow USB debugging?" tap;
  every other thread's FTP/IMAP/SMTP connection went to the ADB proxy.
  It is routed for its own thread only now, like SMB; the process-wide
  patch is gone.
- **A Git rename is one commit.** It was two ("write the new name", "remove
  the old one"), each synced with origin on its own; a push in between
  left the copy committed and unpushed and the original still there, and
  a repeat failed with "already exists". Now a file or folder rename is
  one commit and one push, all or nothing. The side branch
  `axross/unpushed-<time>` that keeps a change origin refused is pushed
  to origin (the message says where it is; only in the local cache when
  origin refuses it). Saves within 2 s of the last fetch or push skip
  the ls-remote before their push.
- **Deleting the root and "file/" are refused on every backend.** Removing
  "/" (the whole share, server, bucket or drive) is refused everywhere -
  on SMB, FTP, SFTP, OneDrive and Azure Files it emptied it, and SCP and
  Telnet sent `rm -rf -- /`. A path ending in "/" names a folder: delete,
  rename, open and stat of `file/` no longer act on the file `file` (FTP,
  SMB, WebDAV, the cloud drives, the shells).
- **Downloads into a local folder need the room once, not twice.** FTP,
  S3, Azure, WebDAV, Dropbox and OneDrive downloads stream straight into
  the destination instead of being stored beside it first: 20 MiB with
  90 MiB free is no longer refused. Upload buffers and ADB, TFTP and
  rsync files go to the spool folder (not a small /tmp) and are removed
  on every path.
- **Growing files, mail sizes, /sys files.** An FTP download of a file
  that grew meanwhile (a log being written) no longer fails ("ended after
  1500 of 1000 bytes"); POP3 messages from Exchange / Microsoft 365 (whose
  sizes are estimates) and NNTP articles copy instead of failing as
  "only 5078 of 5215 bytes"; /sys, /proc and /dev files over SFTP or SCP
  (listed 4096 bytes, a few read) are no longer refused as short.
- **No hidden leftovers after a failed copy.** A refused short read or a
  Cancel of a source that cannot continue where it stopped (POP3, a
  streamed download) removes its hidden `.part` file, and a safety copy
  that failed half-way (disk full) its partial `.previous-*` file.
- **Someone else pushed to your Git branch: your save still lands.** A
  save to a Git URL session asks origin first and builds on its new tip
  when only other files changed (the same file: refused, refresh and
  repeat). A push origin refuses all the same now catches up instead of
  showing "Git push main: (b'8148…', b'0aaa…')" and piling every later
  save onto a diverged branch: unpushed commits that touch other files
  are replayed onto origin's tip and pushed; ones that touch the same
  files are kept on a new branch `axross/unpushed-<time>` that the
  message names, and the branch follows origin. A cache that had
  diverged is no longer read-only until merged in a git client. dulwich's
  "counting objects" no longer goes to the terminal.
- **SFTP no longer hangs on a lost network, and Cancel stops it.** A
  request the server leaves unanswered for 60 s fails with "did not
  answer in time" (also the opening of a new channel); before, a listing,
  download or upload on a connection that went silent waited for ever.
  Cancel closes the SFTP or SCP channel of a transfer at once, also while
  it waits on the network.
- **Moving a Google Doc out of Drive no longer deletes it.** The move
  exported a .docx (no comments, history or sharing) and then deleted
  the original past Drive's trash. It is now refused before anything is
  copied (copy instead); deleting a Google Doc, Sheet, Slides deck or a
  folder puts it in Drive's trash.
- **Retry after a reconnect no longer freezes the window.** Retry asked
  the dropped SMB session whether it was connected - a redial of up to a
  minute per job on the window's thread - and then bound the retry to
  that retired session; it now takes the pane's session without asking.
- **An SMB connection through a proxy no longer takes others with it.**
  Its proxy and workstation name applied to the whole program during the
  up to 60 s connect: an FTP or IMAP login in another pane went through
  that proxy, and another server's SMB connect waited. Both are now for
  the SMB connection only. SMB connection failures are typed
  (connection refused / reset / timed out) also from an open file.
- **Dropbox: a move or delete answered 5xx after it was done is no
  longer "not found"; Paper documents open (as their export).** Cancel in
  the pause after such an answer on the last upload request no longer
  reports the file untouched when it had been written.
- **An IMAP upload after a reconnect is stored.** The message was sent on
  the connection of before the reconnect and lost with an error without
  a reason; it now goes over the live connection.
- **Ctrl+Z, then Enter, undoes - in your language.** The undo question
  named the operation by its internal id ("trash") and the reason in
  English, and No was the default, so Enter restored nothing. Now both are
  translated ("Die letzte Aktion (Verschieben in den Papierkorb)
  widerrufen?"), Yes is the default (the undo is itself the reversal and
  refuses an entry that changed since), and the status bar no longer keeps
  saying "Looking for the operation to undo…" after No or "nothing to undo".
- **German says "Papierkorb".** The German window, handbook and tour
  narration called the trash "Trash" in some 60 places; View → Zoom reads
  Vergrößern / Verkleinern / Normale Größe; menu paths use "→" and dashes
  "–" throughout; the German handbook's Transfers, right-click, feature,
  keyring and settings sections were rewritten in German with the labels
  the window shows.
- **The right-click menu is one column on a 1024x600 screen.** Refresh,
  Copy Path, Links, Metadata, Tags and Send to Workspace moved under More;
  the top level holds at most eighteen entries, also with an archive
  selected and a Paste pending. The Ctrl+C entry says *Copy* (Ctrl+C then
  Ctrl+V copies the files); *More → Copy Path* puts only the paths on the
  clipboard, and the shortcut list says what Ctrl+C and Ctrl+V do.
- **A cancelled copy says what it left.** A copy cancelled half-way keeps
  its hidden partial file so Retry Failed can resume it; the status now
  says so, and Clear Finished removes the partial files of the rows it
  clears. The Transfers buttons are enabled only when they have something
  to act on.
- **Copy errors name your file, not the temp file.** "Fehler:
  /usr/share/.todo.txt.part-c71d0b6a-58df0d1a liegt auf einem
  schreibgeschützten Dateisystem" now names /usr/share/todo.txt, and the
  tooltip no longer repeats the raw English error (it is in the log).
- **Smaller UX fixes.** Moving a folder with hidden files to the trash asks
  once; "1 of 1 item moved" reads "1 item moved"; the connection window is
  called Connection Manager like its menu entry; agent presets have German
  names in the German menus; About names the themes as View → Theme does;
  a tour video that cannot be fetched says so about GitHub, not about DNS;
  hidden files are off for a new user (Ctrl+H shows them; a stored choice
  is kept), and the "." row (this folder, a drop target) is set apart;
  German column headers are no longer clipped; a local-to-local copy shows
  "→" instead of a download arrow; *Activate a pane* offers "When clicked"
  or "When the mouse rests on it for … s".

- **A download that ends early fails instead of finishing short.** An FTP
  data connection cut half-way, followed by the server's "226 Transfer
  complete", gave a job marked done with 1.5 of 3 MB; the download is now
  checked against the size SIZE (or the server's 150 reply) announced, and
  every copy from a remote source against the size known at its start
  (one stat of the source when it came out short). A short copy fails and
  leaves the destination as it was.
- **Overwriting a file on FTP, WebDAV, SCP, Telnet, ADB or a database
  backend no longer reads the old file back before it is needed.** The
  safety copy that restores it after a failed upload is taken right before
  the upload starts: a Cancel or an error during the copy changes nothing
  and ends at once (a Cancel 0.3 s into overwriting a 400 MiB FTP file
  waited 3.3 s while the old file was downloaded and uploaded again). Where
  the server can copy (cp, WebDAV COPY, a database row) the safety copy is
  made there; a read-back checks Cancel and the free space first.
- **Downloads are spooled outside /tmp.** Large FTP, S3, Azure, WebDAV,
  OneDrive and Dropbox downloads (and FTP / Telnet uploads) spooled in
  /tmp, a RAM disk on many systems, and failed with "no space left"
  half-way. They now go next to the local destination, or to
  `$AXROSS_SPOOL_DIR`, or `~/.cache/axross/spool` (a temp folder you chose
  with TMPDIR or the tmpfs setting is kept); a download of known size that
  does not fit fails before it starts, with a message that says so.
- **A session you disconnected stays disconnected.** FTP, IMAP, POP3 and
  Telnet logged in again by themselves - with the stored password - when a
  queued transfer, a scheduled job or an editor save used the session after
  you disconnected it; they now fail with "disconnected".
- **FTP folders without MLSD list fast.** 10,000 files took 15-30 s (each
  name was searched in the whole listing and asked MDTM on its own),
  20,000 files 77 s; now 2.8 s and 5 s. At most 64 files per listing are
  asked MDTM; the others keep their LIST date, corrected by the server's
  clock offset the asked ones show.
- **"Delete" on the root of an NFS mount, an iSCSI disk or an MTP device is
  refused** instead of emptying the whole export, disk or phone.
- **A file path ending in "/" no longer names the file** on RamFS, the
  database backends, NFS (mounted and without a mount) and iSCSI:
  `remove("file/")` deleted the file and `open_read("file/")` read it; they
  now say "Not a directory", as the operating system does. Writing below a
  file on NFS or iSCSI says the same (it said "file exists"); iSCSI says
  "not found" and "not a directory" as such.
- A file name that is not valid UTF-8 is a per-file error on SQLite (and
  the other database backends), not a crash of the whole copy; a cancelled
  copy from a source without modification times (rsh) no longer leaves a
  hidden partial file that no resume could use.

- **Ctrl+Z after a move never moves a different file back.** A move now
  records what it put at the destination (size, modification time, and on
  this machine's disk the inode and device); undo moves an entry back only
  while it is still that file. A file renamed away after the move and a new
  one saved under its name was moved back in its place; now the undo is
  refused with "… is not the file the move put there - it was changed or
  replaced since" (in a folder move, that file stays and the rest goes
  back). Moves journaled before compare the size they wrote.
- **Batch Rename never replaces a file saved meanwhile under a new or old
  name.** The final renames and the rollback refuse a name that appeared
  after the check instead of overwriting it, and report it.
- **A cut or selected file that is gone is no permission problem.** Pasting
  a Cut whose file was removed or renamed since asked "cannot be removed
  after the copy - you lack the permission" and offered Move as
  Administrator; it is left out now and named, and a Cut whose entries are
  all gone is dropped.
- **View > Layout Preset asks before closing running shells and remote
  connections**, as Ctrl+Alt+L does, and the new layout keeps the folders
  of the active and the target pane instead of opening the home folder in
  every pane.
- **An extension handler that fails on every event logs its traceback
  once.** 50 selection changes logged 101 tracebacks; repeats are now
  counted, and the status bar and the Extensions window follow at most every
  five seconds.
- **MCP: a tool that fails answers a result flagged `isError`** (MCP
  specification), not the JSON-RPC error -32603, so the model sees the
  reason; bad arguments stay -32602, unknown tools -32601 (docs/MCP.md §8).
- A scheduled run stopped because axross closed is no longer recorded as a
  failure (nor counted towards disabling the job); Open With > View
  Selected Media… is offered only for media and folders; Cut, Tags and
  Send to Workspace in the right-click menu have their letter; English
  messages say "is not a …" (a restic repository, a world code, a regular
  file, an e-mail address, …) and the scheduler names the Scripts dock.
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

- **A download cut half-way under /dev, /proc or /sys is no longer saved
  as complete.** The exemption for kernel files (listed 4096 bytes, a few
  read) applied to every backend: an FTP server whose folder is called
  /dev delivered half of a 3 MB file and the transfer said done. It now
  holds only where "/" is a whole machine's root (local, SFTP, SCP, the
  shells, ADB) and only for a file listed with a kernel file's size.
- **ADB, TFTP and rsync no longer leave visible spool files in your
  download folder.** Their temporary files (`axross-adb-…`) showed up next
  to the download while it ran and stayed after a crash; they are hidden
  now (`.axross-spool-…`), and leftovers older than a day are removed the
  next time axross spools there.
- **SSH: a server that does not answer keepalive requests no longer looks
  dead.** A silent command (a long checksum) failed with "the network
  connection is probably lost" on such a server; now any packet from the
  server counts as an answer, and a server that drops the request is asked
  with a channel open it must answer. The probe no longer takes over
  paramiko's own completion event.
- **Database backends: renaming onto `//` no longer hides the data.** The
  path kept its two leading slashes, so the entry vanished from every
  listing; `//` is the root now, and the root is refused as a rename
  destination on every backend.
- **Azure Files: a resumed download starts over cleanly.** It claimed
  reads from an offset but downloads whole files, so a resume fetched
  everything again and needed twice the space.
- **A streamed download that breaks names the file.** The error read
  "('Connection broken: IncompleteRead(…)', …)"; it now says "Cannot read
  /path: Connection broken: …" and keeps its type and error number.

### Security

- **Text from outside that froze the window again.** A mail whose words
  were joined by no-break spaces (U+00A0, U+202F, U+2007) was one line of
  128,000 characters for Qt (Hebrew and Latin: 44 s); an agent answer of
  script changes or direction marks (RLM, LRE … PDF, RLI … PDI) between
  no-break spaces 7.2 s, and restoring eight of them 21 s. Words now end
  only where Qt breaks a line, direction marks count as changes of
  direction, changes of script inside a long word are capped, and the
  transcript counts what a line costs to lay out, not its characters
  (older lines then show only their start). A plain mail of carriage
  returns or U+2029 separators (2,000,001 blocks, 954 MB) now counts every
  line end Qt knows for its line cap.
- **Release notes:** 20,000 `<` took 2.4 s to clean up and a Markdown
  table of 19,000 cells 4 s; the clean-up is now linear and a table of more
  than 2000 cells is shown as its lines of text.
- **An SVG that costs more than it counts** (an 8.8 KB filled path drawn
  100 times: 23 s; others minutes) is now drawn in a child process that is
  killed after 10 s (the media viewer shows why).

- **A host-run MCP server imported code from the folder axross was started
  in.** A pure launcher (`python3 -m mcp_server_time`) inherited axross's
  working folder, so a cloned repository's `mcp_server_time/` ran on this
  machine. A program server now starts in its own empty folder
  (`$XDG_STATE_HOME/axross/mcp-run/<server>`, 0700, checked like the update
  cache), `python -m` with `PYTHONSAFEPATH=1`, and a script counts as pure
  only by its absolute path.
- **Pure launchers that were not.** Downloading tools started through an
  allowed interpreter (corepack / pnpx / yarn scripts, `python -m
  pip_run|tox|nox|piptools|build|pipenv`, `perl …/cpan`, `php
  composer.phar`, bazelisk) are refused like `npx`; tool scripts (`ruby
  …/bundle`, `bash …/sdk`, `python -m jupyter`) and node / java options
  that load code (`--experimental-loader`, `--experimental-network-imports`,
  `-Djava.system.class.loader`, a `-D…=` URL) are contained. The launcher
  itself is found on the server's PATH and must be installed by the system
  (root-owned, writable by no one else) or a version manager: `./python3`,
  a `node` in `~/Downloads` or a `.bat` need a sandbox profile or Trusted.
- **A server environment that loads code** (`BASH_ENV`, `ENV`,
  `NODE_OPTIONS`, `PERL5OPT`, `PERL5LIB`, `PYTHONPATH`, `PYTHONSTARTUP`,
  `RUBYOPT`, `LD_*`, `DYLD_*`, `JAVA_TOOL_OPTIONS`, `_JAVA_OPTIONS` …) no
  longer passes as a pure launcher; the details of a detected server and
  Agent Settings show those variables with their values (tokens hidden).
- **A server's stderr could fill axross's memory** (512 MiB without a
  newline: 555 MB). It is read in 64 KiB chunks; the last 20 lines are
  kept, each cut at 4 KiB.
- **Private folders: real path and group.** The update / tour-video cache
  check walked only the parents as written (`~/.cache` a symlink into a
  world-writable folder passed) and accepted a parent its group may write;
  both the written and the real parents are checked now, a group-writable
  parent of yours only passes for your own private group. The packs
  folders (`$XDG_DATA_HOME/axross/packs/<version>` and each wheel folder)
  go on the import path only after the same check.
- **A 40-byte file name could crash axross through a message box.** The
  markup guard read tags the way an HTML parser does; Qt also reads a
  quoted tag name (`<"img">`, `<'table'>`), one with character references
  (`<&#105;mg>`) and a quoted attribute name as markup. The archive name
  `<b></b><'img' src=&#47;dev&#47;zero>.zip` made "Could not extract …"
  read /dev/zero until the process died; nested quoted tables froze the
  window 33-37 s, a 56-byte name laid out a 3.2 GB message box, and
  `<"style">`/`<"title">` or a comment ended by `-- >` hid the rest of a
  message. Labels, tooltips and message boxes now render rich text only
  when every tag in it is written in one plain form both read alike (a
  known tag name, plain attribute names, no comment); anything else is
  shown as written. Labels set to rich text are checked as such, and the
  file pane's messages show archive and file names as written.
- **One archive could build a Git folder that ran code.** archive_extract
  checked every member with one checker that remembered "no HEAD here"
  from before the member HEAD was made, and the repository shape needed
  `objects` and `refs` to be folders while Git only asks that they can be
  entered: members `objects` (an executable file), `HEAD`, `config` (with
  `core.fsmonitor`) and `refs/` made a folder whose `git status` ran the
  config's command. Each member is now looked up afresh, any entry named
  `objects`/`refs` counts, and an archive member named `HEAD` is not
  extracted.
- **More version-control settings that run code are protected:**
  Mercurial's `.hg/hgrc-not-shared` (read for every repository), Sapling's
  `.sl/config`, darcs's `_darcs/prefs/defaults` (`--posthook`) and Breezy's
  `.bzr/branch/branch.conf`, and the `.hg`/`.sl`/`_darcs`/`.bzr` folders
  themselves (a folder renamed to `.hg` brought its `hgrc` along).
- **A root holding /proc handed out axross's environment.** With
  `--mcp-root /` the tools read `/proc/<pid>/environ` (API keys) and the
  command line, memory maps and open files of processes. `/proc/self`,
  those entries of `/proc/<pid>` and `/run/secrets` are now refused for
  reading and writing.
- **Secrets in project folders are not handed out to the agent**: private
  keys and password databases found by their first bytes (PEM, OpenSSH,
  PuTTY, KeePass) and files secret by their name anywhere (`.env`,
  `.git-credentials`, `.netrc`, `.pgpass`, `*.tfstate`, `*.kdbx`, `id_rsa`
  and friends, `*.ppk`, `*.p12`).
- MCP `chmod` refuses a file with other hard links: through a second name
  in the root it changed the mode of `~/.bashrc`.
- The agent sandbox now also sets aside a `.git/config.worktree` and the
  `commondir`/`config.worktree` of submodules' and worktrees' Git folders
  that the task made (only `.git/commondir` was).
- **The whole SMB share could be deleted through a backslash spelling of
  its root.** The root guard normalised paths the POSIX way only, while
  smbclient applies Windows rules: deleting `/x\..` or `\` with
  everything in it emptied the share; on WinRM `C:\Users\..` and `c:\.`
  were no drive root to the guard. The guard now splits on backslashes on
  every backend that does not treat them as a name character, counts drive
  roots, and refuses any `..` in the paths of a delete or a rename (and as
  their destination); the MCP server refuses `..` in remote paths it
  writes, moves or deletes.

- **Rich text that only looked harmless is shown as written.** The markup
  guard of labels, tooltips and message boxes counted `</table>` with a
  regular expression, so one inside an attribute value or a comment closed
  a table Qt still laid out (a 476-byte remote name froze "Delete
  {name}?" for 33.5 s); a CSS comment before the colon
  (`font-size/**/:4000px`) passed every size check, and sizes under the
  caps added up (letter-spacing x 200 letters: 402,172 px wide). End tags
  now count where an HTML parser reads them, CSS comments and escapes are
  read as Qt reads them, and rich text the checks let through is measured
  off screen once: wider than 4000 px or taller than 5000 px (beyond what
  its words take) and it is shown as plain text.
- **Long mails open at once.** A plain-text mail went whole into the
  message view as `<pre>` (4 MB of newlines: 24.6 s, 509 MB; 6 MB of mixed
  Hebrew and Latin: 20.7 s). Plain-text mails now show in a plain view
  that lays out only the lines on screen (lines broken after 1000
  characters, at most 2 MB / 100,000 lines); an HTML mail's formatted view
  gets at most 128 KB of sanitised HTML, with "Show All as Plain Text" for
  the rest.
- **SVG with duplicate ids refused.** The `<use>` cap counted the first
  element an id names, QtSvg draws the last one: duplicated ids drew a
  million elements from a 1.8 KB file. Such a file gets no preview now.
- **Long agent answers and chat messages no longer freeze the window.**
  An agent transcript line of 200,000 mixed-direction characters took more
  than 90 s to lay out, a 16,000-character chat message 0.6-0.9 s. Each
  now lays out its start (mixed-direction text and very long words are cut
  earlier), with "Show all (N characters)" opening the whole text as plain
  text; past 512 K characters the transcript's oldest lines show only
  their start.
- **Protected places checked under every name a path goes by.** The MCP
  server and the agent checked protected places, default-deny and secrets
  on the resolved path only: through a GNU stow link (`~/.config/kitty ->
  ~/dotfiles/kitty`, `~/.wezterm.lua -> dotfiles/...`) the target was
  written, and a key behind `~/.ssh/id_ed25519 -> ~/keys/id_ed25519` was
  handed out. Now the path as typed, each symlink on the way and the
  resolved path count, the target of a symlink in those places is
  protected like the place (read-only in the sandbox; a link in `~/.ssh` and
  the other secret places makes its target secret, hidden in the sandbox).
- **Git folders recognised by what they are.** `.git/commondir` and
  `gitdir` (they point Git at another folder's config, whose
  `core.fsmonitor` runs at the next `git status`), the config and hooks of
  a bare `x.git` and of any folder shaped like a repository (`HEAD`,
  `objects/`, `refs/` - the last of them is not made in a folder that is
  not one yet), Mercurial's `.hg/hgrc` and Jujutsu's `.jj/repo` are refused
  like `.git/config`. The sandbox also keeps `commondir`, `gitdir`,
  alternates, the submodules' and worktrees' configs and the repositories
  one folder below the agent's read-only, and sets aside a new
  `.git/commondir` when the agent's task ends.
- **No write through a hard link.** A file with other hard links was
  written in place, so a hard link in the MCP root changed `~/.bashrc` or a
  `.git/config`; such a file is now refused (write a copy under a new
  name). A hard link to a secret file is not read.
- **Hidden folders are default-deny for reads.** The agent's and the MCP
  server's tools no longer hand out the contents of a hidden entry of the
  home or of `~/snap` unless that folder is granted (the root or an extra
  folder there); names stay listable, other files read as before. More
  credential stores are secret everywhere: snap Firefox and Chromium,
  Telegram Desktop, Discord, Element, Slack, Pidgin, glab, doctl, hcloud,
  fly, ngrok, FileZilla, Remmina, WireGuard, `~/.terraformrc`, Maven and
  Gradle settings. A grant of `~/.local` no longer opens `~/.local/share`.
- **The sandbox no longer runs out of looking for secrets.** The walk for
  secret-named files (histories, tokens, keys) stopped after 50,000
  entries, so a big `~/.cache` left `~/.config` uncovered. Package stores
  are skipped, caches come last, each hidden folder (and each folder of
  `~/.config`, `~/.local/share`, ...) has a budget of its own, and one that
  runs out is hidden whole.
- **More places where `XDG_CONFIG_HOME` is set are read:** `~/.xprofile`,
  `~/.xsessionrc`, `~/.bash_login`, Plasma's `env/*.sh`, fish
  (`set -gx`), `${XDG_CONFIG_HOME:-...}`, `export A=1 XDG_...=`,
  `X=...; export X`, trailing comments and `/home/$USER/...`.
- **Agent MCP servers are contained by default.** A server program ran on
  this machine with your rights unless it was on a list of downloading
  tools, and that list was never complete (`bazel run`, `mix run`, `swift
  run`, `conan install`, `make`, `brew` …). Now only a pure launcher - an
  interpreter running a script or module on disk (`node x.js`, `python -m
  mod`, `java -jar x.jar` …) - starts without a sandbox profile; any other
  program starts in its sandbox profile or when you tick *Trusted* for it
  (Agent Settings > MCP Servers). Commands that download code still never
  run on this machine, trusted or not.
- **Loopback `Host` check parsed strictly.** `Host: localhost:1@evil.example`
  passed the DNS-rebinding check of the MCP HTTP server and of reverse-serve
  (cut at its colon to `localhost`). `Host` is now `host[:port]` with a
  numeric port only, and two `Host` or `Origin` headers are refused.
- **Release notes: the Open Link question shows the real address.** An IDN
  host is shown as punycode (`xn--…`), bidi controls of the path stay
  percent-encoded, the host has a line of its own, control characters of the
  link text are made visible, and a link with a user name
  (`https://github.com@evil.example/`) is not opened.
- **Update and tour-video caches must be private.** They are made 0700 and
  refused (nothing downloaded into or played from them) when they are a
  symbolic link, belong to another user, are writable by group or others,
  or sit in a folder others may change - as the extension code cache.
- **TFTP takes data only from the transfer's peer.** A packet from another
  port or host (a spoofed DATA block) was logged as "discarding" by tftpy
  and then written into the download - into a firmware image, for example.
  It is now dropped, and the client keeps waiting for the server's block.
- **Agent and MCP: hidden files of the home and the settings folders are
  read-only (default-deny).** Beyond the listed places, no tool writes,
  deletes or moves a hidden entry of the home folder or anything in
  `~/.config`, `~/.local/share`, `~/.local/state` (where XDG moves them too,
  `~/Library`, `%APPDATA%`) unless that folder itself is the agent's or MCP
  server's root or extra folder: `~/.pdbrc`, `~/.wezterm.lua`,
  `~/.config/kitty`, `~/.config/starship.toml`, GNOME Shell extensions, KWin
  scripts and 25 more places that run code were writable. zsh files in
  `$ZDOTDIR` (read from `~/.zshenv`) are start files, and Git's files that
  run code (`.git/config`, `.git/hooks`, `.git/info`, `.gitmodules`, a `.git`
  entry) are refused anywhere. The agent sandbox mounts the hidden entries
  read-only, keeps new ones from being made in the home, and mounts the Git
  config and hooks of its folder read-only.
- **Agent and MCP: credential stores are secret.** AWS, Azure, gcloud, gh,
  kube, docker, PyPI, npm, cargo, rclone, Vault and Terraform credentials,
  Claude Code's, `pass`, browser and mail profiles, shell histories and,
  below a hidden folder of the home, every file named like a credential,
  token, secret, key, password database or cookie jar were handed out by
  `read_file` and visible in the sandbox; now refused and shown empty.
- **Trash: no longer a confused deputy.** `~/.axross-trash` is protected and
  secret for every tool (a trashed SSH key was readable, an agent could plant
  an entry whose Restore wrote `~/.bash_profile` or an autostart entry, or
  rewrite a trashed one before Restore / Undo). Each entry's record is signed
  (HMAC with this user's key) with a hash of its data: a forged or changed
  entry is not restored, an older unsigned one only outside protected places,
  and a signed one back into a protected place only after the user confirms
  it in the Trash window.
- **MCP archive_extract: members are checked too.** The new folder is checked
  as an entry and every member before it is made: a folder that would hold a
  protected place (`~/go` with `go/bin`, `~/.local/share/systemd`) and members
  such as `.git/config` or `evil.pth` were written. The packer checks the
  archive's name before writing it, new files are checked as entries.
- **MCP chmod sets no setuid, setgid or sticky bit and makes nothing group- or
  world-writable** (4755, 2755, 1777 and 777 were accepted).
- **Mail view and labels: table spans no longer freeze the GUI.** A cell's
  `colspan` / `rowspan` is at most 8 (a mail's larger span is cut to 8, a
  label, tooltip or message box asking for more is shown as written), and
  both guards count the cells of the grid Qt lays out - the ones spans join
  and the empty ones that fill short rows, a nested table's double per
  table around it - instead of the cells written: a 4.7 KB mail took 34 s,
  an 841-byte label 31.7 s.
- **Media viewer: an SVG whose `<use>` references fan out is refused.** What
  the references draw is worked out before QtSvg sees the file; past 20,000
  elements, or with a reference cycle, there is no thumbnail (ten levels of
  ten references, 2.4 KB, drew a billion paths and pinned a worker).
- **Message boxes: a name with an HTML comment is shown as written.** An
  archive member named `report.pdf - <b>scan finished: no threats.</b><!--`
  hid the error after it in "Could not open …" and showed a verdict of its
  own.
- **Self-update: carried packs and the new binary are checked against the same pack issue.**
  The packs brought along were checked against one SHA256SUMS and the binary
  against another one fetched later; the signed SHA256SUMS that verifies the
  binary must now name the pack-manifest issue the carried packs were checked
  against, else the update is refused.
- **MCP over HTTP: the bearer token is checked before the per-address rate
  cap.** Requests without the token (another local user, a web page's image
  requests to the loopback port) used up the token holder's budget; they now
  draw from a small budget of their own.
- **Reverse WebDAV/S3: one file name no longer breaks the listing for every
  client.** A name with a control character or bytes that are not UTF-8 made
  PROPFIND and the S3 listing malformed XML or dropped the connection; it is
  now percent-encoded in hrefs (no displayname), escaped in the HTML index,
  URL-encoded in S3 listings asked with encoding-type=url and left out (logged)
  otherwise.
- **MCP Discover: a cached cross-reference only applies to its own server.** A
  planted crossref.json could make a listed server install another registry
  package; the cached registry entry must name the server's repository and
  folder, a Docker Hub image its name.
- MCP servers started with cargo, go (install, build, get, …), mvn/mvnw,
  gradle, sbt and similar build tools count as commands that download and run
  code (never run on the host as they are).
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

- **Linux binaries built in CI.** The `linux` job of `cross-platform.yml` runs `scripts/build_dist.sh` (supply-chain gate, glibc 2.34 and 2.36) and uploads `axross-linux-dist`; `assemble_release.py --ci` takes it, so a release needs no builder machine, only the maintainer's key.
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
