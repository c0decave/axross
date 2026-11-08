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
- **FUSE mounts** report when the mount could not be made (no `/dev/fuse`,
  a busy mount point) instead of looking mounted.
- **Windows checkout.** A file named `*.json` in 0.15.176 made the
  repository impossible to check out on Windows, so 0.15.176 had no macOS
  or Windows binaries. It is gone, and a test keeps every file name valid
  on Windows and macOS.

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

### New

- **Help > Handbook** (F1, opened at the part of the window in use, in every
  window) and **Help > Tours** with six guided tours in English and German.
- Pure-Python packs work at once, without a restart; **Update packs** fetches
  a re-issued pack manifest; the updater offers no install for a release
  that has no build for this binary.
- A right-click menu on transfer jobs.
- `--script` takes arguments and wins over `AXROSS_MCP`; `--mcp-http` starts
  the server.

### Changed

- The guided tours dim the rest of the window; narrated tour videos are
  rendered from the real window (`scripts/tour_videos.py`).
- The German interface is translated further, and key names follow the
  keyboard of the language ("Strg+Umschalt+A").
- The release is put together and checked by
  `scripts/assemble_release.py` (docs/PACKAGING.md, "Release flow").

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
