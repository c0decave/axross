# axross 0.15.181 - release notes

The notes of the GitHub release of axross 0.15.181 (the asset
`RELEASE-NOTES-0.15.181.md`). `scripts/assemble_release.py --changelog`
takes the section below; the short entry is in [CHANGELOG.md](../../CHANGELOG.md).

## 0.15.181 - 2026-11-20

0.15.181 lets axross share an Android phone with the console's `adb`,
describes every tool of the MCP server so a client can judge it, and
brings the Markdown reader of axross-markdown 0.16.6 and 0.16.7 into
axross. The downloads are the same as for 0.15.180 (Linux, AppImages,
macOS, Windows, packs, wheel and sdist, signed `SHA256SUMS`); installed
binaries update to it. axross-headless-mcp 0.15.181 carries the same MCP
server changes.

**In short** (the update dialog shows the start of these notes):

- **ADB through the adb server:** with the platform tools' adb server
  running, *USB / adb server* mode reaches the phone through it and shares
  it with the console's `adb` - before, axross failed with "Another program
  holds the phone's USB connection" and asked for `adb kill-server`. The
  connection dialog lists the phones connected now, with their state and a
  Refresh button. Uploads to a phone are atomic.
- **MCP server:** every parameter of every tool is described, the tools say
  what they return and when to use them, `initialize` sends instructions,
  and the server and its registry entry carry a logo.
- **Markdown reader:** no hostile shape holds the window in any container;
  display math in an alert and after text; the editor's preview follows
  the typing in long texts; zoom between 25 and 400 %.

### Compatibility

- **ADB, USB mode:** `adb kill-server` is no longer needed. When the adb
  server of the platform tools runs on 127.0.0.1:5037 (`adb start-server`,
  Android Studio or any `adb` command starts it), axross reaches the phone
  through it; without a server it opens the phone over USB itself, as
  before (libusb-1.0). axross uses an adb server on this computer only:
  `ADB_SERVER_SOCKET` or `ANDROID_ADB_SERVER_PORT` naming another host is
  ignored. The mode is called *USB / adb server*; saved profiles keep
  working unchanged.
- **ADB, TCP mode on localhost:5037** (the server's own port, not a phone)
  now uses the server too, when exactly one phone is connected (TCP mode
  has no serial to choose by; *USB / adb server* mode does).
- **axross-headless-mcp's repository** (c0decave/axross-headless-mcp) is
  written only by axross's export: each commit carries the trailer
  `Exported-From: c0decave/axross@<ref>` and is tagged with the PyPI
  release, and its workflow `drift.yml` exports again from that ref and
  fails on any file that differs, is missing or was added. A fix goes into
  axross and reaches the repository with the next export.
- **MCP tool names are unchanged**; only descriptions, the `initialize`
  instructions and `serverInfo.icons` were added.

### ADB

- `core/adb_server.py` speaks the adb server's host protocol
  (`host:version`, `host:devices-l`, `host:transport:<serial>`) and its
  shell and sync services, on the loopback address only. Its answers are
  treated as untrusted: lengths must be four hex digits, `OKAY` / `FAIL`
  are parsed strictly, a `FAIL` text is cut and cleaned before it is shown,
  every read has a time-out and every host answer a deadline, the device
  list is counted and bounded, a serial is checked before it is sent, and a
  sync `DATA` block is at most 64 KiB.
- USB mode (and TCP to the server's port) goes through the server when one
  answers; the shell's output cap and deadline apply on top; an
  unauthorized phone is waited for with the "Check the phone" notice; each
  transfer gets its own server connection.
- **The Device list** in the connection dialog: the server's phones with
  their state - ready, not allowed yet (accept the prompt on the phone),
  offline, no permission - and a hint for each; without a server the USB
  devices found. Choosing one fills in its serial; serials with `.`, `:`,
  `%` and `@` (Wi-Fi phones of `adb connect`) are kept as they are.
- **Uploads are atomic on every transport:** a file goes to a temporary
  name beside it and replaces the old one when complete, so a broken
  upload leaves the old file as it was; a folder that takes no new file
  gets the bytes in place.
- **Errors say what to do:** not allowed yet, offline, no permission,
  several phones without a serial, an unknown serial; and when the phone
  is busy, whether axross could have shared it through an adb server and
  why it did not (none answers, a setting naming another computer).
- The handbook (en, de, es) and the German strings describe the new mode.

### MCP server

- **Tool definitions a client can judge** (Glama's Tool Definition Quality
  Score for axross-headless-mcp was 3.7 of 5): every parameter of every
  tool is described with its defaults and limits - 54 parameters of 23
  tools had none. `list_dir`, `stat`, `search`, `mkdir`, `remove`,
  `rename`, `copy`, `symlink`, `hardlink`, `script_delete` and
  `remote_close` say what they return and when to use them; `remove` says
  it is permanent, `rename` and `copy` that an existing destination is
  never replaced. `search` names the index it reads (`index_build`) and
  points at `walk` and `list_dir` for the live state; those two point at
  each other.
- **Instructions on `initialize`** (MCP 2025-03-26 and later): facts about
  the tools - the backends, the root, secrets, which tool lists, reads and
  searches what, when a result is truncated or complete, the flags.
  `docs/mcp-tools.json` and `docs/LLM_GUIDE.md` are regenerated.
- **The logo:** `serverInfo.icons` (MCP 2025-11-25 and later) and the
  registry entry `server.json` name the axross-headless-mcp logo by HTTPS
  URL; no image travels in the protocol, and older protocol revisions get
  `serverInfo` as before. `server.json` is checked against the registry's
  own schema.
- **axross-headless-mcp** has a `Dockerfile` at its repository's root, for
  directories that build a server from its repository (Glama, the Docker
  MCP Catalog): it installs the repository's own package, runs it as an
  unprivileged user, read-only and confined to `/data` by default. The
  release image stays `Dockerfile.mcp` in axross.
- The release now commits and tags the exported tree in
  axross-headless-mcp together with the PyPI upload
  (`scripts/headless_release.py sync`), and checks that the repository's
  GitHub release carries what PyPI carries
  (`scripts/headless_release.py compare-dists`; docs/PACKAGING.md, steps 10
  and 12).

### Markdown reader

The reader of axross-markdown 0.16.6 and 0.16.7 (the twentieth review's
fixes), in axross's Markdown viewer and the editor's preview. Times are the
window's own CPU in one event-loop turn.

- **No hostile shape holds the window**, at the top level or in a table
  cell, a heading, a list, a quote, an alert, a footnote, a definition or a
  `<details>`, under both parsers: every case now stays under 0.25 s a
  turn.
  - A heading's or a table cell's text past 2,000 characters is cut with
    "…" (1.2 to 2.1 s before; the editor shows all of it); one code span of
    90,000 characters is laid out in pieces (0.8 to 1.8 s before).
  - A footnote cited 100,000 times shows its first 20 ways back and "and
    N more"; Ctrl+End reached the end after 4.3 s, now 0.2 s.
  - Thousands of headings are laid out in linear time: 30,000 took 104 s,
    now 1.5 s.
  - A long text of one kind (20,000 small tables, 150,000 lines of short
    code spans, a 700 KB line) shows its first part at once.
  - A paragraph of 50,000 emoji: an emoji now counts as 128 letters in a
    paragraph's pieces whatever the fonts, so a turn lays out about 14
    times fewer of them (0.42 to 0.70 s a turn on a CI host with hundreds
    of fonts; here, with a colour emoji font, 0.035 to 0.043 s before and
    0.015 s now).
- **Display math** (`$$` on its own lines) in an alert (`> [!NOTE]`) or
  after a line of text is a display formula, as on GitHub; a lazy line in
  a quoted formula keeps the other lines' marks off.
- **The editor's preview follows the typing** far down a long text and in
  a text without headings.
- **Zoom:** Ctrl+wheel and Ctrl+= zoom through the view's level, between
  25 % and 400 %.
- Image boxes take a theme chosen later; a file that cannot be read says
  why in the page.
- The handbook (en, de, es) describes the reader as it is now.
- Not noted in 0.15.180, but already in it: YAML code is coloured again (a
  token type a Pygments style leaves out takes its parent's colour).

### Releases and packaging

- The CI's stage job uploads each file as an asset of its own (the Linux
  artifact is over GitHub's 2 GB per release asset) and names the line
  that failed.
- `docs/releases/` is claimed as an empty package like `docs/patterns/`:
  the release notes are in the sdist and stay out of the wheel.

### Known limitations

- **ADB over the adb server** is tested against a fake adb server (host
  and sync protocol, with hostile answers), not yet against a phone on
  every system. Android 11's *Wireless debugging* (pairing code, TLS) is
  still not supported - use `adb tcpip 5555`.
- The other known limitations of 0.15.180 remain: the macOS binaries are
  only ad-hoc signed and the Windows ones not signed; there is no macOS
  build for Intel Macs and no Linux build for arm64; printing in the Linux
  binaries writes a PDF.
