# Extensions

Extensions are Python plugins that add entries to the **Extensions** menu,
actions to the file pane's right-click menu, and panels to the window. They
are managed under **Extensions > Manage Extensions…**.

## Trust

An extension runs inside axross with your rights - like a script, it can
read, change and send anything you can. Therefore:

- Every extension starts **switched off**, the bundled examples included.
- Finding an extension never runs it: axross reads its `EXTENSION` manifest
  with Python's `ast` parser. Its code runs only once you switch it on.
- The **paranoid security mode** (Edit > Settings > Security, or
  `AXROSS_SECURITY_MODE=paranoid`) loads no extension at all.
- An extension that raises an error never takes axross down: the error is
  shown in the status bar and in the manager's *Status* column, and
  whatever the extension registered before a failing `activate()` is removed.
- An extension that **hangs or crashes** axross while its code runs (its
  module code or `activate()`) is not loaded by the next start. Before it
  runs, axross writes a marker (extension, pid, time) to
  `~/.local/state/axross/extension-activation/` and removes it afterwards; a
  start that finds the marker of a process that is gone - or one that has
  been activating for longer than 20 s - skips that extension. It stays
  switched on: a notice offers **Try Again** (load it now; a new hang is
  caught by the next start again) and **Keep Off** (switch it off); closing
  the notice keeps it skipped, and **Reload Extensions** or switching it on
  again in the manager is a new try. The log says which process stopped in
  which extension; `suspended` in `extensions.json` lists the skipped ones.
  An `activate()` that takes longer than 1 s is logged as a warning, and
  every load logs its duration.
- `axross --safe-mode` loads **no** extension at the start (they stay
  switched on; switching one on in the manager still loads it). A start
  whose window does not come within 20 s says so on stderr and names the
  extension it is stuck in - see the start modes in the handbook.

## Where they live

| Where | Id |
|---|---|
| `~/.config/axross/extensions/<name>.py` | `user:<name>` |
| `~/.config/axross/extensions/<name>/__init__.py` (a package) | `user:<name>` |
| bundled with axross (`resources/extensions/`) | `bundled:<name>` |

**Extensions > Open Extensions Folder** creates the folder when it is missing
and opens it in the active pane (a new local pane when the active one is
remote); the button of the same name in Edit > Settings > Extensions opens it
in the desktop's file manager.

Names starting with `.` or `_` and symbolic links are ignored. A source file
larger than 512 KiB is refused. Which extensions are on is stored in
`~/.config/axross/extensions.json` (mode 0600).
**Extensions > Reload Extensions** runs the current source again.

**Pausing.** An extension with a panel or event handlers can be paused with
the pause button in its panel's title bar or **Extensions > Pause <name>**.
While paused it gets no `selection_changed`, `path_changed` or
`pane_activated` events, so its panel stops reloading on every folder
change, and the title says *(Paused)*. Resuming sends each event it missed
once, with the active pane's current folder and selection. The paused state
is kept in `extensions.json` across restarts.

## Writing one

```python
EXTENSION = {                     # a plain literal: name is required
    "name": "Hello",
    "version": "1.0",
    "description": "Says hello.",
    "author": "you",
}


def activate(api):                # required
    api.add_menu_action("Say Hello", lambda: api.notify("Hello!"))
    api.add_context_action(
        "Count Selected",
        lambda ctx: api.notify(f"{len(ctx.paths)} selected in {ctx.folder}"),
        applies_to="selection",
    )


def deactivate(api):              # optional
    pass
```

Everything `api` registered is removed again when the extension is switched
off, reloaded or the window closes; `deactivate` is only needed for your own
resources (files, sockets).

## The API

| Call | What it does |
|---|---|
| `api.add_menu_action(label, callback, shortcut=None, icon=None)` | An entry in the Extensions menu; `icon` names an icon of `ui/icon_provider.py` (the window it opens). |
| `api.add_context_action(label, callback, applies_to="any", extensions=())` | An entry in the file pane's right-click menu. `callback(ctx)`. `applies_to`: `any`, `folder` (nothing selected), `selection`, `files`, `folders`, `single_file`, `single_folder` (exactly one folder selected). `extensions=(".md",)` limits it by file name. |
| `api.add_dock(title, widget, icon="extensions")` | A panel on the right with the title bar of the built-in panels (float, [x], close all) and a Send to Workspace button (⇄); its show/hide entry goes into the Extensions menu, which reopens it after [x]. `icon` is the panel's own icon (title bar, menu entry, floating window); the puzzle piece is only the fallback. Returns the `QDockWidget`; see *Panels and workspaces* below. |
| `api.on(event, callback)` | `callback(ctx)` on `selection_changed`, `path_changed` or `pane_activated` of the active pane. |
| `api.run_in_background(work, on_done=None, on_error=None)` | `work()` on a worker thread, `on_done(result)` / `on_error(exc)` back on the GUI thread. Use it for anything that reads files or the network. |
| `api.current()` | The active pane's context, or `None`. |
| `api.notify(text)` | A status bar message. |
| `api.axross` | The whole scripting API (see [SCRIPTING_REFERENCE.md](SCRIPTING_REFERENCE.md)). |
| `api.log` | A logger named `axross.ext.<name>`. |
| `api.window` | The main window - an escape hatch, not a stable API. |

A window an extension opens itself gets its icon with
`ui.icon_provider.set_window_icon(window, NAME)`: title bar, task bar and the
docked-windows bar then show what it is, not the axross icon.

A context `ctx` has `backend` (the pane's file backend - local or remote),
`folder`, `paths` (the selected full paths), `items` (their `FileItem`s),
`pane` and `is_local`. Read files through `ctx.backend.open_read(path)` so
an extension works on SFTP, S3, SMB … as well as locally.

Never block the GUI thread: a slow server would freeze the window. Do the
work in `api.run_in_background` and touch widgets only in `on_done`.

## Panels and workspaces

A panel from `api.add_dock` is on **all workspaces** (the window's dock
area on the right) until the user puts it on one - with the ⇄ button or a
right click in its title bar (*Send to Workspace > <n: workspace> / New
Workspace / All Workspaces*) or *Workspace > Add Extension Panel*. On a
workspace the panel is laid out like a pane: it shows only while that
workspace is on screen, goes along when the workspace is detached to a
window, is dragged by its title bar and takes dragged panes, is resized by
the splitter handles and evened out by *Equalize Pane Sizes*; it does not
float there. Its [x] takes it out of the workspace, and showing it again
from the Extensions menu (or its toolbar button) puts it back.

What an extension can rely on wherever the panel is:

- The dock and the `widget` passed in stay the **same objects**: a panel is
  moved, never rebuilt, so its state (a playlist, a scroll position, a
  running job) stays. `dock.titleBarWidget().set_title(...)` keeps working.
- Closing a workspace **parks** its panels on all workspaces, hidden; the
  widget is not destroyed and no extension call is made.
- Switching the extension off (or *Reload Extensions*) takes its panels
  out of their workspaces as before (`deactivate` runs, the widgets go);
  the next `add_dock` calls - matched by order, the first panel of the
  extension to the first place - put them back where they were. The
  places are saved with the session, also while the extension is off,
  and a workspace that held only such a panel stays until it comes back.
- The session names a panel by the dock's object name,
  `extension-dock-<extension id>-<n>` (n counts the extension's panels
  in the order `add_dock` was called). An extension that wants its panels
  to keep their workspaces adds them in the same order every time.

The Agent's conversations detached into panels of their own (*Detach as
Panel*, *New Agent Window*) are placed the same way and are listed in
*Add Extension Panel* too; they are no extension's panels and never reach
an extension through `add_dock`.

An extension needs no change for any of this. A panel is hidden whenever
its workspace is not on screen, as it is after [x]; an extension that
stops work on a hidden panel (a visualization timer) checks
`widget.isVisible()` as before.

## Bundled examples

| Extension | What it does |
|---|---|
| Checksum Manifest | Right-click: write `SHA256SUMS` for the selection or the folder; verify one (`sha256sum` format; entries that leave the folder are ignored). |
| Entropy Heatmap | Right-click a file: entropy per 4 KiB block as a colour strip (first 16 MiB) - compressed or encrypted regions show red. |
| Folder Treemap | A panel: the current folder as a treemap, subfolders summed in the background (bounded); double-click a box to open it. |
| Drives Overview | A panel: every local and mounted drive (Linux /proc/self/mounts, Windows drive letters, macOS psutil or `mount`) with size, used and free as a sortable table, a pie of the selected drive and bars of all drives; a drive that does not answer within 2 s shows as unknown; double-click opens a drive in the active local pane. |
| Image Batch | Right-click images: scale down and/or convert to PNG, JPEG or WebP into a `resized` subfolder; originals and existing files stay. |
| Media Player | A panel that plays MP3, WAV, Ogg Vorbis, FLAC, Opus, AAC and more (Qt's FFmpeg backend): playlist (right-click > *Play in Media Player*, *Add…*, or drag & drop of files and folders from a pane or the desktop; remote files copied first, at most 512 MB each), rows reorder by dragging, M3U/M3U8 load and save, the last playlist and position restored on the next start; seeking (position slider, Left/Right), shuffle, repeat off/all/one, perceptual volume with mute, on the output device and at the output volume of *Edit → Settings… → Audio*; when audio does not start the panel says why and offers *Try Again* and *Audio Settings…*; keys while the panel has the focus (see docs/USAGE.md); title/artist/album and cover, a 10-band equalizer with presets that folds away and animated visualizations a click switches between - spectrum, mirrored, radial, line and polar spectrum, waterfall, oscilloscope, stereo scope, VU meter, starfield, LED equalizer, particle columns, wave ribbon, ridgelines, spectrum terrain, 3D ring, kaleidoscope, bell curves - in colour schemes (Classic, Fire, Ice, Neon, Mono, the theme's, your own; peaks keep 3:1 contrast) with bar count, peak fall, smoothing and frame rate cap (right-click menu, *Extensions → Media Player Visualizer…*), fullscreen like a screensaver (double-click, F11) or detached into a window of any size; the playlist folds away; choices and fold states are kept (equalizer and visualizations need numpy: `pip install axross[media]`, bundled in axross-full). |
| VirtualBox | Right-click a `.vbox`: register the machine in VirtualBox (`VBoxManage registervm`). Right-click a `.vdi` / `.vmdk` / `.vhd` / `.vhdx`: pick a VM (and a controller when it has several); the disk goes on the first free slot (`VBoxManage storageattach`). Local files only. |
| Backup Repositories | Right-click one folder (or nothing, for the current one): what a restic, Borg or duplicity repository holds. Without a password from its layout (restic counts, Borg's config, duplicity's backup chains from the file names - on any backend); *Unlock…* lists the snapshots through the tool (`restic snapshots --no-lock`, `borg list --bypass-lock`, `duplicity collection-status`; for duplicity the password is first checked by decrypting the newest manifest with gpg, because collection-status reads only file names). The password goes to the tool's environment or gpg's stdin only and is not stored; nothing is written to the repository. |
| Forensic Tools | Right-click a disk image: MD5 / SHA-1 / SHA-256 in one pass; `qemu-img info`; *Convert to Raw Image* (`qemu-img convert -O raw`, never over an existing file); *Browse File System* with The Sleuth Kit (`fls`, deleted files included) and *Extract* (`icat`) - no mount needed; on a qcow2 / VMDK / dynamic VDI / VHD(X) Browse says the partitions are inside a container and offers *Convert to Raw…*; TestDisk and PhotoRec in a terminal pane. Missing tools are named with their package. |
| Agent Stats | A small window, on top and movable anywhere, with what the agent did: tasks, answers, tool calls, errors, declined calls, tokens and time - for all tabs and for the tab that ran last. |
| Markdown Preview | A panel that renders the selected `.md` file (at most 1 MiB, read in the background; links are not followed). |
| Audio Mixer | A panel with every sound setting (Tools → Audio Mixer): *axross* - the master volume, mute and output device, and a channel per source (Media Player, Agent voice, media preview) with its own volume, mute and output; *Equalizer* - axross's one 10-band equalizer with presets, which the Media Player's equalizer row shows and the Agent's voice goes through (`core/audio_eq.py`, needs numpy to be heard); *System* - the sound server through `pactl` (PipeWire or PulseAudio): outputs and inputs with volume, mute and the default, the programs playing and recording with their volume and device (choose one to move it), and the cards' profiles (`core/system_mixer.py`; without pactl the tab says why). Saved in `audio.json`; running players follow at once. |
| IRC | A panel with your IRC networks (*Accounts…*: server, nick, login; several networks at once), their channels and private conversations (*Join Channel…*, *Private Message…*, or double-click a member). TLS with the certificate checked by default; a server with a self-signed certificate is trusted only after you compared its SHA-256 fingerprint, which is then pinned (a different certificate later is refused). Login with SASL SCRAM-SHA-256 (the server proves it knows the password too), SASL PLAIN (only over TLS), SASL EXTERNAL (a client certificate) or NickServ; a SASL login that fails ends the connection - the password is never tried another way. Passwords are kept in the keyring. Channels show topic, members with their status and modes; /me, notices, /commands (*/help* lists them), Tab completes nicks and commands, Up/Down the input history; long or pasted messages are split to fit IRC's line limit and sent with a flood limit. Reconnects with a growing pause and rejoins the channels; axross's default proxy is used unless the account says *Direct*. A conversation opens in a window of its own with *Window*. Messages are shown as plain text (no colours, no images; a web address is a link that is opened only after you saw it whole); CTCP requests (VERSION, TIME ...) are not answered. IRC has no end-to-end encryption: the panel shows *TLS to the server* - the network's servers can read what is written. Accounts in `~/.config/axross/chat.json` (0600, no passwords); `core/chat_irc.py`, `ui/chat_panel.py`. |
| Matrix | A panel with your Matrix accounts (*Accounts…*: homeserver, user, password for the first sign-in), their rooms and direct chats (*Join Room…*, *Direct Chat…*; a new direct chat is created end-to-end encrypted), invitations asked in a dialog. End-to-end encryption with Olm/Megolm (matrix-nio on vodozemac): messages in an encrypted room are encrypted for every device of its members; one that cannot be decrypted says so and its key is asked from your other devices. *Encryption…* lists every device of a room's members with its fingerprint and trust: *Verify Interactively…* (compare seven emoji or numbers - with Element and other clients, which start with a verification request, and with the older direct start; the other side's request is asked in a dialog), *Mark Verified* after comparing the fingerprint, *Blacklist* (it gets no keys), *Ignore*; *Export Keys…* / *Import Keys…* (the passphrase-protected format Element uses, written 0600). Whether messages go to devices nobody verified is the account's choice: send and warn (as Element) or send nothing until each is verified, blacklisted or ignored. The login (access token) and the key store's key are kept in the keyring, the device's keys in `~/.local/state/axross/chat/` (0700), so the next start is the same device. Only https:// homeservers (plain http only to one on this machine); axross's default proxy is used unless the account says *Direct*. Messages are plain text (formatted HTML is not rendered), attachments are named, never fetched; conversations open in windows of their own. Needs `pip install 'axross[chat]'`; `core/chat_matrix.py`, `ui/chat_security.py`. Cross-signing and server-side key backup are not supported yet. |
| XMPP | A panel with your XMPP (Jabber) accounts (*Accounts…*: Jabber ID, password; the server from DNS or given), contacts with presence (contact requests are asked), one-to-one chats and group chats (*Chat With…*, *Join Group Chat…*; MUC). TLS always (STARTTLS or direct TLS) with the certificate checked; a self-signed server is trusted by its pinned SHA-256 fingerprint, checked right after the handshake - before the password is sent. One-to-one chats are end-to-end encrypted with OMEMO 2 (python-omemo + twomemo, Stanza Content Encryption; the old OMEMO of Conversations/Dino too if you install the AGPL `oldmemo` package yourself - it is not bundled); the server sees only a fallback text. New devices of a contact are trusted blindly until one of its devices is verified, then asked (or always asked, as the account says); *Encryption…* lists every device with its fingerprint: mark verified after comparing, trust, distrust. `/plain` switches one chat to unencrypted, `/omemo` back. Message carbons (what you send from another client shows here too), reconnect, axross's default proxy unless *Direct*. Group chats are not OMEMO-encrypted here (TLS to the server only) - the panel says so. OMEMO keys are kept AES-GCM encrypted (the key in the keyring) in `~/.local/state/axross/chat/` (0700). Needs `pip install 'axross[chat]'`; `core/chat_xmpp.py`. |
| Bluetooth | A panel to connect Bluetooth devices through BlueZ on the system D-Bus (PyQt6.QtDBus, no program started; Linux): the adapter with its power switch, a scan for Classic and/or BLE devices with a minimum signal (stops after 2 minutes) listing name, address, type, radio, signal in dBm, advertised vendor, battery, when last heard and Connected / Paired / Trusted, and a filter row (words, radio, named only); *Details…* with everything BlueZ knows of a device and the map of a BLE device's GATT services (read values, watch notifications, known formats decoded); a *Map* of the devices nearby by estimated distance (signal and advertised TX power, smoothed), with a signal history per device; *Add Device…* (scan, pair, trust, connect and use as audio output in one go); connection options and tests (connect single profiles, reconnect automatically, a timed connection test, a test sound on the device's own output and a headset microphone level test, `core/bluetooth_link.py`); Pair (a passkey confirmation, PIN or passkey is asked in a dialog - never accepted without your answer), Trust, Connect, Disconnect, Remove; *Use as Audio Output* connects a speaker or headset, waits for its output in the sound server and makes it the output of *Edit → Settings… → Audio* (the Media Player follows). BlueZ's errors (adapter off, rfkill, wrong PIN, out of range, profile unavailable) are sentences; without D-Bus, `bluetoothd` or an adapter the panel says so and offers nothing else. What a device is also comes from its advertisement (`core/bluetooth_adv.py`: iBeacon, Eddystone, AltBeacon, Apple Continuity such as AirPods with the model and Find My, Microsoft Swift Pair, Google Fast Pair, trackers, Ruuvi / BTHome sensors) and the vendor from the Bluetooth SIG's company list or, for a public address, its OUI (`core/bluetooth_vendor.py`). *Presence…* logs when which device was in range, with the times anybody scanned, keeps a scan running if asked and exports CSV or JSON (`core/bluetooth_presence.py`). *Streams…* opens an HCI capture (`btmon -w`, Android's `btsnoop_hci.log`) and lists its connections and L2CAP channels with their protocol (ATT/GATT, SMP, SDP, RFCOMM, AVDTP audio, AVCTP, HID ...), frames, bytes and rate, draws the traffic over time, follows a capture still being written and shows it with the Media Player's visualizations (`core/bluetooth_stream.py`). *Adapter:* BlueZ (system), or a USB Bluetooth stick that axross drives itself through Bumble (`pip install 'axross[bluetooth-raw]'`, `core/bluetooth_direct.py`): without BlueZ, also on Windows (the stick needs the WinUSB driver, e.g. via Zadig) and macOS (external sticks); scanning, connecting, GATT and pairing (with the same questions) work there, bonds are kept in a 0600 file; audio output and single profiles need BlueZ. axross asks before it takes a stick from the system. Its engine is `core/bluetooth.py`. |
| Arcade | axross's own small games in a window (*Extensions → Arcade…*), with sound and music synthesised at run time on the Audio Mixer's own *Arcade* channel (volume, mute, output; M mutes in a game): **Tilt Maze** - 100 levels in 10 worlds on an isometric board that scrolls: collect every bit while hexagonal drone daemons hunt Bitling (one tracks, one cuts off, one drifts, one patrols, the Hopper jumps pits); a root key turns them, Space jumps over them and over pits; teleporters, extra lives, a level select with each world's code; animated (gliding moves, a squash-and-stretch jump, particles, the board dropping in). **Rockfall** - 40 caves in 5 worlds: dig for crystals with a little mining robot, rocks fall and roll and turn as they do, prisms split falling rocks into crystals, crawlers and seekers hunt; W A S D move, Space with a direction takes the cell beside without stepping in; a scrolling camera, level select and world codes. **Trail Runner** - glowing light trails in eight arenas or a tournament, 1-3 computer riders in three difficulties or two players on one keyboard (W A S D + Space against the arrows + Enter), a boost while the energy lasts, a 3-2-1-GO countdown. **Byte Chase** - the classic top-down maze chase with generated mazes. P pauses, Esc goes back. Every level, graphic, character and tune is the Arcade's own. Best scores in `~/.config/axross/arcade.json`, progress in `arcade-progress.json`. Rules in `core/arcade/`, the windows `ui/arcade_*.py`. |
| System Information | A window with everything about the computer axross runs on (*Extensions → System Information…* or *Tools → System Information…*): an overview with the computer's name, maker, model and OS, rings for CPU load, memory, swap, the root file system and the battery, the hottest temperatures on a colour scale and live sparklines of CPU and memory; then a page each for CPU (per-core use, frequencies, caches, instruction set features, the kernel's view of CPU vulnerabilities), Memory, Storage (a bar per disk with its partitions, mount points and use), Graphics & Displays (adapters, outputs, monitor names from EDID and a sketch of the screens), Network (interfaces, Wi-Fi signal, live throughput, Bluetooth adapters, radio switches), Audio, USB & Peripherals and PCI (as trees, names from `usb.ids` / `pci.ids`), Battery & Power (charge, health against the design capacity, cycles, time left), Sensors (temperatures, fans, voltages), System & OS (firmware, Secure Boot, kernel, desktop) and Virtualisation (VM or container, with the evidence). Read from `/proc` and `/sys` without root and without starting a program (Windows and macOS: what Python and the optional psutil tell); every source has a deadline and a section that cannot be read says why. One search filters all pages; *Copy Section*, *Copy All* and *Save Report…* (text or JSON). Serial numbers, MAC and IP addresses and UUIDs are hidden - on screen and in every copy - until *Show identifiers* is ticked. Live values are read once a second only while the window is on screen. |

Their source in `resources/extensions/` is the best starting point for your own.
