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
| `api.add_menu_action(label, callback, shortcut=None)` | An entry in the Extensions menu. |
| `api.add_context_action(label, callback, applies_to="any", extensions=())` | An entry in the file pane's right-click menu. `callback(ctx)`. `applies_to`: `any`, `folder` (nothing selected), `selection`, `files`, `folders`, `single_file`, `single_folder` (exactly one folder selected). `extensions=(".md",)` limits it by file name. |
| `api.add_dock(title, widget)` | A panel on the right with the title bar of the built-in panels (float, [x], close all) and a Send to Workspace button (⇄); its show/hide entry goes into the Extensions menu, which reopens it after [x]. Returns the `QDockWidget`; see *Panels and workspaces* below. |
| `api.on(event, callback)` | `callback(ctx)` on `selection_changed`, `path_changed` or `pane_activated` of the active pane. |
| `api.run_in_background(work, on_done=None, on_error=None)` | `work()` on a worker thread, `on_done(result)` / `on_error(exc)` back on the GUI thread. Use it for anything that reads files or the network. |
| `api.current()` | The active pane's context, or `None`. |
| `api.notify(text)` | A status bar message. |
| `api.axross` | The whole scripting API (see [SCRIPTING_REFERENCE.md](SCRIPTING_REFERENCE.md)). |
| `api.log` | A logger named `axross.ext.<name>`. |
| `api.window` | The main window - an escape hatch, not a stable API. |

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
| Bluetooth | A panel to connect Bluetooth devices through BlueZ on the system D-Bus (PyQt6.QtDBus, no program started; Linux): the adapter with its power switch, a scan (stops after 2 minutes) listing name, address, type, signal in dBm, battery and Connected / Paired / Trusted; Pair (a passkey confirmation, PIN or passkey is asked in a dialog - never accepted without your answer), Trust, Connect, Disconnect, Remove; *Use as Audio Output* connects a speaker or headset, waits for its output in the sound server and makes it the output of *Edit → Settings… → Audio* (the Media Player follows). BlueZ's errors (adapter off, rfkill, wrong PIN, out of range, profile unavailable) are sentences; without D-Bus, `bluetoothd` or an adapter the panel says so and offers nothing else. Its engine is `core/bluetooth.py`. |

Their source in `resources/extensions/` is the best starting point for your own.
