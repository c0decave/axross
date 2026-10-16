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
- The **paranoid security mode** (Tools > Paranoid Security Mode, or
  `AXROSS_SECURITY_MODE=paranoid`) loads no extension at all.
- An extension that raises an error never takes axross down: the error is
  shown in the status bar and in the manager's *Status* column, and
  whatever the extension registered before a failing `activate()` is removed.

## Where they live

| Where | Id |
|---|---|
| `~/.config/axross/extensions/<name>.py` | `user:<name>` |
| `~/.config/axross/extensions/<name>/__init__.py` (a package) | `user:<name>` |
| bundled with axross (`resources/extensions/`) | `bundled:<name>` |

Names starting with `.` or `_` and symbolic links are ignored. A source file
larger than 512 KiB is refused. Which extensions are on is stored in
`~/.config/axross/extensions.json` (mode 0600).
**Extensions > Reload Extensions** runs the current source again.

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
| `api.add_context_action(label, callback, applies_to="any", extensions=())` | An entry in the file pane's right-click menu. `callback(ctx)`. `applies_to`: `any`, `folder` (nothing selected), `selection`, `files`, `folders`, `single_file`. `extensions=(".md",)` limits it by file name. |
| `api.add_dock(title, widget)` | A panel on the right; its show/hide entry goes into the Extensions menu. |
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

## Bundled examples

| Extension | What it does |
|---|---|
| Checksum Manifest | Right-click: write `SHA256SUMS` for the selection or the folder; verify one (`sha256sum` format; entries that leave the folder are ignored). |
| Entropy Heatmap | Right-click a file: entropy per 4 KiB block as a colour strip (first 16 MiB) - compressed or encrypted regions show red. |
| Folder Treemap | A panel: the current folder as a treemap, subfolders summed in the background (bounded); double-click a box to open it. |
| Image Batch | Right-click images: scale down and/or convert to PNG, JPEG or WebP into a `resized` subfolder; originals and existing files stay. |
| Markdown Preview | A panel that renders the selected `.md` file (at most 1 MiB, read in the background; links are not followed). |

Their source in `resources/extensions/` is the best starting point for your own.
