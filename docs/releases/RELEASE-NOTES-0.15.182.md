# axross 0.15.182 - release notes

The notes of the GitHub release of axross 0.15.182 (the asset
`RELEASE-NOTES-0.15.182.md`). `scripts/assemble_release.py --changelog`
takes the section below; the short entry is in [CHANGELOG.md](../../CHANGELOG.md).

## 0.15.182 - 2026-11-20

0.15.182 is a hotfix: opening a Markdown file froze axross on machines
without a font that has every emoji, locally and over SFTP. It also brings
Open as Markdown, a clean selection after a copy, the media player's
non-UTF-8 track names and clearer MCP tool definitions. The downloads are
the same as for 0.15.181 (Linux, AppImages, macOS, Windows, packs, wheel and
sdist, signed `SHA256SUMS`); installed binaries update to it.
axross-headless-mcp 0.15.182 carries the same MCP server changes.

**In short** (the update dialog shows the start of these notes):

- **Markdown files open at once again** (the hotfix): the viewer no longer
  searches every installed font for every emoji before it shows.
- **Open With > Open as Markdown** for any file.
- **Copy and move** leave the source pane without the transferred entries
  marked.
- **MCP server:** tool definitions an agent can use without guessing.

### The Markdown freeze

Before it showed a file, the Markdown viewer worked out which emoji the
installed fonts can draw (`ui.markdown_view.emoji_fonts`, once per run). On
a machine where no font has every emoji, it asked each of the installed font
families - hundreds on a desktop - for each of the 1,800 emoji, on the GUI
thread: a double-click on a README held the whole window for minutes, local
files as much as SFTP ones. A user's Ctrl+C traceback ended there.

- Each font is now asked only for the emoji still missing, and the search
  ends after `EMOJI_SCAN_SECONDS` (0.25 s). Emoji no font asked by then has
  stay as written (`:rocket:`), as they did before without a font for them.
- Regression tests: with 2000 slow fonts and no emoji font, `emoji_fonts`
  returns within its budget, and opening a Markdown file in the viewer -
  the path a double-click takes - stays under 1.5 s (the old code took
  10.7 s in the same test). A machine with an emoji font finds it first and
  stops there, as before.

### Open as Markdown

Open With has *Open as Markdown* beside *Open as Text* and *Open as Hex*: any
file - a README without an extension, notes.txt - rendered in the Markdown
viewer. A double-click renders Markdown names (`.md`, `.markdown`, ...) as
before.

### Copy and move

Once F5, F6, a drop or Paste has queued the transfer, the transferred
entries are no longer marked in the source pane - the next F5 or Delete took
them again by surprise. Other marked rows keep their mark; a copy cancelled
at the conflict prompt keeps the whole selection.

### MCP server

Every tool's definition was reworked against independent blind reviews:

- **Structure:** a summary sentence, then *Use when*, *Instead* (the
  sibling tool for the other case), *Requires* (the flags it is served
  under), *Behavior* (side effects, idempotency, the time limit) and
  *Returns*. The rules every tool shares - paths, backends, the `_b64`
  twins for non-UTF-8 names, secret files, write guards, paranoid mode,
  the two `max_depth` counts, `truncated`/`complete` - are stated once in
  the `initialize` instructions.
- **Schemas:** titles and annotations on every tool, true to what it does
  (read-only, destructive, idempotent, open-world for tools that reach
  remote backends); defaults, ranges, enums and patterns; unknown arguments
  refused (`additionalProperties: false`); an `outputSchema` on 54 of the 55
  tools, with `structuredContent` from MCP 2025-06-18 on. The text result
  of `list_dir`, `search`, `list_versions` and `list_backends` stays the
  array clients read today; their structured result wraps it in an object.
- **New:** `stat` returns the mode; `grep` takes an `include` glob; `search`
  takes `offset` and a `path` folder filter and says whether more results
  follow; `list_dir` and `walk` entries carry `is_link`; times are ISO 8601
  everywhere (the Unix-seconds `mtime` stays beside them);
  `archive_list`/`archive_extract` take a `password`; `script_delete` says
  whether there was a script.
- **Fixed:** `grep` without a path searched `/`, refused under any other
  MCP root - it searches the root; `walk` and `grep` took `max_depth=0` for
  the default; `grep`'s depth had no ceiling (64 now); `file_type`'s 15 s per
  file raced the call's own 15 s deadline (60 s now); `remote_exec` and
  `remote_script` accepted a timeout longer than the call may run and need
  `backend` now (the default backend runs no commands); `preview` refuses an
  edge outside 16-2048 as its schema says (it clamped silently); `copy` is no
  longer marked destructive (it never replaces a file).

### Compatibility

- **MCP:** the tool names are unchanged. Calls that passed unknown
  arguments were already refused; `remote_exec`/`remote_script` without
  `backend` now fail at once instead of on the default backend; `preview`
  with an edge outside 16-2048 fails instead of being clamped; `preview`,
  `archive_list` and `archive_extract` no longer take `backend` (they were
  local only).

### Fixed

- The media player kept a track whose file name is not UTF-8 (a Latin-1
  collection) or holds a no-break space in its state file and dropped it at
  the next start; such tracks come back now. Control characters are still
  refused.
- `scripts/headless_release.py check` ran the export inside the axross
  checkout with the relative path again, so the headless repository's drift
  workflow failed every time.
