# axross 0.15.183 - release notes

The notes of the GitHub release of axross 0.15.183 (the asset
`RELEASE-NOTES-0.15.183.md`). `scripts/assemble_release.py --changelog`
takes the section below; the short entry is in [CHANGELOG.md](../../CHANGELOG.md).

## 0.15.183 - 2026-11-21

Folder copies are many times faster and show their progress where you look,
the file panes' column headers move and size as they should, the Arcade plays
without gaps in its sound, the Markdown reader of axross-markdown 0.16.8 to
0.16.10 is in axross, and the MCP server's tools have consistent names. The
full list is in the release notes (`RELEASE-NOTES-0.15.183.md` on the
[release page](https://github.com/c0decave/axross/releases/tag/v0.15.183)).
The downloads are the same as for 0.15.182; installed binaries update to it.

**In short:**

- **Folder copies:** a folder of 10,000 small files copies in seconds instead
  of minutes in every direction (SFTP to disk 508 s -> 13 s, disk to SFTP and
  SFTP to SFTP about 13 min -> 16-21 s): small files are read and written in
  pipelined batches, our SSH socket acknowledges at once, and an upload batch
  is verified with one `sha256sum` instead of one per file - and every file
  is verified now (before, the check stopped after the server turned one
  command down). Temp names, conflict answers, the journal and undo work as
  before.
- **Progress in sight:** while a copy runs, the status bar says "Copying
  1,210 of 10,000 files - 12 %" (a click opens Transfers) and the destination
  pane shows it with a thin bar - before, nothing showed it unless Transfers
  was open, and the folders seemed to arrive without their files.
- **Links in a copied folder** are recreated as links (they were copied as
  their targets, and a link to a folder failed the copy over SFTP); where the
  destination cannot hold links they are skipped with a note.
- **Column headers:** a moved column keeps its place (another pane no longer
  puts the old order back), dragging the divider right of Name follows the
  mouse, a double-click on a divider fits the column fast even in huge
  folders.
- **Arcade:** the music no longer drops out when the window is busy (about a
  tenth of it was silence), and a long session or a resized window no longer
  piles up memory (up to 400 MB before).
- **Markdown reader (axross-markdown 0.16.8 to 0.16.10):** no document holds
  the window - a line of backticks froze the built-in viewer for 12 s, long
  raw-HTML lines, heading and list-marker runs, no-break spaces, bracket runs
  and huge tables took seconds - in the window, PDF export, Print and Find,
  measured now as the window's real responsiveness; every pattern is tested
  against hostile input; local images and links work on Windows; the export
  and print dialogs come at once and closing the viewer ends an export;
  `<details>` folds with Qt's parser too; a colour emoji font is the emoji
  family again when one is installed.
- **Shared settings with axross-amp:** axross keeps what axross-amp writes to
  `audio.json` and `media_player.json` (its output device, its own faces and
  settings).

### MCP server

- **MCP server: 52 tools, named verb, then resource.** `list_dir` is now
  `list_directory`, `stat` `get_path_info`, `grep` `search_content`,
  `search` `search_index`, `walk` `walk_tree`, `remove` `delete_path`,
  `transfer_copy` `copy_path_to_backend`, `remote_open` `open_remote_profile`,
  `remote_exec` `run_backend_command`, `agent_run` `run_llm_agent` ... (all in
  `docs/MCP.md` §9.2); the resource word says what a tool takes (file,
  directory, tree, path). Three tools went into another one:
  `metadata_export_file` is `export_metadata` with `out` (only with
  `--mcp-write`), `exec_backends` is `list_backends` with `can_run_commands`
  (each backend says what `commands` it runs), `extensions_info` is
  `list_extensions` with `name`. The group `packer` is part of `archive`.
  Clients that use the former names keep working: `tools/call` takes them
  (with the merged tools' arguments translated), `--mcp-tools packer` still
  works, `tools/list` shows only the new names, and the audit trail names the
  new one. A merged tool answers in its new shape (`exec_backends`: the
  `list_backends` array; `extensions_info`: the `list_extensions` object;
  `metadata_export_file`: the written file in `out`).
- **MCP parameters: one name per meaning.** `max_depth` counts levels from 1
  in every tool; `scan_file_types` and `copy_path_to_backend` take
  `subfolder_levels` (from 0) instead. `search_index` takes `pattern` and
  `max_results` (was `needle`, `limit`), `run_script` `timeout` (was
  `timeout_s`), `create_archive` `path` (was `folder`). The former names
  still work.
- **MCP copy:** `copy_path_to_backend` copies a local link to a file as the
  file, as `copy_tree` does (it skipped it); other links and special files are
  still skipped.
- **MCP instructions** come in sections and say how a failed call answers
  (`isError` with the message, `_meta.type` the kind of error).
- **MCP results:** `search_index` returns `{entries, indexed, truncated}` as
  its text too (it was the bare array), so a client that reads only text sees
  whether there is an index and more pages.
- **MCP tool definitions, again clearer:** the rules every write tool shared
  (write guards, idempotency, `--mcp-write`) are said once in the
  instructions; how a refused secret file shows up in each tree tool, what a
  failed move or copy leaves behind, the order `list_duplicate_groups` pages
  in, what `run_backend_script`'s interpreters run where, every field of
  `identify_file_type`. `read_file_version` pages with `offset` and decodes
  `encoding=text` as `read_file` does; `scan_file_types` lists refused secret
  files in `unreadable`; `list_backends` marks a connection lent by a pane
  (`lent`).

### Compatibility

- **MCP tool and parameter names changed** (see above); every former tool
  name, parameter name and `--mcp-tools packer` keeps working. A merged tool
  answers in its new shape, and `search_index`'s text is now the
  `{entries, indexed, truncated}` object instead of the bare array.
- **Copies:** links inside a copied folder stay links.

### Tested

- The full suite on the release commit: 27,648 passed, 1,887 skipped; the six
  that failed under the machine's load (wall-clock bounds of the Markdown
  stress tests, one audio seek, one relay count) passed each on its own.
- Folder copies are measured against the test SFTP server in every direction
  (10,106 entries), the Arcade's sound against a model of Qt 6.11's audio
  sink with a late GUI thread, the Markdown reader's turns in the window, PDF
  export, Print and Find.
- The MCP tool definitions were graded blind against Glama's TDQS method in
  eight rounds; the last blind grades were about 4.5 of 5.
