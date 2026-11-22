# axross 0.15.184 - release notes

The notes of the GitHub release of axross 0.15.184 (the asset
`RELEASE-NOTES-0.15.184.md`). `scripts/assemble_release.py --changelog`
takes the section below; the short entry is in [CHANGELOG.md](../../CHANGELOG.md).

## 0.15.184 - 2026-11-22

Android phones get a window of their own and an MCP tool group, the Markdown
reader of axross-markdown 0.16.11 to 0.17.3 is in axross (twelve page themes,
no freeze from hostile texts), images on a phone or server open as images,
and the MCP server's tools are fewer and fuller. The full list is in the
release notes (`RELEASE-NOTES-0.15.184.md` on the
[release page](https://github.com/c0decave/axross/releases/tag/v0.15.184)).
The downloads are the same as for 0.15.183; installed binaries update to it.

**In short:**

- **Android devices, in the window and over MCP.** For a phone connected
  over ADB, right-click > More > *Android Device…* (or *Pane > Android
  Device…*) opens a window of the phone itself: *Info* (model, Android
  version, security patch, serial, IMEI where the phone gives it, battery,
  storage, reboot), *Apps* (filter, details and permissions, start, stop,
  uninstall, install and back up APKs), *SMS* (read; write into the store
  or prepare one in the SMS app - never sent by axross), *Logcat* (filter,
  follow, pause, save) and *Screenshot*. Every change asks first,
  Uninstall and Reboot count down, production profiles pass the production
  countdown, the paranoid mode turns changes off, and a slow phone never
  holds the window.
- **MCP: the tool group `adb`** (`--mcp-tools remote,adb`): 20 tools on an
  opened ADB profile - `get_device_info`, `list_device_properties`,
  `get_battery_status`, `list_apps`, `get_app_info`, `list_running_apps`,
  `get_logcat`, `take_screenshot`, `list_sms`, and with `--mcp-write`
  `start_app`, `stop_app`, `install_app`, `uninstall_app`, `export_app`,
  `grant_permission`, `revoke_permission`, `reboot_device`, `write_sms`,
  `compose_sms` (prepares, never sends) and `send_at_command` (root and a
  modem node only). Commands are argument lists, each argument quoted;
  inputs are checked against narrow patterns, answers cleaned of control,
  bidi and invisible characters and capped; every call has a deadline; the
  tools that change the device are refused on production profiles and in
  the paranoid mode and audited without message texts (docs/MCP.md §9.10).
- **MCP, compatibility: `--mcp-tools all` no longer includes `adb`.** `all`
  means every general group now; the Android group comes only by name -
  `--mcp-tools all,adb` is every group, `remote,adb` a phone. A server
  started with `all` serves 54 tools, not 74 (docs/MCP.md §9).
- **MCP: what the tools could not do before.** `list_trash` and
  `restore_from_trash` list and undo what `trash_duplicates` moved (only
  entries from inside the MCP root, back to a free place in it; a tampered
  record is refused); `write_file` takes `write_mode` `create` (never
  replaces), `append` and `at_offset` (with `offset`); `restore_file_version`
  makes an older version current again where the storage keeps versions;
  `list_llm_profiles` names the LLM profiles and their models (never a key
  or an endpoint); `walk_tree`, `search_content` and `list_duplicate_scans`
  page on with `offset` / `next_offset` past their caps, and `search_index`
  and `list_duplicate_groups` name their `next_offset` too.
- **MCP: two pairs merged** (one safety class each): `create_symlink` and
  `create_hardlink` are `create_link` with `kind`, `run_backend_script` is
  `run_backend_command` with `script`; the former names still answer, as
  does `run_llm_agent`'s `profile` (now `llm_profile`), and with the
  results they always gave (`create_link`: `{ok: true}`, plus `target` when
  another one was stored). Other results only gained fields
  (`write_file`'s `file_size`, `offset` / `next_offset` of the paged ones).
- **ADB:** the adb server's messages and device names are stripped of
  U+061C and U+2060-U+206F (and the tag characters) too, not only of the
  bidi overrides.
- **Images on a phone or a server** (ADB, SFTP, SMB, ...) open in the media
  viewer, read off the window's thread - a double-click on a PNG over ADB
  opened the hex editor.
- **Markdown reader (axross-markdown 0.16.11 to 0.17.3):** with Qt's own parser
  a heading keeps its size and weight after an inline span (`# foo *bar*`),
  `_em_` and `__strong__` are italic and bold (not underlined), link titles in
  quotes or parentheses work, Find selects the right text after emoji;
  twelve page themes
  (View > Theme, every one WCAG AA, two AAA), a theme switch without a flash;
  no document holds the window - code-span and fence runs, long raw-HTML
  lines, comments read as GFM reads them (a literal `<!--` no longer hides
  the rest), exports and printing a piece at a time and their memory bounded,
  Find on the page's text; a crash of the editor's preview fixed; the
  settings file changes only by the user's choice.
- **Shared playlist with axross-amp:** both programs' edits merge three
  ways - order and duplicates included -, a track missing at the start (an
  unmounted drive) is kept and shown as missing, not dropped for good.

### Compatibility

- **MCP:** `--mcp-tools all` no longer includes `adb` (`all,adb` is every
  group). Merged and renamed tools and parameters keep answering under their
  former names, with the results they always gave.
- **axross-amp:** the shared playlist file keeps tracks that are missing at
  the start; axross-amp 0.16.0 and later merge it the same way.

### Tested

- The full suite on the release state, with the tests that fail only by
  elapsed time under the machine's load rerun alone.
- The Android tools against a fake adbd and a fake Android userland (no real
  phone yet), with fuzzing of every tool; the Device window offscreen, with a
  heartbeat check that it stays responsive behind a slow phone.
- The MCP definitions graded blind against Glama's TDQS method (about 4.5 of
  5; 53 tools under `--mcp-tools all`).
