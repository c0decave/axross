# Changelog

What changed in each release of axross-headless-mcp. The code is axross's MCP
server (https://github.com/c0decave/axross), written out by axross's
`scripts/export_standalone.py mcp`; its version is axross's.

## 0.15.185 - 2026-11-23

The MCP server's part of axross 0.15.185: the file tools on an ADB profile
(`list_directory`, `get_path_info`, `walk_tree`, `search_index`) read
folders with entries the phone will not show whole again. Such an entry is listed with its name and type,
and names come escaped, so two lines of `ls` never make one name.

## 0.15.184 - 2026-11-22

The MCP server's part of axross 0.15.184: Android devices as a tool group,
fewer and fuller tools.

- **A new tool group `adb`: Android devices** opened as ADB profiles
  (`--mcp-tools remote,adb`; every tool names its backend,
  `backend='profile:phone'`). Reading: `get_device_info` (model, Android
  version, SDK, security patch, serial, IMEI / MEID where the phone gives
  it to the shell - else null with the reason), `list_device_properties`,
  `get_battery_status`, `list_apps`, `get_app_info` (versions, permissions),
  `list_running_apps`, `get_logcat`, `take_screenshot` (an image; with
  `out` a PNG in the root) and `list_sms`. With `--mcp-write`:
  `start_app`, `stop_app`, `install_app` (an APK from the MCP root),
  `uninstall_app`, `export_app` (an app's APKs into the root),
  `grant_permission`, `revoke_permission`, `reboot_device`, `write_sms`
  (read back: Android drops the shell's write unless WRITE_SMS is
  allowed), `compose_sms` (prepares, never sends) and `send_at_command` (one
  AT command, root only). Commands are argument lists, each argument
  quoted; inputs are checked against narrow patterns, answers cleaned and
  bounded, every call has a deadline; the tools that change the device are
  refused on production profiles and in the paranoid mode, and audited
  without message texts.
- **Compatibility: `--mcp-tools all` no longer includes `adb`.** `all` is
  every general group (metadata, duplicates, archive, crypto, index,
  filetype, transfer, remote, exec, agent, extensions); a device group comes
  only by name: `--mcp-tools all,adb` is every group, `remote,adb` a phone.
  A server started with `all` serves 54 tools instead of 74.
- **What the tools could not do before:** `list_trash` and
  `restore_from_trash` (the trash `trash_duplicates` fills; only entries from
  inside the MCP root, back to a free place in it, a tampered record
  refused); `write_file` with `write_mode` `create` (never replaces),
  `append` and `at_offset` (`offset`; both rewrite a file of at most 64 MiB
  through a temp file); `restore_file_version` (an older version made
  current again on S3, Dropbox, Drive, OneDrive, Azure, WebDAV, Git);
  `list_llm_profiles` (names and models only, never a key or an endpoint);
  `offset` / `next_offset` to page on in `walk_tree`, `search_content` and
  `list_duplicate_scans` (`max_scans`); `search_index` and
  `list_duplicate_groups` name their `next_offset` too. `walk_tree` and
  `search_content` take each folder's entries by name now, so pages are
  stable; `list_file_versions` lists newest first. `write_file` is no longer
  marked idempotent (an append adds again).
- **Merged, same safety class:** `create_symlink` and `create_hardlink` are
  `create_link` (`kind`: symbolic or hard); `run_backend_script` is
  `run_backend_command` with `script`. The former names still answer, as
  does `run_llm_agent`'s former `profile` (now `llm_profile`), with the
  results they always gave (`create_link`: `{ok: true}`, plus `target` when
  another one was stored); other results only gained fields (`write_file`'s
  `file_size`, the pages' `offset` / `next_offset`). `send_sms`, never
  released, is `compose_sms`. 74 tools in 15 groups.

## 0.15.183 - 2026-11-21

The MCP server's part of axross 0.15.183: consistent tool and parameter
names, the former ones still working, and faster, verified copies.

- **52 tools, named verb, then resource** (`list_directory`, `get_path_info`,
  `search_content`, `walk_tree`, `delete_path`, `copy_path_to_backend`,
  `open_remote_profile`, `run_backend_command` ...). Merged:
  `metadata_export_file` into `export_metadata` (`out`, with `--mcp-write`),
  `exec_backends` into `list_backends` (`can_run_commands`, `commands`),
  `extensions_info` into `list_extensions` (`name`); the group `packer` into
  `archive`. The former names still work in `tools/call` and
  `--mcp-tools packer` still works; `tools/list` shows the new names only.
- **`search_index`** returns `{entries, indexed, truncated}` as text too.
- **One parameter name per meaning:** `max_depth` counts from 1 everywhere,
  `subfolder_levels` (from 0) in `scan_file_types` and `copy_path_to_backend`;
  `search_index` takes `pattern` and `max_results`, `run_script` `timeout`,
  `create_archive` `path`. The former names still work.
- **`copy_path_to_backend`** copies local links to files as files, like
  `copy_tree`; the instructions come in sections and say how errors answer.
- **`read_file_version`** takes `offset` and `encoding` like `read_file`;
  `scan_file_types` lists refused secret files in `unreadable`;
  `list_backends` marks lent connections. The shared write rules are said
  once in the instructions; the descriptions say how refused files and
  failed copies show up.

## 0.15.182 - 2026-11-20

The MCP server's part of axross 0.15.182: tool definitions an agent can use
without guessing.

- **Every tool** opens with a summary, then *Use when*, *Instead* (the
  sibling tool), *Requires* (the flags), *Behavior* and *Returns*; the
  shared rules (paths, backends, `_b64` twins, secret files, write guards,
  paranoid mode, `max_depth`, `truncated`/`complete`) are in the
  `initialize` instructions once.
- **Schemas:** titles and truthful annotations, defaults, ranges and enums,
  `additionalProperties: false`, an `outputSchema` on 54 of 55 tools
  (`structuredContent` from MCP 2025-06-18).
- **New:** `stat` returns `mode`; `grep` takes `include`; `search` takes
  `offset` and `path`; `is_link` in listings; ISO 8601 times everywhere;
  archive passwords.
- **Fixed:** `grep` without a path searches the MCP root; `max_depth=0`;
  `file_type`'s deadline; `remote_exec`/`remote_script` need `backend`;
  `preview` refuses an out-of-range edge; the drift check's doubled path.
  The tool names are unchanged.

## 0.15.181 - 2026-11-20

The MCP server's part of axross 0.15.181: tool definitions a client can
judge, and this repository written only by axross's export.

- **Every parameter of every tool is described**, with its defaults and
  limits (54 parameters of 23 tools had none). `list_dir`, `stat`,
  `search`, `mkdir`, `remove`, `rename`, `copy`, `symlink`, `hardlink`,
  `script_delete` and `remote_close` say what they return and when to use
  them; `remove` says it is permanent, `rename` and `copy` that an existing
  destination is never replaced; `search` names the index it reads
  (`index_build`) and points at `walk` and `list_dir` for the live state.
  The tool names are unchanged.
- **Instructions on `initialize`** (MCP 2025-03-26 and later): facts about
  the tools - backends, the root, secrets, which tool lists, reads and
  searches what, when a result is truncated, the flags.
- **A logo:** `serverInfo.icons` (MCP 2025-11-25 and later) and the
  registry entry name `docs/assets/logo.png` by HTTPS URL; older protocol
  revisions get `serverInfo` as before.
- **A `Dockerfile`** at the repository's root, for directories that build
  a server from its repository: it installs this repository's package, runs
  it as an unprivileged user, read-only and confined to `/data` by default.
- **This repository is axross's export and nothing else:** each commit
  carries `Exported-From: c0decave/axross@<ref>` and the release tag is the
  PyPI package's source; `drift.yml` exports again from that ref on every
  push, every tag and weekly and fails on any difference.

## 0.15.180 - 2026-11-20

The MCP server's part of axross 0.15.180: three more review rounds of
every area, security with the agent and the MCP server among them.

- **Caps on the big tools:** `walk` takes at most 100 000 entries,
  `recursive_checksum` 50 000 files and `bulk_copy` 100 000 files, each at
  most 64 levels deep - a call above a cap is refused (the schemas say
  `maximum`); a `max_entries` of a billion kept a whole disk's listing in
  memory. `search` reads at most 200 000 index rows, returns at most
  `limit` results (default 1000, at most 10 000) and stops on
  `notifications/cancelled`.
- **Secret folders are not moved whole:** renaming `.kube` (or `.aws`,
  `.docker`, and on a remote `.ssh` and `.gnupg`) took away the name that
  made its files secret, and `read_file` then handed them out. Such
  folders are refused for rename and whole copies; backup copies
  (`credentials.bak`, `config~`) are secret like the files.
- **Secrets on a remote are found by content:** `grep` checks every remote
  file it reads for keys, and a remote `read_file` window is checked like a
  local one; `/proc/*/environ`, shell histories, `rclone.conf` and
  `/etc/ssl/private/*` are secret by name on a remote too.
- **Link targets:** `symlink` makes a target with `..` as the place it
  checked, so re-pointing a link inside the root later cannot lead it out.
- **axross's own code is protected:** run from a source folder inside
  `--mcp-root`, the write tools could rewrite axross's modules and the next
  start ran them; its packages, resources, scripts, a one-file binary and
  a venv's settings and programs are protected places, and no Python code
  is written anywhere below the source folder.
- **Host-run MCP servers' folders are pinned and protected whole**
  (sub-packages, `node_modules`, linked folders), and more programs count
  as runners (`nlx`, the Maven and Gradle wrappers, `pip3.11-wrapper`).
- **HTTP (round 9):** one client's parallel calls no longer make its
  address the busy one; a slow TLS handshake is no longer closed as the
  plain oldest connection; `GET /health` no longer protects its
  connection from being pushed out.
- **Archives:** the `archive` tool's ZIP ratio guard applies from 64 MiB
  per member; member names with control or direction characters are
  refused; ZIP names without the UTF-8 flag are read in their own
  encoding.
- **Backends:** STARTTLS before the login for IMAP, POP3 and LDAP profiles
  on the plain ports (a saved profile too; untick it in axross only for a
  server without TLS); rsync behind a proxy refuses a host with shell
  syntax; WinRM never deletes or copies through a junction; WebDAV
  redirects never turn a write into a success elsewhere; the Git cache
  keeps no token; and the protocol fixes of axross's review rounds.
- **Logs:** control characters, escape sequences and bidi marks are
  escaped in the audit log; remote names with CR, LF or C1 characters are
  refused.

## 0.15.179 - 2026-11-19

The first public release.

- **axross's MCP server without Qt:** file tools for any MCP client on the
  local disk and, through axross's saved connection profiles, on SFTP, SMB,
  WebDAV, S3, Azure, cloud drives, FTP, NFS and more - over stdio or HTTP
  (bearer token, mTLS).
- **Safe by default:** read-only unless `--mcp-write`, every path confined to
  `--mcp-root`, private keys and tokens refused unless
  `--mcp-allow-secret-reads`; scripts and remote commands are separate
  opt-ins.
- **MCP 2025-11-25, 2025-06-18 and 2024-11-05:** tool annotations, structured
  results with output schemas, progress, cancellation, logging, `axross://`
  resources, background tasks.
- **Hardened** in nine rounds of an adversarial review: bounded answers and
  listings, whole-or-nothing outputs, fair admission of HTTP connections,
  per-backend write locks, secrets found in every encoding.
- **Also as** the container image `ghcr.io/c0decave/axross-headless-mcp` and the
  entry `io.github.c0decave/axross-headless-mcp` in the official MCP Registry
  (both published from axross's release workflow).

Known limitation: over HTTP, from the client's own address (or its IPv6 /64),
connections that trickle a byte every few milliseconds look more alive than a
slow TLS handshake and can push it out of a full server.
