# Changelog

What changed in each release of axross-headless-mcp. The code is axross's MCP
server (https://github.com/c0decave/axross), written out by axross's
`scripts/export_standalone.py mcp`; its version is axross's.

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
