# Axross — Attack Surface

Living inventory of every component that accepts untrusted input or
crosses a trust boundary. Each entry lists:

- **Entry point** — file:function, CLI command, or network route.
- **Untrusted input** — where attacker-controlled data enters.
- **Trust boundary** — which boundary the input crosses.
- **Defenses in place** — current validation / mitigation / checks.
- **Known gaps** — what is not yet hardened (so the next reviewer
  knows where to attack).

The list is intentionally short — only entries where a
hostile/malformed input could change program state or leak data. UI
cosmetics that consume only validated values are out of scope.

This document is the input for `devils-advocate-pass-1` and related
peer-review prompts. Keep entries tight; expand when a new untrusted
ingress is added.

## MCP Server, stdio transport (`--mcp-server`)

**Entry point / command.** `main.py` `main()` dispatches to
`core.mcp_server` when `--mcp-server` or `AXROSS_MCP=1` is set. The
process speaks JSON-RPC line-framed over stdin/stdout to an LLM
client. Tool handlers are closures built by `_build_tools` in
`core/mcp_server.py` (run by `_dispatch` or, for `tasks/start`,
`_run_task`, each with a `_ToolContext`); the capability groups of
`--mcp-tools` add the handlers of `core/mcp_groups.py`. All receive
arguments parsed from caller JSON.

**Untrusted input.** Tool call arguments (paths, glob patterns,
hostnames, ports, raw bytes for `write_file`). Although the *client*
is an LLM driven by a human operator, the **tool arguments are
treated as untrusted** because LLM output is not source-of-truth and
prompt-injected docs/web can steer them.

**Trust boundary.** Host machine ↔ LLM agent. The CLI serves one
`LocalFS` backend, plus — with `--mcp-tools remote` — saved connection
profiles the client opens with `remote_open` (backend
`profile:<name>`). The MCP root is `--mcp-root` when given and
defaults to `backend.home()` otherwise; write tools, script execution
and each capability group are opt-in (`--mcp-write`,
`--mcp-allow-scripts`, `--mcp-tools GROUP`), and a group's mutating
tools additionally need `--mcp-write`. The root confines the file
tools and every local path of the group tools — the script tools are
not root-confined at all (`script_run` executes arbitrary Python as
the server's user), and paths on an opened remote profile are not
either (the profile's server account is the boundary there).

**Defenses in place.** Per-tool argument schemas; path
normalisation against MCP root (except the `symlink` target, which is
deliberately not root-checked; reads resolve links through
`_enforce_root` before following them); per-scope task registry with
`MAX_TASKS_PER_SCOPE` (retention cap) and `MAX_RUNNING_TASKS_PER_SCOPE`
(concurrency cap); `tasks/start` draws from the same rate limiter
(`_RateLimiter`) and runs under the same per-tool timeout as
`tools/call`; output size cap (`_read_capped_stream`); write tools
default OFF and, when enabled, require an explicit `--mcp-root` (the
default root is `$HOME`); script tools require explicit
`--mcp-allow-scripts` AND a non-paranoid `security_mode`, and are
refused together with `--mcp-http`; `script_run` runs the script in a
child process (`core.script_runner.run_bounded`: stdin on /dev/null,
its own process group killed when the run ends, a wall-clock
`timeout_s`, stdout/stderr capped, `AXROSS_NONINTERACTIVE=1` so
confirmations and the production tarpit fail closed); write and script tools log
attempt/ok/refused on `core.mcp_server.audit`; every stdout writer
(loop, task threads, log forwarder) shares one lock. Capability
groups (`core/mcp_groups.py`): unknown group names exit 2; group
schemas refuse unknown arguments; pack / extract / decrypt / encrypt
/ metadata export and cleaned copies only create fresh names under
the root (never overwrite); dedupe re-checks every copy and trashes
into `<root>/.axross-trash`; passphrases and the 7z password are
never in results, errors or audit lines; `remote_profiles` uses a
field allow-list (no secrets); `remote_open` takes passwords only
from the keyring of a profile that stores them, never prompts
(refuses unknown SSH host keys and browser sign-ins — Dropbox's
sign-in reads stdin, which on stdio is the protocol stream), refuses
paranoid-mode legacy protocols and profiles that resolve to the local
file system, keeps opened profiles per HTTP session (at most 8,
released when the session ends) and refuses every mutation on a
production-flagged profile.

**Known gaps to attack.** TOCTOU on path normalisation after
symlink follow; argument-coercion edge cases (path with NUL,
windows-style drive letters under Linux MCP root); cancellation
races during long-running tasks; a synchronous `tools/call` on stdio
cannot be cancelled by `notifications/cancelled` (single-threaded
loop) — only its timeout stops it, and a hard-stopped worker keeps
running in the background; verify that `script_run`
truly cannot escape via `os.system` / `ctypes` even when allowed
(it is not sandboxed: with `--mcp-allow-scripts` the client has the
server user's full rights); a process a script starts with `setsid`
leaves the group and outlives the run; no RLIMIT bounds memory or
disk use of a run. Group-specific: hostile archives and
media files reach the existing parsers (`core.archive`,
`core.metadata_formats`, ffprobe) under client control; a saved
profile is a capability grant the client can exercise with every
tool (`--mcp-root` does not apply to it); `duplicates_scan` and
`index_build` write axross' own index databases, so an LLM can grow
them (walks are capped at `MAX_WALK_ENTRIES`); the TOCTOU window
between the root check and the write also exists for the
fresh-name placement of group outputs on remote backends
(existence check, then upload).

## MCP Server, HTTP / SSE transport (`--mcp-http HOST:PORT`)

**Entry point / route.** `core/mcp_http.py` `_McpHTTPHandler`
serves `POST|GET|DELETE /messages` and `GET /health`. Non-loopback hosts
require `--mcp-cert / --mcp-key / --mcp-ca`, enabling mTLS;
loopback bind is allowed plain, behind a bearer token.

**Untrusted input.** HTTP request body (JSON-RPC), URL path, query
string, headers (`Host`, `Origin`, `Mcp-Session-Id`, `Authorization`),
client certificate (under mTLS). All values reach the same tool
dispatcher used by stdio.

**Trust boundary.** Network ↔ host. mTLS pins the trust boundary
at the CA bundle; without TLS, loopback-only by policy and every
request but `GET /health` needs the bearer token (`hmac.compare_digest`,
401 otherwise) - loopback alone is reachable by every local user.

**Defenses in place.** `--mcp-http` host check refuses
non-loopback without TLS; `_make_ssl_context` enforces
`CERT_REQUIRED` and the supplied CA, with the handshake done in the
connection thread under a socket timeout; plain loopback servers
refuse any non-loopback `Host` and any foreign `Origin` (DNS
rebinding); `_PerIPRateLimiter` caps request rate per source IP;
`_SessionRegistry` evicts idle sessions on create and caps live
sessions (`MAX_SESSIONS`); partial TLS flags are an error;
`HTTPServerConfig` validates port (1..65535) before bind.

**Known gaps to attack.** Reverse-proxy deployments where
`X-Forwarded-For` is unspoofable only if proxy strips client
headers; SSE long-poll keepalive may leak side-channel timing;
under mTLS the session id is bound to the SHA-256 of the peer
certificate; on plain loopback sessions are unbound to a client, the
bearer token (shown on stderr, 0600 file) and the Host/Origin check
guard them. `logging/setLevel` acts on the
one server-wide log forwarder, so any session can change the
forwarded log level for every session (routing stays per session).
The script tools are never served over HTTP; `--mcp-allow-scripts`
with `--mcp-http` is refused at startup.

## Headless script runner (`--script <file|->`)

**Entry point / command.** `main.py` `main()` branches into the
script runner when `--script` is supplied; the named Python file
(or stdin if `-`) is executed against the curated `axross.*`
surface defined in `core/scripting.py`.

**Untrusted input.** The script source itself (if the operator was
tricked into running a downloaded script), and any URLs / paths /
hostnames the script subsequently passes to `axross.open(...)`,
`axross.open_url(...)`, `copy(...)`, `archive.extract(...)`.

**Trust boundary.** Operator-typed CLI ↔ script body. Once the
script runs it has the full Python interpreter and can `import`
anything the host environment exposes.

**Defenses in place.** Paranoid security mode blocks `--script`
entirely (`core/security_mode.py`); password prompts go through
`_transient_proxy_password` so the secret is not retained;
`mutation_gate` guards destructive ops; `axross.copy/move/remove`
honour `dry_run=True`; archive extraction uses
`destructive_preview` and zip-slip protection in
`core/archive.py`.

**Known gaps to attack.** Script can still call standard library
directly (no sandbox); environment-variable inheritance (the script
sees `HOME`, `PATH`, `LD_PRELOAD`, etc.); credential leakage if a
script logs a backend's repr that includes a session token.

## Embedded Python REPL (GUI Console dock)

**Entry point / command.** `ui/repl_widget.py` exposes an
interactive Python evaluator that runs in the GUI process. The
operator types code that is compiled with `<repl>` as the filename
and exec'd against the same `axross.*` surface.

**Untrusted input.** The typed code. Realistic threat: a
copy-pasted "helpful snippet" from a web page or LLM output that
silently exfiltrates credentials or sets up a backdoor.

**Trust boundary.** Human operator ↔ REPL process. The REPL has
full access to the GUI's loaded backends, including any session
that holds plaintext passwords in memory.

**Defenses in place.** Tab-completion is side-effect-free (no
property getters fired) so the user cannot accidentally exfiltrate
data by hovering; excepthook routes REPL exceptions inline
(`<repl>` filename short-circuits the modal dialog); persistent
history is stored with mode 0600 under
`~/.local/state/axross/` so other users cannot read past
commands.

**Known gaps to attack.** No syntactic / API-level filter on what
operators paste; clipboard-paste of `import os; os.system("rm
-rf …")` is fully effective; persistent history could itself be
read by a privilege-escalated attacker on the host.

## Protocol backend response parsing (SSH/SFTP, FTP, SMB, IMAP, NNTP, …)

**Entry point / command.** Every protocol client in `core/*_client.py`
parses bytes received from the remote endpoint. Notable concentrators:
`core/ftp_client.py` LIST/MLSD parsers, `core/smb_client.py`
directory-entry decoders, `core/nntp_client.py` (own wire
implementation), `core/telnet_cisco.py` virtual-file synthesis,
`core/imap_client.py` FETCH-response parsing.

**Untrusted input.** Server-controlled bytes: directory listings,
headers, file content, error messages. A malicious server
fully controls these.

**Trust boundary.** Remote server ↔ Axross process. The remote is
*not* in the user's trust domain — Axross often connects to
target servers in a red-team / audit context where the server is
adversarial.

**Defenses in place.** `core/atomic_io.py` / `adaptive_io.py`
enforce cap-on-read for streamed bytes; `archive.py` rejects
absolute paths and `..` traversal during extract; the SSH banner
override (`apply_paramiko_banner_override`) avoids leaking host
fingerprint to passive scanners; `core/conn_health.py` rate-limits
reconnects so a flaky/hostile server cannot trigger a thundering
herd.

**Known gaps to attack.** Decoder fuzzing coverage is uneven across
protocols; verify FTP MLSD parser against `\r\n` smuggling; verify
SMB directory parser against integer-overflow-in-name-length;
NNTP wire-lib parser is new and worth a round of property tests.

## Local file-path operations (`copy / move / remove / archive`)

**Entry point / command.** `core/scripting.py` `copy()`, `move()`,
`remove()`, `archive.py` extract/create. Paths arrive from
`--script`, REPL, GUI file panes, or MCP tool calls.

**Untrusted input.** Source path, destination path, archive
member names, glob patterns. Untrusted especially when the path
comes from a remote backend (e.g. unzipping a hostile archive,
syncing from a malicious S3 bucket).

**Trust boundary.** Operator-provided string ↔ filesystem state.
Once the path resolves, mutating ops cross a destructive boundary.

**Defenses in place.** `_refuse_existing_target_unless_overwrite`
blocks accidental clobber; `_mutation_gate` issues a confirm step
on destructive ops in the GUI; `destructive_preview.py` shows the
exact set of paths a mutating op will touch before commit;
`trash()` provides a soft-delete path; `archive.py` rejects
absolute and `..`-traversing member names; checksums via
`hash_file()` allow post-hoc integrity check.

**Known gaps to attack.** Symlink-after-stat (TOCTOU) on
`copy()`; race between `_path_exists` check and the actual
`write_bytes` call; archive members with mixed `/` and `\\`
separators on Windows; cross-protocol relay paths where the
source backend lies about file size and the destination
buffer overflows the cap.
