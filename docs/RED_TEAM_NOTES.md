# Red-team / devil's-advocate notes

Living document of the adversarial review of the new backends and
features added in the WebDAV / Gopher / TFTP-find / NNTP / DB-FS /
Git / PJL / SLP / REPL session. Each finding lists status,
mitigation, and (if not yet shipped) what's required to close it.

The pattern follows the earlier security-review style in this repo:
treat any byte that crossed a process / network boundary as
attacker-controlled until proven otherwise; treat any user-supplied
config (profile.json, URL, path) as attacker-controlled when the
attacker can influence the user.

---

## Fixed in this session

### F1 — `core/sqlite_fs_client.py`, `core/postgres_fs_client.py`: LIKE-wildcard widening on subtree delete

**Threat model.** A profile holding a SQLite/PG-FS backend with a
hostile (or accidentally crafted) path containing `%` or `_` could
have widened a recursive delete past the intended subtree. Example:
`remove("/fo%", recursive=True)` would have built `LIKE '/fo%/%'`
and matched both `/foo/...` and `/fobar/...`.

**Status.** Fixed. Both adapters now LIKE-escape `%`, `_`, and `\`
and use `ESCAPE '\'`. Path comparison stays exact for the root row.

**Code.** [core/sqlite_fs_client.py:147-160](core/sqlite_fs_client.py#L147-L160), [core/postgres_fs_client.py:158-173](core/postgres_fs_client.py#L158-L173).

### F2 — `core/pjl_client.py`: NAME-quote escape via volume specifier

**Threat model.** PJL FS commands are framed as `@PJL FSDIRLIST
NAME="<volume><path>"`. The volume comes from the profile and was
not validated. A profile setting `volume='0:" SOMETHING "'` could
have broken out of the NAME quoting and injected a second PJL
command. Filenames were already validated; volumes were not.

**Status.** Fixed. `_VOLUME_RE = ^[0-9A-Za-z]:?$` enforced in
`__init__`; mismatched volumes raise `OSError` at construction.

**Code.** [core/pjl_client.py:188-198](core/pjl_client.py#L188-L198).

### F3 — `core/webdav_client.py`: missing PROPFIND-response size cap

**Threat model.** A hostile WebDAV server (or a misconfigured one
with a 100 000-entry directory) could have streamed an unbounded
multi-status XML body that the client buffered into `.content`,
OOMing the UI. The defusedxml parser already blocks XXE / billion-
laughs; the *size* of a syntactically valid response was not
limited.

**Status.** Fixed. PROPFIND responses are now streamed with a hard
cap of `MAX_PROPFIND_BYTES = 64 MiB`; exceeding it raises a
`WebDavRequestError` (status 507 sentinel) before the parser sees
the bytes.

**Code.** [core/webdav_client.py:184-211](core/webdav_client.py#L184-L211).

---

## Known acceptable risks (documented, not patched)

### A1 — REPL has full Python access by design

**Observation.** `ui/repl_widget.py` runs user input through
`code.InteractiveConsole`. There is no sandbox; `import os;
os.system(...)` works. Tab-completion exposes the live globals
namespace.

**Why acceptable.** The REPL is a power-user tool on the user's
own machine — same trust model as `python` at a shell prompt.
Adding a sandbox would be security theatre (the user can already
spawn `python` themselves) and would block legitimate scripting.
Documented prominently in the cheat-sheet.

### A2 — Git-FS does not model symlinks in committed trees

**Observation.** A git repo can contain a `mode 0o120000` (symlink)
entry; our reader treats it as a regular blob and returns the link
target string as file content.

**Why acceptable for v1.** Reading a symlink-blob's bytes is the
canonical git behaviour anyway (`git show <sha>` prints the target
string). We never follow the link via the LocalFS, so there is no
arbitrary-read risk. A future enhancement can surface symlinks via
`readlink()` once the FileBackend protocol grows a `mode` argument
to `stat`.

**Code.** [core/git_fs_client.py:233-262](core/git_fs_client.py#L233-L262).

### A3 — TFTP `_probe_size` writes to a host tempfile

**Observation.** `find_files()` invokes `_probe_size`, which uses
`tftpy.download` to write the candidate file into a
`NamedTemporaryFile`. A hostile / runaway TFTP server could fill
the tempfile up to TFTP's protocol limit (~32 MiB classic, more
with `blksize`), per probe.

**Why acceptable.** The TFTP backend's `MAX_BYTES` cap and tftpy's
own retry budget bound a single probe. Wordlist length is bounded
(default 161 entries; user can hand a longer list but knowingly).
Worst case: a sequential walk of 200 hits at 32 MiB = 6 GiB
written-then-deleted via tempfile lifecycle. Documented in
[docs/USAGE.md](docs/USAGE.md). Future improvement: replace tftpy
with our own minimal TFTP impl that enforces the cap at the wire
layer (already on the roadmap as part of the third-party-libs
audit).

### A4 — SLP backend trusts the daemon to return a small response

**Observation.** `query_udp` reads up to `MAX_RESPONSE_BYTES =
256 KiB` per recvfrom. A hostile daemon could return exactly that
much per request. Multiplied across many service types, a single
list_dir() against a malicious server could allocate megabytes.

**Why acceptable.** Per-host opt-in only (no multicast — that path
is hard-refused at the socket layer). 256 KiB × the number of
service types the user clicks into is bounded by user behaviour,
not protocol. CVE-2023-29552 amplification is structurally
impossible because `slp_lib` does not implement SrvReg (regression
test [test_packet_builders_never_emit_srvreg](tests/test_backend_regressions.py)
greps the source to enforce this).

### A5 — Gopher display-name → selector mapping is best-effort

**Observation.** A malicious server could send a directory listing
where two entries have different selectors but identical display
names. The user clicks "report.txt" and gets whichever selector our
parent-dir cache stored last.

**Why acceptable.** Gopher servers are user-chosen and unicast; the
worst-case is "user reads the wrong file" not "code execution".
Documented under [docs/USAGE.md](docs/USAGE.md) — if disambiguation
matters, the user can read the .gophermap directly.

---

---

## Round 2 — devil's-advocate sub-agent review (this session)

A second-pair-of-eyes pass after F1–F3 caught additional issues. The
findings below are now fixed; the agent's "no-fix-needed" notes are
folded into the open-follow-ups list further down.

### F4 — `core/db_fs_base.py`: `copy()` allowed orphan rows

**Threat.** `mkdir` validated parent existence; `copy()` did not. A
caller passing `copy("/a", "/nope/b")` would insert a row whose
parent `/nope` had no directory entry — invisible to every `list_dir`,
discoverable only by reading the row directly. Quiet correctness bug.

**Status.** Fixed. `copy()` now mirrors `mkdir`'s parent-existence
guard. [core/db_fs_base.py:280-289](core/db_fs_base.py#L280-L289).

### F5 — `core/git_fs_client.py`: empty-tree object pollution

**Threat.** `_modify_tree_rec` unconditionally `add_object`-ed every
recursive subtree result, including the empty trees produced when a
delete emptied a directory. Git GC reaps them eventually, but every
delete left loose objects.

**Status.** Fixed. Empty subtrees are no longer persisted. [core/git_fs_client.py:597-603](core/git_fs_client.py#L597-L603).

### F6 — `core/git_fs_client.py`: `_is_ancestor` walk was unbounded

**Threat.** On long-lived branches (10⁵+ commits), the BFS in
`_is_ancestor` allocated a `seen` set proportional to history depth
on every commit. Real-world repos can hit hundreds of MiB of just
SHA bytes for a single fast-forward check.

**Status.** Fixed. Walk capped at `_ANCESTOR_WALK_CAP = 50_000`;
overflow is treated as "cannot prove ancestry" → fail-closed (refuse
the commit). [core/git_fs_client.py:619-650](core/git_fs_client.py#L619-L650).

### F7 — `core/nntp_lib.py`: `authinfo` left auth in indeterminate state on CR/LF

**Threat.** `_send_line` rejects CR/LF, but `authinfo()` would send
USER first, then raise `NntpError` on a tainted password — leaving the
connection authenticated as the username field but never having sent
PASS. Server state diverged from client state.

**Status.** Fixed. `authinfo()` now validates BOTH username and
password upfront, before sending any AUTHINFO command. [core/nntp_lib.py:233-248](core/nntp_lib.py#L233-L248).

### F8 — `core/nntp_lib.py`: `parse_overview_date(None)` raised

**Threat.** Different Python versions raise different exception types
on malformed Date headers; some return `None` instead of raising.
Empty/None inputs would crash inside `parsedate_to_datetime`.

**Status.** Fixed. Empty input short-circuits to epoch; the `try`
catches `TypeError`, `ValueError`, `AttributeError`, `IndexError`;
explicit `None` check after the call. [core/nntp_lib.py:430-446](core/nntp_lib.py#L430-L446).

### F9 — `core/pjl_client.py`: `:` in path could re-target volume

**Threat.** `_PATH_RE` allowed `:`, but PJL paths get prepended with
`<volume>:` — so a path like `/foo:/etc` could be parsed by some PJL
stacks as "volume `0:/foo`, path `/etc`", redirecting the operation.

**Status.** Fixed. `:` removed from the path allow-list; the volume
specifier supplies its own colon. [core/pjl_client.py:62-68](core/pjl_client.py#L62-L68).

### F10 — `core/pjl_client.py`: `rstrip(UEL)` corrupted binaries

**Threat.** `bytes.rstrip(UEL)` treats UEL as a *set of byte values*,
not a literal terminator. Any file ending in any byte from
`{0x1B, 0x25, 0x2D, 0x31..0x35, 0x58}` would have those bytes
silently truncated.

**Status.** Fixed. Use `bytes.removesuffix(UEL)` instead — matches
the literal frame terminator exactly, only once. [core/pjl_client.py:391-401](core/pjl_client.py#L391-L401).

### F11 — `core/slp_lib.py`: `parse_srv_reply` misaligned on auth blocks

**Threat.** We sent `num_url_auths=0`, but a hostile SLP daemon could
return a SrvRply with auths set anyway. We skipped a fixed 1 byte for
the auth count instead of walking each variable-length auth block,
scrambling the parse of every subsequent URL record. Garbage URLs
then get exposed to the user via `_safe_name`.

**Status.** Fixed. New `_skip_url_auths` walks each block correctly;
parser short-circuits on malformed auth blocks. [core/slp_lib.py:154-181](core/slp_lib.py#L154-L181), [core/slp_lib.py:225-245](core/slp_lib.py#L225-L245).

### F12 — `core/slp_lib.py`: `_read_str` raised `struct.error` instead of `ValueError`

**Threat.** Callers caught `ValueError`; a malformed packet whose
length-field offset overran the buffer raised the wrong exception
type, propagating as an uncaught error rather than being treated as
"malformed reply".

**Status.** Fixed. `_read_u16` now bounds-checks before unpacking and
re-raises `struct.error` as `ValueError`. [core/slp_lib.py:139-152](core/slp_lib.py#L139-L152).

### F13 — `core/slp_lib.py`: UDP source-address spoofing

**Threat.** `recvfrom` returned the on-wire source address; we
discarded it. An off-path attacker who could guess our ephemeral src
port could race a spoofed reply (small UDP-RTT window, but real).

**Status.** Fixed. The destination is resolved upfront; replies from
sources other than the resolved IP+port are discarded and the recv
loop continues until either a matching datagram arrives or the
timeout elapses. [core/slp_lib.py:265-300](core/slp_lib.py#L265-L300).

### F14 — `core/webdav_client.py`: PROPFIND cap-exceeded leaked the response

**Threat.** When the body cap was exceeded, the streaming
`iter_content` loop raised `WebDavRequestError` mid-iteration without
closing the response. The connection-pool kept the half-read socket;
later requests on the same session could read stale body bytes or
block on the pool.

**Status.** Fixed. Wrapped the request in `with self._request(...)`
so every exit path returns the socket to the pool cleanly. [core/webdav_client.py:213-244](core/webdav_client.py#L213-L244).

### F15 — `core/webdav_client.py`: `info()` returned wrong entry on no-match

**Threat.** A misbehaving server returning only an unrelated child
entry for `Depth: 0` would silently return that child as if it were
the requested resource. Caller couldn't tell the difference.

**Status.** Fixed. No-match now raises `FileNotFoundError` with a
diagnostic. [core/webdav_client.py:336-344](core/webdav_client.py#L336-L344).

### F16 — `ui/repl_widget.py`: history file TOCTOU between create and chmod

**Threat.** `Path.write_text` created the file with the umask default
(typically 0o644), and we chmod-ed to 0o600 *afterwards*. Between
those syscalls, another local user could read freshly-written
commands — which can include passwords pasted into the REPL.

**Status.** Fixed. `os.open(..., 0o600)` is called BEFORE writing so
the file is never world-readable on disk. The post-write chmod stays
as belt-and-braces hardening for pre-existing files. [ui/repl_widget.py:230-256](ui/repl_widget.py#L230-L256).

### F17 — `core/gopher_client.py`: pathological path nesting

**Threat.** Each path level cost one TCP round-trip (selector lookup
via parent menu). A user pasting a 10 000-deep selector would trigger
10 000 round-trips and exceed Python's default recursion limit.

**Status.** Fixed. `MAX_PATH_DEPTH = 32` enforced in `_menu_for_path`;
deeper paths raise OSError up-front. [core/gopher_client.py:54-62](core/gopher_client.py#L54-L62), [core/gopher_client.py:323-330](core/gopher_client.py#L323-L330).

### F18 — `core/gopher_client.py`: unbounded directory cache

**Threat.** Every visited directory's listing was cached forever. A
long browsing session against a hostile server emitting unique
selectors per click filled RAM.

**Status.** Fixed. `DIR_CACHE_LIMIT = 256` LRU cap. [core/gopher_client.py:60-62](core/gopher_client.py#L60-L62), [core/gopher_client.py:347-355](core/gopher_client.py#L347-L355).

---

## Round 3 — open follow-ups, all closed in this session

The eleven O-items raised in rounds 1+2 are fixed below. Bug-hunting
patterns from these landings inform future sessions: when a backend
ships, lock the safety property in a regression test the same session;
prefer fail-loud over silent normalisation; per-op revalidation beats
single-shot probes against a network adversary.

### O1 — Git-FS force-push refusal regression test

Added `test_commit_refused_when_local_behind_origin` in
[tests/test_backend_regressions.py](tests/test_backend_regressions.py).
The test synthesises a divergent `refs/remotes/origin/main` whose
parent is the local tip, then asserts the next commit raises
`GitForceRefused` rather than silently rewriting history.

### O2 — REPL output ring-buffer cap

`CONSOLE_BUFFER_CAP_CHARS = 4 MiB` with a 2 MiB tail-keep on overflow
in [ui/repl_widget.py](ui/repl_widget.py#L43-L51). `_append()` now
calls `_maybe_trim_buffer()` after every write so a `for _ in
range(10**8): print('x')` paste truncates the head instead of locking
the Qt widget.

### O3 + O8 — DB-FS rename guards

`DbFsBackend.rename()` now refuses any `(src, dst)` where `dst == src`
or `dst.startswith(src + "/")` — the cyclic-move case that would have
re-traversed the just-inserted tree if any `_db_list` adapter ever went
non-snapshot. [core/db_fs_base.py:240-250](core/db_fs_base.py#L240-L250).

### O4 — NNTP POST disagreement warning

`_NntpPoster.close()` now inspects the body for an existing
`Newsgroups:` header and emits a `WARNING` when the path-target group
isn't in the listed groups. Posting still proceeds (the body header is
the wire authority), but the operator gets a heads-up. [core/nntp_client.py:339-371](core/nntp_client.py#L339-L371).

### O5 — PJL FSMKDIR post-check

`mkdir()` now follows the `FSMKDIR` send with a `stat()` and logs a
WARNING if the directory still doesn't exist — surfaces firmware that
silently ignores the command (Lexmark MarkVision et al.).
[core/pjl_client.py:419-440](core/pjl_client.py#L419-L440).

### O6 — PJL per-op safety revalidation

Every FS op now prepends `@PJL INFO STATUS` to its framed body and
calls `_per_op_revalidate()` on the response. A MITM-substituted
non-PJL device that passed the original probe is caught on the very
first op (the response can't pretend to be PJL without already being
a real PJL device). One extra command per op.
[core/pjl_client.py:217-232](core/pjl_client.py#L217-L232) +
all FS-op call sites.

### O7 — DB-FS strict-normalize

New `_strict_normalize_or_reject()` static helper in
[core/db_fs_base.py:127-147](core/db_fs_base.py#L127-L147). Wired into
`mkdir()` so calls like `mkdir("..")`, `mkdir("/foo/../..")`, and
`mkdir("/")` fail loudly instead of being silent root no-ops that
mask caller bugs. Read entry points keep the lenient `normalize()`
because users legitimately navigate via relative paths in the UI.

### O9 — REPL safe Tab-completion

`_RlCompleter` no longer wraps stdlib `rlcompleter.Completer`. We walk
each object's `__dict__` and class MRO directly — never via `getattr`
— so `@property` descriptors don't fire on Tab. This honours the
"Tab is a *passive* keypress" principle without giving up the
ergonomic `axross.<TAB>` flow. [ui/repl_widget.py:73-148](ui/repl_widget.py#L73-L148).

### O10 — REPL append-only history with periodic compaction

`_append_history()` opens with `O_APPEND | O_CREAT` (mode 0o600) per
submit — one write call instead of rewriting the entire 100 KiB file.
Every `COMPACT_EVERY_N = 200` submits we run `_compact_history_file()`
which atomically rewrites the file (write-tmp → `os.replace`) so the
on-disk size stays bounded at HISTORY_LIMIT entries between sessions.
[ui/repl_widget.py:251-302](ui/repl_widget.py#L251-L302).

### O11 — Gopher filename collision disambiguation

New `_disambiguate()` helper in [core/gopher_client.py:227-252](core/gopher_client.py#L227-L252)
suffixes duplicates with `-1`, `-2`, … (inserted before the extension).
`list_dir()` and `_entry_for_path()` both use the same map so an
exposed leaf name always resolves back to the same underlying menu
entry — no more "click `report.txt` and read whichever entry happened
to come first".

---

---

## Round 4 — REPL expansion + Cisco-Telnet + rsh + layout-presets

This batch covered: a much-bigger curated scripting surface
(`core/scripting.py`), a script directory with REPL slash-commands,
a Doc-Pane next to the REPL, layout presets with cycle hotkey,
the rsh / rcp backend, and a Cisco-IOS-style read-only Telnet view.

### F19 — `core/scripting.py:nntp_post()` allowed header-injection via subject / group

**Threat.** `nntp_post(group, subject, body)` formatted those values
into a `Subject:` / `Newsgroups:` / `From:` envelope with f-strings.
A tainted ``subject = "evil\r\n\r\n<body content>"`` would smuggle
header-block exit and arbitrary body content into the resulting POST.
Same general class as SMTP / HTTP header injection.

**Status.** Fixed. Each header value is rejected up-front when it
contains CR or LF; the call raises ``ValueError`` before any bytes
hit the wire. [core/scripting.py:nntp_post()](core/scripting.py).

### F20 — `core/rsh_client.py`: paths starting with `-` could re-attach as flags

**Threat.** `_validate_path` rejected CR/LF/NUL but a path beginning
with ``-`` (e.g. ``/-rf``) could be re-interpreted by the remote tool
as a flag once the rsh wrapper passed the command to ``/bin/sh``.
``head -c <cap> /-rf`` would surface as ``head -c <cap> -rf``.

**Status.** Fixed. ``_validate_path`` now refuses any leading ``-``
on the basename, *and* the read path uses an explicit ``--`` flag-
terminator before the path: ``head -c <cap> -- <path>``. Belt and
suspenders. [core/rsh_client.py:_validate_path](core/rsh_client.py).

### F21 — `core/telnet_cisco.py`: tainted username / password could smuggle IOS commands

**Threat.** A profile loaded with ``(password literal redacted — see SPEC.md §A9 for the CRLF-injection attack pattern)``
would send a second IOS command across the Telnet wire after the
intended password line, potentially flipping the device into config
mode without the user noticing.

**Status.** Fixed. ``_login()`` validates ``username``, ``password``,
and ``enable_password`` for CR/LF before any send and refuses to
proceed with a clear ``OSError``. [core/telnet_cisco.py:_login()](core/telnet_cisco.py).

### A6 — REPL slash commands have full namespace power, by design

`.run <name>` execs the saved script in the live InteractiveConsole
namespace — same trust model as A1. The slash dispatcher only
interprets a leading ``.`` as a slash command if it matches one of
the seven known verbs, so a literal float like ``.5`` still parses
as Python.

### A7 — Layout-preset DSL is constant data (no runtime injection)

The PRESETS dict ships with the codebase and is not user-editable
at runtime; there is no path that builds a preset from JSON / CLI /
profile data. Adding such a path later would require validating the
node kinds (current `LayoutPresetSpecTests` would catch typos in the
dict).

### A8 — rsh plaintext warning is informational only

Every RshSession init logs a single WARNING about plaintext credentials
+ commands traversing the wire. The backend never refuses to connect
on plaintext (rsh is plaintext-only by definition); the burden is on
the operator to choose this protocol consciously.

### Open follow-ups (Round 4)

- **O12** — Cisco-Telnet prompt regex collisions. A `show running-config`
  output line that *itself* ends in `\nROUTERNAME#` would early-terminate
  the read. Switch to a one-shot delimiter sentinel (e.g.
  ``terminal exec prompt timestamp; show ...; echo AXEND``) to make the
  end-of-output unambiguous.
- **O13** — REPL `.save` stores all history lines including any
  `.delete name` slash commands that touched a different script. Should
  also strip lines that match the `.{verb}` shape so the saved file is
  "the user's actual Python work" minus REPL meta.
- **O14** — rsh `_run_remote` swallows stdout when the remote returned
  bytes the user wants but the command exited non-zero. ``rm`` of a
  non-existent file is a useful no-op-when-missing pattern; a future
  enhancement could whitelist exit codes per command.

---

---

## Round 5 — REPL doc-pane + scripting expansion + terminal upgrade

This batch covered: full long-form `axross.docs()` reference, tabbed
doc-pane (API / Slash / Scripts / Protocol), 9 new internal-API
example scripts (atomic_replace, cas_dedupe, snapshot_walk,
profile_audit, encrypted_archive, encrypted_stream, bookmark_audit,
backend_capabilities, connection_probe, ramfs_pipeline), terminal
font-zoom + theme + +Local-button + Ctrl+Shift+F search-in-scrollback,
per-profile ``terminal_theme`` field.

Devil's-advocate sub-agent caught nine issues; all fixed here.

### F22 — `encrypted_archive.unpack`: off-by-one in zip-slip prefix check

**Threat.** The fence used `os.path.abspath(target).startswith(
os.path.abspath(dst_dir_local))`. For a destination of
`/tmp/foo`, a member absolute-path of `/tmp/foobar/escape.txt`
matched the prefix and would extract into the *sibling* dir.
Classic zip-slip via shared-prefix neighbour.

**Status.** Fixed. The unpack guard now uses
`os.path.commonpath` against `<dst>/` (with trailing separator)
so siblings can no longer share the prefix; on Windows we also
catch `ValueError` for cross-drive members. New regression test
`test_encrypted_archive_zip_slip_prefix_offbyone_refused`
constructs a tarball with `../foobar/escaped.txt` and asserts
the sibling stays empty. [resources/scripts/encrypted_archive.py:55-75](resources/scripts/encrypted_archive.py#L55-L75).

### F23 — `encrypted_archive.unpack`: tarfile-filter fallback was unfiltered

**Threat.** The script tried `tar.extract(..., filter="data")` and
fell back to `tar.extract(...)` on `TypeError`, intending to support
Python < 3.12. But on 3.12+ where the filter exists, hostile members
that the filter rejects raise `tarfile.LinkOutsideDestinationError`
(a different exception class) and propagated past the `except
TypeError`, leaving the user with a half-extracted archive.

**Status.** Fixed in concert with F22. The commonpath guard now
runs *before* the filter call, so even if a hostile member made it
through the filter (or the fallback fired on an old Python), the
extract destination is already proven to be inside the dst dir.
The fallback is now annotated as "pre-3.12 only" instead of
silently disarming the safety net.

### F24 — `axross.docs(name)` allowed arbitrary attribute access

**Threat.** `docs("logging")` happily returned the stdlib logging
module's docstring as if it were part of the axross API. Not a
secret but UX-confusing and a precedent for info-leak: a future
private helper imported into `core.scripting` would be reachable
via `docs("_my_secret")` until someone noticed.

**Status.** Fixed. Strict allow-list against `__all__` plus the
three known topical strings (`slash` / `scripts` / `backend`).
Anything else raises `KeyError` with a helpful "try one of …" hint.
[core/scripting.py](core/scripting.py).

### F25 — Doc-pane Markdown tabs were rendered once at construction

**Threat.** A user saves a script via the REPL's `.save foo`
slash-command, opens the Scripts tab — `foo` isn't there, requires
restart. UX papercut, but also stale-info trap when an admin edits
`~/.config/axross/scripts/` outside the GUI.

**Status.** Fixed. `_MarkdownTab` re-renders in `showEvent`. Cheap
(few ms per render) and keeps every flip-back fresh.
[ui/repl_widget.py](ui/repl_widget.py).

### F26 — Terminal search bar didn't follow widget resize

**Threat.** Open the search overlay, drag the dock wider, the bar
stays glued to the OLD right edge and floats in the middle of the
scrollback.

**Status.** Fixed. `TerminalEmulator` now overrides `resizeEvent`
and re-pins the bar via `_search_bar._reposition()` whenever the
parent resizes.

### F27 — `Profile.terminal_theme` was dead data

**Threat.** Saving a profile with `terminal_theme="Solarized-Dark"`
had no effect; the field was persisted but never read. Pure UX
regression — the feature LOOKED done but did nothing.

**Status.** Fixed. `TerminalPaneWidget.__init__` reads
`profile.terminal_theme` and passes it to `TerminalEmulator(theme=...)`.
Empty string falls back to the dock default; unknown theme names
clamp to "Dark" via the existing `_apply_theme` guard.
[ui/terminal_pane.py](ui/terminal_pane.py).

### F28 — `+ Local` button only added a combo entry, didn't start a session

**Threat.** Click "+ Local", expect a fresh shell tab. Get an
inactive entry that needs a separate Start-button click. Pure UX
papercut — the button name promised a behaviour it didn't deliver.

**Status.** Fixed. `_spawn_local_subshell` now calls
`_start_session()` after switching the combo, with a clean status-
label fallback if PTY allocation fails.
[ui/terminal_widget.py](ui/terminal_widget.py).

### F29 — Ctrl+F was stolen from the remote shell

**Threat.** Originally bound search-in-scrollback to Ctrl+F, which
vim/less/fzf/tmux all use. Pressing Ctrl+F inside vim launched our
search bar instead of vim's `^F` page-down.

**Status.** Fixed. Search-in-scrollback rebound to Ctrl+Shift+F.
Plain Ctrl+F falls through to the Ctrl+letter forwarder as 0x06,
which is what every remote shell expects. Doc updated.

### F30 — `_MarkdownTab` swallowed render failures without logging

**Threat.** A bug in `_render_full_reference` would trigger the
"(failed to render reference: …)" plaintext fallback forever, with
no traceback logged. Future renames in `_HELP_GROUPS` would silently
break the Scripts tab in production while CI passed.

**Status.** Fixed. `log.exception(...)` runs before the plaintext
fallback so the full traceback hits stderr / log file the first
time it happens. The user-visible plaintext stays unchanged.

---

## Patterns that emerged from the five review rounds

These are worth keeping in mind when a future backend ships:

1. **Probe early, validate often.** The PJL safety probe was a
   single-shot in F2 → became per-op in O6 because a network
   adversary can swap targets between probe and op. Same shape
   applies anywhere we trust a remote's identity.
2. **Fail loud, not silent.** O7 and F15 both fixed silent
   "wrong-but-not-error" returns. When normalisation collapses an
   input to something else, prefer raising over surprising.
3. **Cap every unbounded loop.** The walk-cap on `_is_ancestor`
   (F6), the LRU cap on Gopher's `_dir_cache` (F18), the depth cap
   on Gopher path nesting (F17), the buffer cap on REPL output
   (O2) — all are the same fix. New backends should default-cap
   any structure that scales with adversary input.
4. **Lock safety properties in tests.** The SLP "no SrvReg" rule
   has a static-grep regression test ([tests/test_backend_regressions.py](tests/test_backend_regressions.py));
   the Git force-push refusal now has a synthesised-divergence
   test (O1). Both make accidental re-introduction loud.
5. **Treat the on-disk file mode at create time, not after.** O10
   and F16 both rebuilt around `os.open(..., 0o600)` rather than
   write-then-chmod. The TOCTOU window is small but real.

---

## Devil's-advocate considerations that did NOT translate to bugs

These were considered during review and ruled out:

- **WebDAV PROPFIND XXE.** Already blocked by mandatory `defusedxml`;
  hardening tests exercise both the "defused parser raises" and
  "no defusedxml installed → fail-closed" paths.
- **NNTP STARTTLS plaintext-data injection.** Buffer is cleared
  after the upgrade so any pre-encrypt bytes from a hostile MITM
  cannot be folded into the post-upgrade stream.
- **Gopher selector CR/LF smuggling.** Rejected at `_send_selector`
  (test `test_send_selector_rejects_crlf_smuggling`).
- **DB-FS path traversal via `..`.** `posixpath.normpath` collapses
  `..` segments; root is never escaped because we always prepend
  `/` before normalising.
- **SLP multicast-amplification.** Hard-refused at the socket layer
  for any `224.0.0.0/4` or DA discovery group target. Regression test
  enforces the refusal.
- **Git-FS commit without identity.** Constructor allows it (so a
  read-only session works without git config), but `_commit_modification`
  refuses to commit when neither profile nor `~/.gitconfig` provides
  one. Regression test covers this.
- **PJL accidental print.** Mandatory safety probe in `__init__`
  refuses to mark the session usable unless the device responds with
  a recognisable PJL reply. Three regression tests cover it: well-formed
  reply (accept), silent server (refuse), non-PJL response (refuse).

---

## Round 6 — F31-F40 — review of API_GAPS rounds 1+2+Tier-2+round 3

After landing the API_GAPS expansion (~25 new public methods across
12 backends + 8 generic helpers + 6 Tier-2 helpers), a focused
red-team pass on every NEW surface for the same patterns the earlier
rounds found. Ten findings, all fixed in commits 6c4a93d / 638b169 /
c9208fb. Pattern: most were CR/LF / NUL smuggling at API boundaries
that don't auto-quote.

### F31 (CRIT) — LDAP DN-injection via comma in path segment
``LdapFsSession._path_to_dn`` reversed the path segments and joined
them with ``,``. A single segment containing ``,`` (e.g.
``/dc=test,dc=com/ou=evil,ou=admins``) smuggled an extra RDN into
the resulting DN, granting access to a parallel branch. Fix: the
FIRST segment may be a multi-RDN base (``dc=example,dc=com``);
deeper segments must be a single RDN (no unescaped commas, must
contain ``=``). RFC-4514 escaped commas (``\,``) still pass.
Test: ``test_ldap_path_dn_refuses_rdn_injection``.

### F32 (CRIT) — IMAP search/move criteria CR/LF
``ImapSession.search()`` interpolated ``criteria`` into
``imap.uid("SEARCH", None, criteria)`` — imaplib's wire framing
appends ``\r\n`` without re-escaping, so a tainted criterion with
embedded CR/LF smuggled a second IMAP command. Same gate added on
``move()``'s src/dst mailbox arguments. Test:
``test_imap_search_and_move_refuse_crlf_smuggling``.

### F33 (CRIT) — NNTP group-name CR/LF in groups_list / xover / article_headers / raw_head
The wire layer in ``nntp_lib._send_line`` already had a CR/LF
backstop, but rejecting at the public API gives a clearer error AND
aborts BEFORE any partial GROUP-select state change. Test:
``test_nntp_group_arguments_refuse_crlf_smuggling``.

### F34 (CRIT) — Exchange send_mail address + filename CR/LF header injection
``send_mail`` validated only ``subject`` for CR/LF. A tainted
``to`` / ``cc`` / ``bcc`` address or attachment ``filename``
smuggled additional MIME headers (Bcc, Reply-To, Content-Disposition,
X-Mailer-Override). Now every recipient and every attachment
filename is checked before the Mailbox / FileAttachment objects
are constructed. Test:
``test_exchange_send_mail_refuses_crlf_in_addresses_and_filenames``.

### F35 (MED) — ADB install_apk parallel-install collision
Remote tmp filename was ``axross-install-<pid>.apk`` only — two
threads in the same process (REPL + GUI transfer worker, parallel
scripts) collided and the second ``pm install`` ran on the wrong
APK. Fix: append a uuid4-12 suffix per-call. Test:
``test_adb_install_apk_concurrent_calls_use_distinct_remotes``.

### F36 (MED) — http_probe gzip-bomb via decoded body cap
``body_cap`` clipped the DECODED body but reads went through
``decode_content=True``. A 1000:1 gzip ratio meant a 1 KiB
compressed payload could allocate >1 GiB before the cap
triggered. Fix: new ``raw_cap`` parameter (defaults to
``max(body_cap*4, 8 MiB)``) reads raw bytes ahead of decode;
``gzip`` / ``deflate`` / ``br`` decompressed in-memory afterwards
with a streaming partial-fallback that survives a clipped trailer.
Test: ``test_tier2_http_probe_gzip_bomb_capped`` (in-process HTTP
server returns 20:1 gzip-amplified body; raw_cap stops the probe
before body_cap is reached).

### F37 (MED) — port_scan concurrency unbounded
``concurrency=10000`` would blow through ulimit -n. Hard cap at
``_PORT_SCAN_MAX_CONCURRENCY=1024`` with structured ValueError;
``concurrency<1`` also rejected. Test:
``test_tier2_port_scan_concurrency_capped``.

### F38 (MED) — FTP mlst / cwd path CR/LF
Symmetry with ``site()``: the FTP wire is CRLF-delimited, so
``mlst()`` and ``cwd()`` now reject CR/LF in their path argument
the same way ``site()`` already did. Test:
``test_ftp_mlst_and_cwd_refuse_crlf``.

### F39 (LOW) — SSH/SCP exec env VALUE NUL/CR/LF
The KEY allow-list ``[A-Za-z_][A-Za-z0-9_]*`` was already in place;
the VALUE wasn't checked. NUL would terminate the C-string sshd
forwards to the child; CR/LF would land in some sshd audit-log
formats as forged log lines. Symmetry — both halves of the env
tuple are equally adversary-controllable. Test:
``test_ssh_exec_env_value_validation``.

### F40 (LOW) — GDrive / OneDrive share string fields CR/LF
``GDriveSession.share()`` interpolated ``email`` / ``role`` / ``type``
into the Graph permissions POST body without CR/LF guards. Same
for ``OneDriveSession.share()``'s ``link_type`` / ``scope`` /
``password`` / ``expires`` fields. The requests JSON encoder
escapes CR/LF in transit, but Microsoft Graph's audit log can
replay these values verbatim. Tests:
``test_gdrive_share_refuses_crlf_in_email_role_type``,
``test_onedrive_share_refuses_crlf_in_string_fields``.

### Shell-paths deep audit — no findings

Followed every ``subprocess.run`` / ``subprocess.Popen`` /
``chan.exec_command`` / ``self._shell()`` / ``self._exec()`` site
across core/ to look for unquoted user input or shell-metachar
injection. Result: clean.

* All path arguments use ``shlex.quote`` before interpolation
  (verified in adb_client / ssh_client / scp_client / telnet_client).
* All subprocess invocations use argv-list, never shell=True
  (iscsi_client / mtp_client / nfs_client / rsync_client /
  fuse_mount / elevated_io).
* elevated_io scrubs env to ``{PATH=/usr/bin:/bin, LANG=C, LC_ALL=C}``
  and bounds timeouts.
* rsh_client already had F20 (leading-`-` flag injection guard) +
  CR/LF/NUL path guard from earlier rounds.

The pattern lessons from earlier rounds held up: every new exec
verb already used ``shlex.quote`` for paths and argv-lists for
subprocess. The injection gaps were all in API surfaces that send
raw protocol commands (IMAP/NNTP/Exchange MIME/FTP wire) where
the wire format itself uses CRLF as a delimiter — that's where
the guard has to live: at the edge, BEFORE the wire frame is
built.

### Pattern-lesson update (now six rules)

Round 6's ten findings reinforce the existing five lessons and
add one:

6. **CRLF/NUL belongs to the protocol's framing, not its payload.**
   Every protocol whose wire format uses CRLF as a delimiter
   (IMAP, NNTP, FTP, SMTP/MIME, HTTP) is structurally vulnerable
   to a smuggling attack via tainted argument unless the public
   API explicitly rejects CRLF before the wire frame is built.
   Library wrappers (imaplib, exchangelib, etc.) do NOT do this
   uniformly — when in doubt, add the guard.

---

## How to keep this doc honest

When a new backend ships:

1. Spell out who can put bytes into each entry point (network,
   profile, REPL, script).
2. For each: what's the worst byte they could send?
3. Either patch the issue, or land an entry under "Known acceptable
   risks" with the *reason* it's acceptable.
4. If a regression-style test can prove the property (multicast
   refusal, no-SrvReg, fail-closed defusedxml), write it.

This doc is the source-of-truth for "did we think about X" — when
a CVE-style report lands later, the first answer should be a link
to the relevant section.
