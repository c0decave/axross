<p align="center">
  <img src="resources/logo/axross-logo-256.png" alt="Axross" width="160"/>
</p>

# Axross

**One UI, 30+ protocols, an embedded Python REPL, and an MCP tool
surface so an LLM can drive the whole thing.**

- **30+ protocols in one window** — SFTP, SMB, S3, WebDAV, cloud drives, IMAP, Git, databases and more.
- **Copy between any two backends** — S3 → SFTP, WebDAV → SMB, directly, no detour via local disk.
- **Commander-style multi-pane layout** — as many split panes as you like, layout presets, drag & drop.
- **Workspaces** — named pane layouts as tabs, detachable into their own window, restored on the next start.
- **An LLM agent built in** — Agent dock with tabs and sandboxes for LM Studio, Ollama, vLLM or llama.cpp, read-only by default.
- **Talk to the agent** — push-to-talk, spoken answers in German and English, speech recognition locally or on the LLM server.
- **MCP server and client** — LLMs drive axross over stdio or HTTP, and the agent uses the tools of further MCP servers.
- **Built-in Python scripting** — REPL, Scripts dock and 32 ready-made scripts on one `axross.*` API.
- **Tabbed text editor** — syntax highlighting, find/replace, encodings and line endings, for local and remote files.
- **Find Files** — by name, type, content, size or tag, inside archives too, kept as a Smart Folder.
- **Coloured tags** — on any file, following renames and moves, a filter in Find Files.
- **Disk images and forensics** — partitions and file systems, read-only loop mount, hashes, The Sleuth Kit, PhotoRec.
- **Media Player** — playlist, M3U, shuffle/repeat, 10-band equalizer and spectrum.
- **Find duplicates, strip metadata** — content-hash duplicate finder, EXIF/GPS removal before sharing.
- **Encryption without plaintext on disk** — `.axenc` overlay on any backend, decrypted into RAM only.
- **Safe by default** — preview before delete/move, operation journal, `paranoid` mode, SSRF-guarded proxies.
- **Resumable transfers** — survive Ctrl-C and VPN drops, resume from the last verified segment.
- **Archives as folders** — browse ZIP, TAR and 7z, nested ones too, extract only what you pick, zip-bomb-safe.
- **Extensions** — Media Player, Bluetooth, Forensic Tools, Treemap, VirtualBox and more, each off until you switch it on.
- **Install in one line** — `pip install axross`, or a single-file binary for Linux, macOS and Windows.

Axross is a multi-protocol file manager and security toolkit built
with Python and PyQt6. SFTP, SMB, S3, WebDAV, Cloud drives, IMAP,
Usenet, Cisco IOS, printer-FS, BSD r-services — all in the same
split-pane UI, all callable from the same `axross.*` Python API,
all reachable through MCP for an LLM agent.

Languages: **English** · [Deutsch](README_de.md) · [Español](README_es.md)

---

## Screenshots

![Local, SFTP, FTP and WebDAV panes in one window](docs/screenshots/remote-panes.png)

*One window, four file systems.* A local folder and an SFTP share side by side in the thumbnail view, an FTP web root and a WebDAV folder below. Every pane names its connection; the blue **SOURCE** and the green **TARGET** set the direction for copy (F5) and move (F6).

![Four file panes and two local terminals in Hacker Mode](docs/screenshots/quad-files-shells.png)

*Hacker Mode.* Four file panes and two local terminals in one layout. Terminals sit in the splitter next to file panes; the presets `dev-shells`, `triage` and `shells-quad` place them for you.

![The Agent dock: a local model reads a file from inside a bubblewrap sandbox](docs/screenshots/agent-dock.png)

*Agent dock.* A local model (here Qwen 2.5 on llama.cpp) reads a file for you. The tab runs in the `Normal` sandbox (bubblewrap), the mode is `Ask`, and every tool call shows in the transcript.

More screenshots, each with an explanation: **[the slideshow](slideshow.md)**.

---

## 44 highlights

1. **30+ protocols, one consistent UI.** SFTP/SCP, FTP/FTPS, SMB/CIFS,
   WebDAV, S3-compatible, Rsync, NFS, Azure Blob/Files, OneDrive,
   SharePoint, Google Drive, Dropbox, iSCSI, IMAP, POP3, TFTP, Telnet,
   WinRM, WMI/DCOM, Exchange (EWS), DFS-N, ADB, MTP, **Gopher (RFC 1436)**,
   **NNTP / Usenet** (own wire-lib, Python-3.13-safe — stdlib `nntplib`
   is gone), **SQLite-FS / PostgreSQL-FS / Redis-FS / MongoDB GridFS**,
   **Git-as-FS (dulwich)**, **PJL printer-FS** with mandatory safety
   probe, **SLP (RFC 2608)** read-only discovery, **rsh / rcp** legacy
   plaintext, **Cisco IOS Telnet** with `/show/<cmd>.txt` virtual
   files, plus a **RAM-only volatile workspace** (RamFS).

2. **Total-Commander-style multi-pane workflow.** Open as many panes
   as you want, split horizontal/vertical, drag-and-drop between any
   two — including **cross-protocol relay transfers** (S3 → SFTP,
   WebDAV → Rsync, …) without staging on disk.

3. **Layout presets with a cycle hotkey.** Built-in `single`, `dual`,
   `quad-files`, `commander`, `dev-shells`, `triage`, `shells-quad`.
   `Ctrl+Alt+L` rotates forward, `Ctrl+Alt+Shift+L` back.

4. **Embedded Python REPL with 90 public scripting names.** A Console dock
   at the bottom of the GUI, a curated `axross.*` API with file verbs,
   ping/whois/snmp/tls/http helpers, diagnostics, recovery, safety
   previews and result-type classes, persistent history,
   side-effect-free Tab completion (no
   `@property` getters fired by accident), and slash-commands
   `.save / .load / .run / .scripts / .delete`. See
   [docs/SCRIPTING.md](docs/SCRIPTING.md) +
   [docs/SCRIPTING_REFERENCE.md](docs/SCRIPTING_REFERENCE.md).

5. **Inline searchable doc pane.** Right next to the REPL — every
   public `axross.*` function listed by topic, click any to read its
   signature and docstring. Filter live as you type.

6. **32 ready-to-use scripts.** Mirror, dedupe, find-secrets, port-scan,
   SLP inventory, Cisco IOS collection, IMAP archive, sha256-diff,
   bookmarks export, mac-lookup, time-skew, ssh-hostkey-collect,
   tls-cert-survey, http-probe-batch, snmp-walk, ramfs-pipeline, … —
   under [`resources/scripts/`](resources/scripts/), all runnable via
   `axross --script` or the REPL `.run` slash-command.

7. **MCP server mode for LLM agents.** Headless `axross --mcp-server`
   speaks JSON-RPC over stdio or HTTP (mTLS required off loopback)
   and serves the local filesystem under `--mcp-root` (default:
   your home). Read-only by default; `--mcp-write` enables file
   mutations (needs an explicit `--mcp-root`); `--mcp-allow-scripts`
   (stdio only) lets the LLM **write and run its own Python** as
   your user, each run in a child process with a timeout — not
   confined to the root, so treat it as a shell. `--mcp-tools GROUP[,…]` (or `all`) adds capability groups:
   metadata, duplicates, packer, archive, crypto, index, filetype,
   transfer, remote (saved profiles as extra backends, credentials
   only from the keyring, never a prompt) and extensions; their
   mutating tools also need `--mcp-write`. The `exec` group runs
   commands and scripts on remote hosts (SSH, Telnet, rsh, ADB,
   WinRM, Cisco `show`) only with its own `--mcp-allow-exec`; `agent`
   hands a task to your own local LLM, which can read but change
   nothing. The Agent dock (View > Panels) lets a local LLM work with
   axross in the window, asking before every change. `axross --mcp-list-tools`
   prints the JSON manifest of every tool
   ([docs/mcp-tools.json](docs/mcp-tools.json)). See
   [docs/MCP.md](docs/MCP.md).

8. **Encrypted overlay (`.axenc`).** AEAD-sealed file format that
   drops onto any backend. Decrypt straight into RamFS so plaintext
   never hits disk. The `redact.py` script encrypts every file under
   a path that matches a regex.

9. **OPSEC-aware defaults.** Per-profile shell-history suppression
   (zsh + bash + dash, off-by-flag), plaintext-credential warnings
   on every legacy session (Telnet, rsh, NNTP-on-119), client-banner
   blending into OpenSSH / Firefox-ESR mainstream, mandatory PJL
   safety probe (no accidentally-printed bytes on a non-PJL printer).
   Full breakdown in [docs/OPSEC.md](docs/OPSEC.md).

10. **Operational safety layer.** Mutating operations get redacted
    structured logs and an append-only JSONL operation journal; delete,
    trash and transfer flows can be previewed before execution; the
    Tools menu and `axross.*` scripting API expose backend diagnostics,
    recovery scans and recent operation history. `paranoid` security
    mode blocks external viewers, automatic previews, scripts, legacy
    protocols and private-proxy overrides.

11. **Multi-system workflow verbs.** `axross.where_was_i()` recalls
    the last directory + recent ops on any host you've touched.
    `compare_file([h1, h2, h3], "/etc/nginx.conf")` probes the same
    path on N hosts in parallel and emits a unified diff. `inspect_targets`
    does the same for a heterogenous `(backend, path)` list ("is the
    local /tmp/foo.bin really the same as the S3 object and the SFTP
    copy?"). `federated_search([…])` runs one query on many backends in
    parallel - name, content, size, date - with a hit cap and a timeout
    per backend. `dashboard()`
    renders one-screen federation status (text / markdown / json).
    Connection-health pulse keeps every session probed with the
    cheapest no-op the protocol allows; production-tarpit countdown
    fires the first time you do something destructive on a
    `production=True` profile. See
    [docs/MULTI_SYSTEM.md](docs/MULTI_SYSTEM.md) and
    [docs/DAILY_DRIVER.md](docs/DAILY_DRIVER.md).

12. **Reverse-serve over S3 / WebDAV.** `axross.serve_s3(backend)`
    and `axross.serve_webdav(backend)` expose any axross-opened
    backend as a localhost endpoint. restic / aws-cli / terraform /
    rclone / gnome-files / davfs2 / macOS Finder all just work —
    every tool that already speaks S3 or WebDAV gets immediate
    access to whatever protocol axross is fronting (SFTP, SMB, RamFS,
    Postgres-FS, IMAP-as-FS, …). Localhost-bind default + token
    auth on by default + read-only mode + path-traversal rejection. See
    [docs/REVERSE_SERVE.md](docs/REVERSE_SERVE.md).

13. **Resilient cross-backend transfers.** `axross.resumable_copy()`
    splits the source into segments, writes a manifest after each,
    and on a re-run picks up from the first incomplete segment after
    verifying the destination's recorded hashes. Survives Ctrl-C,
    VPN drops, crashed interpreters. Pairs with adaptive chunk-sizing
    (BDP-driven, hysteresis-based reassessment, 16 KiB ≤ chunk ≤ 16
    MiB) so long transfers hit a useful chunk size on Gbit LAN, 4G
    and satellite links alike.

14. **Time-lapse / trail.** `axross.snapshot_now(backend, path)`
    plus `start_trail()` keep a SQLite ledger of metadata snapshots
    for any directory tree, on any backend axross speaks. Diff any
    two snapshots to see added / removed / modified files; optional
    first-32-KiB drift hash. Forensic timeline reconstruction +
    change-tracking + growth monitoring without any server-side
    instrumentation. See [docs/TRAIL.md](docs/TRAIL.md).

15. **LLM-friendly directory inspection.** `axross.summarize(backend,
    path)` produces a one-paragraph synopsis from one round-trip —
    counts, extension histogram, age buckets, top-5 by size. No
    body reads. `explain(backend, path)` runs a 15-pattern matcher
    library and answers "what IS this directory?" — git repo,
    PostgreSQL data dir, nginx config tree, k8s manifests, Maildir,
    web-server log dir, Python / Node / Docker projects, … Designed
    so an LLM agent can plan without an N-thousand-entry list_dir
    dump.

16. **Authorised credential testing.** `axross.bruteforce()`,
    `spray()`, `enumerate_users()` for pentest engagements you have
    written authorisation for. Hard `authorized=True` gate (no
    env-var override, blocked under `paranoid` mode), lockout-first
    defaults, password-spray-by-default. Built-in oracles for POP3 +
    FTP/FTPS + statistical-timing fallback for everything else;
    Bearer-only — never V4-signed. See
    [docs/CRED_ATTACK.md](docs/CRED_ATTACK.md).

17. **CVE-mitigated by design.** SLP backend never builds a `SrvReg`
    packet — the SLP amplification path
    ([CVE-2023-29552](https://nvd.nist.gov/vuln/detail/CVE-2023-29552))
    is structurally impossible. Multicast targets are hard-refused
    at the socket layer.

18. **SSRF guard on every proxy hop.** Default-deny against
    cloud-metadata endpoints (169.254.169.254 + AWS IMDS variants)
    and RFC1918 ranges; opt-in via `AXROSS_ALLOW_PRIVATE_PROXY=1`
    when you genuinely need to proxy through a private LAN. In
    `paranoid` mode, that private-proxy override is ignored.

19. **Explicit proxy support.** SOCKS4/5, HTTP CONNECT and HTTPS
    proxies with Basic / NTLM / Negotiate authentication, a global
    default with bypass list and PAC, and a "Test proxy" check.
    Proxy-capable backends route through `core.proxy` — SSH/SCP, Telnet,
    FTP/FTPS, IMAP, POP3, NNTP, WebDAV, SMB/DFS-N, S3, SVN, databases,
    NFSv4 / iSCSI (loopback tunnel) and the cloud transports. Backends
    that cannot be proxied fail closed instead of silently going direct.
    See [docs/PROXY_SUPPORT.md](docs/PROXY_SUPPORT.md).

20. **Backend-agnostic primitives.** Universal trash, atomic writes
    (temp sibling + rename), snapshot timeline, content-addressable
    storage, archive extraction with zip-bomb / zip-slip guards —
    all uniform across every backend.

21. **Pure-Python where possible.** Own NNTP wire-lib, own WebDAV
    impl (no third-party SDK), own SLPv2 packet builder, own Gopher
    reader, own minimum-viable S3 + WebDAV reverse-server on stdlib
    `http.server`. Smaller dep tree, no SDK lock-in, no Python-3.13
    surprise when stdlib modules disappear.

22. **Headless and GUI from the same source.** PyQt6 file manager,
    MCP stdio/HTTP server, or `axross --script <file>` CLI runner.
    Single-file binaries on the release page: Linux (`axross-full`,
    `axross-slim`), macOS on Apple silicon and Windows x64 (`axross-slim`) - the macOS one is not notarized, so remove its quarantine attribute first ([docs/PACKAGING.md](docs/PACKAGING.md#macos-binary-the-first-start)); AppImage and the `Dockerfile.mcp` image build from
    the source ([docs/PACKAGING.md](docs/PACKAGING.md)), and that image
    specifically excludes PyQt6 to stay copyleft-free.

23. **Extensions.** Python plugins add Extensions-menu entries, right-click
    actions and panels (**Extensions → Manage Extensions…**). Every
    extension starts switched off, finding one never runs it, and
    `paranoid` mode loads none. Twelve bundled ones, among them Media Player, Bluetooth,
    Forensic Tools, Drives Overview, VirtualBox and Backup Repositories. See
    [docs/EXTENSIONS.md](docs/EXTENSIONS.md).

24. **An LLM agent in its own dock.** **View → Panels → Agent** talks to
    the model you pick in **Agent Settings** (Ollama, LM Studio, MLX-LM
    or any OpenAI-compatible endpoint such as llama.cpp). Every tab is a session, kept as one JSON
    file; protection modes `ask`, `plan`, `auto` and `bypass` decide what
    runs without a question; **Topics** offers ready-made tasks; **+**
    and drag & drop from a pane hand files over, and the remote
    connections open in the panes can be lent to it. A model's thinking
    shows apart from its answer, folded to one line until you click it;
    a lamp in the dock's title bar is green while the LLM answers, orange
    while it is being asked and red when it cannot be reached. **Topics ▸ +
    New Topic…** keeps your own tasks; **Settings → Agent → Prompts**
    holds named system/user prompt profiles; **Fetch models** opens a
    list with size, parameters, quantisation and the loaded model. The
    bundled **Agent Stats** extension counts runs, tool calls and tokens.

25. **Agents in a sandbox.** Each tab can run its agent in bubblewrap,
    podman or docker, at the level `lax`, `normal`, `high` or `paranoid`
    (paranoid: the LLM is the only peer, every folder read-only). The
    API key never enters the sandbox. Per tab, **Access…** grants the
    network (none, a `host:port` list, or all, never above the level)
    and folders read-only or writable, and switches the axross functions
    the agent may use outside the sandbox on or off.

26. **An MCP client, too.** **Agent Settings → MCP Servers** connects
    further MCP servers (stdio or HTTP); their tools appear in the tab's
    **Tools** list and ask before every call or before writes only.

27. **Workspaces.** Named pane layouts as tabs (**Workspace → New
    Workspace**), each detachable to a window of its own - another screen,
    or side by side - and back as a tab when that window closes. A new
    workspace starts with a file list or a local terminal, panes move
    between workspaces from the menu or by drag & drop, and several shells
    sit side by side. The workspaces are restored on the next start.

28. **Talk to the agent.** Push-to-talk (F9), toggle or conversation
    mode in the Agent dock. Answers are spoken in German or English with
    Piper voices, English IT terms kept English; each voice has its own
    speed, pitch, expressiveness, volume and pause, tried out with Listen
    in Settings > Voice; speech is recognised
    locally with faster-whisper or on the LLM server, chosen per profile.
    The models are downloaded on demand. Bundled in `axross-full`,
    otherwise `pip install axross[voice]`.

29. **A tabbed text editor.** Every tab is a file on any backend:
    Pygments syntax highlighting, find and replace (regex, case, whole
    word), encodings and line endings, New / Open… / Save As…,
    auto-indent; large files are lexed off the GUI thread.

30. **Find Files.** **Edit → Find Files…** (Alt+F7) searches folders on
    any open connection by name, type preset, content, size, date and
    tag, inside archives too. Hits stream in while the window stays
    usable, and a search is kept as a **Smart Folder** in the bookmarks.
    The offline index drops files deleted since the last indexing.

31. **Coloured tags.** Label any file on any backend - **Important** and
    **Review later** exist from the start. Tags follow renames and moves
    and are a filter in Find Files.

32. **Disk images and forensics.** axross reads qcow2, VDI, VMDK,
    VHD/VHDX and E01 headers, MBR and GPT partition tables and their file
    systems without writing anything, and mounts a partition read-only
    through a loop device. The **Forensic Tools** extension adds MD5 /
    SHA-1 / SHA-256 in one pass, `qemu-img`, The Sleuth Kit (browse and
    extract, deleted files included) and TestDisk/PhotoRec.

33. **Media Player.** An extension panel for MP3, FLAC, Ogg, Opus, AAC
    and more: playlist with drag & drop and M3U, seeking, shuffle and
    repeat, a 10-band equalizer with presets that folds away, eighteen
    visualizations (spectrum, mirrored, radial, line and polar spectrum,
    waterfall, oscilloscope, stereo scope, VU meter, starfield, LED
    equalizer, particle columns, wave ribbon, ridgelines, spectrum
    terrain, 3D ring, kaleidoscope, bell curves) a click on them switches
    between, in colour schemes or your own colours, fullscreen like a
    screensaver or in a window of their own, a playlist that folds away,
    title, artist and cover.

34. **Bookmarks for many places.** Multi-select, groups sorted by name,
    path or age, terminal bookmarks (on a profile, a bare host or
    locally), and **Manage Bookmarks** as a full manager.

35. **Every setting in one place.** **Edit → Settings…** holds every
    option - **Edit → Settings… → Audio** picks PipeWire or PulseAudio,
    the output and input device and their volume, and tests each with a
    tone, a level meter and a recording played back; **Help → Features**
    shows which optional parts are installed and which are missing;
    **Help → Scripting Guide** opens the API guide.

36. **A toolbar for the tools.** Buttons with icons for Agent, Analysis (sift),
    Terminal, Find Files, Scripts, the Python console, Tags, Trash, Media
    Player, Audio & Video Settings, Treemap, Drives, Settings and Features,
    in every theme, grouped by category (Connections, Windows & Panes,
    Files & Search, Media, LLM & Agent, Tools & System, Extensions), each
    category with its own colour behind its buttons. Drag a button to move
    it inside its group; the order is kept across starts, and Reset Toolbar
    Order (right-click the toolbar) brings back the default. **Edit →
    Settings… → Toolbar** switches grouping and colours on or off and sets
    each category's colour.

37. **Archives as folders.** ZIP, TAR and 7z archives open in the
    archive view; step into nested archives and extract everything or
    only the selection, with zip-bomb and zip-slip protection.

38. **Agent profiles.** Named bundles of what an Agent tab gets: LLM
    profile, prompt profile, protection mode, sandbox, tool groups, axross
    functions, files read-only and MCP servers by category or name. Seven
    presets - Files Assistant, Reverse Engineering, Forensics read-only,
    Network & Web Recon, Code & Secrets, Remote Ops, Research - and your
    own in **Settings → Agent → Profiles**, with a preview of what a tab
    gets. The **+** arrow in the Agent dock and **Tools → New Agent Tab
    from Profile** open a tab from one, **Apply Profile…** sets up an open
    tab, and a missing MCP server is one click away (**Install from
    Catalog…**).

39. **MCP servers from a catalog, contained.** **Add from Catalog…**
    searches the built-in catalog, the c0decave MCP Hub (17 security tools
    such as binwalk, capa, Nmap, YARA and The Sleuth Kit; only
    `ghcr.io/c0decave` images pinned by digest), Docker Hub's `mcp`
    namespace, the MCP Registry and curated lists. What is downloaded runs
    only in podman: no capabilities, no new privileges, a read-only root
    and no network unless you allow it. **Detected on this machine** picks
    up the MCP servers your other tools have configured and installs
    downloading ones the contained way. A third-party entry such as REA
    says who maintains it.

40. **Cut and Paste of files.** Ctrl+X / right-click **Cut** marks the
    entries (dimmed, in every pane); Ctrl+V / **Paste** moves them into
    any pane's folder through the transfer queue, and a source is removed
    only after its copy completed and was checked - a cut that is never
    pasted removes nothing. Esc in the filter line clears the filter.

41. **Icon colours.** **Settings → Appearance → Icon colours**: the theme
    default, own colours in every theme (also Hacker and Amber, which
    otherwise draw every icon in their colour) or one colour of your own -
    live, and kept across theme switches and restarts.

42. **Self-update.** `axross-full` and `axross-slim` ask the GitHub
    releases once per start, in the background (**Settings → Updates**;
    off with `AXROSS_NO_UPDATE_CHECK=1` and in `paranoid` mode), and show
    **Update to X.Y.Z…** in the status bar and the Help menu; **Help →
    Check for Updates…** asks at once. **Download and Install** checks the
    Ed25519 signature of the release's SHA256SUMS (`SHA256SUMS.sig`,
    against the release key built into axross), then the SHA-256 against
    SHA256SUMS and GitHub's digest, replaces the binary atomically and
    keeps the old one; **Restart Now** checks it
    again before it starts the new version.

43. **Bundled examples run directly.** **Run** or **Run in Console** on a
    bundled example in the Scripts dock shows its Usage call to adjust and
    runs the example with it; **Copy to My Scripts** keeps the call as a
    commented "Try it" section.

44. **Third-party software, credited.** **Help → Third-Party Software…**
    lists the 222 projects axross uses or ships - purpose, licence, how
    each reaches you, a link - from the same data file as the thanks at
    the end of this README.

---

## Quick start

From PyPI, once a release is published:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install "axross[all]"
axross              # start the GUI
axross --mcp-server # or expose the local filesystem as MCP tools to an LLM
```

From a source checkout:

```bash
git clone https://github.com/c0decave/axross
cd axross
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
axross              # start the GUI
axross --mcp-server # or expose the local filesystem as MCP tools to an LLM
```

```python
# from the embedded REPL — Console dock, bottom of the window
>>> b = axross.open_url("sftp://alice@example.com/")
>>> for f in b.list_dir("/var/log")[:5]:
...     print(f.name, f.size)
>>> axross.copy(b, "/etc/motd", axross.localfs(), "/tmp/motd")
>>> axross.preview_delete(axross.localfs(), ["/tmp/motd"])
>>> axross.diagnose(b)
>>> axross.help()         # or click the doc pane on the right
```

Base install pulls only what the always-available protocols need
(SFTP, SCP, FTP/FTPS, Telnet, IMAP). Install per-protocol extras:

```bash
pip install "axross[smb]"        # SMB / CIFS + DFS-N
pip install "axross[s3]"         # S3-compatible (boto3)
pip install "axross[webdav]"     # WebDAV (requests + defusedxml)
pip install "axross[onedrive]"   # OneDrive + SharePoint (msal)
pip install "axross[gdrive]"     # Google Drive
pip install "axross[dropbox]"    # Dropbox
pip install "axross[postgres]"   # PostgreSQL-as-FS
pip install "axross[redis]"      # Redis-as-FS
pip install "axross[mongo]"      # MongoDB GridFS
pip install "axross[git]"        # Git-as-FS via dulwich
pip install "axross[all]"        # everything light-weight at once
```

From a source checkout, use `pip install -e ".[smb]"` style extras
instead.

Full table of extras + system tools per protocol:
**[INSTALL.md](INSTALL.md)**.

---

## Documentation

| Document | What it covers |
|---|---|
| [INSTALL.md](INSTALL.md) | Prerequisites, per-protocol extras, OAuth setup, wheel build, dev setup. |
| [docs/USAGE.md](docs/USAGE.md) · [USAGE_de.md](docs/USAGE_de.md) · [USAGE_es.md](docs/USAGE_es.md) | User guide — connections, panes, transfers, terminal, right-click actions. |
| [docs/SCRIPTING.md](docs/SCRIPTING.md) · [SCRIPTING_de.md](docs/SCRIPTING_de.md) · [SCRIPTING_es.md](docs/SCRIPTING_es.md) | REPL + `axross.*` API + slash-commands + 32 bundled scripts + MCP scripting tools. |
| [docs/EXTENSIONS.md](docs/EXTENSIONS.md) | Extensions menu — plugin API, trust model, the twelve bundled extensions. |
| [docs/MCP.md](docs/MCP.md) · [MCP_de.md](docs/MCP_de.md) · [MCP_es.md](docs/MCP_es.md) | MCP server reference — tools, sessions, mTLS, rate limits, hardening. |
| [docs/LLM_GUIDE.md](docs/LLM_GUIDE.md) · [llms.txt](llms.txt) | For LLM agents: how to drive axross over MCP and the `axross.*` API correctly, with the tool catalog generated from the manifest. |
| [docs/HANDBUCH.md](docs/HANDBUCH.md) | Full German manual (workflows, dialog reference, keyboard shortcuts). |
| [docs/OPSEC.md](docs/OPSEC.md) | Threat model + per-finding analysis of what the client reveals to servers. |
| [docs/PROXY_SUPPORT.md](docs/PROXY_SUPPORT.md) | SOCKS4/5, HTTP(S) CONNECT, NTLM/Negotiate, default proxy, bypass, PAC — per protocol. |
| [OAUTH_SETUP.md](OAUTH_SETUP.md) | OneDrive / SharePoint / Google Drive / Dropbox app registration recipes. |
| [docs/MULTI_SYSTEM.md](docs/MULTI_SYSTEM.md) · [MULTI_SYSTEM_de.md](docs/MULTI_SYSTEM_de.md) · [MULTI_SYSTEM_es.md](docs/MULTI_SYSTEM_es.md) | Cross-host workflow verbs — `where_was_i`, `compare_file`, `federated_search`, `dashboard`, `resumable_copy`, … |
| [docs/DAILY_DRIVER.md](docs/DAILY_DRIVER.md) · [DAILY_DRIVER_de.md](docs/DAILY_DRIVER_de.md) · [DAILY_DRIVER_es.md](docs/DAILY_DRIVER_es.md) | Production tarpit + adaptive chunk-sizing primitives that sit under the multi-system verbs. |
| [docs/REVERSE_SERVE.md](docs/REVERSE_SERVE.md) · [REVERSE_SERVE_de.md](docs/REVERSE_SERVE_de.md) · [REVERSE_SERVE_es.md](docs/REVERSE_SERVE_es.md) | Expose any axross-opened backend over a minimum-viable S3 / WebDAV API for any tool that already speaks them. |
| [docs/TRAIL.md](docs/TRAIL.md) · [TRAIL_de.md](docs/TRAIL_de.md) · [TRAIL_es.md](docs/TRAIL_es.md) | Time-lapse / change-tracking — periodic metadata snapshots of any directory tree. |
| [docs/CRED_ATTACK.md](docs/CRED_ATTACK.md) · [CRED_ATTACK_de.md](docs/CRED_ATTACK_de.md) · [CRED_ATTACK_es.md](docs/CRED_ATTACK_es.md) | Authorised credential testing — brute-force, password spray, user enumeration with OPSEC defaults. |
| [docs/RED_TEAM_NOTES.md](docs/RED_TEAM_NOTES.md) | Adversarial review of every backend — fixed findings, known-acceptable risks, open follow-ups. |
| [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) | Test suite, Docker lab, protocol coverage matrix. |
| [docs/PACKAGING.md](docs/PACKAGING.md) | PyPI/sdist/wheel release, PyInstaller bundle, AppImage, headless MCP Docker image. |
| [SECURITY.md](SECURITY.md) | Vulnerability disclosure policy. |
| [CONTRIBUTING.md](CONTRIBUTING.md) | PR scope, code style, contribution licensing. |

---

## Contributing

Pull requests welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).
Security reports: [SECURITY.md](SECURITY.md).

## License

Axross source is **Apache License 2.0** — see [LICENSE](LICENSE),
[NOTICE](NOTICE), and per-dependency attribution in
[THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).

Three distribution layers to be aware of:

1. **Source tree** (this repository) — Apache-2.0. Users `pip install`
   PyQt6 themselves; no GPL component is bundled with the source.
2. **Pre-built PyInstaller bundles** (`dist/axross-slim`,
   `dist/axross-full`, the AppImage) — statically link PyQt6, which
   is GPL-3.0-or-commercial from Riverbank. Any such binary
   redistributed by us is therefore offered under **GPL-3.0** terms.
   For a non-GPL binary, rebuild against PySide6 (LGPL-3.0) from the
   same Apache-2.0 source.
3. **`Dockerfile.mcp`** — explicitly excludes PyQt6; the resulting
   image is Apache-2.0 only, no copyleft inheritance.

Copyright © 2026 Marco Lux.

---

<!-- third-party:readme -->
<!-- Generated from resources/credits/third_party.json by `python -m core.third_party --write`; edit the data file, not this block. -->

## Third-party software and thanks

axross stands on the work of many people. Thank you to everyone who builds and maintains the projects below - axross would not exist without them.

The list is generated from [`resources/credits/third_party.json`](resources/credits/third_party.json), the same data the app shows in **Help > Third-Party Software…**. Licence texts and notes for redistributors are in [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).

| Project | Used for | License | Comes with |
|---|---|---|---|
| [adb_shell](https://github.com/JeffLIrion/adb_shell) | Android devices over ADB | Apache-2.0 | axross-full, axross-slim, pip [adb] |
| [axross MCP hub](https://github.com/c0decave/axross-mcp-hub) | Catalogue of container-packaged MCP servers that the MCP catalog installs on request | MIT | container image |
| [azure-storage-blob](https://github.com/Azure/azure-sdk-for-python) | Azure Blob Storage backend | MIT | axross-full, pip [azure] |
| [azure-storage-file-share](https://github.com/Azure/azure-sdk-for-python) | Azure Files backend | MIT | axross-full, pip [azure] |
| [backports.zstd](https://github.com/rogdham/backports.zstd) | Zstandard compression on Python versions before 3.14 | PSF-2.0 | axross-full, axross-slim, pip [archive] |
| [boto3](https://github.com/boto/boto3) | Amazon S3 and S3-compatible storage | Apache-2.0 | axross-full, axross-slim, pip [s3] |
| [Bubblewrap (bwrap)](https://github.com/containers/bubblewrap) | Agent sandbox | LGPL-2.1-or-later | on your system |
| [bzip2](https://sourceware.org/bzip2/) | bzip2 compression (Python's bz2 module) | bzip2-1.0.6 | axross-full, axross-slim |
| [chardet](https://github.com/chardet/chardet) | Text encoding detection | 0BSD | axross-full, axross-slim, pip [encoding] |
| [cryptography](https://github.com/pyca/cryptography) | Encrypted overlay, certificate inspection; cryptography for SSH and TLS | Apache-2.0 OR BSD-3-Clause | axross-full, axross-slim, pip |
| [ctranslate2](https://github.com/OpenNMT/CTranslate2) | Runs the Whisper speech recognition models | MIT | axross-full, pip [voice] |
| [D-Bus](https://www.freedesktop.org/wiki/Software/dbus/) | Desktop bus access of Qt (notifications, portals, keyring) | AFL-2.1 OR GPL-2.0-or-later | axross-full, axross-slim |
| [defusedxml](https://github.com/tiran/defusedxml) | Safe XML parsing (WebDAV responses and other XML input) | PSF-2.0 | axross-full, axross-slim, pip [webdav] |
| [dnspython](https://github.com/rthalley/dnspython) | DNS lookups (scripting helpers and SRV discovery) | ISC | axross-full, axross-slim, pip [dns] |
| [Docker](https://www.docker.com) | Agent sandbox and MCP server containers | Apache-2.0 | on your system |
| [dropbox](https://github.com/dropbox/dropbox-sdk-python) | Dropbox backend | MIT | axross-full, pip [dropbox] |
| [dulwich](https://github.com/dulwich/dulwich) | Git repositories as a file system | Apache-2.0 OR GPL-2.0-or-later | axross-full, axross-slim, pip [git] |
| [espeak-ng](https://github.com/espeak-ng/espeak-ng) | Phonemes for the Piper voices (statically linked into piper's espeakbridge, with its data) | GPL-3.0-or-later | axross-full, pip (with an extra) |
| [exchangelib](https://github.com/ecederstrand/exchangelib) | Microsoft Exchange backend (EWS) | BSD-2-Clause | axross-full, pip [exchange] |
| [Expat](https://libexpat.github.io) | XML parsing (Python's xml modules) | MIT | axross-full, axross-slim |
| [faster-whisper](https://github.com/SYSTRAN/faster-whisper) | Local speech recognition of the Agent dock | MIT | axross-full, pip [voice] |
| [faster-whisper models (Whisper base, small)](https://huggingface.co/Systran) | Local speech recognition models, downloaded in Help > Features… | MIT | downloaded on request |
| [fd](https://github.com/sharkdp/fd) | Find Files: name search | MIT OR Apache-2.0 | axross-full |
| [Feather icons](https://github.com/feathericons/feather) | Style model of axross's own SVG icons (re-drawn, no files copied) | MIT | axross source |
| [FFmpeg (ffmpeg, ffprobe)](https://ffmpeg.org) | Video thumbnails, media details, removing audio/video metadata | LGPL-2.1-or-later OR GPL-2.0-or-later OR GPL-3.0-only | on your system |
| [fusepy](https://github.com/fusepy/fusepy) | Mounting an axross connection as a local folder (FUSE) | ISC | axross-full, axross-slim, pip [fuse] |
| [GCC runtime libraries](https://gcc.gnu.org) | Fortran and OpenMP runtimes (numpy, CTranslate2) | GPL-3.0-or-later WITH GCC-exception-3.1 | axross-full |
| [GLib](https://gitlab.gnome.org/GNOME/glib) | Main loop and D-Bus integration of Qt's platform plugins | LGPL-2.1-or-later | axross-full, axross-slim |
| [GNU dbm](https://www.gnu.org.ua/software/gdbm/) | Key-value files of Python's dbm module | GPL-3.0-or-later | axross-full |
| [GNU Readline](https://tiswww.case.edu/php/chet/readline/rltop.html) | Line editing of Python's readline module | GPL-3.0-or-later | axross-full, axross-slim |
| [google-api-python-client](https://github.com/googleapis/google-api-python-client) | Google Drive backend | Apache-2.0 | axross-full, pip [gdrive] |
| [google-auth-httplib2](https://github.com/googleapis/google-cloud-python) | HTTP transport of the Google Drive client | Apache-2.0 | axross-full, pip [gdrive] |
| [google-auth-oauthlib](https://github.com/googleapis/google-cloud-python) | Google sign-in (OAuth) for Google Drive | Apache-2.0 | axross-full, pip [gdrive] |
| [impacket](https://github.com/fortra/impacket) | WMI / DCOM and SMB tooling for Windows hosts | LicenseRef-Impacket-Apache-1.1-modified | axross-full, pip [wmi] |
| [ipwhois](https://github.com/secynic/ipwhois) | WHOIS / RDAP lookups | BSD-2-Clause | axross-full, axross-slim, pip [whois] |
| [jmtpfs / simple-mtpfs / go-mtpfs](https://github.com/JasonFerrara/jmtpfs) | MTP backend (the first one found on PATH) | GPL-3.0-only OR GPL-2.0-or-later OR BSD-3-Clause | on your system |
| [jsonschema](https://github.com/python-jsonschema/jsonschema) | Validates MCP tool arguments against their schemas | MIT | axross-full, axross-slim |
| [keyring](https://github.com/jaraco/keyring) | Stores profile passwords in the operating system's keyring | MIT | axross-full, axross-slim, pip |
| [keyutils](https://git.kernel.org/pub/scm/linux/kernel/git/dhowells/keyutils.git) | Kernel key retention used by MIT Kerberos | LGPL-2.1-or-later | axross-full, axross-slim |
| [ldap3](https://github.com/cannatag/ldap3) | LDAP backend and helpers | LGPL-3.0-or-later | axross-full, axross-slim, pip [ldap] |
| [libcap](https://sites.google.com/site/fullycapable/) | POSIX capabilities used by libsystemd | BSD-3-Clause OR GPL-2.0-only | axross-full, axross-slim |
| [libffi](https://sourceware.org/libffi/) | Foreign function calls (Python's ctypes, cffi) | MIT | axross-full, axross-slim |
| [libfuse 2](https://github.com/libfuse/libfuse) | Kernel FUSE interface of the FUSE mounts (fusepy) | LGPL-2.1-only | axross-full, axross-slim |
| [Libgcrypt and libgpg-error](https://www.gnupg.org/software/libgcrypt/) | Cryptography used by libsystemd | LGPL-2.1-or-later | axross-full, axross-slim |
| [libselinux](https://github.com/SELinuxProject/selinux) | SELinux library used by GLib and libpq | LicenseRef-PublicDomain | axross-full, axross-slim |
| [libsystemd](https://systemd.io) | Journal and D-Bus helpers used by system libraries | LGPL-2.1-or-later AND MIT | axross-full, axross-slim |
| [libxcb and xcb-util](https://xcb.freedesktop.org) | X protocol bindings of Qt's xcb platform plugin | MIT | axross-full, axross-slim |
| [libxkbcommon](https://xkbcommon.org) | Keyboard handling of Qt (X11 and Wayland) | MIT | axross-full, axross-slim |
| [libxml2](https://gitlab.gnome.org/GNOME/libxml2) | XML library used by system libraries | MIT | axross-full, axross-slim |
| [LZ4](https://github.com/lz4/lz4) | LZ4 compression used by system libraries | BSD-2-Clause | axross-full, axross-slim |
| [manuf](https://github.com/coolbho3k/manuf) | MAC address vendor lookup (Wireshark OUI database) | Apache-2.0 OR GPL-3.0-or-later | axross-full, axross-slim, pip [mac] |
| [MIT Kerberos](https://web.mit.edu/kerberos/) | Kerberos / GSSAPI (libpq, system libraries) | MIT | axross-full, axross-slim |
| [mpdecimal](https://www.bytereef.org/mpdecimal/) | Decimal arithmetic of Python's decimal module | BSD-2-Clause | axross-full, axross-slim |
| [msal](https://github.com/AzureAD/microsoft-authentication-library-for-python) | Microsoft sign-in for OneDrive and SharePoint | MIT | axross-full, pip [onedrive] |
| [ncurses (libtinfo)](https://invisible-island.net/ncurses/) | Terminal capabilities used by Readline | X11 | axross-full, axross-slim |
| [nfs-utils (mount.nfs)](https://linux-nfs.org) | NFS backend | GPL-2.0-or-later | on your system |
| [ntplib](https://github.com/cf-natali/ntplib) | NTP time queries | MIT | axross-full, axross-slim, pip [ntp] |
| [numpy](https://github.com/numpy/numpy) | Equalizer and spectrum of the Media Player extension | BSD-3-Clause AND 0BSD AND MIT AND Zlib AND CC0-1.0 | axross-full, pip [media] |
| [onnxruntime](https://github.com/microsoft/onnxruntime) | Runs the Piper voice models | MIT | axross-full, pip [voice] |
| [open-iscsi (iscsiadm)](https://github.com/open-iscsi/open-iscsi) | iSCSI backend | GPL-2.0-or-later | on your system |
| [OpenSSL](https://www.openssl.org) | TLS and cryptography (Python's ssl module, Qt, libpq) | Apache-2.0 | axross-full, axross-slim |
| [paramiko](https://github.com/paramiko/paramiko) | SSH, SFTP and SCP connections | LGPL-2.1-or-later | axross-full, axross-slim, pip |
| [PCRE and PCRE2](https://www.pcre.org) | Regular expressions used by GLib and libselinux | BSD-3-Clause | axross-full, axross-slim |
| [Pillow](https://github.com/python-pillow/Pillow) | Image thumbnails, image metadata and the image viewer | MIT-CMU | axross-full, axross-slim, pip |
| [Piper voices](https://huggingface.co/rhasspy/piper-voices) | The Agent dock's voices, downloaded in Help > Features… | MIT | downloaded on request |
| [piper-tts](https://github.com/OHF-voice/piper1-gpl) | Speech output of the Agent dock (Piper) | GPL-3.0-or-later | axross-full, pip [voice] |
| [Podman](https://podman.io) | Agent sandbox and MCP server containers | Apache-2.0 | on your system |
| [polkit (pkexec)](https://github.com/polkit-org/polkit) | "Open as root…" and privileged mounts | LGPL-2.0-or-later | on your system |
| [psycopg](https://github.com/psycopg/psycopg) | PostgreSQL backend | LGPL-3.0-only | axross-full, axross-slim, pip [postgres] |
| [psycopg-binary](https://github.com/psycopg/psycopg) | Compiled PostgreSQL driver with libpq | LGPL-3.0-only | axross-full, axross-slim |
| [puremagic](https://github.com/cdgriffith/puremagic) | File type detection from file content | MIT | axross-full, axross-slim, pip [magic] |
| [py7zr](https://github.com/miurahr/py7zr) | 7z archives (browse, extract, pack) | LGPL-2.1-or-later | axross-full, axross-slim, pip [archive] |
| [Pygments](https://github.com/pygments/pygments) | Syntax highlighting in the text editor | BSD-2-Clause | axross-full, axross-slim, pip |
| [pymongo](https://github.com/mongodb/mongo-python-driver) | MongoDB / GridFS backend | Apache-2.0 | axross-full, axross-slim, pip [mongo] |
| [pypdf](https://github.com/py-pdf/pypdf) | Removing PDF metadata | BSD-3-Clause | axross-full, axross-slim, pip [metadata] |
| [PyQt6](https://www.riverbankcomputing.com/software/pyqt/) | Python bindings for Qt: the whole user interface | GPL-3.0-only OR LicenseRef-Riverbank-Commercial | axross-full, axross-slim, pip |
| [pysnmp](https://github.com/lextudio/pysnmp) | SNMP helpers | BSD-2-Clause | axross-full, axross-slim, pip [snmp] |
| [PySocks](https://github.com/Anorov/PySocks) | SOCKS4/5 proxies for every connection | BSD-3-Clause | axross-full, axross-slim, pip |
| [Python](https://www.python.org) | The Python interpreter and standard library inside the binaries | PSF-2.0 | axross-full, axross-slim |
| [Python container image (python:3.12-slim)](https://hub.docker.com/_/python) | Base image of Dockerfile.mcp, Dockerfile.agent and Dockerfile.gui | PSF-2.0 AND LicenseRef-Debian-Packages | container image |
| [pywinpty](https://github.com/andfoy/pywinpty) | The local terminal on Windows (ConPTY) | MIT | pip |
| [pywinrm](https://github.com/diyan/pywinrm) | WinRM backend (Windows Remote Management) | MIT | axross-full, pip [winrm] |
| [qemu-img](https://www.qemu.org) | Opening virtual disk images | GPL-2.0-only | on your system |
| [rarfile](https://github.com/markokr/rarfile) | RAR archives (browse, extract) | ISC | axross-full, axross-slim, pip [archive] |
| [redis](https://github.com/redis/redis-py) | Redis backend | MIT | axross-full, axross-slim, pip [redis] |
| [requests](https://github.com/psf/requests) | HTTP client of the WebDAV, OneDrive and other HTTP backends | Apache-2.0 | axross-full, axross-slim, pip [webdav, onedrive] |
| [ripgrep](https://github.com/BurntSushi/ripgrep) | Find Files: content search | MIT OR Unlicense | axross-full |
| [rsh client (netkit-rsh or GNU Inetutils)](https://www.gnu.org/software/inetutils/) | rsh backend | BSD-4-Clause-UC OR GPL-3.0-or-later | on your system |
| [rsync](https://rsync.samba.org) | rsync backend and fast copies | GPL-3.0-or-later | on your system |
| [SecLists](https://github.com/danielmiessler/SecLists) | Public source of the TFTP common-filename wordlist | MIT | axross source |
| [sift](https://github.com/c0decave/sift) | The Analysis dock's file explanations (sift-summarizer); a sister project of axross | MIT | axross-full, pip (with an extra) |
| [sift-summarizer](https://github.com/c0decave/sift) | sift: the Analysis dock's explanation of the selected file | MIT | axross-full, pip [sift] |
| [Silero VAD](https://github.com/snakers4/silero-vad) | Voice activity detection model that faster-whisper ships | MIT | axross-full, pip (with an extra) |
| [smbprotocol](https://github.com/jborean93/smbprotocol) | SMB / CIFS file shares | MIT | axross-full, axross-slim, pip [smb] |
| [SQLite](https://www.sqlite.org) | Embedded database (Python's sqlite3 module) | blessing | axross-full, axross-slim |
| [Subversion](https://subversion.apache.org) | Subversion backend | Apache-2.0 | on your system |
| [TestDisk / PhotoRec](https://www.cgsecurity.org) | Recovering partitions and files | GPL-2.0-or-later | on your system |
| [tftpy](https://github.com/msoulier/tftpy) | TFTP backend | MIT | axross-full, axross-slim, pip [tftp] |
| [The Sleuth Kit](https://www.sleuthkit.org) | Forensic file system access (fls, icat) | IPL-1.0 AND CPL-1.0 AND GPL-2.0-or-later | on your system |
| [UDisks (udisksctl)](https://github.com/storaged-project/udisks) | Loop-mounting disk images | GPL-2.0-or-later | on your system |
| [urllib3](https://github.com/urllib3/urllib3) | HTTP connection pool (proxies, S3, WebDAV) | MIT | axross-full, axross-slim, pip [git] |
| [util-linux libraries](https://github.com/util-linux/util-linux) | UUIDs, block device and mount information (GLib, Python's uuid module) | LGPL-2.1-or-later AND BSD-3-Clause | axross-full, axross-slim |
| [VirtualBox (VBoxManage)](https://www.virtualbox.org) | VirtualBox disk images | GPL-3.0-only | on your system |
| [watchdog](https://github.com/gorakhargosh/watchdog) | Instant refresh of local folders (inotify, FSEvents, ReadDirectoryChangesW) | Apache-2.0 | axross-full, axross-slim, pip |
| [X.Org client libraries](https://www.x.org) | X11 display connection of Qt's xcb platform plugin | MIT AND X11 | axross-full, axross-slim |
| [xdg-utils (xdg-open)](https://gitlab.freedesktop.org/xdg/xdg-utils) | Opening files and links with the desktop's programs | MIT | on your system |
| [XZ Utils (liblzma)](https://tukaani.org/xz/) | LZMA/XZ compression (Python's lzma module, Pillow) | 0BSD AND LicenseRef-PublicDomain | axross-full, axross-slim |
| [zlib](https://zlib.net) | Deflate compression (Python, Qt and many libraries) | Zlib | axross-full, axross-slim |
| [Zstandard](https://github.com/facebook/zstd) | Zstandard compression (Pillow, system libraries) | BSD-3-Clause OR GPL-2.0-only | axross-full, axross-slim |

<details>
<summary>113 more libraries that come with the projects above</summary>

| Project | Used by | License | Comes with |
|---|---|---|---|
| [alsa-lib](https://github.com/alsa-project/alsa-lib) | PyAV | LGPL-2.1-or-later | axross-full, pip (with an extra) |
| [anyio](https://github.com/agronholm/anyio) | httpx2 | MIT | axross-full, axross-slim, pip (with an extra) |
| [attrs](https://github.com/python-attrs/attrs) | jsonschema | MIT | axross-full, axross-slim |
| [azure-core](https://github.com/Azure/azure-sdk-for-python) | azure-storage-blob | MIT | axross-full, pip (with an extra) |
| [bcrypt](https://github.com/pyca/bcrypt) | paramiko | Apache-2.0 | axross-full, axross-slim, pip |
| [blinker](https://github.com/pallets-eco/blinker) | Flask | MIT | axross-full, pip (with an extra) |
| [botocore](https://github.com/boto/botocore) | boto3 | Apache-2.0 | axross-full, axross-slim, pip (with an extra) |
| [brotli](https://github.com/google/brotli) | py7zr | MIT | axross-full, axross-slim, pip (with an extra) |
| [Brotli (C library)](https://github.com/google/brotli) | Pillow | MIT | axross-full, axross-slim, pip |
| [cached-property](https://github.com/pydanny/cached-property) | exchangelib | BSD-3-Clause | axross-full, pip (with an extra) |
| [certifi](https://github.com/certifi/python-certifi) | requests | MPL-2.0 | axross-full, axross-slim, pip (with an extra) |
| [cffi](https://github.com/python-cffi/cffi) | cryptography | MIT-0 | axross-full, axross-slim, pip |
| [charset-normalizer](https://github.com/jawah/charset_normalizer) | impacket | MIT | axross-full, axross-slim, pip (with an extra) |
| [click](https://github.com/pallets/click) | Flask | BSD-3-Clause | axross-full, axross-slim, pip (with an extra) |
| [Cyrus SASL](https://www.cyrusimap.org/sasl/) | libpq | BSD-Attribution-HPND-disclaimer | axross-full, axross-slim, pip (with an extra) |
| [dav1d](https://code.videolan.org/videolan/dav1d) | PyAV | BSD-2-Clause | axross-full, pip (with an extra) |
| [FFmpeg (PyAV build)](https://ffmpeg.org) | PyAV | LGPL-3.0-or-later | axross-full, pip (with an extra) |
| [FFmpeg (Qt Multimedia build)](https://ffmpeg.org) | Qt 6 | LGPL-2.1-or-later | axross-full, axross-slim, pip |
| [filelock](https://github.com/tox-dev/py-filelock) | huggingface_hub | MIT | axross-full, pip (with an extra) |
| [Flask](https://github.com/pallets/flask) | impacket | BSD-3-Clause | axross-full, pip (with an extra) |
| [FreeType](https://freetype.org) | Pillow | FTL OR GPL-2.0-or-later | axross-full, axross-slim, pip |
| [fsspec](https://github.com/fsspec/filesystem_spec) | huggingface_hub | BSD-3-Clause | axross-full, pip (with an extra) |
| [GMP](https://gmplib.org) | PyAV | LGPL-3.0-or-later OR GPL-2.0-or-later | axross-full, pip (with an extra) |
| [GnuTLS](https://www.gnutls.org) | PyAV | LGPL-2.1-or-later | axross-full, pip (with an extra) |
| [google-api-core](https://github.com/googleapis/google-cloud-python) | google-api-python-client | Apache-2.0 | axross-full, pip (with an extra) |
| [google-auth](https://github.com/googleapis/google-cloud-python) | google-api-python-client | Apache-2.0 | axross-full, pip (with an extra) |
| [googleapis-common-protos](https://github.com/googleapis/google-cloud-python) | google-api-core | Apache-2.0 | axross-full, pip (with an extra) |
| [Graphite](https://github.com/silnrsi/graphite) | HarfBuzz | LGPL-2.1-or-later OR MPL-1.1 OR GPL-2.0-or-later | axross-full, axross-slim |
| [h11](https://github.com/python-hyper/h11) | httpcore2 | MIT | axross-full, axross-slim, pip (with an extra) |
| [HarfBuzz](https://github.com/harfbuzz/harfbuzz) | Qt 6, Pillow | MIT | axross-full, axross-slim, pip |
| [hf-xet](https://github.com/huggingface/xet-core) | huggingface_hub | Apache-2.0 | axross-full, pip (with an extra) |
| [httpcore2](https://github.com/pydantic/httpx2) | httpx2 | BSD-3-Clause | axross-full, axross-slim, pip (with an extra) |
| [httplib2](https://github.com/httplib2/httplib2) | google-api-python-client | MIT | axross-full, pip (with an extra) |
| [httpx2](https://github.com/pydantic/httpx2) | huggingface_hub | BSD-3-Clause | axross-full, axross-slim, pip (with an extra) |
| [huggingface_hub](https://github.com/huggingface/huggingface_hub) | faster-whisper | Apache-2.0 | axross-full, pip (with an extra) |
| [ICU](https://icu.unicode.org) | Qt 6 | Unicode-DFS-2016 | axross-full, axross-slim, pip |
| [idna](https://github.com/kjd/idna) | requests | BSD-3-Clause | axross-full, axross-slim, pip (with an extra) |
| [inflate64](https://github.com/miurahr/inflate64) | py7zr | LGPL-2.1-or-later | axross-full, axross-slim, pip (with an extra) |
| [Intel VPL dispatcher](https://github.com/intel/libvpl) | PyAV | MIT | axross-full, pip (with an extra) |
| [invoke](https://github.com/pyinvoke/invoke) | paramiko | BSD-2-Clause | axross-full, axross-slim, pip |
| [isodate](https://github.com/gweis/isodate) | azure-storage-blob | BSD-3-Clause | axross-full, pip (with an extra) |
| [itsdangerous](https://github.com/pallets/itsdangerous) | Flask | BSD-3-Clause | axross-full, pip (with an extra) |
| [jaraco.classes](https://github.com/jaraco/jaraco.classes) | keyring | MIT | axross-full, axross-slim, pip |
| [jaraco.context](https://github.com/jaraco/jaraco.context) | keyring | MIT | axross-full, axross-slim, pip |
| [jaraco.functools](https://github.com/jaraco/jaraco.functools) | keyring | MIT | axross-full, axross-slim, pip |
| [jeepney](https://gitlab.com/takluyver/jeepney) | keyring | MIT | axross-full, axross-slim, pip |
| [Jinja2](https://github.com/pallets/jinja) | Flask | BSD-3-Clause | axross-full, pip (with an extra) |
| [jmespath](https://github.com/jmespath/jmespath.py) | boto3 | MIT | axross-full, axross-slim, pip (with an extra) |
| [jsonschema-specifications](https://github.com/python-jsonschema/jsonschema-specifications) | jsonschema | MIT | axross-full, axross-slim |
| [libavif](https://github.com/AOMediaCodec/libavif) | Pillow | BSD-2-Clause | axross-full, axross-slim, pip |
| [libdrm](https://gitlab.freedesktop.org/mesa/drm) | PyAV | MIT | axross-full, pip (with an extra) |
| [libjpeg-turbo](https://libjpeg-turbo.org) | Pillow, Qt 6 | IJG AND BSD-3-Clause | axross-full, axross-slim, pip |
| [libpng](https://www.libpng.org) | Pillow, Qt 6 | libpng-2.0 | axross-full, axross-slim, pip |
| [libpq](https://www.postgresql.org) | psycopg-binary | PostgreSQL | axross-full, axross-slim, pip (with an extra) |
| [LibTIFF](https://libtiff.gitlab.io/libtiff/) | Pillow | libtiff | axross-full, axross-slim, pip |
| [libunistring](https://www.gnu.org/software/libunistring/) | PyAV | LGPL-3.0-or-later OR GPL-2.0-or-later | axross-full, pip (with an extra) |
| [libvpx](https://chromium.googlesource.com/webm/libvpx) | PyAV | BSD-3-Clause | axross-full, pip (with an extra) |
| [libwebp](https://chromium.googlesource.com/webm/libwebp) | Pillow, Qt 6 | BSD-3-Clause | axross-full, axross-slim, pip |
| [libxcrypt](https://github.com/besser82/libxcrypt) | libpq | LGPL-2.1-or-later | axross-full, axross-slim, pip (with an extra) |
| [Little CMS](https://www.littlecms.com) | Pillow | MIT | axross-full, axross-slim, pip |
| [lxml](https://github.com/lxml/lxml) | exchangelib | BSD-3-Clause | axross-full, pip (with an extra) |
| [MarkupSafe](https://github.com/pallets/markupsafe) | Flask | BSD-3-Clause | axross-full, pip (with an extra) |
| [more-itertools](https://github.com/more-itertools/more-itertools) | jaraco.classes | MIT | axross-full, axross-slim, pip |
| [multivolumefile](https://github.com/miurahr/multivolume) | py7zr | LGPL-2.1-or-later | axross-full, axross-slim, pip (with an extra) |
| [Nettle](https://www.lysator.liu.se/~nisse/nettle/) | PyAV | LGPL-3.0-or-later OR GPL-2.0-or-later | axross-full, pip (with an extra) |
| [oauthlib](https://github.com/oauthlib/oauthlib) | exchangelib | BSD-3-Clause | axross-full, pip (with an extra) |
| [OpenBLAS](https://github.com/OpenMathLib/OpenBLAS) | numpy | BSD-3-Clause | axross-full, pip (with an extra) |
| [OpenJPEG](https://www.openjpeg.org) | Pillow | BSD-2-Clause | axross-full, axross-slim, pip |
| [OpenLDAP client libraries](https://www.openldap.org) | libpq | OLDAP-2.8 | axross-full, axross-slim, pip (with an extra) |
| [opentelemetry-api](https://github.com/open-telemetry/opentelemetry-python) | google-api-core | Apache-2.0 | axross-full, axross-slim, pip (with an extra) |
| [Opus](https://opus-codec.org) | PyAV | BSD-3-Clause | axross-full, pip (with an extra) |
| [packaging](https://github.com/pypa/packaging) | onnxruntime | Apache-2.0 OR BSD-2-Clause | axross-full, pip (with an extra) |
| [pathvalidate](https://github.com/thombashi/pathvalidate) | piper-tts | MIT | axross-full, pip (with an extra) |
| [protobuf](https://github.com/protocolbuffers/protobuf) | onnxruntime | BSD-3-Clause | axross-full, pip (with an extra) |
| [psutil](https://github.com/giampaolo/psutil) | py7zr | BSD-3-Clause | axross-full, axross-slim, pip (with an extra) |
| [pyasn1](https://github.com/pyasn1/pyasn1) | adb_shell | BSD-2-Clause | axross-full, axross-slim, pip (with an extra) |
| [pyasn1_modules](https://github.com/pyasn1/pyasn1-modules) | impacket | BSD-2-Clause | axross-full, pip (with an extra) |
| [PyAV](https://github.com/PyAV-Org/PyAV) | faster-whisper | BSD-3-Clause | axross-full, pip (with an extra) |
| [pybcj](https://github.com/miurahr/pybcj) | py7zr | LGPL-2.1-or-later | axross-full, axross-slim, pip (with an extra) |
| [pycparser](https://github.com/eliben/pycparser) | cffi | BSD-3-Clause | axross-full, axross-slim, pip |
| [pycryptodomex](https://github.com/Legrandin/pycryptodome) | impacket | BSD-2-Clause AND LicenseRef-PublicDomain | axross-full, axross-slim, pip (with an extra) |
| [PyJWT](https://github.com/jpadilla/pyjwt) | msal | MIT | axross-full, axross-slim, pip (with an extra) |
| [PyNaCl](https://github.com/pyca/pynacl) | paramiko | Apache-2.0 | axross-full, axross-slim, pip |
| [pyOpenSSL](https://github.com/pyca/pyopenssl) | impacket | Apache-2.0 | axross-full, axross-slim, pip (with an extra) |
| [pyparsing](https://github.com/pyparsing/pyparsing) | httplib2 | MIT | axross-full, pip (with an extra) |
| [pyppmd](https://github.com/miurahr/pyppmd) | py7zr | LGPL-2.1-or-later | axross-full, axross-slim, pip (with an extra) |
| [PyQt6_sip](https://github.com/Python-SIP/sip) | PyQt6 | BSD-2-Clause | axross-full, axross-slim, pip |
| [pyspnego](https://github.com/jborean93/pyspnego) | smbprotocol | MIT | axross-full, axross-slim, pip (with an extra) |
| [python-dateutil](https://github.com/dateutil/dateutil) | botocore | Apache-2.0 AND BSD-3-Clause | axross-full, axross-slim, pip (with an extra) |
| [PyYAML](https://github.com/yaml/pyyaml) | ctranslate2 | MIT | axross-full, axross-slim, pip (with an extra) |
| [Qt 6](https://www.qt.io) | PyQt6 | LGPL-3.0-only | axross-full, axross-slim, pip |
| [referencing](https://github.com/python-jsonschema/referencing) | jsonschema | MIT | axross-full, axross-slim |
| [requests-oauthlib](https://github.com/requests/requests-oauthlib) | exchangelib | ISC | axross-full, pip (with an extra) |
| [requests_ntlm](https://github.com/requests/requests-ntlm) | exchangelib | ISC | axross-full, pip (with an extra) |
| [rpds-py](https://github.com/crate-py/rpds) | jsonschema | MIT | axross-full, axross-slim |
| [rsa](https://github.com/sybrenstuvel/python-rsa) | adb_shell | Apache-2.0 | axross-full, axross-slim, pip (with an extra) |
| [s3transfer](https://github.com/boto/s3transfer) | boto3 | Apache-2.0 | axross-full, axross-slim, pip (with an extra) |
| [SecretStorage](https://github.com/mitya57/secretstorage) | keyring | BSD-3-Clause | axross-full, axross-slim, pip |
| [six](https://github.com/benjaminp/six) | impacket | MIT | axross-full, axross-slim, pip (with an extra) |
| [stone](https://github.com/dropbox/stone) | dropbox | MIT | axross-full, pip (with an extra) |
| [SVT-AV1](https://gitlab.com/AOMediaCodec/SVT-AV1) | PyAV | BSD-3-Clause-Clear | axross-full, pip (with an extra) |
| [tokenizers](https://github.com/huggingface/tokenizers) | faster-whisper | Apache-2.0 | axross-full, pip (with an extra) |
| [tqdm](https://github.com/tqdm/tqdm) | faster-whisper | MPL-2.0 AND MIT | axross-full, pip (with an extra) |
| [truststore](https://github.com/sethmlarson/truststore) | httpcore2 | MIT | axross-full, axross-slim, pip (with an extra) |
| [typing_extensions](https://github.com/python/typing_extensions) | azure-storage-blob | PSF-2.0 | axross-full, axross-slim, pip |
| [tzdata](https://github.com/python/tzdata) | exchangelib | Apache-2.0 | axross-full, pip (with an extra) |
| [tzlocal](https://github.com/regebro/tzlocal) | exchangelib | MIT | axross-full, pip (with an extra) |
| [uritemplate](https://github.com/python-hyper/uritemplate) | google-api-python-client | BSD-3-Clause OR Apache-2.0 | axross-full, pip (with an extra) |
| [VMAF](https://github.com/Netflix/vmaf) | PyAV | BSD-2-Clause-Patent | axross-full, pip (with an extra) |
| [Werkzeug](https://github.com/pallets/werkzeug) | Flask | BSD-3-Clause | axross-full, pip (with an extra) |
| [x264](https://www.videolan.org/developers/x264.html) | PyAV | GPL-2.0-or-later | axross-full, pip (with an extra) |
| [x265](https://bitbucket.org/multicoreware/x265_git) | PyAV | GPL-2.0-or-later | axross-full, pip (with an extra) |
| [xmltodict](https://github.com/martinblech/xmltodict) | pywinrm | MIT | axross-full, pip (with an extra) |

</details>
<!-- /third-party:readme -->
