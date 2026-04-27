<p align="center">
  <img src="resources/logo/axross-logo-256.png" alt="Axross" width="160"/>
</p>

# Axross

**One UI, 30+ protocols, an embedded Python REPL, and an MCP tool
surface so an LLM can drive the whole thing.**

Axross is a multi-protocol file manager and security toolkit built
with Python and PyQt6. SFTP, SMB, S3, WebDAV, Cloud drives, IMAP,
Usenet, Cisco IOS, printer-FS, BSD r-services — all in the same
split-pane UI, all callable from the same `axross.*` Python API,
all reachable through MCP for an LLM agent.

Languages: **English** · [Deutsch](README_de.md) · [Español](README_es.md)

---

## 15 highlights

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

4. **Embedded Python REPL with 35+ scripting verbs.** A Console dock
   at the bottom of the GUI, a curated `axross.*` API, persistent
   history, side-effect-free Tab completion (no `@property` getters
   fired by accident), and slash-commands `.save / .load / .run /
   .scripts / .delete`. See [docs/SCRIPTING.md](docs/SCRIPTING.md).

5. **Inline searchable doc pane.** Right next to the REPL — every
   public `axross.*` function listed by topic, click any to read its
   signature and docstring. Filter live as you type.

6. **22 ready-to-use scripts.** Mirror, dedupe, find-secrets, port-scan,
   SLP inventory, Cisco IOS collection, IMAP archive, sha256-diff,
   bookmarks export, … — under
   [`resources/scripts/`](resources/scripts/), all runnable via
   `axross --script` or the REPL `.run` slash-command.

7. **MCP server mode for LLM agents.** Headless `axross --mcp-server`
   speaks JSON-RPC over stdio or HTTPS+mTLS. Read-only by default;
   `--mcp-write` enables file mutations; `--mcp-allow-scripts` lets
   the LLM **write and run its own Python** through the server. See
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

10. **CVE-mitigated by design.** SLP backend never builds a `SrvReg`
    packet — the SLP amplification path
    ([CVE-2023-29552](https://curesec.com/blog/article/CVE-2023-29552-Service-Location-Protocol-Denial-of-Service-Amplification-Attack-212.html))
    is structurally impossible. Multicast targets are hard-refused
    at the socket layer.

11. **SSRF guard on every proxy hop.** Default-deny against
    cloud-metadata endpoints (169.254.169.254 + AWS IMDS variants)
    and RFC1918 ranges; opt-in via `AXROSS_ALLOW_PRIVATE_PROXY=1`
    when you genuinely need to proxy through a private LAN.

12. **Universal SOCKS5 / HTTP-CONNECT.** Every TCP-based backend
    routes through the same `core.proxy` machinery — SSH, Telnet,
    FTP, IMAP, POP3, WebDAV, S3, Gopher, NNTP, rsh, Cisco-Telnet.
    See [docs/PROXY_SUPPORT.md](docs/PROXY_SUPPORT.md).

13. **Backend-agnostic primitives.** Universal trash, atomic writes
    (temp sibling + rename), snapshot timeline, content-addressable
    storage, archive extraction with zip-bomb / zip-slip guards —
    all uniform across every backend.

14. **Pure-Python where possible.** Own NNTP wire-lib, own WebDAV
    impl (no third-party SDK), own SLPv2 packet builder, own Gopher
    reader. Smaller dep tree, no SDK lock-in, no Python-3.13 surprise
    when stdlib modules disappear.

15. **Headless and GUI from the same source.** PyQt6 file manager,
    MCP stdio/HTTP server, or `axross --script <file>` CLI runner.
    AppImage + Docker images on the release page; the `Dockerfile.mcp`
    image specifically excludes PyQt6 to stay copyleft-free.

---

## Quick start

```bash
git clone https://github.com/c0decave/axross
cd axross
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
axross              # start the GUI
axross --mcp-server # or expose backends as MCP tools to an LLM
```

```python
# from the embedded REPL — Console dock, bottom of the window
>>> b = axross.open_url("sftp://alice@example.com/")
>>> for f in b.list_dir("/var/log")[:5]:
...     print(f.name, f.size)
>>> axross.copy(b, "/etc/motd", axross.localfs(), "/tmp/motd")
>>> axross.help()         # or click the doc pane on the right
```

Base install pulls only what the always-available protocols need
(SFTP, SCP, FTP/FTPS, Telnet, IMAP). Install per-protocol extras:

```bash
pip install -e ".[smb]"          # SMB / CIFS + DFS-N
pip install -e ".[s3]"           # S3-compatible (boto3)
pip install -e ".[webdav]"       # WebDAV (requests + defusedxml)
pip install -e ".[onedrive]"     # OneDrive + SharePoint (msal)
pip install -e ".[gdrive]"       # Google Drive
pip install -e ".[dropbox]"      # Dropbox
pip install -e ".[postgres]"     # PostgreSQL-as-FS
pip install -e ".[redis]"        # Redis-as-FS
pip install -e ".[mongo]"        # MongoDB GridFS
pip install -e ".[git]"          # Git-as-FS via dulwich
pip install -e ".[all]"          # everything light-weight at once
```

Full table of extras + system tools per protocol:
**[INSTALL.md](INSTALL.md)**.

---

## Documentation

| Document | What it covers |
|---|---|
| [INSTALL.md](INSTALL.md) | Prerequisites, per-protocol extras, OAuth setup, wheel build, dev setup. |
| [docs/USAGE.md](docs/USAGE.md) · [USAGE_de.md](docs/USAGE_de.md) · [USAGE_es.md](docs/USAGE_es.md) | User guide — connections, panes, transfers, terminal, right-click actions. |
| [docs/SCRIPTING.md](docs/SCRIPTING.md) · [SCRIPTING_de.md](docs/SCRIPTING_de.md) · [SCRIPTING_es.md](docs/SCRIPTING_es.md) | REPL + `axross.*` API + slash-commands + 22 bundled scripts + MCP scripting tools. |
| [docs/MCP.md](docs/MCP.md) · [MCP_de.md](docs/MCP_de.md) · [MCP_es.md](docs/MCP_es.md) | MCP server reference — tools, sessions, mTLS, rate limits, hardening. |
| [docs/HANDBUCH.md](docs/HANDBUCH.md) | Full German manual (workflows, dialog reference, keyboard shortcuts). |
| [docs/OPSEC.md](docs/OPSEC.md) | Threat model + per-finding analysis of what the client reveals to servers. |
| [docs/PROXY_SUPPORT.md](docs/PROXY_SUPPORT.md) | SOCKS5 / SOCKS4 / HTTP-CONNECT per protocol. |
| [OAUTH_SETUP.md](OAUTH_SETUP.md) | OneDrive / SharePoint / Google Drive / Dropbox app registration recipes. |
| [docs/RED_TEAM_NOTES.md](docs/RED_TEAM_NOTES.md) | Adversarial review of every backend — fixed findings, known-acceptable risks, open follow-ups. |
| [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) | Test suite, Docker lab, protocol coverage matrix. |
| [docs/PACKAGING.md](docs/PACKAGING.md) | PyInstaller bundle, AppImage, headless MCP Docker image. |
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
