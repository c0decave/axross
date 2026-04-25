# Axross

A flexible multi-protocol file manager built with Python and PyQt6.
Browse, transfer, and manage files across SFTP, SMB, S3, WebDAV,
the major cloud drives, and 16 other protocols — all from a single
Total-Commander-style interface with split panes, a transfer queue,
and an integrated SSH terminal.

Languages: **English** · [Deutsch](README_de.md) · [Español](README_es.md)

## What it does

- **22 protocols, one UI.** SFTP, SCP, FTP/FTPS, SMB/CIFS, WebDAV,
  S3-compatible, Rsync, NFS, Azure Blob/Files, OneDrive, SharePoint,
  Google Drive, Dropbox, iSCSI, IMAP, Telnet, WinRM, WMI/DCOM,
  Exchange (EWS), DFS-N, ADB, MTP.
- **Multi-pane workflow.** Open as many panes as you like, split
  horizontal/vertical, drag-and-drop between any two — including
  cross-protocol relay transfers.
- **Backend-agnostic primitives.** Universal trash, atomic writes,
  encrypted overlays, snapshot timeline, content-addressable
  storage, archive extraction with zip-bomb / zip-slip guards.
- **MCP server mode.** Expose any backend as a JSON-RPC tool surface
  so an LLM client (Claude Desktop, Cline, a custom agent) can drive
  it. Read-only by default; opt-in `--mcp-write` for mutations.

## Quick start

```bash
git clone https://github.com/c0decave/axross
cd axross
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
axross
```

Base install pulls only what the always-available protocols need
(SFTP, SCP, FTP/FTPS, Telnet, IMAP). Install the rest as extras:

```bash
pip install -e ".[smb]"          # SMB / CIFS + DFS-N
pip install -e ".[s3]"           # S3-compatible
pip install -e ".[onedrive]"     # OneDrive + SharePoint
pip install -e ".[gdrive]"       # Google Drive
pip install -e ".[dropbox]"      # Dropbox
pip install -e ".[all]"          # everything light-weight at once
```

Full table of extras + system tools per protocol: **[INSTALL.md](INSTALL.md)**.

## Documentation

| Document | What it covers |
|---|---|
| [INSTALL.md](INSTALL.md) | Prerequisites, per-protocol extras, OAuth setup, wheel build, dev setup. |
| [docs/USAGE.md](docs/USAGE.md) · [USAGE_de.md](docs/USAGE_de.md) · [USAGE_es.md](docs/USAGE_es.md) | User guide — connections, panes, transfers, terminal, right-click actions. |
| [docs/HANDBUCH.md](docs/HANDBUCH.md) | Full German manual (workflows, dialog reference, keyboard shortcuts). |
| [docs/MCP.md](docs/MCP.md) · [MCP_de.md](docs/MCP_de.md) · [MCP_es.md](docs/MCP_es.md) | MCP server reference — tools, sessions, mTLS, hardening. |
| [docs/OPSEC.md](docs/OPSEC.md) | Threat model + per-finding analysis of what the client reveals to servers. |
| [OAUTH_SETUP.md](OAUTH_SETUP.md) | OneDrive / SharePoint / Google Drive / Dropbox app registration recipes. |
| [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) | Test suite, Docker lab, protocol coverage matrix. |
| [docs/PROXY_SUPPORT.md](docs/PROXY_SUPPORT.md) | SOCKS5 / SOCKS4 / HTTP-CONNECT per protocol. |
| [docs/PACKAGING.md](docs/PACKAGING.md) | PyInstaller bundle, AppImage, headless MCP Docker image. |
| [SECURITY.md](SECURITY.md) | Vulnerability disclosure policy. |
| [CONTRIBUTING.md](CONTRIBUTING.md) | PR scope, code style, contribution licensing. |

## Highlights

- **First-class atomicity.** Writes go to a temp sibling and rename
  on commit. On S3, Azure, Dropbox, GDrive, OneDrive, IMAP, Rsync the
  underlying upload is already atomic; on the rest the rename is the
  commit point.
- **Honest test coverage.** The protocol coverage matrix in
  [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) tells you exactly which
  backends are exercised against real implementations vs. mocked vs.
  untested. No green-CI theatre.
- **OpSec-aware defaults.** Identifiable client banners blended into
  the OpenSSH / Firefox-ESR mainstream; rsync uploads strip local
  uid/gid/perms by default; per-profile overrides for SSH keepalive,
  SMB workstation name, Telnet NAWS. Full breakdown in
  [docs/OPSEC.md](docs/OPSEC.md).
- **MCP-ready.** Headless `axross --mcp-server` exposes the
  configured backend as JSON-RPC tools (stdio or HTTP+mTLS).
  17 tools, per-session rate limits, SSE progress streaming.

## Contributing

Pull requests welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). Security
reports: [SECURITY.md](SECURITY.md).

## License

Axross source is licensed under the **Apache License 2.0** — see
[LICENSE](LICENSE), [NOTICE](NOTICE), and per-dependency attribution
in [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).

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
