# Axross

Ein flexibler Multi-Protokoll-Dateimanager mit Python und PyQt6.
Browse, transferiere und verwalte Dateien über SFTP, SMB, S3,
WebDAV, die großen Cloud-Drives und 16 weitere Protokolle — alles
in einer Total-Commander-artigen Oberfläche mit Split-Panes,
Transfer-Queue und integriertem SSH-Terminal.

Sprachen: [English](README.md) · **Deutsch** · [Español](README_es.md)

## Was es macht

- **22 Protokolle, ein UI.** SFTP, SCP, FTP/FTPS, SMB/CIFS, WebDAV,
  S3-kompatibel, Rsync, NFS, Azure Blob/Files, OneDrive, SharePoint,
  Google Drive, Dropbox, iSCSI, IMAP, Telnet, WinRM, WMI/DCOM,
  Exchange (EWS), DFS-N, ADB, MTP.
- **Multi-Pane-Workflow.** Beliebig viele Panes, horizontal/vertikal
  gesplittet, Drag-and-Drop zwischen je zwei Panes — auch
  cross-Protokoll als Relay-Transfer.
- **Backend-agnostische Primitives.** Universaler Papierkorb,
  atomare Schreibvorgänge, verschlüsselte Overlays, Versions-
  Timeline, Content-Addressable-Storage, Archiv-Entpackung mit
  Zip-Bomb- / Zip-Slip-Guards.
- **MCP-Server-Modus.** Exponiert jedes Backend als JSON-RPC-Tool-
  Surface, sodass ein LLM-Client (Claude Desktop, Cline, ein
  eigener Agent) es steuern kann. Read-only by default; opt-in
  `--mcp-write` für Mutationen.

## Quick Start

```bash
git clone https://github.com/c0decave/axross
cd axross
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
axross
```

Der Base-Install zieht nur das, was die immer-verfügbaren Protokolle
brauchen (SFTP, SCP, FTP/FTPS, Telnet, IMAP). Den Rest als Extras
nachziehen:

```bash
pip install -e ".[smb]"          # SMB / CIFS + DFS-N
pip install -e ".[s3]"           # S3-kompatibel
pip install -e ".[onedrive]"     # OneDrive + SharePoint
pip install -e ".[gdrive]"       # Google Drive
pip install -e ".[dropbox]"      # Dropbox
pip install -e ".[all]"          # alles Leichtgewichtige auf einmal
```

Vollständige Tabelle Extras + System-Tools pro Protokoll:
**[INSTALL.md](INSTALL.md)**.

## Dokumentation

| Dokument | Was es abdeckt |
|---|---|
| [INSTALL.md](INSTALL.md) | Voraussetzungen, Per-Protokoll-Extras, OAuth-Setup, Wheel-Build, Dev-Setup. |
| [docs/USAGE_de.md](docs/USAGE_de.md) · [USAGE.md](docs/USAGE.md) · [USAGE_es.md](docs/USAGE_es.md) | Bedienung — Verbindungen, Panes, Transfers, Terminal, Rechtsklick-Aktionen. |
| [docs/HANDBUCH.md](docs/HANDBUCH.md) | Volles deutsches Handbuch (Workflows, Dialog-Referenz, Tastenkürzel). |
| [docs/MCP_de.md](docs/MCP_de.md) · [MCP.md](docs/MCP.md) · [MCP_es.md](docs/MCP_es.md) | MCP-Server-Referenz — Tools, Sessions, mTLS, Hardening. |
| [docs/OPSEC.md](docs/OPSEC.md) | Threat-Modell + per-Finding-Analyse, was der Client an den Server verrät. |
| [OAUTH_SETUP.md](OAUTH_SETUP.md) | OneDrive / SharePoint / Google Drive / Dropbox App-Registrierung. |
| [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) | Test-Suite, Docker-Lab, Protokoll-Coverage-Matrix. |
| [docs/PROXY_SUPPORT.md](docs/PROXY_SUPPORT.md) | SOCKS5 / SOCKS4 / HTTP-CONNECT pro Protokoll. |
| [docs/PACKAGING.md](docs/PACKAGING.md) | PyInstaller-Bundle, AppImage, Headless-MCP-Docker-Image. |
| [SECURITY.md](SECURITY.md) | Vulnerability-Disclosure-Policy. |
| [CONTRIBUTING.md](CONTRIBUTING.md) | PR-Scope, Code-Style, Contribution-Lizenzierung. |

## Highlights

- **First-class Atomicity.** Schreibvorgänge gehen in eine Sibling-
  Tempdatei und werden beim Commit reingerannt. Auf S3, Azure,
  Dropbox, GDrive, OneDrive, IMAP, Rsync ist der Upload selbst
  atomar; sonst ist der Rename der Commit-Punkt.
- **Ehrliche Test-Coverage.** Die Protokoll-Coverage-Matrix in
  [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) sagt dir exakt, welche
  Backends gegen echte Implementierungen vs. Mock vs. ungetestet
  laufen. Kein grüne-CI-Theater.
- **OpSec-aware Defaults.** Identifizierbare Client-Banner blenden
  in die OpenSSH-/Firefox-ESR-Mehrheit ein; rsync-Uploads strippen
  lokale uid/gid/Permissions by default; Per-Profil-Overrides für
  SSH-Keepalive, SMB-Workstation-Name, Telnet-NAWS. Volle
  Auflistung: [docs/OPSEC.md](docs/OPSEC.md).
- **MCP-ready.** Headless `axross --mcp-server` exponiert das
  konfigurierte Backend als JSON-RPC-Tools (stdio oder HTTP+mTLS).
  17 Tools, Per-Session-Rate-Limits, SSE-Progress-Streaming.

## Mitwirken

Pull Requests willkommen — siehe [CONTRIBUTING.md](CONTRIBUTING.md).
Security-Reports: [SECURITY.md](SECURITY.md).

## Lizenz

Der Axross-Quellcode steht unter der **Apache License 2.0** — siehe
[LICENSE](LICENSE), [NOTICE](NOTICE), und Per-Dependency-Attribution
in [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).

Drei Distributionsebenen sind zu unterscheiden:

1. **Source-Tree** (dieses Repo) — Apache-2.0. Nutzer installieren
   PyQt6 selbst per `pip`; im Source-Tree ist keine GPL-Komponente
   gebündelt.
2. **Vorgefertigte PyInstaller-Bundles** (`dist/axross-slim`,
   `dist/axross-full`, AppImage) — enthalten PyQt6 statisch; PyQt6
   ist GPL-3.0-oder-kommerziell (Riverbank). Solche Bundles werden
   daher unter **GPL-3.0** verteilt. Für ein Non-GPL-Binary baue
   die gleiche Apache-2.0-Source gegen PySide6 (LGPL-3.0).
3. **`Dockerfile.mcp`** — enthält bewusst kein PyQt6; das
   resultierende Image ist Apache-2.0 only, keine Copyleft-Vererbung.

Copyright © 2026 Marco Lux.
