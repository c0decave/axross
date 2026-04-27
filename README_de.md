<p align="center">
  <img src="resources/logo/axross-logo-256.png" alt="Axross" width="160"/>
</p>

# Axross

**Eine UI, 30+ Protokolle, ein eingebetteter Python-REPL, und eine
MCP-Tool-Oberfläche, mit der ein LLM das Ganze fernsteuern kann.**

Axross ist ein Multi-Protokoll-Dateimanager und Security-Toolkit auf
Basis von Python und PyQt6. SFTP, SMB, S3, WebDAV, Cloud-Drives, IMAP,
Usenet, Cisco IOS, Drucker-FS, BSD r-services — alle in derselben
Split-Pane-UI, alle aufrufbar über dieselbe `axross.*`-Python-API,
alle erreichbar über MCP für einen LLM-Agenten.

Sprachen: [English](README.md) · **Deutsch** · [Español](README_es.md)

---

## 15 Highlights

1. **30+ Protokolle, eine konsistente UI.** SFTP/SCP, FTP/FTPS,
   SMB/CIFS, WebDAV, S3-kompatibel, Rsync, NFS, Azure Blob/Files,
   OneDrive, SharePoint, Google Drive, Dropbox, iSCSI, IMAP, POP3,
   TFTP, Telnet, WinRM, WMI/DCOM, Exchange (EWS), DFS-N, ADB, MTP,
   **Gopher (RFC 1436)**, **NNTP / Usenet** (eigene Wire-Lib,
   Python-3.13-tauglich — stdlib `nntplib` ist weg), **SQLite-FS /
   PostgreSQL-FS / Redis-FS / MongoDB GridFS**, **Git als FS
   (dulwich)**, **PJL Drucker-FS** mit verpflichtender Safety-Probe,
   **SLP (RFC 2608)** read-only Discovery, **rsh / rcp** Legacy-
   Plaintext, **Cisco IOS Telnet** mit `/show/<cmd>.txt`-virtueller
   Datei, plus **RAM-only volatiler Workspace** (RamFS).

2. **Total-Commander-style Multi-Pane.** Beliebig viele Panes,
   horizontal/vertikal teilen, Drag-and-Drop zwischen jeglichen zwei
   Panes — inklusive **Cross-Protocol-Relay-Transfers** (S3 → SFTP,
   WebDAV → Rsync, …) ohne Disk-Staging.

3. **Layout-Presets mit Cycle-Hotkey.** Eingebaut:
   `single`, `dual`, `quad-files`, `commander`, `dev-shells`,
   `triage`, `shells-quad`. `Strg+Alt+L` rotiert vorwärts,
   `Strg+Alt+Shift+L` zurück.

4. **Eingebetteter Python-REPL mit 35+ Scripting-Verben.** Console-
   Dock unten in der GUI, kuratierte `axross.*`-API, persistente
   History, side-effect-freies Tab-Completion (keine zufällig
   gefeuerten `@property`-Getter), Slash-Commands `.save / .load /
   .run / .scripts / .delete`. Siehe
   [docs/SCRIPTING_de.md](docs/SCRIPTING_de.md).

5. **Inline-Doc-Pane mit Tabs.** Direkt neben dem REPL — vier Tabs:
   `API` (jede `axross.*`-Funktion mit Suchleiste + voller
   Docstring), `Slash` (alle Slash-Commands), `Scripts` (alle 22
   mitgelieferten Skripte), `Protocol` (das `FileBackend`-Interface,
   das jedes Backend implementiert).

6. **22 fertige Skripte.** Mirror, Dedupe, Find-Secrets, Port-Scan,
   SLP-Inventory, Cisco-IOS-Sammlung, IMAP-Archiv, sha256-Diff,
   Bookmarks-Export, … — unter [`resources/scripts/`](resources/scripts/),
   jedes startbar via `axross --script` oder REPL-Slash `.run name`.

7. **MCP-Server-Modus für LLM-Agenten.** Headless `axross
   --mcp-server` spricht JSON-RPC über stdio oder HTTPS+mTLS.
   Read-only per Default; `--mcp-write` öffnet die Datei-Mutation;
   **`--mcp-allow-scripts` lässt das LLM eigene Python-Skripte
   schreiben und ausführen** über den Server. Siehe
   [docs/MCP_de.md](docs/MCP_de.md).

8. **Verschlüsselter Overlay (`.axenc`).** AEAD-versiegeltes Datei-
   format, das auf jedem Backend liegen kann. Entschlüsseln direkt
   in RamFS — Klartext landet nie auf der Disk. Das Skript
   `redact.py` verschlüsselt jede Datei unter einem Pfad, die einem
   Regex matched.

9. **OPSEC-bewusste Defaults.** Per-Profile Shell-History-
   Suppression (zsh + bash + dash, abschaltbar), Plaintext-Credential-
   Warnungen bei jeder Legacy-Session (Telnet, rsh, NNTP-on-119),
   Client-Banner getarnt als OpenSSH / Firefox-ESR, verpflichtende
   PJL-Safety-Probe (keine zufällig ausgedruckten Bytes auf einem
   Nicht-PJL-Drucker). Vollständig in [docs/OPSEC.md](docs/OPSEC.md).

10. **CVE-frei by design.** SLP-Backend baut nie ein `SrvReg`-Paket
    — der SLP-Amplification-Pfad
    ([CVE-2023-29552](https://curesec.com/blog/article/CVE-2023-29552-Service-Location-Protocol-Denial-of-Service-Amplification-Attack-212.html))
    ist strukturell unmöglich. Multicast-Ziele werden auf Socket-
    Ebene hart verweigert.

11. **SSRF-Guard auf jedem Proxy-Hop.** Default-deny gegen
    Cloud-Metadata-Endpoints (169.254.169.254 + AWS-IMDS-Varianten)
    und RFC1918-Ranges; Opt-in via `AXROSS_ALLOW_PRIVATE_PROXY=1`,
    wenn man wirklich durch ein internes LAN proxy-en will.

12. **Universeller SOCKS5 / HTTP-CONNECT.** Jedes TCP-basierte
    Backend nutzt dieselbe `core.proxy`-Maschinerie — SSH, Telnet,
    FTP, IMAP, POP3, WebDAV, S3, Gopher, NNTP, rsh, Cisco-Telnet.
    Siehe [docs/PROXY_SUPPORT.md](docs/PROXY_SUPPORT.md).

13. **Backend-agnostische Primitive.** Universeller Trash, atomic
    writes (Temp-Sibling + Rename), Snapshot-Timeline, Content-
    addressable Storage, Archiv-Extraktion mit Zip-Bomb / Zip-Slip-
    Schutz — alles uniform über jedes Backend.

14. **Pure-Python wo möglich.** Eigene NNTP-Wire-Lib, eigene WebDAV-
    Implementation (kein Drittanbieter-SDK), eigener SLPv2-Packet-
    Builder, eigener Gopher-Reader. Kleinerer Dep-Tree, kein SDK-
    Lock-in, keine Python-3.13-Überraschung wenn stdlib-Module
    verschwinden.

15. **Headless und GUI aus derselben Quelle.** PyQt6-Dateimanager,
    MCP-stdio/HTTP-Server, oder `axross --script <datei>`-CLI-
    Runner. AppImage + Docker-Images auf der Release-Page; das
    `Dockerfile.mcp`-Image schließt PyQt6 explizit aus, um
    copyleft-frei zu bleiben.

---

## Schnellstart

```bash
git clone https://github.com/c0decave/axross
cd axross
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
axross              # GUI starten
axross --mcp-server # oder Backends als MCP-Tools an einen LLM ausliefern
```

```python
# Aus dem eingebetteten REPL — Console-Dock unten im Fenster
>>> b = axross.open_url("sftp://alice@example.com/")
>>> for f in b.list_dir("/var/log")[:5]:
...     print(f.name, f.size)
>>> axross.copy(b, "/etc/motd", axross.localfs(), "/tmp/motd")
>>> axross.help()         # oder rechts auf den Doc-Pane klicken
```

Vollständige Tabelle der Extras + System-Tools pro Protokoll:
**[INSTALL.md](INSTALL.md)**.

---

## Dokumentation

| Dokument | Inhalt |
|---|---|
| [INSTALL.md](INSTALL.md) | Voraussetzungen, Per-Protokoll-Extras, OAuth-Setup, Wheel-Build, Dev-Setup. |
| [docs/USAGE.md](docs/USAGE.md) · [USAGE_de.md](docs/USAGE_de.md) · [USAGE_es.md](docs/USAGE_es.md) | Benutzerhandbuch — Verbindungen, Panes, Transfers, Terminal, Rechtsklick-Aktionen. |
| [docs/SCRIPTING.md](docs/SCRIPTING.md) · [SCRIPTING_de.md](docs/SCRIPTING_de.md) · [SCRIPTING_es.md](docs/SCRIPTING_es.md) | REPL + `axross.*`-API + Slash-Commands + 22 mitgelieferte Skripte + MCP-Scripting-Tools. |
| [docs/SCRIPTING_REFERENCE.md](docs/SCRIPTING_REFERENCE.md) | Auto-generierte Volldoku jeder Funktion mit Signatur + komplettem Docstring. |
| [docs/MCP.md](docs/MCP.md) · [MCP_de.md](docs/MCP_de.md) · [MCP_es.md](docs/MCP_es.md) | MCP-Server-Referenz — Tools, Sessions, mTLS, Rate-Limits, Hardening. |
| [docs/HANDBUCH.md](docs/HANDBUCH.md) | Vollständiges deutsches Handbuch (Workflows, Dialog-Referenz, Tastenkürzel). |
| [docs/OPSEC.md](docs/OPSEC.md) | Threat-Model + per-Finding-Analyse, was der Client an Server preisgibt. |
| [docs/PROXY_SUPPORT.md](docs/PROXY_SUPPORT.md) | SOCKS5 / SOCKS4 / HTTP-CONNECT pro Protokoll. |
| [OAUTH_SETUP.md](OAUTH_SETUP.md) | OneDrive / SharePoint / Google Drive / Dropbox App-Registration-Rezepte. |
| [docs/RED_TEAM_NOTES.md](docs/RED_TEAM_NOTES.md) | Adversariale Review jedes Backends — gefixte Findings, akzeptierte Risiken, offene Follow-ups. |
| [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) | Test-Suite, Docker-Lab, Protokoll-Coverage-Matrix. |
| [docs/PACKAGING.md](docs/PACKAGING.md) | PyInstaller-Bundle, AppImage, headless MCP-Docker-Image. |
| [SECURITY.md](SECURITY.md) | Vulnerability-Disclosure-Policy. |
| [CONTRIBUTING.md](CONTRIBUTING.md) | PR-Scope, Code-Style, Contribution-Lizenzierung. |

---

## Mitwirken

Pull-Requests willkommen — siehe [CONTRIBUTING.md](CONTRIBUTING.md).
Security-Reports: [SECURITY.md](SECURITY.md).

## Lizenz

Axross-Quellcode ist **Apache License 2.0** — siehe [LICENSE](LICENSE),
[NOTICE](NOTICE), und Per-Dependency-Attributionen in
[THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).

Drei Distributions-Layer zum Beachten:

1. **Source-Tree** (dieses Repo) — Apache-2.0. PyQt6 installiert
   der Nutzer selbst per `pip install`; kein GPL-Bestandteil im
   Source-Tree.
2. **Vorgebaute PyInstaller-Bundles** (`dist/axross-slim`,
   `dist/axross-full`, das AppImage) — linken PyQt6 statisch, das
   ist GPL-3.0-or-commercial von Riverbank. Jedes solche von uns
   weiterverteilte Binary wird daher unter **GPL-3.0** angeboten.
   Für ein Nicht-GPL-Binary gegen PySide6 (LGPL-3.0) aus derselben
   Apache-2.0-Quelle bauen.
3. **`Dockerfile.mcp`** — schließt PyQt6 explizit aus; das
   resultierende Image ist Apache-2.0-only, keine Copyleft-Vererbung.

Copyright © 2026 Marco Lux.
