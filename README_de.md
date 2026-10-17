<p align="center">
  <img src="resources/logo/axross-logo-256.png" alt="Axross" width="160"/>
</p>

# Axross

**Eine UI, 30+ Protokolle, ein eingebetteter Python-REPL, und eine
MCP-Tool-Oberfläche, mit der ein LLM das Ganze fernsteuern kann.**

- **30+ Protokolle in einem Fenster** — SFTP, SMB, S3, WebDAV, Cloud-Drives, IMAP, Git, Datenbanken und mehr.
- **Kopieren zwischen beliebigen Backends** — S3 → SFTP, WebDAV → SMB, direkt, ohne Umweg über die lokale Platte.
- **Multi-Pane-Layout im Commander-Stil** — beliebig viele Split-Panes, Layout-Presets, Drag & Drop.
- **Eingebautes Python-Scripting** — REPL, Scripts-Dock und 32 fertige Scripts auf einer `axross.*`-API.
- **LLM-Agent eingebaut** — Agent-Dock mit Tabs und Sandboxes, MCP über stdio oder HTTP, read-only per Default.
- **Duplikate finden, Metadaten entfernen** — Duplicate Finder per Content-Hash, EXIF/GPS raus vor dem Teilen.
- **Verschlüsselung ohne Klartext auf der Platte** — `.axenc`-Overlay auf jedem Backend, entschlüsselt nur in den RAM.
- **Sicher per Default** — Preview vor Delete/Move, Operation-Journal, `paranoid` Mode, Proxies mit SSRF-Guard.
- **Resumable Transfers** — überstehen Ctrl-C und VPN-Abbrüche, weiter ab dem letzten verifizierten Segment.
- **Installation in einer Zeile** — `pip install axross` oder ein Single-File-Binary von der Release-Page.

Axross ist ein Multi-Protokoll-Dateimanager und Security-Toolkit auf
Basis von Python und PyQt6. SFTP, SMB, S3, WebDAV, Cloud-Drives, IMAP,
Usenet, Cisco IOS, Drucker-FS, BSD r-services — alle in derselben
Split-Pane-UI, alle aufrufbar über dieselbe `axross.*`-Python-API,
alle erreichbar über MCP für einen LLM-Agenten.

Sprachen: [English](README.md) · **Deutsch** · [Español](README_es.md)

---

## Screenshots

![Local-, SFTP-, FTP- und WebDAV-Pane in einem Fenster](docs/screenshots/remote-panes.png)

*Ein Fenster, vier Dateisysteme.* Ein lokaler Ordner und ein SFTP-Share nebeneinander in der Thumbnail-Ansicht, darunter ein FTP-Webroot und ein WebDAV-Ordner. Jedes Pane nennt seine Verbindung; das blaue **SOURCE** und das grüne **TARGET** legen die Richtung für Copy (F5) und Move (F6) fest.

![Upload von einem lokalen Pane nach SFTP mit dem Transfers-Dock](docs/screenshots/remote-transfer.png)

*Upload nach SFTP.* Vier Fotos vom lokalen Pane auf das NAS kopiert; das Transfers-Dock zeigt jede Datei mit Richtung, Größe und Status.

![Vier File-Panes und zwei lokale Terminals im Hacker Mode](docs/screenshots/quad-files-shells.png)

*Hacker Mode.* Vier File-Panes und zwei lokale Terminals in einem Layout. Terminals sitzen im Splitter neben den File-Panes; die Presets `dev-shells`, `triage` und `shells-quad` ordnen sie an.

![Das Layout-Preset quad-files im Amber Mode](docs/screenshots/quad-files.png)

*Amber Mode.* Das Layout-Preset `quad-files`: vier Panes, jedes mit eigener Pfadleiste, Filter, Spalten für Permissions und Owner. `Ctrl+Alt+L` wechselt durch die Presets.

![Das Scripts-Dock mit einem eigenen Script](docs/screenshots/scripts-panel.png)

*Scripts-Dock.* Eigene Scripts neben den read-only Beispielen, geschrieben gegen die `axross.*`-API; sie laufen im Dock oder in der Console.

![Der Duplicate Finder mit zwei Gruppen](docs/screenshots/duplicate-finder.png)

*Duplicate Finder.* Identische Dateien per Content-Hash, gruppiert; die älteste Kopie jeder Gruppe steht fett.

![Metadaten eines Fotos mit EXIF- und GPS-Daten](docs/screenshots/metadata.png)

*Metadaten.* EXIF-Felder und GPS-Position eines Fotos; **Remove Metadata** entfernt sie vor dem Teilen — in place oder als bereinigte Kopie (**Tools → Metadata Settings…**).

![Das Analysis-Dock erklärt eine CSV-Datei](docs/screenshots/analysis.png)

*Analysis-Dock.* Das optionale Extra `sift` erklärt die gewählte Datei — hier eine CSV, ganz ohne LLM.

![Zwei Panes in der Thumbnail-Ansicht, helles Theme](docs/screenshots/thumbnails.png)

*Modern-Light-Theme.* Zwei Panes in der Thumbnail-Ansicht.

![Das Log-Dock nach Copy und Move](docs/screenshots/log-dock.png)

*Log-Dock.* Jedes Copy und Move wird mit seinem Integrity-Check (sha256) und einem Eintrag im Operation-Journal protokolliert.

![Das Agent-Dock: ein lokales Modell liest eine Datei aus einer bubblewrap-Sandbox heraus](docs/screenshots/agent-dock.png)

*Agent-Dock.* Ein lokales Modell (hier Qwen 2.5 auf llama.cpp) liest eine Datei für dich. Der Tab läuft in der Sandbox `Normal` (bubblewrap), der Mode ist `Ask`, und jeder Tool Call steht im Transcript.

![Das Topics-Menü eines Agent-Tabs](docs/screenshots/agent-topics.png)

*Topics.* Fertige Aufgaben — Inventar, Services, Logs, Disk Usage, Zusammenfassung eines Ordners — füllen die Anfrage aus; jeder Tab ist eine eigene Session.

![Der Agent liest eine Datei eines Remote-Panes](docs/screenshots/agent-remote-pane.png)

*Die Verbindung eines Panes, dem Agent geliehen.* Das linke Pane ist mit einem Remote-Speicher verbunden; der Agent liest `/reports/q3.txt` darüber, ohne eigenen Login.

![Agent Settings, Seite Sandboxes](docs/screenshots/agent-sandboxes.png)

*Sandbox-Profile.* Engine (bubblewrap, podman, docker), Level von `lax` bis `paranoid`, erlaubte Hosts und zusätzliche Ordner — vor jeder Aufgabe angewandt.

![Der Access-Dialog eines Agent-Tabs](docs/screenshots/agent-access.png)

*Access pro Tab.* Welche axross-Funktionen der Agent nutzen darf, welche Hosts er erreicht und welche Ordner er sieht, read-only oder schreibbar.

![Agent Settings, Seite MCP Servers](docs/screenshots/agent-mcp-servers.png)

*MCP-Server.* Weitere MCP-Server für den Agent — hier axross selbst über stdio, getestet: 11 Tools.

![Das Agent-Stats-Fenster über dem Hauptfenster](docs/screenshots/agent-stats.png)

*Agent Stats.* Die mitgelieferte Extension zählt Tasks, Tool Calls, Fehler und Tokens, für alle Tabs und den letzten.

---

## 26 Highlights

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

4. **Eingebetteter Python-REPL mit 90 öffentlichen Scripting-Namen.** Console-
   Dock unten in der GUI, kuratierte `axross.*`-API mit Datei-Verben,
   Ping/Whois/SNMP/TLS/HTTP-Helpern, Diagnostics, Recovery, Safety-
   Previews und Result-Klassen, persistente History, side-effect-
   freies Tab-Completion (keine zufällig gefeuerten `@property`-
   Getter), Slash-Commands `.save / .load / .run / .scripts /
   .delete`. Siehe
   [docs/SCRIPTING_de.md](docs/SCRIPTING_de.md) +
   [docs/SCRIPTING_REFERENCE.md](docs/SCRIPTING_REFERENCE.md).

5. **Inline-Doc-Pane mit Tabs.** Direkt neben dem REPL — vier Tabs:
   `API` (jede `axross.*`-Funktion mit Suchleiste + voller
   Docstring), `Slash` (alle Slash-Commands), `Scripts` (alle 32
   mitgelieferten Skripte), `Protocol` (das `FileBackend`-Interface,
   das jedes Backend implementiert).

6. **32 fertige Skripte.** Mirror, Dedupe, Find-Secrets, Port-Scan,
   SLP-Inventory, Cisco-IOS-Sammlung, IMAP-Archiv, sha256-Diff,
   Bookmarks-Export, MAC-Lookup, Time-Skew, SSH-Hostkey-Collect,
   TLS-Cert-Survey, HTTP-Probe-Batch, SNMP-Walk, RamFS-Pipeline, …
   — unter [`resources/scripts/`](resources/scripts/), jedes
   startbar via `axross --script` oder REPL-Slash `.run name`.

7. **MCP-Server-Modus für LLM-Agenten.** Headless `axross
   --mcp-server` spricht JSON-RPC über stdio oder HTTP (mTLS Pflicht
   außerhalb von Loopback) und bedient das lokale Dateisystem unter
   `--mcp-root` (Default: das Home-Verzeichnis). Read-only per
   Default; `--mcp-write` öffnet die Datei-Mutation (braucht ein
   explizites `--mcp-root`); **`--mcp-allow-scripts` (nur stdio)
   lässt das LLM eigene Python-Skripte schreiben und mit deinen
   Rechten ausführen**, jeden Lauf in einem Kindprozess mit Timeout —
   nicht auf die Root begrenzt, also wie eine Shell behandeln. `--mcp-tools GRUPPE[,…]` (oder `all`) fügt
   Capability-Gruppen hinzu: metadata, duplicates, packer, archive,
   crypto, index, filetype, transfer, remote (gespeicherte Profile als
   weitere Backends, Credentials nur aus dem Keyring, nie ein Prompt)
   und extensions; ihre mutierenden Tools brauchen zusätzlich
   `--mcp-write`. Die Gruppe `exec` führt Befehle und Scripts auf
   entfernten Hosts aus (SSH, Telnet, rsh, ADB, WinRM, Cisco `show`),
   nur mit ihrem eigenen `--mcp-allow-exec`; `agent` übergibt eine
   Aufgabe an das eigene lokale LLM, das lesen, aber nichts ändern
   kann. Das Agent-Dock (View > Panels) lässt ein lokales LLM im Fenster
   mit axross arbeiten und fragt vor jeder Änderung. `axross --mcp-list-tools` gibt das JSON-Manifest
   aller Tools aus ([docs/mcp-tools.json](docs/mcp-tools.json)). Siehe
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

10. **Operational-Safety-Layer.** Mutierende Operationen schreiben
    bereinigte strukturierte Logs und ein append-only JSONL-Operation-
    Journal; Delete-, Trash- und Transfer-Flows können vor Ausführung
    vorab gezählt werden; Tools-Menü und `axross.*`-Scripting-API
    bieten Backend-Diagnostics, Recovery-Scans und die jüngste
    Operation-History. Der `paranoid` Security Mode blockiert externe
    Viewer, automatische Previews, Skripte, Legacy-Protokolle und
    Private-Proxy-Overrides.

11. **Multi-System-Workflow-Verbs.** `axross.where_was_i()` ruft
    das letzte Verzeichnis + recent ops jedes besuchten Hosts ab.
    `compare_file([h1, h2, h3], "/etc/nginx.conf")` probt denselben
    Pfad parallel auf N Hosts und liefert einen Unified-Diff.
    `inspect_targets` macht das Gleiche für eine heterogene
    `(backend, path)`-Liste („ist die lokale /tmp/foo.bin wirklich
    dasselbe File wie das S3-Objekt und die SFTP-Kopie?").
    `federated_search([…])` übersetzt eine Anfrage in die effizienteste
    native Suche pro Backend — IMAP SEARCH für IMAP, `find_by_query`
    für DB-FS, generischer Walker sonst. `dashboard()` rendert
    Ein-Bildschirm-Federation-Status (text / markdown / json).
    Connection-Health-Pulse probt jede Session mit dem billigsten
    No-Op des Protokolls; Production-Tarpit-Countdown beim ersten
    destruktiven Op gegen ein `production=True`-Profil. Siehe
    [docs/MULTI_SYSTEM.md](docs/MULTI_SYSTEM.md) und
    [docs/DAILY_DRIVER.md](docs/DAILY_DRIVER.md).

12. **Reverse-Serve über S3 / WebDAV.** `axross.serve_s3(backend)`
    und `axross.serve_webdav(backend)` exponieren jedes geöffnete
    axross-Backend als localhost-Endpoint. restic / aws-cli /
    terraform / rclone / gnome-files / davfs2 / macOS Finder
    funktionieren einfach — jedes Tool, das schon S3 oder WebDAV
    spricht, bekommt sofort Zugriff auf das Protokoll, vor das
    axross sich stellt (SFTP, SMB, RamFS, Postgres-FS, IMAP-as-FS,
    …). Localhost-Bind-Default + Token-Auth per Default + Read-only-Mode
    + Path-Traversal-Reject. Siehe
    [docs/REVERSE_SERVE.md](docs/REVERSE_SERVE.md).

13. **Resiliente Cross-Backend-Transfers.** `axross.resumable_copy()`
    teilt die Quelle in Segmente, schreibt nach jedem ein Manifest,
    und beim Re-Run wird ab dem ersten unfertigen Segment fortgesetzt
    — nach Verifikation der Ziel-Hashes. Übersteht Ctrl-C, VPN-Drops,
    gecrashte Interpreter. Zusammen mit adaptiver Chunk-Größe (BDP-
    gesteuert, Hysterese-Reassessment, 16 KiB ≤ chunk ≤ 16 MiB) treffen
    lange Transfers auf Gbit-LAN, 4G und Sat-Links jeweils eine
    sinnvolle Chunk-Größe.

14. **Time-Lapse / Trail.** `axross.snapshot_now(backend, path)`
    plus `start_trail()` führen ein SQLite-Ledger periodischer
    Metadata-Snapshots für jeden Verzeichnis-Tree auf jedem Backend,
    das axross spricht. Diff zwischen zwei Snapshots zeigt added /
    removed / modified Files; optionaler erste-32-KiB-Drift-Hash.
    Forensische Timeline-Rekonstruktion + Change-Tracking +
    Growth-Monitoring ohne Server-Side-Instrumentation. Siehe
    [docs/TRAIL.md](docs/TRAIL.md).

15. **LLM-freundliche Verzeichnis-Inspection.** `axross.summarize(
    backend, path)` produziert in einer Round-Trip eine
    Ein-Absatz-Synopse — Counts, Endungs-Histogramm, Age-Buckets,
    Top-5 nach Größe. Keine Body-Reads. `explain(backend, path)`
    matcht eine 15-Pattern-Bibliothek und beantwortet „was IST
    das?" — git-Repo, PostgreSQL-Datadir, nginx-Config-Tree,
    k8s-Manifests, Maildir, Web-Log-Dir, Python / Node /
    Docker-Projekte, … Damit ein LLM-Agent ohne N-tausend-Eintrag-
    list_dir-Dump planen kann.

16. **Autorisierte Credential-Tests.** `axross.bruteforce()`,
    `spray()`, `enumerate_users()` für Pentest-Engagements mit
    schriftlicher Authorisation. Hartes `authorized=True`-Gate (kein
    Env-Var-Override, im `paranoid` Mode geblockt), Lockout-First-
    Defaults, Password-Spray-by-Default. Eingebaute Oracles für
    POP3 + FTP/FTPS + statistischer Timing-Fallback sonst. Siehe
    [docs/CRED_ATTACK.md](docs/CRED_ATTACK.md).

17. **CVE-frei by design.** SLP-Backend baut nie ein `SrvReg`-Paket
    — der SLP-Amplification-Pfad
    ([CVE-2023-29552](https://nvd.nist.gov/vuln/detail/CVE-2023-29552))
    ist strukturell unmöglich. Multicast-Ziele werden auf Socket-
    Ebene hart verweigert.

18. **SSRF-Guard auf jedem Proxy-Hop.** Default-deny gegen
    Cloud-Metadata-Endpoints (169.254.169.254 + AWS-IMDS-Varianten)
    und RFC1918-Ranges; Opt-in via `AXROSS_ALLOW_PRIVATE_PROXY=1`,
    wenn man wirklich durch ein internes LAN proxy-en will. Im
    `paranoid` Mode wird dieser Private-Proxy-Override ignoriert.

19. **Expliziter SOCKS5 / HTTP-CONNECT-Support.** Proxy-fähige
    Backends nutzen `core.proxy` — SSH/SCP, Telnet, Cisco-Telnet,
    FTP/FTPS, IMAP, POP3, NNTP, WebDAV, SMB/DFS-N, Gopher, PJL,
    WinRM und unterstützte Cloud-Transporte. Backends, die SOCKS/
    HTTP-Proxy-Settings nicht einhalten können, warnen statt still
    direkt zu verbinden.
    Siehe [docs/PROXY_SUPPORT.md](docs/PROXY_SUPPORT.md).

20. **Backend-agnostische Primitive.** Universeller Trash, atomic
    writes (Temp-Sibling + Rename), Snapshot-Timeline, Content-
    addressable Storage, Archiv-Extraktion mit Zip-Bomb / Zip-Slip-
    Schutz — alles uniform über jedes Backend.

21. **Pure-Python wo möglich.** Eigene NNTP-Wire-Lib, eigene WebDAV-
    Implementation (kein Drittanbieter-SDK), eigener SLPv2-Packet-
    Builder, eigener Gopher-Reader, eigener minimum-viable S3 +
    WebDAV-Reverse-Server auf stdlib `http.server`. Kleinerer
    Dep-Tree, kein SDK-Lock-in, keine Python-3.13-Überraschung wenn
    stdlib-Module verschwinden.

22. **Headless und GUI aus derselben Quelle.** PyQt6-Dateimanager,
    MCP-stdio/HTTP-Server, oder `axross --script <datei>`-CLI-
    Runner. Single-File-Binaries auf der Release-Page: Linux
    (`axross-full`, `axross-slim`), macOS auf Apple Silicon und Windows
    x64 (`axross-slim`) - das macOS-Binary ist nicht notarisiert, vor dem ersten Start also das Quarantine-Attribut entfernen
    ([docs/PACKAGING.md](docs/PACKAGING.md#macos-binary-the-first-start)); AppImage und das
    `Dockerfile.mcp`-Image baut man aus dem Source
    ([docs/PACKAGING.md](docs/PACKAGING.md)), und dieses Image schließt
    PyQt6 explizit aus, um copyleft-frei zu bleiben.

23. **Extensions.** Python-Plugins fügen Einträge im Extensions-Menü,
    Rechtsklick-Aktionen und Panels hinzu (**Extensions → Manage
    Extensions…**). Jede Extension startet ausgeschaltet, sie zu finden
    führt sie nie aus, und der `paranoid` Mode lädt keine. Sechs
    mitgelieferte Beispiele. Siehe [docs/EXTENSIONS.md](docs/EXTENSIONS.md).

24. **Ein LLM-Agent im eigenen Dock.** **View → Panels → Agent** spricht
    mit dem Modell, das du in den **Agent Settings** wählst (Ollama,
    LM Studio, MLX-LM oder ein OpenAI-kompatibler Endpoint wie
    llama.cpp). Jeder Tab ist eine Session, gespeichert als eine
    JSON-Datei; die Protection Modes `ask`, `plan`, `auto` und `bypass`
    entscheiden, was ohne Rückfrage läuft; **Topics** bietet fertige
    Aufgaben; **+** und Drag & Drop aus einem Pane übergeben Dateien, und
    die Remote-Verbindungen der Panes lassen sich ihm leihen. Die
    mitgelieferte Extension **Agent Stats** zählt Runs, Tool Calls und
    Tokens.

25. **Agents in einer Sandbox.** Jeder Tab kann seinen Agent in
    bubblewrap, podman oder docker laufen lassen, auf dem Level `lax`,
    `normal`, `high` oder `paranoid` (paranoid: einziger Peer ist das
    LLM, jeder Ordner read-only). Der API-Key kommt nie in die Sandbox.
    Pro Tab gibt **Access…** das Netzwerk frei (keins, eine
    `host:port`-Liste oder alles, nie über dem Level) und Ordner
    read-only oder schreibbar, und schaltet die axross-Funktionen, die
    der Agent außerhalb der Sandbox nutzen darf, ein oder aus.

26. **Auch ein MCP-Client.** **Agent Settings → MCP Servers** bindet
    weitere MCP-Server an (stdio oder HTTP); ihre Tools erscheinen in der
    **Tools**-Liste des Tabs und fragen vor jedem Aufruf oder nur vor
    Schreibzugriffen.

---

## Schnellstart

Von PyPI, sobald ein Release veröffentlicht ist:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install "axross[all]"
axross              # GUI starten
axross --mcp-server # oder das lokale Dateisystem als MCP-Tools an einen LLM ausliefern
```

Aus einem Source-Checkout:

```bash
git clone https://github.com/c0decave/axross
cd axross
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
axross              # GUI starten
axross --mcp-server # oder das lokale Dateisystem als MCP-Tools an einen LLM ausliefern
```

```python
# Aus dem eingebetteten REPL — Console-Dock unten im Fenster
>>> b = axross.open_url("sftp://alice@example.com/")
>>> for f in b.list_dir("/var/log")[:5]:
...     print(f.name, f.size)
>>> axross.copy(b, "/etc/motd", axross.localfs(), "/tmp/motd")
>>> axross.preview_delete(axross.localfs(), ["/tmp/motd"])
>>> axross.diagnose(b)
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
| [docs/SCRIPTING.md](docs/SCRIPTING.md) · [SCRIPTING_de.md](docs/SCRIPTING_de.md) · [SCRIPTING_es.md](docs/SCRIPTING_es.md) | REPL + `axross.*`-API + Slash-Commands + 32 mitgelieferte Skripte + MCP-Scripting-Tools. |
| [docs/SCRIPTING_REFERENCE.md](docs/SCRIPTING_REFERENCE.md) | Auto-generierte Volldoku jeder Funktion mit Signatur + komplettem Docstring. |
| [docs/MCP.md](docs/MCP.md) · [MCP_de.md](docs/MCP_de.md) · [MCP_es.md](docs/MCP_es.md) | MCP-Server-Referenz — Tools, Sessions, mTLS, Rate-Limits, Hardening. |
| [docs/LLM_GUIDE.md](docs/LLM_GUIDE.md) · [llms.txt](llms.txt) | Für LLM-Agents (englisch): axross über MCP und die `axross.*`-API richtig bedienen, mit dem aus dem Manifest erzeugten Tool-Katalog. |
| [docs/HANDBUCH.md](docs/HANDBUCH.md) | Vollständiges deutsches Handbuch (Workflows, Dialog-Referenz, Tastenkürzel). |
| [docs/OPSEC.md](docs/OPSEC.md) | Threat-Model + per-Finding-Analyse, was der Client an Server preisgibt. |
| [docs/PROXY_SUPPORT.md](docs/PROXY_SUPPORT.md) | SOCKS5 / SOCKS4 / HTTP-CONNECT pro Protokoll. |
| [OAUTH_SETUP.md](OAUTH_SETUP.md) | OneDrive / SharePoint / Google Drive / Dropbox App-Registration-Rezepte. |
| [docs/MULTI_SYSTEM.md](docs/MULTI_SYSTEM.md) · [MULTI_SYSTEM_de.md](docs/MULTI_SYSTEM_de.md) · [MULTI_SYSTEM_es.md](docs/MULTI_SYSTEM_es.md) | Cross-Host-Workflow-Verbs — `where_was_i`, `compare_file`, `federated_search`, `dashboard`, `resumable_copy`, … |
| [docs/DAILY_DRIVER.md](docs/DAILY_DRIVER.md) · [DAILY_DRIVER_de.md](docs/DAILY_DRIVER_de.md) · [DAILY_DRIVER_es.md](docs/DAILY_DRIVER_es.md) | Production-Tarpit + adaptive Chunk-Größe — Primitives unter den Multi-System-Verbs. |
| [docs/REVERSE_SERVE.md](docs/REVERSE_SERVE.md) · [REVERSE_SERVE_de.md](docs/REVERSE_SERVE_de.md) · [REVERSE_SERVE_es.md](docs/REVERSE_SERVE_es.md) | Jedes axross-Backend per minimum-viable S3 / WebDAV API exponieren — alle Tools, die das schon sprechen, kommen sofort dran. |
| [docs/TRAIL.md](docs/TRAIL.md) · [TRAIL_de.md](docs/TRAIL_de.md) · [TRAIL_es.md](docs/TRAIL_es.md) | Time-Lapse / Change-Tracking — periodische Metadata-Snapshots eines Verzeichnis-Trees. |
| [docs/CRED_ATTACK.md](docs/CRED_ATTACK.md) · [CRED_ATTACK_de.md](docs/CRED_ATTACK_de.md) · [CRED_ATTACK_es.md](docs/CRED_ATTACK_es.md) | Autorisierte Credential-Tests — Brute-Force, Password-Spray, User-Enumeration mit OPSEC-Defaults. |
| [docs/RED_TEAM_NOTES.md](docs/RED_TEAM_NOTES.md) | Adversariale Review jedes Backends — gefixte Findings, akzeptierte Risiken, offene Follow-ups. |
| [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) | Test-Suite, Docker-Lab, Protokoll-Coverage-Matrix. |
| [docs/PACKAGING.md](docs/PACKAGING.md) | PyPI/sdist/wheel-Release, PyInstaller-Bundle, AppImage, headless MCP-Docker-Image. |
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
