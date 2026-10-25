<p align="center">
  <img src="resources/logo/axross-logo-256.png" alt="Axross" width="160"/>
</p>

# Axross

**Eine UI, 30+ Protokolle, ein eingebetteter Python-REPL, und eine
MCP-Tool-Oberfläche, mit der ein LLM das Ganze fernsteuern kann.**

- **30+ Protokolle in einem Fenster** — SFTP, SMB, S3, WebDAV, Cloud-Drives, IMAP, Git, Datenbanken und mehr.
- **Kopieren zwischen beliebigen Backends** — S3 → SFTP, WebDAV → SMB, direkt, ohne Umweg über die lokale Platte.
- **Multi-Pane-Layout im Commander-Stil** — beliebig viele Split-Panes, Layout-Presets, Drag & Drop.
- **Workspaces** — benannte Pane-Layouts als Tabs, abtrennbar in ein eigenes Fenster, beim nächsten Start wiederhergestellt.
- **LLM-Agent eingebaut** — Agent-Dock mit Tabs und Sandboxes für LM Studio, Ollama, vLLM oder llama.cpp, read-only per Default.
- **Mit dem Agent sprechen** — Push-to-Talk, gesprochene Antworten auf Deutsch und Englisch, Speech Recognition lokal oder auf dem LLM-Server.
- **MCP-Server und -Client** — LLMs steuern axross über stdio oder HTTP, und der Agent nutzt die Tools weiterer MCP-Server.
- **Eingebautes Python-Scripting** — REPL, Scripts-Dock und 32 fertige Scripts auf einer `axross.*`-API.
- **Text-Editor mit Tabs** — Syntax Highlighting, Find/Replace, Encodings und Line Endings, für lokale und Remote-Dateien.
- **Find Files** — nach Name, Typ, Inhalt, Größe oder Tag, auch in Archiven, gespeichert als Smart Folder.
- **Farbige Tags** — auf jeder Datei, folgen Rename und Move, als Filter in Find Files.
- **Disk-Images und Forensik** — Partitionen und Dateisysteme, read-only Loop Mount, Hashes, The Sleuth Kit, PhotoRec.
- **Media Player** — Playlist, M3U, Shuffle/Repeat, 10-Band-Equalizer und Spektrum.
- **Duplikate finden, Metadaten entfernen** — Duplicate Finder per Content-Hash, EXIF/GPS raus vor dem Teilen.
- **Verschlüsselung ohne Klartext auf der Platte** — `.axenc`-Overlay auf jedem Backend, entschlüsselt nur in den RAM.
- **Sicher per Default** — Preview vor Delete/Move, Operation-Journal, `paranoid` Mode, Proxies mit SSRF-Guard.
- **Resumable Transfers** — überstehen Ctrl-C und VPN-Abbrüche, weiter ab dem letzten verifizierten Segment.
- **Archive wie Ordner** — ZIP, TAR und 7z durchblättern, auch verschachtelt, nur das Gewählte extrahieren, Zip-Bomb-sicher.
- **Extensions** — Media Player, Forensic Tools, Treemap, VirtualBox und mehr, jede aus, bis du sie einschaltest.
- **Installation in einer Zeile** — `pip install axross` oder ein Single-File-Binary für Linux, macOS und Windows.

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

![Vier File-Panes und zwei lokale Terminals im Hacker Mode](docs/screenshots/quad-files-shells.png)

*Hacker Mode.* Vier File-Panes und zwei lokale Terminals in einem Layout. Terminals sitzen im Splitter neben den File-Panes; die Presets `dev-shells`, `triage` und `shells-quad` ordnen sie an.

![Das Agent-Dock: ein lokales Modell liest eine Datei aus einer bubblewrap-Sandbox heraus](docs/screenshots/agent-dock.png)

*Agent-Dock.* Ein lokales Modell (hier Qwen 2.5 auf llama.cpp) liest eine Datei für dich. Der Tab läuft in der Sandbox `Normal` (bubblewrap), der Mode ist `Ask`, und jeder Tool Call steht im Transcript.

Weitere Screenshots, jeder mit Erklärung: **[die Slideshow](slideshow_de.md)**.

---

## 44 Highlights

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
    …). Localhost-Bind-Default + Token-Auth per Default + Read-only-Mode +
    Path-Traversal-Reject. Siehe
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
    führt sie nie aus, und der `paranoid` Mode lädt keine. Elf
    mitgelieferte, darunter Media Player, Forensic Tools, Drives Overview,
    VirtualBox und Backup Repositories. Siehe [docs/EXTENSIONS.md](docs/EXTENSIONS.md).

24. **Ein LLM-Agent im eigenen Dock.** **View → Panels → Agent** spricht
    mit dem Modell, das du in den **Agent Settings** wählst (Ollama,
    LM Studio, MLX-LM oder ein OpenAI-kompatibler Endpoint wie
    llama.cpp). Jeder Tab ist eine Session, gespeichert als eine
    JSON-Datei; die Protection Modes `ask`, `plan`, `auto` und `bypass`
    entscheiden, was ohne Rückfrage läuft; **Topics** bietet fertige
    Aufgaben; **+** und Drag & Drop aus einem Pane übergeben Dateien, und
    die Remote-Verbindungen der Panes lassen sich ihm leihen. Das
    Thinking eines Modells steht getrennt von seiner Antwort, auf eine
    Zeile eingeklappt, bis du es anklickst; eine Lampe in der Titelzeile
    des Docks ist grün, solange das LLM antwortet, orange, während es
    gefragt wird, und rot, wenn es nicht erreichbar ist. **Topics ▸ + New
    Topic…** speichert eigene Aufgaben; **Settings → Agent → Prompts**
    verwaltet benannte System-/User-Prompt-Profile; **Fetch models**
    öffnet eine Liste mit Größe, Parametern, Quantisierung und dem
    geladenen Modell. Die mitgelieferte Extension **Agent Stats** zählt
    Runs, Tool Calls und Tokens.

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

27. **Workspaces.** Benannte Pane-Layouts als Tabs (**Workspace → New
    Workspace**), jedes abtrennbar in ein eigenes Fenster - auf einen
    anderen Bildschirm oder daneben - und zurück als Tab, wenn das
    Fenster schließt. Ein neues Workspace startet mit einer Dateiliste
    oder einem lokalen Terminal, Panes wandern per Menü oder Drag & Drop
    zwischen Workspaces, und mehrere Shells stehen nebeneinander. Die
    Workspaces kommen beim nächsten Start wieder.

28. **Mit dem Agent sprechen.** Push-to-Talk (F9), Toggle oder
    Conversation Mode im Agent-Dock. Antworten kommen gesprochen auf
    Deutsch oder Englisch mit Piper-Voices, englische IT-Begriffe bleiben
    englisch; jede Stimme hat eigene Speed, Pitch, Expressiveness, Volume
    und Pause, mit Listen in Settings > Voice angehört; Speech Recognition läuft lokal mit faster-whisper oder auf
    dem LLM-Server, pro Profil gewählt. Die Modelle werden bei Bedarf
    geladen. In `axross-full` enthalten, sonst `pip install
    axross[voice]`.

29. **Ein Text-Editor mit Tabs.** Jeder Tab ist eine Datei auf einem
    beliebigen Backend: Pygments-Syntax-Highlighting, Find und Replace
    (Regex, Groß-/Kleinschreibung, ganzes Wort), Encodings und Line
    Endings, New / Open… / Save As…, Auto-Indent; große Dateien werden
    abseits des GUI-Threads gelext.

30. **Find Files.** **Edit → Find Files…** (Alt+F7) durchsucht Ordner
    auf jeder offenen Verbindung nach Name, Typ-Preset, Inhalt, Größe,
    Datum und Tag, auch in Archiven. Treffer laufen ein, während das
    Fenster bedienbar bleibt, und eine Suche wird als **Smart Folder** in
    den Bookmarks gespeichert. Der Offline-Index entfernt Dateien, die
    seit dem letzten Indexieren gelöscht wurden.

31. **Farbige Tags.** Jede Datei auf jedem Backend lässt sich markieren -
    **Important** und **Review later** gibt es von Anfang an. Tags
    folgen Rename und Move und sind ein Filter in Find Files.

32. **Disk-Images und Forensik.** axross liest qcow2-, VDI-, VMDK-,
    VHD/VHDX- und E01-Header, MBR- und GPT-Partitionstabellen und ihre
    Dateisysteme, ohne etwas zu schreiben, und mountet eine Partition
    read-only über ein Loop Device. Die Extension **Forensic Tools**
    ergänzt MD5 / SHA-1 / SHA-256 in einem Durchgang, `qemu-img`, The
    Sleuth Kit (durchblättern und extrahieren, gelöschte Dateien
    eingeschlossen) und TestDisk/PhotoRec.

33. **Media Player.** Ein Extension-Panel für MP3, FLAC, Ogg, Opus, AAC
    und mehr: Playlist mit Drag & Drop und M3U, Seeking, Shuffle und
    Repeat, ein einklappbarer 10-Band-Equalizer mit Presets, zehn
    Visualisierungen (Spektrum, gespiegelt, radial, Linien- und
    Polar-Spektrum, Waterfall, Oszilloskop, Stereo-Scope, VU-Meter,
    Starfield), zwischen denen ein Klick darauf wechselt, in Farbschemata
    oder eigenen Farben, im Fullscreen wie ein Screensaver oder in einem
    eigenen Fenster, eine einklappbare Playlist, Titel, Interpret und
    Cover.

34. **Bookmarks für viele Orte.** Mehrfachauswahl, Gruppen sortiert nach
    Name, Pfad oder Alter, Terminal-Bookmarks (auf einem Profil, einem
    bloßen Host oder lokal) und **Manage Bookmarks** als vollwertiger
    Manager.

35. **Alle Settings an einem Ort.** **Edit → Settings…** enthält jede
    Option - **Edit → Settings… → Audio** wählt PipeWire oder PulseAudio,
    Output- und Input-Device samt Volume und testet jedes mit einem Ton,
    einem Level-Meter und einer abgespielten Aufnahme; **Help → Features**
    zeigt, welche optionalen Teile installiert sind und welche fehlen;
    **Help → Scripting Guide** öffnet den API-Guide.

36. **Eine Toolbar für die Werkzeuge.** Buttons mit Icons für Agent,
    Analysis (sift), Terminal, Find Files, Scripts, die Python-Console, Tags,
    Trash, Media Player, Audio & Video Settings, Treemap, Drives, Settings
    und Features, in jedem Theme, nach Kategorie gruppiert (Connections,
    Windows & Panes, Files & Search, Media, LLM & Agent, Tools & System,
    Extensions), jede Kategorie mit ihrer eigenen Farbe hinter ihren
    Buttons. Buttons lassen sich per Drag and Drop innerhalb ihrer Gruppe
    verschieben; die Reihenfolge bleibt über den Neustart erhalten, und
    Reset Toolbar Order (Rechtsklick auf die Toolbar) stellt den Default
    wieder her. **Edit → Settings… → Toolbar** schaltet Gruppierung und
    Farben an oder ab und setzt die Farbe jeder Kategorie.

37. **Archive wie Ordner.** ZIP-, TAR- und 7z-Archive öffnen sich in der
    Archiv-Ansicht; verschachtelte Archive lassen sich betreten, und
    extrahiert wird alles oder nur die Auswahl, mit Zip-Bomb- und
    Zip-Slip-Schutz.

38. **Agent-Profile.** Benannte Bündel dessen, was ein Agent-Tab bekommt:
    LLM-Profil, Prompt-Profil, Protection Mode, Sandbox, Tool-Gruppen,
    axross-Funktionen, Files read-only und MCP-Server nach Kategorie oder
    Name. Sieben Presets - Files Assistant, Reverse Engineering, Forensics
    read-only, Network & Web Recon, Code & Secrets, Remote Ops, Research -
    und eigene in **Settings → Agent → Profiles**, mit einer Preview
    dessen, was ein Tab bekommt. Der **+**-Pfeil im Agent-Dock und **Tools
    → New Agent Tab from Profile** öffnen einen Tab aus einem Profil,
    **Apply Profile…** richtet einen offenen Tab ein, und ein fehlender
    MCP-Server ist einen Klick entfernt (**Install from Catalog…**).

39. **MCP-Server aus einem Katalog, eingesperrt.** **Add from Catalog…**
    durchsucht den eingebauten Katalog, den c0decave MCP Hub (17
    Security-Tools wie binwalk, capa, Nmap, YARA und The Sleuth Kit; nur
    per Digest gepinnte `ghcr.io/c0decave`-Images), den `mcp`-Namespace
    von Docker Hub, die MCP Registry und kuratierte Listen. Was
    heruntergeladen wird, läuft nur in podman: keine Capabilities, keine
    neuen Privilegien, read-only Root und kein Netzwerk, solange du es
    nicht freigibst. **Detected on this machine** übernimmt die
    MCP-Server, die deine anderen Tools konfiguriert haben, und
    installiert herunterladende eingesperrt. Ein Third-Party-Eintrag wie
    REA sagt, wer ihn pflegt.

40. **Cut und Paste von Dateien.** Ctrl+X / Rechtsklick **Cut** merkt die
    Einträge vor (gedimmt, in jedem Pane); Ctrl+V / **Paste** verschiebt
    sie über die Transfer-Queue in den Ordner eines beliebigen Panes, und
    eine Quelle wird erst entfernt, wenn ihre Kopie fertig und geprüft ist -
    ein Cut, der nie eingefügt wird, entfernt nichts. Esc in der
    Filterzeile leert den Filter.

41. **Icon-Farben.** **Settings → Appearance → Icon colours**: der
    Theme-Default, eigene Farben in jedem Theme (auch Hacker und Amber,
    die sonst jedes Icon in ihrer Farbe zeichnen) oder eine eigene Farbe -
    live, und erhalten über Theme-Wechsel und Neustarts.

42. **Self-Update.** `axross-full` und `axross-slim` fragen einmal pro
    Start im Hintergrund die GitHub-Releases (**Settings → Updates**; aus
    mit `AXROSS_NO_UPDATE_CHECK=1` und im `paranoid`-Mode) und zeigen
    **Update to X.Y.Z…** in der Statusleiste und im Help-Menü; **Help →
    Check for Updates…** fragt sofort. **Download and Install** prüft den
    SHA-256 gegen die SHA256SUMS des Releases und den Digest von GitHub,
    ersetzt das Binary atomar und behält das alte; **Restart Now** prüft
    es erneut, bevor es die neue Version startet.

43. **Mitgelieferte Beispiele laufen direkt.** **Run** oder **Run in
    Console** auf einem mitgelieferten Beispiel im Scripts-Dock zeigt
    seinen Usage-Aufruf zum Anpassen und führt das Beispiel damit aus;
    **Copy to My Scripts** behält den Aufruf als auskommentierten
    Abschnitt "Try it".

44. **Third-Party-Software, gewürdigt.** **Help → Third-Party Software…**
    listet die 222 Projekte, die axross nutzt oder mitliefert - Zweck,
    Lizenz, wie es zu dir kommt, Link - aus derselben Datendatei wie der
    Dank am Ende dieser README.

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

---

<!-- third-party:readme -->
<!-- Generated from resources/credits/third_party.json by `python -m core.third_party --write`; edit the data file, not this block. -->

## Third-Party-Software und Dank

axross baut auf der Arbeit vieler Menschen auf. Danke an alle, die die Projekte unten bauen und pflegen - ohne sie gäbe es axross nicht.

Die Liste wird aus [`resources/credits/third_party.json`](resources/credits/third_party.json) erzeugt, denselben Daten, die die App unter **Help > Third-Party Software…** zeigt. Lizenztexte und Hinweise für Weiterverteiler stehen in [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).

| Projekt | Wofür | Lizenz | Kommt mit |
|---|---|---|---|
| [adb_shell](https://github.com/JeffLIrion/adb_shell) | Android devices over ADB | Apache-2.0 | axross-full, axross-slim, pip [adb] |
| [axross MCP hub](https://github.com/c0decave/axross-mcp-hub) | Catalogue of container-packaged MCP servers that the MCP catalog installs on request | MIT | Container-Image |
| [azure-storage-blob](https://github.com/Azure/azure-sdk-for-python) | Azure Blob Storage backend | MIT | axross-full, pip [azure] |
| [azure-storage-file-share](https://github.com/Azure/azure-sdk-for-python) | Azure Files backend | MIT | axross-full, pip [azure] |
| [backports.zstd](https://github.com/rogdham/backports.zstd) | Zstandard compression on Python versions before 3.14 | PSF-2.0 | axross-full, axross-slim, pip [archive] |
| [boto3](https://github.com/boto/boto3) | Amazon S3 and S3-compatible storage | Apache-2.0 | axross-full, axross-slim, pip [s3] |
| [Bubblewrap (bwrap)](https://github.com/containers/bubblewrap) | Agent sandbox | LGPL-2.1-or-later | auf dem eigenen System |
| [bzip2](https://sourceware.org/bzip2/) | bzip2 compression (Python's bz2 module) | bzip2-1.0.6 | axross-full, axross-slim |
| [chardet](https://github.com/chardet/chardet) | Text encoding detection | 0BSD | axross-full, axross-slim, pip [encoding] |
| [cryptography](https://github.com/pyca/cryptography) | Encrypted overlay, certificate inspection; cryptography for SSH and TLS | Apache-2.0 OR BSD-3-Clause | axross-full, axross-slim, pip |
| [ctranslate2](https://github.com/OpenNMT/CTranslate2) | Runs the Whisper speech recognition models | MIT | axross-full, pip [voice] |
| [D-Bus](https://www.freedesktop.org/wiki/Software/dbus/) | Desktop bus access of Qt (notifications, portals, keyring) | AFL-2.1 OR GPL-2.0-or-later | axross-full, axross-slim |
| [defusedxml](https://github.com/tiran/defusedxml) | Safe XML parsing (WebDAV responses and other XML input) | PSF-2.0 | axross-full, axross-slim, pip [webdav] |
| [dnspython](https://github.com/rthalley/dnspython) | DNS lookups (scripting helpers and SRV discovery) | ISC | axross-full, axross-slim, pip [dns] |
| [Docker](https://www.docker.com) | Agent sandbox and MCP server containers | Apache-2.0 | auf dem eigenen System |
| [dropbox](https://github.com/dropbox/dropbox-sdk-python) | Dropbox backend | MIT | axross-full, pip [dropbox] |
| [dulwich](https://github.com/dulwich/dulwich) | Git repositories as a file system | Apache-2.0 OR GPL-2.0-or-later | axross-full, axross-slim, pip [git] |
| [espeak-ng](https://github.com/espeak-ng/espeak-ng) | Phonemes for the Piper voices (statically linked into piper's espeakbridge, with its data) | GPL-3.0-or-later | axross-full, pip (mit einem Extra) |
| [exchangelib](https://github.com/ecederstrand/exchangelib) | Microsoft Exchange backend (EWS) | BSD-2-Clause | axross-full, pip [exchange] |
| [Expat](https://libexpat.github.io) | XML parsing (Python's xml modules) | MIT | axross-full, axross-slim |
| [faster-whisper](https://github.com/SYSTRAN/faster-whisper) | Local speech recognition of the Agent dock | MIT | axross-full, pip [voice] |
| [faster-whisper models (Whisper base, small)](https://huggingface.co/Systran) | Local speech recognition models, downloaded in Help > Features… | MIT | Download auf Anfrage |
| [fd](https://github.com/sharkdp/fd) | Find Files: name search | MIT OR Apache-2.0 | axross-full |
| [Feather icons](https://github.com/feathericons/feather) | Style model of axross's own SVG icons (re-drawn, no files copied) | MIT | axross-Quellcode |
| [FFmpeg (ffmpeg, ffprobe)](https://ffmpeg.org) | Video thumbnails, media details, removing audio/video metadata | LGPL-2.1-or-later OR GPL-2.0-or-later OR GPL-3.0-only | auf dem eigenen System |
| [fusepy](https://github.com/fusepy/fusepy) | Mounting an axross connection as a local folder (FUSE) | ISC | axross-full, axross-slim, pip [fuse] |
| [GCC runtime libraries](https://gcc.gnu.org) | Fortran, OpenMP and atomic runtimes (numpy, CTranslate2, QtPdf) | GPL-3.0-or-later WITH GCC-exception-3.1 | axross-full, axross-slim |
| [GLib](https://gitlab.gnome.org/GNOME/glib) | Main loop and D-Bus integration of Qt's platform plugins | LGPL-2.1-or-later | axross-full, axross-slim |
| [GNU dbm](https://www.gnu.org.ua/software/gdbm/) | Key-value files of Python's dbm module | GPL-3.0-or-later | axross-full |
| [GNU Readline](https://tiswww.case.edu/php/chet/readline/rltop.html) | Line editing of Python's readline module | GPL-3.0-or-later | axross-full, axross-slim |
| [google-api-python-client](https://github.com/googleapis/google-api-python-client) | Google Drive backend | Apache-2.0 | axross-full, pip [gdrive] |
| [google-auth-httplib2](https://github.com/googleapis/google-cloud-python) | HTTP transport of the Google Drive client | Apache-2.0 | axross-full, pip [gdrive] |
| [google-auth-oauthlib](https://github.com/googleapis/google-cloud-python) | Google sign-in (OAuth) for Google Drive | Apache-2.0 | axross-full, pip [gdrive] |
| [impacket](https://github.com/fortra/impacket) | WMI / DCOM and SMB tooling for Windows hosts | LicenseRef-Impacket-Apache-1.1-modified | axross-full, pip [wmi] |
| [ipwhois](https://github.com/secynic/ipwhois) | WHOIS / RDAP lookups | BSD-2-Clause | axross-full, axross-slim, pip [whois] |
| [jmtpfs / simple-mtpfs / go-mtpfs](https://github.com/JasonFerrara/jmtpfs) | MTP backend (the first one found on PATH) | GPL-3.0-only OR GPL-2.0-or-later OR BSD-3-Clause | auf dem eigenen System |
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
| [nfs-utils (mount.nfs)](https://linux-nfs.org) | NFS backend | GPL-2.0-or-later | auf dem eigenen System |
| [ntplib](https://github.com/cf-natali/ntplib) | NTP time queries | MIT | axross-full, axross-slim, pip [ntp] |
| [numpy](https://github.com/numpy/numpy) | Equalizer and spectrum of the Media Player extension | BSD-3-Clause AND 0BSD AND MIT AND Zlib AND CC0-1.0 | axross-full, pip [media] |
| [onnxruntime](https://github.com/microsoft/onnxruntime) | Runs the Piper voice models | MIT | axross-full, pip [voice] |
| [open-iscsi (iscsiadm)](https://github.com/open-iscsi/open-iscsi) | iSCSI backend | GPL-2.0-or-later | auf dem eigenen System |
| [OpenSSL](https://www.openssl.org) | TLS and cryptography (Python's ssl module, Qt, libpq) | Apache-2.0 | axross-full, axross-slim |
| [paramiko](https://github.com/paramiko/paramiko) | SSH, SFTP and SCP connections | LGPL-2.1-or-later | axross-full, axross-slim, pip |
| [PCRE and PCRE2](https://www.pcre.org) | Regular expressions used by GLib and libselinux | BSD-3-Clause | axross-full, axross-slim |
| [Pillow](https://github.com/python-pillow/Pillow) | Image thumbnails, image metadata and the image viewer | MIT-CMU | axross-full, axross-slim, pip |
| [Piper voices](https://huggingface.co/rhasspy/piper-voices) | The Agent dock's voices, downloaded in Help > Features… | MIT | Download auf Anfrage |
| [piper-tts](https://github.com/OHF-voice/piper1-gpl) | Speech output of the Agent dock (Piper) | GPL-3.0-or-later | axross-full, pip [voice] |
| [Podman](https://podman.io) | Agent sandbox and MCP server containers | Apache-2.0 | auf dem eigenen System |
| [polkit (pkexec)](https://github.com/polkit-org/polkit) | "Open as root…" and privileged mounts | LGPL-2.0-or-later | auf dem eigenen System |
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
| [Python container image (python:3.12-slim)](https://hub.docker.com/_/python) | Base image of Dockerfile.mcp, Dockerfile.agent and Dockerfile.gui | PSF-2.0 AND LicenseRef-Debian-Packages | Container-Image |
| [pywinpty](https://github.com/andfoy/pywinpty) | The local terminal on Windows (ConPTY) | MIT | pip |
| [pywinrm](https://github.com/diyan/pywinrm) | WinRM backend (Windows Remote Management) | MIT | axross-full, pip [winrm] |
| [qemu-img](https://www.qemu.org) | Opening virtual disk images | GPL-2.0-only | auf dem eigenen System |
| [rarfile](https://github.com/markokr/rarfile) | RAR archives (browse, extract) | ISC | axross-full, axross-slim, pip [archive] |
| [redis](https://github.com/redis/redis-py) | Redis backend | MIT | axross-full, axross-slim, pip [redis] |
| [requests](https://github.com/psf/requests) | HTTP client of the WebDAV, OneDrive and other HTTP backends | Apache-2.0 | axross-full, axross-slim, pip [webdav, onedrive] |
| [ripgrep](https://github.com/BurntSushi/ripgrep) | Find Files: content search | MIT OR Unlicense | axross-full |
| [rsh client (netkit-rsh or GNU Inetutils)](https://www.gnu.org/software/inetutils/) | rsh backend | BSD-4-Clause-UC OR GPL-3.0-or-later | auf dem eigenen System |
| [rsync](https://rsync.samba.org) | rsync backend and fast copies | GPL-3.0-or-later | auf dem eigenen System |
| [SecLists](https://github.com/danielmiessler/SecLists) | Public source of the TFTP common-filename wordlist | MIT | axross-Quellcode |
| [sift](https://github.com/c0decave/sift) | The Analysis dock's file explanations (sift-summarizer); a sister project of axross | MIT | axross-full, pip (mit einem Extra) |
| [sift-summarizer](https://github.com/c0decave/sift) | sift: the Analysis dock's explanation of the selected file | MIT | axross-full, pip [sift] |
| [Silero VAD](https://github.com/snakers4/silero-vad) | Voice activity detection model that faster-whisper ships | MIT | axross-full, pip (mit einem Extra) |
| [smbprotocol](https://github.com/jborean93/smbprotocol) | SMB / CIFS file shares | MIT | axross-full, axross-slim, pip [smb] |
| [SQLite](https://www.sqlite.org) | Embedded database (Python's sqlite3 module) | blessing | axross-full, axross-slim |
| [Subversion](https://subversion.apache.org) | Subversion backend | Apache-2.0 | auf dem eigenen System |
| [TestDisk / PhotoRec](https://www.cgsecurity.org) | Recovering partitions and files | GPL-2.0-or-later | auf dem eigenen System |
| [tftpy](https://github.com/msoulier/tftpy) | TFTP backend | MIT | axross-full, axross-slim, pip [tftp] |
| [The Sleuth Kit](https://www.sleuthkit.org) | Forensic file system access (fls, icat) | IPL-1.0 AND CPL-1.0 AND GPL-2.0-or-later | auf dem eigenen System |
| [UDisks (udisksctl)](https://github.com/storaged-project/udisks) | Loop-mounting disk images | GPL-2.0-or-later | auf dem eigenen System |
| [urllib3](https://github.com/urllib3/urllib3) | HTTP connection pool (proxies, S3, WebDAV) | MIT | axross-full, axross-slim, pip [git] |
| [util-linux libraries](https://github.com/util-linux/util-linux) | UUIDs, block device and mount information (GLib, Python's uuid module) | LGPL-2.1-or-later AND BSD-3-Clause | axross-full, axross-slim |
| [VirtualBox (VBoxManage)](https://www.virtualbox.org) | VirtualBox disk images | GPL-3.0-only | auf dem eigenen System |
| [X.Org client libraries](https://www.x.org) | X11 display connection of Qt's xcb platform plugin | MIT AND X11 | axross-full, axross-slim |
| [xdg-utils (xdg-open)](https://gitlab.freedesktop.org/xdg/xdg-utils) | Opening files and links with the desktop's programs | MIT | auf dem eigenen System |
| [XZ Utils (liblzma)](https://tukaani.org/xz/) | LZMA/XZ compression (Python's lzma module, Pillow) | 0BSD AND LicenseRef-PublicDomain | axross-full, axross-slim |
| [zlib](https://zlib.net) | Deflate compression (Python, Qt and many libraries) | Zlib | axross-full, axross-slim |
| [Zstandard](https://github.com/facebook/zstd) | Zstandard compression (Pillow, system libraries) | BSD-3-Clause OR GPL-2.0-only | axross-full, axross-slim |

<details>
<summary>114 weitere Libraries, die mit den Projekten oben kommen</summary>

| Projekt | Benutzt von | Lizenz | Kommt mit |
|---|---|---|---|
| [alsa-lib](https://github.com/alsa-project/alsa-lib) | PyAV | LGPL-2.1-or-later | axross-full, pip (mit einem Extra) |
| [anyio](https://github.com/agronholm/anyio) | httpx2 | MIT | axross-full, axross-slim, pip (mit einem Extra) |
| [attrs](https://github.com/python-attrs/attrs) | jsonschema | MIT | axross-full, axross-slim |
| [azure-core](https://github.com/Azure/azure-sdk-for-python) | azure-storage-blob | MIT | axross-full, pip (mit einem Extra) |
| [bcrypt](https://github.com/pyca/bcrypt) | paramiko | Apache-2.0 | axross-full, axross-slim, pip |
| [blinker](https://github.com/pallets-eco/blinker) | Flask | MIT | axross-full, pip (mit einem Extra) |
| [botocore](https://github.com/boto/botocore) | boto3 | Apache-2.0 | axross-full, axross-slim, pip (mit einem Extra) |
| [brotli](https://github.com/google/brotli) | py7zr | MIT | axross-full, axross-slim, pip (mit einem Extra) |
| [Brotli (C library)](https://github.com/google/brotli) | Pillow | MIT | axross-full, axross-slim, pip |
| [cached-property](https://github.com/pydanny/cached-property) | exchangelib | BSD-3-Clause | axross-full, pip (mit einem Extra) |
| [certifi](https://github.com/certifi/python-certifi) | requests | MPL-2.0 | axross-full, axross-slim, pip (mit einem Extra) |
| [cffi](https://github.com/python-cffi/cffi) | cryptography | MIT-0 | axross-full, axross-slim, pip |
| [charset-normalizer](https://github.com/jawah/charset_normalizer) | impacket | MIT | axross-full, axross-slim, pip (mit einem Extra) |
| [click](https://github.com/pallets/click) | Flask | BSD-3-Clause | axross-full, axross-slim, pip (mit einem Extra) |
| [Cyrus SASL](https://www.cyrusimap.org/sasl/) | libpq | BSD-Attribution-HPND-disclaimer | axross-full, axross-slim, pip (mit einem Extra) |
| [dav1d](https://code.videolan.org/videolan/dav1d) | PyAV | BSD-2-Clause | axross-full, pip (mit einem Extra) |
| [FFmpeg (PyAV build)](https://ffmpeg.org) | PyAV | LGPL-3.0-or-later | axross-full, pip (mit einem Extra) |
| [FFmpeg (Qt Multimedia build)](https://ffmpeg.org) | Qt 6 | LGPL-2.1-or-later | axross-full, axross-slim, pip |
| [filelock](https://github.com/tox-dev/py-filelock) | huggingface_hub | MIT | axross-full, pip (mit einem Extra) |
| [Flask](https://github.com/pallets/flask) | impacket | BSD-3-Clause | axross-full, pip (mit einem Extra) |
| [FreeType](https://freetype.org) | Pillow | FTL OR GPL-2.0-or-later | axross-full, axross-slim, pip |
| [fsspec](https://github.com/fsspec/filesystem_spec) | huggingface_hub | BSD-3-Clause | axross-full, pip (mit einem Extra) |
| [GMP](https://gmplib.org) | PyAV | LGPL-3.0-or-later OR GPL-2.0-or-later | axross-full, pip (mit einem Extra) |
| [GnuTLS](https://www.gnutls.org) | PyAV | LGPL-2.1-or-later | axross-full, pip (mit einem Extra) |
| [google-api-core](https://github.com/googleapis/google-cloud-python) | google-api-python-client | Apache-2.0 | axross-full, pip (mit einem Extra) |
| [google-auth](https://github.com/googleapis/google-cloud-python) | google-api-python-client | Apache-2.0 | axross-full, pip (mit einem Extra) |
| [googleapis-common-protos](https://github.com/googleapis/google-cloud-python) | google-api-core | Apache-2.0 | axross-full, pip (mit einem Extra) |
| [Graphite](https://github.com/silnrsi/graphite) | HarfBuzz | LGPL-2.1-or-later OR MPL-1.1 OR GPL-2.0-or-later | axross-full, axross-slim |
| [h11](https://github.com/python-hyper/h11) | httpcore2 | MIT | axross-full, axross-slim, pip (mit einem Extra) |
| [HarfBuzz](https://github.com/harfbuzz/harfbuzz) | Qt 6, Pillow | MIT | axross-full, axross-slim, pip |
| [hf-xet](https://github.com/huggingface/xet-core) | huggingface_hub | Apache-2.0 | axross-full, pip (mit einem Extra) |
| [httpcore2](https://github.com/pydantic/httpx2) | httpx2 | BSD-3-Clause | axross-full, axross-slim, pip (mit einem Extra) |
| [httplib2](https://github.com/httplib2/httplib2) | google-api-python-client | MIT | axross-full, pip (mit einem Extra) |
| [httpx2](https://github.com/pydantic/httpx2) | huggingface_hub | BSD-3-Clause | axross-full, axross-slim, pip (mit einem Extra) |
| [huggingface_hub](https://github.com/huggingface/huggingface_hub) | faster-whisper | Apache-2.0 | axross-full, pip (mit einem Extra) |
| [ICU](https://icu.unicode.org) | Qt 6 | Unicode-DFS-2016 | axross-full, axross-slim, pip |
| [idna](https://github.com/kjd/idna) | requests | BSD-3-Clause | axross-full, axross-slim, pip (mit einem Extra) |
| [inflate64](https://github.com/miurahr/inflate64) | py7zr | LGPL-2.1-or-later | axross-full, axross-slim, pip (mit einem Extra) |
| [Intel VPL dispatcher](https://github.com/intel/libvpl) | PyAV | MIT | axross-full, pip (mit einem Extra) |
| [invoke](https://github.com/pyinvoke/invoke) | paramiko | BSD-2-Clause | axross-full, axross-slim, pip |
| [isodate](https://github.com/gweis/isodate) | azure-storage-blob | BSD-3-Clause | axross-full, pip (mit einem Extra) |
| [itsdangerous](https://github.com/pallets/itsdangerous) | Flask | BSD-3-Clause | axross-full, pip (mit einem Extra) |
| [jaraco.classes](https://github.com/jaraco/jaraco.classes) | keyring | MIT | axross-full, axross-slim, pip |
| [jaraco.context](https://github.com/jaraco/jaraco.context) | keyring | MIT | axross-full, axross-slim, pip |
| [jaraco.functools](https://github.com/jaraco/jaraco.functools) | keyring | MIT | axross-full, axross-slim, pip |
| [JBIG-KIT](https://www.cl.cam.ac.uk/~mgk25/jbigkit/) | LibTIFF | GPL-2.0-or-later | axross-full, axross-slim |
| [jeepney](https://gitlab.com/takluyver/jeepney) | keyring | MIT | axross-full, axross-slim, pip |
| [Jinja2](https://github.com/pallets/jinja) | Flask | BSD-3-Clause | axross-full, pip (mit einem Extra) |
| [jmespath](https://github.com/jmespath/jmespath.py) | boto3 | MIT | axross-full, axross-slim, pip (mit einem Extra) |
| [jsonschema-specifications](https://github.com/python-jsonschema/jsonschema-specifications) | jsonschema | MIT | axross-full, axross-slim |
| [libavif](https://github.com/AOMediaCodec/libavif) | Pillow | BSD-2-Clause | axross-full, axross-slim, pip |
| [libdrm](https://gitlab.freedesktop.org/mesa/drm) | PyAV | MIT | axross-full, pip (mit einem Extra) |
| [libjpeg-turbo](https://libjpeg-turbo.org) | Pillow, Qt 6 | IJG AND BSD-3-Clause | axross-full, axross-slim, pip |
| [libpng](https://www.libpng.org) | Pillow, Qt 6 | libpng-2.0 | axross-full, axross-slim, pip |
| [libpq](https://www.postgresql.org) | psycopg-binary | PostgreSQL | axross-full, axross-slim, pip (mit einem Extra) |
| [LibTIFF](https://libtiff.gitlab.io/libtiff/) | Pillow, Qt 6 | libtiff | axross-full, axross-slim, pip |
| [libunistring](https://www.gnu.org/software/libunistring/) | PyAV | LGPL-3.0-or-later OR GPL-2.0-or-later | axross-full, pip (mit einem Extra) |
| [libvpx](https://chromium.googlesource.com/webm/libvpx) | PyAV | BSD-3-Clause | axross-full, pip (mit einem Extra) |
| [libwebp](https://chromium.googlesource.com/webm/libwebp) | Pillow, Qt 6 | BSD-3-Clause | axross-full, axross-slim, pip |
| [libxcrypt](https://github.com/besser82/libxcrypt) | libpq | LGPL-2.1-or-later | axross-full, axross-slim, pip (mit einem Extra) |
| [Little CMS](https://www.littlecms.com) | Pillow | MIT | axross-full, axross-slim, pip |
| [lxml](https://github.com/lxml/lxml) | exchangelib | BSD-3-Clause | axross-full, pip (mit einem Extra) |
| [MarkupSafe](https://github.com/pallets/markupsafe) | Flask | BSD-3-Clause | axross-full, pip (mit einem Extra) |
| [more-itertools](https://github.com/more-itertools/more-itertools) | jaraco.classes | MIT | axross-full, axross-slim, pip |
| [multivolumefile](https://github.com/miurahr/multivolume) | py7zr | LGPL-2.1-or-later | axross-full, axross-slim, pip (mit einem Extra) |
| [Nettle](https://www.lysator.liu.se/~nisse/nettle/) | PyAV | LGPL-3.0-or-later OR GPL-2.0-or-later | axross-full, pip (mit einem Extra) |
| [oauthlib](https://github.com/oauthlib/oauthlib) | exchangelib | BSD-3-Clause | axross-full, pip (mit einem Extra) |
| [OpenBLAS](https://github.com/OpenMathLib/OpenBLAS) | numpy | BSD-3-Clause | axross-full, pip (mit einem Extra) |
| [OpenJPEG](https://www.openjpeg.org) | Pillow | BSD-2-Clause | axross-full, axross-slim, pip |
| [OpenLDAP client libraries](https://www.openldap.org) | libpq | OLDAP-2.8 | axross-full, axross-slim, pip (mit einem Extra) |
| [opentelemetry-api](https://github.com/open-telemetry/opentelemetry-python) | google-api-core | Apache-2.0 | axross-full, axross-slim, pip (mit einem Extra) |
| [Opus](https://opus-codec.org) | PyAV | BSD-3-Clause | axross-full, pip (mit einem Extra) |
| [packaging](https://github.com/pypa/packaging) | onnxruntime | Apache-2.0 OR BSD-2-Clause | axross-full, pip (mit einem Extra) |
| [pathvalidate](https://github.com/thombashi/pathvalidate) | piper-tts | MIT | axross-full, pip (mit einem Extra) |
| [protobuf](https://github.com/protocolbuffers/protobuf) | onnxruntime | BSD-3-Clause | axross-full, pip (mit einem Extra) |
| [psutil](https://github.com/giampaolo/psutil) | py7zr | BSD-3-Clause | axross-full, axross-slim, pip (mit einem Extra) |
| [pyasn1](https://github.com/pyasn1/pyasn1) | adb_shell | BSD-2-Clause | axross-full, axross-slim, pip (mit einem Extra) |
| [pyasn1_modules](https://github.com/pyasn1/pyasn1-modules) | impacket | BSD-2-Clause | axross-full, pip (mit einem Extra) |
| [PyAV](https://github.com/PyAV-Org/PyAV) | faster-whisper | BSD-3-Clause | axross-full, pip (mit einem Extra) |
| [pybcj](https://github.com/miurahr/pybcj) | py7zr | LGPL-2.1-or-later | axross-full, axross-slim, pip (mit einem Extra) |
| [pycparser](https://github.com/eliben/pycparser) | cffi | BSD-3-Clause | axross-full, axross-slim, pip |
| [pycryptodomex](https://github.com/Legrandin/pycryptodome) | impacket | BSD-2-Clause AND LicenseRef-PublicDomain | axross-full, axross-slim, pip (mit einem Extra) |
| [PyJWT](https://github.com/jpadilla/pyjwt) | msal | MIT | axross-full, axross-slim, pip (mit einem Extra) |
| [PyNaCl](https://github.com/pyca/pynacl) | paramiko | Apache-2.0 | axross-full, axross-slim, pip |
| [pyOpenSSL](https://github.com/pyca/pyopenssl) | impacket | Apache-2.0 | axross-full, axross-slim, pip (mit einem Extra) |
| [pyparsing](https://github.com/pyparsing/pyparsing) | httplib2 | MIT | axross-full, pip (mit einem Extra) |
| [pyppmd](https://github.com/miurahr/pyppmd) | py7zr | LGPL-2.1-or-later | axross-full, axross-slim, pip (mit einem Extra) |
| [PyQt6_sip](https://github.com/Python-SIP/sip) | PyQt6 | BSD-2-Clause | axross-full, axross-slim, pip |
| [pyspnego](https://github.com/jborean93/pyspnego) | smbprotocol | MIT | axross-full, axross-slim, pip (mit einem Extra) |
| [python-dateutil](https://github.com/dateutil/dateutil) | botocore | Apache-2.0 AND BSD-3-Clause | axross-full, axross-slim, pip (mit einem Extra) |
| [PyYAML](https://github.com/yaml/pyyaml) | ctranslate2 | MIT | axross-full, axross-slim, pip (mit einem Extra) |
| [Qt 6](https://www.qt.io) | PyQt6 | LGPL-3.0-only | axross-full, axross-slim, pip |
| [referencing](https://github.com/python-jsonschema/referencing) | jsonschema | MIT | axross-full, axross-slim |
| [requests-oauthlib](https://github.com/requests/requests-oauthlib) | exchangelib | ISC | axross-full, pip (mit einem Extra) |
| [requests_ntlm](https://github.com/requests/requests-ntlm) | exchangelib | ISC | axross-full, pip (mit einem Extra) |
| [rpds-py](https://github.com/crate-py/rpds) | jsonschema | MIT | axross-full, axross-slim |
| [rsa](https://github.com/sybrenstuvel/python-rsa) | adb_shell | Apache-2.0 | axross-full, axross-slim, pip (mit einem Extra) |
| [s3transfer](https://github.com/boto/s3transfer) | boto3 | Apache-2.0 | axross-full, axross-slim, pip (mit einem Extra) |
| [SecretStorage](https://github.com/mitya57/secretstorage) | keyring | BSD-3-Clause | axross-full, axross-slim, pip |
| [six](https://github.com/benjaminp/six) | impacket | MIT | axross-full, axross-slim, pip (mit einem Extra) |
| [stone](https://github.com/dropbox/stone) | dropbox | MIT | axross-full, pip (mit einem Extra) |
| [SVT-AV1](https://gitlab.com/AOMediaCodec/SVT-AV1) | PyAV | BSD-3-Clause-Clear | axross-full, pip (mit einem Extra) |
| [tokenizers](https://github.com/huggingface/tokenizers) | faster-whisper | Apache-2.0 | axross-full, pip (mit einem Extra) |
| [tqdm](https://github.com/tqdm/tqdm) | faster-whisper | MPL-2.0 AND MIT | axross-full, pip (mit einem Extra) |
| [truststore](https://github.com/sethmlarson/truststore) | httpcore2 | MIT | axross-full, axross-slim, pip (mit einem Extra) |
| [typing_extensions](https://github.com/python/typing_extensions) | azure-storage-blob | PSF-2.0 | axross-full, axross-slim, pip |
| [tzdata](https://github.com/python/tzdata) | exchangelib | Apache-2.0 | axross-full, pip (mit einem Extra) |
| [tzlocal](https://github.com/regebro/tzlocal) | exchangelib | MIT | axross-full, pip (mit einem Extra) |
| [uritemplate](https://github.com/python-hyper/uritemplate) | google-api-python-client | BSD-3-Clause OR Apache-2.0 | axross-full, pip (mit einem Extra) |
| [VMAF](https://github.com/Netflix/vmaf) | PyAV | BSD-2-Clause-Patent | axross-full, pip (mit einem Extra) |
| [Werkzeug](https://github.com/pallets/werkzeug) | Flask | BSD-3-Clause | axross-full, pip (mit einem Extra) |
| [x264](https://www.videolan.org/developers/x264.html) | PyAV | GPL-2.0-or-later | axross-full, pip (mit einem Extra) |
| [x265](https://bitbucket.org/multicoreware/x265_git) | PyAV | GPL-2.0-or-later | axross-full, pip (mit einem Extra) |
| [xmltodict](https://github.com/martinblech/xmltodict) | pywinrm | MIT | axross-full, pip (mit einem Extra) |

</details>
<!-- /third-party:readme -->
