# Axross — Bedienung

Diese Anleitung beschreibt, was du mit Axross tun kannst, sobald es
läuft. Installation: siehe [INSTALL.md](../INSTALL.md). Komplettes
deutsches Handbuch: [HANDBUCH.md](HANDBUCH.md).

Sprachen: [English](USAGE.md) · **Deutsch** · [Español](USAGE_es.md)

## Auf einen Blick

Axross ist ein Total-Commander-artiger Dateimanager für 22 Protokolle,
gebaut um drei Ideen herum:

- **Multi-Pane-Layout.** Beliebig viele Panes, horizontal oder
  vertikal gesplittet; jedes Pane verbindet sich mit seinem eigenen
  Backend (lokal, SFTP, S3, IMAP, …).
- **Backend-agnostische Primitives.** Papierkorb, atomare Schreibvorgänge,
  verschlüsselte Overlays, Versions-Timeline, Content-Addressable-Storage —
  alles funktioniert auf jedem Protokoll, auch dort, wo das native API
  es nicht kennt.
- **MCP-Server-Modus.** Axross kann headless laufen und jedes
  konfigurierte Backend als MCP-Tools exponieren — ein LLM-Client kann
  es dann steuern. Read-only by default; opt-in `--mcp-write` für
  Mutationen.

## Verbindungen

Der Connection-Manager (Strg+N) ist der Ort für Profile. Jedes Profil
wählt ein Protokoll und speichert Host / Username / Auth / Proxy /
protokollspezifische Optionen. Sensible Felder (Passwörter,
OAuth-Secrets, Azure-Connection-Strings) gehen in den OS-Keyring; die
Profil-JSON selbst enthält nie Klartext-Credentials.

- **Host-Key-Verifizierung.** Erstkontakt bei SSH zeigt einen
  SHA-256-Fingerprint-Dialog vor dem Connect; vertraute Keys
  persistieren in `~/.ssh/known_hosts`.
- **OAuth-Flows.** OneDrive / SharePoint / Google Drive / Dropbox
  öffnen einen Browser für den Consent-Schritt. Tokens werden unter
  `~/.config/axross/<provider>_token.json` mit `0o600` ab Geburt
  gespeichert. Profil-Proxies gelten für API-/Token-Traffic, den
  Axross selbst kontrolliert; die externe Browser-Consent-Seite kann
  Browser- oder System-Proxy-Settings verwenden. App-Registrierung pro Anbieter:
  [OAUTH_SETUP.md](../OAUTH_SETUP.md).
- **Proxy-Support.** Per Profil SOCKS5 / SOCKS4 / HTTP-CONNECT für
  Backends mit echtem Transport-Hook. SOCKS5 löst Hostnamen
  serverseitig auf (kein DNS-Leak). SOCKS4 hängt vom Transport ab:
  Raw-Socket-Backends können SOCKS4a für serverseitige Namensauflösung
  nutzen, HTTP-SDK-Stacks können lokal auflösen. Für DNS-Leak-Schutz
  SOCKS5 verwenden. Backends ohne sauberen SOCKS/HTTP-Support warnen
  statt Proxy-Felder still zu ignorieren. S3 ist nur über HTTP-CONNECT
  proxyfähig; Rsync kann über OpenBSD `nc` `proxy_username`, aber kein
  `proxy_password` transportieren. Requests-basierte SDK-Sessions, die
  Axross kontrolliert, ignorieren `HTTP_PROXY` / `HTTPS_PROXY` aus der
  Prozess-Umgebung; das Profil ist die Quelle der Route.
- **OpSec-Overrides.** Profil-Felder steuern SSH-Keepalive,
  SMB-Workstation-Name, Telnet-NAWS, rsync-Metadaten-Stripping. Siehe
  [OPSEC.md](OPSEC.md) für das Threat-Modell.

## Multi-Pane-Layout

- Panes anlegen mit **Strg+T**, splitten mit **Strg+Shift+H** /
  **Strg+Shift+V**, schließen mit **Strg+W**.
- Aktives Pane bekommt blauen Rahmen; das **Ziel**-Pane (Kopierziel)
  bekommt einen grünen. Letztes fokussiertes Pane wird Ziel.
- **Alt+Links / Alt+Rechts** durchschreiten Pane-Historie;
  **Strg+Tab** zykliert.
- Drag-and-Drop zwischen Panes startet einen Transfer (lokal↔remote,
  remote↔remote, cross-Protokoll).

## Transfers

Jeder pane-übergreifende Copy/Move geht in die Transfer-Queue. Das
untere Dock zeigt Fortschritt, Throughput und ETA. Transfers laufen in
Worker-Threads und überleben einen abgewiesenen Dialog oder ein
geschlossenes Pane.

- **Atomare Semantik.** Jeder Schreibvorgang geht in eine Sibling-
  Tempdatei (`.tmp-<hex>.tmp`) und wird am Ende reingerannt. Auf
  S3 / Azure / Dropbox / GDrive / OneDrive / IMAP / Rsync ist der
  Upload selbst schon atomar; sonst ist der Rename der Commit-Punkt.
- **Resume.** Fehlgeschlagene Transfers können fortgesetzt werden;
  die Teilbytes auf dem Ziel werden wiederaufgenommen.
- **Retry.** „Retry Failed" wiederholt jeden Fehler-Transfer der Queue.
- **Verify.** Pro-Job-Flag `verify_checksum` re-hasht das Ziel nach
  dem Upload und lehnt bei Mismatch ab.

## Backend-übergreifender Feature-Layer

Diese Module funktionieren auf **jedem** Backend — auch dort, wo das
native Protokoll sie nicht kennt.

| Modul | Was es liefert |
|---|---|
| `core.atomic_io` | `atomic_write(backend, path, data)` — native-atomar auf S3 / Azure / Dropbox / GDrive / OneDrive / IMAP / Rsync; tmp-then-rename überall sonst. |
| `core.atomic_recovery` | Crash-Recovery-Sweep für `.tmp-*.tmp`-Leichen. Per-Pane-Navigate-Hook entfernt >1 h alte Reste. Legacy-Präfix `.axross-atomic-*.tmp` wird weiter erkannt. |
| `core.server_ops` | `server_side_copy` / `server_side_move` mit automatischem Fallback auf `open_read` + `open_write`, wenn das Backend keinen nativen Copy hat. |
| `core.watch` | File-Watching-API. Nativ inotify auf LocalFS (mit watchdog), Polling überall sonst. Toggle in der Pfadleiste. |
| `core.trash` | Universaler Papierkorb: `trash` / `list_trash` / `restore` / `empty_trash`. Per-Entry-Sidecar-Metadata, kein zentrales Manifest. |
| `core.xlink` | Cross-Protokoll-Symlinks per `.axlink`-JSON-Pointer-Datei. |
| `core.encrypted_overlay` | AES-256-GCM at-rest, PBKDF2-HMAC-SHA256 mit 200 k Iterationen. |
| `core.cas` | Content-Addressable-Layer: SQLite-Index `(backend, path) → checksum`, Duplikat-Erkennung, `ax-cas://<algo>:<hex>`-URLs. |
| `core.snapshot_browser` | Uniforme Versionshistorie über S3, Dropbox, GDrive, OneDrive, Azure Blob. |
| `core.metadata_index` | Offline-SQLite-Suche nach Name / Ext / Größe / mtime. |
| `core.previews` | Lokaler Bild-Thumbnailer mit MIME-Allowlist, Größenkappen, Qt-Allocator-Gate. F3 / Doppelklick. |
| `core.archive` | Sichere Entpackung von zip / tar / 7z (`.zip .xpi .jar .war .apk .epub .docx .xlsx .odt .tar .tar.gz .tgz .tar.bz2 .tbz2 .tar.xz .txz .7z`). Zip-Slip-/Bomb-/Lying-Metadata-Guards; `.7z` braucht das `[archive]`-Extra. |
| `core.elevated_io` | `pkexec`-gated lokales Lesen für `/etc/shadow` & Co. — Axross hält selbst keine Privilegien. „Open as root…"-Kontextmenü. |
| `core.fuse_mount` | FUSE-Mount jedes Backends. Read-only by default; `writeable=True` aktiviert create / write / unlink / mkdir / rename. Optionales `[fuse]`-Extra. |
| `core.mcp_server` | Stdio-JSON-RPC-MCP-Server, der das konfigurierte Backend als Tools exponiert. `--mcp-write` ergänzt mutierende Tools, gecappt auf einen pfad-traversal-sicheren Root. |

## Rechtsklick-Aktionen

| Aktion | Trigger | Was passiert |
|---|---|---|
| Neuer Ordner | Rechtsklick | `backend.mkdir(path)` auf jedem schreibfähigen Backend. |
| Neue Datei… | Rechtsklick | 0-Byte-Datei via `backend.open_write(path).write(b"")`. |
| Neuer Symlink… | Rechtsklick | Zwei Prompts. Sichtbar nur auf Backends mit `supports_symlinks=True`. |
| Neuer Hardlink… | Rechtsklick | Gleiche Form; Cross-Device → `OSError(EXDEV)`. |
| Find in Index | `Strg+Shift+F` | Suche im Offline-Metadaten-Index. |
| CAS Duplicate Finder | View-Menü | Gruppieren nach Content-Hash, `ax-cas://…`-URLs kopieren. |
| Move to Trash | Rechtsklick | Universaler Papierkorb. |
| Show Trash… | Rechtsklick | Wiederherstellen / Permanent-Löschen-Dialog. |
| Show Versions… | Rechtsklick | Snapshot-Browser — Save Version As, Restore as Current. |
| Show Checksum… | Rechtsklick | Native-Checksum (S3 ETag, Drive md5, ssh sha256sum…) mit Stream-Hash-Fallback. |
| Extract to folder… | Rechtsklick auf Archiv | Gleichnamiger Geschwister-Ordner, cancelbar, mit `core.archive`-Safety-Guards. Nur lokale Backends. |
| Encrypt / Decrypt mit Passphrase | Rechtsklick | AES-256-GCM. |
| Open as root… | Rechtsklick | Lokal-only; pkexec-Flow. Versteckt wenn polkit/pkexec fehlen. |
| Create XLink… | Rechtsklick | Cross-Protokoll-Pointer-Datei. |
| Mount as FUSE (read-only / read-write)… | Rechtsklick | Zwei Menü-Einträge, damit der Mount-Modus upfront sichtbar ist. Toggelt zu „Unmount FUSE" wenn aktiv. |
| Batch-Umbenennen… | Rechtsklick (Mehrfachauswahl) | Find/Replace oder Regex mit Live-Preview + atomarer Rename. |
| Berechtigungen… | Rechtsklick | chmod-Dialog mit Checkbox-Grid + Oktal-Eingabe. |

## Pfadleiste

- **Auto-Refresh ◉** abonniert das Pane auf `core.watch`; debounced
  Refresh bei Backend-Änderungen.
- **Live-Filter** in der Pfadleiste filtert die Liste in Echtzeit.
- **Bookmarks** als linkes Dock; F8 setzt Bookmark, F12 toggelt das
  Dock.

## Editoren und Viewer

- **Texteditor** (built-in) — für Dateien < 1 MB, mit Konflikt-
  Erkennung beim Speichern.
- **Hex-Editor** — read-only; nützlich für Triage auf Remote-Dateien.
- **Bild-Viewer** — F3 / Doppelklick, MIME-Allowlist, Größen-
  kappen.
- **SSH-Terminal** — Tab-Dock neben der Transfer-Queue. Lokales PTY
  (`pty.fork()`) und remote-SSH-über-paramiko stehen beide bereit;
  die SSH-Variante reused die bestehende Verbindung.

## Transfer-/Terminal-/Log-Dock

- Der untere Streifen hat drei Tabs: **Transfers**, **Terminal**,
  **Log**. Jeder flasht bernsteinfarben, wenn off-screen etwas
  passiert (Transfer-Status, Shell-Output, Log-Zeile). Klick raist
  + cleart.
- Rechtsklick auf einen Transfer für **Cancel**, **Retry**, **Open
  destination folder**.

## Scripting & eingebettete REPL

Axross liefert ein kuratiertes Python-Surface (``axross.*``) mit
89 öffentlichen Namen (Verben + 9 Result-Klassen für Network-
Helper). Drei Wege zum gleichen Surface:

- **Console-Dock** (View-Menü) — REPL mit Multi-Line-Input,
  History, Tab-Completion, Seitenpanel mit jeder Funktion + Docstring.
- **Headless** — ``axross --script myscript.py`` führt dein
  Python im selben Namensraum aus; ideal für Cron/CI/Batches.
- **MCP** — wenn ``--mcp-allow-scripts`` gesetzt ist, ist das
  Surface auch über MCP-Tool-Calls erreichbar.

Quick examples:

```python
b = axross.localfs()
items = b.list_dir("/var/log")[:10]
hits = axross.grep(b, "/var/log", r"kernel:.*panic")

src = axross.open("my-sftp")           # benannt per Connection Manager
axross.copy(src, "/etc/hosts", axross.localfs(), "/tmp/hosts.bak")

probe = axross.http_probe("https://example.com")
ips = axross.dns_resolve("example.com")
```

API-Browser:
- ``axross.help()`` — Cheat-Sheet nach Kategorie
- ``axross.docs("backend")`` / ``"scripts"`` / ``"slash"`` —
  Markdown-Referenz pro Topic
- ``docs/SCRIPTING_REFERENCE.md`` — vollständige Verb-/Klassen-Doku

REPL-Slash-Commands: ``.help``, ``.scripts``, ``.save <name>``,
``.load <name>``, ``.run <name>``, ``.delete <name>``, ``.open``.

Detaillierte Verb-Listen siehe **[USAGE.md](USAGE.md)** (EN) oder
``docs/SCRIPTING_REFERENCE.md``.

### UI-Helfer — message / confirm / toast

Skripte + REPL können modale Dialoge und Toasts zeigen, die
**ohne Qt-Event-Loop sauber auf stdout/stdin zurückfallen** (das
gleiche Skript läuft also in Cron/CI weiter):

```python
axross.message("Backup fertig (123 Dateien kopiert)",
               level="success")

if axross.confirm("47 Dateien löschen? Nicht rückgängig.",
                  default_yes=False):
    for p in doomed:
        backend.remove(p)

axross.toast("Verbindung weg — re-try", level="error")
axross.toast("1,2 MB gespeichert", level="success", timeout=2)
```

Levels: ``"info"`` (blau), ``"success"`` (grün), ``"warning"``
(gelb), ``"error"`` (rot) — jeweils mit eingebettetem SVG-Status-
Icon und axross-Glyph als Fenster-Icon.

## SSH-/SCP-Terminal-Multiplexing

Wenn du via SSH oder SCP verbunden bist, öffnet axross **eine**
TCP-Verbindung + paramiko-Transport. Folge-Operationen multiplexen
darauf:

- **SFTP/Datei-Ops** laufen auf einem dedizierten Channel.
- **Open Terminal** (Terminal-Dock) allokiert einen weiteren
  Channel mit PTY — voll-interaktive Shell, kein zweites Login,
  kein zweiter Key-Challenge. Funktioniert gleich für SSH und SCP.

Damit bekommt eine SCP-Pane den selben "Remote-Shell hier
öffnen"-Rechtsklick wie eine SSH-Pane, auf der gleichen Verbindung.

## Keyring-Auto-Detect & Re-Detect

Gespeicherte Passwörter landen im OS-Keyring (Secret-Service /
KWallet / Windows Credential Locker / macOS Keychain / KeePassXC
Secret-Service-Plug-in). axross probt beim ersten Speichern auf
ein lauffähiges Backend; ohne Daemon ist "Save in keyring"
deaktiviert mit konkreter Install-Hilfe:

- **Arch:** ``sudo pacman -S gnome-keyring`` (oder kwallet,
  oder keepassxc)
- **Debian:** ``sudo apt install gnome-keyring``
- **Fedora:** ``sudo dnf install gnome-keyring``

Wenn du den Daemon **nach** axross-Start aufmachst, hilft
**File → Re-detect System Keyring** (oder einfach noch mal Speichern
versuchen — der nächste ``store_password`` re-checkt automatisch).

## MCP-Server

Axross läuft wahlweise als Model-Context-Protocol-Server, sodass ein
LLM-Client (Claude Desktop, Cline, ein eigener Agent) jedes
konfigurierte Backend über JSON-RPC-Tools steuern kann.

```bash
axross --mcp-server                                  # read-only, stdio
axross --mcp-server --mcp-write                      # Schreib-Tools (auf Root gecappt)
axross --mcp-server --mcp-http 127.0.0.1:7331        # HTTP-Loopback
```

17 Tools (`list_dir`, `stat`, `read_file`, `checksum`, `search`,
`walk`, `grep`, `list_versions`, `open_version_read`, `preview` +
7 Schreib-Tools bei `--mcp-write`), `resources/*`-Endpoints,
`notifications/message`-Log-Forwarding, Per-Tool-Timeouts,
Per-Session-Token-Bucket-Rate-Limits, HTTP-Sessions mit SSE-Progress,
optional Multi-Backend-Routing.

Volle Referenz: **[docs/MCP_de.md](MCP_de.md)** (DE) · [MCP.md](MCP.md) (EN) · [MCP_es.md](MCP_es.md) (ES).

## Konfigurationsdateien

- `~/.config/axross/profiles.json` — Verbindungsprofile (`0o600`).
- `~/.config/axross/bookmarks.json` — Bookmark-Bar.
- `~/.config/axross/session.json` — Pane-Layout beim letzten Beenden.
- `~/.config/axross/column_prefs.json` — Pro-Pane-Spaltenbreiten.
- `~/.config/axross/<provider>_token.json` — OAuth-Refresh-Tokens (`0o600`).
- `~/.local/state/axross/logs/axross.log` — rotierendes Logfile (5 MB, 3 Backups).

## Wo es weitergeht

- **Nur verbinden?** [OAUTH_SETUP.md](../OAUTH_SETUP.md) führt durch
  die Cloud-Storage-App-Registrierungen.
- **Auf feindlichen Netzen?** [OPSEC.md](OPSEC.md) listet jeden
  Client-zu-Server-Fingerprint, den Axross sendet, plus Mitigations.
- **Axross von einem LLM aus steuern?** [MCP_de.md](MCP_de.md) ist
  die kanonische Protokoll-Referenz.
- **Bauen oder beitragen?** [DEVELOPMENT.md](DEVELOPMENT.md) hat
  Test-Suite, Lab-Compose und Coverage-Matrix.
- **Volles Handbuch?** [HANDBUCH.md](HANDBUCH.md).
