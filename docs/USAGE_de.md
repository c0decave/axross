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

Der Connection-Manager (Strg+Shift+N) ist der Ort für Profile;
Quick Connect (Strg+N) öffnet ein gespeichertes. Jedes Profil
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

- Panes anlegen durch Splitten mit **Strg+Shift+H** /
  **Strg+Shift+V**, schließen mit **Strg+W**.
- Aktives Pane bekommt blauen Rahmen; das **Ziel**-Pane (Kopierziel)
  bekommt einen grünen. Letztes fokussiertes Pane wird Ziel.
- Ein Pane wird aktiv, wenn die Maus 1 s darin ruht.
  **View → Activate Pane** stellt 1, 2 oder 3 s ein, oder **On Click**.
  Der Tastaturfokus folgt nur aus der Dateiliste eines anderen Panes,
  nie aus einem Textfeld.
- **Alt+Links / Alt+Rechts** durchschreiten Pane-Historie;
  **Tab** / **Shift+Tab** in einer Dateiliste wechseln das Pane.
- Drag-and-Drop zwischen Panes startet einen Transfer (lokal↔remote,
  remote↔remote, cross-Protokoll).

### Das Layout kommt beim Start zurück

Beim Beenden speichert axross das Layout in `session.json`; der
nächste Start baut es automatisch wieder auf:

- den Splitter-Baum mit seinen Größen, die Window-Geometry, das
  Dock-Layout (welche Docks offen sind und wo) und das Theme;
- lokale Panes auf ihren Ordnern — ein inzwischen gelöschter Ordner
  öffnet stattdessen den Home-Ordner, ohne Dialog;
- lokale Terminal-Panes als frische Shell an derselben Stelle, im
  Ordner, in dem die alte Shell stand (Home, wenn er fehlt).

**Ein Start verbindet nie.** Ein Pane oder Terminal eines gespeicherten
Connection-Profils kommt als Placeholder zurück, *Not connected —
&lt;Profil&gt;*, mit einem **Reconnect**-Button. Bei einem File-Pane
verbindet Reconnect genau wie das Öffnen des Profils über Quick Connect
(Passwort-Prompt, Host-Key-Prüfung) und setzt das Pane an die Stelle
des Placeholders, auf seinen gespeicherten Ordner. Bei einem Terminal
öffnet es das Terminal des Profils wie ein Layout-Preset (gespeichertes
Passwort, kein Prompt). Der Restore führt keine Scripts und keine
Extensions aus, und der Paranoid Security Mode bleibt unberührt.

**File > Restore Layout on Start** (standardmäßig an) schaltet das ab;
die Wahl landet sofort in `session.json`, und ein Start zeigt dann das
Default-Layout mit einem Pane. Eine fehlende, unlesbare oder ungültige
`session.json` startet ebenfalls mit dem Default-Layout; der Grund steht
im Log. **File > Restore Last Session** (**Strg+Shift+R**) baut das
gespeicherte Layout weiterhin auf Wunsch auf, und dort verbinden
Remote-Panes.

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
| Duplicate Finder | View-Menü | Gruppieren nach Content-Hash, `ax-cas://…`-URLs kopieren; markierte Kopien in den axross-Trash verschieben, nachdem live geprüft ist, dass eine echte andere Kopie bleibt. |
| View Media… / View Selected Media… | Rechtsklick, View-Menü | Bilder, PDFs und Videos des Ordners (optional rekursiv) oder der Auswahl als Overview-Grid, Viewer zum Durchklicken oder Slideshow — siehe *Editoren und Viewer*. |
| Show / Remove / Export Metadata… | Rechtsklick | EXIF / GPS / XMP / IPTC, Office-Properties, PDF-Info, Audio-/Video-Tags der Auswahl — oder des ganzen Ordners, wenn nichts ausgewählt ist (Unterordner optional) — siehe *Datei-Metadata*. |
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
  Dock. Ordner, die aus einem Pane ins Dock gezogen werden (freie
  Fläche, Gruppe oder zwischen zwei Einträge), werden dort zu Bookmarks,
  Remote-Ordner mit ihrem Connection-Profile. Dateien und Ordner, die
  *auf* ein Bookmark fallen, werden in dessen Ordner verschoben (Strg
  kopiert), mit derselben Prüfung auf vorhandene Namen wie F5 / F6;
  ein fehlender Ordner oder ein Remote, das nicht antwortet, wird
  gemeldet und nichts eingereiht, ein Remote-Bookmark ohne offene
  Connection verbindet zuerst und überträgt dann.

## Editoren und Viewer

Jeder Viewer, Editor und Dialog hat oben rechts zwei Buttons: [x]
schließt ihn, der Button links daneben maximiert ihn über den ganzen
Bildschirm und stellt die vorherige Größe wieder her. `Ctrl+M` tut
dasselbe, ebenso der Maximize-Button der Titelleiste.

- **Texteditor** (built-in) — für Dateien < 1 MB, mit Konflikt-
  Erkennung beim Speichern.
- **Hex-Editor** — read-only; nützlich für Triage auf Remote-Dateien.
- **Bild-Viewer** — F3 / Doppelklick, MIME-Allowlist, Größen-
  kappen.
- **Media Viewer** — *View → View Media…* oder Rechtsklick → *View
  Media…* auf den Ordner (*View Selected Media…* für ausgewählte
  Dateien und Ordner). Wählbar sind die Typen (Bilder inkl. SVG,
  PDFs, Videos über QtMultimedia), ob Unterordner einbezogen werden
  (Tiefe 1–32; höchstens 5000 Dateien, Symlink-Ordner werden nicht
  verfolgt, unlesbare Ordner übersprungen und gezählt) und der
  Start: **Overview first** (Thumbnail-Grid mit Filter, Sortierung
  nach Name / Datum / Ordner und Größen-Slider; Enter oder
  Doppelklick öffnet), **Start slideshow** oder **Click through**.
  Im Viewer: Links / Rechts / PageUp / PageDown / Space blättern
  (Stopp am ersten und letzten Element; im PDF seitenweise, nach der
  letzten Seite zum nächsten Element), Home / End, F11 Fullscreen,
  Ctrl+M Maximize / Restore (das Fenster merkt sich Größe, Position
  und Maximize-Zustand für das nächste Öffnen),
  Mausrad oder `+` / `-` Zoom, `F` Fit, `1` 100 %, `R` drehen, `S`
  Slideshow (Intervall in Sekunden; die Slideshow läuft im Kreis,
  ein Video spielt bis zum Ende), Esc zurück zur Overview, nochmal
  Esc schließt. **Entf** (Delete) löscht die gezeigte Datei (oder
  das ausgewählte Tile) nach einer Rückfrage; das Bild oder ein Tile
  auf eine Pane ziehen verschiebt es dorthin, mit Strg wird kopiert -
  wie ein Drag aus der Pane, aus der der Viewer kam (in einem
  hineingezoomten Bild pannt der Drag stattdessen). Der
  Bild-Viewer kann beides auch. Funktioniert auf jedem Backend: Remote-Dateien
  werden bis zum *Open Size Limit* in ein privates Temp-Verzeichnis
  kopiert und danach gelöscht; zu große, verschlüsselte oder kaputte
  Dateien zeigen den Grund statt des Inhalts. SVG wird nur ohne
  DOCTYPE/Entities, Skripte und Verweise nach außen gerendert. Der
  `paranoid`-Mode sperrt den Viewer.
  `I` (oder der *Info*-Button) zeigt die Metadata des aktuellen
  Elements in einem Side-Panel, mit *Remove metadata* — auch im
  Bild-Viewer.
- **SSH-Terminal** — Tab-Dock neben der Transfer-Queue. Lokales PTY
  (`pty.fork()`) und remote-SSH-über-paramiko stehen beide bereit;
  die SSH-Variante reused die bestehende Verbindung.

## Datei-Metadata

Rechtsklick → **Show Metadata…**, **Remove Metadata…** oder **Export
Metadata…** wirkt auf die ausgewählten Dateien und Ordner, ohne Auswahl
auf den Ordner selbst. Das Metadata-Fenster zeigt je Datei eine Zeile,
ihre Felder hintereinander als `key: value`; Doppelklick oder Rechtsklick
→ *Properties…* öffnet alle Felder dieser Datei, gruppiert und eins pro
Zeile, Rechtsklick → *Remove Metadata* bereinigt nur die ausgewählten
Dateien. Dazu Filter, *Copy* (die Felder der ausgewählten Dateien als
Text), *Export…* (JSON oder CSV) und *Remove Metadata* für alle
gelisteten Dateien. Ordner werden flach gelesen;
*Include subfolders* geht tiefer (höchstens 5000 Dateien, Tiefe 8,
Symlink-Ordner werden nicht verfolgt). Lesen und Entfernen laufen im
Hintergrund mit Fortschritt und *Cancel*. In Bild- und Media-Viewer
öffnet `I` dieselbe Information als Side-Panel.

| Art | Lesen | Entfernt | Bleibt |
|---|---|---|---|
| JPEG, PNG, WebP, GIF | eingebaut | EXIF (GPS, Kamera, Seriennummern, Zeiten, Autor, Software), eingebettete Thumbnails, XMP, IPTC, Kommentare, PNG-Text-Chunks, Daten hinter dem Bild | EXIF-Orientation, ICC-Farbprofil; die Pixel werden nie neu kodiert und auf Gleichheit geprüft |
| TIFF | eingebaut | dasselbe, über verlustfreies Neuspeichern | Orientation, ICC-Profil; JPEG-komprimiertes TIFF wird abgelehnt |
| docx / xlsx / pptx, odt / ods / odp | eingebaut | `docProps/core.xml`, `app.xml`, `custom.xml`, ODF-`meta.xml`, der Zip-Kommentar | alle anderen Teile, die zu denselben Bytes entpacken |
| PDF | pypdf, sonst QtPdf | Info-Dictionary, XMP-Streams, PieceInfo, frühere Revisionen (komplettes Neuschreiben) | — braucht das Extra `[metadata]` (`pip install 'axross[metadata]'`) |
| Audio / Video | `ffprobe` | alle Tags und Kapitel, Data-Streams (GPS-Spuren von Kameras), das Cover-Bild von Audio-Dateien (`ffmpeg -c copy`, keine Neukodierung) | die Streams |

**Wie geschrieben wird** — *Tools → Metadata Settings…*:

- **In place** (Default): die Datei wird atomar ersetzt, das Original
  bleibt im axross-Trash. Ein Lauf — eine Datei oder ein ganzer
  Ordner — ist ein Eintrag für *Edit → Undo Last Operation* (`Ctrl+Z`),
  der jedes Original Byte für Byte zurückholt, aber nur solange die
  Datei noch genau das enthält, was das Entfernen geschrieben hat.
- **Cleaned copy**: `name.clean.ext` neben dem Original
  (`name.clean (1).ext`, wenn es das schon gibt); nichts wird
  überschrieben.

Eine Nachfrage gibt es nur, wenn dort *Ask before removing metadata*
angehakt ist. Remote-Dateien gehen über eine private Temp-Kopie bis zum
*Open Size Limit* und zurück über den atomaren Schreibweg des Backends;
eine Verbindung, deren Trash nicht beschreibbar ist, bekommt
stattdessen eine bereinigte Kopie, und das Ergebnis sagt es. Eine Datei,
die sich während des Bereinigens ändert, bleibt unangetastet. Im
`paranoid`-Mode funktionieren Lesen und Entfernen, außer bei Audio /
Video: das hieße ffprobe / ffmpeg auf den Dateiinhalt loszulassen.
Skripte: `axross.metadata`, `axross.remove_metadata`,
`axross.export_metadata` (siehe [SCRIPTING_de.md](SCRIPTING_de.md)).

## Transfer-/Terminal-/Log-Dock

- Der untere Streifen hat drei Tabs: **Transfers**, **Terminal**,
  **Log**. Jeder flasht bernsteinfarben, wenn off-screen etwas
  passiert (Transfer-Status, Shell-Output, Log-Zeile). Klick raist
  + cleart.
- Rechtsklick auf einen Transfer für **Cancel**, **Retry**, **Open
  destination folder**.
- Das Terminal (Dock und Terminal-Pane) ist ein VT100-/xterm-Screen:
  Carriage Return, Cursor-Bewegungen, Erase, Scroll-Regionen und der
  Alternate Screen funktionieren, also stehen zsh-Prompts,
  Zeilen-Editing, `less`, `top` und Editoren an der richtigen Stelle.
  Die Terminal-Größe der Shell ist die Größe der Terminal-Fläche und
  folgt jedem Resize (`stty size` zeigt sie). Farben werden nicht
  angezeigt.
- Tasten im Terminal gehen an die Shell: Strg+Buchstabe (auf macOS die
  Control-Taste), Funktionstasten, Pfeile und Editiertasten — Strg+W,
  Strg+Q oder F6 schließen dort also keine Pane, beenden axross nicht
  und verschieben keine Dateien. Einfügen mit Strg+Shift+V (macOS:
  Command+V), Mittelklick oder Kontextmenü; der Text geht an die Shell.
  Command-Shortcuts auf macOS und die Zoom-Tasten bleiben bei axross.
- Während eines Datei-Drags über einer Pane bekommt die Zeile, in die
  der Drop geht, einen Rahmen, und ein Hinweis am Cursor nennt den
  Ordner: *Move to …* oder mit Strg *Copy to …*. Die Zeile `..` ist
  der Ordner darüber.

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

Der headless-Prompt von ``confirm()`` fragt nur, wenn stdin ein
Terminal ist. Ohne Mensch — Cron, Pipe, der Kindprozess des
Scripts-Docks, ein MCP-``script_run`` oder ``AXROSS_NONINTERACTIVE=1`` —
wirft er ``axross.NonInteractiveError``, statt den Default zu nehmen;
``assume_yes=True`` antwortet dort ohne Rückfrage mit Ja.

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
ein lauffähiges Backend. Jedes andere keyring-Backend funktioniert
ebenso, solange es keine Eingabe im Terminal braucht (etwa
keyring-pass oder keyrings.cryptfile über ``keyringrc.cfg``); sind
mehrere installiert, nimmt axross das, das keyring selbst zuerst
nimmt. Klartextdateien (``PlaintextKeyring``) und das
``EncryptedKeyring`` von keyrings.alt, das sein Master-Passwort im
Terminal abfragt, werden nicht genutzt. Ohne brauchbares Backend ist
"Save in keyring" deaktiviert mit konkreter Install-Hilfe:

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

Die Read-only-Datei-Tools (`list_dir`, `stat`, `read_file`,
`checksum`, `search`, `walk`, `grep`, …), die Schreib-Tools bei
`--mcp-write`, die Capability-Gruppen von `--mcp-tools`
(`axross --mcp-list-tools` gibt jedes Tool aus, das ein Satz Flags
anbietet), `resources/*`-Endpoints,
`notifications/message`-Log-Forwarding, Per-Tool-Timeouts,
Per-Session-Token-Bucket-Rate-Limits, HTTP-Sessions mit SSE-Progress,
optional Multi-Backend-Routing.

Volle Referenz: **[docs/MCP_de.md](MCP_de.md)** (DE) · [MCP.md](MCP.md) (EN) · [MCP_es.md](MCP_es.md) (ES).
Für LLM-Clients: [LLM_GUIDE.md](LLM_GUIDE.md) (englisch).

## Agent-Dock — ein lokales LLM arbeitet mit axross

View > Panels > Agent (Ctrl+Shift+A) öffnet einen Chat mit einem
LLM-Profil (die Profile des Analyse-Docks: LM Studio, Ollama, vLLM,
llama.cpp oder ein anderer OpenAI-kompatibler Server; LLM… verwaltet
sie). Das Modell arbeitet mit denselben Tools wie der MCP-Server, im
oben angezeigten Ordner (dem des aktiven Panes, wenn es lokale Dateien
zeigt).

**Tabs.** Jeder Tab ist ein eigener Verlauf mit eigenem Modell,
Protection-Mode, Sandbox, Ordner und Tools: „+" oder Ctrl+T öffnet
einen, ein Doppelklick benennt ihn um. Mit *Keep tabs* (Tools > Agent
Settings…) ist jeder Tab eine JSON-Datei in
`~/.config/axross/agent/sessions/` (`0o600`) und kommt beim nächsten
Start wieder. Ctrl+Enter sendet, Esc stoppt, Pfeil hoch/runter holt
frühere Aufgaben zurück.

**Protection-Modes** (je Tab):

- **Ask** — jede Änderung und jeder Remote-Befehl wartet auf Ja in
  einem Dialog, der Tool und Argumente zeigt (Passphrasen maskiert).
- **Plan** — der Agent liest nur und schreibt einen Plan; *Run this
  plan* führt ihn dann im Ask-Mode aus.
- **Auto** — Änderungen laufen ohne Frage; Remote-Befehle und Tools
  eines MCP-Servers auf „always" fragen weiter.
- **Bypass** — nichts fragt. Nur wählbar, wenn in den Agent Settings
  eingeschaltet, nie im Security-Mode paranoid, und rot markiert.

**Dateien übergeben.** Das „+"-Menü hängt Auswahl oder Ordner des
aktiven Panes an, Dateien aus einem Dialog oder einen Pfad aus der
Zwischenablage; Dateien lassen sich aus einem Pane auf den Tab ziehen,
oder *Send to Agent* im Rechtsklick-Menü des Panes. Eine lokale Datei
außerhalb des Tab-Ordners macht ihren Ordner für diesen Tab lesbar
(read-only).

**Tools** (Tools ▸ im Tab): die Datei-Tools, die angehakten Gruppen
(metadata, filetype, archive, …), *Allow changes to files*, *Allow
remote commands*, eine Zeile `mcp:<name>` je MCP-Server und `ext:<id>`
je Extension mit Agent-Tools. Immer dabei: `ask_user` (der Agent fragt
dich etwas) und `update_plan` (eine Checkliste über dem Eingabefeld).

**Topics ▸** füllt das Eingabefeld mit einer vorbereiteten Aufgabe —
System inventory, Install or update software (im Plan-Mode), Service
status, Collect logs, Disk usage, Summarise a folder, Read data out —
zum Ergänzen und Absenden. Extensions können eigene hinzufügen.

**axross-Funktionen** sind die Tools, die axross selbst für den Agent
ausführt — außerhalb seiner Sandbox, mit den Rechten von axross:
*Remote files* (die in den Panes offenen Verbindungen, Backend
`pane:<name>`), *Saved connections* (gespeicherte Profile, die der
Agent selbst öffnet), *Remote commands* (SSH-/WinRM-/…-Hosts),
*MCP-Server* und *Extension-Tools*. Sie sind ein Weg aus der Sandbox
heraus; deshalb sichert sie ein Hauptschalter, und der ist
**standardmäßig aus**. Ein Production-Profil verweigert jede Änderung.

**Was ein Tab erreichen darf** — zwei Ebenen, beide müssen es erlauben:

- *Agent Settings > Access* ist die Obergrenze jedes Tabs: der
  Hauptschalter *Let agents use axross functions* und jede Funktion.
  Dort aus heißt in jedem Tab aus.
- *Access…* im Tab (oder *Agent Settings > Sessions* für alle Tabs auf
  einmal) ist die eigene Wahl des Tabs innerhalb davon: sein
  Hauptschalter und seine Funktionen, sein **Netzwerk** und seine
  **Ordner**. Ein neuer Tab startet mit dem Hauptschalter, wie Agent
  Settings ihn hat.

| Netzwerk eines Tabs | Bedeutung |
|---|---|
| As the sandbox profile says | Level und Allowed Hosts des Profils (ohne Sandbox: keine Grenze) |
| None | gar kein Host |
| Only these hosts | die eigene `host:port`-Liste des Tabs |
| All hosts | nur bei einer lax-Sandbox oder ohne Sandbox |

Der Sandbox-Level bleibt die Obergrenze: ein Tab engt nur ein, was sein
Level kann (paranoid bietet nur *None*, normal und high kein *All*).
Das Netzwerk gilt für die eigenen Verbindungen der Sandbox, für
Remote-Arbeit in axross und für http-MCP-Server gleichermaßen und wird
bei jeder Verbindung geprüft. Die **Ordner** eines Tabs sind read-only
oder read-write; read-write nur, wo der Level Extra-Ordner zulässt (lax,
normal), und mit *Allow changes to files*. Der Tooltip von *Access…*
fasst alles zusammen.

**Sandboxes** (Agent Settings > Sandboxes): ein Tab kann seinen Agent
in bubblewrap, podman oder docker laufen lassen. Ein Sandbox-Profil hat
einen Level:

| Level | Netzwerk | Ordner | Extra-Ordner |
|---|---|---|---|
| lax | das des Hosts | wie eingestellt | wie eingestellt |
| normal | nur Allowed Hosts | wie eingestellt | wie eingestellt |
| high | nur Allowed Hosts | wie eingestellt | read-only |
| paranoid | nur das LLM | read-only | read-only |

Die Anfragen ans Modell, der API-Key und die Zustimmung bleiben
draußen: die Sandbox hat kein eigenes Netzwerk, axross sendet für sie.
Allowed Hosts (`host:port`) erreicht sie über axross, geprüft bei jeder
Verbindung — eine Änderung gilt sofort. Remote-Verbindungen,
gespeicherte Profile, MCP-Server und Extension-Tools laufen ebenfalls
in axross, außerhalb der Sandbox, ihre Zugangsdaten kommen also nie
hinein; Level und Allowed Hosts der Sandbox entscheiden, ob der Agent
sie nutzen darf (paranoid: keine). Die Limits des Levels für Speicher,
Tasks und CPU gelten bei podman und docker; bubblewrap bekommt sie über
einen systemd-User-Scope (ohne einen nur den Speicher, per `prlimit`).
podman und docker brauchen das Image: `scripts/axross-podman.sh
agent-image` ([PACKAGING.md](PACKAGING.md)).

**MCP-Server** (Agent Settings > MCP Servers): weitere MCP-Server — ein
Programm (stdio) oder ein HTTP-Endpunkt —, deren Tools ein Tab als
`<server>__<tool>` anbieten kann. *Test* listet ihre Tools. Ein Server
auf „always" fragt bei jedem Aufruf; „writes" lässt Tools, die der
Server als read-only markiert, ohne Frage laufen. Ein Programm kann in
einem Sandbox-Profil laufen; der Token eines HTTP-Servers liegt im
Keyring.

**Extensions** können den Agent starten (`api.run_agent`,
`api.open_agent_tab`), ihm Tools geben (`api.add_agent_tool`), Topics
hinzufügen (`api.add_agent_topic`) und seinen Events folgen
(`api.on_agent_event`). Die mitgelieferte Extension *Agent Stats* zeigt
ein kleines Fenster, immer oben und verschiebbar, mit Aufgaben,
Antworten, Tool-Aufrufen, Fehlern, Tokens und Zeit.

Ein Profil, dessen Server nicht auf diesem Rechner oder in seinem Netz
liegt, fragt vorher, weil das Gelesene dorthin geht.

Im Container: `scripts/axross-podman.sh gui --llm-model DATEI.gguf`
startet axross auf deinem Display, llama.cpp daneben und das Profil
gleich mit ([PACKAGING.md](PACKAGING.md)). Mit `--agent-sandbox` läuft
dort auch die bubblewrap-Sandbox: podman maskiert `/proc`, das
bubblewrap selbst mounten muss; ohne die Option sagt der Tab das. Im
Container bubblewrap wählen - podman kann dort keine eigenen Container
starten.

Ein MCP-Client kann dem gleichen lokalen Modell mit `--mcp-tools agent`
(`agent_run`) eine Aufgabe übergeben; dieses Modell kann nur lesen
([MCP_de.md](MCP_de.md) §9.9).

## Konfigurationsdateien

- `~/.config/axross/profiles.json` — Verbindungsprofile (`0o600`).
- `~/.config/axross/bookmarks.json` — Bookmark-Bar.
- `~/.config/axross/session.json` — Pane-Layout, Window-Geometry und
  Dock-Layout beim letzten Beenden; beim Start wiederhergestellt,
  außer File > Restore Layout on Start ist aus.
- `~/.config/axross/column_prefs.json` — Spaltenbreiten und
  ausgeblendete Spalten, eine Datei für alle Panes.
- `~/.config/axross/agent/settings.json` — Agent Settings (Modes, Access,
  Sandbox-Profile, MCP-Server; `0o600`).
- `~/.config/axross/agent/sessions/` — eine JSON-Datei je behaltenem Agent-Tab (`0o600`).
- `~/.config/axross/<provider>_token.json` — OAuth-Refresh-Tokens (`0o600`).
- `~/.config/axross/ramfs.json` — RAM-Workspace-Einstellungen. `"tmpfs_enabled": true`
  legt jede Temp-Datei des Prozesses (Download-/Upload-Buffer ab 8 MiB,
  Archiv-Entpacken, FUSE-Write-Buffer) auf eine RAM-Disk (`/run/user/$UID`,
  sonst `/dev/shm`) statt auf die Platte: nichts landet auf der Platte, aber
  es kostet RAM, daher standardmäßig aus. Ein im Environment gesetztes
  `TMPDIR` gewinnt immer.
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
