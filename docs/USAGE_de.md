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

- **Fehlende Features.** *Help > Features…* listet jedes optionale
  Feature - Verbindungen, Dateianalyse und Archive, externe Tools wie
  ripgrep, rsync oder qemu-img, Sleuth Kit, TestDisk / PhotoRec und
  VBoxManage der Forensic- und VirtualBox-Extensions - als installiert
  oder fehlend, mit dem Weg dahin.
  *Install Selected* startet `python -m pip install …` in der Python,
  die axross ausführt, nach einer Rückfrage mit dem Befehl (Ausgabe im
  Log, meist ohne Neustart); ein Frozen-Build verlinkt den
  axross-full-Download desselben Releases; ein Tool zeigt den
  Paketbefehl dieses Systems zum Kopieren. Ein Backend mit fehlenden
  Abhängigkeiten oder eine Analyse ohne sift bietet dasselbe Fenster an.
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
- Ein Pane wird aktiv, wenn die Maus 0,5 s darin ruht.
  **Edit → Settings… → General → Activate a pane** stellt 0,5, 1, 2 oder
  3 s ein, oder **On Click**.
  Der Tastaturfokus folgt nur aus der Dateiliste eines anderen Panes,
  nie aus einem Textfeld.
- **Alt+Links / Alt+Rechts** durchschreiten Pane-Historie;
  **Tab** / **Shift+Tab** in einer Dateiliste wechseln das Pane.
- Drag-and-Drop zwischen Panes startet einen Transfer (lokal↔remote,
  remote↔remote, cross-Protokoll).

### Workspaces — mehrere Layouts, auf mehreren Bildschirmen

Ein Workspace ist ein eigenes, benanntes Pane-Layout. **Workspace → New
Workspace → With File List** (**Ctrl+Alt+N**) öffnet einen mit einem
lokalen Pane, **With Terminal** (**Ctrl+Alt+Shift+N**) einen mit einer
lokalen Shell; ab dem zweiten stehen die Workspaces als Tabs über den
Panes. **Ctrl+Alt+PgDown /
PgUp** schalten durch, und jeder behält sein eigenes Quell- und Ziel-Pane.

- **Mehrere Shells:** **Workspace → Add Terminal Pane** (auch im
  Rechtsklick-Menü des Tabs) legt eine weitere lokale Shell in den
  Workspace, neben die Panes, die schon da sind.
- **Umbenennen:** Doppelklick auf den Tab, sein Rechtsklick-Menü oder
  **Workspace → Rename Workspace…**.
- **Detach to Window** (Workspace-Menü oder Rechtsklick auf den Tab)
  legt den Workspace in ein eigenes Fenster — etwa auf einen anderen
  Bildschirm. Schließt man das Fenster, kommt der Workspace als Tab
  zurück.
- **Pane verschieben:** **Workspace → Move Pane to Workspace** schickt
  das aktive Pane in einen anderen (oder neuen) Workspace; oder den
  Pane-Header auf ein Pane eines anderen Workspace oder Fensters ziehen.
  File-Panes und Terminal-Panes lassen sich gleich ziehen (ein
  Terminal-Pane auch über seinen ⇄-Button); hält man ein gezogenes Pane
  eine halbe Sekunde über einen Workspace-Tab, öffnet sich dieser Tab —
  so erreicht ein Pane auch einen Workspace im Hintergrund.
- **Close Workspace** schließt ihn mit seinen Panes (nach Rückfrage);
  schließt das letzte Pane eines Workspace, geht der Workspace mit. Ein
  Workspace bleibt immer.
- Ein Layout-Preset (**View → Layout Preset**) ersetzt nur die Panes
  des aktuellen Workspace.
- Alle Workspaces — Namen, Reihenfolge, der aktuelle, Layouts mit ihren
  Terminals und Ordnern, welche abgelöst sind und wo ihre Fenster stehen
  — kommen beim nächsten Start zurück (siehe unten).

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

*Restore the layout of the last session on start* (**Edit → Settings… →
General**, standardmäßig an) schaltet das ab;
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

- **Atomare Semantik.** Jeder Schreibvorgang geht in eine versteckte
  Sibling-Tempdatei (`.<name>.part-<job>-<fingerprint>`) und wird am
  Ende reingerannt. Auf
  S3 / Azure / Dropbox / GDrive / OneDrive / IMAP / Rsync ist der
  Upload selbst schon atomar; sonst ist der Rename der Commit-Punkt.
- **Resume.** Fehlgeschlagene Transfers können fortgesetzt werden;
  die Teilbytes auf dem Ziel werden wiederaufgenommen. Ein Transfer,
  der an einem vollen Ziel scheitert, löscht seine Teildatei.
- **Retry.** „Retry Failed" wiederholt jeden Fehler-Transfer der Queue,
  jeden genau einmal.
- **Cancel All** stoppt auch eine Kopie oder einen Move, dessen
  Ordner-Walk noch läuft: keine seiner Dateien kommt in die Queue.
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
| `core.metadata_index` | Offline-SQLite-Suche nach Name / Ext / Größe / mtime. Eine Datei: `$AXROSS_METADATA_DB`, sonst `$XDG_DATA_HOME/axross/metadata.sqlite`, sonst `~/.local/share/axross/metadata.sqlite` (ein Index, der schon dort liegt, bleibt in Gebrauch). Gefüllt nur über *Index Active Folder…*, nicht durchs Browsen — Details im Handbuch, Abschnitt *Metadata-Index*. |
| `core.previews` | Lokaler Bild-Thumbnailer mit MIME-Allowlist, Größenkappen, Qt-Allocator-Gate. F3 / Doppelklick. |
| `core.archive` | Sichere Entpackung von zip / tar / 7z (`.zip .xpi .jar .war .apk .epub .docx .xlsx .odt .tar .tar.gz .tgz .tar.bz2 .tbz2 .tar.xz .txz .7z`). Zip-Slip-/Bomb-/Lying-Metadata-Guards; `.7z` braucht das `[archive]`-Extra. |
| `core.elevated_io` | `pkexec`-gated lokales Lesen für `/etc/shadow` & Co. — Axross hält selbst keine Privilegien. „Open as root…"-Kontextmenü. |
| `core.fuse_mount` | FUSE-Mount jedes Backends. Read-only by default; `writeable=True` aktiviert create / write / unlink / mkdir / rename. Optionales `[fuse]`-Extra. |
| `core.mcp_server` | Stdio-JSON-RPC-MCP-Server, der das konfigurierte Backend als Tools exponiert. `--mcp-write` ergänzt mutierende Tools, gecappt auf einen pfad-traversal-sicheren Root. |

## Rechtsklick-Aktionen

| Aktion | Trigger | Was passiert |
|---|---|---|
| Disk Image… | Rechtsklick (eine `.img .raw .dd .iso .qcow2 .vdi .vmdk .vhd(x) .e01 …`-Datei) | Container (qcow2, VDI, VMDK, VHD/VHDX, E01), Partitionstabelle (MBR mit logischen Partitionen, GPT) sowie Dateisystem und Label jedes Volumes, in reinem Python über jedes Backend gelesen. Ein lokales Image mountet ein Volume über ein Loop-Device genau über dessen Bytes: zuerst `udisksctl` ohne Abfrage (wo polkit es erlaubt), dann `sudo`, dann `pkexec`, zuletzt `udisksctl` mit polkit-Abfrage. Das sudo-Passwort wird einmal gefragt und im Speicher gehalten, solange axross läuft (nie auf Platte, nie auf einer Kommandozeile); *Remember the sudo password* (*Edit → Settings… → Security*) schaltet das ab, dann gilt wieder `udisksctl` (polkit fragt), `pkexec`, `sudo` mit Abfrage jedes Mal. Im Paranoid Security Mode wird es nie gemerkt. sudo, pkexec und udisksctl laufen nur aus root-eigenen Systemordnern, nie aus `$PATH`. **Read-only**, außer *Allow writing* ist angehakt und bestätigt. Der Mount-Ordner öffnet sich in einem neuen Pane; *Unmount* gibt das Loop-Device zurück. Von axross angelegte Mounts bleiben über Neustarts bekannt (`~/.config/axross/mounts.json`, nur noch gemountete kommen zurück). *Identify File Type…* erkennt Disk-Images auch am Inhalt (GPT, MBR, virtuelle Disks) und bietet für so eine Zeile *Disk Image…* an, egal wie die Datei heißt. qcow2 / dynamisches VDI / VMDK erst konvertieren (`qemu-img convert -O raw`); ein festes VDI mountet direkt. |
| Tags ▸ | Rechtsklick auf eine Auswahl | Einen farbigen Tag anhaken (Important und Review later gibt es; New Tag… legt einen an) für jede gewählte Datei auf jedem Backend; Punkte in der Namensspalte, die Tags im Tooltip; `tag:<name>` im Filterfeld zeigt nur diese Dateien; *View > Tagged Files…* listet die Dateien jedes Tags und springt hin. Gespeichert in `~/.config/axross/tags.json`. |
| Neuer Ordner | Rechtsklick | `backend.mkdir(path)` auf jedem schreibfähigen Backend. |
| Neue Datei… | Rechtsklick | 0-Byte-Datei via `backend.open_write(path).write(b"")`. |
| Neuer Symlink… | Rechtsklick | Zwei Prompts. Sichtbar nur auf Backends mit `supports_symlinks=True`. |
| Neuer Hardlink… | Rechtsklick | Gleiche Form; Cross-Device → `OSError(EXDEV)`. |
| Find in Index | `Strg+Shift+F` | Suche im Offline-Metadaten-Index. |
| Calculate Size (N dirs) | Rechtsklick auf Ordner | Gesamtgröße, Datei- und Ordnerzahl jedes gewählten Ordners, im Hintergrund über die Connection gezählt (*Cancel* in der Statuszeile); die Ergebnistabelle sortiert, und die Größen stehen in der Size-Spalte des Panes, bis der Ordner neu geladen wird. **Hidden Files zählen mit**: Dotfiles, versteckte Ordner und Einträge mit Hidden-Flag des Backends werden wie jeder andere Eintrag summiert — wie bei `du` —, egal ob das Pane sie anzeigt. Ein Link zählt mit seiner eigenen Größe und wird nie verfolgt; ein Ordner, der sich nicht lesen lässt, wird im Ergebnis genannt und übersprungen. |
| Identify Files in This Folder… | Rechtsklick (auch auf freie Fläche); der Button im Fenster *Identify File Type* | Jede Datei direkt im Ordner (ein gewählter Ordner, sonst der angezeigte; Unterordner werden gezählt, nicht betreten; Hidden Files eingeschlossen) wie bei *Identify File Type…* am Inhalt erkannt, im Hintergrund und über die Connection — also auch in Remote-Panes. Begrenzt: höchstens 2000 Dateien, 64 KiB je Datei, 15 s Timeout je Lesevorgang, *Cancel*; `file(1)` wird nicht gefragt. Die Spalten sortieren: Name, erkannter Typ, MIME-Type, *mismatch*-Verdict, Größe, eine Notiz — bei einem Disk-Image Container, Partitionstabelle und Partitionszahl (`Raw disk image, MBR, 2 partitions, 4.0 MiB`; dafür höchstens 4 MiB gelesen) — und für lokale Dateien mit installiertem `sift`-Extra die Art laut sift. Eine Zeile öffnet *Disk Image…* (Disk-Images) oder *Properties…*; Doppelklick nimmt das Passende. |
| Duplicate Finder | View-Menü | Gruppieren nach Content-Hash, `ax-cas://…`-URLs kopieren; markierte Kopien in den axross-Trash verschieben, nachdem live geprüft ist, dass eine echte andere Kopie bleibt. |
| View Media… / View Selected Media… | Rechtsklick, View-Menü | Bilder, PDFs und Videos des Ordners (optional rekursiv) oder der Auswahl als Overview-Grid, Viewer zum Durchklicken oder Slideshow — siehe *Editoren und Viewer*. |
| Show / Remove / Export Metadata… | Rechtsklick | EXIF / GPS / XMP / IPTC, Office-Properties, PDF-Info, Audio-/Video-Tags der Auswahl — oder des ganzen Ordners, wenn nichts ausgewählt ist (Unterordner optional) — siehe *Datei-Metadata*. |
| Move to Trash | Rechtsklick | Universaler Papierkorb. Läuft wie Delete Permanently: im Hintergrund, mit derselben zweiten Rückfrage für Hidden Entries. |
| Delete Permanently | Rechtsklick, `Del` | Zählt zuerst abseits des GUI-Threads, was wegfällt (Ordner, Dateien, Bytes, Hidden Entries), dann die Rückfrage. Ein ausgewählter Ordner mit Hidden Entries (Dotfiles oder Hidden-Flag des Backends) - oder einer, den die Prüfung nicht vollständig lesen konnte - braucht ein zweites OK mit No als Default. Das Löschen läuft im Hintergrund: die Statuszeile zeigt den Fortschritt, Cancel hält beim nächsten Eintrag an - auch innerhalb eines Ordners, der lokal, per SMB, SFTP oder FTP gelöscht wird; die Statuszeile sagt dann, wie viel von diesem Ordner schon weg ist (Gelöschtes bleibt gelöscht; ein Server, der einen ganzen Ordner mit einem Request löscht, etwa WebDAV oder S3, löscht diesen Ordner zu Ende) - Fehler werden je Eintrag gemeldet, danach wird der Ordner neu geladen. Ein Pfad, der gerade gelöscht wird, wird abgewiesen, auch aus dem anderen Pane. |
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
- **Terminal-Bookmarks** öffnen eine Shell statt eines Ordners: eine
  lokale Shell, eine auf einem SSH-Profile (SFTP/SCP) oder eine auf einem
  bloßen Host — *SSH Host (no profile)*: Host oder IP-Adresse, Port (22),
  User, optional eine Key-Datei —, optional mit Arbeitsverzeichnis, in
  das gewechselt wird. Angelegt über den ☆-Button eines Terminal-Panes
  (*Bookmark this Terminal*) oder *New Terminal Bookmark…* im
  Rechtsklickmenü der Sidebar; ein Klick öffnet ein Terminal-Pane neben
  dem aktiven Pane. Ein Bookmark enthält nie ein Credential: ein
  Profile-Bookmark nennt das Profile; ein Host-Bookmark verbindet wie
  Quick Connect — im Hintergrund, fragt bei unbekanntem Host-Key, ob er
  vertraut werden soll (known_hosts, nie stillschweigend), nimmt die
  Key-Datei oder einen laufenden ssh-agent, fragt das Passwort, wenn das
  nicht reicht, und die Passphrase eines verschlüsselten Keys; nichts
  Eingetippte wird gespeichert, der Proxy aus *Settings → Network & Proxy*
  gilt. Ein fehlendes Profile, eines ohne Shell oder ein Host, der kein
  Hostname ist, wird gemeldet, und nichts öffnet sich. Die Shell eines
  Host-Bookmarks gehört nicht zum gespeicherten Layout.

## Editoren und Viewer

Jeder Viewer, Editor und Dialog hat oben rechts zwei Buttons: [x]
schließt ihn, der Button links daneben maximiert ihn über den ganzen
Bildschirm und stellt die vorherige Größe wieder her. `Ctrl+M` tut
dasselbe, ebenso der Maximize-Button der Titelleiste. Im Dialog
verschiebt ein Ziehen mit der linken Maustaste auf dem Rest dieser
oberen Zeile den Dialog, auf der Titelleiste eines floating Panels das
Panel - auch wo der Window Manager keine Titelleiste zeichnet
(spectrwm, andere Tiling-Setups) oder das Fenster maximiert hält
(spectrwm-Layout `fullscreen`), und unter Wayland: axross lässt es dann
vom Window Manager verschieben. Ein Doppelklick auf die Titelleiste
eines floating Panels dockt es wieder an.

- **Texteditor** (built-in) — jede zum Bearbeiten geöffnete Datei ist
  ein Tab eines Editor-Fensters (*Edit* / F4 im Pane, lokal oder
  remote): Syntax-Highlighting (Pygments; die Sprache nach Name oder
  `#!`-Zeile, in der Statusleiste änderbar), Zeilennummern, Suchen und
  Ersetzen mit Regex, Case und ganzem Wort (Strg+F / Strg+H, F3), Gehe
  zu Zeile (Strg+G), Umbruch, Zoom, Zeilenenden (LF / CRLF / CR) und
  Encoding (UTF-8, UTF-8 BOM, Latin-1, UTF-16) unter *Format*, Save /
  Save All. *File → New* (Strg+N) öffnet einen Tab ohne Datei, *Open…*
  (Strg+O) lokale Dateien (Remote-Dateien öffnet ihr Pane), *Save As…*
  (Strg+Umschalt+S) schreibt einen lokalen Tab in eine lokale Datei und
  einen Remote-Tab in einen Pfad auf seinem Backend und fragt, bevor er
  eine Datei ersetzt; Save All ist Strg+L. Enter übernimmt die
  Einrückung der Zeile, nach `:` (Python, YAML) oder `{`
  (Klammer-Sprachen) eine Ebene mehr. *Tools → Text Editor* öffnet das
  Fenster ohne Datei. Ein Save behält das Zeilenende jeder unberührten Zeile, ein
  BOM und geschützte Leerzeichen, schreibt atomar und fragt nach, wenn
  die Datei seit dem Öffnen geändert wurde; das Pane mit dem Ordner
  wird aktualisiert. Schließen mit ungespeicherten Änderungen fragt Save
  / Discard / Cancel; der letzte geschlossene Tab schließt das Fenster,
  rechts in der Menüleiste sitzen Maximize und [x]. Geöffnet werden Dateien bis zum Open-Size-Limit
  (32 MB vorgegeben, *Edit → Settings… → Files & Panes*).
- **Hex-Editor** — nützlich für Triage auf Remote-Dateien.
- **Bild-Viewer** — F3 / Doppelklick, MIME-Allowlist, Größen-
  kappen.
- **PDF** — F3 / Doppelklick öffnet das PDF allein im Media Viewer
  (braucht QtPdf; ohne QtPdf oder im Security-Mode `paranoid` öffnet
  stattdessen der Hex-Editor, das Log nennt den Grund).
- **Media Viewer** — *View → View Media…* oder Rechtsklick → *View
  Media…* auf den Ordner (*View Selected Media…* für ausgewählte
  Dateien und Ordner). Wählbar sind die Typen (Bilder inkl. SVG,
  PDFs, Videos über QtMultimedia), ob Unterordner einbezogen werden
  (Tiefe 1–32; höchstens 5000 Dateien, Symlink-Ordner werden nicht
  verfolgt, unlesbare Ordner übersprungen und gezählt) und der
  Start: **Overview first** (Thumbnail-Grid mit Filter, Sortierung
  nach Name / Datum / Ordner und Größen-Slider; Enter oder
  Doppelklick öffnet), **Start slideshow** oder **Click through**.
  Im Viewer: Links / Rechts / PageUp / PageDown / Space gehen zur
  vorigen / nächsten Datei (Stopp am ersten und letzten Element; auch
  im PDF, und die Slideshow blättert nur in einem allein geöffneten PDF). Ein PDF mit
  mehr als einer Seite bekommt eine Seitensteuerung `← n / m →` in der
  Button-Leiste; Hoch / Runter blättern seine Seiten. Home / End, F11 Fullscreen,
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
- **Media Player** (mitgelieferte Extension, *Extensions → Manage
  Extensions…*) — ein Dock, das MP3, WAV, Ogg Vorbis, FLAC, Opus, AAC
  und mehr abspielt. Tracks kommen per Rechtsklick → *Play in Media
  Player*, *Add…* oder per Drag & Drop von Dateien und Ordnern aus
  einem Datei-Pane oder vom Desktop auf die Playlist dazu (Ordner
  liefern ihre Audiodateien sortiert, höchstens 2000, 6 Ebenen tief;
  was kein Audio ist, wird mit Hinweis übersprungen; Remote-Dateien
  werden abseits des GUI-Threads in einen temporären Ordner kopiert,
  je Datei höchstens 512 MB, je Drop 2 GB). Zeilen lassen sich per
  Drag umsortieren; der laufende Track (fett, Play-Icon, im
  Dock-Titel) spielt weiter. Spulen mit dem Positions-Slider (Klick
  oder Ziehen, `1:23 / 4:56`). ⏮ startet den Track nach 3 s neu,
  sonst geht es zurück; Shuffle spielt jeden Track einmal pro Runde,
  Repeat ist off / all / one. Ein nicht abspielbarer Track wird
  markiert und übersprungen. *Load…* / *Save…* lesen und schreiben
  M3U-/M3U8-Playlists (UTF-8, relative Pfade für Tracks unter dem
  Ordner der Playlist, `#EXTINF`-Titel und -Längen; URLs, fehlende
  oder Nicht-Audio-Einträge werden übersprungen, Dateien über 1 MiB
  oder mit NUL-Bytes abgelehnt; temporäre Kopien von Remote-Tracks
  werden nicht gespeichert). Liste, aktueller Track samt Position,
  Lautstärke, Mute, Shuffle und Repeat kommen beim nächsten Start
  wieder (`~/.config/axross/media_player.json`, Mode 0600). Die
  Lautstärke folgt einer wahrnehmungsgerechten (kubischen) Kurve;
  Mute-Button. Output-Device und Output-Volume aus *Edit → Settings… →
  Audio* gelten obendrauf (eine Änderung dort erreicht einen laufenden
  Track sofort). Startet das Audio nicht, sagt das Panel warum:
  *Try Again* prüft noch einmal und startet den Player, sobald das
  Audio antwortet, *Audio Settings…* öffnet die Audio-Seite (anderes
  Backend oder Device). Tasten, solange der Player den Fokus hat: Space
  Play/Pause, Enter spielt die markierte Zeile, Delete entfernt die
  markierten Zeilen, Links / Rechts spulen 5 s (mit Shift 30 s),
  Strg+Links / Strg+Rechts vorheriger / nächster Track, M Mute,
  + / - Lautstärke. Mit numpy: 10-Band-Equalizer mit Presets (der
  Pfeil links von *Equalizer* klappt die Band-Slider ein und gibt der
  Playlist den Platz) und eine animierte Visualisierung: Spektrum,
  gespiegeltes Spektrum, radiales Spektrum, Oszilloskop oder Stereo-VU-
  Meter - ein Klick darauf wechselt zur nächsten. Gewählte
  Visualisierung und eingeklappter Equalizer kommen beim nächsten Start
  wieder.
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

**Wie geschrieben wird** — *Edit → Settings… → Metadata* (*Tools →
Metadata Settings…* öffnet sie):

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

**Ollama** betreibt ein Modell ohne weitere Angabe mit einem Context von
4096 Tokens, und schon die Anweisungen und Tools des Agents brauchen
2.000 bis 5.000 Tokens (5.259 mit *Allow changes to files*). Den Server
mit `OLLAMA_CONTEXT_LENGTH=16384` starten oder `PARAMETER num_ctx 16384`
in einem Modelfile setzen: Ollama kürzt einen Request, der nicht passt,
ohne Meldung, und seine OpenAI-kompatible API nimmt keine Context-Größe
an. Hat eine Antwort den Context gefüllt, sagt der Tab das.

**Tabs.** Jeder Tab ist ein eigener Verlauf mit eigenem Modell,
Protection-Mode, Sandbox, Ordner und Tools: „+" oder Ctrl+T öffnet
einen, ein Doppelklick benennt ihn um. Mit *Keep tabs* (Tools > Agent
Settings…) ist jeder Tab eine JSON-Datei in
`~/.config/axross/agent/sessions/` (`0o600`) und kommt beim nächsten
Start wieder. Ctrl+Enter sendet, Esc oder Stop beendet die Aufgabe
sofort - auch während das Modell noch an der Antwort schreibt (der
Request wird abgebrochen, der Server hört auf zu generieren) - und
Pfeil hoch/runter holt frühere Aufgaben zurück. Schreibt ein
Reasoning-Modell seine ganze Antwort nur ins Reasoning (Qwen3 in LM
Studio tut das manchmal), wird sie so gekennzeichnet angezeigt; endet
ein Modell ganz ohne Antwort, steht das da.

**Thinking.** Was ein Reasoning-Modell denkt, bevor es antwortet oder
ein Tool aufruft (`reasoning_content` bzw. `reasoning` neben der
Antwort, oder `<think>…</think>` an ihrem Anfang), steht getrennt von
der Antwort: eine graue, kursive Zeile **▸ Thinking** mit dem ersten
Satz. Ein Klick auf *Thinking* klappt den ganzen Text auf, ein zweiter
wieder zu. Vorgelesen wird nur die Antwort. Gespeicherte Tabs behalten
das Thinking, zugeklappt.

**Die Lampe** in der Title-Bar des Docks zeigt, ob das LLM des Tabs
antwortet: **grün** - der letzte Request an seinen Endpoint (eine
Modell-Liste oder ein Request einer Aufgabe) hat geklappt; **orange** -
einer läuft; **rot** - er ist gescheitert, es gibt kein Profil, oder der
Endpoint ist remote und hat noch keinen Consent (gefragt wird erst bei
der ersten Aufgabe). Der Tooltip nennt Endpoint, Modell und Grund; ein
Klick prüft erneut. Die Prüfung holt im Hintergrund die Modell-Liste des
Servers, nur solange das Dock sichtbar ist.

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
status, Collect logs, Disk usage, Summarise a folder, Read data out,
Review a config folder, Free disk space (mit den Tools des Duplicate
Finders) — zum Ergänzen und Absenden. Extensions können eigene
hinzufügen.

**Eigene Topics** („Work prompts"): Topics ▸ *+ New Topic…* öffnet ein
leeres Formular, *Save This Task as Topic…* übernimmt das Eingabefeld,
*Edit or Delete My Topics…* ändert oder löscht sie. Ein Topic speichert
Titel, Slash-Command,
den Prompt (`{folder}` und `{backend}` werden eingesetzt), den
vorgeschlagenen Mode, was er braucht und welche Tool-Gruppen er
anhakt, in `~/.config/axross/agent/work_prompts.json`. Jedes Topic hat
einen Command: `/` im Eingabefeld zeigt sie (`/free-space`,
`/review-config`, eigene); Text nach dem Command bleibt unter dem Prompt
stehen. Ein Command füllt das Feld — du liest und sendest.

**Prompts** (*Edit → Settings… → Agent → Prompts*): System-Prompt (die
Regeln, die das Modell zuerst bekommt) und User-Prompt (ein Template für
jede Aufgabe: `{task}` wird zum getippten Text, Text ohne `{task}` kommt
davor, leer schickt die Aufgabe wie getippt) als benannte Profile.
*Default* ist axross' eigener Prompt und lässt sich weder ändern noch
löschen — *Duplicate* legt eine änderbare Kopie an. *Prompt profile of
new requests* wählt das Profil für die nächste Anfrage jedes Tabs; der
Tab ergänzt weiter Ordner, Plan-Mode und Vorlese-Regeln. Gespeichert in
`~/.config/axross/agent/settings.json`.

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
ein kleines Fenster über dem Hauptfenster (ein normales Fenster:
verschieben, Größe ändern, schließen; auch unter Tiling-Window-Managern
schwebend) mit Aufgaben,
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

### Mit dem Agent sprechen

Der Button **🎤** im Tab spricht mit dem Agent, **🔊** liest seine
Antworten vor. Sprache erkennt das LLM-Profil des Tabs (LLM Profiles,
*Advanced*): lokal mit Whisper — nichts verlässt den Rechner — oder ein
OpenAI-kompatibler Server (`/audio/transcriptions`; ein entfernter fragt,
bevor er eine Aufnahme hört). Antworten spricht eine lokale Piper-Stimme.

- **Mikrofon-Modi** (Settings > Voice): *Push-to-talk* (Button halten,
  oder die Hold-Taste, Default **F9**, solange das Agent-Dock den Fokus
  hat), *Toggle* (Klick startet, erneuter Klick oder eine Pause beendet)
  und *Conversation* (nach jeder gesprochenen Antwort hört es wieder zu;
  Klick auf den Button beendet).
- **Erkannter Text** landet im Aufgabenfeld zum Lesen und Senden, oder
  wird sofort gesendet (eine Conversation sendet immer).
- **Was gesprochen wird:** nur die Antwort - keine Tool-Aufrufe, kein Code
  (ein kurzer Satz sagt, dass Code angezeigt wird), keine URLs oder langen
  Pfade. Stop, Esc, Tippen oder eine neue Aufgabe beenden es. Lehnt axross
  einen Tool-Aufruf ab (Files read-only, nicht erlaubt, keine Permission),
  sagt die Stimme das kurz; die erste Sprachnutzung einer Session grüßt.
- **Stimme und Sprache:** männlich oder weiblich, Deutsch oder Englisch,
  oder *der Antwort folgen*. In deutscher Sprache werden englische
  IT-Begriffe (Server, Backup, Pull Request, …) englisch gesprochen; ein
  Begriff, den die Antwort in `{Klammern}` schreibt, ebenso (die Klammern
  werden nicht angezeigt).
- **Einrichtung:** `pip install axross[voice]` (piper-tts, faster-whisper;
  in axross-full enthalten), dann *Help > Features…*, Gruppe **Voice**:
  Stimmen und ein Whisper-Modell herunterladen (gepinnte Checksummen,
  nach `~/.local/share/axross/voice/`).
- **Sicherheit:** Bestätigungen werden immer geklickt, nie gesprochen; im
  paranoiden Security Mode ist das Mikrofon aus; Audio und Transkripte
  bleiben im Speicher.

## Settings

**Edit → Settings…** (**Strg+,**; unter macOS im Application-Menü) bündelt
alle Einstellungen von axross in einem Fenster: links die Kategorien,
rechts die Seite der gewählten, darüber ein Feld, das eine Einstellung
über ihren Namen findet (*sudo*, *proxy* oder *zoom* tippen).

| Kategorie | Einstellungen |
|---|---|
| General | Sprache (gilt ab dem nächsten Start), Layout der letzten Session beim Start wiederherstellen, wann ein Pane aktiv wird (per Klick oder nach 0,5–3 s Maus im Pane) |
| Appearance | Theme, Compact Mode, Monochrome Icons, Schriftgröße (Zoom), Hidden Files hervorheben und ihre Farbe (eine auf dem Theme schwer lesbare Farbe erst nach Rückfrage) |
| Files & Panes | Hidden Files zeigen, Open Size Limit, RAM-Workspaces (an / aus, Größenlimit, frei gehaltener Speicher) und Temp-Dateien im RAM (gilt ab dem nächsten Start) |
| Network & Proxy | Default-Proxy, Bypass-Liste, PAC-Script, ein Test |
| LLM Profiles | Die LLM-Server von Agent- und Analysis-Dock; *Fetch models* öffnet eine Liste mit Größe, Parametern, Quantisierung und dem geladenen Modell, soweit der Server sie meldet |
| Agent | General, Prompts, Access, Sandboxes, MCP Servers, Sessions |
| Voice | Antworten vorlesen, gesprochene Sprache, Stimme, Mikrofon-Modus, Hold-Taste, erkannten Text einfügen oder senden, die Pause, die das Sprechen beendet |
| Audio | Audio-Backend (Automatic, PipeWire, PulseAudio; das Backend dieses Laufs wird gezeigt, eine Änderung gilt ab dem nächsten Start), Output-Device und Volume (skaliert alles, was axross abspielt) mit *Play Test Tone*, Input-Device und Volume (Gain) mit *Test Microphone* (ein Level-Meter) und *Record 3 s and Play Back*, das Ergebnis des Audio-Checks und *Check Audio Again* |
| Metadata | Wie Remove Metadata schreibt, vorher fragen |
| Search | Gleichzeitig durchsuchte Hosts von *Find on Network Hosts*; wo Offline- und Duplicate-Index liegen |
| Security | Paranoid Security Mode (bleibt für den nächsten Start; `AXROSS_SECURITY_MODE` im Environment gewinnt), sudo-Passwort merken |
| Extensions | Welche Extensions eingeschaltet sind |

Die **Audio**-Seite fasst Qt Multimedia erst an, wenn der Audio-Check
(ein eigener Prozess) geantwortet hat; scheitert er, nennt die Seite den
Grund, die Tests bleiben aus, und das Backend lässt sich trotzdem wählen
und speichern. Ein gespeichertes Device, das nicht eingesteckt ist,
bleibt als *(not connected)* in seiner Liste - bis es wieder da ist,
spielt der System-Default. Ein Device, das bei offener Seite eingesteckt
wird, erscheint sofort.

**OK, Apply, Cancel** gelten auf jeder Seite gleich: geschrieben werden
nur Seiten, deren Werte geändert wurden; OK und Apply prüfen zuerst jede
geänderte Seite und speichern gar nichts, solange eine ein Problem hat
(diese Seite wird gezeigt, das Problem steht darüber); dann wird jede
geänderte Seite gespeichert und wirkt sofort. Cancel, Esc und das [x]
verwerfen, was nicht übernommen wurde.

*Tools → Network & Proxy…, LLM Profiles…, Agent Settings…, Metadata
Settings…* und *Extensions → Manage Extensions…* öffnen das Settings-
Fenster auf ihrer Seite. *View → Show Hidden Files* (**Strg+H**), *View →
Theme* und *View → Zoom* bleiben schnelle Schalter; sie werden sofort
gespeichert, wie die Seite.

## Konfigurationsdateien

- `~/.config/axross/profiles.json` — Verbindungsprofile (`0o600`).
- `~/.config/axross/bookmarks.json` — Bookmark-Bar.
- `~/.config/axross/session.json` — Pane-Layout, Window-Geometry und
  Dock-Layout beim letzten Beenden; beim Start wiederhergestellt,
  außer *Restore the layout of the last session on start* (Settings >
  General) ist aus. Das `window`-Objekt hält auch das Aussehen (Theme,
  Compact, Monochrome Icons, Schriftgröße, Hidden Files) und die Sprache.
- `~/.config/axross/settings.json` — kleine Einstellungen: Open Size
  Limit, Pane-Aktivierung, Metadata-Schreibweise und -Nachfrage, sudo-
  Passwort merken, gleichzeitig durchsuchte Hosts, der Security Mode.
- `~/.config/axross/proxy.json`, `llm.json`, `extensions.json` — Default-
  Proxy, LLM-Profile, eingeschaltete Extensions (Secrets im Keyring).
- `~/.config/axross/agent/voice.json` — die Voice-Einstellungen (`0o600`).
- `~/.config/axross/audio.json` — die Audio-Einstellungen: Backend,
  Output- und Input-Device, Volumes (`0o600`).
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
