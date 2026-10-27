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
  öffnen einen Browser für den Consent-Schritt (Dropbox fragt danach den
  angezeigten Code in einem Fenster ab). Der Verbindungsdialog nennt je Dienst,
  was wo anzulegen ist; Googles Client-Datei füllt beide Felder (Import Client
  JSON…). Tokens werden unter
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
  remote↔remote, cross-Protokoll). **Ctrl+X** / **Ctrl+V** sind Cut und
  Paste zwischen zwei beliebigen Ordnern (siehe Transfers).

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
- **Pane in einen anderen Workspace schicken:** Rechtsklick auf das Pane
  → **Send to Workspace** - in der Liste eines File-Panes (auf einer
  Datei oder auf der leeren Fläche, am Ende des Menüs), auf dem Header
  eines Panes oder im Terminal - und einen Workspace oder **New
  Workspace** wählen. Die Workspaces sind nummeriert, wie ihre Tabs
  stehen (**1: Workspace 1**, **2: Logs**; ein abgelöster trägt
  *(window)*), und bei 1 bis 9 wählt die Ziffer den Eintrag, solange das
  Menü offen ist. **Workspace → Send Pane to Workspace** tut dasselbe für
  das aktive Pane; oder den Pane-Header auf ein Pane eines anderen
  Workspace oder Fensters ziehen. File-Panes und Terminal-Panes lassen
  sich gleich ziehen (ein Terminal-Pane auch über seinen ⇄-Button); ein
  Workspace, dessen letztes Pane geht, schließt; hält man ein gezogenes Pane
  eine halbe Sekunde über einen Workspace-Tab, öffnet sich dieser Tab —
  so erreicht ein Pane auch einen Workspace im Hintergrund.
- **Extension-Panels** (Media Player, Drives Overview, Markdown Preview,
  …) sind auf allen Workspaces, bis man eines auf einen Workspace legt:
  der ⇄-Button in seiner Titelleiste (oder ein Rechtsklick darauf, *Send
  to Workspace*) bietet jeden Workspace (der, auf dem es liegt, mit
  Haken), **New Workspace** und **All Workspaces**, und
  **Workspace → Add Extension Panel** (auch im Rechtsklick-Menü des Tabs)
  holt ein Panel in einen Workspace. Dort ist es ein Pane: es erscheint
  nur mit seinem Workspace, geht mit, wenn der Workspace abgelöst wird,
  lässt sich an der Titelleiste auf ein anderes Pane ziehen und nimmt
  gezogene Panes an, wird über den Splitter in der Größe geändert und von
  **Equalize Pane Sizes** mit ausgeglichen. Sein [x] nimmt es aus dem
  Workspace; über das **Extensions**-Menü wieder eingeblendet, kommt es
  an seinen Platz zurück. Schließt der Workspace, parkt er seine Panels
  auf All Workspaces (ausgeblendet, mit ihrem Zustand); wird die
  Extension ausgeschaltet, gehen ihre Panels heraus, eingeschaltet kommen
  sie zurück.
- **Close Workspace** schließt ihn mit seinen Panes (nach Rückfrage);
  schließt das letzte Pane eines Workspace, geht der Workspace mit. Ein
  Workspace bleibt immer.
- **Equalize Pane Sizes** (**Ctrl+Shift+E**) gleicht den Workspace auf
  dem Bildschirm aus — auch einen, der nur Terminals oder
  Extension-Panels hält.
- Ein Layout-Preset (**View → Layout Preset**) ersetzt nur die Panes
  des aktuellen Workspace.
- Alle Workspaces — Namen, Reihenfolge, der aktuelle, Layouts mit ihren
  Terminals und Ordnern, welche abgelöst sind und wo ihre Fenster stehen
  — kommen beim nächsten Start zurück (siehe unten).

### Das Layout kommt beim Start zurück

Beim Beenden speichert axross das Layout in `session.json`; der
nächste Start baut es automatisch wieder auf:

- den Splitter-Baum mit seinen Größen, die Window-Geometry, das
  Dock-Layout (welche Docks offen sind und wo, und welche Tabs axross
  selbst gemacht hat) und das Theme;
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

### Docks: die rechte Spalte und automatische Tabs

- Die rechte Dock-Spalte (Analysis, Agent, abgelöste Konversationen,
  Extension-Panels wie der Media Player) reicht bis zur Unterkante des
  Fensters; der untere Bereich (Transfers, Terminal, Log, Console,
  Scripts) ist so breit wie die Panes und die Bookmarks-Spalte. Die
  Bookmarks-Spalte endet über dem unteren Bereich, so bleiben dessen
  Tabellen und Terminal-Zeilen breit.
- Brauchen die Docks einer Spalte mehr Höhe, als die Spalte hat - jedes
  einen brauchbaren Teil seines Inhalts (200 px, oder alles, wenn es
  weniger braucht), nicht nur seine Titelleiste -, werden benachbarte
  Docks zu Tabs zusammengelegt, bis sie passen; die Tabs stehen unten
  an der Gruppe. Nichts überlappt, auch wenn ein Window Manager das
  Fenster kleiner hält (Tiling, maximiert).
- Ist wieder Platz (größeres Fenster, ein Dock geschlossen, gefloatet
  oder weggezogen), stehen die Docks, die axross getabbt hat, wieder
  untereinander, wo sie waren. Docks, die du selbst getabbt hast,
  bleiben Tabs, und ein Dock, das du aus einer automatischen Tab-Gruppe
  ziehst, wird dafür nicht wieder getabbt - nur wenn die Spalte nicht
  einmal die Titelleisten der Docks fassen könnte.
- Solange eine Maustaste gedrückt ist (ein Separator oder ein Dock wird
  gezogen), bewegt sich nichts; geprüft wird, wenn das Resize zur Ruhe
  gekommen ist. Panels, die auf einem Workspace liegen, sind dort Panes
  und gehören zu keiner Spalte.
- Welche Tabs axross gemacht hat, steht mit dem Dock-Layout in
  `session.json`; nach einem Neustart gehen sie bei genug Platz wieder
  auseinander.

## Transfers

**Cut und Paste.** *Cut* (Ctrl+X oder Rechtsklick > Cut) merkt sich
nur die ausgewählten Einträge - nichts wird entfernt; solange der Cut
wartet, sind sie abgeblendet. *Paste* (Ctrl+V oder Rechtsklick > Paste,
auch auf freier Fläche) in einem beliebigen Pane - anderer Ordner,
andere Verbindung - verschiebt sie als Move über die Transfer-Queue in
dessen Ordner: mit derselben Prüfung auf vorhandene Namen wie F5 / F6,
und jede Quelle wird erst entfernt, wenn ihre eigene Kopie fertig und
geprüft ist; ein fehlgeschlagener, abgebrochener oder unvollständiger
Transfer lässt sie stehen. Ein Cut ohne Paste entfernt nichts: ein
neuer Cut ersetzt ihn, Esc in seinem Pane verwirft ihn, Schließen des
Panes oder ein Verbindungswechsel ebenso. Paste in den Ordner, aus dem
die Einträge stammen, tut nichts; ein Ordner in sich selbst wird
abgelehnt. Sobald der Move in der Queue ist, ist der Cut erledigt.

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
- **Parallel transfers.** *Edit → Settings… → Files & Panes →
  Parallel transfers* (1–8, vorgegeben 1) lässt mehrere Jobs
  nebeneinander laufen, gestartet in Queue-Reihenfolge; das versteckt
  die Round Trips vieler kleiner Dateien auf einer langsamen Leitung.
  Eine Verbindung, die keine zwei Jobs zugleich tragen kann (SCP und
  jedes andere Protokoll außer lokalen Dateien, RAM-Workspaces, SFTP,
  SMB, FTP, WebDAV und S3), arbeitet ihre Jobs weiter einzeln ab, und
  zwei Jobs schreiben nie zugleich dasselbe Ziel. Eine Änderung gilt
  für die Jobs, die danach starten. Jeder SFTP-Job läuft auf einem
  eigenen SSH-Channel, und Server begrenzen die Channels pro
  Verbindung (OpenSSH `MaxSessions`, vorgegeben 10). Jeder FTP-Transfer
  läuft auf einer eigenen Control Connection; Server begrenzen oft die
  Verbindungen pro User oder Adresse, und eine FTP-Verbindung, deren
  Server einen zweiten Login ablehnt, arbeitet ihre Jobs einzeln ab.

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
| Analyse with sift / Analyse Folder with sift | Rechtsklick (der Ordner-Eintrag auch auf freie Fläche), das Actions-Menü, *Tools → Analyse with sift* | Öffnet das Dock *Analysis (sift)* (sifts Sieb-Icon, `Ctrl+Shift+I`) und erklärt die Datei dort ohne Modell. Mehrere gewählte Dateien oder ein Ordner (der gewählte, sonst der angezeigte) werden als ein Batch für das aktive LLM-Profil angeboten; *Tools → Analyse with sift* nimmt die Auswahl, ohne Auswahl den angezeigten Ordner. sifts eigene Directory-Zusammenfassung (`sift --dir-summary`, ab sift 0.1.96) gehört nicht zum Dock: ein Ordner wird Datei für Datei analysiert. Ohne sift (axross-slim oder eine Source-Installation ohne das Extra `sift`) sagt jeder Eintrag, dass sift in axross-full oder im Extra `axross[sift]` steckt, mit Link auf *Help → Features…*. |
| Duplicate Finder | View-Menü | Gruppieren nach Content-Hash, `ax-cas://…`-URLs kopieren; markierte Kopien in den axross-Trash verschieben, nachdem live geprüft ist, dass eine echte andere Kopie bleibt. |
| View Media… / View Selected Media… | Rechtsklick, View-Menü | Bilder, PDFs und Videos des Ordners (optional rekursiv) oder der Auswahl als Overview-Grid, Viewer zum Durchklicken oder Slideshow — siehe *Editoren und Viewer*. |
| Show / Remove / Export Metadata… | Rechtsklick | EXIF / GPS / XMP / IPTC, Office-Properties, PDF-Info, Audio-/Video-Tags der Auswahl — oder des ganzen Ordners, wenn nichts ausgewählt ist (Unterordner optional) — siehe *Datei-Metadata*. |
| Cut / Paste | Rechtsklick (Paste auch auf freier Fläche), `Ctrl+X` / `Ctrl+V` | Cut merkt sich die Auswahl und entfernt nichts (die Einträge sind abgeblendet); Paste in einem beliebigen Pane verschiebt sie über die Transfer-Queue in dessen Ordner - siehe *Transfers*. Ein Cut ohne Paste lässt alles, wo es ist. |
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
  **Ctrl+F** springt ins Filterfeld; **Esc** dort löscht den Filter und
  kehrt zur Liste zurück. Esc in der Liste stoppt zuerst einen laufenden
  Load, löscht dann einen aktiven Filter, dann die Auswahl, dann einen
  wartenden Cut dieses Panes.
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
  liefern ihre Audiodateien sortiert, höchstens 2000, 6 Ebenen tief,
  Links auf Ordner werden einmal verfolgt; auch .m4b, .wv, .webm und
  weitere Formate, die die Engine abspielt, zählen; was keinen Track
  ergibt - kein Audio, nicht lesbar, zu tief -, nennt der Hinweis mit
  Anzahl, Dateien neben gefundenen Tracks wie Cover nicht; Remote-Dateien
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
  gespiegeltes Spektrum, radiales Spektrum, Oszilloskop, Stereo-VU-
  Meter, Linien-Spektrum (logarithmische Frequenzachse), Waterfall
  (Spektrogramm), Polar-Spektrum, Stereo-Scope (Goniometer: L gegen R),
  ein Starfield, das mit dem Bass schneller wird, *LED equalizer*
  (Blöcke mit fallendem Peak-Block), *Particle columns* (Punkte, aus
  denen im Beat Funken aufsteigen), *Wave ribbon* (ein Band aus Linien,
  das sich mit dem Beat dreht), *Ridgelines* (die History des Spektrums
  in der Tiefe unter einer gestreiften Sonne), *Spectrum terrain* (die
  History als Wireframe-Landschaft), *3D ring* (Balken auf einem
  gekippten Ring), *Kaleidoscope* (gespiegelte Blüten aus Bass, Mitten
  und Höhen) oder *Bell curves* (eine Glockenkurve je Band) - ein Klick
  darauf wechselt zur nächsten. Ihr Rechtsklick-Menü listet jede
  Visualisierung und jedes Farbschema (Classic, Fire, Ice, Neon, Mono,
  *Follow the theme*, *Custom*), die Anzahl der Balken und das
  Frame-Rate-Limit; *Visualizer Settings…* (auch *Extensions → Media
  Player Visualizer…*) ergänzt die eigenen Farben (Hintergrund, leise
  und laute Balken, Peaks - eine Peak-Farbe ohne 3:1-Kontrast zum
  Hintergrund wird angepasst), Peak-Fall-Speed und Smoothing.
  *Fullscreen* (Menü, Doppelklick oder F11 auf der Visualisierung) zeigt
  sie allein auf dem Bildschirm wie einen Screensaver - Esc, F11 oder
  ein Doppelklick beenden das, der Mauszeiger verschwindet nach 2,5 s
  ohne Bewegung (abschaltbar); *Detach into a Window* legt sie in ein
  eigenes Fenster beliebiger Größe, das weiterläuft, *Attach to the
  Panel* oder das Schließen des Fensters holt sie zurück. Der Pfeil links
  von *Playlist* (oder *Show Playlist* im Menü) klappt die Playlist ein:
  das Panel ist dann Steuerung und Visualisierung, die Tasten wirken
  weiter, und auf das Panel gezogene Dateien landen weiterhin in der
  Playlist. Visualisierung, ihre Farben und Optionen, eingeklappter
  Equalizer und eingeklappte Playlist kommen beim nächsten Start wieder.
- **Bluetooth** (mitgelieferte Extension, *Extensions → Manage
  Extensions…*) — ein Panel, um Lautsprecher, Kopfhörer und andere
  Bluetooth-Geräte über BlueZ (`bluetoothd`) am System-D-Bus zu
  verbinden; es startet kein Programm. Es zeigt den Adapter (bei
  mehreren: auswählen) mit dem Schalter *Powered*, und *Scan* listet, was
  in Reichweite ist: Name, Adresse, Typ (Lautsprecher, Headset, Telefon,
  Tastatur …), Signalstärke in dBm während des Scans, Akkustand, wo das
  Gerät ihn meldet, und Connected / Paired / Trusted. Ein Scan endet nach
  2 Minuten von selbst. Für das gewählte Gerät: *Pair* (*Cancel Pairing*,
  solange es läuft), *Trust* / *Untrust* (ein Trusted-Gerät darf sich
  selbst wieder verbinden), *Connect*, *Disconnect*, *Remove* (nach einer
  Rückfrage). Bei Lautsprechern und Kopfhörern läuft das Pairing meist
  ohne Frage; will ein Gerät einen Passkey bestätigt, eine PIN oder einen
  Passkey, fragt ein Dialog - nichts wird ohne deine Antwort angenommen, Schließen ist
  ein Nein. *Use as Audio Output* verbindet einen Lautsprecher oder ein
  Headset bei Bedarf, wartet bis zu 20 s, bis sein Ausgang im Soundserver
  erscheint, und macht ihn zum Ausgang von *Edit → Settings… → Audio*,
  dem der Media Player und die anderen Player sofort folgen; erscheint
  kein Ausgang (das A2DP-Profil fehlt, z. B. weil PipeWire oder
  PulseAudio ohne Bluetooth-Unterstützung läuft), sagt das Panel es und
  bietet *Audio Settings…* an. Fehler von BlueZ werden zu Sätzen (Adapter
  aus, per rfkill blockiert, falsche PIN, Gerät außer Reichweite, Profil
  nicht verfügbar). Ohne System-D-Bus, ohne laufenden `bluetoothd` oder
  ohne Adapter sagt das Panel das und bietet nichts weiter an; es merkt,
  wenn der Dienst startet oder ein Adapter eingesteckt wird. Nur Linux.
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
- Das Log-Dock filtert nach Level und nach Area: *Areas* neben dem Level
  ist eine Liste der Logging-Areas zum Anhaken (eine Area nimmt ihre
  Sub-Areas mit; *Other* ist alles außerhalb, *All Areas* der Default).
  Beide Filter zeigen die bisher empfangenen Zeilen neu. Was überhaupt
  geloggt wird, steht in *Edit → Settings… → Logging* (siehe
  [Logging](#logging)).
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
LLM-Profil (die Profile des Analysis-Docks (sift): LM Studio, Ollama, vLLM,
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

**Verläufe als eigene Panels.** Rechtsklick auf einen Tab → **Detach as
Panel** - oder den Tab weit aus der Tab-Leiste ziehen - macht den
Verlauf zu einem eigenen Panel; **Tools → New Agent Window** (oder ⧉
neben „+") öffnet einen neuen Verlauf gleich als Panel. **Send to
Workspace** im selben Tab-Menü erledigt es in einem Schritt: der Verlauf
wird abgelöst und auf den gewählten Workspace gelegt, mit **New
Workspace** allein auf einen neuen, wo er die Hauptansicht ist - per
Rechtsklick auf dessen Tab → **Detach to Window** bekommt er ein eigenes
Fenster. Es wandert
derselbe Verlauf: eine laufende Aufgabe läuft weiter, ihre Rückfragen
kommen weiterhin, nichts startet neu. Ein solches Panel liegt wie ein
Extension-Panel: auf **All Workspaces** (im Dock-Bereich des Fensters)
oder - über den ⇄-Button bzw. Rechtsklick auf seine Titelleiste (*Send
to Workspace*) oder **Workspace → Add Extension Panel** - auf einem
Workspace, wo es ein Pane ist: an der Titelleiste ziehen, in der Größe
ändern, beim Detach des Workspace geht es mit. ⇲ (oder *Attach to Agent
Dock* im Rechtsklick-Menü) setzt es als Tab zurück. Sein [x] schließt
den Verlauf wie das Schließen seines Tabs: gibt es einen Verlauf, fragt
es vorher, dann ist er gelöscht. Wird sein Workspace geschlossen, bleibt
es auf All Workspaces; *close all panels in this area* setzt es zurück
ins Agent-Dock. Jedes Panel hat seine eigene Lampe; die Voice arbeitet
für den Verlauf, in dem sie gestartet wurde, sonst für den, in dem
zuletzt getippt wurde; Settings, Profile und Extensions erreichen jeden
Verlauf. Mit *Keep tabs* kommen abgelöste Verläufe nach einem Neustart
auf ihrem Workspace bzw. auf All Workspaces wieder; einer, dessen
Workspace nicht wiederkommt (das Layout wird nicht wiederhergestellt),
ist wieder ein Tab.

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

**Files read-only** (in der oberen Zeile des Tabs, und für jeden Tab in
Agent Settings > Access): der Agent liest Dateien, ändert aber keine —
kein Schreiben, Löschen oder Verschieben, keine Remote Commands (ein
Command kann Dateien ändern), Extra-Ordner read-only, keine schreibenden
Tools von MCP-Servern oder Extensions, und eine Sandbox mountet nichts
schreibbar. Das gilt dort, wo die Tools des Agents gebaut werden, und
noch einmal bei jedem Aufruf, nicht nur im Dialog. Eine genaue
Ausnahme: ein MCP-Server, der deine Dateien nicht ändern kann, behält
seine Tools — ein Container-Server auf axross' eigener podman-Zeile (aus
einem Catalog installiert) mit `--network=none` und nur read-only
Ordnern (`:ro`). Sein *Asks* gilt weiter: mit "Every call asks" wartet
jeder Aufruf auf dein Yes. Jeder andere Server (Netzwerk, ein
schreibbarer Ordner, ein Programm auf diesem Rechner, ein HTTP-Server,
eine von Hand geschriebene podman-Zeile) bietet nur die Tools an, die er
als read-only markiert, und gar keins, wenn er vor jedem Aufruf fragt.

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

**Agent-Profile** richten einen Tab in einem Schritt ein: LLM-Profil,
Prompt-Profil, Protection Mode, Sandbox, Tool-Gruppen, axross-Funktionen
(Hauptschalter, Funktionen, Netzwerk), *Files read-only*, *Allow changes
to files* / *Allow remote commands* und die MCP-Server, die er anbietet —
gewählt **nach Kategorie** (die Catalog-Kategorie, aus der ein Server
installiert wurde, z. B. *Security: Reverse Engineering*; *Category* in
Agent Settings > MCP Servers setzt eine von Hand) und/oder **nach Name**
(oder nach dem Catalog-Eintrag, aus dem er stammt — ein umbenannter
Server passt weiter). Der Pfeil neben "+" im Agent-Dock bietet **New Tab
from Profile**, **Apply Profile…** (auch im Rechtsklick-Menü eines Tabs)
und **Edit Agent Profiles…**; Tools > New Agent Tab from Profile öffnet
einen Tab für den Ordner des aktiven Panes. *Apply Profile…* zeigt
vorher, was der Tab bekäme; es ändert die Settings des Tabs, Ordner und
Konversation bleiben, und ein Tab mit laufendem Task lehnt ab (erst
stoppen — der laufende Task behält die Settings, mit denen er startete).
Der Tab nennt sein Profil (*Profile: …*) und listet, was die Obergrenze
gekappt hat oder fehlt, mit **Install from Catalog…** (der Catalog öffnet
auf dieser Kategorie oder sucht den Server-Namen).

Ein Profil **erweitert Agent Settings > Access nie**: sind axross-Funktionen
dort aus, werden die MCP-Server des Profils nicht angeboten, und der Tab
sagt es; Bypass nur, wo er wählbar ist; ein Sandbox-Profil, das es nicht
gibt, bleibt stehen und wird verweigert, nie still "No sandbox". Unter
*Files read-only* bietet ein Server mit *Asks* "Every call asks" gar kein
Tool an, außer er ist ein Container ohne Netzwerk mit read-only Ordnern
(siehe *Files read-only* oben) — der Tab nennt jeden solchen Server und
warum.

Eingebaute **Presets** (read-only, markiert *(preset)*; *Copy* macht ein
änderbares Profil daraus):

| Preset | Was es einrichtet |
|---|---|
| Files Assistant | die File-Tools von axross, die offenen Remote-Verbindungen; Änderungen fragen; keine MCP-Server |
| Reverse Engineering | Kategorien *Security: Reverse Engineering* und *Security: Firmware & Forensics*; Sandbox *High* |
| Forensics read-only | Kategorie *Security: Firmware & Forensics*; Files read-only |
| Network & Web Recon | Kategorien *Security: Network Recon*, *Security: Web*, *Security: OSINT*; Mode Ask |
| Code & Secrets | Server *git* und *filesystem*, Kategorie *Security: Code & Secrets* |
| Remote Ops | Remote Files, Saved Connections, Remote Commands (jedes fragt); Mode Ask |
| Research | Server *fetch*, *memory*, *sequentialthinking*; nicht Files read-only (fetch braucht Netzwerk), *Allow changes to files* aus |

Ein Preset, dessen Server nicht installiert sind, richtet den Rest des
Tabs trotzdem ein. Agent Settings > **Profiles** bearbeitet die eigenen
Profile (New, Copy, Delete), zeigt in einer Preview, was ein Tab innerhalb
der Access-Seite bekommt, und wählt das **Profil neuer Tabs**. Gespeichert
in `~/.config/axross/agent/settings.json` (`agent_profiles`,
`agent_profile`); ein von Hand geänderter Eintrag wird geprüft wie der
Rest der Datei (unbekannte Keys fallen weg, falsche Typen nehmen ihren
Default, ein vergebener Name — auch der eines Presets — verwirft den
Eintrag).

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
einem Sandbox-Profil laufen; eines ohne sagt *runs on this machine, not
in a container*. Der Token eines HTTP-Servers liegt im Keyring. Ein
getippter Befehl, der Code herunterlädt (`npx …`, `uvx …`, `docker run
…`), wird nie als Programm auf diesem Rechner gespeichert: *Install in a
Container* baut ihn in rootless podman (ohne Netz), oder der Grund, warum
das nicht geht, wird gezeigt. Eine von Hand bearbeitete Settings-Datei mit
so einem Befehl startet ihn ebenso wenig (der Server wird ausgelassen, mit
Log-Zeile), und eine Container-Zeile mit erweiternden Flags
(`--privileged`, `--cap-add`, Host-Namespaces, andere Mounts) wird
abgelehnt.

*Tools → MCP Servers…* öffnet diese Seite (Edit → Settings… → Agent →
MCP Servers). **Add from Catalog…** durchsucht die *MCP-Quellen* und
installiert einen Server in **rootless podman**; nichts davon läuft auf
dem Host:

- **Quellen** (Agent Settings → MCP Sources, jede abschaltbar): der
  mitgelieferte Katalog (offizielle Referenz-Server aus Dockers
  kuratiertem `mcp/*`-Namespace plus zwei Security-Server, per Digest
  gepinnt, geht offline), Docker Hubs `mcp`-Namespace, die offizielle
  MCP Registry (`registry.modelcontextprotocol.io`) und eigene
  Katalogdateien oder `https://`-URLs. *Check* liest eine und nennt, was
  sie enthält oder warum sie abgelehnt wird (falsches Schema, größer als
  1 MiB, kein JSON, ein Eintrag ohne gepinnten Digest …). Was eine Quelle
  sagt, wird als reiner Text gezeigt.
- **c0decave MCP Hub** (standardmäßig an): ein Katalog desselben Schemas
  unter `https://raw.githubusercontent.com/c0decave/axross-mcp-hub/main/catalog.json`.
  Nur Images unter `ghcr.io/c0decave/`, gepinnt per echtem
  `sha256`-Digest, werden übernommen; jeder andere Eintrag (andere
  Registry, npm, pypi, Remote, kein Digest) wird mit Grund abgelehnt.
  Solange der Hub nicht antwortet, sagt die Statuszeile *not reachable or
  not published yet*, und die anderen Quellen arbeiten wie gewohnt.
- **Discover** (standardmäßig an): kuratierte Awesome-Listen zum Stöbern -
  [R00T-Kim/awesome-offensive-mcp](https://github.com/R00T-Kim/awesome-offensive-mcp)
  (CC0; ein Snapshot liegt axross bei, Discover geht also offline) und
  [wong2/awesome-mcp-servers](https://github.com/wong2/awesome-mcp-servers)
  (MIT; nur live gelesen). Ihr README wird als nicht vertrauenswürdiger
  Text gelesen: Kategorie, Name, Beschreibung und der GitHub-Repository-Link,
  sonst nichts - kein Markup, kein anderer Link. Ein Eintrag ist nur dann
  **installable via MCP Registry** oder **installable via Docker Hub**,
  wenn diese Quelle dasselbe Repository nennt (im Hintergrund geprüft,
  höchstens 300 Requests je Lauf, 24 h im Cache); sonst ist er **link
  only**: *Open Repository*, keine Installation - axross baut nie aus einem
  bloßen GitHub-Repository. *Refresh* liest die Listen und prüft neu.
- **Install**: ein Image wird per Digest gepullt (bei Docker Hub wird der
  Digest des Tags vorher erfragt; andere werden auf den Digest gepinnt,
  den podman meldet). Ein npm- oder pypi-Paket wird in einem Container
  eines gepinnten `node:22-slim`- / `python:3.13-slim`-Images installiert
  (`npm --ignore-scripts`, `pip --only-binary=:all:`), dessen einziges
  Netz die Paket-Registry ist, und als `localhost/axross-mcp:<name>-<version>`
  committet - nie npx, uvx, npm oder pip auf dem Host. Ein Remote-Server
  (Streamable HTTP, https) wird ein HTTP-Server. Der Fortschritt wird
  gezeigt, *Cancel Install* bricht ab; danach wird der Server getestet
  (initialize, tools/list) und eingeschaltet, wenn der Test bestand.
  **Save** behält ihn.
- **Wie er läuft**: `podman run --rm -i --init --pull=never` ohne
  Capabilities, ohne neue Privilegien, mit read-only Root, kleinem
  noexec-`/tmp`, Prozess- und Speicherlimits. Netz standardmäßig
  **None**; **Allowlist** erreicht nur die angegebenen `host:port` über
  einen Proxy in axross (für Programme, die `HTTPS_PROXY` beachten; die
  anderen haben gar keine Route); **Full** jeden Host. Ordner nur wie
  gewählt, read-only, solange *Writable* nicht angehakt ist. Umgebungswerte
  und Secrets (im Keyring) erreichen den Container über eine Pipe, nie auf
  der Kommandozeile oder in einer Datei.
- **Uninstall** entfernt den Server und beim Speichern sein Image per ID
  (`podman rmi`, nie erzwungen: ein Image in Benutzung, anders getaggt
  oder schon vor der Installation vorhanden bleibt). **Check for Update**
  zeigt einen neueren Digest oder eine neuere Version; aktualisiert wird
  nichts von selbst.

**Detected on this machine** (Agent Settings → MCP Servers und die
Tools-Liste jedes Agent-Tabs): MCP-Server, die hier schon eingerichtet
sind, werden mit einer Checkbox angeboten, ohne einen Befehl zu tippen -
die Server von Claude Desktop (`claude_desktop_config.json`), Claude Code
(`~/.claude.json`, auch je Projekt, und `.mcp.json` im Ordner des Tabs),
VS Code (`settings.json` → `mcp.servers`,
`mcp.json`, `.vscode/mcp.json`) und Cursor (`~/.cursor/mcp.json`,
`.cursor/mcp.json`), dazu podman-Images, die axross installiert hat (auch
wenn die Settings den Server verloren haben). Ein Haken in Agent Settings
fügt den Server eingeschaltet hinzu (Save behält ihn), Haken weg entfernt
ihn; ein Haken an einer `detected:<name>`-Zeile eines Tabs fügt ihn hinzu,
speichert die Settings und hakt `mcp:<name>` in diesem Tab an - das Modell
bekommt seine Tools sofort. Danach ist er ein Server wie jeder andere
(dieselben Confirm-Modes, standardmäßig „always"). **Was heruntergeladen
wird, läuft im Container, nie auf diesem Rechner:** ein Befehl, der beim
Start Code holt (`npx`, `bunx`, `pnpm dlx`, `yarn dlx`, `npm exec`, `uvx`,
`uv tool run`, `pipx run`, `docker`/`podman run` …), wird beim Haken
gekapselt installiert - das npm- oder pypi-Paket im gepinnten
`node`/`python`-Container gebaut (die neueste exakte Version, wenn der
Befehl keine nennt), ein Image gepullt und mit axross' gehärteter
podman-Zeile gestartet, ohne Netz; die Flags einer `docker run`-Zeile
(`--privileged`, `--network=host`, Volumes, `--cap-add`, `--device`,
Host-Namespaces, `--security-opt` …) werden nicht übernommen, und die
Details nennen, was wegfiel. Was sich nicht umsetzen lässt (eine Git-URL,
`--package`, `uv run`, eine unbekannte Option …), wird gezeigt, ist aber
nicht anhakbar, mit Grund. Ein Programm, das schon auf der Platte liegt,
läuft wie es ist, im Sandbox-Profil neuer Tabs (Agent Settings) bzw. des
Tabs, in dem es angehakt wurde, und sagt das: *runs on this machine, not
in a container*; eines, das es hier nicht gibt, ist nicht anhakbar. Die
Dateien werden nur gelesen, als nicht vertrauenswürdige Daten (reguläre Dateien bis 8 MiB,
JSON oder TOML, nichts wird ausgeführt). Umgebungswerte, die nach Secrets
aussehen (am Namen - TOKEN, PASSWORD, API_KEY … - oder an der Form), und
Bearer-Tokens landen nie in einem Log oder in `agent.json`: das
Einschalten fragt vorher und legt sie im Keyring ab. Programme im PATH
werden nicht erkannt: dort identifiziert nichts einen MCP-Server, ohne
ihn auszuführen oder am Namen zu raten.

Eine eigene Katalogdatei hat das Schema `axross-mcp-catalog`, Version 1
(Beispiel in [USAGE.md](USAGE.md)); `kind` ist `oci` (gepinnt per
`digest`), `npm` oder `pypi` (`package` und eine exakte `version`) oder
`remote` (`url`, `bearer`).

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
- **Sprache:** Deutsch oder Englisch, oder *der Antwort folgen*. In
  deutscher Sprache werden englische IT-Begriffe (Server, Backup, Pull
  Request, …) englisch gesprochen; ein Begriff, den die Antwort in
  `{Klammern}` schreibt, ebenso (die Klammern werden nicht angezeigt).
- **Voices** (ein Tab je Sprache): die Stimme, die die Sprache spricht
  (Deutsch: Thorsten oder Kerstin, Englisch: Ryan oder Lessac), ob sie
  heruntergeladen ist, **Download** (ein zweiter Klick bricht ab) und
  **Listen** - spricht zwei Beispielsätze mit den Werten des Tabs,
  gespeichert oder nicht, über den Output aus *Settings > Audio*; ein
  zweiter Klick stoppt. Jede Stimme behält eigene Werte, wie sie spricht:
  *Speed* (0,5-2×), *Pitch* (±6 Halbtöne; Piper kennt keine Tonhöhe, also
  wird die Sprache um den Faktor langsamer erzeugt und dann um ihn höher
  resampelt - die Länge bleibt), *Expressiveness* und *Rhythm variation*
  (wie stark Tonfall und Lautlängen variieren, 0-200 %), *Volume* (Anteil
  am Output-Volume, 10-100 %) und *Pause between sentences* (0-2 s);
  *Reset* setzt einen Wert zurück, *Reset All* alle Werte der Stimme.
  Jede gesprochene Antwort nutzt sie.
- **Einrichtung:** `pip install axross[voice]` (piper-tts, faster-whisper;
  in axross-full enthalten), dann **Download** neben einer Stimme auf der
  Seite Voice, oder *Help > Features…*, Gruppe **Voice**, für Stimmen und
  ein Whisper-Modell (gepinnte Checksummen, nach
  `~/.local/share/axross/voice/`).
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
| Appearance | Theme, Compact Mode, Monochrome Icons, Icon Colours (Theme default; Own colours in every theme - auch in Hacker und Amber, die jedes Icon in einer Farbe zeichnen; One colour nach Wahl), Schriftgröße (Zoom), Hidden Files hervorheben und ihre Farbe (eine auf dem Theme schwer lesbare Farbe erst nach Rückfrage) |
| Toolbar | Buttons nach Kategorie gruppieren, die Farbe jeder Kategorie hinter ihren Buttons zeigen, die Farbe jeder Kategorie (Connections, Windows & Panes, Files & Search, Media, LLM & Agent, Tools & System, Extensions), *Reset to Defaults* |
| Files & Panes | Hidden Files zeigen, Open Size Limit, Parallel transfers, RAM-Workspaces (an / aus, Größenlimit, frei gehaltener Speicher) und Temp-Dateien im RAM (gilt ab dem nächsten Start) |
| Network & Proxy | Default-Proxy, Bypass-Liste, PAC-Script, ein Test |
| LLM Profiles | Die LLM-Server von Agent- und Analysis-Dock; *Fetch models* öffnet eine Liste mit Größe, Parametern, Quantisierung und dem geladenen Modell, soweit der Server sie meldet |
| Analysis (sift) | Automatische Analyse der gewählten Datei (aus: eine Auswahl nennt die Datei nur, *Analyse* erklärt sie), das LLM-Profil von *Analyse with LLM* (das aktive oder ein eigenes - der Agent behält seine Wahl), Max Bytes pro Datei (begrenzt auch die Kopie einer Remote-Datei), Time Budget pro Datei, Vision, Context Tokens (0 = was der Server meldet), Tags pro Datei, Categories (eine pro Zeile), sifts Ergebnisse im Cache behalten, *Clear Cache*; sifts Version, oder ein Link zu *Help → Features…*, wenn dieser Build kein sift hat |
| Agent | General, Prompts, Access, Sandboxes, MCP Servers, MCP Sources, Sessions |
| Voice | Antworten vorlesen, gesprochene Sprache, die Stimme jeder Sprache (Download, Listen) und wie sie spricht (Speed, Pitch, Expressiveness, Rhythm variation, Volume, Pause zwischen Sätzen), Mikrofon-Modus, Hold-Taste, erkannten Text einfügen oder senden, die Pause, die das Sprechen beendet |
| Audio | Audio-Backend (Automatic, PipeWire, PulseAudio; das Backend dieses Laufs wird gezeigt, eine Änderung gilt ab dem nächsten Start), Output-Device und Volume (skaliert alles, was axross abspielt) mit *Play Test Tone*, Input-Device und Volume (Gain) mit *Test Microphone* (ein Level-Meter) und *Record 3 s and Play Back*, das Ergebnis des Audio-Checks und *Check Audio Again* |
| Metadata | Wie Remove Metadata schreibt, vorher fragen |
| Search | Gleichzeitig durchsuchte Hosts von *Find on Network Hosts*; wo Offline- und Duplicate-Index liegen |
| Security | Paranoid Security Mode (bleibt für den nächsten Start; `AXROSS_SECURITY_MODE` im Environment gewinnt), sudo-Passwort merken |
| Extensions | Welche Extensions eingeschaltet sind |
| Updates | Check for updates at start, Updates automatisch laden, *Check Now*, der letzte Check (siehe [Updates](#updates)) |
| Logging | Das Gesamt-Level (DEBUG, INFO, WARNING, ERROR), ein Level je Area (Inherit, ein Level oder Off; Third-Party-Libraries WARNING), Größe und Rotation des Logfiles, *Log to terminal (stderr)*, wiederholte Messages zusammenfassen, *Reset to Defaults* (siehe [Logging](#logging)) |

Die Seite **Analysis (sift)** schreibt `~/.config/axross/analysis.json`;
das offene Analysis-Dock nutzt eine gespeicherte Änderung sofort und
erklärt die gezeigte Datei neu. Die Grenzen sind sifts eigene - ein Wert,
den sift ablehnen würde (ein Context von 100 Tokens, eine Category
doppelt), wird über der Seite genannt, und nichts wird gespeichert. sifts
Ergebnisse liegen im Cache `~/.cache/axross/sift`
(`$XDG_CACHE_HOME/axross/sift`, nur für dich lesbar); *Clear Cache*
entfernt dort sifts Einträge und sonst nichts. Eine kaputte
`analysis.json` liest sich als Defaults und bleibt als
`analysis.json.unreadable-…` daneben liegen, bevor das nächste Speichern
sie ersetzt.

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

### Logging

Die Seite **Logging** bestimmt, was ins Log kommt - ohne es
zuzumüllen. Jeder Teil von axross gehört zu genau einer Area:
Application, Protocols (ein Eintrag je Familie: SFTP / SSH / SCP / rsync,
SMB / DFS, FTP / TFTP, WebDAV, Cloud Storage, NFS / iSCSI, Mail und News,
WinRM / WMI, Datenbanken, Git / SVN, Devices, Legacy-Protokolle,
Connections und Proxy), Local Files, Transfers, Indexing / Search,
Analysis, Agent / LLM, MCP (Client und Server), Scripting, Media / Audio /
Voice, Update, Security, Terminal, Extensions, User Interface und
Third-Party Libraries (paramiko, smbprotocol, urllib3 und requests, die
Cloud-SDKs, Pillow, asyncio, ...). Eine Area steht auf *Inherit* (das
Level der Area darüber, ganz oben das Gesamt-Level), DEBUG, INFO, WARNING,
ERROR oder *Off*. Das Gesamt-Level ist INFO; Third-Party-Libraries stehen
auf WARNING, DEBUG für SMB zeigt also die SMB-Schritte von axross, nicht
jedes Paket der Library. Eine Area auf DEBUG verfolgt ein Problem dort,
während der Rest auf INFO bleibt - ihre Debug-Zeilen entstehen gar nicht
erst, solange die Area leiser steht.

Das Logfile ist `~/.local/state/axross/logs/axross.log` (nur für dich
lesbar); es rotiert bei 5 MiB und behält 3 rotierte Dateien - beides wird
auf der Seite eingestellt (1-100 MiB, 1-20 Dateien). *Log to terminal
(stderr)* schreibt dieselben Zeilen ins Terminal, aus dem axross gestartet
wurde. *Collapse repeated messages* (an, 10 s): eine Message, die einer vor
weniger als dem Fenster geschriebenen gleicht (gleiche Area, Level, Text
und Fehler), wird gezählt statt geschrieben, die Zahl folgt als eine
Zeile, `Last message repeated 999 more times in 10.0 s: ...` - ein Timer,
der alle 10 ms scheitert, gibt zwei Zeilen je Fenster, nicht hundert pro
Sekunde. *Reset to Defaults* zeigt die Defaults; OK oder Apply speichert
sie. Jede Änderung wirkt sofort und steht in
`~/.config/axross/logging.json`.

`--debug` auf der Kommandozeile loggt jede axross-Area für diesen Lauf auf
DEBUG und schreibt ins Terminal; `--verbose` hebt jede Area auf mindestens
INFO, ebenfalls mit Terminal. Third-Party-Libraries behalten dabei ihr
Level, und die Seite sagt, solange ein solches Flag gilt.

*Tools → Network & Proxy…, LLM Profiles…, Agent Settings…, MCP Servers…, Metadata
Settings…* und *Extensions → Manage Extensions…* öffnen das Settings-
Fenster auf ihrer Seite. *View → Show Hidden Files* (**Strg+H**), *View →
Theme* und *View → Zoom* bleiben schnelle Schalter; sie werden sofort
gespeichert, wie die Seite.

## Updates

Die One-File-Binaries (`axross-full`, `axross-slim`, das macOS- und das
Windows-`axross-slim`) aktualisieren sich aus den GitHub-Releases von
`c0decave/axross`:

- **Check beim Start.** Einmal pro Start, etwa zwei Sekunden nachdem das
  Fenster erscheint, fragt axross die GitHub-API nach dem neuesten
  Release: ein https-Request, im Hintergrund; der Start wartet nie darauf. Eine
  neuere Version erscheint als **Update to X.Y.Z…** rechts in der
  Statusleiste und im *Help*-Menü. Ein gescheiterter Check (kein Netz,
  GitHubs Rate Limit) ist eine Zeile im Log und der Status auf *Settings →
  Updates*, nie ein Dialog. Releases mit Draft- oder Prerelease-Markierung
  werden ignoriert.
- **Help → Check for Updates…** prüft sofort und zeigt die Antwort, auch
  wenn axross aktuell ist.
- **Das Update-Fenster** zeigt diese und die neue Version, die Release
  Notes (als Markdown dargestellt; Bilder und andere Ressourcen darin
  werden nie geladen, HTML darin erscheint als Text, und nur http- und
  https-Links öffnen sich, im Browser) und einen Link zur Release-Seite
  und bietet **Download and
  Install**, **Skip This Version** (für diese Version kein Hinweis mehr;
  von Hand gefragt, wird sie trotzdem angeboten) und **Remind Me Later**
  (kein Hinweis bis zum nächsten Start).
- **Download and Install** lädt das Binary dieses Builds (axross-full
  bekommt axross-full, ein Slim-Build sein Slim-Binary), prüft dessen
  SHA-256 gegen die `SHA256SUMS` desselben Release (und gegen GitHubs
  eigenen Digest der Datei) und lehnt alles ab, was nicht passt - dann
  wird nichts ersetzt, und die Teildatei wird gelöscht. Vorher muss die
  `SHA256SUMS` selbst gültig signiert sein: `SHA256SUMS.sig` ist eine
  Ed25519-Signatur mit dem axross-Release-Key, dessen Public Key in axross
  eingebaut ist. Ein Release ohne sie, oder mit einer, die nicht
  verifiziert, wird abgelehnt ("The update is refused: release X.Y.Z is
  not signed with the axross release key") - wer das Release ändern kann,
  kann dessen Checksummen ändern, aber nicht diese Signatur erzeugen. Eine geprüfte
  Datei ersetzt das laufende Binary mit einem atomaren Rename, mit den
  Permissions der alten Datei; die alte bleibt daneben als
  `<name>.previous`. Sie wirkt ab dem nächsten Start; **Restart Now**
  schließt axross (es fragt nach ungespeicherter Arbeit wie bei jedem
  Schließen) und startet die neue Version.
- **Ein Ordner ohne Schreibrecht** (ein von root installiertes Binary)
  wird nicht angefasst: die geprüfte Datei landet in
  `~/.cache/axross/update/`, und **Save to…** legt eine Kopie ab, wo du
  willst.
- **Windows** kann ein laufendes Programm nicht ersetzen: die neue Version
  wird neben der alten als `axross-slim-windows-x64-X.Y.Z.exe` gespeichert;
  axross schließen und die alte Datei durch sie ersetzen (oder die neue
  starten).
- **Eine Python-Installation** (pip oder ein Source-Checkout) wird nie
  ersetzt; das Fenster nennt `pip install -U axross`.

*Settings → Updates*: **Check for updates at start** (an), **Download
updates automatically** (aus: der Hinweis bietet den Download an; an:
eine beim Start gefundene Version wird im Hintergrund geladen, geprüft und
installiert und wartet auf den nächsten Start), **Check Now** und Zeit und
Ergebnis des letzten Checks. Kontaktiert werden nur `github.com`,
`api.github.com` und `release-assets.githubusercontent.com`, über https;
jeder Redirect wird gegen diese Liste geprüft. Der Default-Proxy
(*Network & Proxy*) wird benutzt; ohne ihn `https_proxy` aus dem
Environment. Der Check beim Start läuft nicht mit
`AXROSS_NO_UPDATE_CHECK=1` im Environment oder im Paranoid Security Mode;
*Check Now* funktioniert trotzdem.

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
  Passwort merken, gleichzeitig durchsuchte Hosts, der Security Mode, die
  Update-Einstellungen (`update_check_at_start`, `update_auto_download`,
  eine übersprungene Version, der letzte Check).
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
- `~/.config/axross/logging.json` — die Logging-Settings: Gesamt-Level, Level je Area,
  Größe und Rotation des Logfiles, Terminal, Zusammenfassen wiederholter Messages
  (`0o600`).
- `~/.local/state/axross/logs/axross.log` — rotierendes Logfile (5 MiB, 3 rotierte
  Dateien, sofern *Edit → Settings… → Logging* nichts anderes sagt; `0o600`).

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
