# Axross — Benutzerhandbuch

Ein Multi-Protokoll-Dateimanager mit PyQt6. Inspiriert von Total
Commander, gebaut für Leute, die SFTP neben S3 neben IMAP neben FUSE
brauchen und die gleichen Werkzeuge (Checksum, Papierkorb,
Versionshistorie, Verschlüsselung) auf jedem Backend erwarten.

Dieses Handbuch erklärt wie das Tool funktioniert — von Installation
über tägliche Workflows bis zu den Feinheiten der Feature-Module.

---

## 1. Einführung

**Was ist axross?** Ein Dateimanager der 20 Protokolle über ein
einheitliches Backend-Interface anspricht:

- **Dateisysteme**: Local, SFTP, SCP, SMB/CIFS, DFS-N, NFS, iSCSI
- **Web/Cloud**: FTP/FTPS, WebDAV, S3, Azure Blob/Files, OneDrive,
  SharePoint, Google Drive, Dropbox
- **Windows-spezifisch**: WinRM (PowerShell-Remoting), WMI/DCOM
- **E-Mail/Transport**: IMAP, Exchange (EWS), Telnet, Rsync

Oberhalb davon liegt ein "Feature-Layer": Module die auf jedem
Backend funktionieren, auch wenn das native Protokoll sie nicht
kennt — universaler Papierkorb, verschlüsselte Overlay-Dateien,
cross-protokoll Symlinks, Snapshot-Browser, Content-Addressable-
Storage etc.

**Wann ist das nützlich?**
- Du hantierst regelmäßig mit Dateien auf verschiedenen Protokollen
  und willst sie in einem einzigen Fenster nebeneinander haben.
- Du willst cloud-native Features (Versionshistorie, Checksums) ohne
  jedem Cloud-Provider seine eigene Oberfläche lernen zu müssen.
- Du willst Server-Dateien mit lokalen Tools anfassen — via
  FUSE-Mount kann jedes Backend als normales Verzeichnis erscheinen.
- Du willst einen LLM (Claude Desktop, Cline) auf ein Backend
  loslassen — der eingebaute MCP-Server macht das möglich.

**Was es NICHT ist:**
- Kein Shell-Ersatz — komplexe TUI-Apps (vim, htop) laufen im
  integrierten Terminal nur eingeschränkt.
- Kein Sync-Tool à la rclone — Transfers sind einmalige
  Copy-Operationen, keine laufende Synchronisation.
- Kein Backup-Tool — Snapshots kommen von den Backends selbst.

---

## 2. Installation

### Systemvoraussetzungen

- Python 3.10 oder neuer
- Linux / macOS / Windows (vorherige Tests waren auf Linux; macOS
  solide; Windows ungetestet außer als Client-zu-Windows-Target)
- Optional: `pkexec` für "Open as root", `fusepy` für FUSE-Mounts,
  `rsync` / `iscsiadm` / `mount.nfs` für die jeweiligen Protokolle

### Basis-Installation

```bash
git clone <repo-url>
cd axross
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
axross
```

Die Basis-Installation kann SFTP, SCP, FTP/FTPS, Telnet und IMAP.
Alles andere kommt als Extra dazu.

### Extras für einzelne Protokolle

```bash
pip install -e ".[smb]"       # SMB/CIFS + DFS-N
pip install -e ".[webdav]"    # WebDAV
pip install -e ".[s3]"        # S3-kompatibel
pip install -e ".[azure]"     # Azure Blob + Azure Files
pip install -e ".[onedrive]"  # OneDrive + SharePoint
pip install -e ".[gdrive]"    # Google Drive
pip install -e ".[dropbox]"   # Dropbox
pip install -e ".[winrm]"     # WinRM / PowerShell-Remoting
pip install -e ".[wmi]"       # WMI / DCOM
pip install -e ".[exchange]"  # Exchange / EWS
pip install -e ".[fuse]"      # FUSE-Mount

pip install -e ".[all]"       # Alle "leichten" Protokolle auf einmal
                              # (ohne winrm/wmi/exchange/fuse)
```

Nicht installierte Backends werden im Connection-Dialog ausgegraut
gezeigt mit dem passenden `pip install`-Befehl. Nichts bricht —
axross funktioniert auch mit Basis-Installation.

### Start-Modi

Aus einem Terminal gestartet gibt axross das Terminal sofort zurück: das
Fenster läuft in einer eigenen Session im Hintergrund weiter, auf dem
Terminal erscheint nichts, das Log geht wie immer in die Log-Datei.
`--foreground`, `--verbose` und `--debug` bleiben im Vordergrund;
`--script`, `--mcp-server`, `--mcp-list-tools`, `--version` und `--help`
laufen ohnehin im Terminal, ebenso ein Start, dessen Ausgabe in eine Pipe
oder Datei geht. Unter Linux ohne `DISPLAY`/`WAYLAND_DISPLAY` (SSH ohne
X-Forwarding) bleibt axross ebenfalls im Vordergrund, damit die Meldung
„no screen" im Terminal ankommt. Das Terminal kommt zurück, sobald das
Fenster steht (bei einem warmen Start unter einer Sekunde).

**Startup Watchdog.** Ist das Hauptfenster 20 s nach dem Start noch nicht
da, schreibt axross den Stack jedes Threads nach
`~/.local/state/axross/logs/crash.log` und meldet auf stderr (bei einem
Hintergrund-Start auf dem Terminal, aus dem gestartet wurde) und im Log,
was passiert ist, wo es hängt - etwa in welcher Extension - und was zu tun
ist. Der Prozess läuft weiter; erscheint das Fenster doch noch, steht das
im Log. `AXROSS_STARTUP_WATCHDOG_SECONDS` ändert die Grenze, `0` schaltet
den Watchdog ab. Eine Extension, in der ein Start hängen geblieben oder
abgestürzt ist, lädt der nächste Start nicht (siehe `docs/EXTENSIONS.md`);
`--safe-mode` lädt beim Start gar keine Extension.

```bash
axross                       # Normal-Start (GUI); aus einem Terminal im Hintergrund
axross --safe-mode           # GUI ohne Extensions (für einen Start, der in einer hängt)
axross --foreground          # GUI, das Terminal bleibt belegt
axross --verbose             # GUI im Vordergrund, Log (INFO) auch auf stderr
axross --debug               # Mit Debug-Logging auf stderr (Vordergrund)
axross --mcp-server          # Als MCP-Server auf stdio (siehe §9)
axross --mcp-server --mcp-http 127.0.0.1:7331   # MCP als HTTP
```

---

## 3. Erster Start

Beim ersten Start siehst du:

```
┌─────────────────────────────────────────────────────────┐
│ [Menüleiste]                                            │
├─────────────────────────────────────────────────────────┤
│ [Toolbar: Connections | Panes | Files | Media | ...]    │
├─────────────────────────────────────────────────────────┤
│ [Pfadleiste]                    [Pfadleiste]           │
│ ┌─────────────────────┐        ┌─────────────────────┐ │
│ │                     │        │                     │ │
│ │   Datei-Pane 1      │        │   Datei-Pane 2      │ │
│ │   (lokal, home)     │        │   (leer/lokal)      │ │
│ │                     │        │                     │ │
│ └─────────────────────┘        └─────────────────────┘ │
├─────────────────────────────────────────────────────────┤
│ ┌─Transfers─┬─Terminal─┬─Log─┐                         │
│ │                                                      │ │
│ │   Aktive Bottom-Dock (tabified)                      │ │
│ └──────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

**Toolbar** = ein Button je Werkzeug, nach Kategorie gruppiert:
Connections, Windows & Panes, Files & Search (Main-Leiste), Media,
LLM & Agent, Tools & System, Extensions (Tools-Leiste, in einem schmalen
Fenster in der zweiten Zeile). Ein Separator trennt die Gruppen, und die
Farbe der Kategorie liegt als dezenter Tint hinter jedem Button; ein
gedrückter oder aktiver Button (z. B. ein offenes Dock) hat zusätzlich
eine Linie unten. Ein Button lässt sich per Drag and Drop innerhalb seiner
Gruppe verschieben; Rechtsklick auf die Toolbar → *Reset Toolbar Order*
stellt die Default-Reihenfolge wieder her. *Edit → Settings… → Toolbar*
schaltet Gruppierung und Farben ab und setzt die Farbe jeder Kategorie
(*Reset to Defaults* stellt alles zurück). Ein Button, den eine Extension
mitbringt, landet in Extensions.

**Aktives Pane** = blauer Rahmen. **Ziel-Pane** = grüner Rahmen.
Klick in ein Pane → wird aktiv, das vorherige wird Ziel. Das ist
die Basis für Transfers: Datei auswählen im aktiven Pane, `F5`
drücken → geht ins Ziel-Pane.

Die drei Tabs unten (Transfers / Terminal / Log) sind tabified:
nur einer ist gleichzeitig sichtbar. Wenn in einem nicht-sichtbaren
Tab was passiert (neuer Transfer-Status, Shell-Output, Log-
Eintrag), färbt sich das Tab-Label bernsteinfarben.

---

## 4. Grundkonzepte

### Backend

Jedes Protokoll ist ein *Backend*, das das `FileBackend`-Interface
implementiert. Das Interface hat ca. 20 Methoden: `list_dir`,
`stat`, `open_read`, `open_write`, `mkdir`, `remove`, `rename`,
`checksum`, `list_versions`, `symlink`, `hardlink`, usw.

Welche davon ein Backend wirklich beherrscht, steht in der
**BackendRegistry** (`core/backend_registry.py`). Das UI fragt die
Registry und zeigt/versteckt Aktionen entsprechend — z.B. "New
Symlink…" ist nur sichtbar wenn `backend.supports_symlinks` True ist.

### Pane

Ein **Pane** (`FilePaneWidget`) ist ein Datei-Browser für genau
*ein* Backend an *einem* Pfad. Du kannst beliebig viele Panes
gleichzeitig haben — horizontal und vertikal gesplittet. Ein Pane
hält eine Referenz auf ein Backend-Session und zeigt dessen
aktuellen Pfad.

### Connection-Pool

Mehrere Panes auf denselben Server teilen sich eine Transport-
Verbindung (`ConnectionManager`). Das heißt: wenn du dreimal zum
gleichen SFTP-Server verbindest (in drei Panes), wird nur eine
SSH-Transport-Instanz aufgebaut. Ref-Counting sorgt dafür, dass
der Transport erst abgebaut wird, wenn das letzte Pane sich
abmeldet.

### Profile

Verbindungsparameter (Host, Port, User, Auth-Typ, Proxy, …) werden
als **ConnectionProfile** gespeichert in `~/.config/axross/
profiles.json`. Das JSON enthält NIEMALS Passwörter — die gehen in
den OS-Keyring (GNOME Keyring, KWallet, macOS Keychain).

---

## 5. Verbindungen einrichten

`Ctrl+Shift+N` öffnet den Connection-Manager (`Ctrl+N`: Quick Connect zu
einem gespeicherten Profil). Wähle ein Protokoll aus dem
Dropdown — die restlichen Felder ändern sich entsprechend.

### SFTP (Standard)

- **Host / Port**: z.B. `server.example.com` / 22
- **Username**: dein SSH-User
- **Auth-Typ**: Password / Key-File / SSH-Agent
- **Proxy-Command** (optional): klassisches OpenSSH-`ProxyCommand`
  Format mit `%h` / `%p` / `%r` Tokens

Beim ersten Verbindungsversuch zu einem unbekannten Host erscheint
der Fingerprint-Dialog. Dein Host-Key wird nach Bestätigung in
`~/.ssh/known_hosts` persistiert.

**SSH-Config-Import**: Der "Import ~/.ssh/config"-Button liest deine
bestehende OpenSSH-Config und erzeugt axross-Profile aus den
Host-Einträgen. Keys und ProxyCommands werden übernommen.

### SCP

Wie SFTP, aber das Backend spricht SCP (`openssh-server`-Shell-
Befehle) statt SFTP. Nützlich wenn der Server kein SFTP-Subsystem
freigibt oder wenn du die SCP-Semantik brauchst (`-p`-Zeitstempel).

### FTP / FTPS

- **Host / Port**: 21 (FTP) oder 990 (FTPS implicit), 21 (FTPS explicit)
- **Passive-Mode**: Standard ist an; deaktivieren wenn dein Server
  aktives FTP erfordert
- **FTPS-TLS-Verification**: Standard ist an; deaktivieren nur für
  Lab-/Self-Signed-Server (dann NICHT Produktion)

### SMB/CIFS

- **Host / Share**: `server.local` / `data`
- **Username / Password**
- **Port**: 445 (Default)

Pfade intern als Forward-Slash (`/foo/bar.txt`), auf dem Wire
als Backslash-UNC (`\\server\share\foo\bar.txt`).

### DFS-N

Wie SMB, aber die Namespace-Pfade werden transparent via Referral
aufgelöst. Jede Dateioperation "just works" gegen
`\\domain\dfs\link`.

### WebDAV

- **URL**: z.B. `https://cloud.example/dav/`
- **Username / Password**

Server-side Copy/Move werden via `COPY`/`MOVE` HTTP-Methoden
gemacht — kein Byte-Streaming durch den Client.

### S3 / S3-kompatibel

- **Access Key / Secret Key**: als Username/Passwort eingegeben
- **Bucket**: Name des Buckets
- **Region** (optional): z.B. `eu-west-1`
- **Endpoint** (optional): für MinIO/Ceph/Wasabi/R2

### Azure Blob / Azure Files

- **Account Name**: dein Storage-Account
- **Container** (Blob) / **Share** (Files)
- **Account Key** ODER **Connection String** ODER **SAS-Token**
  (einer der drei reicht)

### OneDrive / SharePoint / Google Drive / Dropbox

OAuth-Flow. Siehe [OAUTH_SETUP.md](../OAUTH_SETUP.md) für die
einmalige App-Registrierung. Nach erfolgreichem OAuth wird der
Refresh-Token im Keyring persistiert.

### IMAP

Mailbox als Dateisystem: Ordner = Verzeichnis, Nachricht als
`<uid>_<subject>.eml` RFC-822 Raw-Datei, Attachments unter `<uid>/`.

### Exchange (EWS)

Wie IMAP aber über die EWS-SOAP-API via `exchangelib`. Unterstützt
mkdir (neuer Mail-Ordner), open_write (neue Mail uploaden —
Subject/To/Cc/Body aus dem MIME-Header geparsed), rename (Ordner
umbenennen), copy (Nachricht zwischen Ordnern kopieren).

### Telnet

Shell-als-Filesystem via Telnet-Session. Nur für Legacy-Targets wo
SSH nicht geht.

### WinRM / WMI/DCOM

Windows-Remote-Access ohne SMB. WinRM spricht PowerShell; WMI
spricht DCOM. Details in [WINDOWS_TESTING.md](WINDOWS_TESTING.md).

### Rsync / NFS / iSCSI

Diese drei brauchen System-Binaries (`rsync`, `mount.nfs`,
`iscsiadm`) und teils root-Rechte. Bei NFS und iSCSI wird via
passwortlosem `sudo -n` gemountet — richte das ein, bevor du diese
Protokolle nutzt.

---

## 6. Datei-Operationen

### Navigation

- **Doppelklick** / **Enter** auf einem Verzeichnis → hineinnavigieren
- **`..`** am Anfang der Liste → hoch
- **Alt+Left** / **Alt+Right** → Pfad-Historie zurück/vor
- **Tab** / **Shift+Tab** → zum nächsten / vorigen Pane wechseln
- **Ctrl+R** → Pane aktualisieren (list_dir neu ausführen)

### Erstellen

Rechtsklick → Kontextmenü:

- **New Folder** — `backend.mkdir(path)` auf jedem Schreib-fähigen
  Backend.
- **New File…** — Erstellt eine 0-Byte-Datei via
  `backend.open_write(path).write(b"")`. Funktioniert universell.
- **New Symlink…** — Nur sichtbar auf Backends die
  `supports_symlinks = True` flippen (LocalFS, SFTP). Zwei Prompts:
  Target (wohin der Link zeigt) und Linkname.
- **New Hardlink…** — Nur auf `supports_hardlinks = True`. Cross-
  Device-Hardlinks geben OSError(EXDEV) — das wird im Dialog gezeigt.

### Kopieren / Verschieben

1. Im Quell-Pane Dateien auswählen (Ctrl+Click für Mehrfach).
2. `F5` ODER Rechtsklick → "Copy to Target Pane" ODER
   Drag & Drop ins Ziel-Pane.
3. Transfers erscheinen im **Transfers-Tab** unten. Pro Job: Name,
   Fortschritt, Geschwindigkeit, ETA.

**Move** statt Copy: Rechtsklick → "Move to Target Pane". Nach
erfolgreichem Transfer wird die Quell-Datei gelöscht.

**Namenskonflikte**: Vor dem ersten Job prüft axross im Hintergrund,
welche Namen im Ziel schon existieren, und fragt pro Name: Overwrite,
Overwrite if Newer, Skip, Rename (`name (1).ext`) — optional für alle
restlichen Konflikte — oder Cancel (dann wird nichts kopiert). Ordner
werden zusammengeführt; gefragt wird nach den Konflikten darin. Ein
übersprungener Move lässt die Quelle stehen. Taucht eine Datei erst
nach der Abfrage im Ziel auf, bricht der Job ab, statt sie zu
überschreiben. Scripting/MCP behalten ihr explizites `overwrite=`.

**Resume**: Wird ein Transfer abgebrochen (Verbindungsabbruch,
manueller Cancel), bleibt eine Partial-Datei als `.filename.part-
<job-id>` im Ziel-Verzeichnis. Beim nächsten Transfer-Versuch der
gleichen Quelle erkennt axross das automatisch und macht an der
richtigen Offset weiter.

**Retry Failed**: Der Button im Transfers-Tab startet alle
fehlgeschlagenen / abgebrochenen Jobs erneut — mit Resume.

### Rename

Rechtsklick → "Rename…". Ein einzelner Rename geht über
`backend.rename(old, new)`.

**Batch-Rename** (Mehrfachauswahl → Rechtsklick → "Batch Rename…"):
Find/Replace oder Regex-Pattern mit Live-Preview. Zwei-Stufen-
Commit: erst alle in temporäre Namen (`oldname.rename-<hex>`),
dann in die finalen Namen. Wenn ein Target schon existiert (außer
als Teil des Rename-Sets) oder zwei Patterns auf denselben neuen
Namen mappen, wird die ganze Operation abgebrochen — nie partieller
State.

### Delete

Rechtsklick → **"Move to Trash"** (Standard, geht via `core.trash`)
ODER **"Delete (skip trash)"** für direktes `backend.remove()`.
Rekursives Löschen von Verzeichnissen fragt bei >0 Einträgen nach.

### Permissions (chmod)

Rechtsklick → "Permissions…" — Dialog mit 3×3 Checkbox-Grid und
Oktal-Eingabefeld (bidirektional verbunden). `backend.chmod()` wird
aufgerufen. Backends ohne POSIX-Mode-Bits (S3, WebDAV, Azure, etc.)
werfen OSError — wird im Dialog angezeigt.

### Show Checksum

Rechtsklick → "Show Checksum…". Bevorzugt native Backend-Checksums
(S3 ETag, Google Drive md5Checksum, `sha256sum` via SSH-Shell).
Wenn das Backend keinen bereitstellt, wird ein Stream-Hash via
`open_read` berechnet — mit Fortschritts-Dialog und Cancel-Button.

### Calculate Size

Rechtsklick auf Ordner → "Calculate Size (N dirs)". Zählt Größe, Dateien
und Ordner jedes gewählten Ordners im Hintergrund über die Connection
(Cancel in der Statuszeile) und zeigt eine sortierbare Tabelle. **Hidden
Files zählen mit** — Dotfiles, versteckte Ordner und Einträge mit
Hidden-Flag des Backends, wie bei `du` —, auch wenn das Pane sie nicht
anzeigt. Links zählen mit ihrer eigenen Größe und werden nicht verfolgt.

### Identify Files in This Folder

Rechtsklick (auch auf freie Fläche) → "Identify Files in This Folder…",
oder der gleichnamige Button im Fenster *Identify File Type*. Erkennt jede
Datei direkt im Ordner am Inhalt, Hidden Files eingeschlossen (höchstens 2000 Dateien, 64 KiB je
Datei, abbrechbar), auch auf Remote-Connections; die Tabelle sortiert,
Disk-Images zeigen Container, Partitionstabelle und Partitionszahl und
öffnen per Zeile *Disk Image…*, jede Zeile *Properties…*.

---

## 7. Feature-Module

### Universaler Papierkorb

Via `core.trash`. Jedes Backend bekommt einen `.axross-trash/`
Ordner (default unter `backend.home()`). Gelöschte Dateien wandern
dorthin mit einer `.meta.json`-Sidecar-Datei (Original-Pfad,
Zeitstempel, Größe).

- **Move to Trash** (Rechtsklick) → versendet die Datei in den Trash.
- **Show Trash…** (Rechtsklick) → Browser-Dialog mit Restore /
  Permanent-Delete / Empty-Trash.

Warum Sidecars statt zentrales Manifest? Weil S3/FTP/WebDAV keinen
atomaren CAS haben. Per-Entry-Sidecars = nie Read-Modify-Write auf
geteiltem State.

### Cross-Protokoll-Symlinks (XLink)

Rechtsklick → "Create XLink…". Erzeugt eine `.axlink`-JSON-Datei
die auf eine andere Backend-URL zeigt. Verwendbar um z.B. in einem
SFTP-Pane auf eine S3-Datei zu verweisen — ein Doppelklick auf die
`.axlink` navigiert axross zum Ziel.

Allowlist von Schemes (sftp, s3, webdav, https, smb, axross-link,
ax-cas) verhindert dass jemand dir ein `.axlink` mit
`javascript:`, `file:`, `data:` etc. unterschiebt.

### Encrypted Overlay

Rechtsklick → "Encrypt with passphrase…" / "Decrypt…". AES-256-GCM,
Schlüssel via PBKDF2-HMAC-SHA256 mit 200k Iterationen aus der
Passphrase abgeleitet. Das Resultat ist eine `.axenc`-Datei die
auf jedem Backend liegen kann.

### Content-Addressable Storage (CAS)

Lokaler SQLite-Index der `(backend_id, path) → checksum`-Mapping
hält, gespeist beim Checksum-Berechnen. Features:

- **Duplicate Finder** (View-Menü → "Duplicate Finder…"): Gruppiert
  Dateien mit identischem Inhalts-Hash über alle Backends hinweg.
  "Rebuild from Active Pane" indexiert den Ordner des aktiven Panes;
  ein erneuter Rebuild hasht nur Dateien, deren Größe oder Änderungszeit
  sich geändert hat. Symlinks und der axross-Trash werden nicht indexiert.
  Rechtsklick: Ordner öffnen, "Keep This Copy, Select the Others",
  "Select All but One", Pfad / Name / URL kopieren, aus dem Index
  entfernen. "Move Selected to Trash…" (auch Entf) verschiebt nur die
  markierten Kopien in den axross-Trash (wiederherstellbar über
  "Show Trash…") und prüft vorher live nach: Die Datei muss noch den
  indexierten Inhalt haben, und eine *echte* andere Kopie muss bleiben —
  kein Symlink, kein Hardlink, kein anderer Pfad zur selben Datei und
  nicht dieselbe Datei über ein zweites Backend (z. B. SMB und SFTP auf
  dasselbe NAS). Was sich nicht belegen lässt, bleibt liegen, mit Grund.
- **`ax-cas://`-URLs**: Eine stabile URL-Form die eine Datei über
  ihren Hash statt über einen Pfad referenziert. Die URL lässt sich
  kopieren und in einem anderen Pane öffnen.

### Metadata-Index

Noch ein lokaler SQLite-Index — diesmal für Name / Extension /
Size / Mtime. Gefüllt wird er nur über **Edit → Index Active Folder…**
(oder den Button *Index Current Pane…* im Suchdialog): das Verzeichnis
des aktiven Panes wird rekursiv eingelesen. Navigieren allein füllt
ihn nicht. Gespeichert ist er in einer Datei:
`$AXROSS_METADATA_DB`, sonst `$XDG_DATA_HOME/axross/metadata.sqlite`
(wenn `XDG_DATA_HOME` ein absoluter Pfad ist), sonst
`~/.local/share/axross/metadata.sqlite`. Ein Index, der schon am alten
Ort liegt, bleibt in Gebrauch, solange am neuen keiner liegt — wer
`XDG_DATA_HOME` setzt, verliert nichts. Der Duplikat-Index `cas.sqlite`
folgt denselben Regeln (`$AXROSS_CAS_DB`); *Edit → Settings… → Search*
zeigt beide Pfade, der Suchdialog den des Metadata-Index.

- **Was drinsteht:** je Datei und Ordner eine Zeile — Connection,
  voller Pfad, Name, Größe, Ordner ja/nein, Extension, Änderungszeit und
  wann indexiert wurde. Kein Inhalt, keine Checksummen.
- **Wie er gefüllt und aktualisiert wird:** rekursiver Walk über die
  Connection (jedes Backend, Hidden Entries eingeschlossen), höchstens
  50 Ebenen und 1 000 000 Einträge je Lauf, in Batches zu 500
  geschrieben, abbrechbar (Indexiertes bleibt). Ein zweiter Lauf über
  denselben Ordner aktualisiert die Zeilen; Zeilen von inzwischen
  gelöschten Dateien entfernt die GUI **nicht** (das MCP-Tool
  `index_build` mit `prune` tut es).
- **`Ctrl+Shift+F`** → Suchdialog. Substring über Name, optional
  nach Extension / Min-Size / Max-Size / Zeitraum filterbar,
  optional auf das Backend des aktiven Panes beschränkt. Extension,
  Größe und Datum nutzen SQLite-Indizes; ein Namens-Substring
  (`LIKE '%…%'`) kann keinen nutzen und liest jede Zeile.
- **Gemessen** auf der Entwicklungsmaschine mit `/usr` (290 872 Einträge,
  lokale Platte, Maschine unter fremder Last): erster Lauf 125 s (rund
  2 300 Einträge/s), zweiter Lauf 53 s, Indexdatei 98 MiB; eine
  Namenssuche 0,4–1,2 s (jede Zeile wird gelesen; viele Treffer dauern
  länger), eine Extension-Suche 37 ms. Gut für „wo lag die Datei" über
  Connections, die gerade offline sind; eine Inhaltssuche ist er nicht
  (das ist *Find Files → Contains*, live).
- **Und sift?** sift ist ein Datei-*Analyzer*, keine Suchmaschine: es
  baut keinen Index und hat keine Suche — Kommandozeile und API fassen
  Dateien zusammen, gespeichert wird nur ein Cache der Zusammenfassungen,
  nach dem Content-Hash der Datei. Ein besserer Index ist dort also nicht
  zu holen.

### Find Files

**Edit → Find Files…** (`Alt+F7` / `Ctrl+Alt+F`, im Pane per Rechtsklick
*Find in This Folder…*) sucht über mehrere Verzeichnisse auf allen
offenen Connections gleichzeitig: nach Name (Text oder Pattern wie
`*.jpg`, optional Regex), Inhalt (Text oder Regex, zeilenweise), Size,
Datum und **Typen** — Images, Videos, Audio, Documents, Archives,
Disk & VM images (dd/raw/img, ISO, qcow2, VDI, VMDK, VHD(X), E01, …),
Crypto wallets (`wallet.dat`, Electrum, Ethereum-Keystores `UTC--…`,
Exodus, Monero, MetaMask & Co.), Keys & certificates, Source code,
Email, Databases. Optional auch **in Archiven** (zip, tar.*, gz/bz2/xz/zst,
verschachtelt; 7z/rar nach Namen) und im Offline-Index. **Tag** beschränkt
die Treffer auf Dateien mit diesem Tag (ein getaggtes Archiv zählt für
seine Mitglieder); ein Smart Folder behält den Tag.

Lokal arbeiten `fd` und `ripgrep` (`rg`), wenn sie installiert sind;
sonst liefert ein eingebauter Walker dieselben Ergebnisse. Die
Ergebnisse kommen laufend, *Stop* bricht ab, Doppelklick zeigt die
Datei markiert im Pane. **Save as Smart Folder…** legt die Suche als
Smart Folder in die Bookmarks; ein Klick darauf startet sie erneut.

**Kann sift das schon?** Nein — Suchen über Ordner, nach Typ und in
Archiven ist Find Files von axross selbst (`core.file_search`,
`core.file_categories`, `core.archive`); sift sucht nicht. Was Find Files
von sift nimmt: ist das `sift`-Extra installiert (`axross[sift]`), fragt
der *Types*-Filter `sift.detect` nach lokalen Dateien, deren Name nichts
verrät (keine Extension, die ein Preset kennt), und ordnet dessen Art
(image, pdf, docx, archive, sqlite, email, source code, …) einem Preset
zu. Remote-Dateien und Archiv-Member werden nur nach Name und Ordner
typisiert. Einen Schalter gibt es nicht: ist sift da, wird es benutzt. In
Archiven listet sift die Member in seiner Zusammenfassung (Analysis-Dock),
durchsucht sie aber nicht; das macht *Inside archives* von Find Files.

**Wo sind sifts Optionen?** *View → Panels → Analysis (sift)*
(`Ctrl+Shift+I`; Rechtsklick → *Analyse with sift*)
erklärt die gewählte Datei — ohne Modell automatisch, mit dem aktiven
LLM-Profile auf *Analyse with LLM*. Der Button *LLM…* im Dock öffnet
*Edit → Settings… → LLM Profiles* (die Modell-Server). *Help → Features…*
zeigt, ob das sift-Extra installiert ist, und bietet die Installation an
(`pip install axross[sift]`; ein Frozen Build bietet stattdessen den
Download von axross-full). *Identify Files in This Folder…* zeigt sifts
Art lokaler Dateien als eigene Spalte.

Funktioniert offline — ein S3-Pane mit 10M Objekten braucht keine
Online-Abfrage sobald einmal indiziert.

### Snapshot-Browser (Versionshistorie)

Rechtsklick → "Show Versions…". Funktioniert für Backends mit
nativer Versionierung: S3 (ObjectVersions), Dropbox (rev-Chain),
Google Drive (revision-history), OneDrive (history), Azure Blob
(snapshots), WebDAV (DeltaV wenn verfügbar), Git (eine Version je
Commit des Branches, der die Datei geändert hat; die Version-ID ist der
Commit-SHA).

- **Save Version As** → Eine spezifische alte Version als neue Datei
  lokal speichern.
- **Restore as Current** → Alte Version zur aktuellen machen (falls
  das Backend das unterstützt — S3 z.B. via Copy-In-Place).

### Image Viewer / Previews

`F3` oder Doppelklick auf ein Bild. `Ctrl+M` Maximize / Restore, `F11`
Fullscreen (Esc verlässt Fullscreen, nochmal Esc schließt); Größe,
Position und Maximize-Zustand werden beim Schließen in `session.json`
(`window.viewers`) gemerkt. Geht durch `core.previews`:

- Strikte MIME-Allowlist (PNG, JPEG, WebP, GIF, BMP, TIFF; **SVG
  bewusst ausgeschlossen** — SVG kann JavaScript enthalten).
- `MAX_INPUT_SIZE` (default 50 MiB) + `MAX_DIMENSION` (default
  16384 px) als Dimension-Bomb-Schutz.
- Qt `QImageReader.setAllocationLimit` gegen Pixel-Bomb.
- Lokaler Thumbnail-Cache unter `~/.cache/axross/thumbs/`.

Nur lokale Backends — Remote-Bilder werden erst in einen Temp-
Bereich gespiegelt, dann gerendert.

### Audio

*Edit → Settings… → Audio* konfiguriert und testet den Sound von axross
(Media Player, Media-Preview, Voice des Agent-Docks):

- **Backend:** Automatic, PipeWire oder PulseAudio (`QT_AUDIO_BACKEND`).
  Automatic nimmt PipeWire, wo sein Daemon läuft, sonst PulseAudio (das
  `pipewire-pulse` ebenfalls bedient). Gezeigt wird das Backend dieses
  Laufs; Qt liest die Wahl einmal pro Prozess, eine Änderung gilt also
  ab dem nächsten Start. Ein selbst gesetztes `QT_AUDIO_BACKEND` gewinnt.
- **Output:** Device (System-Default oder ein bestimmtes) und Volume,
  das alles skaliert, was axross abspielt; *Play Test Tone* spielt 1 s
  Sinus auf dem gewählten Device in der gewählten Volume. Die Stimmen des
  Agent-Docks haben unter *Settings > Voice* zusätzlich je ein eigenes
  *Volume* als Anteil davon, neben *Speed*, *Pitch* und den anderen Werten,
  wie sie sprechen; **Listen** spielt dort eine Probe über diesen Output.
- **Input:** Device und Volume (Gain); *Test Microphone* zeigt ein
  Level-Meter, *Record 3 s and Play Back* nimmt 3 s auf und spielt sie
  auf dem gewählten Output ab.
- **Status:** das Ergebnis des Audio-Checks (ein eigener Prozess, bevor
  axross Qt Multimedia anfasst) und *Check Audio Again*. Scheitert der
  Check, sind die Tests aus, das Backend lässt sich trotzdem wählen.

Gespeichert in `~/.config/axross/audio.json` (`0o600`); laufende Player
übernehmen Volume und Output-Device sofort, wo Qt es erlaubt, sonst beim
nächsten Abspielen. Ein Device, das nicht eingesteckt ist, wird durch
den System-Default ersetzt (eine Log-Zeile). Startet im Media Player das
Audio nicht, führen *Try Again* und *Audio Settings…* von dort weiter.

### Elevated IO (pkexec)

Rechtsklick → "Open as root…". Nutzt `pkexec` um `cat`/`tee`/`stat`
mit Root-Rechten auszuführen. axross selbst läuft als normaler
User — die Privilegien leben nur im pkexec-Subprozess. Nützlich für
`/etc/shadow` oder `/root/…`.

Nur lokale Backends. Menüpunkt versteckt wenn `pkexec` oder eine
der Helper-Binaries (`cat`, `tee`, `stat`, `ls`) fehlt.

### FUSE-Mount

Rechtsklick → "Mount as FUSE (read-only)…" ODER "Mount as FUSE
(read-write)…". Das aktive Backend wird als FUSE-Mount im
gewählten Verzeichnis exponiert.

- **Read-only**: Alle Read-Callbacks funktionieren, Mutations
  antworten mit EROFS. TTL-Cache für Listings/Stats (30s default).
- **Read-write**: Create/Write/Unlink/Mkdir/Rename funktionieren.
  Writes landen in einem per-Handle Tempfile und werden bei Close
  als Ganzes an `backend.open_write` übergeben — "Whole-File-
  Overwrite"-Semantik, passt zu S3/Dropbox/IMAP ohne deren Verträge
  zu biegen.
- **Rename-Fallback**: Wenn das Backend keinen nativen Rename
  unterstützt (S3, IMAP, Exchange), wird intern `copy + remove`
  versucht. Schlägt das auch fehl, wird der Kopiervorgang zurück-
  gerollt (neue Datei gelöscht) damit keine Duplikate bleiben.

Braucht das `[fuse]`-Extra (fusepy). Zum Aushängen: entweder den
Menüpunkt nutzen oder `fusermount -u /mount/point` im Terminal.

### Atomic Recovery

Wenn ein Transfer mitten in einer Atomic-Write-Operation abbricht,
bleibt manchmal eine `.tmp-<hex>.tmp`-Leiche liegen (ältere Versionen
verwendeten `.axross-atomic-<hex>.tmp` — Recovery erkennt beide).
`core.atomic_recovery` macht beim Betreten eines Verzeichnisses
einen Sweep: Dateien die dem strikten Namensmuster entsprechen
UND älter als 1 h sind werden stillschweigend entfernt. Konservativ
genug dass laufende Operationen nicht gestört werden.

### Watch (Auto-Refresh)

Das Toggle-Symbol ◉ in der Pfadleiste abonniert das Pane auf
`core.watch`. Auf LocalFS wird inotify via `watchdog` genutzt (wenn
installiert), sonst wird per 2-Sekunden-Intervall die
Verzeichnisstruktur gepollt und Differenzen erkannt. Der Pane
refresht debounced bei Änderungen.

---

## 8. Bottom-Docks: Transfers / Terminal / Log

Die drei Docks sind tabified — nur einer ist gleichzeitig sichtbar.

**Transfers**: Laufende und beendete Transfer-Jobs mit Fortschritts-
Balken. "Cancel All" bricht alle ab, "Clear Finished" räumt Tote
weg, "Retry Failed" startet ERROR/CANCELLED-Jobs mit Resume neu.

**Terminal**: Dropdown zum Wechseln zwischen Sessions — "Local
Shell" (via `pty.fork`) oder "SSH: <hostname>" für jede aktive
SSH-Verbindung. Start/Stop/Clear-Buttons. ANSI-Escape-Sequenz-
Handling, aber kein vollwertiges Terminal — komplexe TUI-Apps wie
vim/htop laufen nur begrenzt.

**Log**: Echtzeit-Log aller `logging.getLogger()`-Ausgaben.
Level-Filter (Combo-Box), Auto-Scroll-Toggle, Clear-Button. Logs
gehen auch auf die Platte unter `~/.local/state/axross/logs/
axross.log`.

**Tab-Aktivitäts-Indikator**: Wenn in einem *versteckten* Tab was
passiert, färbt sich das Tab-Label bernsteinfarben. Klickst du den
Tab an, reset es. Macht es unmöglich einen langen Transfer oder
Log-ERROR zu übersehen.

---

## 9. MCP-Server für LLMs

axross kann als [Model Context Protocol](https://modelcontextprotocol.io)
Server laufen. Ein LLM-Client (Claude Desktop, Cline, ein eigenes
Python-Skript) kann dann Dateien auf dem konfigurierten Backend
auflisten, lesen, durchsuchen — bei `--mcp-write` auch schreiben.

### Stdio-Modus (einfachster)

```bash
# Read-only; default-Backend ist LocalFS rooted at $HOME.
axross --mcp-server

# Per Env-Var
AXROSS_MCP=1 axross

# Read-write (mit Path-Traversal-Cap auf backend.home())
axross --mcp-server --mcp-write
```

### HTTP-Modus (für Remote-LLMs)

```bash
# Loopback ohne TLS (nur zum Testen):
axross --mcp-server --mcp-http 127.0.0.1:7331

# Remote mit mTLS:
axross --mcp-server --mcp-http 0.0.0.0:7331 \
    --mcp-cert server.pem \
    --mcp-key server.key \
    --mcp-ca trusted-clients.pem
```

Non-Loopback ohne TLS wird abgelehnt — sonst würden JSON-RPC-
Payloads (inklusive Datei-Inhalte bei `--mcp-write`) im Klartext
durchs Netz gehen.

### Tool-Surface

Read-only (immer verfügbar):

- `list_dir(path)` — Verzeichnis-Einträge
- `stat(path)` — Name/Typ/Größe/mtime
- `read_file(path, max_bytes=…)` — base64, Cap 4 MiB
- `checksum(path, algorithm=…)` — nativer Fingerprint
- `search(needle, ext, min_size, max_size)` — Metadata-Index-Suche
- `walk(path, max_depth=4, max_entries=1000)` — rekursive Listung
  mit Progress-Notifications (stdio)

Mit `--mcp-write`:

- `write_file(path, content_b64)` — auf root gekappt
- `mkdir(path)`, `remove(path, recursive=False)` — gleicher Cap

**Progress über HTTP V1 nicht unterstützt** — SSE kommt in einer
späteren Version. Für long-running Work heute → stdio-Transport.

---

## 10. Terminal-Integration

Neben dem zentralen Terminal-Dock können Panes auch ein eingebettetes
Terminal bekommen: Rechtsklick auf einen SSH-Pane → "Embed Terminal".
Das Terminal läuft über dieselbe SSH-Transport-Instanz wie das
Filesystem — kein zweiter Login, keine zweite Authentifizierung.

Beim Schließen des Panes fragt axross nach wenn das Terminal noch
aktiv ist. "Pin"-Button behält das Terminal auch beim Pane-Schließen
offen.

---

## 11. Proxy-Konfiguration

Im Connection-Dialog ist der Proxy-Tab. Unterstützt:

- **SOCKS4/4a** (keine IPv6)
- **SOCKS5** (mit optionaler Auth)
- **HTTP CONNECT** (mit `Proxy-Authorization: Basic` wenn
  Credentials gesetzt)
- **SSH ProxyCommand** (nur für SFTP/SCP)

Der Proxy wird nur bei Backends aktiviert, deren Transport axross
wirklich kontrollieren kann. Nicht unterstützte Protokolle warnen
beim Verbinden, statt die Proxy-Einstellung still zu ignorieren
(Details: `docs/PROXY_SUPPORT.md`). Rsync läuft über OpenBSD `nc`;
`proxy_username` ist möglich, `proxy_password` wird dort aber
abgelehnt, weil `nc` keinen sicheren nicht-interaktiven Passwort-
Parameter bietet.

OneDrive / SharePoint / Google Drive / Dropbox öffnen beim ersten
OAuth-Setup einen externen Browser. Axross proxied die eigenen API- und
Token-Requests; die Browser-Consent-Seite selbst folgt Browser- oder
System-Proxy-Settings und wird bei Profil-Proxy als Einschränkung
gewarnt.

Requests-basierte SDK-Sessions, die Axross kontrolliert, deaktivieren
`HTTP_PROXY` / `HTTPS_PROXY` aus der Prozess-Umgebung (`trust_env=False`):
die Profil-Proxy-Felder sind die Quelle der Wahrheit.

SSRF-Schutz: Proxy-Hosts auf privaten Ranges (10/8, 172.16/12,
192.168/16, 127/8, 169.254.169.254/AWS-Metadata, ::1, fe80::/10
usw.) werden standardmäßig abgelehnt. Override mit
`AXROSS_ALLOW_PRIVATE_PROXY=1` — *nur* für Lab-Setups.

Welche Backends den profilweiten Proxy tatsächlich honorieren
steht in [PROXY_SUPPORT.md](PROXY_SUPPORT.md). Kurzfassung: SFTP/SCP,
WebDAV, FTP/FTPS, SMB/DFS-N, IMAP/POP3/NNTP, Telnet/Cisco-Telnet,
Gopher, PJL, ADB-TCP, Azure, OneDrive/SharePoint, Google Drive,
Dropbox, WinRM und Rsync sind angebunden. S3 ist nur via HTTP-CONNECT
angebunden; SOCKS wird dort abgelehnt. Kernel-/USB-/UDP-Backends und
DB-/VCS-Treiber ohne sauberen Socket-Hook warnen statt still direkt zu
gehen.

---

## 12. Tastaturkürzel

| Kürzel             | Aktion                                |
|--------------------|---------------------------------------|
| `Ctrl+N`           | Quick Connect (gespeichertes Profil)  |
| `Ctrl+Shift+N`     | Connection-Manager                    |
| `Ctrl+W`           | Aktives Pane schließen                |
| `Ctrl+H`           | Versteckte Dateien umschalten         |
| `Ctrl+Shift+H`     | Pane horizontal splitten              |
| `Ctrl+Shift+V`     | Pane vertikal splitten                |
| `Ctrl+Shift+F`     | Find in Index (Metadata-Search)       |
| `Alt+F7`, `Ctrl+Alt+F` | Find Files (Name, Typ, Inhalt, Archive) |
| `F3` / Doppelklick | Viewer (Bild / Text / Hex)            |
| `F5`               | Dateien zum Ziel-Pane kopieren        |
| `F2`               | Umbenennen                            |
| `Ctrl+R`           | Aktives Pane aktualisieren            |
| `Ctrl+S`           | Datei im Editor speichern             |
| `Alt+Left`         | Pfad-Historie: zurück                 |
| `Alt+Right`        | Pfad-Historie: vor                    |
| `Tab`              | Zum nächsten Pane wechseln            |
| `Ctrl+,`           | Settings: alle Einstellungen nach Kategorien (Edit → Settings…) |

---

## 13. Konfigurationsdateien

| Pfad                                      | Inhalt                              |
|-------------------------------------------|-------------------------------------|
| `~/.config/axross/profiles.json`         | Verbindungsprofile (ohne Passwörter) |
| `~/.config/axross/bookmarks.json`        | Verzeichnis-Lesezeichen              |
| `~/.config/axross/column_prefs.json`     | Pro-Pane-Spaltenbreiten              |
| `~/.config/axross/session.json`          | Pane-Layout beim letzten Beenden     |
| `~/.local/state/axross/logs/axross.log` | Rolling Log (5 MiB × 3 Backups)      |
| `~/.cache/axross/thumbs/`                | Thumbnail-Cache                      |
| `~/.cache/axross/metadata.db`            | Metadata-Index (SQLite)              |
| `~/.cache/axross/cas.db`                 | CAS-Index (SQLite)                   |
| `~/.ssh/known_hosts`                      | SSH-Host-Keys (Standard-OpenSSH-Datei) |

Passwörter, Tokens, Secrets: **NIE** in Dateien, immer im OS-
Keyring.

---

## 14. Logging + Debug

Normal: INFO-Level auf die Log-Datei + Log-Dock. Mit `--debug` auf
stderr und DEBUG-Level ausführlich.

Häufige Log-Quellen:

- `core.connect_worker` — Connect-Flow (Threading, Host-Key-Prompts)
- `core.transfer_worker` — Transfer-Status, Fehler, Resume-
  Entscheidungen
- `core.ssh_client`, `core.sftp_client`, etc. — Protokoll-spezifisch
- `ui.main_window` — Pane-Splits, Profile-Laden, Session-Restore

Wenn was kaputt ist: `--debug` starten, im Log nach `ERROR` oder
`WARNING` greppen. Stacktraces landen automatisch bei unhandled
Exceptions — ein Trace-Eintrag mit `Traceback (most recent call
last):` ist der Anfang.

---

## 15. Troubleshooting

**"Backend greyed out in Connection-Dialog"** — Das optionale
Extra ist nicht installiert. Der Dialog zeigt den `pip install`-
Befehl daneben.

**"Password nicht gespeichert beim Neustart"** — Dein System hat
keinen Keyring-Daemon. Auf Linux: GNOME Keyring oder KWallet
starten lassen. Auf headless Systemen kann das nicht funktionieren
— da bleibt nur "Password nicht speichern" und jedes Mal neu
eingeben.

**"SFTP hängt beim Connect"** — Firewall blockt SSH auf Port 22,
oder die Hostname-Auflösung klemmt. Prüfe: `ssh -v user@host` auf
der Kommandozeile. Wenn das auch hängt, ist es nicht axross.

**"Transfer bricht bei ~2 GiB ab"** — Manche FTPS-Server haben
einen Daten-Channel-Timeout. axross macht Keepalive alle 30 s;
wenn das nicht reicht, steig auf SFTP um.

**"FUSE-Mount freezes beim Browsen"** — Der Backend braucht länger
als der FUSE-Kernel-Timeout (default 120 s) für eine Listing-
Operation. Bei Cloud-Backends mit vielen Objekten unter einem
Prefix kann das passieren. Workaround: navigiere in kleinere
Sub-Pfade.

**"Open as root fehlt im Menü"** — `pkexec` oder eine der Helper
(`cat`, `tee`, `stat`) ist nicht installiert. `apt install
policykit-1` bzw. `pacman -S polkit` installiert den Daemon.

**"SSH agent keys all rejected"** — Der Server will einen
spezifischen Key-Typ den dein Agent nicht hat. Schalte auf "Key
File" um und gib den Pfad direkt an.

**"Metadata-Search findet nichts"** — Der Index wird nur über
**Edit → Index Active Folder…** gefüllt, nicht beim Navigieren. Öffne
den Bereich, den du durchsuchbar haben willst, im aktiven Pane und
starte dort die Indexierung. Ohne Index sucht **Edit → Find Files…**
direkt in den Verzeichnissen.

---

## 16. Sicherheit — was wir schützen

**Path-Traversal**: Backend-Antworten gehen durch `core.remote_
name.validate_remote_name` bevor sie in SQLite / Filesystem /
UI fließen. NUL-Bytes, Bidi-Override-Zeichen, ASCII-Controls und
`.`/`..`-Segmente werden abgewiesen.

**Host-Key-Verification**: UnknownHostKeyError beim ersten Connect
fragt den Benutzer; HostKeyMismatchError bricht hart ab. Keine
stillschweigende Acceptance.

**Credential-Leak-Prevention**: Passwörter und Tokens sind NIE im
Klartext in Config-Dateien oder Logs. Debug-Logs loggen Usernames
separat von INFO (um PII in zentralen Log-Aggregatoren zu vermeiden).

**MCP-Server-Scope**: Der HTTP-Transport mit mTLS-Verifikation
lässt nur Clients mit gültigem Zertifikat überhaupt an den JSON-
RPC-Layer. `--mcp-write` ist OPT-IN; der Root-Cap auf `backend.
home()` verhindert dass ein LLM `/etc/passwd` schreibt.

**Preview-Safety**: Bild-Thumbnails laufen durch eine strikte MIME-
Allowlist, Dimensions-Caps und Qt-Allocation-Limits. SVG ist
bewusst ausgeschlossen (könnte JavaScript enthalten).

**Proxy-SSRF**: Standardmäßig keine Proxies durch private /
Metadata-Adressranges (169.254.169.254/AWS-IMDS, 10/8, etc.).

---

## 17. Was das Tool NICHT macht

- **Keine laufende Synchronisation** — Transfers sind Einmal-
  Operationen. Für Sync: rclone, Syncthing, rsync-Skripte.
- **Keine Backup-Verwaltung** — Snapshots kommen vom Backend selbst.
  Für Backups: Borg, Restic, Duplicati.
- **Keine User-Management-Features** — Kein Ändern von Passwörtern
  auf dem Remote-System, keine Gruppen-Admin, kein sudoers-Edit.
  Das ist Shell-Job.
- **Keine Datei-Editor-Features außer Minimum** — Integrierter
  Editor ist für <1 MB Konfig-Dateien. Echte Editoren (vim, VSCode)
  nutzt man über FUSE-Mount oder via File-Download-Edit-Upload.

---

## 18. Weitere Dokumentation

- [README.md](../README.md) / [README_de.md](../README_de.md) —
  Kurz-Übersicht und Install-Instructions.
- [OAUTH_SETUP.md](../OAUTH_SETUP.md) — OAuth-App-Registrierung
  für OneDrive / SharePoint / Google Drive / Dropbox.
- [PROXY_SUPPORT.md](PROXY_SUPPORT.md) — Welche Backends den
  per-Profile Proxy honorieren, welche nur Process-Env-Variablen
  nutzen, welche komplett ignorieren.
- [WINDOWS_TESTING.md](WINDOWS_TESTING.md) — WinRM/WMI/DFS-N
  Test-Target aufsetzen.
- [TEST_COVERAGE_MATRIX.md](TEST_COVERAGE_MATRIX.md) — welches
  Backend welche Operation wie gut abdeckt.
