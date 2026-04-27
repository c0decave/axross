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

```bash
axross                       # Normal-Start (GUI)
axross --debug               # Mit Debug-Logging auf stderr
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
│ [Toolbar: Connect, Split, Refresh, ...]                 │
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

`Ctrl+N` öffnet den Connection-Dialog. Wähle ein Protokoll aus dem
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
- **Ctrl+Tab** → zum nächsten Pane wechseln
- **F2** → Pane aktualisieren (list_dir neu ausführen)

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

- **Duplicate Finder** (View-Menü → "CAS Duplicates…"): Gruppiert
  Dateien mit identischem Inhalts-Hash über alle Backends hinweg.
- **`ax-cas://`-URLs**: Eine stabile URL-Form die eine Datei über
  ihren Hash statt über einen Pfad referenziert. Die URL lässt sich
  kopieren und in einem anderen Pane öffnen.

### Metadata-Index

Noch ein lokaler SQLite-Index — diesmal für Name / Extension /
Size / Mtime. Wird inkrementell gefüllt beim Navigieren.

- **`Ctrl+Shift+F`** → Suchdialog. Substring über Name, optional
  nach Extension / Min-Size / Max-Size / Zeitraum filterbar,
  optional auf das Backend des aktiven Panes beschränkt.

Funktioniert offline — ein S3-Pane mit 10M Objekten braucht keine
Online-Abfrage sobald einmal indiziert.

### Snapshot-Browser (Versionshistorie)

Rechtsklick → "Show Versions…". Funktioniert für Backends mit
nativer Versionierung: S3 (ObjectVersions), Dropbox (rev-Chain),
Google Drive (revision-history), OneDrive (history), Azure Blob
(snapshots), WebDAV (DeltaV wenn verfügbar).

- **Save Version As** → Eine spezifische alte Version als neue Datei
  lokal speichern.
- **Restore as Current** → Alte Version zur aktuellen machen (falls
  das Backend das unterstützt — S3 z.B. via Copy-In-Place).

### Image Viewer / Previews

`F3` oder Doppelklick auf ein Bild. Geht durch `core.previews`:

- Strikte MIME-Allowlist (PNG, JPEG, WebP, GIF, BMP, TIFF; **SVG
  bewusst ausgeschlossen** — SVG kann JavaScript enthalten).
- `MAX_INPUT_SIZE` (default 50 MiB) + `MAX_DIMENSION` (default
  16384 px) als Dimension-Bomb-Schutz.
- Qt `QImageReader.setAllocationLimit` gegen Pixel-Bomb.
- Lokaler Thumbnail-Cache unter `~/.cache/axross/thumbs/`.

Nur lokale Backends — Remote-Bilder werden erst in einen Temp-
Bereich gespiegelt, dann gerendert.

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

SSRF-Schutz: Proxy-Hosts auf privaten Ranges (10/8, 172.16/12,
192.168/16, 127/8, 169.254.169.254/AWS-Metadata, ::1, fe80::/10
usw.) werden standardmäßig abgelehnt. Override mit
`AXROSS_ALLOW_PRIVATE_PROXY=1` — *nur* für Lab-Setups.

Welche Backends den profilweiten Proxy tatsächlich honorieren
steht in [PROXY_SUPPORT.md](PROXY_SUPPORT.md). Kurzfassung: SFTP,
SCP, WebDAV, Telnet ja. Cloud-Backends nehmen `HTTPS_PROXY`/
`HTTP_PROXY` aus der Prozess-Environment. Alles andere ignoriert
Proxy-Settings.

---

## 12. Tastaturkürzel

| Kürzel             | Aktion                                |
|--------------------|---------------------------------------|
| `Ctrl+N`           | Neue Verbindung (Connection-Dialog)   |
| `Ctrl+W`           | Aktives Pane schließen                |
| `Ctrl+H`           | Versteckte Dateien umschalten         |
| `Ctrl+Shift+H`     | Pane horizontal splitten              |
| `Ctrl+Shift+V`     | Pane vertikal splitten                |
| `Ctrl+Shift+F`     | Find in Index (Metadata-Search)       |
| `F3` / Doppelklick | Viewer (Bild / Text / Hex)            |
| `F5`               | Dateien zum Ziel-Pane kopieren        |
| `F2`               | Aktives Pane aktualisieren            |
| `Ctrl+S`           | Datei im Editor speichern             |
| `Alt+Left`         | Pfad-Historie: zurück                 |
| `Alt+Right`        | Pfad-Historie: vor                    |
| `Ctrl+Tab`         | Zum nächsten Pane wechseln            |

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

**"Metadata-Search findet nichts"** — Der Index wird nur gefüllt
wenn du in Verzeichnissen navigierst. Ein Pane-Open auf `/` füllt
nur `/`. Navigiere einmal durch die Bereiche die du durchsuchbar
haben willst.

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
