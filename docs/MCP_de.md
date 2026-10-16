# MCP-Server — ausführlich

Axross kann als [Model Context Protocol](https://modelcontextprotocol.io)
(MCP) Server laufen, sodass ein LLM-Client (Claude Desktop, Cline,
ein eigener Agent) über eine JSON-RPC-Tool-Fläche auf einem lokalen
Verzeichnisbaum arbeitet. Der CLI-Server (`axross --mcp-server`, stdio
oder HTTP) bedient das lokale Dateisystem (`LocalFS`), begrenzt auf die
MCP-Root. Optionale **Capability-Gruppen** (`--mcp-tools`, §9) fügen
Metadaten, den Duplicate Finder, den Packer, Archive, Verschlüsselung,
den Search-Index, Dateityp-Erkennung, Transfers zwischen Backends,
gespeicherte Connection-Profile als weitere Backends und die
Extension-Liste hinzu. Ein maschinenlesbares Manifest aller Tools
liefert `axross --mcp-list-tools` bzw. [`mcp-tools.json`](mcp-tools.json)
(§9.7).

Der Server spricht MCP-Protokoll-Version **2024-11-05**.

Sprachen: [English](MCP.md) · **Deutsch** · [Español](MCP_es.md)

---

## 1. Transporte

### 1.1 Stdio

```bash
# Read-only; LocalFS, MCP-Root per Default $HOME (änderbar mit --mcp-root):
axross --mcp-server

# Per Env-Var (gleiches Verhalten):
AXROSS_MCP=1 axross

# Die neun Schreib-Tools (write_file, mkdir, remove, rename, copy,
# bulk_copy, symlink, hardlink, chmod). Path-Traversal gekappt an einer
# gewählten Wurzel. AXROSS_MCP_WRITE=1 ist das Env-Var-Gegenstück:
axross --mcp-server --mcp-write --mcp-root ~/data

# Script-Tools (script_list/api_schema/read/write/delete/run) — nur stdio:
axross --mcp-server --mcp-allow-scripts

# Capability-Gruppen (§9); AXROSS_MCP_TOOLS=metadata,packer ist das
# Env-Var-Gegenstück, 'all' schaltet jede Gruppe ein:
axross --mcp-server --mcp-tools metadata,filetype
axross --mcp-server --mcp-write --mcp-root ~/data --mcp-tools all

# Das Tool-Manifest (JSON) zu einem Satz Flags ausgeben, nichts starten:
axross --mcp-list-tools --mcp-tools all --mcp-write
```

`--mcp-write` ohne `--mcp-root` wird verweigert (Exit 2): die
Default-Root ist das Home-Verzeichnis, und das ist zu weit, um
beschreibbar zu sein. Eine unbekannte `--mcp-tools`-Gruppe wird
verweigert (Exit 2), mit einer stderr-Zeile, die die gültigen Gruppen
nennt.

`--mcp-allow-scripts` wird im Security-Mode `paranoid` verweigert
(Exit 2) und zusammen mit `--mcp-http` ebenfalls (Exit 2): Script-
Ausführung über einen Netzwerk-Transport wird nicht angeboten. Was die
Script-Tools erreichen können, steht in §2.

Requests über stdin (zeilen-delimitiertes JSON), Responses über
stdout. Logs nur nach stderr. Wenn der MCP-Pfad aktiv ist, wird
PyQt nicht importiert — der Server läuft sauber auf Headless-Hosts.

### 1.2 HTTP (+ optional mTLS)

```bash
# Loopback-HTTP (ohne TLS auf Nicht-Loopback verweigert):
axross --mcp-server --mcp-http 127.0.0.1:7331

# mTLS — alle drei Dateien nötig:
axross --mcp-server --mcp-http 0.0.0.0:7331 \
    --mcp-cert server.pem --mcp-key server.key --mcp-ca trusted-ca.pem
```

Endpoints:

| Methode + Pfad                        | Zweck                                                            |
|--------------------------------------|------------------------------------------------------------------|
| `POST /messages`                     | Einen JSON-RPC-Request senden, eine Response empfangen.          |
| `GET /messages` (SSE)                | Event-Stream für Notifications, session-gebunden.                |
| `DELETE /messages`                   | Session explizit beenden.                                        |
| `GET /health`                        | Unauthentifiziert; liefert `{server, version}`.                  |

Sessions sind auf HTTP Pflicht. Der erste `POST /messages` mit
`initialize` bekommt eine frische Session-ID im Response-Header
`Mcp-Session-Id`; jeder weitere Request stempelt diese ID mit.
Unbekannte / abgelaufene IDs antworten 404.

mTLS läuft mit `CERT_REQUIRED` + TLS 1.2 Minimum: ein Client, der
kein CA-signiertes Zertifikat vorzeigen kann, wird während des
Handshakes abgewiesen — noch bevor HTTP überhaupt parst.

Der HTTP-Transport bedient die Read-only-Tools, (mit `--mcp-write`)
die Schreib-Tools und die `--mcp-tools`-Gruppen; die Script-Tools
bedient er nie.

---

## 2. Tool-Oberfläche

Die Datei-Tools unten sind immer die Basis. Alles andere (Metadaten,
Duplikate, Packer, Archive, Verschlüsselung, Index-Aufbau, Dateitypen,
Transfers, Remote-Profile, Extensions) ist eine Capability-Gruppe,
siehe §9.

### Read-only-Tools (immer aktiv)

| Name                 | Beschreibung                                                          |
|----------------------|-----------------------------------------------------------------------|
| `list_dir(path)`     | Verzeichniseinträge.                                                  |
| `stat(path)`         | Name, Typ, Größe, mtime.                                              |
| `read_file(path, max_bytes=)` | Base64-kodierter Inhalt; standardmäßig auf 4 MiB gekappt.     |
| `checksum(path, algorithm=)`  | `sha256` (Default), `sha1`, `md5` oder `sha512`. Nutzt den nativen Hash des Backends nur, wenn er vom angefragten Algorithmus ist, sonst Streaming durch hashlib (sendet Progress). |
| `search(needle, ext, min_size, max_size)` | Offline-Metadaten-Index, auf die aktive Backend-ID und die MCP-Root beschränkt. |
| `walk(path, max_depth, max_entries)`      | Begrenzte rekursive Listung; sendet `notifications/progress`. |
| `recursive_checksum(path, algorithm, max_files, max_depth, max_file_bytes)` | Hasht jede Datei unter einem Pfad (Dateien über 1 GiB per Default übersprungen); ein Progress-Frame pro gehashter Datei. |
| `grep(pattern, path, max_depth, max_matches)` | Regex-Suche in Datei-Inhalten. Dateien >4 MiB übersprungen, max. 500 Treffer; sendet Progress. |
| `list_versions(path)` | Metadaten pro Version — wo das Backend es unterstützt.              |
| `open_version_read(path, version_id, max_bytes=)` | Base64-Inhalt einer bestimmten Version.         |
| `preview(path, edge=256)` | Thumbnail eines Bildes — als MCP **image content** mit korrektem mimeType. |

### Schreib-Tools (nur bei `--mcp-write`)

| Name                              | Beschreibung                                                               |
|-----------------------------------|----------------------------------------------------------------------------|
| `write_file(path, content_b64)`   | Base64-Upload.                                                             |
| `mkdir(path)`                     | Verzeichnis anlegen.                                                       |
| `remove(path, recursive=False)`   | Löschen.                                                                   |
| `rename(src, dst)`                | Umbenennen / Verschieben.                                                  |
| `copy(src, dst)`                  | Server-seitige Kopie wo unterstützt; Stream-Fallback sonst.                |
| `bulk_copy(src, dst, max_files, max_depth, max_file_bytes, overwrite)` | Baum-Kopie (Dateien über 10 GiB per Default übersprungen); ein Progress-Frame pro kopierter Datei. |
| `symlink(target, link_path)`      | `link_path` muss unter der Root liegen; `target` wird bewusst **nicht** gegen die Root geprüft (darf ins Leere oder nach außen zeigen — spätere Tools lösen Links über `_enforce_root` auf, bevor sie ihnen folgen). Kein Capability-Flag wird geprüft; ein Backend ohne Symlinks lässt den Call scheitern. |
| `hardlink(target, link_path)`     | Beide Enden müssen unter der Root liegen. Kein Capability-Flag wird geprüft; ein Backend ohne Hardlinks lässt den Call scheitern. |
| `chmod(path, mode)`               | POSIX-Mode-Bits. Akzeptiert int oder Oktal-String.                         |

Jeder Schreib-Tool-Aufruf läuft zuerst durch `_enforce_root` — eine
Payload wie `/etc/passwd` wird abgewiesen, bevor irgendein IO das
Backend erreicht (einzige Ausnahme: das `symlink`-Target, siehe oben).
Jeder Call schreibt Audit-Einträge auf den Logger
`core.mcp_server.audit`, mit Tool, Ergebnis, Pfad und Größe —
niemals mit den Payload-Bytes.

### Script-Tools (nur bei `--mcp-allow-scripts`, nur stdio)

| Name                          | Beschreibung                                                      |
|-------------------------------|-------------------------------------------------------------------|
| `script_list()`               | Namen der gespeicherten Skripte in `~/.config/axross/scripts/`.   |
| `script_api_schema()`         | Die `axross.*`-API als JSON (wie `axross.api_schema()`): je Funktion Signatur, typisierte Parameter, Rückgabetyp, Kurzbeschreibung, `mutates`, `prompts`; die öffentlichen Klassen; die Methoden jeder Backend-Session. Read-only. |
| `script_read(name)`           | Quelltext eines gespeicherten Skripts.                            |
| `script_write(name, source)`  | `<name>.py` speichern (Mode 0600); überschreibt.                  |
| `script_delete(name)`         | Gespeichertes Skript entfernen; idempotent.                       |
| `script_run(name, args?, timeout_s?)` | Gespeichertes Skript in einem eigenen Python-Prozess ausführen, mit `axross.*` im Scope; `args` werden zu `sys.argv[1:]`. Liefert eine strukturierte Antwort (unten). |

`script_run` im Detail — worauf sich ein Client verlassen kann:

* **Ein Kindprozess, nie der Server.** stdin ist leer: `input()` bekommt
  `EOFError` und kann nie den JSON-RPC-Stream lesen. Das Kind läuft in
  einer eigenen Prozessgruppe; endet der Lauf, enden alle Prozesse, die
  er gestartet hat (einer, der `setsid` aufruft, entkommt).
* **Wall-Clock.** `timeout_s` (Default 60, höchstens 600) beendet den
  Lauf: SIGTERM an die Gruppe, 3 s später SIGKILL. `tasks/start` +
  `tasks/cancel` starten und stoppen ein Skript im Hintergrund.
* **Antwort.** `{name, exit, timed_out, duration_ms, stdout, stderr,
  namespace_keys}`; nach einer nicht gefangenen Exception zusätzlich
  `error_type`, `error` und ein begrenzter `traceback` (nur die Frames
  des Skripts). `exit` folgt `SystemExit` exakt (`None` ist 0, ein int
  ist er selbst, auch über 255, alles andere geht nach stderr und gibt
  1); ein gestoppter Lauf hat die negative Signalnummer.
  `namespace_keys` sind die Top-Level-Namen, die das Skript hinterlässt
  (höchstens 500).
* **Ausgabe.** stdout und stderr fassen je bis zu 1 MiB Zeichen; mehr
  stoppt den Lauf, und der Aufruf scheitert (`script output exceeded …`).
* **Kein Mensch.** Das Kind läuft mit `AXROSS_NONINTERACTIVE=1`:
  `axross.confirm()` wirft `NonInteractiveError`, außer das Skript
  übergibt `assume_yes=True`, und ein Schreibzugriff auf ein als
  *production* markiertes Profil wird verweigert, außer der Server
  wurde mit `AXROSS_TARPIT_DISABLE=1` gestartet. `script_api_schema`
  markiert jede Funktion, die einen Menschen brauchen kann (`prompts`)
  oder Zustand ändert (`mutates`).
* **Argumente.** `args`: höchstens 64 Strings mit je höchstens 4096
  Zeichen, ohne NUL; ein falsches `args` oder `timeout_s` wird
  verweigert, bevor etwas läuft (`-32602`).

**Security-Hinweis:** die Script-Tools sind **überhaupt nicht** auf
die MCP-Root begrenzt. Namen sind auf `[A-Za-z0-9_-]+` im
Script-Verzeichnis beschränkt, aber `script_run` führt beliebigen
Python-Code mit den Rechten des Server-Users aus — es kann alles
lesen und schreiben, was dieser User darf, Netzwerkverbindungen
öffnen und jedes `axross.*`-Backend nutzen. `--mcp-allow-scripts` ist
wie das Aushändigen einer Shell zu behandeln. Im Security-Mode
`paranoid` und mit `--mcp-http` wird es verweigert. `script_write`,
`script_delete` und `script_run` hinterlassen attempt / ok / refused
auf `core.mcp_server.audit` (Name, Größe, Exit-Code, `timed_out`, den
Exception-Typ — nie den Quelltext, die Argumente oder die Ausgabe des
Skripts).

### Capability: Resources

Wenn der Server mit Ressourcen-Katalog gebaut wird, kommen drei
Endpoints dazu:

| Methode                        | Zweck                                                      |
|--------------------------------|------------------------------------------------------------|
| `resources/list`               | Bis zu 100 Einträge direkt unter der konfigurierten Wurzel. |
| `resources/templates/list`     | Ein URI-Template für beliebige absolute Pfade.             |
| `resources/read`               | Ein einzelnes `axross://<pfad>` holen.                    |

Text-ähnliche mimes liefern `{uri, mimeType, text}`; alles andere
(oder eine `.txt`, deren Bytes kein gültiges UTF-8 sind) fällt
zurück auf `{uri, mimeType: octet-stream, blob: b64(bytes)}`.

### Capability: Logging

Beide Transporte verdrahten genau einen `_LogForwarder` pro Server
(stdio schreibt nach stdout; HTTP routet jeden Record in den SSE-Stream
der Session, in der er entstand). Ausgewählte Log-Records werden als
`notifications/message`-Frames an den Client weitergeleitet. Nur die
Logger `core.mcp_server` und `core.mcp_server.audit` werden
weitergeleitet — fremdes Backend-Chatter leckt nicht raus. Der
Default-Schwellenwert ist `warning`; Audit-Zeilen sind `info` und
erreichen den Client erst, wenn er das Level senkt.

Client kann den Schwellenwert live regeln:

```json
{"jsonrpc": "2.0", "id": 1, "method": "logging/setLevel",
 "params": {"level": "debug"}}
```

Akzeptiert: `debug`, `info`, `notice`, `warning`, `error`,
`critical`, `alert`, `emergency`.

**Auf HTTP gilt das Level serverweit, nicht pro Session:** es gibt
einen gemeinsamen Forwarder, also ändert ein `logging/setLevel` aus
irgendeiner Session den Schwellenwert für alle Sessions dieses
Servers. Das Routing bleibt pro Session — eine Session bekommt nur
ihre eigenen Records —, aber ein Client kann die Streams aller
Clients gesprächiger oder stiller machen.

### Weitere Methoden

| Methode         | Zweck                                                                   |
|-----------------|-------------------------------------------------------------------------|
| `initialize`    | Handshake; liefert Protokoll-Version, Server-Info und Capabilities.    |
| `ping`          | MCP-Liveness-Check; leeres Result.                                      |
| `tools/list`    | Der Tool-Katalog mit Input-Schemas.                                     |
| `tools/call`    | Ein Tool synchron ausführen.                                            |
| `tasks/start`   | **Axross-Erweiterung, nicht Teil von MCP.** Startet ein Tool im Hintergrund; liefert `task_id`. Gleicher Schema-Check, gleiches Rate-Limit und gleicher Tool-Timeout wie `tools/call`; höchstens 8 laufende Tasks pro Scope (`MAX_RUNNING_TASKS_PER_SCOPE`). |
| `tasks/status`  | Status, letzter Progress und — nach Ende — Result oder Fehler.          |
| `tasks/cancel`  | Laufenden Task abbrechen.                                               |
| `tasks/list`    | Kurze Übersicht der Tasks des Scopes.                                   |

Tasks sind auf HTTP pro Session gescoped, auf stdio serverweit.
Beendete Tasks bleiben eine Stunde erhalten (`TASK_RETENTION_SECONDS`);
hält ein Scope mehr als 100 Tasks (`MAX_TASKS_PER_SCOPE`), werden die
ältesten beendeten früher entfernt. Results über 16 MiB werden zum
Fehler.

---

## 3. Progress, Cancel, Timeouts

### 3.1 Progress

Wenn `_meta.progressToken` auf einem `tools/call` mitgegeben wird,
sendet der Server `notifications/progress`-Frames aus den Handlern,
die das unterstützen: `walk` (besuchte Einträge), `grep` (gescannte
Dateien), `checksum` (gehashte Bytes, nur im Streaming-Fallback),
`recursive_checksum` (gehashte Dateien) und `bulk_copy` (kopierte
Dateien) sowie die langen Gruppen-Tools aus §9 (`metadata_read` /
`metadata_export` auf Ordnern, `metadata_remove`, `file_type_scan`,
`duplicates_scan`, `duplicates_dedupe`, `index_build`, `pack`,
`archive_extract`, `transfer_copy`). In einem `tasks/start`-Task melden dieselben Tools Progress
mit der `task_id` als Token. Auf stdio gehen die Frames durch denselben
Lock wie jede Response nach stdout, Frames aus verschiedenen Threads
verschachteln sich also nie innerhalb einer Zeile; auf HTTP landen sie
pro Session in einer Queue und werden über den SSE-Stream
(`GET /messages`) ausgeliefert.

### 3.2 Cancellation

Clients senden `notifications/cancelled` mit `requestId`. Ein
Cancel-Register (auf HTTP pro Session, auf stdio pro Server) setzt
ein `threading.Event`, das jeder länger laufende Handler per
`ctx.check_cancel()` pollt. Der Handler raised `CancelledError`, der
Dispatcher antwortet -32603 mit `data.type = "CancelledError"`, der
Client verwirft die Response.

**Bekannte Einschränkung — stdio:** die stdio-Loop ist
single-threaded. Solange ein synchroner `tools/call` läuft, wartet die
Loop auf ihn und liest keinen weiteren Input; ein
`notifications/cancelled` für diesen Call wird also erst gelesen, wenn
er fertig ist. Auf stdio stoppt einen synchronen `tools/call` daher
nur sein Timeout (§3.3). Was auf stdio abbrechbar sein muss, läuft
über `tasks/start` + `tasks/cancel` — das funktioniert auf beiden
Transporten. Auf HTTP läuft jeder Request in einem eigenen Thread,
dort erreicht `notifications/cancelled` auch einen laufenden Call.

### 3.3 Timeouts

Jedes Tool hat einen Wall-Clock-Deckel:

| Klasse (`timeout_class`) | Timeout | Tools                                                                      |
|-------------|---------|----------------------------------------------------------------------------|
| `quick`     | 15 s    | `stat`, `read_file`, `list_dir`, `search`, `list_versions`, `open_version_read` und jedes Tool ohne eigenen Eintrag — auch die Script-Tools außer `script_run` |
| `walk`      | 60 s    | `walk`, `grep`                                                             |
| `preview`   | 30 s    | `preview`                                                                  |
| `write`     | 30 s    | `write_file`, `mkdir`, `remove`, `rename`, `copy`, `symlink`, `hardlink`, `chmod` |
| `stream`    | 300 s   | `checksum`, `recursive_checksum`, `bulk_copy`                              |
| `long`      | 1800 s  | Ganzbaum-Jobs der Gruppen (§9): `duplicates_scan`, `duplicates_dedupe`, `index_build`, `pack`, `archive_extract`, `transfer_copy`, `transfer_move`, `metadata_remove` |
| `script`    | 610 s   | `script_run`. Es stoppt sein Kind schon bei seinem eigenen `timeout_s` (Default 60 s, höchstens 600 s); die Klasse rechnet Kill-Grace und Output-Drain dazu, die Deadline sichert also nur ab |

Die Klasse jedes Gruppen-Tools steht im Manifest (§9.7). Ein
`tasks/start`-Task bekommt denselben Timeout wie sein Tool.

Zwei parallele Mechanismen decken den Deadline ab:

1. Ein `threading.Timer` kippt das Cancel-Event des Handlers, wenn
   die Deadline abläuft. Handler die `ctx.check_cancel()` pollen
   (`walk`, `grep`) beenden sich beim nächsten Tick sauber.
2. Der Dispatcher lässt den Handler in einem dedizierten Worker-
   Thread laufen und joined mit demselben Timeout. Wenn der Handler
   in einem einzigen blockierenden IO-Call festhängt
   (`backend.read_file` auf riesigem Blob; `backend.checksum` beim
   Stream-Hashing über langsames SFTP), gibt der Join die
   Kontrolle an den Dispatcher zurück — der **Client** wird
   entblockt und erhält `ERR_TIMEOUT` — obwohl der Hintergrund-
   Thread möglicherweise weiterläuft und seinen Seiteneffekt
   irgendwann fertigstellt.

Die Response im Hard-Stop-Fall trägt `data.hard_stop = true`
damit Clients erkennen, dass der Server das Warten aufgegeben hat
(statt eines kooperativen Cancels, bei dem der Handler mittendrin
sauber abgebrochen hat).

Error-Code **-32002** mit `data.type = "TimeoutError"` in beiden
Fällen, unterscheidbar vom Client-initiierten Cancel (-32603,
`CancelledError`).

**Ehrliche Einschränkung:** der Hard-Stop bricht den Backend-Call
*nicht* ab. Ein `write_file`, das in Timeout läuft, kann trotzdem
Bytes auf dem Remote landen lassen. Ein `remove` in Timeout kann
den Pfad trotzdem löschen. Der Client sieht eine Timeout-Antwort;
der Operator sollte vom unbekannten Zustand der Operation
ausgehen und entweder re-check machen oder mit einer geeigneten
Idempotency-Key neu absetzen. Beliebige blockierende IO kann
nicht sicher unterbrochen werden; wer das Gegenteil behauptet,
lügt oder forkt.

---

## 4. Rate-Limit

Standard an: 30-Token-Burst, 1 Token/Sek. Refill (60 Calls pro
Minute im Dauerbetrieb). `tools/call` und `tasks/start` ziehen aus
demselben Bucket (ein Bucket pro Server auf stdio, einer pro Session
auf HTTP); `tools/list`, `initialize`, `ping`, `resources/*`,
`tasks/status|cancel|list` und `logging/setLevel` bleiben frei.

Ablehnung: -32001 mit `data.type = "RateLimitError"`. Ein
`tasks/start` über dem Cap laufender Tasks ist ebenfalls -32001, mit
`data.type = "TaskLimitError"`.

Einstellbar über `ServerConfig.rate_burst` /
`rate_refill_per_sec`, deaktivierbar mit
`rate_limit_enabled = False`.

---

## 5. Multi-Backend

Von der CLI aus führt die Gruppe `remote` (§9.5) zu weiteren Backends:
`remote_open` macht aus einem gespeicherten Connection-Profil das
Backend `profile:<name>`, und das Default-`LocalFS` bekommt die ID
`local`. Wer den Server aus Python einbettet, kann zusätzlich ein Dict
`{id: backend}` als `ServerConfig.backends` (oder
`HTTPServerConfig.backends`) übergeben. In beiden Fällen:

 - Ein read-only `list_backends`-Tool liefert
   `[{id, class, name, is_default, remote}]` (geöffnete Profile
   zusätzlich `profile`, `protocol`, `production`), damit der LLM sie
   aufzählen kann.
 - Jedes andere Tool bekommt im inputSchema ein optionales
   `backend: string`-Feld (Tools, die ihre Backends selbst benennen wie
   `transfer_copy`, oder gar keins berühren, nicht). Ohne Angabe →
   Default; mit ID → Routing. Unbekannte IDs landen auf -32602.
 - Backends einer statischen Library-Registry sind wie das Default-
   Backend an die MCP-Root gebunden; mit `remote_open` geöffnete
   Profile nicht (§9.5).

Beispiel:

```python
from core.mcp_server import ServerConfig, serve
from core.local_fs import LocalFS
from core.s3_client import S3Backend

serve(ServerConfig(
    backend=LocalFS(),           # Default
    backends={
        "home": LocalFS(),
        "bucket": S3Backend(…),
    },
))
```

---

## 6. HTTP-Session-Lebenszyklus

```
┌──────────┐                                 ┌──────────┐
│  Client  │  POST /messages  {initialize}   │  Server  │
│          │ ──────────────────────────────> │          │
│          │                                 │          │
│          │  200  Mcp-Session-Id: <uuid>    │          │
│          │ <────────────────────────────── │          │
│          │                                 │          │
│          │  GET  /messages  (SSE)          │          │
│          │       Mcp-Session-Id: <uuid>    │          │
│          │ ──────────────────────────────> │          │
│          │                                 │          │
│          │   data: notifications/progress  │          │
│          │   data: notifications/message   │          │
│          │ <────────────────────────────── │          │
│          │                                 │          │
│          │  POST /messages  {tools/call}   │          │
│          │       Mcp-Session-Id: <uuid>    │          │
│          │ ──────────────────────────────> │          │
│          │                                 │          │
│          │  DELETE /messages               │          │
│          │       Mcp-Session-Id: <uuid>    │          │
└──────────┘                                 └──────────┘
```

 - Idle-Sessions werden nach 30 Minuten geräumt (einstellbar).
 - Queue-Deckel pro Session: 10 000 Notifications. Ein Client,
   der seinen SSE-Stream nie leert, lässt den Server nicht
   wachsen — Überschuss fällt raus, Warnung im Log.
 - SSE-Keepalive: Kommentar-Zeile alle 15 s, damit Idle-Killer-
   Proxys den Stream nicht abschneiden.

---

## 7. Security-Härtung

Jeder Eintrag hier ist ein expliziter Guard gegen ein durchdachtes
Red-Team-Szenario. Die MCP-Tests liegen in `tests/test_mcp_*.py`:

| Datei | Deckt ab |
|-------|----------|
| `tests/test_mcp_error_redaction.py` | Secrets in Backend-Fehlertexten werden redigiert (tools/call, Tasks, recursive_checksum). |
| `tests/test_mcp_http_hardening.py` | DNS-Rebinding (Host/Origin), Session-Cap und Idle-Eviction, kaputte Params/IDs, unvollständige TLS-Flags, idle TCP-Client vs. accept. |
| `tests/test_mcp_http_sse_lifecycle.py` | Ein SSE-Stream pro Session, DELETE/Idle-Eviction beenden ihn, Replay beim Reconnect. |
| `tests/test_mcp_search_root.py` | `search` liefert nie indizierte Pfade außerhalb der Root. |
| `tests/test_mcp_tasks_limits.py` | `tasks/start`-Rate-Limit, Cap laufender Tasks, Tool-Timeout. |
| `tests/test_mcp_write_root.py` | `--mcp-write` braucht `--mcp-root`; `--mcp-allow-scripts` mit `--mcp-http` verweigert. |
| `tests/test_mcp_script_audit.py` | Script-Tools schreiben den Audit-Trail, ohne Quelltext oder Ausgabe. |
| `tests/test_mcp_script_run_child.py` | `script_run` im Kindprozess: Timeout und Gruppen-Kill, kein Enkelprozess bleibt, `input()` liest nie den stdio-Stream, Cancel, Output-Cap, Argumentprüfung, strukturierte Antwort. |
| `tests/test_mcp_stdio_write_lock.py` | Gleichzeitige stdio-Writer verschachteln sich nie innerhalb einer Zeile. |
| `tests/test_mcp_tools_flag.py` | Parsing von `--mcp-tools` / `AXROSS_MCP_TOOLS`, Exit 2 bei unbekannter Gruppe, Default-Oberfläche unverändert, read-only `all` ohne mutierendes Tool. |
| `tests/test_mcp_group_metadata_filetype.py` | Gruppen `metadata` und `filetype`: Root-Escapes, Symlinks, kein Überschreiben, Audit. |
| `tests/test_mcp_group_duplicates_index.py` | Gruppen `duplicates` und `index`: Index-Zeilen außerhalb der Root tauchen nie auf, Re-Check vor dem Dedupe, Trash unter der Root. |
| `tests/test_mcp_group_packer_archive.py` | Gruppen `packer` und `archive`: Zip-Slip, Passwort nie im Log, Cancel hinterlässt nichts. |
| `tests/test_mcp_group_crypto.py` | Gruppe `crypto`: Passphrase nie in Antworten, Fehlern oder Audit; kein Überschreiben. |
| `tests/test_mcp_group_remote_transfer.py` | Gruppen `remote` und `transfer`: keine Secrets in der Liste, keine Prompts, Host-Keys, Production-Profile, Scoping pro Session, resumable Copy. |
| `tests/test_mcp_group_extensions.py` | Gruppe `extensions`: das Auflisten importiert nie eine Extension. |
| `tests/test_mcp_manifest.py` | `--mcp-list-tools` und das eingecheckte `docs/mcp-tools.json` bleiben synchron mit dem Code. |
| `tests/test_mcp_groups_e2e.py` | Der echte Server über stdio und HTTP mit `--mcp-tools all`: ein Call pro Gruppe, `tasks/start` + `tasks/cancel`. |
| `tests/test_fuzz_mcp.py` | Feindliche Requests gegen Dispatcher, beide Transporte und jedes Gruppen-Tool. |

§7.1, §7.5, §7.7, §7.8, §7.11 und der Hard-Stop aus §7.4 haben in
diesem Satz noch keinen eigenen Test.

### 7.0 Script-Tools sind nicht auf die Root begrenzt

Die MCP-Root (§7.1) begrenzt nur die Datei-Tools. Die Script-Tools
(`--mcp-allow-scripts`, nur stdio) führen beliebigen Python-Code als
Server-User aus (in einem Kindprozess, ein Skript kann den Server also
weder blockieren noch seinen Protokoll-Stream lesen) und sind auf gar
nichts begrenzt — siehe §2.

### 7.1 Filesystem-Escape — Symlink-auflösender Root-Check

`_enforce_root` fährt zwei Pässe: erst `abspath` für
`..`/`.`-Kollaps, dann `realpath` um Symlinks aufzulösen und
erneut gegen die Root zu prüfen. Ohne den zweiten Pass könnte ein
Symlink unter der Root (extern oder vom LLM selbst über das
`symlink`-Write-Tool angelegt) nach `/` zeigen und
`write_file("/root/escape/etc/cron.d/evil")` durchlassen. Jetzt
`PermissionError`, beantwortet als -32603 mit
`data.type = "PermissionError"` und einer Message, die die Root nennt.
Die Capability-Gruppen (§9) schicken jeden lokalen Pfad durch
denselben Check.

### 7.2 Log-Demux — keine Cross-Session-Leckage

Genau **ein** `_LogForwarder` pro Server, an den
`core.mcp_server`-Logger-Baum gehängt. Ein
`contextvars.ContextVar`, das der Dispatcher beim Eintritt setzt,
sagt `emit()` welche Session-Queue das Record empfängt. Session
A's SSE-Stream bekommt nie Log-Frames aus Session B's Tool-Call.
Das frühere "ein Forwarder pro Session"-Design leckte still quer
weil Python-Logging additiv ist.

### 7.3 Session-Forwarder-Unregister beim Drop

`_SessionRegistry.drop` und `evict_idle` entfernen den Sink aus
dem Forwarder bevor die Session verworfen wird. Ohne diesen
Schritt füllte der Forwarder die tote Queue weiter bis
`queue.Full` warnte, was den Forwarder erneut feuerte, der in
jede tote Queue schrieb — Log-Verstärkungs-Schleife. Jetzt: Sink
geht mit der Session.

### 7.4 Hard-Stop-Timeout

Siehe §3.3. Kurz: Handler laufen in einem dedizierten Worker-
Thread mit `join(timeout)`. Hängt der Worker in blockierendem
Backend-IO fest, gibt der Dispatcher dennoch `ERR_TIMEOUT` mit
`data.hard_stop = true` zurück; der Worker läuft als Zombie
weiter (blockierende IO kann nicht sicher unterbrochen werden),
aber der Client ist entblockt.

### 7.5 Grep-ReDoS-Preflight

Vor `re.compile` wird das Pattern geprüft auf:

 - Länge-Cap (512 Zeichen).
 - Nested-Unbounded-Quantifier-Heuristik (`(…+)+`, `(…*)*`, usw.)

Catastrophic-Backtracking-Patterns werden mit -32602 und
actionable Message abgelehnt. Nicht abgedeckt: alternation-
basiertes Backtracking (`(a|a)+`) — dafür ist der 60-s-Hard-Stop
aus §3.3 der Backstop.

### 7.6 Per-Session-Rate-Limiter

Jede `_HttpSession` hat ihren eigenen Token-Bucket. Ein feindlicher
Client drainiert seine eigenen Tokens ohne andere Sessions zu
treffen. Konfig: `rate_burst`, `rate_refill_per_sec` auf
`HTTPServerConfig` (Defaults 30-Token-Burst, 1 Token/Sek Refill).

### 7.7 Per-IP-HTTP-Edge-Cap

Vor Body-Parsing / Session-Lookup / Dispatch konsultieren `do_GET`
/ `do_POST` / `do_DELETE` einen Per-Source-IP-Bucket
(`_PerIPRateLimiter`). Ein Flood an malformed oder
unauthentifizierten POSTs kann keine CPU in der JSON-RPC-Pipeline
verbrennen. `/health` ist exempt damit Reverse-Proxy-Probes sich
nicht selbst aushungern. Bucket-Einträge > 5 min idle werden
geGC't. Konfig: `http_ip_burst`, `http_ip_refill_per_sec`,
`http_ip_rate_enabled` (Defaults 120 Burst, 60 req/s).

### 7.8 Session-ID ans Client-Cert-Fingerprint gebunden

Bei `initialize` snapshottet der Server SHA-256 des DER-Zertifikats
des Peers auf `_HttpSession.cert_fingerprint`. Jeder folgende POST
/ DELETE / SSE derriviert den Fingerprint erneut und lehnt bei
Mismatch mit 403 ab. Ein geleakter `Mcp-Session-Id`-Header ist
wertlos für jemanden mit anderem Cert. Non-TLS-Sessions (Loopback)
haben keinen Fingerprint und keine Bindung — explizite Trade-Off
für lokale-Dev-Ergonomie.

### 7.9 Audit "attempt" vor dem Backend-Call

Jedes Schreib-Tool — und `script_write`, `script_delete`,
`script_run` — emittet `outcome=attempt` VOR dem Backend-Aufruf (bzw.
dem Skript), dann `outcome=ok` oder `outcome=refused` danach. Ein
Prozess-Crash zwischen erfolgreichem Backend-Call und der "ok"-
Zeile hinterlässt trotzdem Spur: Operatoren sehen "attempt" ohne
matching Outcome und wissen dass der Zustand unbekannt ist.

### 7.10 Resource-URI-Decode + Query/Fragment-Strip

`_parse_resource_uri` dekodiert Prozent-kodierte Bytes
(`%2e%2e%2f` → `../`) bevor `_enforce_root` den Pfad sieht —
kodierte Traversal-Versuche werden vom realpath-Pass aus §7.1
gefangen. Query-Strings und Fragments werden entfernt damit sie
nicht in Backend-spezifische Pfade leaken.

### 7.11 `list_backends` — eindeutiger Default

Wenn ein Operator dieselbe Backend-Instanz unter zwei IDs
registriert, beansprucht nur die erste `is_default = true`. Vorher
sagte der Identity-Check beide seien Default, was Clients beim
Default-Pick verwirrte.

---

## 8. Error-Codes

| Code     | Name                    | Wofür                                                |
|----------|-------------------------|------------------------------------------------------|
| -32700   | PARSE                   | JSON-Decode fehlgeschlagen.                          |
| -32600   | INVALID_REQUEST         | Method fehlt, Body ist kein Objekt.                  |
| -32601   | METHOD_NOT_FOUND        | Method/Tool unbekannt oder Capability deaktiviert.   |
| -32602   | INVALID_PARAMS          | jsonschema-Fehler, ValueError im Handler, bad URI.   |
| -32603   | INTERNAL                | Andere Exception als ValueError/TypeError im Handler (OSError, `PermissionError` eines Root-Escapes, ein verweigertes Profil, …; `data.type` nennt sie), oder Cancel. |
| **-32001** | **RATE_LIMITED**      | `tools/call` / `tasks/start` gedrosselt, oder Cap laufender Tasks erreicht. |
| **-32002** | **TIMEOUT**           | Tool hat seinen Wall-Clock-Timeout gerissen.         |

---

## 9. Capability-Gruppen (`--mcp-tools`)

Ohne `--mcp-tools` bietet der Server genau die Tools aus §2.
`--mcp-tools GRUPPE[,GRUPPE...]` (wiederholbar; `AXROSS_MCP_TOOLS` wird
dazu vereinigt) fügt Gruppen hinzu; `all` fügt jede Gruppe hinzu. Eine
unbekannte Gruppe beendet den Start mit Exit-Code 2 und einer
stderr-Zeile mit den gültigen Gruppen. Das Flag heißt `--mcp-tools`,
nicht `--backend`: "Backend" ist in axross schon ein Protokoll-Backend,
und Remote-Backends sind selbst eine der Gruppen.

### 9.1 Typische Setups

```bash
# Read-only: Datei-Tools plus Metadaten lesen und Dateitypen
axross --mcp-server --mcp-tools metadata,filetype

# Packen und Entpacken in ~/data (mutierende Tools brauchen --mcp-write,
# und das braucht --mcp-root)
axross --mcp-server --mcp-write --mcp-root ~/data --mcp-tools packer,archive

# Search-Index aufbauen und Duplikate finden, read-only
axross --mcp-server --mcp-root ~/photos --mcp-tools index,duplicates

# Gespeicherte Profile als weitere Backends, Kopieren zwischen ihnen und ~/data
axross --mcp-server --mcp-write --mcp-root ~/data --mcp-tools remote,transfer

# Alles, über Loopback-HTTP
axross --mcp-server --mcp-http 127.0.0.1:7331 --mcp-write --mcp-root ~/data --mcp-tools all
# ... oder mit Environment-Variablen
AXROSS_MCP=1 AXROSS_MCP_WRITE=1 AXROSS_MCP_TOOLS=all axross --mcp-root ~/data
```

### 9.2 Gruppen und Tools

Read-only-Tools einer Gruppe brauchen nur `--mcp-tools <gruppe>`;
mutierende werden ohne `--mcp-write` gar nicht registriert (und
`--mcp-write` wird ohne `--mcp-root` verweigert).

| Gruppe | Tool | Art | Nötige Flags | Timeout-Klasse |
|--------|------|-----|--------------|----------------|
| `metadata` | `metadata_read` | read-only | `--mcp-tools metadata` | stream |
| `metadata` | `metadata_export` | read-only | `--mcp-tools metadata` | stream |
| `metadata` | `metadata_export_file` | mutating | `--mcp-tools metadata` `--mcp-write` `--mcp-root DIR` | stream |
| `metadata` | `metadata_remove` | mutating | `--mcp-tools metadata` `--mcp-write` `--mcp-root DIR` | long |
| `duplicates` | `duplicates_scan` | read-only | `--mcp-tools duplicates` | long |
| `duplicates` | `duplicates_scans` | read-only | `--mcp-tools duplicates` | quick |
| `duplicates` | `duplicates_groups` | read-only | `--mcp-tools duplicates` | quick |
| `duplicates` | `duplicates_dedupe` | mutating | `--mcp-tools duplicates` `--mcp-write` `--mcp-root DIR` | long |
| `packer` | `pack_formats` | read-only | `--mcp-tools packer` | quick |
| `packer` | `pack` | mutating | `--mcp-tools packer` `--mcp-write` `--mcp-root DIR` | long |
| `archive` | `archive_list` | read-only | `--mcp-tools archive` | walk |
| `archive` | `archive_extract` | mutating | `--mcp-tools archive` `--mcp-write` `--mcp-root DIR` | long |
| `crypto` | `encrypt` | mutating | `--mcp-tools crypto` `--mcp-write` `--mcp-root DIR` | stream |
| `crypto` | `decrypt` | mutating | `--mcp-tools crypto` `--mcp-write` `--mcp-root DIR` | stream |
| `index` | `index_build` | read-only | `--mcp-tools index` | long |
| `filetype` | `file_type` | read-only | `--mcp-tools filetype` | quick |
| `filetype` | `file_type_scan` | read-only | `--mcp-tools filetype` | stream |
| `transfer` | `transfer_copy` | mutating | `--mcp-tools transfer` `--mcp-write` `--mcp-root DIR` | long |
| `transfer` | `transfer_move` | mutating | `--mcp-tools transfer` `--mcp-write` `--mcp-root DIR` | long |
| `remote` | `remote_profiles` | read-only | `--mcp-tools remote` | quick |
| `remote` | `remote_open` | read-only | `--mcp-tools remote` | walk |
| `remote` | `remote_close` | read-only | `--mcp-tools remote` | quick |
| `remote` | `list_backends` | read-only | `--mcp-tools remote` | quick |
| `extensions` | `extensions_list` | read-only | `--mcp-tools extensions` | quick |
| `extensions` | `extensions_info` | read-only | `--mcp-tools extensions` | quick |

"Read-only" heißt: keine Datei des Users ändert sich. `duplicates_scan`
und `index_build` schreiben sehr wohl in axross' eigene Indizes (den
des Duplicate Finders und den der Metadaten-Suche, unter
`~/.local/share/axross/`), dieselben, die die GUI benutzt;
`remote_open` öffnet eine Netzwerkverbindung.

Was jede Gruppe tut:

* **metadata** — Metadaten von Bildern (EXIF/XMP/IPTC; JPEG, PNG,
  WebP, GIF, TIFF), Office-Dateien, PDF und Audio/Video (ffprobe) einer
  Datei oder eines Ordners lesen; als JSON oder CSV exportieren, als
  Text oder in eine neue Datei; entfernen, indem neben jeder Datei eine
  bereinigte Kopie entsteht (`photo.jpg` → `photo.clean.jpg`). Das
  Entfernen in place gibt es über MCP nicht: es legt das Original in
  den axross-Trash des Home-Verzeichnisses, außerhalb der MCP-Root.
* **duplicates** — der Duplicate Finder: einen Ordner in den
  Duplikat-Index hashen, Scans und Duplikat-Gruppen auflisten (jede
  Kopie im angefragten Ordner und in der Root — Zeilen, die die GUI
  anderswo indexiert hat, tauchen nie auf), und Dedupe: die älteste
  Kopie jeder Gruppe behalten und die anderen nach
  `<root>/.axross-trash` verschieben, nachdem jede Kopie auf der Platte
  erneut geprüft wurde. Ein Dry Run, solange nicht `dry_run=false`.
* **packer** — zip, tar.gz / tar.zst / tar.xz / tar.bz2, 7z (mit
  Passwort: AES-256, auch die Dateiliste verschlüsselt) und
  Einzeldatei-gz / zst / xz / bz2. ZIP hat keine Passwort-Option
  (ZipCrypto ist gebrochen).
* **archive** — Einträge auflisten, ohne zu entpacken; in einen frischen
  Ordner entpacken (`x.zip` → `x`, `x-1`, …) mit den Guards aus
  `core.archive` gegen Zip-Slip, Links, Größe (1 GiB), Anzahl
  (10.000 Einträge) und Kompressionsrate (100). Nur lokale Archive:
  ein Remote-Archiv zuerst mit `transfer_copy` holen.
* **crypto** — das axross-`.axenc`-Format der GUI (AES-256-GCM,
  PBKDF2-SHA256 mit 200.000 Iterationen, höchstens 1 GiB pro Datei).
* **index** — den Offline-Metadaten-Index füllen, den `search` liest,
  damit `search` ohne GUI Daten hat; `prune` entfernt Zeilen
  verschwundener Dateien.
* **filetype** — Dateien am Inhalt erkennen (Magic Bytes, derselbe
  Detektor wie in der GUI) und eine lügende Endung melden.
* **transfer** — Dateien oder Bäume kopieren oder eine Datei
  verschieben, zwischen zwei beliebigen Backends (`local` und den mit
  `remote_open` geöffneten Profilen); `resumable=true` kopiert in
  4-MiB-Segmenten mit einem Manifest unter
  `$XDG_STATE_HOME/axross/resume/`, sodass ein unterbrochener Copy
  dort weitermacht, wo er stand, wenn er mit denselben Argumenten
  erneut aufgerufen wird.
* **remote** — siehe §9.5.
* **extensions** — installierte Extensions auflisten, ob eingeschaltet
  oder nicht. Keine kann über MCP laufen: `activate(api)` einer
  Extension bekommt die Qt-`ExtensionAPI` und kann nur Menü-Actions,
  Kontext-Actions und Docks hinzufügen — es gibt keine Headless-Action
  zum Aufrufen, und das Laden führt ihren Code mit den Rechten des
  Users aus.

### 9.3 Sicherheitsmodell

Jeder Guard des Basis-Servers bleibt; die Gruppen legen Schichten
darauf:

1. **Opt-in pro Gruppe.** Kein Flag, keine Gruppe.
2. **`--mcp-write` pro mutierendem Tool**, das selbst `--mcp-root`
   verlangt. Ohne es gibt es die mutierenden Tools nicht.
3. **Root-Confinement.** Jeder lokale Pfad läuft durch den
   symlink-auflösenden Root-Check aus §7.1; Walks überspringen
   Symlinks und Einträge, die außerhalb der Root landen.
4. **Nichts wird überschrieben.** Archive, entpackte Ordner, ver- und
   entschlüsselte Dateien, Metadaten-Exporte und bereinigte Kopien
   bekommen einen frischen Namen (`bundle (2).zip`, `x-1`,
   `a (2).txt`, `photo.clean (1).jpg`); Dateien, die axross selbst
   anlegt (Exporte, entschlüsselter Klartext, Ciphertext), haben
   Mode 0600.
5. **Audit.** Jedes mutierende Gruppen-Tool schreibt `attempt` und dann
   `ok` oder `refused` nach `core.mcp_server.audit` — Pfade, Namen,
   Anzahlen und Größen, nie Dateiinhalte, Passphrasen oder Passwörter.
6. **Secrets bleiben aus den Antworten.** Passphrasen und das
   7z-Passwort sind `writeOnly`-Schema-Felder, die in keinem Ergebnis,
   keinem Fehler und keiner Audit-Zeile auftauchen; `remote_profiles`
   listet Profile über eine Feld-Allowlist (kein Passwort, Key, Token,
   SAS oder Connection-String).
7. **Begrenzte Arbeit.** Jede Liste hat einen Cap (`max_files`,
   `max_groups`, `max_entries`, …, `truncated=true` beim Kappen); lange
   Jobs melden Progress, prüfen Cancellation und laufen unter
   `tasks/start`; Ergebnisse über 16 MiB werden wie bei jedem Tool
   abgelehnt.

### 9.4 Security-Mode `paranoid`

Keine Gruppe wird als Ganzes verweigert. Was der Mode `paranoid` in der
GUI und im Scripting blockiert, bleibt hier blockiert:

* `remote_open` verweigert die Legacy-Protokolle (`ftp`, `telnet`,
  `cisco-telnet`, `tftp`, `gopher`, `nntp`, `pop3`, `rsh`);
  `remote_profiles` meldet sie als `openable: false`.
* `metadata_*` starten kein ffprobe / ffmpeg auf Audio und Video (der
  Report nennt den Grund), genau wie in der GUI.
* `extensions_list` meldet `allowed: false` und jede Extension
  `active: false`.
* Die Script-Tools bleiben verweigert (`--mcp-allow-scripts` endet mit
  Exit 2).

### 9.5 Remote-Profile

* `remote_profiles` listet die gespeicherten Profile (Name, Protokoll,
  Host, Port, User, Auth-Typ, ob ein Passwort gespeichert ist,
  Production-Flag) und sagt pro Profil, ob `remote_open` es verweigern
  würde.
* `remote_open(profile)` verbindet über den Connection-Manager der GUI
  und registriert das Backend `profile:<name>`; jedes andere Tool
  erreicht es mit `backend: "profile:<name>"`. `remote_close` gibt es
  wieder frei.
* **Credentials kommen aus dem Keyring**, und nur, wenn das Profil sein
  Passwort speichert ("Store password" im Connection-Dialog). Der
  MCP-Server fragt nie nach: ein Profil, das ein nicht gespeichertes
  Passwort braucht, ein SSH-Host-Key, der noch nicht in
  `~/.ssh/known_hosts` steht, oder ein Browser-Login (OneDrive,
  SharePoint, Google Drive, Dropbox) wird mit einem Fehler verweigert,
  der das sagt. So ein Profil einmal in der GUI verbinden.
* **`--mcp-root` gilt nicht für Remote-Pfade**: ein Profil erreicht,
  was sein Server diesem Account erlaubt. Ein Profil, das auf das
  lokale Dateisystem führt, wird verweigert, weil es die Root umgehen
  würde.
* **Production-Profile sind über MCP read-only**: der Countdown der GUI
  vor einer destruktiven Operation lässt sich nicht anzeigen, also wird
  jede Mutation auf ihnen verweigert.
* Geöffnete Profile gelten pro Session auf HTTP (ein Client sieht nie
  die eines anderen), höchstens 8 pro Session; endet eine HTTP-Session
  (`DELETE` oder Idle-Eviction), werden ihre Verbindungen geschlossen.
* Beliebige URLs zu öffnen wird nicht angeboten: eine vom LLM gewählte
  URL könnte den Server auf `sftp://localhost` mit dem SSH-Agent des
  Users richten oder auf eine lokale Datei (`sqlite://`,
  `git+local://`) und so `--mcp-root` umgehen. Ein gespeichertes Profil
  ist die eigene Entscheidung des Users.

### 9.6 Ein JSON-RPC-Call pro Gruppe

```json
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"metadata_read","arguments":{"path":"/home/me/data/IMG_0001.jpg"}}}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"duplicates_scan","arguments":{"path":"/home/me/data/photos"}}}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"pack","arguments":{"folder":"/home/me/data","names":["report","notes.txt"],"archive_name":"bundle","format":"7z","password":"…"}}}
{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"archive_extract","arguments":{"path":"/home/me/data/bundle.zip"}}}
{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"encrypt","arguments":{"path":"/home/me/data/notes.txt","passphrase":"…"}}}
{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"index_build","arguments":{"path":"/home/me/data"}}}
{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"file_type_scan","arguments":{"path":"/home/me/data/inbox","mismatches_only":true}}}
{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"transfer_copy","arguments":{"src":"/home/me/data/report","dst_backend":"profile:nas","dst":"/backup/report","resumable":true}}}
{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"remote_open","arguments":{"profile":"nas"}}}
{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"extensions_list","arguments":{}}}
```

Ein langer Job im Hintergrund, auf beiden Transporten abbrechbar:

```json
{"jsonrpc":"2.0","id":11,"method":"tasks/start","params":{"name":"duplicates_scan","arguments":{"path":"/home/me/data"}}}
{"jsonrpc":"2.0","id":12,"method":"tasks/status","params":{"task_id":"<task_id>"}}
{"jsonrpc":"2.0","id":13,"method":"tasks/cancel","params":{"task_id":"<task_id>"}}
```

### 9.7 Maschinenlesbares Manifest

`axross --mcp-list-tools` nimmt dieselben Flags `--mcp-tools`,
`--mcp-write` und `--mcp-allow-scripts` (und `AXROSS_MCP_*`-Variablen)
wie der Server, startet nichts und gibt JSON aus: pro Tool `name`,
`group`, `mutating`, `required_flags`, `transports`, `timeout_class`,
`timeout_seconds`, `description` und `input_schema`, dazu die
Gruppen-Tabelle und die Timeout-Klassen (Aufbau wie im Beispiel in
[MCP.md §9.7](MCP.md)).

Jedes Schema nennt Typen, Pflichtfelder, Enums, Defaults und Grenzen,
und Gruppen-Tools lehnen unbekannte Argumente ab
(`additionalProperties: false`). [`mcp-tools.json`](mcp-tools.json) ist
das Manifest für `--mcp-tools all --mcp-write --mcp-allow-scripts`;
`tests/test_mcp_manifest.py` schlägt fehl, sobald es nicht mehr zum
Code passt.
