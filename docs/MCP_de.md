# MCP-Server — ausführlich

Axross kann als [Model Context Protocol](https://modelcontextprotocol.io)
(MCP) Server laufen, sodass ein LLM-Client (Claude Desktop, Cline,
ein eigener Agent) über eine JSON-RPC-Tool-Fläche beliebige
konfigurierte Backends bedient.

Der Server spricht MCP-Protokoll-Version **2024-11-05**.

Sprachen: [English](MCP.md) · **Deutsch** · [Español](MCP_es.md)

---

## 1. Transporte

### 1.1 Stdio

```bash
# Read-only; Default-Backend ist LocalFS mit Wurzel in $HOME.
axross --mcp-server

# Per Env-Var (gleiches Verhalten):
AXROSS_MCP=1 axross

# Schreib-Tools (write_file, mkdir, remove, rename, copy, symlink,
# hardlink, chmod). Path-Traversal gekappt an einer gewählten Wurzel:
axross --mcp-server --mcp-write --mcp-root /home/ich/data
```

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

---

## 2. Tool-Oberfläche

### Read-only-Tools (immer aktiv)

| Name                 | Beschreibung                                                          |
|----------------------|-----------------------------------------------------------------------|
| `list_dir(path)`     | Verzeichniseinträge.                                                  |
| `stat(path)`         | Name, Typ, Größe, mtime.                                              |
| `read_file(path, max_bytes=)` | Base64-kodierter Inhalt; standardmäßig auf 4 MiB gekappt.     |
| `checksum(path, algorithm=)`  | Natives Fingerprint wo verfügbar (S3-ETag, sha256, md5).      |
| `search(needle, ext, min_size, max_size)` | Offline-Metadaten-Index, auf die aktive Backend-ID beschränkt. |
| `walk(path, max_depth, max_entries)`      | Begrenzte rekursive Listung; sendet `notifications/progress`. |
| `grep(pattern, path, max_depth, max_matches)` | Regex-Suche in Datei-Inhalten. Dateien >4 MiB übersprungen, max. 500 Treffer. |
| `list_versions(path)` | Metadaten pro Version — wo das Backend es unterstützt.              |
| `open_version_read(path, version_id)` | Base64-Inhalt einer bestimmten Version.                     |
| `preview(path, edge=256)` | Thumbnail eines Bildes — als MCP **image content** mit korrektem mimeType. |

### Schreib-Tools (nur bei `--mcp-write`)

| Name                              | Beschreibung                                                               |
|-----------------------------------|----------------------------------------------------------------------------|
| `write_file(path, content_b64)`   | Base64-Upload.                                                             |
| `mkdir(path)`                     | Verzeichnis anlegen.                                                       |
| `remove(path, recursive=False)`   | Löschen.                                                                   |
| `rename(src, dst)`                | Umbenennen / Verschieben.                                                  |
| `copy(src, dst)`                  | Server-seitige Kopie wo unterstützt; Stream-Fallback sonst.                |
| `symlink(target, link_path)`      | Nur Backends mit `supports_symlinks=True`.                                 |
| `hardlink(target, link_path)`     | Nur Backends mit `supports_hardlinks=True`.                                |
| `chmod(path, mode)`               | POSIX-Mode-Bits. Akzeptiert int oder Oktal-String.                         |

Jeder Schreib-Tool-Aufruf läuft zuerst durch `_enforce_root` — eine
Payload wie `/etc/passwd` wird abgewiesen, bevor irgendein IO das
Backend erreicht. Jeder Call schreibt einen Audit-Eintrag auf den
Logger `core.mcp_server.audit`, mit Tool, Ergebnis, Pfad und Größe
— niemals mit den Payload-Bytes.

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

Wenn der Server einen `_LogForwarder` verdrahtet (stdio macht das
standardmäßig; HTTP pro Session), werden ausgewählte Log-Records
als `notifications/message`-Frames an den Client weitergeleitet.
Nur der `core.mcp_server`-Logger-Baum wird weitergeleitet —
fremdes Backend-Chatter leckt nicht raus.

Client kann den Schwellenwert live regeln:

```json
{"jsonrpc": "2.0", "id": 1, "method": "logging/setLevel",
 "params": {"level": "debug"}}
```

Akzeptiert: `debug`, `info`, `notice`, `warning`, `error`,
`critical`, `alert`, `emergency`.

---

## 3. Progress, Cancel, Timeouts

### 3.1 Progress

Wenn `_meta.progressToken` auf einem `tools/call` mitgegeben wird,
sendet der Server `notifications/progress`-Frames aus Handlern,
die das unterstützen (heute `walk`, künftig weitere
Traversierungs-Tools). Auf stdio gehen die Frames direkt nach
stdout; auf HTTP landen sie pro Session in einer Queue und werden
über den SSE-Stream (`GET /messages`) ausgeliefert.

### 3.2 Cancellation

Clients senden `notifications/cancelled` mit `requestId`. Ein
Per-Session-Cancel-Register setzt ein `threading.Event`, das jeder
länger laufende Handler per `ctx.check_cancel()` pollt. Der
Handler raised `CancelledError`, der Dispatcher antwortet -32603
mit `data.type = "CancelledError"`, der Client verwirft die
Response.

### 3.3 Timeouts

Jedes Tool hat einen Wall-Clock-Deckel:

| Kategorie   | Timeout | Tools                                                                      |
|-------------|---------|----------------------------------------------------------------------------|
| Kurz        | 15 s    | `stat`, `read_file`, `list_dir`, `checksum`, `search`, `list_versions`, `open_version_read` |
| Traversal   | 60 s    | `walk`, `grep`                                                             |
| Preview     | 30 s    | `preview`                                                                  |
| Schreiben   | 30 s    | jedes Schreib-Tool                                                         |

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

Standard an: 30-Token-Burst, 1 Token/Sek. Refill (60 `tools/call`
pro Minute im Dauerbetrieb). Nur `tools/call` ist gekappt;
`tools/list`, `initialize`, `ping`, `resources/*` und
`logging/setLevel` bleiben frei.

Ablehnung: -32001 mit `data.type = "RateLimitError"`.

Einstellbar über `ServerConfig.rate_burst` /
`rate_refill_per_sec`, deaktivierbar mit
`rate_limit_enabled = False`.

---

## 5. Multi-Backend

Übergib ein Dict `{id: backend}` als `ServerConfig.backends`
(oder `HTTPServerConfig.backends`). Wenn gesetzt:

 - Ein neues read-only `list_backends`-Tool liefert
   `[{id, class, name, is_default}]`, damit der LLM sie
   aufzählen kann.
 - Jedes andere Tool bekommt im inputSchema ein optionales
   `backend: string`-Feld. Ohne Angabe → Default; mit ID →
   Routing. Unbekannte IDs landen auf -32602.

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
Red-Team-Szenario. Tests in
`tests/test_hardening_regressions.py` (Klassen `McpServerTests`
und `McpHttpTransportTests`).

### 7.1 Filesystem-Escape — Symlink-auflösender Root-Check

`_enforce_root` fährt zwei Pässe: erst `abspath` für
`..`/`.`-Kollaps, dann `realpath` um Symlinks aufzulösen und
erneut gegen die Root zu prüfen. Ohne den zweiten Pass könnte ein
Symlink unter der Root (extern oder vom LLM selbst über das
`symlink`-Write-Tool angelegt) nach `/` zeigen und
`write_file("/root/escape/etc/cron.d/evil")` durchlassen. Jetzt
`PermissionError` → -32602.

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

Jedes Schreib-Tool emittet `outcome=attempt` VOR dem Backend-
Aufruf, dann `outcome=ok` oder `outcome=refused` danach. Ein
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
| -32603   | INTERNAL                | Unerwartete Exception im Handler, oder Cancel.       |
| **-32001** | **RATE_LIMITED**      | `tools/call` gedrosselt.                             |
| **-32002** | **TIMEOUT**           | Tool hat seinen Wall-Clock-Timeout gerissen.         |
