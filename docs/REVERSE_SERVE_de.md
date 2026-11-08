# Reverse-Serve — Backend per S3 / WebDAV exponieren

[English](REVERSE_SERVE.md) · [Deutsch](REVERSE_SERVE_de.md) · [Español](REVERSE_SERVE_es.md)

Jedes Tool, das schon **S3** spricht (terraform, aws-cli, restic,
rclone, …) oder **WebDAV** (gnome-files, davfs2, cadaver, macOS
Finder, Browser), kommt sofort an *jedes* Protokoll, das axross
spricht — weil axross davorsteht, ihre Requests entgegennimmt und
auf das Backend weiterreicht, das du geöffnet hast (SFTP, SMB,
RamFS, Postgres-FS, IMAP-as-FS, …).

Zwei Server-Flavours heute, beide auf stdlib `http.server`:

| Verb | Endpoint | Kompatible Clients |
|---|---|---|
| `axross.serve_s3(backend)` | path-style S3 (`http://host:9000/bucket/key`) | `aws s3 --endpoint-url`, `restic -r s3:…`, `rclone` (Provider Other), terraform `s3` Backend |
| `axross.serve_webdav(backend)` | minimum-viable WebDAV | `davfs2 mount`, `gnome-files davs://`, macOS Finder, `cadaver`, Browser read-only |

Beide liefern ein lebendes :class:`core.reverse_serve.ReverseServer`-
Handle; `.shutdown()` stoppt. Mehrere Reverse-Server parallel auf
verschiedenen Ports möglich.

Ein zukünftiger `serve_sftp` (paramiko `ServerInterface`) plugt sich
über `core.reverse_serve.register_server_factory` ein. Reverse-NFS
bleibt explizit out-of-scope (braucht userspace NFS-Impl).

---

## Quickstart — restic backupt zu deinem SFTP-Server

```python
>>> backend = axross.open_url("sftp://alice@backup-host/")
>>> srv = axross.serve_s3(backend, port=9000)
>>> srv.base_url
'http://127.0.0.1:9000'
>>> srv.auth_token
'kX3v…'
```

In einem zweiten Terminal, mit dem Token als Access Key ID (das Secret
wird nicht geprüft):

```bash
$ export AWS_ACCESS_KEY_ID='<srv.auth_token>'
$ export AWS_SECRET_ACCESS_KEY=anything
$ restic -r s3:http://127.0.0.1:9000/restic-backups init
$ restic -r s3:http://127.0.0.1:9000/restic-backups backup ~/Documents
```

restic schreibt sein Repository jetzt in `restic-backups/` auf das
geöffnete Backend — hier SFTP, könnte aber genauso RamFS,
Dropbox-FS oder lokale Disk sein.

```python
>>> srv.shutdown()
```

---

## Quickstart — gnome-files browst dein IMAP-„Filesystem"

```python
>>> mail = axross.open_url("imap+ssl://alice@mail.example.com/")
>>> srv = axross.serve_webdav(mail, port=8080, read_only=True)
```

In gnome-files in die Pfadleiste:

```
davs://127.0.0.1:8080
```

gnome-files fragt nach einem User-Namen (beliebig) und einem Passwort: `srv.auth_token`.

Folders = IMAP-Folders, Files = Messages — die gleiche Sicht, die
axross intern hat, jetzt sichtbar für jedes Tool, das WebDAV spricht.

---

## Quickstart — das LAN per HTTPS bedienen

Jenseits von Loopback spricht der Server HTTPS: eine PEM-Zertifikatskette
und ihren privaten Schlüssel übergeben.

```python
>>> srv = axross.serve_webdav(backend, bind="0.0.0.0", port=8443,
...                           auth_token=secrets.token_urlsafe(32),
...                           cert_file="/etc/axross/cert.pem",
...                           key_file="/etc/axross/key.pem")
>>> srv.base_url
'https://0.0.0.0:8443'
```

Ein Non-Loopback-Bind ohne `cert_file` + `key_file` wird **abgelehnt**
(`PermissionError`): Token und jede Datei gingen im Klartext übers Netz.
`allow_insecure_http=True` bedient trotzdem Plain-HTTP, für ein Netz,
dem du traust, oder einen TLS-Proxy auf demselben Host, und loggt eine
Warnung. Ein selbstsigniertes Zertifikat (`openssl req -x509 -newkey
rsa:2048 -nodes -keyout key.pem -out cert.pem -days 365 -subj /CN=myhost`)
geht, wenn die Clients ihm vertrauen (`aws --ca-bundle cert.pem`,
`curl --cacert cert.pem`, `rclone --ca-cert cert.pem`).

---

## OPSEC-Defaults

| Default | Wert | Warum |
|---|---|---|
| Bind | `127.0.0.1` | Public-Interface erfordert explizit `bind="0.0.0.0"`. Ein verirrter Reverse-Server soll nie versehentlich dein remote SFTP ins LAN exponieren. |
| Auth | ein Token, auch auf localhost | Ein Loopback-Server erzeugt einen (`srv.auth_token`); `auth_token="…"` setzt einen eigenen. Clients senden ihn als `Authorization: Bearer <token>`, als Basic-Passwort (WebDAV-Clients fragen danach) oder als AWS Access Key ID (aws-cli, restic, boto3). `auth_token=None` schaltet Auth ab, nur auf Loopback: dann erreicht jeder lokale User des Hosts das Backend. Non-local Binds wie `0.0.0.0` werden ohne expliziten Token **abgelehnt**. |
| TLS | HTTPS mit `cert_file` + `key_file` | Loopback bedient Plain-HTTP, solange kein Zertifikat angegeben ist. Ein Non-Loopback-Bind ohne eines wird **abgelehnt**, wie `core/mcp_http.py` es ablehnt: der Token (Bearer, Basic-Passwort oder AWS Key ID) ginge im Klartext übers Netz. `allow_insecure_http=True` ist das explizite Opt-in, als Warnung geloggt. TLS 1.2 oder neuer; `cert_file` ohne `key_file` (oder umgekehrt) wird abgelehnt. |
| Read-only | False | `read_only=True` lehnt jeden Mutating-Verb (PUT/DELETE/MKCOL/MOVE/COPY) mit HTTP 403 ab. |
| Path-Traversal | abgelehnt | Jeder Pfad wird normalisiert; `..`-Segmente, Segmente mit Backslash und Segmente, die mit einem Laufwerk (`C:`) beginnen, liefern 400, und jeder zusammengesetzte Pfad muss im Pfad-Flavour des Backends unter der Root bleiben (auch Windows-Pfade). |
| Body-Cap | 8 GiB pro Request | Gegen Content-Length-Lügen. |
| Body-Länge | `Content-Length` oder `Transfer-Encoding: chunked` | Ein Chunked-Body (`curl -T -`, `rclone rcat`) wird beim Streamen dekodiert, unter demselben Cap. Ein PUT mit keinem von beiden ist **411 Length Required**, die Datei bleibt wie sie war; beide zugleich, ein anderes Transfer-Coding oder kaputtes Chunk-Framing wird abgelehnt (400 / 501) und lässt die Datei ebenfalls stehen. |
| aws-chunked | dekodiert | boto3 / aws-cli über HTTPS senden `Content-Encoding: aws-chunked` (Chunk-Frames mit nachgestellter Prüfsumme oder Chunk-Signaturen): Das Objekt sind die Daten in den Frames, genau `x-amz-decoded-content-length` Bytes; ein Body, der nicht dazu passt, wird abgelehnt (400 / 411) und lässt die Datei stehen. Chunk-Signaturen und Prüfsummen werden nicht geprüft, wie keine Signatur. |
| HTTP | 1.1, Keep-Alive | Eine Verbindung trägt den nächsten Request nur, wenn der letzte Body bis zum Ende gelesen wurde (sonst wird sie geschlossen, mit `Connection: close`: ein ungelesener Body wird nie als Request genommen); sie wartet höchstens 5 s auf den nächsten, und das Stoppen des Servers schließt sie sofort. `Expect: 100-continue` wird erst beantwortet, wenn Token, Pfad, Read-only-Schalter und Größe geprüft sind - ein abgelehnter PUT bekommt seine endgültige Antwort, nie die Einladung, den Body zu senden. Ohne die 100 warteten boto3 und aws-cli 1 s pro PUT. |

Reverse-Server prüft **kein** AWS-Signature-V4 — er liest aus einem
signierten Request nur die Access Key ID und vergleicht sie mit dem
Token. aws-cli / restic / rclone / boto3 laufen also mit
`AWS_ACCESS_KEY_ID=<token>` und beliebigem Secret; curl und andere
HTTP-Clients senden `Authorization: Bearer <token>`.

Voll-signierten S3-Endpoint? Echtes Gateway (MinIO, SeaweedFS,
garage). Der axross-Reverse-Server ist **Swiss-Army-Gateway, kein
gehärteter S3-Cluster**.

---

## Was implementiert ist

Ein stat oder Listing, das fehlschlägt, wird nie als „nicht da“
beantwortet: 404, `NoSuchKey` und `NoSuchBucket` heißen, der Pfad fehlt
wirklich; eine Verweigerung ist 403 (`AccessDenied`), jeder andere Fehler
500 (`InternalError`). Ein Ordner, der sich nicht listen lässt, lässt
PROPFIND bzw. ListObjects scheitern, statt leer zu erscheinen oder seine
Keys auszulassen - Sync-Clients (rclone, `aws s3 sync --delete`) halten
eine leere oder kürzere Antwort für „gelöscht“ und entfernen ihre Kopie.
Ein WebDAV-`COPY` auf einen existierenden Ordner wird abgelehnt (409),
nie hineinkopiert.

### S3

| Verb | Status |
|---|---|
| `GET /` (ListBuckets) | ✓ — Top-Level-Dirs von `root_path` sind Buckets |
| `GET /<bucket>?prefix=…&max-keys=…` (ListObjects) | ✓ |
| `GET /<bucket>/<key>` (GetObject) | ✓ |
| `HEAD /<bucket>/<key>` (HeadObject) | ✓ |
| `HEAD /<bucket>` (HeadBucket) | ✓ |
| `GET /<bucket>?location` (GetBucketLocation) | ✓ — die Default-Region (ein leeres `LocationConstraint`) |
| `PUT /<bucket>/<key>` (PutObject) | ✓ — `If-None-Match: *` wird beachtet (412 `PreconditionFailed`, wenn der Key existiert; vor dem Schreiben geprüft, nicht atomar damit); `If-Match` und ein ETag in `If-None-Match` sind 501, die ETags sind synthetisch |
| `PUT` mit `x-amz-copy-source` (CopyObject, UploadPartCopy) | ✗ - 501 `NotImplemented`, nichts wird geschrieben: `aws s3 mv` / `cp` zwischen zwei Keys und rclones Server-Side-Copy scheitern, statt eine leere Kopie zu schreiben (und bei `mv` danach die Quelle zu löschen) |
| Jede andere Subresource (`?tagging`, `?acl`, `?versionId=`, `?retention`, `?legal-hold`, `?versioning`, ListParts `GET ?uploadId=`, …) bei GET / HEAD / PUT / DELETE / POST | ✗ - 501 `NotImplemented`; das Objekt wird weder geliefert noch ersetzt noch gelöscht. Presign-Parameter (`X-Amz-*`, `AWSAccessKeyId` / `Expires` / `Signature`), das `x-id` der SDKs und die ListObjects- / GetObject-Parameter werden bedient |
| `DELETE /<bucket>/<key>` (DeleteObject) | ✓ |
| `POST /<bucket>?delete` (DeleteObjects) | ✗ |
| Multipart-Upload (`POST ?uploads`, `PUT ?partNumber=&uploadId=`, `POST ?uploadId=`, `DELETE ?uploadId=`) | ✓ - siehe *Multipart-Upload* unten; ListParts / ListMultipartUploads und UploadPartCopy sind 501 |
| Versioning | ✗ |
| Tags / ACLs / Lifecycle | ✗ |
| Signed URLs / V4-Auth | ✗ (Bearer only) |

Path-Style only. Single-PUT-Uploads gekappt am Body-Limit (8 GiB).

#### Multipart-Upload

Uploads über der Multipart-Schwelle der SDKs (8 MiB bei boto3 und
aws-cli, also `aws s3 cp` jeder größeren Datei) und restics Pack-Uploads
nutzen ihn. Die Parts warten in einem privaten lokalen Ordner,
`$XDG_CACHE_HOME/axross/s3-multipart/` (Modus 0700, abgelehnt, wenn er
ein Link ist oder einem anderen Benutzer gehört), bis
CompleteMultipartUpload sie in der genannten Reihenfolge über denselben
Speicherweg wie ein PUT ins Objekt streamt: Das alte Objekt bleibt, bis
jedes Byte angekommen ist. Die Grenzen:

| Grenze | Wert |
|---|---|
| Gleichzeitig offene Uploads | 16 (einer mehr: 400 `InvalidRequest`) |
| Parts pro Upload | 10.000 (Part-Nummern 1-10000) |
| Bytes pro Upload und aller offenen Uploads zusammen | 8 GiB, das Single-PUT-Cap (400 `EntityTooLarge` / 503 `SlowDown`, gegen die `Content-Length` des Parts geprüft, bevor der Body gelesen wird) |
| Untätiger Upload | wird nach 1 Stunde ohne Request mit seinen Parts verworfen |
| Part-Liste (Complete) | höchstens 4 MiB, keine DTD / Entities, Part-Nummern aufsteigend, jedes ETag das für seinen Part gelieferte (sonst 400 `InvalidPart` / `MalformedXML`) |

Ein Upload gehört zu seinem Bucket und Key (ein anderer Key mit seiner
ID ist `NoSuchUpload`); ein zweimal hochgeladener Part ersetzt den
ersten; in Complete nicht genannte Parts werden verworfen.
AbortMultipartUpload, Complete und das Stoppen des Servers entfernen die
Parts; Ordner, die ein axross hinterließ, das ohne Stoppen seines Servers
endete, werden nach einem Tag entfernt. Complete antwortet sofort 200 und
hält den Client mit einem Leerzeichen alle 10 s hin, während es das Objekt
zusammensetzt (wie S3); ein Fehler danach ist ein `<Error>` in dieser 200,
den die SDKs als Fehler melden, und der Upload bleibt, sodass Complete
erneut versucht werden kann. Die Parts belegen lokalen Plattenplatz bis
zum Cap: Auf einem Host mit wenig temporärem Platz die Part-Parallelität
der Clients senken (`aws configure set default.s3.max_concurrent_requests
2`) oder ihre Schwelle anheben, um große Dateien als einen PUT zu senden
(`aws configure set default.s3.multipart_threshold 5GB`; boto3:
`TransferConfig(multipart_threshold=...)`).

### WebDAV

| Verb | Status |
|---|---|
| `OPTIONS` | ✓ |
| `GET` (Datei oder HTML-Index für Dirs) | ✓ |
| `HEAD` | ✓ |
| `PUT` | ✓ |
| `DELETE` | ✓ (rekursiv) |
| `MKCOL` | ✓ |
| `MOVE`, `COPY` | ✓ (nutzt nativen rename / copy wenn da) |
| `PROPFIND` Depth 0/1 | ✓ |
| `PROPFIND` Depth infinity | ✗ |
| `LOCK` / `UNLOCK` | ✓ als No-Ops |
| `PROPPATCH` | ✗ |

`PROPFIND` liefert das Standard-Subset (`displayname`,
`getcontentlength`, `getlastmodified`, `resourcetype`).

Lock-Support ist **fake** — `LOCK` liefert plausibles Token, kein
echtes Locking. macOS Finder + davfs2 brauchen das zum Mount;
Trade-off ok, weil Reverse-Server konstruktionsbedingt single-user
ist.

---

## Threat-Model

Reverse-Server ist **Glue-Layer vor einem schon authentifizierten
Backend**. Was das Backend trusted, trusted der Reverse-Server.
Konkret:

* Backend-Auth ist *schon* passiert. Wer den Reverse-Server erreicht,
  hat den Zugriff dessen, der das Backend geöffnet hat. **Nicht auf
  ein remote SFTP zeigen, das Daten hält, an die der lokale User
  nicht ran soll.**
* Tokens werden mit `hmac.compare_digest` verglichen. Sie gehen im
  Klartext (Bearer-Header, Basic-Passwort oder AWS Access Key ID) — kein Replay-Schutz, keine Nonce,
  kein Time-Bound. Wie jedes Shared-Secret behandeln: bei Verdacht
  rotieren, nie loggen, jenseits localhost via TLS.
* TLS jenseits von Loopback. Ein Non-Loopback-Bind bedient HTTPS
  (`cert_file` + `key_file`) oder wird abgelehnt; mit
  `allow_insecure_http=True` ist es Plain-HTTP, und jeder auf dem Weg
  liest den Token. Alternativen: ein TLS-Proxy (nginx, caddy) vor einem
  Loopback-Bind, oder ein SSH-Tunnel (`-L 9000:127.0.0.1:9000`), sodass
  das LAN nur deinen SSH-Client sieht. Client-Zertifikate (mTLS) werden
  nicht geprüft; der Token ist die Authentifizierung.
* Kein Rate-Limit. Ein hostiler Client kann das Backend DoS-en.
  Reverse-Server ist für kooperative Umgebungen.

Im Zweifel: localhost-bind, SSH-Tunnel für remote, echtes Gateway
(MinIO etc.) sobald die Client-Population größer als „ich" wird.

---

## Siehe auch

* [`docs/MULTI_SYSTEM.md`](MULTI_SYSTEM.md) — Multi-System-Verbs auf axross-Backends.
* [`docs/OPSEC.md`](OPSEC.md) — was der axross-Client an Server preisgibt (umgekehrte Frage).
* [`docs/SCRIPTING_REFERENCE.md`](SCRIPTING_REFERENCE.md) — vollständige `axross.*`-Referenz.
