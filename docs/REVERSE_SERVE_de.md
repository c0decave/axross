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

## OPSEC-Defaults

| Default | Wert | Warum |
|---|---|---|
| Bind | `127.0.0.1` | Public-Interface erfordert explizit `bind="0.0.0.0"`. Ein verirrter Reverse-Server soll nie versehentlich dein remote SFTP ins LAN exponieren. |
| Auth | ein Token, auch auf localhost | Ein Loopback-Server erzeugt einen (`srv.auth_token`); `auth_token="…"` setzt einen eigenen. Clients senden ihn als `Authorization: Bearer <token>`, als Basic-Passwort (WebDAV-Clients fragen danach) oder als AWS Access Key ID (aws-cli, restic, boto3). `auth_token=None` schaltet Auth ab, nur auf Loopback: dann erreicht jeder lokale User des Hosts das Backend. Non-local Binds wie `0.0.0.0` werden ohne expliziten Token **abgelehnt**. |
| Read-only | False | `read_only=True` lehnt jeden Mutating-Verb (PUT/DELETE/MKCOL/MOVE/COPY) mit HTTP 403 ab. |
| Path-Traversal | abgelehnt | Jeder Pfad wird normalisiert; `..`-Segmente, Segmente mit Backslash und Segmente, die mit einem Laufwerk (`C:`) beginnen, liefern 400, und jeder zusammengesetzte Pfad muss im Pfad-Flavour des Backends unter der Root bleiben (auch Windows-Pfade). |
| Body-Cap | 8 GiB pro Request | Gegen Content-Length-Lügen. |

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
| `PUT /<bucket>/<key>` (PutObject) | ✓ |
| `DELETE /<bucket>/<key>` (DeleteObject) | ✓ |
| `POST /<bucket>?delete` (DeleteObjects) | ✗ |
| Multipart-Upload | ✗ |
| Versioning | ✗ |
| Tags / ACLs / Lifecycle | ✗ |
| Signed URLs / V4-Auth | ✗ (Bearer only) |

Path-Style only. Single-PUT-Uploads gekappt am Body-Limit (8 GiB);
größere Objekte brauchen Multipart, was wir nicht sprechen.

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
* Keine TLS-Termination. Bind `0.0.0.0` → TLS-Proxy davor (nginx,
  caddy) oder via SSH `-L 9000:127.0.0.1:9000` tunneln.
* Kein Rate-Limit. Ein hostiler Client kann das Backend DoS-en.
  Reverse-Server ist für kooperative Umgebungen.

Im Zweifel: localhost-bind, SSH-Tunnel für remote, echtes Gateway
(MinIO etc.) sobald die Client-Population größer als „ich" wird.

---

## Siehe auch

* [`docs/MULTI_SYSTEM.md`](MULTI_SYSTEM.md) — Multi-System-Verbs auf axross-Backends.
* [`docs/OPSEC.md`](OPSEC.md) — was der axross-Client an Server preisgibt (umgekehrte Frage).
* [`docs/SCRIPTING_REFERENCE.md`](SCRIPTING_REFERENCE.md) — vollständige `axross.*`-Referenz.
