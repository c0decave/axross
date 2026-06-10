# Reverse-Serve — Exponer un backend por S3 / WebDAV

[English](REVERSE_SERVE.md) · [Deutsch](REVERSE_SERVE_de.md) · [Español](REVERSE_SERVE_es.md)

Cualquier herramienta que ya hable **S3** (terraform, aws-cli,
restic, rclone, …) o **WebDAV** (gnome-files, davfs2, cadaver, macOS
Finder, navegadores) accede inmediatamente a *cualquier* protocolo
que axross hable — porque axross se planta delante, recibe sus
requests y las reenvía al backend que abriste (SFTP, SMB, RamFS,
Postgres-FS, IMAP-as-FS, …).

Dos sabores de servidor hoy, ambos sobre stdlib `http.server`:

| Verbo | Endpoint | Clientes compatibles |
|---|---|---|
| `axross.serve_s3(backend)` | path-style S3 (`http://host:9000/bucket/key`) | `aws s3 --endpoint-url`, `restic -r s3:…`, `rclone` (provider Other), backend `s3` de terraform |
| `axross.serve_webdav(backend)` | WebDAV minimum-viable | `davfs2 mount`, `gnome-files davs://`, macOS Finder, `cadaver`, navegador read-only |

Ambos devuelven un :class:`core.reverse_serve.ReverseServer` vivo;
`.shutdown()` para parar. Múltiples reverse-servers en paralelo en
puertos distintos.

Un futuro `serve_sftp` (paramiko `ServerInterface`) entra vía
`core.reverse_serve.register_server_factory`. Reverse-NFS está
explícitamente fuera de scope.

---

## Quick start — restic backupeando a tu SFTP

```python
>>> backend = axross.open_url("sftp://alice@backup-host/")
>>> srv = axross.serve_s3(backend, port=9000)
>>> srv.base_url
'http://127.0.0.1:9000'
```

En otro terminal:

```bash
$ export AWS_ACCESS_KEY_ID=anything
$ export AWS_SECRET_ACCESS_KEY=anything
$ restic -r s3:http://127.0.0.1:9000/restic-backups init
$ restic -r s3:http://127.0.0.1:9000/restic-backups backup ~/Documents
```

restic escribe ahora su repo en `restic-backups/` sobre el backend
abierto — aquí SFTP, podría ser RamFS, Dropbox-FS o disco local.

```python
>>> srv.shutdown()
```

---

## Quick start — gnome-files navegando tu IMAP

```python
>>> mail = axross.open_url("imap+ssl://alice@mail.example.com/")
>>> srv = axross.serve_webdav(mail, port=8080, read_only=True)
```

En gnome-files, en la barra de path:

```
davs://127.0.0.1:8080
```

Las carpetas son carpetas IMAP, los ficheros son mensajes — la
misma vista que axross tiene internamente, ahora visible para
cualquier herramienta WebDAV.

---

## Defaults OPSEC

| Default | Valor | Por qué |
|---|---|---|
| Bind | `127.0.0.1` | Interfaz pública requiere `bind="0.0.0.0"` explícito. Un reverse-server perdido nunca debería exponer tu SFTP remoto al LAN por error. |
| Auth | ninguna en localhost | `auth_token="…"` para `Authorization: Bearer <token>`. Binds non-local como `0.0.0.0` se **rechazan** sin auth token. |
| Read-only | False | `read_only=True` rechaza todo verbo mutador (PUT/DELETE/MKCOL/MOVE/COPY) con HTTP 403. |
| Path traversal | rechazado | Cada path se normaliza; segmentos `..` devuelven 400. |
| Cap del body | 8 GiB por request | Contra mentiras de Content-Length. |

El reverse-server **no** hace AWS Signature V4 — el endpoint
path-style autentica solo por Bearer. restic / rclone / aws-cli
aceptan creds dummy (sin auth) o header `Authorization` custom.

Para endpoint S3 totalmente firmado: gateway real (MinIO,
SeaweedFS, garage). El reverse-server de axross es **gateway
swiss-army, no cluster S3 endurecido**.

---

## Qué está implementado

### S3

| Verbo | Estado |
|---|---|
| `GET /` (ListBuckets) | ✓ — top-level de `root_path` son buckets |
| `GET /<bucket>?prefix=…&max-keys=…` (ListObjects) | ✓ |
| `GET /<bucket>/<key>` (GetObject) | ✓ |
| `HEAD /<bucket>/<key>` (HeadObject) | ✓ |
| `HEAD /<bucket>` (HeadBucket) | ✓ |
| `PUT /<bucket>/<key>` (PutObject) | ✓ |
| `DELETE /<bucket>/<key>` (DeleteObject) | ✓ |
| `POST /<bucket>?delete` (DeleteObjects) | ✗ |
| Multipart upload | ✗ |
| Versioning | ✗ |
| Tags / ACLs / Lifecycle | ✗ |
| Signed URLs / V4 auth | ✗ (Bearer only) |

Solo path-style. Uploads single-PUT capados al body limit (8 GiB);
objetos mayores requieren multipart, que no hablamos.

### WebDAV

| Verbo | Estado |
|---|---|
| `OPTIONS` | ✓ |
| `GET` (fichero o índice HTML para dirs) | ✓ |
| `HEAD` | ✓ |
| `PUT` | ✓ |
| `DELETE` | ✓ (recursivo) |
| `MKCOL` | ✓ |
| `MOVE`, `COPY` | ✓ (rename / copy nativos cuando hay) |
| `PROPFIND` Depth 0/1 | ✓ |
| `PROPFIND` Depth infinity | ✗ |
| `LOCK` / `UNLOCK` | ✓ como no-ops |
| `PROPPATCH` | ✗ |

`PROPFIND` devuelve el subset estándar (`displayname`,
`getcontentlength`, `getlastmodified`, `resourcetype`).

Soporte LOCK es **falso** — `LOCK` devuelve token plausible, no
hay locking real. macOS Finder y davfs2 lo necesitan para montar; el
trade-off es aceptable porque el reverse-server es single-user por
construcción.

---

## Modelo de amenazas

El reverse-server es **una capa pegamento delante de un backend ya
autenticado**. Lo que el backend confía, lo confía el reverse-server.
Concretamente:

* La auth del backend ya pasó. Quien llegue al reverse-server tiene
  el acceso de quien abrió el backend. **No apuntes esto a un SFTP
  remoto con datos a los que el usuario local no debe acceder.**
* Los Bearer tokens se comparan con `hmac.compare_digest`. Se pasan
  como plain `Authorization: Bearer <token>` — sin protección anti-
  replay, sin nonce, sin bound temporal. Trátalo como cualquier
  shared secret: rota al sospechar, nunca loguees, transporta sobre
  TLS si sale de localhost.
* No hay terminación TLS. Si bindeas `0.0.0.0`, mete un proxy TLS
  delante (nginx, caddy), o tunelea por SSH
  `-L 9000:127.0.0.1:9000` para que la LAN solo vea tu cliente SSH.
* No hay rate limit. Un cliente hostil puede DoS-ear el backend.
  El reverse-server es para entornos cooperativos.

En la duda: bind localhost, túnel SSH para acceso remoto, gateway
real (MinIO etc.) cuando la población de clientes crezca más allá
de «yo».

---

## Ver también

* [`docs/MULTI_SYSTEM.md`](MULTI_SYSTEM.md) — verbos multi-sistema sobre backends axross.
* [`docs/OPSEC.md`](OPSEC.md) — qué revela el cliente al server.
* [`docs/SCRIPTING_REFERENCE.md`](SCRIPTING_REFERENCE.md) — referencia API.
