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
>>> srv.auth_token
'kX3v…'
```

En otro terminal, con el token como access key id (el secret no se
comprueba):

```bash
$ export AWS_ACCESS_KEY_ID='<srv.auth_token>'
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

gnome-files pide un nombre de usuario (cualquiera) y un password: `srv.auth_token`.

Las carpetas son carpetas IMAP, los ficheros son mensajes — la
misma vista que axross tiene internamente, ahora visible para
cualquier herramienta WebDAV.

---

## Quick start — servir la LAN por HTTPS

Fuera de loopback el servidor habla HTTPS: pasa una cadena de
certificados PEM y su clave privada.

```python
>>> srv = axross.serve_webdav(backend, bind="0.0.0.0", port=8443,
...                           auth_token=secrets.token_urlsafe(32),
...                           cert_file="/etc/axross/cert.pem",
...                           key_file="/etc/axross/key.pem")
>>> srv.base_url
'https://0.0.0.0:8443'
```

Un bind non-loopback sin `cert_file` + `key_file` se **rechaza**
(`PermissionError`): el token y cada fichero cruzarían la red en claro.
`allow_insecure_http=True` sirve HTTP plano igualmente, para una red en
la que confías o un proxy TLS en el mismo host, y loguea un aviso. Un
certificado autofirmado (`openssl req -x509 -newkey rsa:2048 -nodes
-keyout key.pem -out cert.pem -days 365 -subj /CN=myhost`) funciona si
los clientes confían en él (`aws --ca-bundle cert.pem`,
`curl --cacert cert.pem`, `rclone --ca-cert cert.pem`).

---

## Defaults OPSEC

| Default | Valor | Por qué |
|---|---|---|
| Bind | `127.0.0.1` | Interfaz pública requiere `bind="0.0.0.0"` explícito. Un reverse-server perdido nunca debería exponer tu SFTP remoto al LAN por error. |
| Auth | un token, también en localhost | Un servidor loopback genera uno (`srv.auth_token`); `auth_token="…"` fija uno propio. Los clientes lo envían como `Authorization: Bearer <token>`, como password Basic (los clientes WebDAV lo piden) o como AWS access key id (aws-cli, restic, boto3). `auth_token=None` desactiva la auth, solo en loopback: entonces cualquier usuario local del host llega al backend. Binds non-local como `0.0.0.0` se **rechazan** sin token explícito. |
| TLS | HTTPS con `cert_file` + `key_file` | Loopback sirve HTTP plano mientras no se dé un certificado. Un bind non-loopback sin él se **rechaza**, como lo rechaza `core/mcp_http.py`: el token (Bearer, password Basic o AWS key id) cruzaría la red en claro. `allow_insecure_http=True` es el opt-in explícito, logueado como aviso. TLS 1.2 o posterior; `cert_file` sin `key_file` (o al revés) se rechaza. |
| Read-only | False | `read_only=True` rechaza todo verbo mutador (PUT/DELETE/MKCOL/MOVE/COPY) con HTTP 403. |
| Path traversal | rechazado | Cada path se normaliza; segmentos `..`, segmentos con barra invertida y segmentos que empiezan por una unidad (`C:`) devuelven 400, y cada path unido debe quedar bajo la raíz en el estilo de paths del backend (también paths de Windows). |
| Cap del body | 8 GiB por request | Contra mentiras de Content-Length. |
| Longitud del body | `Content-Length` o `Transfer-Encoding: chunked` | Un body chunked (`curl -T -`, `rclone rcat`) se decodifica mientras llega, bajo el mismo cap. Un PUT sin ninguno de los dos es **411 Length Required** y el fichero queda como estaba; los dos a la vez, otro transfer coding o un framing de chunks roto se rechaza (400 / 501) y también deja el fichero intacto. |
| aws-chunked | decodificado | boto3 / aws-cli por HTTPS envían `Content-Encoding: aws-chunked` (frames de chunks con un checksum al final, o firmas de chunk): el objeto son los datos dentro de los frames, exactamente `x-amz-decoded-content-length` bytes; un body que no coincide se rechaza (400 / 411) y deja el fichero intacto. Las firmas de chunk y los checksums no se comprueban, como ninguna firma. |
| HTTP | 1.1, keep-alive | Una conexión lleva el siguiente request solo si el último body se leyó hasta el final (si no, se cierra, con `Connection: close`: un body sin leer nunca se toma por un request); espera como mucho 5 s al siguiente, y parar el servidor la cierra al instante. `Expect: 100-continue` se responde solo después de comprobar el token, la ruta, el modo solo lectura y el tamaño - un PUT rechazado recibe su respuesta final, nunca una invitación a enviar el body. Sin el 100, boto3 y aws-cli esperaban 1 s por PUT. |

El reverse-server **no** comprueba AWS Signature V4 — de una request
firmada lee solo el access key id y lo compara con el token. aws-cli /
restic / rclone / boto3 funcionan con `AWS_ACCESS_KEY_ID=<token>` y
cualquier secret; curl y otros clientes HTTP envían
`Authorization: Bearer <token>`.

Para endpoint S3 totalmente firmado: gateway real (MinIO,
SeaweedFS, garage). El reverse-server de axross es **gateway
swiss-army, no cluster S3 endurecido**.

---

## Qué está implementado

Un stat o un listado que falla nunca se responde como "no existe": 404,
`NoSuchKey` y `NoSuchBucket` significan que la ruta realmente falta; un
rechazo es 403 (`AccessDenied`), cualquier otro fallo 500
(`InternalError`). Una carpeta que no se puede listar hace fallar el
PROPFIND o el ListObjects en vez de aparecer vacía u omitir sus claves:
los clientes de sincronización (rclone, `aws s3 sync --delete`) toman una
respuesta vacía o más corta por "borrado" y eliminan su copia. Un `COPY`
WebDAV sobre una carpeta existente se rechaza (409), nunca copia dentro.

### S3

| Verbo | Estado |
|---|---|
| `GET /` (ListBuckets) | ✓ — top-level de `root_path` son buckets |
| `GET /<bucket>?prefix=…&max-keys=…` (ListObjects) | ✓ |
| `GET /<bucket>/<key>` (GetObject) | ✓ |
| `HEAD /<bucket>/<key>` (HeadObject) | ✓ |
| `HEAD /<bucket>` (HeadBucket) | ✓ |
| `GET /<bucket>?location` (GetBucketLocation) | ✓ — la región por defecto (un `LocationConstraint` vacío) |
| `PUT /<bucket>/<key>` (PutObject) | ✓ — `If-None-Match: *` se respeta (412 `PreconditionFailed` si la key existe; comprobado antes de escribir, no de forma atómica con ello); `If-Match` y un ETag en `If-None-Match` son 501, los ETags son sintéticos |
| `PUT` con `x-amz-copy-source` (CopyObject, UploadPartCopy) | ✗ - 501 `NotImplemented`, no se escribe nada: `aws s3 mv` / `cp` entre dos keys y la copia server-side de rclone fallan en vez de escribir una copia vacía (y en `mv` borrar luego el origen) |
| Cualquier otro subresource (`?tagging`, `?acl`, `?versionId=`, `?retention`, `?legal-hold`, `?versioning`, ListParts `GET ?uploadId=`, …) en GET / HEAD / PUT / DELETE / POST | ✗ - 501 `NotImplemented`; el objeto ni se devuelve, ni se reemplaza, ni se borra. Los parámetros de presign (`X-Amz-*`, `AWSAccessKeyId` / `Expires` / `Signature`), el `x-id` de los SDKs y los parámetros de ListObjects / GetObject se sirven |
| `DELETE /<bucket>/<key>` (DeleteObject) | ✓ |
| `POST /<bucket>?delete` (DeleteObjects) | ✗ |
| Multipart upload (`POST ?uploads`, `PUT ?partNumber=&uploadId=`, `POST ?uploadId=`, `DELETE ?uploadId=`) | ✓ - ver *Multipart upload* abajo; ListParts / ListMultipartUploads y UploadPartCopy son 501 |
| Versioning | ✗ |
| Tags / ACLs / Lifecycle | ✗ |
| Signed URLs / V4 auth | ✗ (Bearer only) |

Solo path-style. Uploads single-PUT capados al body limit (8 GiB).

#### Multipart upload

Lo usan los uploads por encima del umbral multipart de los SDKs (8 MiB
en boto3 y aws-cli, o sea `aws s3 cp` de cualquier fichero mayor) y los
uploads de packs de restic. Las partes esperan en una carpeta local
privada, `$XDG_CACHE_HOME/axross/s3-multipart/` (modo 0700, rechazada si
es un enlace o pertenece a otro usuario), hasta que
CompleteMultipartUpload las vuelca, en el orden indicado, al objeto por
el mismo camino que un PUT: el objeto anterior se mantiene hasta que
llega cada byte. Los límites:

| Límite | Valor |
|---|---|
| Uploads abiertos a la vez | 16 (uno más: 400 `InvalidRequest`) |
| Partes por upload | 10.000 (números de parte 1-10000) |
| Bytes por upload, y de todos los uploads abiertos juntos | 8 GiB, el cap de un PUT (400 `EntityTooLarge` / 503 `SlowDown`, comprobado contra el `Content-Length` de la parte antes de leer el body) |
| Upload inactivo | se descarta con sus partes tras 1 hora sin request |
| Lista de partes (Complete) | como mucho 4 MiB, sin DTD / entidades, números ascendentes, cada ETag el devuelto para su parte (si no, 400 `InvalidPart` / `MalformedXML`) |

Un upload está ligado a su bucket y key (otra key con su id es
`NoSuchUpload`); una parte subida dos veces reemplaza a la primera; las
partes no listadas en Complete se descartan. AbortMultipartUpload,
Complete y parar el servidor borran las partes; las carpetas que dejó un
axross que terminó sin parar su servidor se borran al cabo de un día.
Complete responde 200 enseguida y mantiene al cliente esperando con un
espacio cada 10 s mientras compone el objeto (como S3); un fallo después
es un `<Error>` dentro de ese 200, que los SDKs elevan como error, y el
upload se mantiene, así que Complete puede reintentarse. Las partes
ocupan disco local hasta el cap: en un host con poco espacio temporal,
bajar la concurrencia de partes de los clientes (`aws configure set
default.s3.max_concurrent_requests 2`) o subir su umbral para enviar
ficheros grandes en un solo PUT (`aws configure set
default.s3.multipart_threshold 5GB`; boto3:
`TransferConfig(multipart_threshold=...)`).

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
* Los tokens se comparan con `hmac.compare_digest`. Viajan en claro
  (header Bearer, password Basic o AWS access key id) — sin protección anti-
  replay, sin nonce, sin bound temporal. Trátalo como cualquier
  shared secret: rota al sospechar, nunca loguees, transporta sobre
  TLS si sale de localhost.
* TLS fuera de loopback. Un bind non-loopback sirve HTTPS
  (`cert_file` + `key_file`) o se rechaza; con
  `allow_insecure_http=True` es HTTP plano y cualquiera en el camino
  lee el token. Alternativas: un proxy TLS (nginx, caddy) delante de un
  bind loopback, o un túnel SSH (`-L 9000:127.0.0.1:9000`) para que la
  LAN solo vea tu cliente SSH. Los certificados de cliente (mTLS) no se
  comprueban; el token es la autenticación.
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
