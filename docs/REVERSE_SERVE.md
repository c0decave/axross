# Reverse-Serve — Expose a Backend over S3 / WebDAV

Languages: **English** · [Deutsch](REVERSE_SERVE_de.md) · [Español](REVERSE_SERVE_es.md)

Every tool that already speaks **S3** (terraform, aws-cli, restic,
rclone, …) or **WebDAV** (gnome-files, davfs2, cadaver, macOS
Finder, browsers) can immediately reach *any* protocol axross speaks
— because axross stands in front, accepting their requests and
forwarding them to whatever backend you've opened (SFTP, SMB,
RamFS, Postgres-FS, IMAP-as-FS, …).

Two server flavours today, both built on stdlib `http.server`:

| Verb | Endpoint | Compatible clients |
|---|---|---|
| `axross.serve_s3(backend)` | path-style S3 (`http://host:9000/bucket/key`) | `aws s3 --endpoint-url`, `restic -r s3:…`, `rclone` (provider Other), terraform `s3` backend |
| `axross.serve_webdav(backend)` | minimum-viable WebDAV | `davfs2 mount`, `gnome-files davs://`, macOS Finder, `cadaver`, browser read-only |

Both return a live :class:`core.reverse_serve.ReverseServer` handle;
call `.shutdown()` to stop. Multiple reverse-servers can run side
by side on different ports.

A future `serve_sftp` (paramiko `ServerInterface`) slots in via
`core.reverse_serve.register_server_factory`. Reverse-NFS is
explicitly out of scope (needs a userspace NFS impl).

---

## Quick start — restic backing up to your SFTP server

```python
>>> backend = axross.open_url("sftp://alice@backup-host/")
>>> srv = axross.serve_s3(backend, port=9000)
>>> srv.base_url
'http://127.0.0.1:9000'
>>> srv.auth_token
'kX3v…'
```

In another terminal, with the token as the access key id (the secret is
not checked):

```bash
$ export AWS_ACCESS_KEY_ID='<srv.auth_token>'
$ export AWS_SECRET_ACCESS_KEY=anything
$ restic -r s3:http://127.0.0.1:9000/restic-backups init
$ restic -r s3:http://127.0.0.1:9000/restic-backups backup ~/Documents
```

restic now writes its repository into `restic-backups/` on the
backend you opened — over SFTP, in this example, but it could just
as easily be RamFS, Dropbox-FS or your local disk.

When done:

```python
>>> srv.shutdown()
```

---

## Quick start — gnome-files browsing your IMAP "filesystem"

```python
>>> mail = axross.open_url("imap+ssl://alice@mail.example.com/")
>>> srv = axross.serve_webdav(mail, port=8080, read_only=True)
```

In gnome-files, type into the path bar:

```
davs://127.0.0.1:8080
```

gnome-files asks for a user name (any) and a password: `srv.auth_token`.

Folders represent IMAP folders, files represent messages — the same
view axross gives you internally, now visible to every tool that
speaks WebDAV.

---

## Quick start — serving the LAN over HTTPS

Off loopback the server speaks HTTPS: pass a PEM certificate chain and
its private key.

```python
>>> srv = axross.serve_webdav(backend, bind="0.0.0.0", port=8443,
...                           auth_token=secrets.token_urlsafe(32),
...                           cert_file="/etc/axross/cert.pem",
...                           key_file="/etc/axross/key.pem")
>>> srv.base_url
'https://0.0.0.0:8443'
```

A non-loopback bind without `cert_file` + `key_file` is **refused**
(`PermissionError`): the token and every file would cross the network
in clear. `allow_insecure_http=True` serves plain HTTP anyway, for a
network you trust or a TLS proxy on the same host, and logs a warning.
A self-signed certificate (`openssl req -x509 -newkey rsa:2048 -nodes
-keyout key.pem -out cert.pem -days 365 -subj /CN=myhost`) works when
the clients are told to trust it (`aws --ca-bundle cert.pem`,
`curl --cacert cert.pem`, `rclone --ca-cert cert.pem`).

---

## OPSEC defaults

| Default | Value | Why |
|---|---|---|
| Bind | `127.0.0.1` | Listening on a public interface requires `bind="0.0.0.0"` explicitly. A stray reverse-server should never accidentally expose your remote SFTP to the LAN. |
| Auth | a token, on localhost too | A loopback server generates one (`srv.auth_token`); `auth_token="…"` sets your own. Clients send it as `Authorization: Bearer <token>`, as the Basic password (WebDAV clients are asked for it), or as the AWS access key id (aws-cli, restic, boto3). `auth_token=None` turns auth off, on loopback only: every local user of the host can then reach the backend. Non-local binds such as `0.0.0.0` are **refused** without an explicit token. |
| TLS | HTTPS with `cert_file` + `key_file` | Loopback serves plain HTTP unless a certificate is given. A non-loopback bind without one is **refused**, as `core/mcp_http.py` refuses it: the token (Bearer, Basic password or AWS key id) would cross the network in clear. `allow_insecure_http=True` is the explicit opt-in, logged as a warning. TLS 1.2 or later; `cert_file` without `key_file` (or the reverse) is refused. |
| Read-only | False | Pass `read_only=True` to refuse every mutating verb (PUT / DELETE / MKCOL / MOVE / COPY) with HTTP 403. |
| Path traversal | rejected | Every incoming path is normalised; `..` segments, segments with a backslash and segments that start with a drive (`C:`) are rejected with 400, and every joined path must stay below the root in the backend's own path flavour (Windows paths included). |
| Body cap | 8 GiB per request | Hard cap to keep a hostile client from exhausting RAM via Content-Length lies. |
| Body length | `Content-Length` or `Transfer-Encoding: chunked` | A chunked body (`curl -T -`, `rclone rcat`) is decoded as it streams, under the same cap. A PUT with neither is **411 Length Required** and the file stays as it was; both at once, another transfer coding, or broken chunk framing is refused (400 / 501) and keeps the file too. |
| aws-chunked | decoded | boto3 / aws-cli over HTTPS send `Content-Encoding: aws-chunked` (chunk frames with a trailing checksum, or chunk signatures): the object is the data inside the frames, exactly `x-amz-decoded-content-length` bytes; a body that does not match it is refused (400 / 411) and keeps the file. Chunk signatures and checksums are not checked, as no signature is. |
| HTTP | 1.1, keep-alive | A connection carries the next request only when the last body was read to its end (else it closes, with `Connection: close`: an unread body is never taken for a request); it waits at most 5 s for the next one, and stopping the server closes it at once. `Expect: 100-continue` is answered only after the token, the path, the read-only switch and the size checks passed - a refused PUT gets its final answer, never an invitation to send the body. Without the 100 boto3 and aws-cli waited 1 s per PUT. |

The reverse-server **does not** check AWS Signature V4 — it reads only
the access key id out of a signed request and compares it with the
token. So aws-cli / restic / rclone / boto3 work with
`AWS_ACCESS_KEY_ID=<token>` and any secret; curl and other plain HTTP
clients send `Authorization: Bearer <token>`.

For a fully signed S3 endpoint, run a real gateway (MinIO,
SeaweedFS, garage). The axross reverse-server is a **swiss-army
gateway, not a hardened S3 cluster**.

---

## What's implemented

A stat or a listing that fails is never answered as "not there": 404,
`NoSuchKey` and `NoSuchBucket` mean the path really is missing; a refusal
is 403 (`AccessDenied`), any other failure 500 (`InternalError`). A
folder that cannot be listed fails the PROPFIND or the ListObjects call
instead of showing up empty or leaving its keys out - sync clients
(rclone, `aws s3 sync --delete`) take an empty or shorter answer as
"deleted" and remove their copy. A WebDAV `COPY` onto an existing folder
is refused (409), never copied into it.

### S3

| Verb | Status |
|---|---|
| `GET /` (ListBuckets) | ✓ — top-level dirs of `root_path` are buckets |
| `GET /<bucket>?prefix=…&max-keys=…` (ListObjects) | ✓ |
| `GET /<bucket>/<key>` (GetObject) | ✓ |
| `HEAD /<bucket>/<key>` (HeadObject) | ✓ |
| `HEAD /<bucket>` (HeadBucket) | ✓ |
| `GET /<bucket>?location` (GetBucketLocation) | ✓ — the default region (an empty `LocationConstraint`) |
| `PUT /<bucket>/<key>` (PutObject) | ✓ — `If-None-Match: *` is honoured (412 `PreconditionFailed` when the key exists; checked before the write, not atomically with it); `If-Match` and an ETag in `If-None-Match` are 501, the ETags being synthetic |
| `PUT` with `x-amz-copy-source` (CopyObject, UploadPartCopy) | ✗ - 501 `NotImplemented`, nothing is written: `aws s3 mv` / `cp` between two keys and rclone's server-side copy fail instead of writing an empty copy (and `mv` then deleting the source) |
| Any other subresource (`?tagging`, `?acl`, `?versionId=`, `?retention`, `?legal-hold`, `?versioning`, ListParts `GET ?uploadId=`, …) on GET / HEAD / PUT / DELETE / POST | ✗ - 501 `NotImplemented`; the object is neither returned, replaced nor deleted. Presign parameters (`X-Amz-*`, `AWSAccessKeyId` / `Expires` / `Signature`), the SDKs' `x-id` and the ListObjects / GetObject parameters are served |
| `DELETE /<bucket>/<key>` (DeleteObject) | ✓ - 204 also for a key that does not exist; a delete the backend refuses is 403 `AccessDenied` (500 for any other failure), never 204 |
| `POST /<bucket>?delete` (DeleteObjects) | ✗ |
| Multipart upload (`POST ?uploads`, `PUT ?partNumber=&uploadId=`, `POST ?uploadId=`, `DELETE ?uploadId=`) | ✓ - see *Multipart upload* below; ListParts / ListMultipartUploads and UploadPartCopy are 501 |
| Versioning | ✗ |
| Tags / ACLs / Lifecycle | ✗ |
| Signed URLs / V4 signatures | ✗ - the signature is not checked; the access key id is compared with the token (see *Auth*) |

Path-style only. Virtual-host-style (`bucket.example.com/key`) is
not parsed. Single-PUT uploads cap at the body limit (8 GiB).

#### Multipart upload

Uploads above the SDKs' multipart threshold (8 MiB in boto3 and
aws-cli, `aws s3 cp` of any larger file) and restic's pack uploads use
it. The parts wait in a private local folder,
`$XDG_CACHE_HOME/axross/s3-multipart/` (mode 0700, refused when it is a
link or belongs to another user), until CompleteMultipartUpload streams
them, in the order listed, into the object through the same store as a
PUT: the old object stays until every byte arrived. The limits:

| Limit | Value |
|---|---|
| Uploads open at once | 16 (one more: 400 `InvalidRequest`) |
| Parts per upload | 10,000 (part numbers 1-10000) |
| Bytes per upload, and of all open uploads together | 8 GiB, the single-PUT cap (400 `EntityTooLarge` / 503 `SlowDown`, checked against the part's `Content-Length` before the body is read) |
| Idle upload | dropped with its parts after 1 hour without a request |
| Part list (Complete) | at most 4 MiB, no DTD / entities, part numbers ascending, every ETag the one returned for its part (else 400 `InvalidPart` / `MalformedXML`) |

An upload is bound to its bucket and key (another key with its id is
`NoSuchUpload`); a part uploaded twice replaces the first; parts not
listed in Complete are dropped. AbortMultipartUpload, Complete and
stopping the server remove the parts; folders an axross that ended
without stopping its server left are removed after a day. Complete
answers 200 at once and keeps the client waiting with a space every 10 s
while it assembles the object (as S3 does); a failure after that is an
`<Error>` in the 200, which the SDKs raise, and the upload stays, so
Complete can be tried again. The parts take local disk space up to the
cap: on a host whose temporary space is small, lower the clients'
part concurrency (`aws configure set default.s3.max_concurrent_requests
2`) or raise their threshold to send big files as one PUT
(`aws configure set default.s3.multipart_threshold 5GB`; boto3:
`TransferConfig(multipart_threshold=...)`).

### WebDAV

| Verb | Status |
|---|---|
| `OPTIONS` | ✓ |
| `GET` (file or HTML index for dirs) | ✓ |
| `HEAD` | ✓ |
| `PUT` | ✓ |
| `DELETE` | ✓ (recursive); 404 only when nothing is there, 403 when the backend refuses; `DELETE /` (the served root) is refused with 403 |
| `MKCOL` | ✓ - 405 on an existing resource, 409 when a parent is missing (never created implicitly) |
| `MOVE`, `COPY` | ✓ (uses backend native rename / copy where present); `Overwrite: F` honoured; moving the served root, or onto it, is refused with 403 |
| `PROPFIND` Depth 0/1 | ✓ |
| `PROPFIND` Depth infinity | answered like Depth 1 (the resource and its direct children) |
| `LOCK` / `UNLOCK` | ✓ as no-ops (returns plausible tokens) |
| `PROPPATCH` | ✗ |

`PROPFIND` returns the standard subset (`displayname`,
`getcontentlength`, `getlastmodified`, `resourcetype`). That covers
every client we've tested.

Lock support is **fake** — `LOCK` returns a plausible token but no
actual locking is enforced. macOS Finder and davfs2 require this
to mount; the trade-off is acceptable because the reverse-server is
single-user by construction.

---

## Threat model

The reverse-server is **a glue layer in front of an authenticated
backend you already opened**. Whatever the backend trusts, the
reverse-server trusts. Concretely:

* The backend's authentication has *already* happened. Once a client
  connects to the reverse-server, they have the access of whoever
  opened the backend. **Do not point this at a remote SFTP that holds
  data the local user must not access.**
* Tokens are compared with `hmac.compare_digest`. They travel in clear
  (Bearer header, Basic password or AWS access key id) — no replay
  protection, no nonce, no time bound. Treat them like any other
  shared secret: rotate on suspicion, never log them, transport over
  TLS if leaving localhost.
* TLS off loopback. A non-loopback bind serves HTTPS (`cert_file` +
  `key_file`) or is refused; with `allow_insecure_http=True` it is plain
  HTTP and anyone on the path reads the token. Alternatives: a TLS proxy
  (nginx, caddy) in front of a loopback bind, or an SSH tunnel
  (`-L 9000:127.0.0.1:9000`) so the only thing the LAN sees is your SSH
  client. Client certificates (mTLS) are not checked; the token is the
  authentication.
* No rate limiting. A hostile client can DoS the backend you're
  serving. The reverse-server is for cooperative environments.

When in doubt: bind to localhost, use an SSH tunnel for remote
access, and switch to a real S3 gateway (MinIO, SeaweedFS) when the
client population grows beyond "me".

---

## See also

* [`docs/MULTI_SYSTEM.md`](MULTI_SYSTEM.md) — multi-system verbs that consume axross-opened backends.
* [`docs/OPSEC.md`](OPSEC.md) — what the axross client reveals to remote servers (the symmetric question).
* [`docs/SCRIPTING_REFERENCE.md`](SCRIPTING_REFERENCE.md) — full `axross.*` API reference.
