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
```

In another terminal:

```bash
$ export AWS_ACCESS_KEY_ID=anything
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

Folders represent IMAP folders, files represent messages — the same
view axross gives you internally, now visible to every tool that
speaks WebDAV.

---

## OPSEC defaults

| Default | Value | Why |
|---|---|---|
| Bind | `127.0.0.1` | Listening on a public interface requires `bind="0.0.0.0"` explicitly. A stray reverse-server should never accidentally expose your remote SFTP to the LAN. |
| Auth | none on localhost | Pass `auth_token="…"` for `Authorization: Bearer <token>`. Non-local binds such as `0.0.0.0` are **refused** unless an auth token is set. |
| Read-only | False | Pass `read_only=True` to refuse every mutating verb (PUT / DELETE / MKCOL / MOVE / COPY) with HTTP 403. |
| Path traversal | rejected | Every incoming path is normalised; `..` segments are rejected with 400. |
| Body cap | 8 GiB per request | Hard cap to keep a hostile client from exhausting RAM via Content-Length lies. |

The reverse-server **does not** do AWS Signature V4 — the path-style
endpoint is bearer-token-authed only. restic / rclone / aws-cli all
accept either dummy credentials (when no auth) or a custom
`Authorization` header (`--header "Authorization: Bearer …"` for
restic; `--header_upload Authorization=…` for rclone).

For a fully signed S3 endpoint, run a real gateway (MinIO,
SeaweedFS, garage). The axross reverse-server is a **swiss-army
gateway, not a hardened S3 cluster**.

---

## What's implemented

### S3

| Verb | Status |
|---|---|
| `GET /` (ListBuckets) | ✓ — top-level dirs of `root_path` are buckets |
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

Path-style only. Virtual-host-style (`bucket.example.com/key`) is
not parsed. Single-PUT uploads cap at the body limit (8 GiB);
larger objects need multipart, which we don't speak yet.

### WebDAV

| Verb | Status |
|---|---|
| `OPTIONS` | ✓ |
| `GET` (file or HTML index for dirs) | ✓ |
| `HEAD` | ✓ |
| `PUT` | ✓ |
| `DELETE` | ✓ (recursive) |
| `MKCOL` | ✓ |
| `MOVE`, `COPY` | ✓ (uses backend native rename / copy where present) |
| `PROPFIND` Depth 0/1 | ✓ |
| `PROPFIND` Depth infinity | ✗ — declines |
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
* Bearer tokens are compared with `hmac.compare_digest`. They are
  passed as plain `Authorization: Bearer <token>` — no replay
  protection, no nonce, no time bound. Treat them like any other
  shared secret: rotate on suspicion, never log them, transport over
  TLS if leaving localhost.
* No TLS termination. If you bind to `0.0.0.0` you should sit a TLS
  proxy (nginx, caddy) in front, or tunnel via SSH `-L 9000:127.0.0.1:9000`
  so the only thing the LAN sees is your SSH client.
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
