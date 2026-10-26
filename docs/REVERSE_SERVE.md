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

## OPSEC defaults

| Default | Value | Why |
|---|---|---|
| Bind | `127.0.0.1` | Listening on a public interface requires `bind="0.0.0.0"` explicitly. A stray reverse-server should never accidentally expose your remote SFTP to the LAN. |
| Auth | a token, on localhost too | A loopback server generates one (`srv.auth_token`); `auth_token="…"` sets your own. Clients send it as `Authorization: Bearer <token>`, as the Basic password (WebDAV clients are asked for it), or as the AWS access key id (aws-cli, restic, boto3). `auth_token=None` turns auth off, on loopback only: every local user of the host can then reach the backend. Non-local binds such as `0.0.0.0` are **refused** without an explicit token. |
| Read-only | False | Pass `read_only=True` to refuse every mutating verb (PUT / DELETE / MKCOL / MOVE / COPY) with HTTP 403. |
| Path traversal | rejected | Every incoming path is normalised; `..` segments, segments with a backslash and segments that start with a drive (`C:`) are rejected with 400, and every joined path must stay below the root in the backend's own path flavour (Windows paths included). |
| Body cap | 8 GiB per request | Hard cap to keep a hostile client from exhausting RAM via Content-Length lies. |

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

### S3

| Verb | Status |
|---|---|
| `GET /` (ListBuckets) | ✓ — top-level dirs of `root_path` are buckets |
| `GET /<bucket>?prefix=…&max-keys=…` (ListObjects) | ✓ |
| `GET /<bucket>/<key>` (GetObject) | ✓ |
| `HEAD /<bucket>/<key>` (HeadObject) | ✓ |
| `HEAD /<bucket>` (HeadBucket) | ✓ |
| `PUT /<bucket>/<key>` (PutObject) | ✓ |
| `DELETE /<bucket>/<key>` (DeleteObject) | ✓ - 204 also for a key that does not exist; a delete the backend refuses is 403 `AccessDenied` (500 for any other failure), never 204 |
| `POST /<bucket>?delete` (DeleteObjects) | ✗ |
| Multipart upload | ✗ |
| Versioning | ✗ |
| Tags / ACLs / Lifecycle | ✗ |
| Signed URLs / V4 signatures | ✗ - the signature is not checked; the access key id is compared with the token (see *Auth*) |

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
