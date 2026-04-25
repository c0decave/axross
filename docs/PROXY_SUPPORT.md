# Proxy Support per Protocol

How a ``ProxyConfig`` (``proxy_type``, ``proxy_host``, ``proxy_port``,
``proxy_username``) set on a ConnectionProfile actually affects the
network path for each backend.

Stand: commit `d0e45de` on `origin/main`.

## Verdict Table

| Protocol | Profile proxy honoured? | SOCKS4 | SOCKS5 | HTTP CONNECT | Scope | Notes |
|---|:-:|:-:|:-:|:-:|---|---|
| **SFTP** | ✅ full | ✅ | ✅ | ✅ | entire SSH channel | paramiko.Transport gets a pre-proxied socket from `create_proxy_socket`. |
| **SCP** | ✅ full | ✅ | ✅ | ✅ | entire SSH channel | same as SFTP. |
| FTP / FTPS | ⚠ ignored | — | — | — | — | ``ftplib`` has no proxy hook. Setting a proxy on the profile does nothing. |
| SMB | ⚠ ignored | — | — | — | — | ``smbprotocol`` takes no proxy kwarg. |
| WebDAV | ⚠ ignored | — | — | — | — | ``webdavclient3`` has no per-session proxy; the profile field is dropped. |
| S3 | ⚙ env-inherited | — | — | ✅ | via env | boto3 reads ``HTTPS_PROXY`` / ``HTTP_PROXY`` from the process env, NOT from the profile. |
| Rsync | ⚠ ignored | — | — | — | — | shell-out; profile proxy not plumbed. Use SSH-mode rsync + SFTP profile if you need proxying. |
| NFS | ⚠ ignored | — | — | — | — | kernel-level mount; no userspace proxy. |
| iSCSI | ⚠ ignored | — | — | — | — | kernel initiator; no userspace proxy. |
| IMAP | ⚠ ignored | — | — | — | — | ``imaplib`` has no proxy hook. |
| Telnet | ⚠ ignored | — | — | — | — | custom raw-socket transport; no proxy plumbing. |
| Azure Blob | ⚙ env-inherited | — | — | ✅ | via env | ``azure-storage-blob`` respects ``HTTPS_PROXY`` process-wide only. |
| Azure Files | ⚙ env-inherited | — | — | ✅ | via env | same as Azure Blob. |
| OneDrive / SharePoint | ⚙ env-inherited | — | — | ✅ | via env | ``msal`` + ``requests`` read ``HTTPS_PROXY``. |
| Dropbox | ⚙ env-inherited | — | — | ✅ | via env | dropbox SDK reads ``HTTPS_PROXY``. |
| Google Drive | ⚙ env-inherited | — | — | ✅ | via env | google-api-client reads ``HTTPS_PROXY``. |

### Legend

- **✅ full** — profile's proxy setting takes effect for every byte on the wire.
- **⚙ env-inherited** — the library ignores the profile but reads the OS
  environment variables (``HTTPS_PROXY`` / ``HTTP_PROXY`` / scheme-specific).
  Set those **before** starting axross if you need proxying for these.
- **⚠ ignored** — axross silently drops the proxy fields. A connect
  now logs a warning so this isn't invisible (see
  `core/connection_manager.py`).

## How to proxy cloud backends today

Because S3 / Azure / OneDrive / Dropbox / Google Drive only honour
process-env proxies:

```bash
HTTPS_PROXY=http://proxy.example.local:8080 axross
# or
HTTP_PROXY=socks5://127.0.0.1:1080 axross
```

Per-profile proxying for these would require shipping a custom HTTP
adapter per SDK — future work; see Phase 5 backlog.

## SSRF guard

Regardless of backend, the proxy host itself is subject to the
Defense-in-Depth Layer 6 guard: RFC1918 / loopback / link-local
addresses are refused unless ``AXROSS_ALLOW_PRIVATE_PROXY=1`` is
set in the environment. See [core/proxy.py](../core/proxy.py).
