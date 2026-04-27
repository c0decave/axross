# Proxy Support per Protocol

How a ``ProxyConfig`` (``proxy_type``, ``proxy_host``, ``proxy_port``,
``proxy_username``, ``proxy_password``) set on a connection profile
actually affects the network path for each backend.

Unlike the previous version of this document, every TCP-based
backend now genuinely honours the per-profile proxy fields. Only
kernel-level transports (NFS, iSCSI) genuinely cannot be tunnelled
through a userspace proxy; everything else has a real hook in
either the library API, a subclass, or a scoped monkey-patch.

## Verdict table

| Protocol | SOCKS4 | SOCKS5 | HTTP CONNECT | Auth | Mechanism |
|---|:-:|:-:|:-:|:-:|---|
| **SFTP / SCP** | ✅ | ✅ | ✅ | ✅ | `paramiko.Transport(sock)` with `core.proxy.create_proxy_socket` |
| **WebDAV** | ✅ | ✅ | ✅ | ✅ | `requests.Session.proxies = {"http(s)": "socks5h://…"}` |
| **Telnet** | ✅ | ✅ | ✅ | ✅ | custom raw-socket transport, `create_proxy_socket` |
| **FTP / FTPS** | ✅ | ✅ | ✅ | ✅ | subclass override of `ftplib.FTP.connect` to swap in a proxied socket. **Active mode incompatible** — auto-forces PASV when a proxy is set. |
| **SMB / CIFS / DFS-N** | ✅ | ✅ | ✅ | ✅ | scoped monkey-patch of `socket.create_connection` during `smbclient.register_session` (process-global lock serialises across threads) |
| **IMAP / IMAPS** | ✅ | ✅ | ✅ | ✅ | `_ProxyIMAP4` / `_ProxyIMAP4_SSL` subclasses overriding `_create_socket` |
| **S3-compatible** | ✅ | ✅ | ✅ | ✅ | `botocore.config.Config(proxies={...})` |
| **Azure Blob / Files** | ✅ | ✅ | ✅ | ✅ | custom `azure.core.pipeline.transport.RequestsTransport` with pre-proxied `requests.Session` |
| **OneDrive / SharePoint** | ✅ | ✅ | ✅ | ✅ | direct `self._http.proxies = {…}` on the MSAL-attached session |
| **Google Drive** | ✅ | ✅ | ✅ | ✅ | `httplib2.Http(proxy_info=ProxyInfo(...))` wrapped in `google_auth_httplib2.AuthorizedHttp` |
| **Dropbox** | ✅ | ✅ | ✅ | ✅ | post-construction patch of the SDK's internal `requests.Session` (`session.proxies`) |
| **Exchange (EWS)** | ✅ | ✅ | ✅ | ✅ | post-Account patch of `protocol._session_pool` + override of `protocol.create_session`. **Autodiscover incompatible** — `autodiscover=True` + proxy is rejected at construction (the autodiscover step bypasses the session pool). |
| **WinRM** | ✅ | ✅ | ✅ | ✅ | walks the pywinrm `Session → Protocol → Transport → requests.Session` chain and sets `.proxies` |
| **Rsync (daemon)** | ✅ | ✅ | ✅ | ⚠ no auth | `RSYNC_CONNECT_PROG` env var with `nc -X 5 -x …` (rsync 3.0+, OpenBSD nc required). Proxy auth is not propagated by nc — use rsync-over-SSH if your proxy needs creds. |
| **Rsync (over SSH)** | ✅ | ✅ | ✅ | ✅ | `-o ProxyCommand=nc -X 5 -x …` injected into the `-e ssh` arg |
| **ADB (Android, TCP)** | ✅ | ✅ | ✅ | ✅ | scoped monkey-patch of `socket.create_connection` during `AdbDeviceTcp.connect` |
| **ADB (Android, USB)** | ❌ | ❌ | ❌ | — | USB transport has no TCP layer. Setting a proxy on a USB profile raises a clear error rather than silently ignoring it. |
| **MTP (Android)** | ❌ | ❌ | ❌ | — | external FUSE mounter, USB-only — not a network transport. |
| **POP3 / POP3S** | ✅ | ✅ | ✅ | ✅ | `_ProxyPOP3` / `_ProxyPOP3_SSL` subclasses overriding `_create_socket` (read-only backend). |
| **TFTP** | ❌ | ❌ | ❌ | — | UDP transport. SOCKS5 UDP-ASSOCIATE is rare in production proxies; HTTP CONNECT is TCP-only. |
| **NFS** | ❌ | ❌ | ❌ | — | kernel mount; not proxiable from user space. |
| **iSCSI** | ❌ | ❌ | ❌ | — | kernel initiator; not proxiable from user space. |
| **RamFS** | — | — | — | — | in-process; no network at all, proxy fields N/A. |

### Legend

- **✅** — profile's proxy setting takes effect for every byte on the wire.
- **❌** — protocol genuinely cannot be tunnelled through a userspace proxy.
- **⚠** — supported with a documented limitation (auth, autodiscover, mode).

## Implementation overview

### `core.proxy` central helpers

Every backend now reaches the proxy via one of three primitives:

1. **`create_proxy_socket(profile, host, port)`** — returns a
   pre-connected `socket.socket` with the SOCKS / HTTP-CONNECT
   handshake already done. Used by SSH, SCP, Telnet, IMAP, FTP.
2. **`build_requests_proxies(...)`** — returns a `{"http": ...,
   "https": ...}` dict ready to assign to a `requests.Session`. SOCKS5
   uses the `socks5h://` scheme so DNS resolution happens at the
   proxy. IPv6 proxy hosts are bracketed. Refuses to drop a password
   that has no username (would silently leak the secret nowhere).
   Used by WebDAV, OneDrive, Dropbox, Exchange, WinRM, S3, Azure.
3. **`patched_create_connection(profile)`** — context manager that
   swaps `socket.create_connection` for a proxied wrapper for the
   duration of the call, with a process-global lock so concurrent
   patches across threads can't strand each other's replacement.
   Used by SMB and ADB, which use libraries that have no other hook.

### SSRF guard

Regardless of which path the proxy goes through, the proxy host
itself is subject to the same Defense-in-Depth Layer 6 guard:
loopback, link-local, and RFC1918 addresses are refused unless the
user explicitly sets `AXROSS_ALLOW_PRIVATE_PROXY=1` in the
environment. Cloud metadata endpoints (AWS 169.254.169.254 etc.)
are deny-by-default to stop a hostile profile from making us proxy
through the metadata service.

### Configuration

All backends accept the same five kwargs in their constructor:

```
proxy_type      "none" | "socks4" | "socks5" | "http"
proxy_host      "proxy.example"
proxy_port      1080
proxy_username  ""        # optional
proxy_password  ""        # optional, retrieved from keyring
```

The `ConnectionManager._create_session` path injects them
automatically from the profile via `_proxy_kwargs(profile)` — there
is no per-protocol special-casing of which fields to pass.

The session-key (used for connection pool reuse) includes
`proxy_type`, `proxy_host`, `proxy_port`, and `proxy_username`, so
two profiles to the same host with different proxies get separate
sessions.

## Caveats and edge cases

### FTP

FTP **active mode** has the server dial back to the client; this
cannot be tunnelled through an outbound-only proxy. When a profile
configures both a proxy and `ftp_passive=False`, axross logs a
warning and forces PASV. PASV-mode FTPS also works through the
proxy because the data-connection target the server returns is
typically reachable through the same proxy as the control channel.

### Exchange autodiscover

Exchangelib's autodiscover step uses a static helper that bypasses
the per-Account session pool — meaning a proxy attached after
`Account()` would miss the autodiscover bytes. To prevent silent
leakage, axross **rejects** the combination at construction time:

```
ExchangeSession(..., autodiscover=True, proxy_type="socks5", ...)
# → OSError: Exchange: proxy + autodiscover=True is not supported …
```

Use `autodiscover=False` with an explicit `server="outlook.office365.com"`
(or your on-prem EWS endpoint) when proxying.

### Rsync auth

The OpenBSD `nc -X` flags accept `-x host:port` but most builds do
not propagate proxy authentication to the SOCKS / HTTP handshake. If
your proxy requires auth, use **rsync over SSH** (the `ssh -o
ProxyCommand=...` path) instead of native rsync-daemon mode — the
ssh command-line accepts proxy creds via the standard
`username:password@host` form in `ProxyCommand`.

### ADB USB mode

ADB has two transports: TCP (`adb tcpip 5555`, network-level) and
USB (no network at all). Setting a proxy on a USB-mode profile is
nonsensical and is rejected at construction with a clear error
rather than silently ignored.

### NFS / iSCSI / MTP

These are kernel-level mounts (NFS via `mount -t nfs`, iSCSI via
`iscsiadm`, MTP via an external FUSE mounter). Network IO happens
entirely in kernel space and is invisible to a userspace SOCKS
proxy. If you need to tunnel them, do it at the OS level (e.g.
route the entire process or container through a proxied network
namespace).

## How to test

The host test suite includes a `ProxySupportTests` class
(`tests/test_hardening_regressions.py`) that:

- Verifies `build_requests_proxies` URL formation, IPv6 brackets,
  credential URL-encoding, password-without-username refusal, and
  the SSRF guard.
- Verifies `patched_create_connection` restores `socket.create_connection`
  after a successful run, after an exception inside the context,
  and after concurrent threaded use.
- Verifies every backend session ctor accepts the `proxy_*` kwargs
  in its signature.
- Verifies the rsync helpers produce well-formed
  `RSYNC_CONNECT_PROG` and ssh `ProxyCommand` strings, including
  IPv6 bracketing.
- Verifies ADB USB mode + proxy raises, Exchange autodiscover +
  proxy raises.

For end-to-end proxy tests against real protocols there is a
`socks-proxy` and `http-proxy` container in `tests/docker/` —
exercised by `test_protocols.py` Section 21d. Bring up the lab
(`cd tests/docker && docker compose up -d --build`) and the proxy
tests run automatically.
