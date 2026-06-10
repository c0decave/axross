# Proxy Support per Protocol

How a ``ProxyConfig`` (``proxy_type``, ``proxy_host``, ``proxy_port``,
``proxy_username``, ``proxy_password``) set on a connection profile
actually affects the network path for each backend.

The rule is deliberately strict: a protocol is marked supported only
when axross can wire the configured profile proxy into the transport
itself. Backends without a reliable SOCKS/HTTP-CONNECT hook now emit
a warning instead of silently ignoring proxy fields.

## Verdict table

| Protocol | SOCKS4 | SOCKS5 | HTTP CONNECT | Auth | Mechanism |
|---|:-:|:-:|:-:|:-:|---|
| **SFTP / SCP** | ✅ | ✅ | ✅ | ✅ | `paramiko.Transport(sock)` with `core.proxy.create_proxy_socket` |
| **WebDAV** | ✅ | ✅ | ✅ | ✅ | `requests.Session.proxies = {"http(s)": "socks5h://…"}` |
| **Telnet** | ✅ | ✅ | ✅ | ✅ | custom raw-socket transport, `create_proxy_socket` |
| **Cisco Telnet** | ✅ | ✅ | ✅ | ✅ | same raw Telnet transport as `TelnetSession` |
| **FTP / FTPS** | ✅ | ✅ | ✅ | ✅ | subclass override of `ftplib.FTP.connect` to swap in a proxied socket. **Active mode incompatible** — auto-forces PASV when a proxy is set. |
| **SMB / CIFS / DFS-N** | ✅ | ✅ | ✅ | ✅ | scoped monkey-patch of `socket.create_connection` during `smbclient.register_session` (process-global lock serialises across threads) |
| **IMAP / IMAPS** | ✅ | ✅ | ✅ | ✅ | `_ProxyIMAP4` / `_ProxyIMAP4_SSL` subclasses overriding `_create_socket` |
| **POP3 / POP3S** | ✅ | ✅ | ✅ | ✅ | `_ProxyPOP3` / `_ProxyPOP3_SSL` subclasses overriding `_create_socket` (read-only backend). |
| **NNTP / NNTPS** | ✅ | ✅ | ✅ | ✅ | own NNTP wire client opens via `create_proxy_socket` before optional TLS / STARTTLS |
| **Gopher / Gophers** | ✅ | ✅ | ✅ | ✅ | own Gopher socket helper uses `create_proxy_socket`, then optional TLS |
| **PJL** | ✅ | ✅ | ✅ | ✅ | raw JetDirect/PJL socket helper uses `create_proxy_socket` |
| **S3-compatible** | ❌ | ❌ | ✅ | ✅ | `botocore.config.Config(proxies={...})`; botocore does not reliably accept SOCKS proxy URLs, so axross rejects SOCKS with a warning. |
| **Azure Blob / Files** | ✅ | ✅ | ✅ | ✅ | custom `azure.core.pipeline.transport.RequestsTransport` with pre-proxied `requests.Session` |
| **OneDrive / SharePoint** | ⚠ | ⚠ | ⚠ | ✅ | Graph calls use a proxied `requests.Session`; MSAL receives the same proxy dict. First-time interactive browser consent is outside axross and may use browser/system proxy settings. |
| **Google Drive** | ⚠ | ⚠ | ⚠ | ✅ | OAuth token/refresh uses a proxied `requests` transport; Drive API uses `httplib2.Http(proxy_info=ProxyInfo(...))` via `AuthorizedHttp`. First-time browser consent is outside axross. |
| **Dropbox** | ⚠ | ⚠ | ⚠ | ⚠ | Dropbox API calls use the SDK's internal proxied `requests.Session` and fail closed if the hook disappears; first-time browser consent is external, and the no-redirect OAuth code exchange is SDK-owned. |
| **Exchange (EWS)** | ⚠ | ⚠ | ⚠ | ✅ | constructor-only support with `autodiscover=False` and explicit `server=...`; saved profiles warn because they do not expose those fields yet. Session-pool proxy hooks fail closed if they cannot be verified. |
| **WinRM** | ✅ | ✅ | ✅ | ✅ | walks the pywinrm `Session → Protocol → Transport → requests.Session` chain and sets `.proxies`; fails closed if a configured proxy cannot be attached. |
| **Rsync (daemon)** | ✅ | ✅ | ✅ | ⚠ username only | `RSYNC_CONNECT_PROG` env var with `nc -X 5 -P user -x …` (rsync 3.0+, OpenBSD nc required). Proxy passwords cannot be passed non-interactively and are rejected. |
| **Rsync (over SSH)** | ✅ | ✅ | ✅ | ⚠ username only | `-o ProxyCommand=nc -X 5 -P user -x …` injected into the `-e ssh` arg. Proxy passwords cannot be passed non-interactively and are rejected. |
| **ADB (Android, TCP)** | ✅ | ✅ | ✅ | ✅ | scoped monkey-patch of `socket.create_connection` during `AdbDeviceTcp.connect` |
| **ADB (Android, USB)** | ❌ | ❌ | ❌ | — | USB transport has no TCP layer. Setting a proxy on a USB profile raises a clear error rather than silently ignoring it. |
| **MTP (Android)** | ❌ | ❌ | ❌ | — | external FUSE mounter, USB-only — not a network transport. |
| **TFTP** | ❌ | ❌ | ❌ | — | UDP transport. SOCKS5 UDP-ASSOCIATE is rare in production proxies; HTTP CONNECT is TCP-only. |
| **NFS** | ❌ | ❌ | ❌ | — | kernel mount; not proxiable from user space. |
| **iSCSI** | ❌ | ❌ | ❌ | — | kernel initiator; not proxiable from user space. |
| **RamFS** | — | — | — | — | in-process; no network at all, proxy fields N/A. |
| **SQLite** | — | — | — | — | local file backend; proxy fields N/A. |
| **PostgreSQL / Redis / MongoDB / LDAP** | ❌ | ❌ | ❌ | — | library transports are not currently wrapped by `core.proxy`; setting proxy kwargs logs a warning. |
| **Git / SVN / rsh / WMI / SLP** | ❌ | ❌ | ❌ | — | subprocess/library transports are not uniformly proxyable in axross; setting proxy kwargs logs a warning. |

### Legend

- **✅** — profile's proxy setting takes effect for every byte on the wire.
- **❌** — protocol genuinely cannot be tunnelled through a userspace proxy.
- **⚠** — supported with a documented limitation (auth, OAuth bootstrap, autodiscover, mode).

## Implementation overview

### `core.proxy` central helpers

Every backend now reaches the proxy via one of three primitives:

1. **`create_proxy_socket(profile, host, port)`** — returns a
   pre-connected `socket.socket` with the SOCKS / HTTP-CONNECT
   handshake already done. Used by SSH, SCP, Telnet, Cisco-Telnet,
   IMAP, POP3, NNTP, FTP, Gopher and PJL.
2. **`build_requests_proxies(...)`** — returns a `{"http": ...,
   "https": ...}` dict ready to assign to a `requests.Session`. SOCKS5
   uses the `socks5h://` scheme so DNS resolution happens at the
   proxy. IPv6 proxy hosts are bracketed. Refuses to drop a password
   that has no username (would silently leak the secret nowhere), and
   refuses `proxy_port=0` / out-of-range ports whenever a proxy host
   is set.
   Axross-owned sessions also set `trust_env=False` so `HTTP_PROXY` /
   `HTTPS_PROXY` from the process environment cannot silently override a
   profile route. Used by WebDAV, OneDrive, Dropbox, Exchange, WinRM,
   Azure and HTTP-CONNECT S3.
3. **`patched_create_connection(profile)`** — context manager that
   swaps `socket.create_connection` for a proxied wrapper for the
   duration of the call, with a process-global lock so concurrent
   patches across threads can't strand each other's replacement.
   A configured proxy port is validated before the monkey-patch is
   installed, so malformed settings fail before any direct connect can
   happen.
   Used by SMB, DFS-N and ADB, which use libraries that have no
   better hook.

### SSRF guard

Regardless of which path the proxy goes through, the proxy host
itself is subject to the same Defense-in-Depth Layer 6 guard:
loopback, link-local, and RFC1918 addresses are refused unless the
user explicitly sets `AXROSS_ALLOW_PRIVATE_PROXY=1` in the
environment. Cloud metadata endpoints (AWS 169.254.169.254 etc.)
are deny-by-default to stop a hostile profile from making us proxy
through the metadata service.

### Configuration

Proxy-capable direct constructors, and unsupported direct constructors
that accept proxy metadata for warning purposes, use the same five
kwargs:

```
proxy_type      "none" | "socks4" | "socks5" | "http"
proxy_host      "proxy.example"
proxy_port      1080
proxy_username  ""        # optional
proxy_password  ""        # optional, retrieved from keyring
```

The `ConnectionManager._create_session` path injects them
automatically from the profile via `_proxy_kwargs(profile)` for
profile-routable proxy-capable backends. Protocols that cannot honour
those fields call `_warn_unsupported_proxy(profile)` so the user gets
a warning instead of a silent direct connection.

When `proxy_type != "none"`, `proxy_host` is mandatory and
`proxy_port` must be `1..65535`. Port `0` means "unset" in stored
profiles and is accepted only while the proxy is disabled. A
half-configured proxy fails closed instead of becoming a direct
connection.

The session-key (used for connection pool reuse) includes the
effective proxy route plus protocol-specific transport options
(for example FTPS verification, S3 endpoint, POP3 TLS, ADB mode and
Telnet NAWS), so two profiles to the same host with different route
or backend behaviour get separate sessions.

## Caveats and edge cases

### FTP

FTP **active mode** has the server dial back to the client; this
cannot be tunnelled through an outbound-only proxy. When a profile
configures both a proxy and `ftp_passive=False`, axross logs a
warning and forces PASV. PASV-mode FTPS also works through the
proxy because the data-connection target the server returns is
typically reachable through the same proxy as the control channel.
`MLSD`, `NLST`, `RETR` and `STOR` all use the same proxied PASV
data-channel override.

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

### OAuth browser consent

OneDrive / SharePoint, Google Drive and Dropbox all have a first-time
browser consent step. Axross can proxy the API calls it owns and, where
the SDK exposes a hook, the token exchange/refresh request. The browser
window itself is not an axross transport, so it may use the browser's
own or the OS' proxy settings. When a profile proxy is configured and
an interactive OAuth bootstrap is needed, axross logs a WARNING for this
limitation instead of implying that the external browser is tunnelled.

For repeat connections using cached tokens, API traffic goes through the
documented backend proxy hook.

### S3 SOCKS

S3 is intentionally **HTTP CONNECT only** in axross. The boto3 /
botocore proxy path accepts ordinary HTTP proxy URLs, but SOCKS URLs
are not handled reliably by botocore's transport stack. When a saved
profile or direct `S3Session` configures `proxy_type="socks4"` or
`"socks5"`, axross logs a warning and raises a clear `OSError`.

Use a local SOCKS-to-HTTP relay if you need to reach S3 through an
upstream SOCKS proxy.

### Unsupported backends

Backends in the unsupported rows above call either
`_warn_unsupported_proxy(profile)` (saved profiles) or
`core.proxy.warn_unsupported_proxy(...)` (direct construction paths
that accept proxy metadata, either explicitly or via `**kwargs`). The
expected behaviour is: no silent direct traffic when a user believes a
proxy is active. The connection may still be made directly, but it is
logged at WARNING level first; optional-dependency failures happen
after that warning.

### Rsync auth

The OpenBSD `nc -X` flags accept `-x host:port` and, on supported
builds, `-P proxy_username`. They do **not** provide a safe
non-interactive `proxy_password` flag. Axross therefore passes
`proxy_username` when available, but rejects `proxy_password` for both
rsync-daemon and rsync-over-SSH mode instead of pretending it was used.

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
  after concurrent threaded use, and refuses an unset proxy port
  before installing the patch.
- Verifies half-configured proxies (`proxy_type` set without
  `proxy_host`) fail closed before a direct connection can be opened.
- Verifies profile-like proxy application uses `proxy_host`, not the
  target `host`.
- Verifies every proxy-capable session ctor accepts the `proxy_*`
  kwargs, and unsupported direct constructors warn before continuing
  or before optional-dependency errors.
- Verifies requests-like SDK sessions disable process-environment proxy
  inheritance (`trust_env=False`) before applying the profile proxy.
- Verifies OAuth browser bootstrap warnings for OneDrive / SharePoint
  and Google Drive.
- Verifies the rsync helpers produce well-formed
  `RSYNC_CONNECT_PROG` and ssh `ProxyCommand` strings, including
  IPv6 bracketing and shell-shaped host rejection.
- Verifies ADB USB mode + proxy raises, Exchange autodiscover +
  proxy raises, and Exchange / WinRM / Dropbox / Google Drive SDK
  hooks fail closed when a configured proxy cannot be attached.

For end-to-end proxy tests against real protocols there is a
`socks-proxy` (SOCKS4/SOCKS5) and `http-proxy` (HTTP proxy/CONNECT)
container in `tests/docker/` — exercised by `test_protocols.py`
Section 21d. That section has one direct smoke per proxy protocol
(SOCKS4, SOCKS5, HTTP CONNECT), then a backend-level proxy matrix for
WebDAV, FTP, FTPS, SMB, IMAP, POP3, Telnet, Cisco-Telnet, Rsync,
Azure Blob, and S3. S3 pins SOCKS4/SOCKS5 as explicit rejection tests
and HTTP as the supported proxy path. Bring up the lab
(`cd tests/docker && docker compose up -d --build`) and run the proxy
subset with:

```
pytest tests/test_protocols.py -k "proxy_protocol or proxy_matrix or via_socks5_proxy or via_http_connect_proxy"
```

Optional internet smokes for all three proxy protocols are gated behind
`AXROSS_LIVE_INTERNET_PROXY_TESTS=1` so air-gapped CI does not flap.
