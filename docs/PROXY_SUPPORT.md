# Proxy Support per Protocol

How a ``ProxyConfig`` (``proxy_type``, ``proxy_host``, ``proxy_port``,
``proxy_username``, ``proxy_password``) set on a connection profile
actually affects the network path for each backend.

The rule is deliberately strict: a protocol is marked supported only
when axross can wire the configured profile proxy into the transport
itself. A backend that touches the network but cannot honour the proxy
**fails closed** (`ProxyUnsupportedError`, an `OSError`) instead of
connecting directly; removing the proxy from the profile is the explicit
opt-out. Backends with no network transport at all (RamFS, SQLite, MTP)
only log that the setting has no effect, because nothing can leak.

## Proxy kinds

`proxy_type` is one string: transport, optionally `+` an authentication
scheme (HTTP kinds only).

| Kind | Meaning |
|---|---|
| `socks4` | SOCKS4. Host names are sent as SOCKS4a; a server that only speaks plain SOCKS4 (e.g. Dante) needs an IPv4 address as target |
| `socks5` | SOCKS5 (host names resolved at the proxy), optional username/password. Exception: a profile that pins the address family (IPv4 / IPv6) resolves the target locally to pick that family |
| `http` | HTTP CONNECT; Basic when a username is set |
| `https` | HTTP CONNECT over **TLS to the proxy**; certificate verified against `ca_file`, else the system store |
| `http+basic` / `+ntlm` / `+negotiate` / `+kerberos` | explicit scheme; `https+…` likewise |

NTLM and Negotiate use `pyspnego` (already shipped with SMB support).
Kerberos needs the optional `gssapi` / `krb5` libraries, which the
prebuilt binaries do not bundle; without them the error says so.

## Default proxy, bypass list, PAC

*Tools → Network & Proxy…* stores one default (`~/.config/axross/proxy.json`,
mode 0600; the password lives in the keyring entry `__default_proxy__`,
or -- without *Save password in keyring* -- in memory until axross exits):
kind, endpoint, credentials, CA file, a **bypass list** and an optional
**PAC** location.

Each profile chooses how it uses it (`proxy_mode`):

| Mode | Effect |
|---|---|
| `custom` | the profile's own proxy fields (what every profile did before; no proxy fields means direct) |
| `default` | the default above: bypass list first, then PAC if set, else the fixed endpoint |
| `none` | always direct, even when a default exists |

A ProxyCommand (SSH jump host) belongs to `custom`; `default` and `none`
ignore one left on the profile.

Profiles that exist before the upgrade stay `custom`, i.e. they do **not**
silently inherit the default. *Use for all profiles…* switches every
proxy-capable profile to `default` in one step, except profiles that
reach their host through a ProxyCommand.

- **Bypass entries**: `host`, `.domain` / `*.domain` (the domain and its
  subdomains), IP literals, CIDR blocks, `<local>`, `*`, each optionally
  `:port`. An entry with a port matches only that port; a profile without
  a port is judged by its protocol's default port. A host name is never
  resolved to test a CIDR (that would be a DNS lookup outside the proxy).
- **PAC** (`http(s)` URL or file): evaluated by a restricted interpreter
  (`core/pac.py`) -- no `eval`, no file or network access of its own,
  step / depth / string limits (64 KiB per string, however it is built),
  the usual helper functions. As in browsers, `dnsResolve`, `isInNet` and
  `isResolvable` look the name up with the local resolver. Results are cached for 300 s, and the last good
  script is kept when a refresh fails. A script that cannot be fetched or
  evaluated **fails the connection closed**; it never falls back to
  direct. For PAC results the authentication scheme comes from the
  default's kind (`http+ntlm` makes a PAC `PROXY` entry authenticate with
  NTLM). The default's credentials go to a proxy the PAC names only when
  the PAC is a local file or an `https` URL, or when it names the
  configured proxy itself: a PAC fetched over plain `http` can be rewritten
  on the way, and must not be able to point the password at another host.
- **Test proxy** opens a real tunnel to a target you name and reports the
  stage that failed (`config`, `proxy`, `tls`, `auth`, `tunnel`).
- Each pane shows its route (`via SOCKS5 host:port`; tooltip: why, never a
  password).
- `scripting.open_url(...)` without `proxy_*` keywords uses the default.

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
| **S3-compatible** | ✅ | ✅ | ✅ | ✅ | `botocore.config.Config(proxies={...})` pointed at the loopback shim for every kind botocore cannot speak itself (SOCKS, HTTPS, NTLM/Negotiate) |
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
| **PostgreSQL** | ✅ | ✅ | ✅ | ✅ | libpq dials a loopback tunnel (`core.proxy.LocalTunnel`) via `hostaddr`/`port`; `host` keeps the real name so TLS verifies it |
| **Redis** | ✅ | ✅ | ✅ | ✅ | custom redis-py connection class opens the socket with `create_proxy_socket`; `rediss://` is layered on top, verifying the real host |
| **MongoDB** | ✅ | ✅ | ✅ | ✅ | pymongo dials a loopback tunnel with `directConnection=True` (otherwise the driver would dial discovered replica-set members around the proxy). The backend sets no TLS options today. |
| **LDAP / LDAPS** | ✅ | ✅ | ✅ | ✅ | ldap3 dials a loopback tunnel; LDAPS passes `valid_names`/`sni` so the certificate is still checked against the real host |
| **Git** | ✅ | ✅ | ✅ | ✅ | `http(s)`: urllib3 `SOCKSProxyManager`/`ProxyManager` handed to dulwich; `ssh` / scp-style / `git://`: loopback tunnel, ssh keeps the real host identity via `HostKeyAlias` |
| **SVN** | ✅ | ✅ | ✅ | ✅ | `svn://`, `svn+ssh://`: loopback tunnel (`HostKeyAlias` for ssh). `http(s)://`: the svn client only speaks plain HTTP proxies, so SOCKS / HTTPS / NTLM go through the loopback shim; the endpoint and secret live in a private 0600 `servers` file, never in argv. The private `--config-dir` replaces `~/.subversion` for that session. |
| **SLP** | ⚠ | ⚠ | ⚠ | ✅ | TCP mode: `create_proxy_socket`. UDP mode: **SOCKS5 only** (UDP ASSOCIATE); the target is resolved by the proxy, never locally. Other proxy types fail closed. |
| **TFTP** | ❌ | ⚠ | ❌ | ✅ | UDP: **SOCKS5 only** (UDP ASSOCIATE) through a scoped patch of tftpy's UDP socket. The server must be an **IP address** (tftpy resolves names locally, which would leak the lookup); SOCKS4/HTTP fail closed. Transfers are serialised by a lock. |
| **NFS (v4)** | ✅ | ✅ | ✅ | ✅ | the kernel mounts the loopback end of a tunnel (`127.0.0.1:/export`, `port=<tunnel>`); one TCP port is all NFSv4 needs. **NFSv3 fails closed** (mountd / portmap / statd need several ports). |
| **iSCSI** | ✅ | ✅ | ✅ | ✅ | the initiator logs in to the loopback end of a tunnel; the node record is created by hand (SendTargets would hand back the target's real portal addresses), and a login that the target redirects off the tunnel is torn down and rejected. |
| **rsh** | ❌ | ❌ | ❌ | — | needs a reverse stderr connection from the server and a privileged source port; **fails closed**. |
| **WMI** | ❌ | ❌ | ❌ | — | DCOM negotiates dynamic RPC ports after the endpoint mapper; **fails closed**. |
| **RamFS** | — | — | — | — | in-process; no network at all, proxy fields N/A. |
| **SQLite** | — | — | — | — | local file backend; proxy fields N/A. |

The connection dialog disables the proxy group for protocols that cannot
use it (`core.connection_manager.proxy_unavailable_reason`).

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
4. **`LocalTunnel` / `open_tunnel(kwargs, host, port)`** — a loopback
   listener (127.0.0.1, ephemeral port, **same-uid peers only** via
   `/proc/net/tcp`, 64-connection cap) that relays every accepted
   connection through the proxy. For libraries that open their own
   sockets and offer no hook (psycopg, pymongo, ldap3, `svn://`, dulwich
   over ssh). The tunnel dies with the session.
5. **`create_udp_proxy_socket` / `patched_module_udp_socket`** — SOCKS5
   UDP ASSOCIATE for SLP and TFTP. SOCKS4 and HTTP CONNECT cannot carry
   UDP and are refused.
6. **`core.proxy_http.LocalProxyShim` / `effective_http_proxy(cfg)`** — a
   loopback *HTTP* proxy for libraries that only accept a plain HTTP
   proxy URL (botocore, the svn client, rsync's helper, httplib2). It
   dials the real upstream itself -- SOCKS4/5, TLS to the proxy, Basic /
   NTLM / Negotiate -- and relays CONNECT and absolute-form requests.
   Same-uid peers only; a shim port is registered with the SSRF guard
   only while it is live. Chunked request bodies are refused (501);
   authenticated absolute-form requests buffer the body (limit 16 MiB)
   because NTLM may need to resend it.

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
proxy_type      "none" | "socks4" | "socks5" | "http" | "https"
                # optionally "+basic" | "+ntlm" | "+negotiate" | "+kerberos" on http / https
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

botocore (via urllib3) only speaks HTTP proxy URLs, so SOCKS4/5, HTTPS
and NTLM/Negotiate proxies are fronted by the loopback shim
(`effective_http_proxy`): botocore sees `http://127.0.0.1:<port>`, the
shim talks to the real proxy. Earlier versions rejected SOCKS for S3.

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

NFSv4 and iSCSI are kernel clients, but each needs only one TCP
connection. axross starts a loopback tunnel to the real server through
the proxy and points the kernel at it:

- **NFSv4**: `mount -t nfs -o vers=4.x,port=<tunnel>,nolock,tcp
  127.0.0.1:/export`. The session shows the real server name.
- **iSCSI**: `iscsiadm -m node -o new` for the tunnel portal, then login.
  After login the session's current portal is verified; a target that
  redirects the login to another address is logged out and the connect
  fails. open-iscsi follows the redirect itself, so by the time axross
  sees it the initiator has already logged in to the redirected address
  directly -- the check stops the session from being used, it cannot
  prevent that one direct login.
- The tunnel peer is the kernel (uid 0), so these two tunnels also accept
  root-owned peers; every other tunnel stays same-uid only.
- **NFSv3 fails closed**: it negotiates mountd, portmap and statd on
  several ports. Switch the profile to NFSv4 or remove the proxy.
- **MTP** is USB / FUSE and has no network path.

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

### Proxy lab (podman)

`tests/test_proxy_lab.py` runs against **real proxy servers** and is
opt-in because it builds images:

```
AXROSS_PROXY_LAB=1 .venv/bin/python -m pytest tests/test_proxy_lab.py -q
python -m tests.proxy_lab up|down      # start / remove the lab by hand
```

Everything is named `axproxy-*` on its own network and removed afterwards.
squid 6 serves Basic, an NTLM handshake (`ntlm_fake_auth`: validates the
message flow, not the password), an open port and a TLS port; Dante serves
SOCKS4/5 with and without authentication. The targets (sshd, FTP with
passive mode, HTTP, redis) publish no ports and their names (`ssh.lab` ...)
do not resolve on the host, so every green test is proof of routing -- the
negative controls assert that the same name fails without a proxy. The
suite covers raw tunnels for every proxy kind, wrong / missing credentials,
a TLS proxy with the wrong CA, the probe stages, SFTP / FTP / HTTP through
each kind, and the default proxy, bypass list and PAC through
`ConnectionManager`. The NTLM *password check* is covered by
`tests/test_proxy_http.py` (a pyspnego server verifies the credentials).
Kerberos is not exercised (it needs a KDC).

For end-to-end proxy tests against real protocols there is also a
`socks-proxy` (SOCKS4/SOCKS5) and `http-proxy` (HTTP proxy/CONNECT)
container in `tests/docker/` — exercised by `test_protocols.py`
Section 21d. That section has one direct smoke per proxy protocol
(SOCKS4, SOCKS5, HTTP CONNECT), then a backend-level proxy matrix for
WebDAV, FTP, FTPS, SMB, IMAP, POP3, Telnet, Cisco-Telnet, Rsync,
Azure Blob, and S3 (SOCKS5 and HTTP). Bring up the lab
(`cd tests/docker && docker compose up -d --build`) and run the proxy
subset with:

```
pytest tests/test_protocols.py -k "proxy_protocol or proxy_matrix or via_socks5_proxy or via_http_connect_proxy"
```

Optional internet smokes for all three proxy protocols are gated behind
`AXROSS_LIVE_INTERNET_PROXY_TESTS=1` so air-gapped CI does not flap.
