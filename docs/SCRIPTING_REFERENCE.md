# `axross.*` Scripting Reference

Auto-generated from the live `core.scripting` module — every public function with its full signature and docstring, grouped by topic.


Also available at runtime: `axross.docs()` returns this same Markdown; `axross.docs(name)` returns a single section. The GUI doc-pane renders the same content.


---


## Open / connect

### `axross.open(profile_name: 'str', password: str | None  (optional) = None, key_passphrase: 'str | None' = None)`

Open a backend by saved profile name. Returns a FileBackend
session. Raises :class:`KeyError` if the profile doesn't exist
and :class:`OSError` for connection failure.

### `axross.open_url(url: 'str', **kwargs)`

Open a backend from a URL like ``sftp://user@host/``,
``s3://bucket``, ``smb://server/share``, ``gopher://host:70``.

Sensitive credentials in the URL are honoured but a saved profile
is preferred for anything you'll re-use — :func:`open` looks up
keys / passphrases via ``keyring`` so they don't end up in
process history.

**Proxy support** (SOCKS4 / SOCKS5 / HTTP CONNECT). Pass any of
``proxy_type``, ``proxy_host``, ``proxy_port``, ``proxy_username``,
``proxy_password`` as kwargs; for proxy-capable protocols
(sftp, scp, ftp/s, smb/dfsn, webdav, rsync, telnet,
cisco-telnet, imap, pop3, nntp, gopher, pjl, adb-tcp,
azure_blob/files, onedrive, sharepoint, gdrive, dropbox, winrm,
and S3 over HTTP CONNECT), the proxy is wired into the backend's
transport. Backends without clean SOCKS/HTTP support log a warning
instead of silently ignoring the proxy fields. Per-protocol caveats
still apply: S3 is HTTP-CONNECT only, and rsync's OpenBSD-nc path
cannot carry ``proxy_password``. Requests-based SDK sessions
controlled by Axross ignore process-level ``HTTP_PROXY`` /
``HTTPS_PROXY`` so the profile/script proxy is the route source of
truth. OAuth browser consent pages are external and may follow
browser/system proxy settings. When ``proxy_type`` is not ``"none"``,
``proxy_host`` and a non-zero ``proxy_port`` are required;
half-configured proxies fail closed instead of falling back to
direct traffic.

Example::

    b = axross.open_url(
        "sftp://alice@gateway.example.com/",
        password="hunter2",
        proxy_type="socks5",
        proxy_host="127.0.0.1",
        proxy_port=1080,
    )

Recognised schemes match registered backend protocol IDs, with
a few ergonomic aliases: ``http://`` / ``https://`` open WebDAV,
``gophers://`` opens TLS Gopher, ``nntps://`` opens TLS NNTP,
``git+local://`` opens a local Git repository path, and
``sftp+key://`` / ``sftp+agent://`` select SSH auth mode.

### `axross.localfs()`

Return a LocalFS session pointed at the host's filesystem.

### `axross.ramfs(max_bytes: 'int | None' = None)`

Return a fresh RamFS session — bytes never touch disk.
``max_bytes`` overrides the default per-instance cap.

### `axross.list_profiles() -> 'list[str]'`

Return the names of all saved connection profiles.

### `axross.get_profile(name: 'str')`

Look up a saved :class:`ConnectionProfile` by name.

Returns ``None`` if no profile matches. Use :func:`list_profiles`
to discover the available names.

### `axross.save_profile(profile) -> 'None'`

Persist a :class:`core.profiles.ConnectionProfile`. The profile
object itself can be constructed via ``ConnectionProfile(name=...,
protocol=..., host=...)`` — see ``help(core.profiles.ConnectionProfile)``.

### `axross.delete_profile(name: 'str') -> 'None'`

Delete a saved profile by name. No-op if the profile doesn't
exist.

### `axross.list_backends() -> 'list[str]'`

Return the protocol IDs of every registered backend (sftp,
smb, s3, …) regardless of whether the optional dependency is
installed. Use :func:`available_backends` for the installed
subset.

### `axross.available_backends() -> 'list[str]'`

Return the protocol IDs of backends whose dependencies are
actually installed.


## File I/O

### `axross.copy(src_backend, src_path: 'str', dst_backend, dst_path: 'str', buffer_size: 'int' = 1048576, *, overwrite: 'bool' = False) -> 'int'`

Copy bytes from one backend to another. Returns the number of
bytes transferred. Same-backend copies use the backend's native
``copy()`` if available; cross-backend copies always stream.

Existing destinations are refused by default. Pass
``overwrite=True`` when replacement is intentional.

### `axross.move(src_backend, src_path: 'str', dst_backend, dst_path: 'str', *, overwrite: 'bool' = False) -> 'int'`

Move a file from one backend to another. Same-backend uses
rename; cross-backend uses copy + delete-source.

Existing destinations are refused by default. Cross-backend moves
also refuse replacing an existing destination even with
``overwrite=True`` because a later source-delete failure cannot
restore the replaced remote object reliably across all protocols.

### `axross.remove(backend, path: 'str', *, recursive: 'bool' = False, confirm: 'bool' = False) -> 'str'`

Delete ``path`` from ``backend`` after an explicit opt-in.

This scripting helper deliberately refuses to run unless
``confirm=True`` is passed. Use :func:`preview_delete` first and
pair this with :func:`confirm` in interactive scripts.

Returns the pre-operation preview summary when available.

### `axross.trash(backend, path: 'str', *, root: 'str | None' = None, confirm: 'bool' = False) -> 'str'`

Move ``path`` to Axross trash after an explicit opt-in.

This is the recoverable alternative to :func:`remove`, but it is
still destructive from the source path, so ``confirm=True`` is
required. Returns the trash id.

### `axross.read_bytes(backend, path: 'str', *, max_bytes: 'int | None' = 67108864) -> 'bytes'`

Read a file into memory.

Capped by default so a hostile backend cannot make a REPL/script
pull unbounded data into the process. Pass ``max_bytes=None`` for
an explicit uncapped read.

### `axross.write_bytes(backend, path: 'str', data: 'bytes', *, overwrite: 'bool' = False) -> 'int'`

Write ``data`` to ``path`` on ``backend``. Returns bytes written.

Existing destinations are refused by default. Pass
``overwrite=True`` when replacement is intentional.

### `axross.read_text(backend, path: 'str', encoding: 'str' = 'utf-8', *, max_bytes: 'int | None' = 67108864) -> 'str'`

Read an entire file as text. Decodes the bytes via ``encoding``
with ``errors="replace"`` so a stray non-UTF-8 byte never raises;
use :func:`read_bytes` when you need exact-bytes round-trip.

### `axross.write_text(backend, path: 'str', text: 'str', encoding: 'str' = 'utf-8', *, overwrite: 'bool' = False) -> 'int'`

Write a UTF-8 text file. Convenience wrapper around
:func:`write_bytes` — encodes ``text`` and forwards. Returns the
number of bytes written. Existing destinations are refused unless
``overwrite=True`` is passed.

### `axross.checksum(backend, path: 'str', algorithm: 'str' = 'sha256') -> 'str'`

Return the backend's content fingerprint for ``path``. Falls
back to a streaming hash when the backend has no cheap server-side
checksum.

### `axross.hash_bytes(data: 'bytes', algorithm: 'str' = 'sha256') -> 'str'`

Hex digest of ``data`` under ``algorithm`` (anything
:mod:`hashlib.new` accepts: sha1, sha256, sha512, md5, …).

### `axross.hash_file(backend, path: 'str', algorithm: 'str' = 'sha256', chunk_size: 'int' = 1048576) -> 'str'`

Streaming hex digest of a backend-side file. Same as
:func:`checksum` but never tries to use a server-side fingerprint
— use this when you specifically want algorithm parity across
different backends.


## Encryption + archives

### `axross.encrypt(backend, path: 'str', passphrase: 'str', keep_original: 'bool' = True, *, overwrite: 'bool' = False) -> 'str'`

Encrypt ``path`` with the axross encrypted-overlay format and
write the ciphertext to ``<path>.axenc``. Returns the new path.

The plaintext is kept by default. Pass ``keep_original=False`` to
remove it after the ciphertext has been written. Existing
ciphertext destinations are refused unless ``overwrite=True`` is
passed.

### `axross.decrypt(backend, path: 'str', passphrase: 'str') -> 'bytes'`

Read and decrypt an .axenc file. Returns the plaintext bytes —
the caller decides where to put them (write_bytes to disk, hand
them to a parser, etc.).

### `axross.extract_archive(local_path: 'str', dst_dir: 'str', progress=None) -> 'str'`

Extract a local archive (zip / tar / 7z) to ``dst_dir``. Returns
the destination directory after the extract. Refuses zip-bombs
and zip-slip via the same guards used by the file-manager UI.

``progress`` is an optional callable ``(current, total, name)``
invoked once per archive entry.

### `axross.is_archive(path: 'str') -> 'bool'`

True when ``path`` looks like a zip / tar / 7z by extension.


## Bookmarks + scripts

### `axross.list_bookmarks() -> 'list'`

Return all saved bookmarks (list of :class:`Bookmark`).

### `axross.add_bookmark(name: 'str', path: 'str', backend_name: 'str' = 'Local', profile_name: 'str' = '', icon_name: 'str' = 'bookmark') -> 'None'`

Create a new bookmark. Idempotent on (path, backend_name).

### `axross.remove_bookmark(index: 'int') -> 'None'`

Remove the bookmark at ``index`` (zero-based).

### `axross.script_dir() -> 'str'`

Return the script-storage directory path. Created on first
access. Mode 0700 so other local users can't read scripts that
might contain credentials.

### `axross.list_scripts() -> 'list[str]'`

Names of every saved script in :func:`script_dir`.

### `axross.save_script(name: 'str', source: 'str') -> 'str'`

Write ``source`` to ``script_dir()/<name>.py`` (mode 0o600).
Overwrites any existing file with the same name. Returns the
final on-disk path.

### `axross.load_script(name: 'str') -> 'str'`

Read the source of a saved script as a UTF-8 string. Raises
``FileNotFoundError`` when the script doesn't exist; ``ValueError``
when the name contains characters outside the allow-list.

### `axross.delete_script(name: 'str') -> 'None'`

Remove a saved script. No-op if the file is already gone.

### `axross.run_script(name: 'str', env: 'dict | None' = None) -> 'dict'`

Execute a saved script in a fresh namespace pre-populated with
``axross`` (this module). Returns the post-exec namespace so the
caller can inspect any variables it left behind. ``env`` overrides
/ augments the initial namespace.


## Per-protocol

### `axross.find_tftp_files(backend, wordlist=None, on_progress=None) -> 'list'`

Walk ``backend.find_files()`` (TFTP wordlist scan). The backend
must be a :class:`TftpSession`; raises :class:`AttributeError`
otherwise.

### `axross.slp_discover(host: 'str', scope: 'str' = 'DEFAULT', port: 'int' = 427, use_tcp: 'bool' = False) -> 'dict'`

One-shot SLPv2 discover: returns ``{service_type: [(url, ttl)]}``
for everything the daemon at ``host`` advertises in ``scope``.
Pure read; no SrvReg path is ever exercised
(CVE-2023-29552 mitigation).

### `axross.nntp_post(backend, group: 'str', subject: 'str', body: 'str', author: 'str' = 'axross <noreply@axross>') -> 'None'`

Post a fully-formed article to ``group`` on ``backend`` (an
:class:`NntpSession`). Builds a minimal RFC 5322 envelope around
``subject`` + ``body``; for richer headers, hand the writer a
pre-built bytes payload via ``backend.open_write(...)``.

Header values are validated for CR/LF before being formatted into
the envelope so a tainted ``subject`` cannot smuggle additional
headers / body content into the post (RFC 5322 / RFC 3977 header-
injection class of bug).

### `axross.git_push(backend, branch: 'str | None' = None) -> 'None'`

Push committed work on ``backend`` (a :class:`GitFsSession`) to
its origin. Raises :class:`GitForceRefused` on non-fast-forward.
Pass ``branch=None`` to push every branch the session has touched.

### `axross.exec(backend, cmd: 'str', *, timeout: 'float | None' = 30.0, stdin: 'bytes | str | None' = None, stdout_cap: 'int' = 1048576, stderr_cap: 'int' = 65536, env: 'dict[str, str] | None' = None)`

Run a shell command on a remote backend. Returns
:class:`models.exec_result.ExecResult` with ``returncode``,
``stdout``, ``stderr`` and the corresponding ``truncated_*`` flags.

Works on any backend whose session implements ``.exec()`` —
currently SSH/SFTP and SCP. For protocols where ``exec`` is the
wrong shape (Cisco IOS, IMAP, S3 …) use the per-protocol helper
instead (``axross.show()``, ``axross.imap_search()``, …).

Quote untrusted arguments yourself::

    import shlex
    r = axross.exec(b, f"ls -la {shlex.quote(path)}").check()

Pass ``stdin`` as ``bytes`` (or a ``str`` that we'll utf-8 encode)
to feed input to the remote process before reading its output.

### `axross.interactive_shell(backend, *, term: 'str' = 'xterm-256color', cols: 'int' = 80, rows: 'int' = 24, env: 'dict[str, str] | None' = None)`

Open an interactive shell on the same SSH transport ``backend``
is already using. Multiplexing — file ops on ``backend`` keep
working while the shell is open. Returns a
:class:`models.interactive_shell.InteractiveShell` wrapper with
``read`` / ``write`` / ``read_until`` / ``resize_pty`` /
``close`` / ``interact`` / iter-as-lines.

Currently supported on SSH/SFTP and SCP backends — both reuse
the same paramiko Transport. Other backends raise TypeError::

    with axross.open("alpha-ssh") as b:
        sh = axross.interactive_shell(b, cols=200, rows=50)
        sh.write(b"htop\n")
        ...

### `axross.query(backend, sql_or_args, *args, **kwargs)`

Generic database-query dispatch. Calls ``backend.query()`` for
SQL backends (SQLite / Postgres) or ``backend.find()`` for Mongo
when ``sql_or_args`` looks like a collection name + filter dict.

SQL form::

    rows = axross.query(b, "SELECT * FROM users WHERE id = ?", (1,))

Mongo form::

    rows = axross.query(b, "orders", {"status": "open"}, limit=50)

Redis is intentionally NOT dispatched here — Redis isn't SQL.
Use ``b.cmd("CONFIG", "GET", "maxmemory")`` directly.

### `axross.tables(backend) -> 'list[str]'`

Return every table (SQLite/Postgres) or collection (Mongo) on
``backend``. Wraps the per-backend method of the same name.

### `axross.imap_search(backend, criteria: 'str' = 'ALL', *, mailbox: 'str' = 'INBOX') -> 'list'`

Wrapper around message-backend search. For IMAP this returns
the list of UIDs matching an IMAP search expression (RFC 3501);
for Exchange it returns the backend's lightweight message dicts::

    uids = axross.imap_search(b, 'UNSEEN SUBJECT "invoice"')

### `axross.imap_move(backend, uid: 'int', src_mailbox: 'str', dst_mailbox: 'str') -> 'None'`

Move an IMAP message by UID. Uses MOVE if the server supports
it, COPY+\Deleted+EXPUNGE otherwise. See ``ImapSession.move``.

### `axross.imap_set_flags(backend, uid: 'int', flags: 'list[str]', *, mailbox: 'str' = 'INBOX', mode: 'str' = 'set') -> 'None'`

STORE flags on an IMAP message by UID. ``mode`` is ``set`` /
``add`` / ``remove``.

### `axross.share(backend, path: 'str', **kwargs) -> 'str'`

Create a shareable link for ``path`` on a cloud backend that
supports it. Dispatches to:

* ``S3Session.presign(path, expires=...)`` → pre-signed URL
* ``DropboxSession.shared_link_create(path, public=...)`` → URL
* ``GDriveSession.share(path, role=...)`` → ``{"url": ...}``  (just the URL)
* ``OneDriveSession.share(path, link_type=...)`` → URL

The keyword args differ per backend — pass them through; we keep
the signature loose because each cloud's notion of "share" is
nominally the same but parameter-named differently.

### `axross.ldap_search(backend, base_dn: 'str', filter: 'str' = '(objectClass=*)', *, scope: 'str' = 'subtree', attributes: 'list[str] | None' = None, limit: 'int' = 1000) -> 'list[dict]'`

Run a raw LDAP search via the connected ``LdapFsSession``.
Returns up to ``limit`` entries as dicts ``{dn, attributes}``::

    users = axross.ldap_search(
        b, "ou=people,dc=example,dc=com",
        "(objectClass=inetOrgPerson)",
        attributes=["cn", "mail", "uid"],
    )


## Network helpers

### `axross.dns_resolve(host: 'str', family: 'str' = 'any') -> 'list[str]'`

Return the IPs ``host`` resolves to. ``family`` is ``"v4"``,
``"v6"``, or ``"any"``.

Returns an empty list when the name doesn't resolve — caller should
distinguish this from "no records of the requested family" by
enabling axross's DEBUG log: every resolution failure is logged
there with the exception text.

### `axross.dns_records(name: 'str', rtype: 'str' = 'A', *, resolver: 'str | None' = None, timeout: 'float' = 3.0) -> 'list[str]'`

Return DNS records of ``rtype`` for ``name``. Uses ``dnspython``
so we get TXT/MX/SRV/CAA/NAPTR records in addition to the basic
A / AAAA / CNAME / NS / PTR.

``resolver`` is an optional DNS server IP — falls back to system
resolvers when ``None``.

Returned values are textual: ``["1.2.3.4"]`` for A, ``["10 mail.x"]``
for MX, etc. — already formatted, so the caller doesn't need to
know the rdata structure.

### `axross.dns_reverse(ip: 'str', *, resolver: 'str | None' = None, timeout: 'float' = 3.0) -> 'list[str]'`

PTR lookup for an IP. Returns a list (most addresses have at
most one PTR but the protocol allows multiple).

### `axross.port_open(host: 'str', port: 'int', timeout: 'float' = 3.0) -> 'bool'`

``True`` if a TCP connect to ``host:port`` succeeds within
``timeout`` seconds. Useful for lab-up probes in scripts.

### `axross.port_scan(host: 'str', ports: 'Iterable[int]', *, timeout: 'float' = 1.0, concurrency: 'int' = 64) -> 'list[int]'`

Concurrent TCP-connect scan. Returns the sorted list of
ports that accepted a connection within ``timeout``.

``concurrency`` caps the number of in-flight connects so we
don't trip per-host conntrack limits or open thousands of FDs.
Default 64 is friendly for any modern Linux box; hard ceiling
is ``_PORT_SCAN_MAX_CONCURRENCY`` (1024) — anything above that
would blow through ``ulimit -n`` and fail in confusing ways.
F37.

Use a generator for huge port ranges::

    axross.port_scan("10.0.0.1", range(1, 65536), concurrency=128)

### `axross.subnet_hosts(cidr: 'str') -> 'list[str]'`

Iterate every usable host in ``cidr`` (e.g. ``"10.0.0.0/29"``).
Returns a list of IP strings — for /29 that's 6 addresses, for
/24 it's 254. Refuses ranges larger than /16 to prevent the user
from accidentally enumerating 65k addresses they didn't mean to.

### `axross.tcp_banner(host: 'str', port: 'int', *, timeout: 'float' = 3.0, max_bytes: 'int' = 4096, send: 'bytes | None' = None) -> 'bytes'`

Connect to ``host:port`` and read up to ``max_bytes`` of the
server's initial response. Useful for service-ID probes (SSH,
FTP, SMTP, IMAP all greet with a banner).

``send`` is an optional payload to send first — needed for HTTP
(``b"HEAD / HTTP/1.0\r\n\r\n"``) and other protocols that
don't speak first.

Raises ``OSError`` (incl. ``TimeoutError`` subclass) on connect or
read failure. Returns ``b""`` if the server accepts the connection
but sends no bytes within the timeout.

### `axross.tls_cert(host: 'str', port: 'int' = 443, *, timeout: 'float' = 5.0, sni: 'str | None' = None, verify: 'bool' = False) -> 'TlsCert'`

TLS handshake against ``host:port`` and return the parsed
leaf certificate.

``sni`` defaults to ``host`` so virtual-hosted servers return the
right cert. Pass ``sni=""`` to disable SNI.

``verify=False`` (the default) means we accept self-signed and
expired certs — this helper is for INSPECTION (the user wants to
see what's there), not for authenticated connection. Set
``verify=True`` and the system trust-store applies.

Raises ``OSError`` on connect failure, ``ssl.SSLError`` on
handshake failure.

### `axross.ssh_hostkey(host: 'str', port: 'int' = 22, *, timeout: 'float' = 5.0) -> 'SshHostKey'`

Connect, complete the SSH KEX, fetch the server's host key
and return its fingerprints. NO authentication is attempted.

Raises ``OSError`` on connect, ``paramiko.SSHException`` on KEX
failure.

### `axross.http_probe(url: 'str', *, method: 'str' = 'GET', headers: 'dict[str, str] | None' = None, body: 'bytes | str | None' = None, timeout: 'float' = 10.0, allow_redirects: 'bool' = True, body_cap: 'int' = 1048576, raw_cap: 'int | None' = None, verify: 'bool' = True) -> 'HttpProbe'`

Lightweight HTTP/HTTPS probe via ``requests``. Returns the
response status, headers, body (up to ``body_cap``), redirect
chain, and the TLS leaf cert when applicable.

Why not raw ``requests.request`` — this helper sets sane defaults
(timeout, body cap, captures redirect chain), and unconditionally
parses the TLS cert via ``tls_cert`` so a script can audit a
deployment without two round-trips.

``verify=True`` honours the system trust-store. Set False to
inspect a self-signed cert (the cert info is still returned).

F36: ``body_cap`` clips the DECODED body. A hostile gzip-encoded
response can amplify ~1000x — a 1 KiB compressed payload can
decode to >1 GiB, blowing through ``body_cap`` long after the
raw stream has eaten our memory budget. ``raw_cap`` caps the
on-the-wire bytes BEFORE decompression; defaults to
``max(body_cap * 4, 8 MiB)`` which is generous for legitimate
Content-Encoding ratios but stops a real bomb.

### `axross.snmp_get(host: 'str', oid: 'str', *, community: 'str' = 'public', port: 'int' = 161, timeout: 'float' = 3.0, retries: 'int' = 1, user: 'str | None' = None, auth_key: 'str | None' = None, priv_key: 'str | None' = None, auth_proto: 'str | None' = None, priv_proto: 'str | None' = None) -> 'SnmpVar'`

Issue a single SNMP GET request. Returns one ``SnmpVar`` for
the OID. Raises ``OSError`` on transport failure.

For v3, supply ``user`` (and optionally ``auth_key`` / ``priv_key``).
For v2c (the default), the ``community`` string is enough.

### `axross.snmp_walk(host: 'str', base_oid: 'str', *, community: 'str' = 'public', port: 'int' = 161, timeout: 'float' = 3.0, retries: 'int' = 1, max_vars: 'int' = 10000, user: 'str | None' = None, auth_key: 'str | None' = None, priv_key: 'str | None' = None, auth_proto: 'str | None' = None, priv_proto: 'str | None' = None) -> 'list[SnmpVar]'`

Walk an OID subtree, returning every leaf as an ``SnmpVar``.
``max_vars`` caps the result at a sane number — a walk of ``1.3``
on a packed device returns thousands of varbinds.

### `axross.snmp_set(host: 'str', oid: 'str', value: 'Any', *, value_type: 'str' = 'OctetString', community: 'str' = 'private', port: 'int' = 161, timeout: 'float' = 3.0, retries: 'int' = 1) -> 'SnmpVar'`

Issue an SNMP SET. ``value_type`` is the pysnmp type-class name
(``OctetString`` / ``Integer`` / ``Counter32`` / …).

Default community is ``"private"`` — most devices distinguish
read-only ``"public"`` from read-write ``"private"``. Override
explicitly when your device uses a different community.

### `axross.ping(host: 'str', *, port: 'int' = 80, timeout: 'float' = 3.0, count: 'int' = 1) -> 'list[PingResult]'`

TCP-based reachability probe — connect to ``host:port`` and
measure RTT. Returns one ``PingResult`` per ``count`` attempt.

Why TCP and not ICMP: ICMP raw sockets need CAP_NET_RAW (root
on Linux). A TCP-connect to a known-listening port is the
standard "no-privileges" reachability probe and works through
most firewalls that pass HTTP/HTTPS but drop ICMP.

``port`` defaults to 80 — adjust to the service the host is
expected to run (22 for SSH boxes, 443 for web, 53 for DNS,
389 for LDAP, …). The probe never sends any application data;
the connect is closed cleanly the moment the 3-way handshake
completes.

``count`` lets a script gather a few samples to spot variance
without rolling its own loop. Returns one ``PingResult`` per
attempt, in attempt order.

### `axross.mac_lookup(mac: 'str') -> 'OuiInfo'`

Look up the IEEE OUI vendor for a MAC address.

Accepts every common MAC formatting:
* ``00:1A:2B:3C:4D:5E``    (colon-separated)
* ``00-1A-2B-3C-4D-5E``    (hyphen-separated)
* ``001A.2B3C.4D5E``       (Cisco dotted-quad)
* ``001A2B3C4D5E``         (12 hex chars, no separator)

Uses the ``manuf`` package (Wireshark-derived OUI database).
Raises ``OSError`` with an install hint when ``manuf`` isn't
installed, ``ValueError`` for malformed MACs.

Returns ``OuiInfo`` — when the OUI isn't in the registry, the
``vendor`` / ``vendor_long`` fields are None but the call
doesn't raise (vendor-unknown is a valid answer for locally-
administered or recently-allocated MACs).

### `axross.whois(query: 'str', *, timeout: 'float' = 5.0) -> 'WhoisInfo'`

RIR / ASN / registrar lookup.

Auto-detects whether ``query`` is an IP (v4 or v6) or a domain
name. IPs go through ``ipwhois`` (RDAP-aware, no flat-file
parsing); domains aren't yet supported by this helper — they
raise NotImplementedError pointing at the system ``whois``
binary, which is the practical fallback (registrar WHOIS is a
free-text mess that's hard to parse cleanly without a third-
party service).

### `axross.time_skew(host: 'str', *, source: 'str' = 'http', port: 'int | None' = None, timeout: 'float' = 5.0, verify_tls: 'bool' = False) -> 'TimeSkew'`

Measure clock drift of ``host`` vs. the local clock.

``source``:
* ``"ntp"``  — query an NTP server (default port 123/UDP).
                Most accurate; needs ntplib.
* ``"http"`` — fetch the URL ``http(s)://host[:port]/`` and
                parse the ``Date:`` response header. Universal
                fallback — every HTTP/1.1 server emits Date.
* ``"tls"``  — TLS 1.2 ServerHello carries gmt_unix_time in
                the random field; we'd need a custom handshake
                to read it (the timestamp was REMOVED in TLS 1.3
                for privacy reasons). Not implemented in this
                helper — raises NotImplementedError pointing
                at HTTP as the practical alternative.

``verify_tls`` — when ``source='https'`` the default is **False**:
time-skew measurement only consumes the ``Date:`` header, never
the response body, and the whole point of the verb is "probe a
host whose cert chain you may not trust". A MITM could feed a
wrong Date value, but the consequence is a wrong skew reading,
not a leak of secrets. Pass ``verify_tls=True`` if you need
strict cert validation (e.g. for compliance scans).

Returns ``TimeSkew(offset_seconds, rtt_seconds, source)``.
Positive offset = remote ahead, negative = remote behind.


## Search across backends

### `axross.find_files(backend, path: 'str', *, pattern: 'str | None' = None, ext: 'str | None' = None, mtime_after: 'datetime | None' = None, mtime_before: 'datetime | None' = None, size_min: 'int | None' = None, size_max: 'int | None' = None, max_depth: 'int | None' = None, follow_links: 'bool' = False) -> 'Iterator'`

Recursive walk of ``backend`` rooted at ``path``, filtered by
every non-None criterion. Yields :class:`models.file_item.FileItem`.

``pattern`` is a glob (``*.txt``); ``ext`` is shorthand (".txt"
or "txt", case-insensitive). Supplying both ANDs them.

``follow_links`` is OFF by default — symlink-loop bombs are a
classic find footgun. Set True only when you trust the tree.

### `axross.grep(backend, path: 'str', pattern: 'str', *, max_size: 'int' = 10485760, max_matches: 'int' = 100, ignore_case: 'bool' = False, binary: 'bool' = False) -> 'list[GrepHit]'`

Search ``backend:path`` for ``pattern`` (a regex). Returns up
to ``max_matches`` hits.

If ``path`` names a directory the search recurses. Files larger
than ``max_size`` are skipped (set to 0 to disable). Set
``binary=True`` to also search files that contain NUL bytes.

### `axross.diff_files(b1, p1: 'str', b2, p2: 'str', *, max_bytes: 'int' = 10485760, n_context: 'int' = 3) -> 'list[str]'`

Unified diff of two files, possibly on different backends.
Returns a list of diff lines (incl. ``--- / +++`` headers). Empty
list = no difference.


## Content inspection

### `axross.magic_type(data: 'bytes', *, default: 'str' = 'application/octet-stream') -> 'str'`

Detect file type by magic bytes. Returns the MIME type if
recognised, ``default`` otherwise. Uses pure-Python ``puremagic``
so no libmagic dep is needed at runtime.

Pass ``data`` as the first ~1 KiB of the file (we only inspect
the first 8 KiB regardless — feeding the whole file is wasteful
but harmless).

### `axross.text_encoding(data: 'bytes', *, sample_bytes: 'int' = 65536) -> 'dict'`

Guess the text encoding of ``data``. Returns a dict::

    {"encoding": "utf-8", "confidence": 0.99, "language": ""}

Uses ``chardet`` so the detector understands legacy code pages
(Windows-125x, Big5, Shift-JIS, …). For empty input returns
``{"encoding": None, "confidence": 0.0, ...}``.

### `axross.entropy(data: 'bytes', *, base: 'int' = 2) -> 'float'`

Shannon entropy of ``data`` in bits/byte (when ``base=2``).

Cheap triage primitive: high-entropy blobs (>7.5 bits/byte) are
almost certainly compressed or encrypted; low-entropy blobs are
structured. Returns ``0.0`` for empty input.

``base`` is the log base — 2 gives bits/byte, math.e gives nats,
10 gives dits. Default 2 matches what ``binwalk`` and most
forensic tools report.

### `axross.archive_inspect(path: 'str', *, max_entries: 'int' = 100000) -> 'list[ArchiveEntry]'`

List the entries inside ``path`` without extracting. Detects
the archive type by extension first (``.zip`` / ``.tar*`` /
``.7z``) and falls through to magic-byte sniffing for unknown
suffixes.

Supported:
* ZIP / JAR / WAR — stdlib ``zipfile``
* TAR + gzip/bzip2/xz/zstd compression — stdlib ``tarfile``
* 7z — ``py7zr`` (axross[archive] extra)

Caps result at ``max_entries`` so a zip-bomb-shaped archive
can't fill memory. Raises ``OSError`` for malformed archives
or unsupported formats; ``ValueError`` for truncated input.


## Safety + diagnostics

### `axross.diagnose(backend, *, root: 'str | None' = None, write_test: 'bool' = False) -> 'str'`

Run live diagnostics against an open backend and return a
plain-text report.

``write_test=True`` performs a reversible write/rename/delete
probe in ``root`` (or the backend home directory when omitted).
Keep it false for read-only targets or when you only want cheap
connectivity checks.

### `axross.preview_delete(backend, paths: 'list[str]', *, max_entries: 'int' = 10000) -> 'str'`

Preview a delete/trash operation before executing it.

Returns a compact summary with item counts, total bytes and warning
or truncation counts.

### `axross.preview_transfer(source_backend, dest_backend, source_paths: 'list[str]', dest_dir: 'str', *, operation: 'str' = 'copy', max_entries: 'int' = 10000) -> 'str'`

Preview a copy/move before queueing it.

Returns a compact summary with item counts, total bytes and
destination conflict counts.

### `axross.recovery_scan(backend, root: 'str | None' = None) -> 'str'`

Scan a backend location for recoverable temp/trash items and
return a plain-text report.

### `axross.recent_operations(limit: 'int' = 20) -> 'list[dict]'`

Return recent redacted operation-journal events.

### `axross.security_mode(name: 'str | None' = None) -> 'str'`

Get or set the runtime security mode.

Passing ``"paranoid"`` disables external viewers, automatic
previews, scripts, legacy protocols and private-proxy overrides.
Passing ``"normal"`` restores the default policy.


## Credential testing (authorised use only)

### `axross.bruteforce(profile, *, users, passwords, rate_per_min: 'float' = 30.0, timeout_per_attempt: 'float' = 10.0, abort_on_lockout: 'bool' = True, abort_after_n_lockouts: 'int' = 1, abort_after_n_failures: 'int | None' = None, max_attempts: 'int | None' = None, stop_on_first_success_per_user: 'bool' = True, progress=None, on_unknown_host=None, state_file=None, dry_run: 'bool' = False, jitter_s: 'float' = 0.0, authorized: 'bool' = False)`

Run a brute-force credential test in user-major order against a
saved profile (name or :class:`ConnectionProfile`).

Iterates every password in ``passwords`` against every user in
``users`` (user 1 → all passwords → user 2 → all passwords → …).
Lockout-aware: the first attempt that classifies as LOCKOUT stops
the entire run unless ``abort_on_lockout=False`` is set with an
explicit ``abort_after_n_lockouts`` budget.

``authorized=True`` is **mandatory** — this gate is a hard refusal
from the underlying module, not a polite hint. Read
``docs/CRED_ATTACK.md`` and the OPSEC checklist before calling.

Returns an :class:`core.cred_attack.AttackReport`. Successful
credentials live on ``report.successes`` as ``Credential`` objects
(cleartext password — handle with care).
For SSH/SCP profiles, ``on_unknown_host`` is forwarded to the
host-key decision callback; leave it unset unless you have an
explicit trust policy for the target.

### `axross.spray(profile, *, users, password: str | None  (optional) = None, passwords=None, rate_per_min: 'float' = 30.0, timeout_per_attempt: 'float' = 10.0, abort_on_lockout: 'bool' = True, abort_after_n_lockouts: 'int' = 1, max_attempts: 'int | None' = None, stop_on_first_success_per_user: 'bool' = True, progress=None, on_unknown_host=None, state_file=None, dry_run: 'bool' = False, jitter_s: 'float' = 0.0, authorized: 'bool' = False)`

Run a password spray in password-major order — the safer
pattern for AD-style targets where lockout is per-user-per-window.

Try ``password`` (or the first item in ``passwords``) against
every user in ``users``, then move to the next password. Pass
either ``password=`` (single) or ``passwords=`` (list).

``authorized=True`` is mandatory. See :func:`bruteforce` for the
other arguments. Returns an
:class:`core.cred_attack.AttackReport`.

### `axross.enumerate_users(profile, candidates, *, method: 'str' = 'auto', timeout_per_probe: 'float' = 10.0, timing_samples: 'int' = 5, rate_per_min: 'float' = 30.0, jitter_s: 'float' = 0.0, progress=None, on_unknown_host=None, authorized: 'bool' = False)`

Probe whether each candidate username exists on the target.

``method="auto"`` (default) uses a registered per-protocol oracle
when one exists (POP3, FTP, FTPS today) and falls back to
statistical timing comparison otherwise. ``method="oracle"``
refuses to run if the protocol has no oracle; ``method="timing"``
forces the timing path even when an oracle exists.

Oracle probes and timing attempts are paced with ``rate_per_min``
and optional ``jitter_s`` just like spray/bruteforce attempts.

Returns an :class:`core.cred_attack.EnumReport`. ``authorized=True``
is mandatory.


## Multi-system workflow

### `axross.where_was_i(host: 'str | None' = None)`

Look up the visit-history record(s).

With no argument, returns every recorded host (most-recent first)
as a list of :class:`core.visit_history.HostVisit`. With a host
string, returns the single best-matching record (substring match
over hostnames) or ``None``.

History is recorded automatically by ``connect`` / file-op verbs
when they pass through :mod:`core.visit_history.record_visit`. The
JSON store lives at ``~/.config/axross/visit_history.json`` (mode
0o600); treat it as sensitive engagement data — it carries the
path layout of every host you've touched.

### `axross.health_pulse()`

Snapshot the live connection-health pulse for every enrolled
session — last-probe latency, median latency, staleness flag.

Returns a list of :class:`core.conn_health.HealthRecord`. Empty
when no sessions have been enrolled.

### `axross.summarize(backend, path: 'str' = '', *, max_entries: 'int' = 2000)`

One-paragraph synopsis of a directory: file/dir/link counts,
extension histogram, age buckets, newest/oldest entries, top-5
largest files. Reads metadata only — no file contents are fetched.

Returns a :class:`core.inspect.Summary`; call ``.render()`` for a
one-line human string. LLM-friendly: a single network round-trip
yields the gist of "what's in this place" without an N-thousand
entry ``list_dir`` dump.

### `axross.explain(backend, path: 'str' = '')`

Heuristic best-guess "what IS this directory?" — git repo,
PostgreSQL data dir, nginx config tree, k8s manifests, Maildir,
web-server log dir, and friends. Returns the highest-confidence
pattern match as a :class:`core.inspect.ExplainResult`, or an
empty result if nothing scored above 0.2.

### `axross.compare_file(backends: 'list', path: 'str', *, content: 'bool' = True, content_cap_bytes: 'int | None' = None, parallelism: 'int' = 8, per_target_timeout_s: 'float' = 30.0)`

Compare the SAME path across N backends in parallel.

Returns a :class:`core.multi_view.CompareReport` with per-backend
metadata + sha256 + pairwise unified-diff strings against the
first probe with text content. ``content=False`` skips the body
download and only diffs metadata (cheaper on cloud backends).

### `axross.inspect_targets(targets: 'list', *, content: 'bool' = True, content_cap_bytes: 'int | None' = None, parallelism: 'int' = 8, per_target_timeout_s: 'float' = 30.0)`

Inspect a list of ``(backend, path)`` pairs in parallel.

Returns :class:`core.multi_view.InspectReport` aligned with input
order. Use this to answer "is the local /tmp/foo.bin the same
file as the S3 object and the SFTP copy?".

### `axross.federated_search(backends: 'list', query=None, *, name: 'str' = '', regex: 'str' = '', contains: 'str' = '', contains_is_regex: 'bool' = False, min_size: 'int' = -1, max_size: 'int' = -1, modified_after: 'float' = 0.0, modified_before: 'float' = 0.0, roots: 'list[str] | None' = None, max_depth: 'int' = 6, max_hits_per_backend: 'int' = 500, max_hits_total: 'int' = 5000, parallelism: 'int' = 8, per_backend_timeout_s: 'float' = 60.0, progress=None)`

Run one search query against many backends in parallel.

The dispatcher picks the most efficient adapter per backend
(IMAP SEARCH for IMAP, native ``find_by_query`` for DB-FS family,
client-side walk for the rest). Pass either a pre-built
:class:`core.search_federation.SearchQuery` (``query=…``) or the
individual filter kwargs to construct one inline.

Returns a :class:`core.search_federation.SearchResult`.

### `axross.resumable_copy(src_backend, src_path: 'str', dst_backend, dst_path: 'str', *, segment_size: 'int' = 4194304, manifest_path=None, overwrite: 'bool' = False, progress=None)`

Cross-backend copy with checkpoint-resume.

Splits the source into segments, writes a manifest after each
completed segment, and on a re-run picks up from the first
incomplete segment after verifying the destination matches the
recorded hashes. Returns a
:class:`core.copy_resume.ResumeReport`.

### `axross.dashboard(*, with_capacity: 'bool' = False, recent_ops_limit: 'int' = 10, fmt: 'str' = 'text')`

Federation-status dashboard — one screen, every connection.

``fmt`` selects the renderer:

* ``"text"`` (default) — fixed-width text for the REPL.
* ``"markdown"`` — markdown table for MCP / LLM responses.
* ``"json"`` — structured JSON the GUI / scripts can consume.

Read-only — never performs mutating ops.


## Time-lapse / trail

### `axross.snapshot_now(backend, path: 'str', *, name: 'str' = '', head_hash: 'bool' = False, max_files: 'int' = 5000)`

Take a single time-lapse snapshot of a directory tree.

Records ``(name, size, mtime, optional sha-prefix)`` per file plus
a synthesised tree-hash, into the local SQLite trail database
(``~/.config/axross/trail.db``). Pair with :func:`start_trail` to
take snapshots on a recurring interval and :func:`diff_snapshots`
to compare any two snapshots of the same trail.

### `axross.start_trail(backend, path: 'str', *, name: 'str' = '', interval_s: 'float' = 300.0, head_hash: 'bool' = False, max_files: 'int' = 5000, on_snapshot=None)`

Start a background trail — periodic snapshots until
:func:`stop_trail` is called. Returns the trail name.

### `axross.stop_trail(name: 'str') -> 'bool'`

Stop a named background trail. Returns True if one was found.

### `axross.list_trails()`

List every recorded trail with its metadata.

### `axross.list_snapshots(trail_name: 'str', *, limit: 'int' = 100)`

List the most recent snapshots of one trail (newest first).

Returns a list of :class:`core.trail.Snapshot`.

### `axross.diff_snapshots(snapshot_a: 'int', snapshot_b: 'int')`

Compare snapshot A to snapshot B (B is the newer / target).

Returns a :class:`core.trail.TrailDiff` with added / removed /
modified path lists.


## Reverse-serve (expose a backend over S3 / WebDAV)

### `axross.serve_s3(backend, *, bind: 'str' = '127.0.0.1', port: 'int' = 9000, read_only: 'bool' = False, auth_token: 'str' = '', root_path: 'str' = '/')`

Expose ``backend`` as a minimum-viable S3 endpoint so any
existing S3 client (aws-cli / restic / rclone / terraform) can
speak to it.

Localhost-bound by default. Pass ``bind="0.0.0.0"`` only when you
intentionally want LAN access; non-local binds without
``auth_token=…`` are refused. Returns a live
:class:`core.reverse_serve.ReverseServer` handle; call
``.shutdown()`` to stop.

### `axross.serve_webdav(backend, *, bind: 'str' = '127.0.0.1', port: 'int' = 8080, read_only: 'bool' = False, auth_token: 'str' = '', root_path: 'str' = '/')`

Expose ``backend`` as a minimum-viable WebDAV endpoint —
``davfs2 mount``, gnome-files (``davs://``), macOS Finder, browser
read-only listings all work. Same OPSEC rules as
:func:`serve_s3`. Returns a :class:`core.reverse_serve.ReverseServer`.


## Result types (dataclasses returned by helpers above)

### `axross.TlsCert(subject: 'str', issuer: 'str', san: 'list[str]', not_before: 'datetime', not_after: 'datetime', serial: 'int', sha256: 'str', raw_der: 'bytes') -> None`

Parsed peer certificate. ``raw_der`` is the binary DER blob
so callers can re-parse with their own tooling if needed.

### `axross.SshHostKey(host: 'str', port: 'int', key_type: 'str', fingerprint_sha256: 'str', fingerprint_md5: 'str', raw: 'bytes') -> None`

SSH host key as returned by paramiko's transport handshake.
``key_type`` is paramiko's name (``ssh-ed25519``, ``ssh-rsa``,
``ecdsa-sha2-nistp256`` …). ``fingerprint_sha256`` is the standard
base64 form OpenSSH's ``ssh-keygen -l`` prints.

### `axross.HttpProbe(status: 'int', url: 'str', headers: 'dict[str, str]', body: 'bytes', truncated: 'bool', redirect_chain: 'list[str]', cert: 'TlsCert | None') -> None`

Result of an :func:`http_probe` call. ``redirect_chain`` lists
every URL we were redirected through (incl. the original); ``cert``
is non-None for HTTPS responses.

### `axross.GrepHit(path: 'str', line_no: 'int', line: 'str') -> None`

GrepHit(path: 'str', line_no: 'int', line: 'str')

### `axross.SnmpVar(oid: 'str', type: 'str', value: 'Any') -> None`

One OID/value pair returned from a GET / WALK.

### `axross.ArchiveEntry(name: 'str', size: 'int', compressed_size: 'int | None', is_dir: 'bool', modified: 'datetime | None') -> None`

One entry from :func:`archive_inspect`. ``size`` is the
uncompressed size in bytes; ``compressed_size`` is what's actually
on disk (None when the format doesn't track it separately —
tar). ``modified`` is a UTC datetime when known.

### `axross.PingResult(host: 'str', port: 'int', reachable: 'bool', rtt_ms: 'float | None') -> None`

Outcome of a TCP-ping. ``rtt_ms`` is ``None`` when the host
didn't accept the connection within the timeout; otherwise it's
the round-trip in milliseconds (connect-only, no full TLS/TCP
handshake).

### `axross.OuiInfo(mac: 'str', oui: 'str', vendor: 'str | None', vendor_long: 'str | None') -> None`

OUI (Organisationally Unique Identifier) lookup result.
``vendor`` is the short name (``"VMware"``); ``vendor_long`` the
full registry entry (``"VMware, Inc."``). Both ``None`` when the
OUI isn't in the database.

### `axross.WhoisInfo(query: 'str', kind: 'str', asn: 'int | None', asn_description: 'str | None', country: 'str | None', cidr: 'str | None', registry: 'str | None', raw: 'dict') -> None`

Result of a :func:`whois` lookup. ``kind`` is ``"ip"`` for
address lookups (RIR / ASN data) or ``"domain"`` for registrar
queries. Some fields will be ``None`` when the source registry
doesn't expose them.

### `axross.TimeSkew(host: 'str', source: 'str', offset_seconds: 'float', rtt_seconds: 'float') -> None`

Result of a :func:`time_skew` measurement. ``offset_seconds``
is positive when the remote source is AHEAD of local; negative
when behind. ``rtt_seconds`` is the round-trip used to compute
the offset (useful for confidence: small RTT → tight offset).
``source`` records which protocol answered.


## UI helpers (REPL / scripts)

### `axross.message(text: 'str', *, title: 'str' = 'axross', level: 'str' = 'info') -> 'None'`

Show a modal informational dialog with the given message.

``level`` selects the state colour + icon: ``"info"`` (blue),
``"success"`` (green), ``"warning"`` (yellow), ``"error"`` (red).
Other values fall back to ``"info"``.

With a running Qt app, opens a :class:`QMessageBox` with a
coloured state-icon and the bundled axross glyph as the window
icon. Without Qt (headless ``--script`` / cron / CI), prints
``"[axross] LEVEL: TITLE — TEXT"`` to stdout so the same code
works in both contexts.

Example::

    axross.message("Backup completed (123 files copied)",
                   level="success")

### `axross.confirm(text: 'str', *, title: 'str' = 'axross', default_yes: 'bool' = False) -> 'bool'`

Show a Yes/No dialog. Returns True on Yes, False otherwise.

Headless fallback (no Qt event loop): reads a single y/n from
stdin so ``--script`` and REPL-without-GUI both work. Accepts
``y/yes/j/ja/s/si/sí`` as Yes; default answer is ``default_yes``.

Example::

    if axross.confirm("Delete 47 files? Cannot be undone.",
                      title="Confirm cleanup"):
        for p in doomed:
            backend.remove(p)

### `axross.toast(text: 'str', *, level: 'str' = 'info', timeout: 'float' = 4.0) -> 'None'`

Non-modal toast in the bottom-right corner of the main window.

Auto-dismisses after ``timeout`` seconds. Multiple toasts stack.
Levels: same colour palette as :func:`message`.

Example::

    axross.toast("Connection lost — retrying", level="error")
    axross.toast("Saved 1.2 MB to /tmp/dump.json",
                 level="success", timeout=2)


## Misc

### `axross.help() -> 'None'`

Print the curated cheat-sheet of the scripting surface.

### `axross.docs(name: 'str | None' = None) -> 'str'`

Return long-form documentation as Markdown.

* ``axross.docs()`` — every public ``axross.*`` function with full
  signature + docstring, grouped by topic. Useful for piping into
  a viewer or saving to a file.
* ``axross.docs("open")`` — just one function. Same shape as
  ``help(axross.open)`` but as a string and including the
  one-paragraph topical context where applicable.
* ``axross.docs("slash")`` — REPL slash-command reference.
* ``axross.docs("scripts")`` — bundled-script reference (names +
  one-line summary pulled from each script's docstring).
* ``axross.docs("backend")`` — the ``FileBackend`` protocol every
  backend implements (``list_dir``, ``open_read``, ``copy``, …).

The output is plain Markdown. The doc-pane in the GUI calls this
too — same source-of-truth for the headless and the GUI surface.


---

## REPL slash-commands

Typed at the `>>> ` prompt; not Python. They never touch the interpreter namespace.

| Command | Effect |
|---|---|
| `.help` | This list |
| `.scripts` | Names of every saved script |
| `.save <name>` | Save the current session's history into `<name>.py` (mode 0o600) |
| `.load <name>` | Print the source of a saved script |
| `.run <name>` | Execute a saved script in the live REPL namespace |
| `.delete <name>` | Remove a saved script |
| `.open` | Print the script-directory path (`~/.config/axross/scripts/`) |


---

## Bundled example scripts

Every script is runnable as `axross --script resources/scripts/<name>.py` or via the REPL `.run <name>` command after copying into `~/.config/axross/scripts/`.

### `atomic_replace.py`

atomic_replace.py — safe in-place rewrite via core.atomic_io.

### `backend_capabilities.py`

backend_capabilities.py — emit a capability matrix across every
registered backend.

### `bookmark_audit.py`

bookmark_audit.py — verify every saved bookmark still resolves.

### `bookmarks_export.py`

bookmarks_export.py — export saved axross bookmarks to JSON / CSV.

### `bulk_rename.py`

bulk_rename.py — regex-based rename across a directory.

### `cas_dedupe.py`

cas_dedupe.py — content-addressable dedupe across backends.

### `cisco_collect.py`

cisco_collect.py — collect IOS show-output across a host list.

### `connection_probe.py`

connection_probe.py — open every saved profile, time the connect.

### `dedupe.py`

dedupe.py — find duplicate files by content hash.

### `du.py`

du.py — disk-usage tree across any backend, sorted by size.

### `encrypted_archive.py`

encrypted_archive.py — pack a directory tree as one encrypted blob.

### `encrypted_stream.py`

encrypted_stream.py — encrypt/decrypt big files via the streaming
codec in ``core.encrypted_overlay``.

### `find_secrets.py`

find_secrets.py — scan a backend for files containing leaked secrets.

### `fingerprint_diff.py`

fingerprint_diff.py — sha256-diff two backend trees.

### `git_changelog.py`

git_changelog.py — extract a flat changelog from a Git-FS branch.

### `gopher_archive.py`

gopher_archive.py — recursively download a Gopher hole.

### `hash_audit.py`

hash_audit.py — verify a manifest against a backend.

### `imap_archive.py`

imap_archive.py — archive an IMAP folder to .eml files on disk.

### `lab_smoke.py`

lab_smoke.py — touch every available backend's root.

### `mirror.py`

mirror.py — incremental mirror between two backends.

### `nntp_subjects.py`

nntp_subjects.py — collect subject lines for the most recent N
articles in a Usenet group.

### `port_scan.py`

port_scan.py — small-and-fast TCP port probe.

### `profile_audit.py`

profile_audit.py — flag risky settings across saved profiles.

### `ramfs_decrypt.py`

ramfs_decrypt.py — decrypt an .axenc file straight into RAM.

### `ramfs_pipeline.py`

ramfs_pipeline.py — chain transforms through a RAM workspace.

### `redact.py`

redact.py — encrypt every file under PATH whose name matches a
regex, leaving other files untouched.

### `s3_inventory.py`

s3_inventory.py — content-type histogram + top-N largest objects.

### `slp_inventory.py`

slp_inventory.py — discover SLP services across a host list.

### `snapshot_walk.py`

snapshot_walk.py — version timeline via core.snapshot_browser.

### `sqlite_export.py`

sqlite_export.py — pack a directory tree into a single SQLite file.

### `tftp_audit.py`

tftp_audit.py — wordlist scan across a list of TFTP servers.

### `webdav_quota.py`

webdav_quota.py — print WebDAV quota across a list of endpoints.


---

## `FileBackend` protocol

Every session object (the thing `axross.open(...)` returns) implements this protocol. Methods are spelled the same on every backend; semantic gaps are surfaced via `BackendCapabilities` and clean `OSError` raises.

### `backend.checksum(self, path: 'str', algorithm: 'str' = 'sha256') -> 'str'`

Return a hex-encoded checksum of the file's content.

Implementations SHOULD use a native server-side checksum when
available (S3 ETag, WebDAV DAV:getetag, Azure Content-MD5,
Dropbox content_hash, Google Drive md5Checksum, ssh shell
sha256sum) instead of streaming the file. The *algorithm*
argument is a hint: backends MAY return whatever native
algorithm they provide and mark it in the return format
(e.g. "md5:abc..."). Callers that need a specific algorithm
must compare the prefix.

Returns ``""`` when the backend has no cheap checksum and
computing one would require a full read — transfer_worker
handles full-read checksums itself in that case.

Raises :class:`OSError` on the underlying protocol failure.

### `backend.chmod(self, path: 'str', mode: 'int') -> 'None'`

Change file permissions. mode is octal (e.g. 0o755).

### `backend.copy(self, src: 'str', dst: 'str') -> 'None'`

Server-side copy of *src* to *dst* within this backend.

Backends with native copy (S3 CopyObject, WebDAV COPY, Azure
Copy Blob, shell ``cp``) MUST implement this without streaming
bytes through the client — that is the whole point of the
primitive. Backends without a native copy raise
:class:`OSError` and callers should fall back to
:func:`core.server_ops.copy_via_stream` which wires
open_read + open_write.

Raises :class:`OSError` when the operation is not supported
or the underlying protocol fails. ``rename()`` remains the
move primitive.

### `backend.disk_usage(self, path: 'str') -> 'tuple[int, int, int]'`

Return (total, used, free) bytes for the filesystem containing path.
Returns (0, 0, 0) if not supported.

### `backend.exists(self, path: 'str') -> 'bool'`

Check if path exists.

### `backend.hardlink(self, target: 'str', link_path: 'str') -> 'None'`

Create a hard link at *link_path* to the same inode as
*target*. Raises :class:`OSError` on backends that don't
model hardlinks. LocalFS overrides this.

### `backend.home(self) -> 'str'`

Return the home/default directory.

### `backend.is_dir(self, path: 'str') -> 'bool'`

Check if path is a directory.

### `backend.join(self, *parts: 'str') -> 'str'`

Join path components using this backend's separator.

### `backend.list_dir(self, path: 'str') -> 'list[FileItem]'`

List directory contents. Raises OSError on failure.

### `backend.list_versions(self, path: 'str') -> 'list'`

Return historical versions of *path*, newest first.

Backends with native versioning (S3, Azure Blob, Dropbox,
GDrive, OneDrive, WebDAV DeltaV) populate this. Backends
without versioning return ``[]``. Each element is a
:class:`models.file_version.FileVersion`.

### `backend.mkdir(self, path: 'str') -> 'None'`

Create a directory. Raises OSError on failure.

### `backend.normalize(self, path: 'str') -> 'str'`

Normalize a path (resolve .., ., etc.).

### `backend.open_read(self, path: 'str') -> 'IO[bytes]'`

Open a file for reading. Caller must close the returned handle.

### `backend.open_version_read(self, path: 'str', version_id: 'str')`

Open a historical version of *path* for streaming read.

Returns a binary file-like handle. The handle MUST be closed
by the caller.

Raises :class:`OSError` when the backend has no versioning
or the version_id no longer exists.

### `backend.open_write(self, path: 'str', append: 'bool' = False) -> 'IO[bytes]'`

Open a file for writing. Caller must close the returned handle.

### `backend.parent(self, path: 'str') -> 'str'`

Return the parent directory of the given path.

### `backend.readlink(self, path: 'str') -> 'str'`

Read symlink target. Raises OSError if not a symlink.

### `backend.remove(self, path: 'str', recursive: 'bool' = False) -> 'None'`

Remove a file or directory. If recursive=True, remove directory tree.

### `backend.rename(self, src: 'str', dst: 'str') -> 'None'`

Rename/move a file or directory.

### `backend.separator(self) -> 'str'`

Return the path separator for this backend.

### `backend.stat(self, path: 'str') -> 'FileItem'`

Get file/directory info. Raises OSError on failure.

### `backend.symlink(self, target: 'str', link_path: 'str') -> 'None'`

Create a symbolic link at *link_path* pointing to *target*.

Raises :class:`OSError` on backends that don't model symlinks.
LocalFS + SFTP-over-SSH override this.
