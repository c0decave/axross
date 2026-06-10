# Test Coverage Matrix

Stand: nach den Erweiterungs-Sessions (Logos / WebDAV-Refactor /
psutil weg / Gopher / TFTP-find / REPL / DB-FS / NNTP / Git / PJL /
SLP / rsh / Cisco-Telnet / Doc-Pane / Layout-Presets / Shell-Upgrade
/ Internal-API-Skripte). Docker-Lab muss laufen für die `live`-
markierten Tests.

## Gesamtzahlen

| Suite | Tests | Runs on |
|---|---|---|
| `test_protocols.py` | 215 | docker test-runner-iscsi (host-net) |
| `test_network.py` (SSH/Proxy) | 33 | docker test-runner |
| `test_new_features.py` | 12 | docker test-runner |
| `test_backend_regressions.py` | ~95 (inkl. neue Backends + Scripts) | host (Qt) |
| `test_e2e.py` | 25 | host (Qt) |
| `test_regressions.py` | 16 | host (Qt) |
| `test_pane_layout_regressions.py` | 4 | host (Qt) |
| `test_hardening_regressions.py` | ~145 (inkl. F1-F30) | host (Qt) |
| **Gesamt** | **~545 + 110 subtests** | |

Letzte volle Sweep (host-Suiten ohne live-Lab): **1360 passed,
5 skipped, 110 subtests passed, 0 failures**.

Lint: `ruff` clean auf allen neuen Modulen
(`core/scripting.py`, `core/rsh_client.py`, `core/telnet_cisco.py`,
`core/db_fs_base.py`, `core/sqlite_fs_client.py`,
`core/postgres_fs_client.py`, `core/redis_fs_client.py`,
`core/mongo_fs_client.py`, `core/git_fs_client.py`,
`core/git_fs_writer_helper.py`, `core/pjl_client.py`,
`core/slp_lib.py`, `core/slp_client.py`, `core/nntp_lib.py`,
`core/nntp_client.py`, `core/gopher_client.py`,
`ui/repl_widget.py`, `ui/layout_presets.py`,
`resources/scripts/*.py`).

## Matrix 1: Backend-Operation × Protokoll (Happy-Path)

Legende: ✓ live gegen Docker verifiziert · `·` nicht getestet · ⚠ raises-OSError-Kontrakt geprüft

| Methode | FTP | FTPS | SMB | WebDAV | S3 | Rsync | NFS | iSCSI | IMAP | Telnet | Azure | LocalFS |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| list_dir | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| stat | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| is_dir | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| exists | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| mkdir | ✓ | ✓ | ✓ | ✓ | ✓ | · | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| remove | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| rename | ✓ | ✓ | ✓ | ✓ | ✓ | · | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| open_read | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| open_write | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| normalize | · | · | · | · | · | · | · | · | · | ✓ | · | · |
| separator | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| join | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| parent | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| home | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| chmod | ⚠ | ⚠ | ⚠ | ⚠ | · | · | ✓ | ✓ | ⚠ | ✓ | ⚠ | ✓ |
| readlink | ⚠ | ⚠ | · | · | · | · | ✓ | ✓ | ⚠ | ✓ | ⚠ | ✓ |
| disk_usage | ✓ | ✓ | ✓ | ✓ | ✓ | · | ✓ | ✓ | ⚠ | ✓ | ⚠ | ✓ |
| checksum | ✓ | · | · | ✓ | ✓ | · | · | · | · | · | · | ✓ |
| copy (server-side) | ⚠ | · | · | ✓ | ✓ | · | · | · | · | · | · | ✓ |
| list_versions | ⚠ | ⚠ | ⚠ | ✓ (empty) | ✓ | ⚠ | ⚠ | ⚠ | ⚠ | ⚠ | ⚠ | ⚠ |
| open_version_read | ⚠ | ⚠ | ⚠ | ⚠ | ✓ | ⚠ | ⚠ | ⚠ | ⚠ | ⚠ | ⚠ | ⚠ |
| trash (core.trash) | ✓ | · | ✓ | ✓ | ✓ | · | · | · | · | · | · | ✓ |
| xlink (core.xlink) | ✓ | · | · | ✓ | ✓ | · | · | · | · | · | · | ✓ |
| encrypted (core.encrypted_overlay) | ✓ | · | · | ✓ | ✓ | · | · | · | · | · | · | ✓ |

## Neue Test-Sektionen (Phase 1-4 in `test_protocols.py`)

| Sektion | Thema | Tests |
|---|---|:-:|
| 16 | Checksum primitives | 5 |
| 17 | Atomic-write helper | 2 |
| 18 | Server-side copy | 3 |
| 19 | Version history | 4 |
| 20 | Universal trash | 5 |
| 21 | Cross-protocol symlinks | 3 |
| 22 | Encrypted overlay | 3 |

## Matrix 2: Sad-Path × Protokoll

| Sad Case | FTP | FTPS | SMB | WebDAV | S3 | Rsync | NFS | iSCSI | IMAP | Telnet | Azure |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| wrong_credentials | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | n/a | n/a | ✓ | ✓ | ✓ |
| unreachable_host | ✓ | · | ✓ | · | · | · | · | · | · | ✓ | · |
| unicode_filename | ✓ | · | ✓ | ✓ | ✓ | · | · | · | · | · | · |
| unicode_mkdir_rename_stat | ✓ | · | · | · | · | · | · | · | · | · | · |
| full_unicode_server_limit_pinned | ✓ | · | · | · | · | · | · | · | · | · | · |
| empty_file_rt | ✓ | · | ✓ | ✓ | ✓ | · | · | · | · | ✓ | · |
| malformed_path | ✓ | · | ✓ | · | ✓ | · | · | · | · | · | · |
| path_traversal (via `_safe_basename`) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| mid_transfer_connection_drop | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | kernel | kernel | ✓ | ✓ | ✓ |
| bandwidth_cap | · | · | · | ✓ | ✓ | · | kernel | kernel | · | ✓ | · |
| high_latency | · | · | · | ✓ | ✓ | · | kernel | kernel | ✓ | · | · |
| disk_full / ENOSPC | ✓ | · | · | · | · | · | · | · | · | · | · |
| tls_self_signed_rejected_by_default | n/a | ✓ | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a |
| tls_hostname_mismatch | n/a | ✓ | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a |
| symlink_loop | n/a | n/a | n/a | n/a | n/a | n/a | · | ✓ | n/a | n/a | n/a |

## Matrix 3: Capacity tests

| Protokoll | Größe | Integrity-Check |
|---|---|---|
| SSH (SFTP) | **1 GiB** | SHA-256 |
| FTP | 100 MiB | SHA-256 |
| SMB | 100 MiB | SHA-256 |
| WebDAV | 100 MiB | SHA-256 |
| S3 | 100 MiB | SHA-256 |
| Rsync | 100 MiB | SHA-256 |
| NFS | 100 MiB | SHA-256 |
| Azure Blob | 100 MiB | SHA-256 |
| iSCSI | 50 MiB | SHA-256 (LUN-limited) |

## Matrix 4: Concurrency

| Test | Deckung |
|---|---|
| SMB: shared session, 2 threads, separate Dateien | ✓ |
| S3: 4 parallele Uploads zu distinkten Keys | ✓ |
| TransferManager: 5 queued LocalFS-Jobs | ✓ (host) |

smbprotocol's Session-Pool ist prozessweit / eine Session pro Host — dokumentiert als Library-Limitation.

## Matrix 5: Docker-Lab-Endpoints

| IP | Service | Image | Besonderheiten |
|---|---|---|---|
| 10.99.0.10-12 | ssh-alpha/beta/gamma | OpenSSH | 3 Server für Cross-Host-Tests |
| 10.99.0.20 | socks-proxy | dante | SOCKS4 / SOCKS5 |
| 10.99.0.21 | http-proxy | tinyproxy | HTTP proxy / CONNECT; allow-list covers tested lab TCP ports |
| 10.99.0.30 | ftp-server | stilliard/pure-ftpd | vsftpd→pure-ftpd migriert (SIGSEGV) |
| 10.99.0.31 | smb-server | Samba | |
| 10.99.0.32 | webdav-server | Apache mod_dav | |
| 10.99.0.33 | s3-server | MinIO | |
| 10.99.0.34 | rsync-server | rsyncd | |
| 10.99.0.35 | nfs-server | itsthenetwork/nfs-server-alpine | ganesha→kernel-NFS migriert |
| 10.99.0.36 | imap-server | Dovecot | |
| 10.99.0.37 | telnet-server | inetutils-telnetd | |
| 10.99.0.38 | ftps-server | stilliard/pure-ftpd | explicit+implicit TLS, self-signed |
| 10.99.0.39 | azurite-server | mcr.microsoft.com/azure-storage/azurite | `--skipApiVersionCheck` |
| 10.99.0.40 | iscsi-server | tgt | `tgt-admin --execute`, LUN ext4 pre-formatiert |
| 10.99.0.41 | tftp-server | tftpd-hpa | seed files in /srv/tftp |
| 10.99.0.42 | **rsh-server** | rsh-redone-server + xinetd (debian:bullseye) | TCP 513/514. user `axuser`, .rhosts `+ +`. **Live-verifiziert** in dieser Runde. |
| 10.99.0.50 | toxiproxy | ghcr.io/shopify/toxiproxy | TCP fault injection |
| 10.99.0.60 | tiny-ftp-server | stilliard/pure-ftpd | 16 MB tmpfs home (quota testing) |

## Matrix 6: Hardening-Regressions (host-side)

136 Tests in `tests/test_hardening_regressions.py` (1 pre-existing
Skip bei fehlendem `google-auth`). Hauptklassen:

| Test-Klasse | Tests | Gebiet |
|---|:-:|---|
| SecureStorageTests | 5 | 0o600-from-birth, atomic replace, parent 0o700 |
| OAuthTokenPersistenceTests | 1 | Dropbox token via helper |
| TelnetTransportTests | 6 | Host-Validation, Port, IPv6, WARNING-Log |
| ProxyErrorLoggingTests | 2 | Refused logs WARNING, chains cause |
| CredentialsLoggingTests | 2 | WARNING-Level + Profilname, ImportError |
| TransferManagerDirectoryErrorTests | 1 | `directory_error` signal |
| DropboxTokenLoaderTests | 6 | Schema-Validation |
| SSHHostKeyTrustLogTests | 1 | TOFU-Log: Key-Type + SHA256 |
| ImapPlaintextWarningTests | 1 | WARNING bei `use_ssl=False` |
| GDriveTokenRefreshLoggingTests | 2 (1 skip) | Refresh-Exception |
| WebDavXxeHardeningTests | 2 | defusedxml, fail-closed |
| TelnetMarkerRandomnessTests | 2 | `secrets.token_hex` |
| SafeBasenameTests | 8 | `.`, `..`, `/`, `\`, `\x00`, Unicode, normal |
| TransferManagerFilenameSanitizationTests | 1 | `..`-Eintrag skipped |
| QApplicationSingletonTests | 1 | Widget-Konstruktion |
| TransferCancellationTests | 1 | `cancel_event` → `CANCELLED` |
| TransferManagerConcurrencyTests | 1 | 5 queued jobs alle DONE |
| ChecksumPrimitiveTests | 3 | sha256/md5 aliases, error on unknown |
| TransferIntegrityVerificationTests | 3 | Post-transfer CRC mismatch → FAIL |
| AtimeSupportTests | 3 | atime/created Felder auf FileItem |
| AtomicWriteTests | 3 | tmp-then-rename, rollback on failure |
| ServerSideCopyMoveTests | 4 | native copy + stream fallback |
| WatcherTests | 3 | PollingWatcher created/modified/deleted |
| CloudVersioningTests | 7 | Mock-SDK: Dropbox/GDrive/OneDrive/Azure |
| UniversalTrashTests | 11 | trash/restore/empty, rollback, orphan |
| CrossProtocolLinkTests | 12 | .axlink schema + happy/sad |
| EncryptedOverlayTests | 14 | AES-GCM roundtrip + tamper + KDF guard |
| ContentAddressableTests | 10 | CAS upsert/find/duplicates/URL |
| SnapshotBrowserTests | 9 | Timeline merge + filter + read_snapshot |
| MetadataIndexTests | 11 | SQLite search by name/ext/size/mtime |

## Matrix 7: Neue Backends + Features (Erweiterungs-Sessions)

Stand jeder Komponente nach den Erweiterungs-Runden. Drei Achsen:
**Unit** = host-side Test mit in-process Fakes / Mocks; **Live** =
gegen einen real laufenden Docker-Container; **Wire** = Protokoll-
Handshake direkt verifiziert (Hex-Frames durch).

| Komponente | Modul | Unit | Live | Wire | Anmerkung |
|---|---|:-:|:-:|:-:|---|
| **Gopher** (RFC 1436) | `core/gopher_client.py` | ✓ | · | ✓ | 4 Tests, in-proc TCP-Server. Keine Gopher-Container im Lab. |
| **NNTP** wire-lib | `core/nntp_lib.py` | ✓ | · | ✓ | 2 Tests, scripted-fake TCP. STARTTLS/AUTHINFO Code-Pfad nur unit. |
| **NNTP** Session | `core/nntp_client.py` | ✓ | · | · | Hängt am wire-lib; kein Live-Innd-Container. |
| **SQLite-FS** | `core/sqlite_fs_client.py` | ✓ | ✓ | · | `test_full_lifecycle` round-trip mit echtem SQLite. |
| **Postgres-FS** | `core/postgres_fs_client.py` | · | · | · | Adapter-Code zeile-für-zeile parallel zu SQLite (gleiche `_DbFsBackend`-Basis); unit braucht `psycopg`-Container. |
| **Redis-FS** | `core/redis_fs_client.py` | · | · | · | Wie Postgres — Adapter, nicht separat unit-tested. |
| **Mongo GridFS** | `core/mongo_fs_client.py` | · | · | · | Wie Postgres. |
| **Git-FS** (dulwich) | `core/git_fs_client.py` | ✓ | ✓ | · | 5 Tests gegen lokale bare-Repos inkl. force-push refusal. |
| **PJL** (Drucker-FS) | `core/pjl_client.py` | ✓ | · | ✓ | 3 Tests inkl. Safety-Probe (accept/reject/silent). Kein Drucker im Lab. |
| **SLP** (RFC 2608) | `core/slp_lib.py`, `core/slp_client.py` | ✓ | · | ✓ | 3 Tests inkl. multicast-refused + no-SrvReg static-grep. |
| **rsh / rcp** | `core/rsh_client.py` | ✓ | ✓ ⓘ | ✓ | 4 Tests via mocked subprocess + **Live**-Container `10.99.0.42` verifiziert (xinetd + rsh-redone-server, alle FileBackend-Verben round-trippen). `test_rsh_live_round_trip` skipt wenn `/usr/bin/rsh` nicht auf PATH. |
| **Cisco-Telnet** (read-only) | `core/telnet_cisco.py` | ✓ | · | · | 2 Parser-Tests. Kein IOS-Image im Lab. |
| **TFTP find_files** | `core/tftp_client.py:find_files` | ✓ | · | · | 4 Tests + bundled wordlist (161 Einträge). |
| **WebDAV** Refactor (eigene Impl) | `core/webdav_client.py` | ✓ | ✓ | · | Apache mod_dav: **27/33 live** (6 env-abhängig: SOCKS-Proxy, Toxiproxy). Refaktorierung von `webdavclient3` → `requests + defusedxml`. |
| **psutil → /proc/meminfo** | `core/ram_fs.py` | ✓ | · | · | Linux: kernel-direct. Non-Linux: psutil-Fallback. |
| **REPL Widget** | `ui/repl_widget.py` | ✓ | · | · | Multi-line / history / safe-Tab / slash-commands smoke-tested. |
| **Doc-Pane** (4 tabs) | `ui/repl_widget.py:_ApiDocPane` | ✓ | · | · | Build-Smoke + 46 API-Items in der API-Tab. Re-render in `showEvent`. |
| **Layout-Presets** | `ui/layout_presets.py` | ✓ | · | · | DSL-Validitäts-Test + Apply-Smoke. 7 Presets, Cycle Ctrl+Alt+L. |
| **Terminal Font-Zoom** | `ui/terminal_widget.py` | ✓ | · | · | Smoke: zoom-clamp + reset. |
| **Terminal Themes** | `ui/terminal_widget.py:TERMINAL_THEMES` | ✓ | · | · | Smoke + safe-fallback bei unbekanntem Namen. Per-Profile via `Profile.terminal_theme` + `TerminalPaneWidget` honored. |
| **+Local-Subshell** | `ui/terminal_widget.py:_spawn_local_subshell` | ✓ | · | · | Spawn fügt Combo-Eintrag hinzu **und** startet Session. |
| **Search-in-Scrollback** | `ui/terminal_widget.py:_TerminalSearchBar` | ✓ | · | · | Build-Smoke + resize-pin via `resizeEvent`. **Hotkey Ctrl+Shift+F** (nicht Ctrl+F — vim/less/fzf bleiben unbeeinflusst). |
| **`axross.docs(name)`** | `core/scripting.py` | ✓ | · | · | Allow-list strict gegen `__all__` (kein arbitrary-attr-Leak). 4 Quality-Regression-Tests. |
| **Docstring-Qualität** | `tests/test_backend_regressions.py` | ✓ | · | · | Min 40 Zeichen pro `__all__`-Funktion; rendert `(no docstring)` ist illegal. |
| **MCP `script_*` Tools** | `core/mcp_server.py` | ✓ | · | · | Build-Smoke gated by `--mcp-allow-scripts`. |
| **32 Bundled-Skripte** | `resources/scripts/*.py` | siehe unten | | | |

### Bundled-Skript-Coverage

| Skript | Test | Anmerkung |
|---|---|---|
| `mirror.py` | ✓ E2E | `test_mirror_skips_matching_files` |
| `dedupe.py` | ✓ E2E | `test_dedupe_finds_identical_files` |
| `du.py` | ✓ E2E | `test_du_against_localfs` |
| `bulk_rename.py` | ✓ E2E | dry-run preserves files |
| `find_secrets.py` | ✓ E2E | catches AWS access key |
| `port_scan.py` | ✓ E2E | finds open loopback port |
| `redact.py` | ✓ E2E | dry-run lists targets |
| `hash_audit.py` | ✓ E2E | mismatch + missing detected |
| `fingerprint_diff.py` | ✓ E2E | added/removed/changed/unchanged |
| `sqlite_export.py` | ✓ E2E | pack + re-mount |
| `ramfs_decrypt.py` | ✓ E2E | encrypt → decrypt-into-RAM |
| `bookmarks_export.py` | ✓ E2E | JSON round-trip mit HOME-isoliert |
| `s3_inventory.py` | ✓ E2E | walk + extension histogram (LocalFS proxy) |
| `git_changelog.py` | ✓ E2E | local bare repo + 3 commits |
| `gopher_archive.py` | ✓ E2E | in-proc Gopher server |
| `atomic_replace.py` | ✓ E2E | round-trip rewrite |
| `encrypted_archive.py` | ✓ E2E + zip-slip | pack/unpack + sibling-prefix-attack refused |
| `encrypted_stream.py` | ✓ E2E | streaming AEAD round-trip 300 KiB |
| `backend_capabilities.py` | ✓ E2E | matrix contains every protocol_id |
| `tftp_audit.py` | smoke | braucht TFTP-Container mit content |
| `slp_inventory.py` | smoke | braucht SLP-Daemon (kein Container im Lab) |
| `nntp_subjects.py` | smoke | braucht NNTP-Server |
| `webdav_quota.py` | smoke | braucht WebDAV mit RFC-4331-Quota |
| `cisco_collect.py` | smoke | braucht Cisco IOS Box |
| `imap_archive.py` | smoke | braucht IMAP mailbox mit Inhalt |
| `lab_smoke.py` | smoke | sinnvoll erst mit konfigurierten Profilen |
| `ramfs_pipeline.py` | smoke | passphrase-rotation: kein E2E aber Imports OK |
| `bookmark_audit.py` | smoke | braucht reale Profile/Bookmarks |
| `profile_audit.py` | smoke | braucht reale Profile-Setups |
| `cas_dedupe.py` | smoke | braucht CAS-DB-Setup |
| `snapshot_walk.py` | smoke | braucht versionierten Backend |

**Smoke-Subtest pro Skript** läuft via `test_every_script_imports_with_docstring` —
20 von 31 haben full E2E, 11 sind import-validated only.

## Bestätigt nicht verifiziert (BACKLOG)

Dokumentiert in [docs/BACKLOG.md](BACKLOG.md):

1. **OAuth-Flows** (OneDrive, SharePoint, GDrive, Dropbox) — brauchen echte Test-Accounts
2. **HTTP 429 / SDK-Retry-Policy** — Lab-Server emittieren nativ kein 429; braucht programmierbaren Mock-HTTP-Server
3. **FTP data-channel fault injection** — PASV gibt Server-IP zurück, Datenkanal umgeht toxiproxy
4. **smbprotocol: zwei unabhängige Sessions pro Host** — Library-Limitation

## Echte Bugs gefunden beim Schreiben der Tests

| Commit | Datei | Bug |
|---|---|---|
| (live) | `core/webdav_client.py` | `is_dir('/')` returned False auf Apache mod_dav nach Refactor (asymmetrisches `rstrip("/")` mit `or "/"`) |
| (live) | 8 neue Backends | `join("/", "x")` baute `//x` (truthy `"/"` survived strip → empty cleaned) — Gopher-archive E2E offenbarte es, alle 8 gleich gepatcht |
| Round 4 F19 | `core/scripting.py` | `nntp_post(subject)` mit `\r\n\r\n` → SMTP-style header-injection |
| Round 4 F20 | `core/rsh_client.py` | Pfad mit Lead-`-` (`/-rf`) konnte als Flag re-interpretiert werden |
| Round 4 F21 | `core/telnet_cisco.py` | username/password mit CR/LF → command-smuggling |
| Round 5 F22 | `resources/scripts/encrypted_archive.py` | zip-slip prefix off-by-one (`/tmp/foo` matched `/tmp/foobar/x`) |
| Round 5 F23 | `resources/scripts/encrypted_archive.py` | Tarfile-Filter-Fallback war effektiv unfiltered auf Python <3.12 |
| Round 5 F24 | `core/scripting.py` | `docs(name)` erlaubte arbitrary-attr-Zugriff (`docs("logging")` leakte stdlib) |
| Round 5 F27 | `core/profiles.py` + `ui/terminal_pane.py` | `terminal_theme`-Field war dead data — nie gelesen |
| Round 5 F28 | `ui/terminal_widget.py` | `+Local`-Button fügte nur Combo-Eintrag, startete keine Session |
| Round 5 F29 | `ui/terminal_widget.py` | Ctrl+F klaute remote-shell-Tasten von vim/less/fzf |
| `92adbbc` | `core/secure_storage.py` (neu) | OAuth-Token-Dateien kurzzeitig 0o644 (TOCTOU) |
| `92adbbc` | `core/webdav_client.py` | XXE via `xml.etree.ElementTree.fromstring` auf Remote-XML |
| `92adbbc` | `core/telnet_client.py` | Schwacher `random.randint` für Shell-Marker |
| `92adbbc` | `core/telnet_client.py` | Hartverdrahtetes `AF_INET`, kein IPv6 |
| `92adbbc` | `core/nfs_client.py` | `mountport=` auch für NFSv4 gesetzt (unsupported) |
| `92adbbc` | `core/iscsi_client.py` | `ISCSI_ERR_SESSION_EXISTS` nicht toleriert |
| `92adbbc` | `core/iscsi_client.py` | `_wait_for_device` pollte nur udev-Symlinks |
| `f26c2a3` | `core/transfer_manager.py` | Remote-Filename `..` konnte Zielordner escapen |
| `f26c2a3` | `core/webdav_client.py` | defusedxml-Fallback öffnete stdlib-Parser |
| `2b53dce` | `core/ftp_client.py` | `UnicodeDecodeError` crashte `is_dir()` |
| `2b53dce` | `core/smb_client.py` | Lazy auth + globales Session-Registry carryover |
| `1284bc9` | `core/webdav_client.py` | `stat()` `is_dir=False` auf Apache mod_dav (content_type ignoriert) |
| `9df80bb` | `core/smb_client.py` | Race condition in `__init__` delete+register+probe |
| `09996fb` | `core/ftp_client.py` | **FTPS ignorierte Server-Certs komplett (CERT_NONE)** |

## Commit-Historie der Test-Evolution

```
381cf66  init
92adbbc  Harden OAuth storage, protocol clients, docker test lab  (27 Dateien)
f26c2a3  Block remote-filename path escape + fail-closed WebDAV XML + Azurite
d117dc7  Fill protocol-coverage matrix: path helpers, chmod, readlink, disk_usage
2b53dce  Sad/edge-path coverage + two real backend bugs in the process
1284bc9  WebDAV stat: content_type fallback for directory detection
7306d63  FTP unicode: mkdir/rename/stat live + pin server's Emoji/CJK limit
4f35dc6  iSCSI: rename + symlink-loop readlink coverage
c0f39e9  Toxiproxy + mid-transfer connection-drop tests
326a3a6  Toxiproxy bandwidth + latency toxics; HTTP 429 → backlog
0cd2826  Large-file round-trips: 100 MB × 8 protocols + 1 GB SSH canary
9df80bb  Concurrency tests + SMB per-host init lock
a24a5d6  Quota-full via tmpfs: tiny-ftp-server + LocalFS ENOSPC
09996fb  Fix: FTPS was silently accepting any server cert (MITM vulnerability)

────── Phase 1-3a (filesystem capabilities) ──────
   Capabilities refinement + checksums (sha256/md5/etag alias)
   FileItem: atime + created fields
   atomic_write helper (native-atomic vs tmp-then-rename)
   Server-side copy + rename-based move with fallback
   File watching (PollingWatcher + optional watchdog)

────── Phase 3b-4f (extended filesystem features) ──────
3d85f12  Phase 3b: Snapshot / version history API
         (S3/Dropbox/GDrive/OneDrive/Azure native versioning)
49ac604  Phase 4a: Universal trash (core.trash)
4403297  Phase 4b: Cross-protocol symlinks (.axlink)
fb6c2ab  Phase 4c: Encrypted overlay (AES-256-GCM + PBKDF2)
1f2fa6b  Phase 4d: Content-addressable layer (core.cas)
8154b45  Phase 4e: Virtual snapshot browser
487e2a4  Phase 4f: Offline metadata index (SQLite search)
```
