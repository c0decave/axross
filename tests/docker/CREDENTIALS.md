# Docker Lab Credentials

Human-readable reference for the test-lab profiles defined in
[`axross-lab-profiles.json`](axross-lab-profiles.json). All passwords
are **lab-only** — the containers are throwaway, on an isolated
`10.99.0.0/24` bridge network, and must **never** be reused in
production.

Bring the lab up with `docker compose up -d --build` in this
directory, then import the profiles via
`axross → File → Import Profiles (JSON)… → axross-lab-profiles.json`.

## Credential table

| Profile                         | Protocol | Host : Port       | Username          | Password                  | Extras                                                                         |
|---------------------------------|----------|-------------------|-------------------|---------------------------|--------------------------------------------------------------------------------|
| Lab SFTP alpha                  | SFTP     | 10.99.0.10 : 22   | `alpha`           | `alpha123`                | —                                                                              |
| Lab SCP alpha                   | SCP      | 10.99.0.10 : 22   | `alpha`           | `alpha123`                | Shares SSH container with SFTP alpha                                           |
| Lab SFTP beta                   | SFTP     | 10.99.0.11 : 22   | `beta`            | `beta123`                 | —                                                                              |
| Lab SFTP gamma                  | SFTP     | 10.99.0.12 : 22   | `gamma`           | `gamma123`                | —                                                                              |
| Lab FTP                         | FTP      | 10.99.0.30 : 21   | `ftpuser`         | `ftp123`                  | vsftpd                                                                         |
| Lab FTPS                        | FTPS     | 10.99.0.38 : 21   | `ftpsuser`        | `ftps123`                 | Self-signed cert; `ftps_verify_tls=False`                                      |
| Lab Tiny-FTP (quota demo)       | FTP      | 10.99.0.60 : 21   | `tinyftp`         | `tiny123`                 | Quota-limited — forces disk-usage corner cases                                 |
| Lab SMB                         | SMB      | 10.99.0.31 : 445  | `smbuser`         | `smb123`                  | Share: `testshare`                                                             |
| Lab WebDAV                      | WebDAV   | 10.99.0.32 : 80   | `davuser`         | `dav123`                  | URL: `http://10.99.0.32:80`                                                    |
| Lab S3 (MinIO)                  | S3       | 10.99.0.33 : 9000 | `minioadmin`      | `minioadmin123`           | Bucket `testbucket`, endpoint `http://10.99.0.33:9000`                         |
| Lab Rsync (daemon)              | Rsync    | 10.99.0.34 : 873  | `rsyncuser`       | `rsync123`                | Module `testmod`                                                               |
| Lab NFS v4                      | NFS      | 10.99.0.35 : 2049 | —                 | —                         | Export `/`; **kernel NFS client required on host**                             |
| Lab IMAP                        | IMAP     | 10.99.0.36 : 143  | `imapuser`        | `imap123`                 | Dovecot                                                                        |
| Lab Telnet                      | Telnet   | 10.99.0.37 : 23   | `telnetuser`      | `telnet123`               | xinetd + telnetd — plaintext by design                                         |
| Lab Azure Blob (Azurite)        | Azure    | 10.99.0.39 : 10000 | `devstoreaccount1` | *(see below)*           | Emulator, container `axross-test`                                              |
| Lab iSCSI                       | iSCSI    | 10.99.0.40 : 3260 | —                 | —                         | IQN `iqn.2024-01.com.axross:test-target`; **needs `iscsi_tcp` kernel module** |

### Azurite connection string
Azure Blob uses a static emulator connection string rather than a
password field. The import-profile flow puts it in
`azure_connection_string`:

```
DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==;BlobEndpoint=http://10.99.0.39:10000/devstoreaccount1;
```

That key is the **well-known Azurite dev account key** published in
the Microsoft docs — it's the same on every Azurite install and is
never valid against real Azure.

## Remote bookmarks against the lab

Every profile above can be bookmarked:

1. Import the JSON, pick a profile, click **Connect**.
2. In the newly-opened pane, navigate to a subfolder.
3. Press **F8** (or Right-click → Bookmark This Directory).
4. Close the pane; the bookmark appears in the left sidebar.
5. Click the sidebar entry — the app re-opens the connection (using
   the stored or prompted password) and navigates to the saved path.

For profiles where `store_password=false` (all lab entries), the
first bookmark click prompts for the password; the "Save password?"
follow-up persists it so subsequent clicks are non-interactive.

## `_password` field in the JSON

The `axross-lab-profiles.json` file ships plaintext `_password`
fields next to the standard profile data. This is **lab-only
convenience** — the real `profile.json` format never stores
passwords there (they go into the OS keyring via `store_password`).
The import path reads `_password` during `verify_lab_profiles.py`
and an extended import helper to pre-populate the keyring for
scripted test runs; normal application use doesn't see these.

## Rotating a lab password

Nothing fancy is needed — the passwords are baked into each
container's entrypoint script under [`tests/docker/`](.). To
rotate:

1. Change the entry in the container's Dockerfile / config.
2. Update the matching `_password` in `axross-lab-profiles.json`.
3. Update the row in this document.
4. `docker compose build && docker compose up -d`.

## Security note

These credentials are in a git-tracked file and exist only for the
throwaway Docker lab. An attacker reading the repo gains no real
access — the containers are local to your machine and the
`10.99.0.0/24` network doesn't route. If you ever expose a lab
container to a real network, rotate every password first.
