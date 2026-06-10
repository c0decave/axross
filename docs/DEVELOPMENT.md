# Development

This document covers everything below the "user-facing" line: how to
set up a working environment, run the test suite, drive the Docker
protocol lab, and read the coverage matrix honestly.

For the user-facing tour see [USAGE.md](USAGE.md). For installation
see [INSTALL.md](../INSTALL.md). For the contribution policy see
[CONTRIBUTING.md](../CONTRIBUTING.md).

## Getting set up

```bash
git clone https://github.com/c0decave/axross
cd axross
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[all]"
pip install -r dev-requirements.txt
```

`dev-requirements.txt` covers `pytest`, coverage, `ruff`, `build`,
plus `cryptography` and `jsonschema` that some MCP tests exercise
directly.

## Repository layout

```
axross/
├── core/         # Backend protocol clients + feature layer
├── ui/           # PyQt6 widgets, dialogs, main window
├── models/       # Data classes shared by core + ui
├── tests/        # pytest suites (host + protocol + e2e)
│   └── docker/   # docker-compose lab for protocol tests
├── docs/         # User-facing + dev-facing docs (this folder)
├── build/        # PyInstaller spec + AppImage resources
├── scripts/      # Build / packaging helpers
├── security/     # Internal red-team scanner toolkit
├── main.py       # CLI entry point
└── pyproject.toml
```

## Host test suite (no Docker required)

```bash
QT_QPA_PLATFORM=offscreen .venv/bin/pytest -q \
    tests/test_hardening_regressions.py \
    tests/test_regressions.py \
    tests/test_new_features.py \
    tests/test_backend_regressions.py \
    tests/test_pane_layout_regressions.py \
    tests/test_e2e.py
```

Expected: ≥ 1130 passed, 5 skipped, 1 warning in ~30 s.

The five skipped tests in the default run are:

* Three FUSE tests gated on `fusepy` being importable.
* One GDrive-refresh test gated on `google-auth`.
* One end-to-end test that needs the docker lab to be up.

## Docker lab

The lab spins up real protocol servers (vsftpd, Samba, MinIO,
Apache mod_dav, OpenSSH, Dovecot, telnetd, Azurite, etc.) so the
protocol tests run against actual implementations.

```bash
cd tests/docker && docker compose up -d --build
cd ../..
.venv/bin/pytest tests/test_protocols.py tests/test_network.py
```

Service catalogue with ports + credentials:
[tests/docker/TESTENV.md](../tests/docker/TESTENV.md). Compose
file: [tests/docker/docker-compose.yml](../tests/docker/docker-compose.yml).

### Protocol coverage matrix (honest)

Not every backend is cleanly exercised by the lab. Some protocols
can't be containerised (OAuth SaaS, Windows-only subsystems);
others are containerised but the tests skip without extra host
privileges. This table is the source of truth — if a row says "⚠"
or "❌", don't trust the green CI badge alone.

| Protocol          | Container              | Test section                                | Status              | Reality check |
|-------------------|------------------------|---------------------------------------------|---------------------|---------------|
| SFTP              | ssh-alpha/beta/gamma   | `test_ssh_*` + cross-protocol              | ✅ real             | paramiko against OpenSSH in container |
| SCP               | (shares SSH)           | indirect via SFTP tests                    | ⚠ partial           | not separately exercised — paramiko reuses the SSH channel |
| FTP               | ftp-server             | Section 1                                  | ✅ real             | vsftpd |
| FTPS              | ftps-server            | Section 1b                                 | ✅ real             | explicit AUTH TLS + implicit :990 |
| SMB / CIFS        | smb-server             | Section 2                                  | ✅ real             | Samba |
| WebDAV            | webdav-server          | Section 3                                  | ✅ real             | Apache mod_dav |
| S3-compatible     | s3-server (MinIO)      | Section 4                                  | ✅ real             | MinIO speaks the S3 wire protocol |
| Rsync             | rsync-server           | Section 5                                  | ✅ real             | rsyncd daemon |
| IMAP              | imap-server            | Section 7                                  | ✅ real             | Dovecot |
| Telnet            | telnet-server          | Section 8                                  | ✅ real             | xinetd + telnetd |
| NFS               | nfs-server             | Section 6                                  | ⚠ skipped           | kernel NFS client can't bind inside the Docker bridge; runs only when the test runner is privileged + `modprobe nfs` on the host. |
| iSCSI             | iscsi-server           | Section 6b                                 | ⚠ privileged-only   | needs `iscsi_tcp` kernel module + the `test-runner-iscsi` container (privileged, host networking). Skipped otherwise. |
| Azure Blob        | azurite-server         | Section 9 + 13                             | ⚠ emulator          | Azurite, not real Azure. Wire-level quirks of the real service won't show up here. |
| Azure Files       | azurite-server         | —                                          | ❌ untested         | Azurite supports the API but no dedicated tests. |
| OneDrive          | —                      | —                                          | ❌ untested         | MS Graph OAuth only; no Docker equivalent. |
| SharePoint        | —                      | —                                          | ❌ untested         | Same. |
| Google Drive      | —                      | —                                          | ❌ untested         | Google OAuth; no Docker equivalent. |
| Dropbox           | —                      | —                                          | ❌ untested         | Dropbox OAuth; no Docker equivalent. |
| WinRM             | —                      | `tests/test_windows_integration.py`        | ❌ needs real host  | PowerShell-Remoting against a real Windows target. |
| WMI / DCOM        | —                      | `tests/test_windows_integration.py`        | ❌ needs real host  | Same. |
| Exchange (EWS)    | —                      | —                                          | ❌ untested         | No Exchange emulator exists; real Office 365 / on-prem required. |
| DFS-N             | —                      | `tests/test_windows_integration.py`        | ❌ needs real host  | DFS referrals need an Active-Directory namespace. |
| ADB (Android)     | —                      | `AdbClientTests` in hardening regressions   | ⚠ mocked only       | Wire protocol + shell-quoting + push/pull mocked. Real-device tests need an Android phone with USB debugging accepted. |
| MTP (Android)     | —                      | `MtpClientTests` in hardening regressions   | ⚠ mocked only       | Mounter subprocess + parser mocked. Real-device tests need `jmtpfs` / `simple-mtpfs` on PATH and a connected phone. |

Supporting infrastructure containers (not backends themselves):
`socks-proxy`, `http-proxy` (used in Section 21d), `toxiproxy`
(Section 12), `test-runner` / `test-runner-iscsi` (the pytest host
itself).

**Test counts** (against a fully-up lab, privileged iSCSI runner,
NFS module loaded): ~231 tests in `test_protocols.py` plus 33 in
`test_network.py`. Without the privileged bits, NFS + iSCSI
sections skip.

Full per-section breakdown: [TEST_COVERAGE_MATRIX.md](TEST_COVERAGE_MATRIX.md).

### Windows integration tests

WinRM, WMI / DCOM and DFS-N need a real Windows host — there's no
Linux emulator that behaves like PowerShell-Remoting. The test
file `tests/test_windows_integration.py` skips every test until
the env vars are set:

```bash
export AXROSS_WIN_HOST="win-target.example"
export AXROSS_WIN_USER="axross"
export AXROSS_WIN_PASSWORD="…"
export AXROSS_WIN_DFSN_NAMESPACE="TestShare"   # optional, for DFS-N
.venv/bin/pytest tests/test_windows_integration.py
```

See [WINDOWS_TESTING.md](WINDOWS_TESTING.md) for the Azure CLI /
Hyper-V / VirtualBox setup recipe the target needs (WinRM-HTTPS
listener, DCOM, DFS-N namespace).

## Test coverage

Host-suite line coverage is ≈ 51 % over `core/` + `ui/`, with 48 of
72 modules at ≥ 85 %. The modules still below that line are
large-SDK protocol backends (each needs its own SDK-mock fixture
layer) and the Qt-UI giants (`main_window`, `file_pane`,
`connection_dialog`) that need dialog automation. The container
suite in `tests/docker/` covers the protocol backends end-to-end
when the lab is running.

## OpSec hardening tests

`tests/test_hardening_regressions.py::OpSecHardeningTests` guards
the [OPSEC.md](OPSEC.md) mitigations: SSH banner override,
uniform User-Agent, rsync metadata stripping, env allow-list,
SMB `socket.gethostname` patch behaviour, atomic temp prefix,
ADB pubkey scrub. A future refactor that accidentally reverts a
hardening default fails this suite loudly.

```bash
QT_QPA_PLATFORM=offscreen .venv/bin/pytest \
    tests/test_hardening_regressions.py::OpSecHardeningTests
```

## Packaging

PyInstaller bundle (slim or full flavour), AppImage, and the
headless MCP Docker image: [PACKAGING.md](PACKAGING.md).

## Building a release tarball

```bash
scripts/build_release.sh --tarball
```

Runs identity / secret / PEM scrub gates, copies the public-release
file set to `../axross-release/`, produces `axross-<version>.tar.gz`
+ `.sha256` + `.sha512`, and verifies the tarball round-trips
byte-for-byte against the source tree. See the script's `--help`
for safety guards and exit codes.

## Supply-chain audit

[SUPPLY_CHAIN_AUDIT.md](SUPPLY_CHAIN_AUDIT.md) — runtime + build-time
dependency review, current-as-of `f606698`. Verdict GREEN. Two
informational observations: `ruamel.yaml` over-include in slim (now
excluded), opentelemetry pulled by Azure in full (opt-in only).

## Contributing

[CONTRIBUTING.md](../CONTRIBUTING.md) covers PR scope, code style
(`ruff` is the only style gate), commit shape, and the licensing
note that applies to every contribution.

## Reporting security issues

Do not open a public issue for anything with exploit potential.
[SECURITY.md](../SECURITY.md) has the disclosure contact and
timeline.
