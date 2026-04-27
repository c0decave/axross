# Installation

This is the single canonical install reference. The top-level READMEs
(EN/DE/ES) link here instead of duplicating these steps in each language.

## Prerequisites

- **Python** ≥ 3.10
- **Qt 6** libraries — ship with the PyQt6 wheel on all supported platforms.
- **Linux**: `apt install python3-venv` or the equivalent on your distro so
  `python3 -m venv` is available.
- Optional system tools (only needed for protocols that call out via
  `subprocess`):
  - `rsync` binary — Rsync backend.
  - `mount.nfs`, `umount` (root/sudo) — NFS backend.
  - `iscsiadm`, `mount`, `blkid` (root/sudo + `open-iscsi`) — iSCSI backend.
  - `pkexec` + polkit rules — "Open as root…" action
    (`core.elevated_io`).

## Base install

```bash
git clone <repo-url>
cd axross
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
axross        # launches the GUI
```

Base install pulls only what the always-available protocols need:

| Package         | Version  | Purpose                                        |
|-----------------|----------|------------------------------------------------|
| PyQt6           | ≥ 6.6    | GUI framework                                  |
| paramiko        | ≥ 3.4    | SSH / SFTP / SCP                               |
| PySocks         | ≥ 1.7    | SOCKS4 / SOCKS5 proxy                          |
| keyring         | ≥ 25.0   | OS secret store for passwords                  |

FTP, Telnet, IMAP use only the Python standard library — no extra deps.

## Optional protocol extras

Install just the ones you need. Unavailable backends appear greyed out
in the Connection Manager with an inline `pip install` hint.

```bash
pip install -e ".[smb]"       # SMB / CIFS + DFS-N (smbprotocol)
pip install -e ".[webdav]"    # WebDAV (requests + defusedxml — pure-Python)
pip install -e ".[s3]"        # S3-compatible (boto3)
pip install -e ".[azure]"     # Azure Blob + Azure Files (azure-storage-*)
pip install -e ".[onedrive]"  # OneDrive + SharePoint (msal, requests)
pip install -e ".[gdrive]"    # Google Drive (google-api-python-client)
pip install -e ".[dropbox]"   # Dropbox (dropbox SDK)
pip install -e ".[winrm]"     # WinRM / PowerShell-Remoting (pywinrm)
pip install -e ".[wmi]"       # WMI / DCOM read-only (impacket)
pip install -e ".[exchange]"  # Exchange Web Services (exchangelib)
pip install -e ".[fuse]"      # FUSE mount any backend (fusepy, Linux/macOS)
```

### Install everything at once

```bash
pip install -e ".[all]"
```

`[all]` covers SMB, WebDAV, S3, Azure, OneDrive/SharePoint, GDrive,
Dropbox. It deliberately **excludes** `winrm`, `wmi`, `exchange`, and
`fuse` because each of those pulls a heavy dep (impacket brings in
~50 MB of crypto code; exchangelib pulls lxml; fusepy needs matching
kernel FUSE support). Add them explicitly when you need them.

### One-shot sanity check

```bash
.venv/bin/python -c 'import main; print("axross ok")'
```

## Cloud services (OAuth)

OneDrive, SharePoint, Google Drive, and Dropbox require OAuth app
registration before first use. Client IDs are not shipped with the
repo — every user needs their own.

See [OAUTH_SETUP.md](OAUTH_SETUP.md) for each provider's step-by-step
recipe.

## Building a wheel

```bash
pip install build
python -m build
# dist/axross-<version>-py3-none-any.whl
```

Install on another machine:

```bash
pip install dist/axross-<version>-py3-none-any.whl
# Or with extras:
pip install "dist/axross-<version>-py3-none-any.whl[all]"
```

## Development setup

```bash
source .venv/bin/activate
pip install -e ".[all]"
pip install -r dev-requirements.txt
```

`dev-requirements.txt` covers pytest, coverage, ruff, build, plus
`cryptography` and `jsonschema` that some MCP tests exercise directly.

Run the host test suite (no Docker required):

```bash
QT_QPA_PLATFORM=offscreen .venv/bin/pytest -q \
    tests/test_hardening_regressions.py tests/test_regressions.py \
    tests/test_new_features.py tests/test_backend_regressions.py \
    tests/test_pane_layout_regressions.py tests/test_e2e.py
```

Expected: ~925 pass, 5 skip (three FUSE tests gated on `fusepy`,
one GDrive-refresh test gated on `google-auth`, one end-to-end test
that needs the docker lab).

For the Docker protocol lab see the **Development / Testing** section
in [README.md](README.md) — the protocol coverage matrix there spells
out exactly which backends are cleanly tested and which aren't.

## Uninstall

```bash
pip uninstall axross
rm -rf .venv
rm -rf ~/.config/axross ~/.local/state/axross  # settings + logs
# Keyring entries — the "Forget Password" option in the Connection
# Manager removes individual entries; wholesale cleanup depends on
# your OS keyring front-end (Seahorse, kwallet-query, security).
```
