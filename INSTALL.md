# Installation

This is the single canonical install reference. The top-level READMEs
(EN/DE/ES) link here instead of duplicating these steps in each language.

## Prerequisites

- **Python** ≥ 3.10
- **Linux**: `apt install python3-venv` or the equivalent on your distro so
  `python3 -m venv` is available.
- **Linux GUI / containers**: PyQt6 ships Qt itself, but minimal images still
  need the system loader libraries used by Qt plugins. On Debian/Ubuntu slim
  images install:

  ```bash
  apt-get update
  apt-get install -y --no-install-recommends \
      libglib2.0-0 libgl1 libegl1 libfontconfig1 libxkbcommon0 libdbus-1-3
  ```

  Headless modes such as `axross --help`, `axross --script`, and
  `axross --mcp-server` do not need those GUI libraries.
- Optional system tools (only needed for protocols that call out via
  `subprocess`):
  - `rsync` binary — Rsync backend.
  - `mount.nfs`, `umount` (root/sudo) — NFS backend.
  - `iscsiadm`, `mount`, `blkid` (root/sudo + `open-iscsi`) — iSCSI backend.
  - `pkexec` + polkit rules — "Open as root…" action
    (`core.elevated_io`).

## PyPI install

Once a release is published:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install "axross[all]"
axross        # launches the GUI
```

Use `pip install axross` for the smallest base install and add
protocol extras as needed.

## Source install

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
pip install "axross[smb]"       # SMB / CIFS + DFS-N (smbprotocol)
pip install "axross[webdav]"    # WebDAV (requests + defusedxml — pure-Python)
pip install "axross[s3]"        # S3-compatible (boto3)
pip install "axross[azure]"     # Azure Blob + Azure Files (azure-storage-*)
pip install "axross[onedrive]"  # OneDrive + SharePoint (msal, requests)
pip install "axross[gdrive]"    # Google Drive (google-api-python-client)
pip install "axross[dropbox]"   # Dropbox (dropbox SDK)
pip install "axross[winrm]"     # WinRM / PowerShell-Remoting (pywinrm)
pip install "axross[wmi]"       # WMI / DCOM read-only (impacket)
pip install "axross[exchange]"  # Exchange Web Services (exchangelib)
pip install "axross[fuse]"      # FUSE mount any backend (fusepy, Linux/macOS)
```

From a source checkout, use the editable equivalent, for example
`pip install -e ".[smb]"`.

### Install light extras at once

```bash
pip install "axross[all]"
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
pip install build twine
python -m build
python -m twine check dist/*
# dist/axross-<version>.tar.gz
# dist/axross-<version>-py3-none-any.whl
```

Install on another machine:

```bash
pip install dist/axross-<version>-py3-none-any.whl
# Or with extras:
pip install "dist/axross-<version>-py3-none-any.whl[all]"
```

Smoke-test the built artifact without the source tree:

```bash
tmpdir="$(mktemp -d)"
python3 -m venv "$tmpdir/venv"
"$tmpdir/venv/bin/pip" install --no-deps dist/axross-<version>-py3-none-any.whl
"$tmpdir/venv/bin/python" -c 'import axross; print(axross.__version__)'
"$tmpdir/venv/bin/python" -m axross --help
"$tmpdir/venv/bin/axross" --help
```

## Publishing to PyPI

Build from a clean, tagged checkout and always validate on TestPyPI first:

```bash
rm -rf dist
python -m build
python -m twine check dist/*
python -m twine upload --repository testpypi dist/*
python -m twine upload dist/*
```

Authentication should use PyPI/TestPyPI API tokens, either from
`~/.pypirc` or environment variables consumed by `twine`.

## Versioning

The package version has one source of truth: `axross/_version.py`.
`pyproject.toml` reads it via `tool.setuptools.dynamic`, so do not
duplicate the version in project metadata.

Use PEP 440 versions:

```text
0.4.1        # patch release
0.5.0        # feature release
1.0.0        # stable major release
0.5.0rc1     # release candidate
0.4.1.post1  # post-release metadata/docs fix
```

Release bump checklist:

```bash
python - <<'PY'
from axross._version import __version__
print(__version__)
PY
rm -rf dist
python -m build
python -m twine check dist/*
```

Tag releases as `v<version>`, for example `v0.4.1`.

## Development setup

```bash
source .venv/bin/activate
pip install -e ".[all]"
pip install -r dev-requirements.txt
```

`dev-requirements.txt` covers pytest, coverage, ruff, build, twine, plus
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
