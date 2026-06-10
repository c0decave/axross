# Windows Integration Testing

The WinRM, WMI/DCOM, and DFS-N backends have full unit-test coverage
of their path parsing and mocked-transport logic (see
`tests/test_hardening_regressions.py`), but nothing in CI exercises
them against a real Windows target. There is no practical Linux
emulator for PowerShell Remoting / WMI-DCOM / MS-DFS-N, so
end-to-end verification requires a real Windows host.

This document is the recipe a developer (or a CI job with a
Windows-capable runner) follows to stand up a throwaway Windows test
target and run `tests/test_windows_integration.py` against it.

## Target options

Any of these work; pick by cost / speed / persistence trade-off.

### 1. Cloud Windows Server (fastest for CI)

Spin up a Windows Server 2019+ VM (Azure / AWS / GCP image
catalogues ship them with WinRM already enabled). Total cost
~€0.02/h; stop the VM when not testing.

Azure example:

```bash
az vm create \
    --resource-group axross-test --name axx-winrm \
    --image Win2019Datacenter --size Standard_B2s \
    --admin-username axross --admin-password 'SomeStrongPass!1' \
    --public-ip-sku Standard --nsg-rule RDP
# Open the WinRM and SMB ports separately:
az vm open-port --resource-group axross-test --name axx-winrm --port 5985
az vm open-port --resource-group axross-test --name axx-winrm --port 5986
az vm open-port --resource-group axross-test --name axx-winrm --port 445
```

### 2. Hyper-V / VirtualBox (fastest for local dev)

Download the Windows Server 2022 Evaluation ISO (180-day licence)
and install it in Hyper-V / VirtualBox with bridged or
host-only networking. Run `winrm quickconfig -force` once at the
admin PowerShell prompt.

### 3. Windows Server container (bleeding edge)

Microsoft's `mcr.microsoft.com/windows/server:ltsc2022` image runs
on a Windows Docker host — use if you already have one. WinRM
must be configured inside the container; not recommended unless
you're already in that ecosystem.

## One-time setup on the target

```powershell
# Run as Administrator on the Windows target.

# Enable WinRM HTTPS on 5986 (prefer over 5985 / plaintext):
$cert = New-SelfSignedCertificate -DnsName "axx-winrm.local" -CertStoreLocation Cert:\LocalMachine\My
winrm create winrm/config/Listener?Address=*+Transport=HTTPS `
    "@{Hostname=`"axx-winrm.local`"; CertificateThumbprint=`"$($cert.Thumbprint)`"}"
netsh advfirewall firewall add rule name="WinRM HTTPS" dir=in action=allow protocol=TCP localport=5986

# Enable DCOM for the WMI backend:
winrm set winrm/config/service '@{AllowUnencrypted="false"}'
Enable-PSRemoting -Force

# For DFS-N tests: install the DFS-Namespaces role and create a
# stand-alone namespace at \\axx-winrm\TestShare.
Install-WindowsFeature -Name FS-DFS-Namespace -IncludeManagementTools
New-SmbShare -Name TestShare -Path "C:\TestShare" -FullAccess Everyone
New-DfsnRoot -TargetPath "\\axx-winrm\TestShare" -Type Standalone -Path "\\axx-winrm\TestShare"
New-DfsnFolder -Path "\\axx-winrm\TestShare\inner" -TargetPath "\\axx-winrm\actual-inner"
```

## Running the tests

Set the target details in the environment and run the integration
suite:

```bash
export AXROSS_WIN_HOST="axx-winrm.example.com"
export AXROSS_WIN_USER="axross"
export AXROSS_WIN_PASSWORD set via your local .env (literal redacted from public docs)
export AXROSS_WIN_WINRM_SCHEME="https"        # or "http" for 5985
export AXROSS_WIN_WINRM_PORT="5986"
export AXROSS_WIN_WINRM_CA="/path/to/self-signed.pem"  # optional
export AXROSS_WIN_SMB_SHARE="TestShare"
export AXROSS_WIN_DFSN_NAMESPACE="\\axx-winrm\TestShare"

.venv/bin/python -m pytest tests/test_windows_integration.py -v
```

Tests that require a specific env var are skipped when the var is
missing, so a developer without a Windows target can still run the
file without failures — they just see lots of "skipped" entries.

## What each test covers

| Test | Backend | Requires |
|---|---|---|
| `test_winrm_whoami` | WinRM | WIN_HOST + WIN_USER + WIN_PASSWORD |
| `test_winrm_listing_roundtrip` | WinRM | same, plus a writable C:\Temp |
| `test_winrm_small_file_roundtrip` | WinRM | same |
| `test_wmi_enumerates_dir` | WMI/DCOM | same, plus DCOM reachable |
| `test_dfsn_referral_resolution` | DFS-N | WIN_DFSN_NAMESPACE |
| `test_dfsn_file_listing` | DFS-N | same |

## Debugging

* `winrm get winrm/config` on the target surfaces the active
  listener configuration.
* If the Python client sees a TLS hostname mismatch, regenerate the
  cert with the DNS name the client actually connects to (the
  `-DnsName` argument above).
* Kerberos auth is not currently tested — the WinRM backend uses
  NTLM over the HTTPS listener, which covers most hardened
  deployments without needing a domain-joined test runner.

## Future work

* Add the WinRM cert + a private-network setup to the existing
  `tests/docker/docker-compose.yml` via a
  `mcr.microsoft.com/windows/servercore` worker. This only helps
  teams already running Docker on a Windows-capable host.
* DFS-N stand-alone (non-domain) namespaces suffice for the
  referral-resolution smoke tests; DFS-R replication tests would
  need a full AD forest and are out of scope.
