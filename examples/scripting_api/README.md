# Axross scripting API examples

These examples are executable Python modules. The unit suite imports
them, runs the local-safe examples, and verifies that every public
`axross.*` scripting API has at least one example mapping.

Run the local examples from a checkout:

```bash
python -m pytest tests/test_scripting_examples.py -q
```

Run the Docker-backed examples after starting the lab:

```bash
cd tests/docker
docker compose up -d --build ssh-alpha ftp-server webdav-server imap-server \
  tftp-server ldap-server snmpd-fake
docker compose run --rm --no-deps \
  -e AXROSS_LIVE_SCRIPTING_EXAMPLE_TESTS=1 \
  test-runner pytest -p no:cacheprovider tests/test_scripting_examples.py -q
```

## Modules

| Module | Focus |
|---|---|
| `local_file_workflows.py` | LocalFS/RamFS file operations, safety previews, search, inspection, trail, dashboard |
| `script_store.py` | Profiles, bookmarks, saved scripts, runtime docs/help, UI prompt pattern |
| `network_diagnostics.py` | TCP/HTTP/DNS/address helpers against a local test HTTP server |
| `credential_testing.py` | Authorized credential-test dry-runs and oracle enumeration without network traffic |
| `protocol_recipes.py` | SQLite query/tables plus protocol-specific recipes that need real services |
| `docker_protocol_smoke.py` | Docker lab examples for FTP, WebDAV, IMAP, TFTP, LDAP, SNMP, SSH host-key, HTTP probes |

The Docker module is opt-in because it talks to real network services.
It skips individual services that are not reachable so a partial lab
can still test the examples it has started.

SNMP is best-effort in the Docker lab: some net-snmp builds fail to
bind the UDP fixture port in containers. In that case the SNMP example
reports a skipped result while the other protocol examples still run.
