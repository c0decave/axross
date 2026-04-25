"""Validate tests/docker/axross-lab-profiles.json end-to-end.

For every profile in the JSON:
1. Parse via ``ConnectionProfile.from_dict`` (no crash, all required
   protocol fields present).
2. Route through ``ConnectionManager._create_session`` — the backend
   is actually instantiated and ``connect()`` is driven where needed.
3. A minimal per-backend smoke op (list_dir, bucket exists, etc.)
   confirms the endpoint is reachable.
4. Clean disconnect.

Run inside ``test-runner-iscsi`` (host networking → the 10.99.0.x
IPs are routable):

    docker compose run --rm test-runner-iscsi \\
        python /app/tests/docker/verify_lab_profiles.py

Exits 0 on full success. Any failing profile is reported with
traceback; exit code == failure count.

Profiles that are environmentally skipped:
* iSCSI (needs kernel modules + privileged mode + careful session
  state — exercised separately in tests/test_protocols.py TestIscsi)
* OAuth backends (onedrive / gdrive / dropbox) have no lab instance.
"""
from __future__ import annotations

import json
import os
import sys
import traceback
from pathlib import Path

# Allow running as a plain script inside the test-runner container.
_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent.parent))


from core import backend_registry  # noqa: E402
from core.connection_manager import ConnectionManager  # noqa: E402
from core.profiles import ConnectionProfile  # noqa: E402


# Protocols we don't smoke-test here. iSCSI is exercised by the
# kernel-privileged suite; OAuth backends have no offline-friendly
# endpoint.
SKIP_PROTOCOLS = frozenset({"iscsi", "onedrive", "sharepoint", "gdrive", "dropbox"})


def _smoke(session, protocol: str) -> None:
    """One tiny operation per backend: proves we went past the handshake."""
    if protocol in ("sftp", "scp"):
        home = session.home()
        session.list_dir(home)
    elif protocol in ("ftp", "ftps"):
        home = session.home()
        session.list_dir(home)
    elif protocol == "smb":
        session.list_dir("/")
    elif protocol == "webdav":
        session.list_dir("/")
    elif protocol == "s3":
        # bucket probe already happened in __init__; list root confirms.
        session.list_dir("/")
    elif protocol == "rsync":
        session.list_dir("/")
    elif protocol == "nfs":
        # NFS mount happens on connect; list the export.
        session.list_dir("/")
    elif protocol == "imap":
        # IMAP root = list of folders (INBOX at least).
        session.list_dir("/")
    elif protocol == "telnet":
        session.list_dir(session.home())
    elif protocol == "azure_blob":
        session.list_dir("/")
    else:
        raise RuntimeError(f"no smoke op defined for {protocol!r}")


def main() -> int:
    # Populate the backend registry. In the GUI this runs at app
    # start; doing it inside main() (not at module import) keeps the
    # side effect local to the script's execution so accidental
    # pytest collection doesn't leak registry state.
    backend_registry.init_registry()

    # Host-key auto-trust is appropriate for an ephemeral docker lab
    # but would be a gaping security hole on a real machine. Require
    # an explicit opt-in so nobody runs this script pointed at the
    # public internet by accident.
    if os.environ.get("AXROSS_LAB_TRUST_HOSTS") != "1":
        print(
            "Refusing to run: set AXROSS_LAB_TRUST_HOSTS=1 to confirm "
            "this verifier may auto-accept any SSH host key it sees.\n"
            "This is intended for the docker lab only.",
            file=sys.stderr,
        )
        return 2

    path = _HERE / "axross-lab-profiles.json"
    with path.open(encoding="utf-8") as fh:
        data = json.load(fh)

    passed: list[str] = []
    failed: list[tuple[str, str]] = []
    skipped: list[str] = []

    cm = ConnectionManager()
    for name, blob in data.items():
        password = blob.pop("_password", "") or ""
        # Allow the lab JSON to carry connection strings that the GUI
        # import refuses (because they'd trip the keyring gate). The
        # verifier promotes them back onto the profile after parse.
        inline_azure_cs = blob.pop("_azure_connection_string", "") or ""
        # _comment is a free-text note in the JSON; drop it so
        # from_dict doesn't choke on an unexpected field.
        blob.pop("_comment", None)
        try:
            profile = ConnectionProfile.from_dict(blob)
        except Exception as exc:
            failed.append((name, f"from_dict failed: {exc}"))
            continue
        if inline_azure_cs:
            profile.azure_connection_string = inline_azure_cs

        if profile.protocol in SKIP_PROTOCOLS:
            skipped.append(f"{name} ({profile.protocol})")
            continue

        try:
            # Lab-only: auto-accept unknown host keys.
            session = cm.connect(
                profile, password=password,
                on_unknown_host=lambda _exc: True,
            )
            try:
                _smoke(session, profile.protocol)
            finally:
                cm.release(profile)
            passed.append(name)
        except Exception as exc:
            failed.append((name, f"{type(exc).__name__}: {exc}"))

    print(f"\n=== Lab profile verification ===")
    print(f"Passed:  {len(passed)}")
    for n in passed:
        print(f"  [OK]   {n}")
    print(f"Skipped: {len(skipped)}")
    for n in skipped:
        print(f"  [--]   {n}")
    print(f"Failed:  {len(failed)}")
    for n, err in failed:
        print(f"  [FAIL] {n}: {err}")
    return len(failed)


if __name__ == "__main__":
    raise SystemExit(main())
