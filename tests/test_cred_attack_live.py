"""Live Docker-lab tests for ``core.cred_attack.bruteforce``.

These tests intentionally hit real protocol services from
``tests/docker/docker-compose.yml``. They are skipped by default so the
normal unit suite stays self-contained:

    cd tests/docker
    docker compose up -d --build ssh-alpha ftp-server ftps-server \
        smb-server webdav-server s3-server rsync-server imap-server \
        telnet-server cisco-fake test-runner
    docker compose run --rm --no-deps \
        -e AXROSS_LIVE_CRED_ATTACK_TESTS=1 \
        test-runner pytest -p no:cacheprovider tests/test_cred_attack_live.py -q
"""

from __future__ import annotations

import os
import socket
from collections.abc import Callable
from dataclasses import dataclass

import pytest

from core.cred_attack import AttemptResult, bruteforce
from core.profiles import ConnectionProfile

pytestmark = pytest.mark.skipif(
    os.environ.get("AXROSS_LIVE_CRED_ATTACK_TESTS") != "1",
    reason="set AXROSS_LIVE_CRED_ATTACK_TESTS=1 and run inside tests/docker lab",
)


def _auto_trust(_err: object) -> bool:
    return True


def _port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


@dataclass(frozen=True)
class BruteCase:
    name: str
    profile: ConnectionProfile
    password: str
    probe_port: int
    on_unknown_host: Callable[[object], bool] | None = None


CASES = [
    BruteCase(
        "sftp",
        ConnectionProfile(
            name="cred-live-sftp",
            protocol="sftp",
            host="10.99.0.10",
            port=22,
            username="alpha",
            auth_type="password",
        ),
        "alpha123",
        22,
        _auto_trust,
    ),
    BruteCase(
        "scp",
        ConnectionProfile(
            name="cred-live-scp",
            protocol="scp",
            host="10.99.0.10",
            port=22,
            username="alpha",
            auth_type="password",
        ),
        "alpha123",
        22,
        _auto_trust,
    ),
    BruteCase(
        "ftp",
        ConnectionProfile(
            name="cred-live-ftp",
            protocol="ftp",
            host="10.99.0.30",
            port=21,
            username="ftpuser",
            auth_type="password",
            ftp_passive=True,
        ),
        "ftp123",
        21,
    ),
    BruteCase(
        "ftps",
        ConnectionProfile(
            name="cred-live-ftps",
            protocol="ftps",
            host="10.99.0.38",
            port=21,
            username="ftpsuser",
            auth_type="password",
            ftp_passive=True,
            ftps_verify_tls=False,
        ),
        "ftps123",
        21,
    ),
    BruteCase(
        "smb",
        ConnectionProfile(
            name="cred-live-smb",
            protocol="smb",
            host="10.99.0.31",
            port=445,
            username="smbuser",
            auth_type="password",
            smb_share="testshare",
        ),
        "smb123",
        445,
    ),
    BruteCase(
        "webdav",
        ConnectionProfile(
            name="cred-live-webdav",
            protocol="webdav",
            host="10.99.0.32",
            port=80,
            username="davuser",
            auth_type="password",
            webdav_url="http://10.99.0.32:80",
        ),
        "dav123",
        80,
    ),
    BruteCase(
        "s3",
        ConnectionProfile(
            name="cred-live-s3",
            protocol="s3",
            host="10.99.0.33",
            port=9000,
            username="minioadmin",
            auth_type="password",
            s3_bucket="testbucket",
            s3_endpoint="http://10.99.0.33:9000",
            s3_region="us-east-1",
        ),
        "minioadmin123",
        9000,
    ),
    BruteCase(
        "rsync",
        ConnectionProfile(
            name="cred-live-rsync",
            protocol="rsync",
            host="10.99.0.34",
            port=873,
            username="rsyncuser",
            auth_type="password",
            rsync_module="testmod",
            rsync_ssh=False,
        ),
        "rsync123",
        873,
    ),
    BruteCase(
        "imap",
        ConnectionProfile(
            name="cred-live-imap",
            protocol="imap",
            host="10.99.0.36",
            port=143,
            username="imapuser",
            auth_type="password",
            imap_ssl=False,
        ),
        "imap123",
        143,
    ),
    BruteCase(
        "pop3",
        ConnectionProfile(
            name="cred-live-pop3",
            protocol="pop3",
            host="10.99.0.36",
            port=110,
            username="imapuser",
            auth_type="password",
            pop3_ssl=False,
        ),
        "imap123",
        110,
    ),
    BruteCase(
        "telnet",
        ConnectionProfile(
            name="cred-live-telnet",
            protocol="telnet",
            host="10.99.0.37",
            port=23,
            username="telnetuser",
            auth_type="password",
        ),
        "telnet123",
        23,
    ),
    BruteCase(
        "cisco-telnet",
        ConnectionProfile(
            name="cred-live-cisco",
            protocol="cisco-telnet",
            host="10.99.0.43",
            port=23,
            username="admin",
            auth_type="password",
        ),
        "cisco123",
        23,
    ),
]


@pytest.mark.parametrize("case", CASES, ids=lambda c: c.name)
def test_bruteforce_finds_valid_credential_against_docker_lab(case: BruteCase):
    if not _port_open(case.profile.host, case.probe_port):
        pytest.skip(f"{case.name} lab service is not reachable")

    report = bruteforce(
        case.profile,
        users=[case.profile.username],
        passwords=[f"wrong-{case.name}-password", case.password],
        rate_per_min=60000,
        timeout_per_attempt=20.0,
        abort_on_lockout=False,
        abort_after_n_lockouts=10,
        on_unknown_host=case.on_unknown_host,
        authorized=True,
    )

    assert report.successes, report.summary()
    assert len(report.successes) == 1, [cred for cred in report.successes]
    assert report.successes[0].username == case.profile.username
    assert report.successes[0].password == case.password
    assert any(a.result is AttemptResult.FAILED for a in report.attempts), [
        a.to_dict() for a in report.attempts
    ]
    assert report.lockouts == 0, [a.to_dict() for a in report.attempts]
