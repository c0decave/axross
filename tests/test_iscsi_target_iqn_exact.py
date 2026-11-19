"""iSCSI: the profile's target is matched by its whole IQN, never as a
part of another one.

Protocol review (round 1): ``iscsiadm -m session -P 3`` and the
discovery output were searched with ``iqn in line``. With the profile on
``...:disk1`` and another session on ``...:disk10`` (or ``disk1-old``),
the device of disk10 was picked and mounted - writes to the wrong LUN;
discovery "found" disk1 when only disk10 was there, and the tunnel check
read disk10's portals.
"""

from __future__ import annotations

import subprocess

import pytest

from core.iscsi_client import IscsiSession

SESSIONS = """\
iSCSI Transport Class version 2.0-870
Target: iqn.2026-01.lab:disk10 (non-flash)
\tCurrent Portal: 10.0.0.9:3260,1
\tPersistent Portal: 10.0.0.9:3260,1
\t\tAttached scsi disk {other}\t\tState: running
Target: iqn.2026-01.lab:disk1 (non-flash)
\tCurrent Portal: 127.0.0.1:3260,1
\tPersistent Portal: 127.0.0.1:3260,1
\t\tAttached scsi disk {ours}\t\tState: running
"""


def _session(stdout: str, iqn: str = "iqn.2026-01.lab:disk1") -> IscsiSession:
    s = IscsiSession.__new__(IscsiSession)
    s.__dict__.update(_iface="", _iface_created=False, _tunnel=None, _proxied=False,
                      _portal_ip="10.0.0.5", _portal_port=3260, _target_iqn=iqn,
                      _logged_in=True, _own_login=True)
    s._run_privileged = lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, stdout, "")
    s._logout = lambda: None
    return s


def test_sad_device_of_another_target_with_a_longer_iqn_is_not_ours(monkeypatch):
    # Our block comes second: a substring match took disk10's device first.
    out = SESSIONS.format(other="null", ours="zero")
    assert _session(out)._query_device_via_iscsiadm() == "/dev/zero"


def test_sad_discovery_finds_only_the_whole_iqn():
    s = _session("10.0.0.5:3260,1 iqn.2026-01.lab:disk10\n")
    with pytest.raises(OSError, match="not found"):
        s._discover()


def test_happy_discovery_finds_the_iqn():
    _session("10.0.0.5:3260,1 iqn.2026-01.lab:disk1\n")._discover()


def test_edge_tunnel_check_reads_only_our_targets_portals():
    out = SESSIONS.format(other="null", ours="zero")
    _session(out)._assert_session_via_tunnel("127.0.0.1:3260")  # disk10's 10.0.0.9 not counted
