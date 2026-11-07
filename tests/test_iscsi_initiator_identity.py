"""iSCSI: what the initiator sends about itself is the profile's choice.

A profile (Connect to Server, a saved profile, axross.open_url) may set
the initiator name (IQN) and the network interface the connection leaves
through. Both go into an open-iscsi interface record of the session's own
(``iscsiadm -m iface``), every discovery / node command names it with
``-I``, and disconnect removes it - the system's initiatorname.iscsi and
other sessions are never touched. Without either field nothing changes.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import iscsi_client as IC  # noqa: E402
from core.profiles import ConnectionProfile  # noqa: E402

TARGET = "iqn.2026-10.example:disk1"


class Recorder:
    def __init__(self, fail_on: str = ""):
        self.calls: list[list[str]] = []
        self.fail_on = fail_on

    def __call__(self, cmd, **kw):
        self.calls.append(list(cmd))
        if self.fail_on and self.fail_on in cmd:
            if kw.get("check", True):
                raise subprocess.CalledProcessError(1, cmd, "", "iscsiadm: failed")
            return subprocess.CompletedProcess(cmd, 1, "", "iscsiadm: failed")
        out = f"192.0.2.10:3260,1 {TARGET}\n" if "discovery" in cmd else ""
        return subprocess.CompletedProcess(cmd, 0, out, "")


@pytest.fixture
def session(monkeypatch, tmp_path):
    rec = Recorder()
    monkeypatch.setattr(IC.IscsiSession, "_run_privileged", lambda self, cmd, **kw: rec(cmd, **kw))
    monkeypatch.setattr(IC.IscsiSession, "_wait_for_device", lambda self: None)
    monkeypatch.setattr(IC.IscsiSession, "_write_chap_secrets_to_node_file", lambda self: True)

    def make(**kw):
        return IC.IscsiSession("192.0.2.10", TARGET, mount_point=str(tmp_path), auto_mount=False, **kw), rec
    return make


def _iface_of(calls):
    named = {c[c.index("-I") + 1] for c in calls if "-I" in c}
    assert len(named) == 1, named
    return named.pop()


def test_happy_the_profile_s_initiator_name_and_interface_are_sent(session):
    sess, rec = session(initiator_name="iqn.2026-11.org.example:pentest-box", initiator_interface="eth1")
    iface = _iface_of(rec.calls)
    assert iface.startswith("axross-")
    # the record comes first, with the name and the interface
    assert rec.calls[0] == ["iscsiadm", "-m", "iface", "-I", iface, "-o", "new"]
    updates = {(c[c.index("-n") + 1], c[c.index("-v") + 1]) for c in rec.calls if "iface" in c and "update" in c}
    assert updates == {("iface.transport_name", "tcp"),
                       ("iface.initiatorname", "iqn.2026-11.org.example:pentest-box"),
                       ("iface.net_ifacename", "eth1")}
    # discovery and login go through it
    for verb in ("discovery", "--login"):
        cmd = next(c for c in rec.calls if verb in c)
        assert cmd[cmd.index("-I") + 1] == iface
    rec.calls.clear()
    sess.disconnect()
    assert ["--logout" in c and "-I" in c for c in rec.calls].count(True) == 1
    assert rec.calls[-2][-4:] == ["-I", iface, "-o", "delete"] and "node" in rec.calls[-2]
    assert rec.calls[-1] == ["iscsiadm", "-m", "iface", "-I", iface, "-o", "delete"]


def test_happy_chap_and_the_node_file_use_the_session_s_record(session, monkeypatch):
    sess, rec = session(username="u", password="p", initiator_name="anything.the-target.accepts:x")
    iface = _iface_of(rec.calls)
    chap = next(c for c in rec.calls if "node.session.auth.authmethod" in c)
    assert chap[chap.index("-I") + 1] == iface
    # the CHAP secrets go into the node record of that interface, not "default"
    patterns = []
    monkeypatch.setattr(IC.glob, "glob", lambda pattern: patterns.append(pattern) or ["/x"])
    assert sess._node_config_paths() == ["/x"]
    assert patterns == [f"/etc/iscsi/nodes/{TARGET}/192.0.2.10,3260,*/{iface}"]


def test_happy_without_sender_fields_nothing_changes(session):
    sess, rec = session()
    assert not any("-I" in c for c in rec.calls)
    assert not any("iface" in c for c in rec.calls)
    sess.disconnect()
    assert not any("iface" in c for c in rec.calls)


def test_sad_a_failed_record_update_removes_the_record_again(monkeypatch, tmp_path):
    rec = Recorder(fail_on="iface.initiatorname")
    monkeypatch.setattr(IC.IscsiSession, "_run_privileged", lambda self, cmd, **kw: rec(cmd, **kw))
    with pytest.raises(subprocess.CalledProcessError):
        IC.IscsiSession("192.0.2.10", TARGET, mount_point=str(tmp_path), auto_mount=False,
                        initiator_name="iqn.2026-11.org.example:x")
    iface = _iface_of(rec.calls)
    assert rec.calls[-1] == ["iscsiadm", "-m", "iface", "-I", iface, "-o", "delete"]
    assert not any("discovery" in c or "--login" in c for c in rec.calls)


@pytest.mark.parametrize("name", [
    "iqn.2026-11.org.example:client1", "eui.02004567A425678D", "naa.52004567BA64678D",
    "IQN.free-form_Name:with.any!printable~chars", "x" * 223,
])
def test_happy_initiator_names_are_free(name):
    assert IC.validate_initiator_name(f"  {name} ") == name


@pytest.mark.parametrize("name", [
    "iqn.2026-11.org.example:a b",          # a space ends the value in the record
    "iqn.x#comment",                         # '#' comments the rest out
    "iqn.x\nnode.startup = automatic",       # a second key in the record
    "iqn.é",                            # not ASCII
    "x" * 224,                               # RFC 3720: at most 223 bytes
])
def test_sad_initiator_names_that_would_break_the_record_are_refused(name):
    with pytest.raises(ValueError):
        IC.validate_initiator_name(name)


@pytest.mark.parametrize("name,ok", [
    ("eth0", True), ("enp3s0f1.100", True), ("wlan0", True), ("", True),
    ("a" * 16, False), ("..", False), ("eth0/1", False), ("eth 0", False), ("eth#0", False),
])
def test_interface_names(name, ok):
    if ok:
        assert IC.validate_interface(name) == name
    else:
        with pytest.raises(ValueError):
            IC.validate_interface(name)


def test_happy_targets_discover_sends_the_given_name_and_cleans_up(monkeypatch):
    calls = []

    def run(cmd, **kw):
        calls.append(list(cmd))
        out = f"192.0.2.10:3260,1 {TARGET}\n" if "discovery" in cmd else ""
        return subprocess.CompletedProcess(cmd, 0, out, "")
    monkeypatch.setattr(IC.shutil, "which", lambda b: "/usr/sbin/iscsiadm")
    monkeypatch.setattr(IC.subprocess, "run", run)
    found = IC.IscsiSession.targets_discover("192.0.2.10", initiator_name="iqn.2026-11.org.example:scan")
    assert found == [{"portal": "192.0.2.10:3260", "iqn": TARGET}]
    iface = _iface_of(calls)
    assert ["/usr/sbin/iscsiadm", "-m", "iface", "-I", iface, "-o", "update", "-n",
            "iface.initiatorname", "-v", "iqn.2026-11.org.example:scan"] in calls
    disc = next(c for c in calls if "discovery" in c)
    assert disc[disc.index("-I") + 1] == iface
    assert calls[-1] == ["/usr/sbin/iscsiadm", "-m", "iface", "-I", iface, "-o", "delete"]


def test_happy_the_profile_keeps_the_sender_fields():
    p = ConnectionProfile(name="t", protocol="iscsi", host="192.0.2.10", iscsi_target_iqn=TARGET,
                          iscsi_initiator_name="iqn.2026-11.org.example:c", iscsi_initiator_interface="eth1")
    back = ConnectionProfile.from_dict(p.to_dict())
    assert (back.iscsi_initiator_name, back.iscsi_initiator_interface) == ("iqn.2026-11.org.example:c", "eth1")
    plain = ConnectionProfile(name="t", protocol="iscsi", host="h", iscsi_target_iqn=TARGET).to_dict()
    assert "iscsi_initiator_name" not in plain and "iscsi_initiator_interface" not in plain


def test_happy_connection_manager_hands_the_fields_to_the_backend(monkeypatch):
    from core import connection_manager as CM

    seen = {}

    class Fake:
        connected = True

        def __init__(self, **kw):
            seen.update(kw)
    monkeypatch.setattr(CM, "load_backend_class", lambda proto: Fake)
    p = ConnectionProfile(name="t", protocol="iscsi", host="192.0.2.10", iscsi_target_iqn=TARGET,
                          iscsi_initiator_name="iqn.2026-11.org.example:c", iscsi_initiator_interface="eth1")
    CM.ConnectionManager().connect(p)
    assert seen["initiator_name"] == "iqn.2026-11.org.example:c"
    assert seen["initiator_interface"] == "eth1"


def test_happy_scripting_open_url_takes_the_sender_fields(monkeypatch):
    """axross.open_url("iscsi://...", iscsi_initiator_name=..., ...)."""
    from core import connection_manager as CM
    from core import scripting

    seen = {}

    class Fake:
        connected = True
        name = "fake"

        def __init__(self, **kw):
            seen.update(kw)
    monkeypatch.setattr(CM, "load_backend_class", lambda proto: Fake)
    scripting.open_url("iscsi://192.0.2.10/", iscsi_target_iqn=TARGET, proxy_type="none",
                       iscsi_initiator_name="iqn.2026-11.org.example:script",
                       iscsi_initiator_interface="eth2")
    assert seen["initiator_name"] == "iqn.2026-11.org.example:script"
    assert seen["initiator_interface"] == "eth2"
