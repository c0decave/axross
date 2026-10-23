"""Find your own files on many SMB hosts at once (operator, remote-todo.txt).

Operator: *„das hier ist die range, das ist mein login, bitte suche
mir alle meine files dort raus bzw. analysiere dort meine files"*, decided:
*„lass uns impacket nehmen"*, targets *„hostliste, ips und eingegrenzter
bereich z.b. cidr"*, *„nur lesend, parallel default 4, aber settings
einstellbar"*.

Three parts:

* ``core.net_helpers.parse_targets`` - host names, IPv4/IPv6 addresses,
  CIDR blocks and IPv4 ranges into one bounded, de-duplicated host list.
* ``core.smb_shares`` - the share list of a host through impacket
  (NetShareEnum over SRVSVC); ``SmbSession.shares_list`` no longer runs the
  ``smbclient`` binary.
* ``core.remote_sweep`` - one credential against many hosts, read only: a
  canary logon first, then N hosts in parallel; the first logon failure stops
  the whole run (a typo must not lock a domain account on 50 hosts).

Unit tests use a fake connection; the live tests run against the podman lab
Samba (10.99.0.31, plus a second instance at 10.99.0.131 when started) and
skip without it.
"""

from __future__ import annotations

import os
import socket
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

LAB_SMB = "10.99.0.31"
LAB_SMB2 = "10.99.0.131"
LAB_USER, LAB_PASS = "smbuser", "smb" + "123"


def _port_open(host: str, port: int = 445, timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


lab = pytest.mark.skipif(not _port_open(LAB_SMB), reason="the lab's Samba (10.99.0.31) is not reachable")
lab2 = pytest.mark.skipif(
    not (_port_open(LAB_SMB) and _port_open(LAB_SMB2)),
    reason="the second lab Samba (10.99.0.131) is not running",
)


# --- targets ----------------------------------------------------------------


class TestParseTargets:
    def test_happy_mixed_list_in_order(self):
        from core.net_helpers import parse_targets

        out = parse_targets("fileserver, 10.0.0.1\n10.0.0.8/30 nas.corp.example\n2001:db8::5")
        assert out == ["fileserver", "10.0.0.1", "10.0.0.9", "10.0.0.10", "nas.corp.example", "2001:db8::5"]

    def test_happy_ipv4_ranges_long_and_short(self):
        from core.net_helpers import parse_targets

        assert parse_targets("10.0.0.5-10.0.0.7") == ["10.0.0.5", "10.0.0.6", "10.0.0.7"]
        assert parse_targets("10.0.0.5-7") == ["10.0.0.5", "10.0.0.6", "10.0.0.7"]

    def test_happy_ipv6_cidr(self):
        from core.net_helpers import parse_targets

        assert parse_targets("2001:db8::/126") == ["2001:db8::1", "2001:db8::2", "2001:db8::3"]

    @pytest.mark.parametrize(
        "bad",
        ["", "   ", "host\x00name", "fs1\x1b[31m", "-oProxyCommand", "a..b", "999.1.1.1", "10.0.0.0/33",
         "10.0.0.9-10.0.0.5", "10.0.0.5-300", "10.0.0.5-2001:db8::1", "under_score!", "x" * 254,
         "*.corp.example", "smb://host", "\\\\host\\share"],
    )
    def test_sad_garbage_is_refused_with_the_entry_named(self, bad):
        from core.net_helpers import TargetError, parse_targets

        with pytest.raises(TargetError):
            parse_targets(bad if bad.strip() else bad)

    def test_sad_too_many_hosts_is_refused_before_expanding(self):
        from core.net_helpers import TargetError, parse_targets

        with pytest.raises(TargetError, match="65534"):
            parse_targets("10.0.0.0/16", max_hosts=1024)
        t0 = time.monotonic()
        with pytest.raises(TargetError):
            parse_targets("2001:db8::/32", max_hosts=1024)  # 2**96 addresses: never expanded
        assert time.monotonic() - t0 < 0.5

    def test_sad_the_sum_of_entries_counts_against_the_cap(self):
        from core.net_helpers import TargetError, parse_targets

        with pytest.raises(TargetError, match="1036"):
            parse_targets("10.0.0.0/22 10.1.0.0/28", max_hosts=1024)

    def test_sad_single_names_count_against_the_cap_too(self):
        from core.net_helpers import TargetError, parse_targets

        with pytest.raises(TargetError, match="limit of 2"):
            parse_targets("fs1 fs2 fs3", max_hosts=2)
        with pytest.raises(TargetError):
            parse_targets("fs1 10.0.0.1 10.0.0.2", max_hosts=2)
        assert parse_targets("fs1 fs1 fs1 fs2", max_hosts=2) == ["fs1", "fs2"]  # duplicates are free

    def test_edge_slash_32_31_and_duplicates(self):
        from core.net_helpers import parse_targets

        assert parse_targets("10.0.0.7/32") == ["10.0.0.7"]
        assert parse_targets("10.0.0.6/31") == ["10.0.0.6", "10.0.0.7"]
        assert parse_targets("10.0.0.1 10.0.0.1, 10.0.0.0/30 FILESERVER fileserver") == [
            "10.0.0.1", "10.0.0.2", "fileserver"]

    def test_edge_exactly_the_cap_is_allowed(self):
        from core.net_helpers import parse_targets

        assert len(parse_targets("10.0.0.0/22", max_hosts=1022)) == 1022

    def test_edge_comments_and_blank_lines_in_a_host_file(self):
        from core.net_helpers import parse_targets

        text = "# office\nfs1\n\n  fs2   # second floor\n;10.0.0.1\n"
        assert parse_targets(text) == ["fs1", "fs2", "10.0.0.1"]


# --- share list through impacket ----------------------------------------------


class _FakeShare(dict):
    pass


def _share(name, stype, remark=""):
    return {"shi1_netname": name + "\x00", "shi1_type": stype, "shi1_remark": remark + "\x00"}


class _FakeConn:
    """Stands in for impacket.smbconnection.SMBConnection."""

    instances: list = []
    shares: list = []
    login_error: Exception | None = None

    def __init__(self, remote_name, remote_host, sess_port=445, timeout=60, **kw):
        self.remote_host = remote_host
        self.port = sess_port
        self.timeout = timeout
        self.logged_in = None
        self.closed = False
        _FakeConn.instances.append(self)

    def login(self, user, password, domain="", lmhash="", nthash=""):
        if _FakeConn.login_error is not None:
            raise _FakeConn.login_error
        self.logged_in = (user, password, domain)

    def listShares(self):
        return list(_FakeConn.shares)

    def close(self):
        self.closed = True


@pytest.fixture
def fake_impacket(monkeypatch):
    from core import smb_shares

    _FakeConn.instances = []
    _FakeConn.login_error = None
    _FakeConn.shares = [
        _share("public", 0, "Public share"),
        _share("home", 0, "User home"),
        _share("hp-laser", 1, "Office printer"),
        _share("IPC$", 3 | 0x80000000, "IPC Service"),
        _share("C$", 0 | 0x80000000, "Default share"),
    ]
    monkeypatch.setattr(smb_shares, "_connection_class", lambda: _FakeConn)
    return _FakeConn


class TestSharesThroughImpacket:
    def test_happy_types_comments_and_special_flag(self, fake_impacket):
        from core.smb_shares import list_shares

        out = {s["name"]: s for s in list_shares("fs1", username="alice", password="pw", domain="CORP")}
        assert out["public"] == {"name": "public", "type": "Disk", "comment": "Public share", "special": False}
        assert out["hp-laser"]["type"] == "Printer"
        assert out["IPC$"]["type"] == "IPC" and out["IPC$"]["special"] is True
        assert out["C$"]["type"] == "Disk" and out["C$"]["special"] is True
        conn = fake_impacket.instances[-1]
        assert conn.logged_in == ("alice", "pw", "CORP")
        assert conn.closed

    def test_happy_shares_list_keeps_its_contract_without_a_binary(self, fake_impacket, monkeypatch):
        import shutil
        import subprocess

        from core.smb_client import SmbSession

        def boom(*a, **kw):
            raise AssertionError("no external binary may run")

        monkeypatch.setattr(subprocess, "run", boom)
        monkeypatch.setattr(shutil, "which", boom)
        out = SmbSession.shares_list("fs1", username="alice", password="pw")
        assert {s["name"] for s in out} == {"public", "home", "hp-laser", "IPC$", "C$"}
        assert set(out[0]) >= {"name", "type", "comment"}

    def test_sad_logon_failure_becomes_permission_error_without_the_password(self, fake_impacket):
        from core.smb_shares import list_shares

        fake_impacket.login_error = _session_error("STATUS_LOGON_FAILURE")
        with pytest.raises(PermissionError) as info:
            list_shares("fs1", username="alice", password="s3cr3t-pw")
        assert "STATUS_LOGON_FAILURE" in str(info.value)
        assert "s3cr3t-pw" not in str(info.value)
        assert fake_impacket.instances[-1].closed

    def test_sad_unreachable_host_is_an_os_error(self, monkeypatch):
        from core import smb_shares

        class Refused(_FakeConn):
            def __init__(self, *a, **kw):
                raise OSError(111, "Connection refused")

        monkeypatch.setattr(smb_shares, "_connection_class", lambda: Refused)
        with pytest.raises(OSError, match="refused"):
            smb_shares.list_shares("fs1")

    @pytest.mark.parametrize("bad", ["host\nfoo", "10.0.0.5\rA", "", "a b", "-x"])
    def test_sad_bad_host_names_are_refused_before_connecting(self, fake_impacket, bad):
        from core.smb_shares import list_shares

        with pytest.raises(ValueError):
            list_shares(bad)
        assert fake_impacket.instances == []

    def test_edge_anonymous_uses_an_empty_login(self, fake_impacket):
        from core.smb_shares import list_shares

        list_shares("fs1")
        assert fake_impacket.instances[-1].logged_in == ("", "", "")

    def test_edge_custom_port_and_timeout_reach_the_connection(self, fake_impacket):
        from core.smb_shares import list_shares

        list_shares("fs1", port=4455, timeout=3.0)
        conn = fake_impacket.instances[-1]
        assert (conn.port, conn.timeout) == (4455, 3.0)


def _session_error(status_name: str):
    from impacket import nt_errors
    from impacket.smbconnection import SessionError

    return SessionError(getattr(nt_errors, status_name))


# --- the sweep ----------------------------------------------------------------


class _Host:
    def __init__(self, files=None, *, reachable=True, login_error=None, shares=None, delay=0.0,
                 list_error=None):
        self.files = files or {}
        self.reachable = reachable
        self.login_error = login_error
        self.shares = shares if shares is not None else ["data"]
        self.delay = delay
        self.list_error = list_error
        self.logins = 0
        self.writes = 0


class _FakeSmb:
    """A read-only SMB view of one fake host, the shape remote_sweep wants."""

    def __init__(self, host: _Host):
        self.host = host

    def login(self, username, password, domain):
        self.host.logins += 1
        time.sleep(self.host.delay)
        if self.host.login_error:
            raise self.host.login_error

    def disk_shares(self, include_special=False):
        return list(self.host.shares)

    def list_dir(self, share, path):
        if self.host.list_error:
            raise self.host.list_error
        prefix = path.rstrip("/") + "/" if path != "/" else "/"
        seen = {}
        for full, size in self.host.files.get(share, {}).items():
            if not full.startswith(prefix):
                continue
            rest = full[len(prefix):]
            name = rest.split("/", 1)[0]
            seen[name] = ("/" in rest, size)
        return [(n, d, s, 1_700_000_000.0) for n, (d, s) in sorted(seen.items())]

    def owner_sid(self, share, path):
        return "S-1-5-21-1-2-3-1104" if "mine" in path else "S-1-5-21-1-2-3-500"

    def user_sid(self):
        return "S-1-5-21-1-2-3-1104"

    def close(self):
        pass


def _hosts():
    return {
        "fs1": _Host({"data": {"/docs/report-mine.docx": 10, "/docs/other.docx": 20, "/wallet.dat": 5}}),
        "fs2": _Host({"data": {"/mine/photo.jpg": 30}}),
        "fs3": _Host(reachable=False),
    }


def _run(hosts, **cfg):
    from core import remote_sweep as RS

    hits, statuses = [], []
    lock = threading.Lock()

    def on_hit(hit):
        with lock:
            hits.append(hit)

    def on_status(host, state, detail=""):
        with lock:
            statuses.append((host, state, detail))

    cancel = cfg.pop("cancel", None)
    config = RS.SweepConfig(
        targets=cfg.pop("targets", " ".join(hosts)),
        username="alice", password=cfg.pop("password", "pw"), domain="CORP", **cfg)
    result = RS.sweep(
        config, on_hit=on_hit, on_status=on_status,
        connect=lambda h, port, timeout: _FakeSmb(hosts[h]),
        reachable=lambda h, port, timeout: hosts[h].reachable,
        cancel=cancel,
    )
    return result, sorted(hits, key=lambda h: h.unc), statuses


class TestSweep:
    def test_happy_finds_files_on_every_reachable_host(self):
        result, hits, statuses = _run(_hosts())
        assert [h.unc for h in hits] == [
            r"\\fs1\data\docs\other.docx", r"\\fs1\data\docs\report-mine.docx",
            r"\\fs1\data\wallet.dat", r"\\fs2\data\mine\photo.jpg"]
        assert result.hosts_searched == 2 and result.hosts_unreachable == 1
        assert ("fs3", "unreachable", "") in statuses
        assert not result.aborted

    def test_happy_name_filter_and_owner_only(self):
        _, hits, _ = _run(_hosts(), name="*.docx")
        assert [h.unc.rsplit("\\", 1)[1] for h in hits] == ["other.docx", "report-mine.docx"]
        _, hits, _ = _run(_hosts(), owner_only=True)
        assert [h.unc for h in hits] == [r"\\fs1\data\docs\report-mine.docx", r"\\fs2\data\mine\photo.jpg"]

    def test_happy_parallel_default_is_four_and_a_setting(self, monkeypatch, tmp_path):
        from core import open_limits as OL
        from core import remote_sweep as RS

        store: dict = {}
        monkeypatch.setattr(OL, "read_setting", lambda key, default=None: store.get(key, default))
        monkeypatch.setattr(OL, "write_setting", lambda key, value: store.__setitem__(key, value))
        assert RS.parallel_hosts() == 4
        RS.set_parallel_hosts(8)
        assert RS.parallel_hosts() == 8
        for bad in (0, -1, 65, True, 2.5, "4"):
            with pytest.raises(ValueError):
                RS.set_parallel_hosts(bad)
        store["remote_sweep_parallel"] = "garbage"
        assert RS.parallel_hosts() == 4
        store["remote_sweep_parallel"] = 8
        assert RS.SweepConfig(targets="fs1", username="", password="").parallel == 8

    def test_happy_parallel_runs_at_most_n_hosts_at_once(self):
        hosts = {f"h{i}": _Host({"data": {"/f": 1}}, delay=0.05) for i in range(12)}
        active, peak = [0], [0]
        lock = threading.Lock()
        real_login = _FakeSmb.login

        def counting_login(self, *a):
            with lock:
                active[0] += 1
                peak[0] = max(peak[0], active[0])
            try:
                real_login(self, *a)
            finally:
                with lock:
                    active[0] -= 1

        _FakeSmb.login = counting_login
        try:
            result, hits, _ = _run(hosts, parallel=3)
        finally:
            _FakeSmb.login = real_login
        assert len(hits) == 12 and result.hosts_searched == 12
        assert peak[0] <= 3

    def test_sad_wrong_password_on_the_canary_stops_before_any_other_host(self):
        hosts = _hosts()
        for h in hosts.values():
            h.login_error = _session_error("STATUS_LOGON_FAILURE")
        result, hits, statuses = _run(hosts)
        assert result.aborted and "STATUS_LOGON_FAILURE" in result.abort_reason
        assert hits == []
        assert sum(h.logins for h in hosts.values()) == 1  # the canary only

    def test_sad_a_canary_that_never_got_to_the_logon_does_not_count(self):
        """A first host that answers on 445 but fails before the credential is
        judged (a reset, a dialect it refuses) is no canary: the next host
        must be, alone - else a mistyped password reaches `parallel` hosts at
        once."""
        # The logon takes a moment, as on a real network: hosts started
        # together all reach it before the first refusal comes back.
        hosts = {f"h{i}": _Host({"data": {"/f": 1}}, delay=0.2) for i in range(6)}
        hosts["h0"].login_error = ConnectionResetError("connection reset by peer")
        for name in ("h1", "h2", "h3", "h4", "h5"):
            hosts[name].login_error = _session_error("STATUS_LOGON_FAILURE")
        result, hits, _ = _run(hosts, parallel=4)
        assert result.aborted and "STATUS_LOGON_FAILURE" in result.abort_reason
        assert sum(hosts[n].logins for n in ("h1", "h2", "h3", "h4", "h5")) == 1
        assert result.hosts_failed == 1 and hits == []

    def test_happy_after_a_failed_first_host_the_next_canary_unlocks_the_rest(self):
        hosts = {f"h{i}": _Host({"data": {"/f": 1}}) for i in range(5)}
        hosts["h0"].login_error = ConnectionResetError("connection reset by peer")
        result, hits, _ = _run(hosts, parallel=4)
        assert not result.aborted
        assert result.hosts_failed == 1 and result.hosts_searched == 4 and len(hits) == 4

    @pytest.mark.parametrize("status", ["STATUS_ACCOUNT_LOCKED_OUT", "STATUS_PASSWORD_EXPIRED",
                                        "STATUS_ACCOUNT_DISABLED", "STATUS_LOGON_FAILURE"])
    def test_sad_a_logon_failure_after_the_canary_stops_the_rest(self, status):
        hosts = {f"h{i}": _Host({"data": {"/f": 1}}) for i in range(10)}
        hosts["h3"].login_error = _session_error(status)
        result, _, _ = _run(hosts, parallel=1)
        assert result.aborted and status in result.abort_reason
        assert sum(h.logins for h in hosts.values()) == 4  # h0 (canary), h1, h2, h3 - then stop

    def test_sad_access_denied_on_one_share_is_reported_and_the_run_goes_on(self):
        hosts = _hosts()
        hosts["fs1"].list_error = PermissionError("STATUS_ACCESS_DENIED")
        result, hits, statuses = _run(hosts)
        assert not result.aborted
        assert [h.unc for h in hits] == [r"\\fs2\data\mine\photo.jpg"]
        assert any(s[0] == "fs1" and "ACCESS_DENIED" in s[2] for s in statuses)

    def test_sad_bad_targets_raise_before_any_connection(self):
        from core.net_helpers import TargetError

        with pytest.raises(TargetError):
            _run({}, targets="10.0.0.0/8")

    def test_sad_no_write_method_exists_on_the_read_only_session(self):
        from core import remote_sweep as RS

        for name in ("putFile", "deleteFile", "createDirectory", "deleteDirectory", "rename",
                     "writeFile", "open_write", "remove"):
            assert not hasattr(RS.ReadOnlySmb, name), name

    def test_edge_cancel_stops_quickly(self):
        hosts = {f"h{i}": _Host({"data": {"/f": 1}}, delay=0.2) for i in range(40)}
        cancel = threading.Event()
        threading.Timer(0.3, cancel.set).start()
        t0 = time.monotonic()
        result, _, _ = _run(hosts, parallel=2, cancel=cancel)
        assert result.cancelled
        assert time.monotonic() - t0 < 2.0
        assert sum(h.logins for h in hosts.values()) < 40

    def test_edge_no_reachable_host_ends_cleanly(self):
        hosts = {"a": _Host(reachable=False), "b": _Host(reachable=False)}
        result, hits, _ = _run(hosts)
        assert hits == [] and result.hosts_unreachable == 2 and not result.aborted

    def test_edge_max_files_per_host_and_depth(self):
        files = {f"/d{i}/f{j}": 1 for i in range(5) for j in range(50)}
        files["/a/b/c/d/e/deep.txt"] = 1
        hosts = {"fs": _Host({"data": files})}
        result, hits, _ = _run(hosts, max_files_per_host=60, max_depth=3)
        assert len(hits) == 60 and result.truncated
        assert not any("deep.txt" in h.unc for h in hits)

    def test_edge_a_host_with_endless_folders_stops_at_the_entry_cap(self):
        """A hostile (or just huge) share: every folder holds more folders,
        nothing matches the name. The walk must end at a per-host entry cap,
        not run until the user cancels."""
        from core import remote_sweep as RS

        class Endless(_FakeSmb):
            listed = 0

            def list_dir(self, share, path):
                Endless.listed += 1
                return [(f"d{i}", True, 0, 0.0) for i in range(50)]

        config = RS.SweepConfig(targets="fs", username="alice", password="pw", name="*.none",
                                max_entries_per_host=1000)
        statuses = []
        result = RS.sweep(config, on_hit=lambda h: None,
                          on_status=lambda host, state, detail="": statuses.append((state, detail)),
                          connect=lambda h, port, timeout: Endless(_Host()),
                          reachable=lambda h, port, timeout: True)
        assert result.truncated and Endless.listed <= 1000 // 50 + 1
        assert any("1000 entries" in detail for _state, detail in statuses)

    def test_sad_a_bad_entry_cap_is_refused(self):
        from core import remote_sweep as RS

        for bad in (0, -1, True, 1.5):
            with pytest.raises(ValueError):
                RS.SweepConfig(targets="fs", username="", password="", max_entries_per_host=bad)

    def test_edge_reparse_point_folders_are_not_descended(self):
        """Windows junctions and folder symlinks (FILE_ATTRIBUTE_REPARSE_POINT)
        are skipped like symlinked folders in Find Files: no loops, no
        duplicates. A reparse-point file is still a file."""
        from core import remote_sweep as RS

        class Entry:
            def __init__(self, name, attrs):
                self.name, self.attrs = name, attrs

            def get_longname(self):
                return self.name

            def is_directory(self):
                return self.attrs & 0x10

            def get_filesize(self):
                return 7

            def get_mtime_epoch(self):
                return 1.0

            def get_attributes(self):
                return self.attrs

        class Conn:
            def listPath(self, share, pattern):
                return [Entry(".", 0x10), Entry("..", 0x10), Entry("real", 0x10),
                        Entry("Application Data", 0x10 | 0x400), Entry("link.txt", 0x20 | 0x400),
                        Entry("plain.txt", 0x20)]

        smb = RS.ReadOnlySmb("fs", 445, 1.0)
        smb._conn = Conn()
        assert sorted(smb.list_dir("data", "/")) == [
            ("link.txt", False, 7, 1.0), ("plain.txt", False, 7, 1.0), ("real", True, 7, 1.0)]

    def test_edge_the_password_never_reaches_status_or_abort_text(self):
        hosts = _hosts()
        hosts["fs2"].list_error = OSError("boom")
        _, _, statuses = _run(hosts, password="S3cret-Value")
        assert statuses and not any("S3cret-Value" in s[2] for s in statuses)
        hosts = _hosts()
        hosts["fs1"].login_error = _session_error("STATUS_LOGON_FAILURE")
        result, _, statuses = _run(hosts, password="S3cret-Value")
        assert "S3cret-Value" not in result.abort_reason
        assert not any("S3cret-Value" in s[2] for s in statuses)


# --- live: the podman lab Samba ----------------------------------------------


@lab
def test_live_shares_of_the_lab_samba_without_smbclient(monkeypatch):
    import shutil

    from core.smb_client import SmbSession

    monkeypatch.setattr(shutil, "which", lambda name: None)  # no binary on the path
    shares = {s["name"]: s for s in SmbSession.shares_list(LAB_SMB, username=LAB_USER, password=LAB_PASS)}
    assert shares["testshare"]["type"] == "Disk"
    assert shares["IPC$"]["type"] == "IPC"


@lab
def test_live_wrong_password_is_a_permission_error():
    from core.smb_shares import list_shares

    with pytest.raises(PermissionError, match="LOGON_FAILURE"):
        list_shares(LAB_SMB, username=LAB_USER, password="definitely-wrong")


@lab
def test_live_sweep_finds_lab_files_read_only():
    from core import remote_sweep as RS

    hits = []
    config = RS.SweepConfig(targets=f"{LAB_SMB} 10.99.0.250", username=LAB_USER, password=LAB_PASS,
                            name="*.txt", reachable_timeout=0.5)
    result = RS.sweep(config, on_hit=hits.append, on_status=lambda *a: None)
    uncs = sorted(h.unc for h in hits)
    assert rf"\\{LAB_SMB}\testshare\readme.txt" in uncs
    assert rf"\\{LAB_SMB}\testshare\subdir\nested.txt" in uncs
    assert result.hosts_unreachable == 1 and not result.aborted


@lab
def test_live_sweep_wrong_password_aborts_after_one_logon():
    from core import remote_sweep as RS

    config = RS.SweepConfig(targets=LAB_SMB, username=LAB_USER, password="wrong")
    result = RS.sweep(config, on_hit=lambda h: None, on_status=lambda *a: None)
    assert result.aborted and "LOGON_FAILURE" in result.abort_reason


@lab2
def test_live_two_hosts_in_parallel():
    from core import remote_sweep as RS

    hits = []
    config = RS.SweepConfig(targets=f"{LAB_SMB},{LAB_SMB2}", username=LAB_USER, password=LAB_PASS,
                            name="readme.txt", parallel=2)
    result = RS.sweep(config, on_hit=hits.append, on_status=lambda *a: None)
    assert {h.host for h in hits} == {LAB_SMB, LAB_SMB2}
    assert result.hosts_searched == 2


@lab2
def test_live_wrong_password_never_reaches_the_second_host():
    """Lockout safety against two real Samba hosts: the canary refuses the
    password, the second host is skipped - it never sees a logon."""
    from core import remote_sweep as RS

    statuses = []
    config = RS.SweepConfig(targets=f"{LAB_SMB} {LAB_SMB2}", username=LAB_USER,
                            password="definitely-wrong", parallel=2)
    result = RS.sweep(config, on_hit=lambda h: None,
                      on_status=lambda host, state, detail="": statuses.append((host, state)))
    assert result.aborted and "LOGON_FAILURE" in result.abort_reason
    assert (LAB_SMB2, "skipped") in statuses
    assert not any(host == LAB_SMB2 and state != "skipped" for host, state in statuses)


@lab
def test_live_owner_only_finds_the_users_files():
    """Everything in the lab share belongs to smbuser (Dockerfile.smb
    chown -R), so "only my files" keeps them all - via the owner SID of
    each file and the account's SID from LSARPC."""
    from core import remote_sweep as RS

    hits = []
    config = RS.SweepConfig(targets=LAB_SMB, username=LAB_USER, password=LAB_PASS,
                            name="*.txt", owner_only=True)
    result = RS.sweep(config, on_hit=hits.append, on_status=lambda *a: None)
    assert not result.aborted
    names = sorted(h.path for h in hits if h.share == "testshare")
    assert names == ["/readme.txt", "/subdir/nested.txt"]
    sids = {h.owner_sid for h in hits}
    assert len(sids) == 1 and next(iter(sids)).startswith("S-1-5-21-")


@lab
def test_live_owner_sid_of_a_file_and_user_sid_agree():
    from core.remote_sweep import ReadOnlySmb

    smb = ReadOnlySmb(LAB_SMB, 445, 10.0)
    smb.login(LAB_USER, LAB_PASS, "")
    try:
        assert smb.owner_sid("testshare", "/readme.txt") == smb.user_sid()
        assert "testshare" in smb.disk_shares() and "IPC$" not in smb.disk_shares(include_special=True)
    finally:
        smb.close()


# --- paranoid mode ----------------------------------------------------------


class TestParanoid:
    def test_sad_paranoid_mode_blocks_a_sweep_before_any_connection(self):
        from core import security_mode as SM

        old = SM.current_policy().name
        SM.set_policy("paranoid")
        try:
            hosts = _hosts()
            with pytest.raises(PermissionError, match="paranoid"):
                _run(hosts)
            assert sum(h.logins for h in hosts.values()) == 0
        finally:
            SM.set_policy(old)

    def test_happy_normal_mode_allows_it(self):
        from core import security_mode as SM

        assert SM.NORMAL.allow_network_sweep and not SM.PARANOID.allow_network_sweep


def test_sad_without_impacket_the_error_says_what_to_install(monkeypatch):
    """slim and a pip install without the extra have no impacket (it is a
    heavy, opt-in dependency, never in "all")."""
    import builtins

    from core import smb_shares

    real_import = builtins.__import__

    def no_impacket(name, *args, **kwargs):
        if name.startswith("impacket"):
            raise ImportError("No module named 'impacket'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_impacket)
    with pytest.raises(OSError) as info:
        smb_shares.list_shares("fs1")
    text = str(info.value)
    assert "pip install axross[wmi]" in text and "axross-full" in text


def test_edge_duplicates_do_not_count_against_the_host_limit():
    """Verification round: a block given twice was refused although it adds
    no host - each entry was sized against the room left before dedup."""
    from core.net_helpers import TargetError, parse_targets

    assert len(parse_targets("10.0.0.0/24, 10.0.0.0/24", max_hosts=256)) == 254
    assert len(parse_targets("10.0.0.5-20\n10.0.0.10-15", max_hosts=16)) == 16
    with pytest.raises(TargetError):
        parse_targets("10.0.0.0/24, 10.0.1.0/24", max_hosts=256)  # 512 distinct hosts
    with pytest.raises(TargetError):
        parse_targets("10.0.0.0/16", max_hosts=256)  # counted, never expanded
