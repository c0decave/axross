"""NFSv4 and iSCSI behind a proxy: the kernel dials a loopback tunnel.

No kernel mount or initiator is involved: ``subprocess.run`` is replaced
by a recorder, so the tests pin down WHAT the kernel is told to connect
to and what happens when that goes wrong.
"""

from __future__ import annotations

import socket
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import connection_manager as cm  # noqa: E402
from core import iscsi_client, nfs_client, proxy  # noqa: E402

_PROXY = {"proxy_type": "socks5", "proxy_host": "proxy.example", "proxy_port": 1080}
_IQN = "iqn.2026-01.example:disk0"


def _done(stdout: str = "", returncode: int = 0) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess([], returncode, stdout, "")


def _port_open(port: int) -> bool:
    with socket.socket() as probe:
        probe.settimeout(0.5)
        return probe.connect_ex(("127.0.0.1", port)) == 0


class _Recorder:
    """Stand-in for ``subprocess.run`` that logs argv and answers by rule."""

    def __init__(self, session_portal: str | None = None) -> None:
        self.calls: list[list[str]] = []
        self.session_portal = session_portal
        self.node_portal = ""

    def __call__(self, cmd, *args, **kwargs):
        argv = [a for a in cmd if a != "sudo" and a != "-n"]
        self.calls.append(argv)
        if argv[:1] == ["iscsiadm"] and "-p" in argv and "node" in argv:
            self.node_portal = argv[argv.index("-p") + 1]
        if argv[:3] == ["iscsiadm", "-m", "session"]:
            portal = self.session_portal or self.node_portal
            return _done(
                f"Target: {_IQN} (non-flash)\n"
                f"\tCurrent Portal: {portal},1\n"
                f"\tPersistent Portal: {portal},1\n"
                "\t\tAttached scsi disk sdb\t\tState: running\n"
            )
        return _done()

    def with_prefix(self, *prefix: str) -> list[list[str]]:
        return [c for c in self.calls if c[: len(prefix)] == list(prefix)]


class NfsTunnelTest(unittest.TestCase):
    def _session(self, run: _Recorder, **kwargs):
        patches = [
            mock.patch.object(nfs_client.subprocess, "run", run),
            mock.patch.object(nfs_client.os, "geteuid", return_value=0),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        return nfs_client.NfsSession("10.9.9.9", "/export", mount_point="/mnt/x", **kwargs)

    def test_v4_mounts_the_loopback_tunnel_not_the_server(self) -> None:
        run = _Recorder()
        session = self._session(run, version=4, **_PROXY)
        self.addCleanup(session.disconnect)
        mount = run.with_prefix("mount")[0]
        source = mount[-2]
        opts = mount[mount.index("-o") + 1]
        port = session._tunnel.port
        self.assertEqual(source, "127.0.0.1:/export")
        self.assertIn(f"port={port}", opts)
        self.assertIn("vers=4", opts)
        self.assertNotIn("10.9.9.9", " ".join(mount))
        self.assertNotIn("mountport", opts)

    def test_tunnel_accepts_root_peers_for_the_kernel_socket(self) -> None:
        session = self._session(_Recorder(), version=4, **_PROXY)
        self.addCleanup(session.disconnect)
        self.assertTrue(session._tunnel._allow_root_peers)

    def test_v3_fails_closed_before_anything_runs(self) -> None:
        run = _Recorder()
        with mock.patch.object(nfs_client.subprocess, "run", run):
            with self.assertRaises(proxy.ProxyUnsupportedError) as ctx:
                nfs_client.NfsSession("h", "/export", version=3, **_PROXY)
        self.assertEqual(run.calls, [])
        self.assertIn("version to 4", str(ctx.exception))

    def test_disconnect_unmounts_and_closes_the_tunnel(self) -> None:
        run = _Recorder()
        session = self._session(run, version=4, **_PROXY)
        port = session._tunnel.port
        self.assertTrue(_port_open(port))
        session.disconnect()
        self.assertEqual(len(run.with_prefix("umount")), 1)
        self.assertFalse(_port_open(port))

    def test_failed_mount_closes_the_tunnel(self) -> None:
        def boom(cmd, *a, **k):
            raise subprocess.CalledProcessError(32, cmd, stderr="mount failed")

        seen: list[int] = []
        real_start = proxy.LocalTunnel.start

        def spy(self_):
            started = real_start(self_)
            seen.append(self_.port)
            return started

        with (
            mock.patch.object(nfs_client.subprocess, "run", boom),
            mock.patch.object(nfs_client.os, "geteuid", return_value=0),
            mock.patch.object(proxy.LocalTunnel, "start", spy),
        ):
            with self.assertRaises(OSError):
                nfs_client.NfsSession("h", "/export", version=4, mount_point="/mnt/x", **_PROXY)
        self.assertEqual(len(seen), 1)
        self.assertFalse(_port_open(seen[0]))

    def test_without_proxy_the_server_is_mounted_directly(self) -> None:
        run = _Recorder()
        session = self._session(run, version=4)
        self.assertIsNone(session._tunnel)
        self.assertEqual(run.with_prefix("mount")[0][-2], "10.9.9.9:/export")

    def test_without_proxy_v3_still_works(self) -> None:
        run = _Recorder()
        session = self._session(run, version=3)
        self.assertIn(
            "mountport=2049",
            run.with_prefix("mount")[0][run.with_prefix("mount")[0].index("-o") + 1],
        )
        self.assertIsNone(session._tunnel)


class IscsiTunnelTest(unittest.TestCase):
    def _session(self, run: _Recorder, **kwargs):
        patches = [
            mock.patch.object(iscsi_client.subprocess, "run", run),
            mock.patch.object(iscsi_client.shutil, "which", return_value="/sbin/iscsiadm"),
            mock.patch.object(iscsi_client.glob, "glob", return_value=[]),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        return iscsi_client.IscsiSession(
            "10.9.9.9", _IQN, mount_point="/mnt/y", auto_mount=False, **kwargs
        )

    def test_registers_the_tunnel_portal_and_skips_sendtargets(self) -> None:
        run = _Recorder()
        session = self._session(run, **_PROXY)
        self.addCleanup(session.disconnect)
        portal = f"127.0.0.1:{session._tunnel.port}"
        self.assertEqual(run.with_prefix("iscsiadm", "-m", "discovery"), [])
        created = [c for c in run.calls if "new" in c and "-o" in c]
        self.assertEqual(len(created), 1)
        self.assertEqual(created[0][created[0].index("-p") + 1], portal)
        logins = [c for c in run.calls if "--login" in c]
        self.assertEqual(logins[0][logins[0].index("-p") + 1], portal)
        self.assertNotIn("10.9.9.9", " ".join(" ".join(c) for c in run.calls))

    def test_redirect_to_another_portal_logs_out_and_raises(self) -> None:
        run = _Recorder(session_portal="10.1.1.1:3260")
        real_start = proxy.LocalTunnel.start
        ports: list[int] = []

        def spy(self_):
            started = real_start(self_)
            ports.append(self_.port)
            return started

        with mock.patch.object(proxy.LocalTunnel, "start", spy):
            with self.assertRaises(OSError) as ctx:
                self._session(run, **_PROXY)
        self.assertIn("bypass the proxy", str(ctx.exception))
        logouts = [c for c in run.calls if "--logout" in c]
        self.assertEqual(len(logouts), 1)
        self.assertEqual(logouts[0][logouts[0].index("-p") + 1], f"127.0.0.1:{ports[0]}")
        self.assertFalse(_port_open(ports[0]))

    def test_session_without_portal_info_is_not_trusted(self) -> None:
        run = _Recorder()
        original = run.__call__

        def blank(cmd, *a, **k):
            if "session" in cmd:
                run.calls.append(list(cmd))
                return _done("")
            return original(cmd, *a, **k)

        with self.assertRaises(OSError):
            self._session(blank_run := mock.Mock(side_effect=blank), **_PROXY)
        self.assertTrue(blank_run.called)

    def test_disconnect_logs_out_and_closes_the_tunnel(self) -> None:
        run = _Recorder()
        session = self._session(run, **_PROXY)
        port = session._tunnel.port
        session.disconnect()
        self.assertEqual(
            len(
                run.with_prefix(
                    "iscsiadm", "-m", "node", "-T", _IQN, "-p", f"127.0.0.1:{port}", "--logout"
                )
            ),
            1,
        )
        self.assertFalse(_port_open(port))

    def test_without_proxy_sendtargets_discovery_is_used(self) -> None:
        run = _Recorder()

        def discovering(cmd, *a, **k):
            if "discovery" in cmd:
                run.calls.append([c for c in cmd if c not in ("sudo", "-n")])
                return _done(f"10.9.9.9:3260,1 {_IQN}\n")
            return run(cmd, *a, **k)

        session = self._session(mock.Mock(side_effect=discovering))
        self.assertIsNone(session._tunnel)
        self.assertEqual(len(run.with_prefix("iscsiadm", "-m", "discovery")), 1)


class PeerCheckTest(unittest.TestCase):
    HEAD = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid\n"

    @staticmethod
    def row(local: str, remote: str, state: str, uid: int, sl: int = 0) -> str:
        return (
            f"   {sl}: {local} {remote} {state} 00000000:00000000 00:00000000 "
            f"00000000 {uid:>5} 0 1 1\n"
        )

    def _check(self, uid: int, rows: str, root_ok: bool, server=None) -> bool:
        data = self.HEAD + rows
        with (
            mock.patch.object(proxy.os, "getuid", return_value=uid),
            mock.patch.object(proxy.os.path, "exists", return_value=True),
            mock.patch("builtins.open", mock.mock_open(read_data=data)),
        ):
            return proxy._peer_is_same_user(("127.0.0.1", 0x1F90), root_ok, server)

    CLIENT = "0100007F:1F90"
    LISTENER = "0100007F:0050"

    def test_same_uid_is_accepted(self) -> None:
        self.assertTrue(self._check(1000, self.row(self.CLIENT, self.LISTENER, "01", 1000), False))

    def test_root_peer_is_refused_by_default(self) -> None:
        self.assertFalse(self._check(1000, self.row(self.CLIENT, self.LISTENER, "01", 0), False))

    def test_root_peer_is_accepted_when_the_kernel_is_the_client(self) -> None:
        self.assertTrue(self._check(1000, self.row(self.CLIENT, self.LISTENER, "01", 0), True))

    def test_other_user_is_refused_even_with_root_allowed(self) -> None:
        self.assertFalse(self._check(1000, self.row(self.CLIENT, self.LISTENER, "01", 1234), True))

    def test_time_wait_leftover_with_the_same_source_port_is_ignored(self) -> None:
        # A closed earlier connection (TIME_WAIT is reported as uid 0) that
        # used the same source port must not shadow the live client.
        rows = self.row(self.CLIENT, "0100007F:2000", "06", 0, 0) + self.row(
            self.CLIENT, self.LISTENER, "01", 1000, 1
        )
        self.assertTrue(self._check(1000, rows, False))

    def test_the_row_for_this_listener_wins_over_another_connection(self) -> None:
        rows = self.row(self.CLIENT, "0100007F:2000", "01", 4242, 0) + self.row(
            self.CLIENT, self.LISTENER, "01", 1000, 1
        )
        self.assertTrue(self._check(1000, rows, False, server=("127.0.0.1", 0x50)))
        self.assertFalse(self._check(1000, rows, False, server=("127.0.0.1", 0x2000)))

    def test_unknown_peer_is_refused(self) -> None:
        self.assertFalse(self._check(1000, "", False))


class ClassificationTest(unittest.TestCase):
    def test_nfs_and_iscsi_are_proxiable_now(self) -> None:
        self.assertIsNone(cm.proxy_unavailable_reason("nfs"))
        self.assertIsNone(cm.proxy_unavailable_reason("iscsi"))

    def test_rsh_and_wmi_stay_refused(self) -> None:
        self.assertTrue(cm.proxy_unavailable_reason("rsh"))
        self.assertTrue(cm.proxy_unavailable_reason("wmi"))


if __name__ == "__main__":
    unittest.main()
