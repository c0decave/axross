from __future__ import annotations

import io
import os
import signal
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from PyQt6.QtCore import QCoreApplication, QMimeData, QModelIndex, Qt
from PyQt6.QtWidgets import QApplication, QMessageBox

from core.connection_manager import ConnectionManager
from core.local_fs import LocalFS
from core.profiles import ConnectionProfile, ProfileManager
from core.proxy import ProxyConfig, create_direct_socket, create_proxy_socket
from core.transfer_manager import TransferManager
from core.transfer_worker import TransferJob, TransferStatus, TransferWorker
from models.file_item import FileItem
from models.file_table_model import FileTableModel
from ui.connection_dialog import ConnectionDialog
from ui.file_pane import FilePaneWidget
from ui.terminal_widget import LocalTerminalSession
from ui.text_editor import TextEditorDialog

APP = QApplication.instance() or QApplication([])


class ProxyRegressionTests(unittest.TestCase):
    def test_http_connect_preserves_tunnel_bytes(self) -> None:
        # This test uses 127.0.0.1 as the proxy host — blocked by the
        # SSRF guard in create_proxy_socket. We deliberately opt in for
        # the duration of the test.
        import os as _os

        _prev = _os.environ.get("AXROSS_ALLOW_PRIVATE_PROXY")
        _os.environ["AXROSS_ALLOW_PRIVATE_PROXY"] = "1"
        try:
            self._run_http_connect_check()
        finally:
            if _prev is None:
                _os.environ.pop("AXROSS_ALLOW_PRIVATE_PROXY", None)
            else:
                _os.environ["AXROSS_ALLOW_PRIVATE_PROXY"] = _prev

    def _run_http_connect_check(self) -> None:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        proxy_port = server.getsockname()[1]

        def serve() -> None:
            conn, _ = server.accept()
            try:
                _ = conn.recv(4096)
                conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\nSSH-2.0-test\r\n")
                time.sleep(0.1)
            finally:
                conn.close()
                server.close()

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()

        sock = create_proxy_socket(
            ProxyConfig(proxy_type="http", host="127.0.0.1", port=proxy_port),
            "example.com",
            22,
        )
        try:
            sock.settimeout(1.0)
            self.assertEqual(sock.recv(64), b"SSH-2.0-test\r\n")
        finally:
            sock.close()
        thread.join(timeout=1.0)

    def test_rejects_control_characters_in_target_host(self) -> None:
        with self.assertRaises(ConnectionError):
            create_direct_socket("bad\r\nhost", 22)


class TransferRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QCoreApplication.instance() or QCoreApplication([])

    def test_all_finished_emits_once_after_queue_drains(self) -> None:
        manager = TransferManager()
        fs = LocalFS()
        events: list[str] = []
        manager.all_finished.connect(lambda: events.append("all_finished"))

        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                src1 = os.path.join(tmpdir, "a.bin")
                src2 = os.path.join(tmpdir, "b.bin")
                out_dir = os.path.join(tmpdir, "out")
                os.mkdir(out_dir)

                Path(src1).write_bytes(b"a" * 128 * 1024)
                Path(src2).write_bytes(b"b" * 128 * 1024)

                manager.transfer_files(fs, fs, [src1, src2], out_dir)

                deadline = time.monotonic() + 5.0
                while time.monotonic() < deadline and len(events) < 1:
                    self.app.processEvents()
                    time.sleep(0.01)

                deadline = time.monotonic() + 1.0
                while time.monotonic() < deadline:
                    self.app.processEvents()
                    time.sleep(0.01)

                self.assertEqual(events, ["all_finished"])
                self.assertTrue(os.path.exists(os.path.join(out_dir, "a.bin")))
                self.assertTrue(os.path.exists(os.path.join(out_dir, "b.bin")))
        finally:
            manager.shutdown()

    def test_resume_continues_from_existing_partial_file(self) -> None:
        fs = LocalFS()
        worker = TransferWorker()
        with tempfile.TemporaryDirectory() as tmpdir:
            src = os.path.join(tmpdir, "src.bin")
            out_dir = os.path.join(tmpdir, "out")
            os.mkdir(out_dir)
            data = b"a" * 200_000
            Path(src).write_bytes(data)

            job = TransferJob(
                source_path=src,
                dest_path=os.path.join(out_dir, "src.bin"),
                total_bytes=len(data),
                filename="src.bin",
                resume=True,
            )
            job.source_backend = fs
            job.dest_backend = fs
            part_path = os.path.join(out_dir, f".src.bin.part-{job.job_id}")
            Path(part_path).write_bytes(data[:100_000])

            worker._do_transfer(job, lambda *_: None)
            self.assertEqual(Path(os.path.join(out_dir, "src.bin")).read_bytes(), data)

    def test_resume_finalizes_already_complete_partial_file(self) -> None:
        fs = LocalFS()
        worker = TransferWorker()
        with tempfile.TemporaryDirectory() as tmpdir:
            src = os.path.join(tmpdir, "src.bin")
            out_dir = os.path.join(tmpdir, "out")
            os.mkdir(out_dir)
            data = b"complete-partial"
            Path(src).write_bytes(data)

            job = TransferJob(
                source_path=src,
                dest_path=os.path.join(out_dir, "src.bin"),
                total_bytes=len(data),
                filename="src.bin",
                resume=True,
            )
            job.source_backend = fs
            job.dest_backend = fs
            part_path = os.path.join(out_dir, f".src.bin.part-{job.job_id}")
            Path(part_path).write_bytes(data)

            worker._do_transfer(job, lambda *_: None)

            self.assertEqual(Path(job.dest_path).read_bytes(), data)
            self.assertFalse(Path(part_path).exists())

    def test_resume_restarts_when_source_is_not_seekable(self) -> None:
        class NonSeekable:
            def __init__(self, data: bytes):
                self._buf = io.BytesIO(data)

            def read(self, n: int = -1) -> bytes:
                return self._buf.read(n)

            def seek(self, *_args):
                raise OSError("not seekable")

            def close(self) -> None:
                self._buf.close()

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                self.close()

        fs = LocalFS()
        source = mock.MagicMock()
        worker = TransferWorker()
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = os.path.join(tmpdir, "out")
            os.mkdir(out_dir)
            data = b"fresh-data"
            source.open_read.return_value = NonSeekable(data)

            job = TransferJob(
                source_path="/remote/src.bin",
                dest_path=os.path.join(out_dir, "src.bin"),
                total_bytes=len(data),
                filename="src.bin",
                resume=True,
            )
            job.source_backend = source
            job.dest_backend = fs
            part_path = os.path.join(out_dir, f".src.bin.part-{job.job_id}")
            Path(part_path).write_bytes(b"stale")

            worker._do_transfer(job, lambda *_: None)

            self.assertEqual(Path(job.dest_path).read_bytes(), data)

    def test_move_reports_error_when_source_delete_fails(self) -> None:
        worker = TransferWorker()
        source = mock.MagicMock()
        dest = mock.MagicMock()
        source.open_read.return_value = io.BytesIO(b"abc")
        source.checksum.return_value = ""
        source.remove.side_effect = OSError("source locked")
        dest.open_write.return_value = io.BytesIO()
        dest.checksum.return_value = ""

        job = TransferJob(
            source_path="/src.bin",
            dest_path="/dst.bin",
            total_bytes=3,
            filename="src.bin",
            move=True,
            use_temp_file=False,
        )
        job.source_backend = source
        job.dest_backend = dest

        worker._process_job(job)

        self.assertEqual(job.status, TransferStatus.ERROR)
        self.assertIn("removing the source failed", job.error_message)

    def test_retry_reuses_partial_file_for_resume(self) -> None:
        manager = TransferManager()
        fs = LocalFS()
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                src = os.path.join(tmpdir, "src.bin")
                dst = os.path.join(tmpdir, "dst.bin")
                data = b"a" * 128_000
                Path(src).write_bytes(data)

                job = TransferJob(
                    source_path=src,
                    dest_path=dst,
                    total_bytes=len(data),
                    filename="dst.bin",
                )
                job.source_backend = fs
                job.dest_backend = fs
                job.status = TransferStatus.ERROR
                job.temp_path = os.path.join(tmpdir, ".dst.bin.part-stable")
                Path(job.temp_path).write_bytes(data[:64_000])
                manager._jobs[job.job_id] = job

                retry = manager.retry_job(job.job_id)
                self.assertIsNotNone(retry)
                assert retry is not None
                self.assertTrue(retry.resume)
                self.assertEqual(retry.temp_path, job.temp_path)
                retry.cancel_event.set()
                manager.shutdown()
                manager = None
        finally:
            if manager is not None:
                manager.shutdown()


class LocalFSRegressionTests(unittest.TestCase):
    def test_symlink_delete_removes_link_only(self) -> None:
        fs = LocalFS()
        with tempfile.TemporaryDirectory() as tmpdir:
            target = os.path.join(tmpdir, "target.txt")
            link = os.path.join(tmpdir, "link.txt")
            broken = os.path.join(tmpdir, "broken.txt")

            Path(target).write_text("hello", encoding="utf-8")
            os.symlink(target, link)
            os.symlink(os.path.join(tmpdir, "missing.txt"), broken)

            self.assertTrue(fs.exists(link))
            self.assertTrue(fs.exists(broken))
            self.assertFalse(fs.is_dir(link))

            fs.remove(link)
            self.assertFalse(fs.exists(link))
            self.assertTrue(fs.exists(target))


class TerminalRegressionTests(unittest.TestCase):
    def test_local_terminal_echoes_output(self) -> None:
        session = LocalTerminalSession()
        try:
            session.start()
            session.write(b"printf 'hello\\n'\n")
            deadline = time.monotonic() + 3.0
            output = b""
            while time.monotonic() < deadline and b"hello" not in output:
                chunk = session.read()
                if chunk:
                    output += chunk
                time.sleep(0.05)
            self.assertIn(b"hello", output)
        finally:
            session.close()

    def test_close_reaps_child_process_and_does_not_leave_zombie(self) -> None:
        # happy path: a real shell session, properly cleaned up. Pre-fix
        # close() called waitpid(WNOHANG) once — if SIGTERM had not yet
        # been processed, the child stayed <defunct> until the worker
        # exited. We now block briefly and escalate to SIGKILL so the
        # child is reaped before close() returns.
        session = LocalTerminalSession()
        session.start()
        pid = session._pid
        self.assertIsNotNone(pid)
        session.close()
        # After close, the pid should be fully reaped — no zombie.
        # waitpid(pid, WNOHANG) on a reaped child raises ChildProcessError;
        # if the child is still a zombie, it would return (pid, status).
        with self.assertRaises(ChildProcessError):
            os.waitpid(pid, os.WNOHANG)

    def test_close_is_idempotent_when_called_twice(self) -> None:
        # edge: close() may be called from finally-blocks and explicit
        # cleanup paths; the second call must not raise.
        session = LocalTerminalSession()
        session.start()
        session.close()
        session.close()  # must be a no-op, not an exception

    def test_close_escalates_to_sigkill_when_child_ignores_sigterm(self) -> None:
        # sad: the child shell may trap or ignore SIGTERM (e.g.
        # ``trap '' TERM`` or a stuck child); close() must still reap it
        # by escalating to SIGKILL inside its grace window. We simulate
        # by forking a child that traps SIGTERM and refuses to die. The
        # tightened close() should escalate and reap; the buggy version
        # returned immediately and left the child running.
        import pty as _pty
        pid, master_fd = _pty.fork()
        if pid == 0:
            try:
                signal.signal(signal.SIGTERM, signal.SIG_IGN)
                # Busy loop ignoring SIGTERM; only SIGKILL ends this.
                while True:
                    time.sleep(0.1)
            finally:
                os._exit(0)
        # Build a synthetic session that owns this child.
        session = LocalTerminalSession()
        session._pid = pid
        session._master_fd = master_fd
        session._running = True
        t0 = time.monotonic()
        session.close()
        elapsed = time.monotonic() - t0
        # The grace window is 0.5s; with SIGKILL escalation the call
        # should return well under 2s even on a heavily loaded CI box.
        self.assertLess(elapsed, 2.0)
        with self.assertRaises(ChildProcessError):
            os.waitpid(pid, os.WNOHANG)

    def test_close_without_start_is_safe(self) -> None:
        # sad: close() before start() — no fds, no child — must not
        # raise. The buggy version was fine here too, but the harder
        # close() path needs to stay safe.
        session = LocalTerminalSession()
        session.close()  # no exception
        self.assertFalse(session.is_active)


class ProfileRegressionTests(unittest.TestCase):
    def test_remove_clears_regular_and_proxy_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with (
                mock.patch("core.profiles.CONFIG_DIR", Path(tmpdir)),
                mock.patch("core.profiles.PROFILES_FILE", Path(tmpdir) / "profiles.json"),
                mock.patch("core.profiles.delete_password") as delete_password,
                mock.patch("core.profiles.delete_proxy_password") as delete_proxy_password,
            ):
                manager = ProfileManager()
                profile = ConnectionProfile(name="demo", host="example.com", username="user")
                manager.add(profile)
                manager.remove("demo")

                delete_password.assert_any_call("demo")
                delete_proxy_password.assert_any_call("demo")

    def test_from_dict_sanitizes_invalid_values(self) -> None:
        profile = ConnectionProfile.from_dict(
            {
                "name": "demo",
                "host": "example.com",
                "port": "22",
                "username": "user",
                "auth_type": "totally-invalid",
                "proxy_type": "bad",
                "proxy_port": 99999,
                "address_family": "strange",
                "store_password": "yes",
            }
        )

        self.assertEqual(profile.port, 22)
        self.assertEqual(profile.auth_type, "password")
        self.assertEqual(profile.proxy_type, "none")
        self.assertEqual(profile.proxy_port, 0)
        self.assertEqual(profile.address_family, "auto")
        self.assertFalse(profile.store_password)

    def test_from_dict_rejects_non_object(self) -> None:
        with self.assertRaises(TypeError):
            ConnectionProfile.from_dict("not-a-dict")  # type: ignore[arg-type]

    def test_from_dict_unknown_protocol_falls_back_to_sftp(self) -> None:
        p = ConnectionProfile.from_dict(
            {"name": "x", "host": "h", "protocol": "quantum-uplink"},
        )
        self.assertEqual(p.protocol, "sftp")

    def test_get_password_returns_none_when_disabled(self) -> None:
        # store_password=False means get_password is never consulted.
        p = ConnectionProfile(name="np", host="h", store_password=False)
        self.assertIsNone(p.get_password())

    def test_get_password_reads_keyring_when_enabled(self) -> None:
        with mock.patch("core.profiles.get_password", return_value="s3cr3t") as get_pw:
            p = ConnectionProfile(name="yp", host="h", store_password=True)
            self.assertEqual(p.get_password(), "s3cr3t")
            get_pw.assert_called_once_with("yp")

    def test_set_password_writes_keyring_when_enabled(self) -> None:
        with mock.patch("core.profiles.store_password") as store_pw:
            p = ConnectionProfile(name="wp", host="h", store_password=True)
            p.set_password("t0p")
            store_pw.assert_called_once_with("wp", "t0p")

    def test_set_password_skipped_when_disabled(self) -> None:
        with mock.patch("core.profiles.store_password") as store_pw:
            p = ConnectionProfile(name="np2", host="h", store_password=False)
            p.set_password("ignored")
            store_pw.assert_not_called()

    def test_proxy_password_getters_and_setters(self) -> None:
        with (
            mock.patch("core.profiles.get_proxy_password", return_value="px") as g,
            mock.patch("core.profiles.store_proxy_password") as s,
        ):
            p = ConnectionProfile(name="pp", host="h", store_proxy_password=True)
            self.assertEqual(p.get_proxy_password(), "px")
            p.set_proxy_password("new-px")
            g.assert_called_once()
            s.assert_called_once_with("pp", "new-px")

    def test_proxy_password_disabled_is_noop(self) -> None:
        with (
            mock.patch("core.profiles.get_proxy_password") as g,
            mock.patch("core.profiles.store_proxy_password") as s,
        ):
            p = ConnectionProfile(name="pp2", host="h", store_proxy_password=False)
            self.assertIsNone(p.get_proxy_password())
            p.set_proxy_password("x")
            g.assert_not_called()
            s.assert_not_called()

    def test_to_dict_includes_protocol_specific_fields(self) -> None:
        # FTP: emits ftp_passive. S3: includes region / endpoint when set.
        p = ConnectionProfile(
            name="ftp1",
            protocol="ftp",
            host="h",
            ftp_passive=False,
        )
        self.assertEqual(p.to_dict()["ftp_passive"], False)

        s = ConnectionProfile(
            name="s3x",
            protocol="s3",
            host="h",
            s3_bucket="b",
            s3_region="eu-west-1",
            s3_endpoint="https://m",
        )
        d = s.to_dict()
        self.assertEqual(d["s3_bucket"], "b")
        self.assertEqual(d["s3_region"], "eu-west-1")
        self.assertEqual(d["s3_endpoint"], "https://m")

    def test_to_dict_rsync_and_nfs_branches(self) -> None:
        rs = ConnectionProfile(
            name="r",
            protocol="rsync",
            host="h",
            rsync_module="mod",
            rsync_ssh=True,
            rsync_ssh_key="/k",
        )
        d = rs.to_dict()
        self.assertEqual(d["rsync_module"], "mod")
        self.assertEqual(d["rsync_ssh_key"], "/k")

        nfs = ConnectionProfile(
            name="n",
            protocol="nfs",
            host="h",
            nfs_export="/exp",
            nfs_version=4,
        )
        d = nfs.to_dict()
        self.assertEqual(d["nfs_export"], "/exp")
        self.assertEqual(d["nfs_version"], 4)

    def test_to_dict_cloud_branches(self) -> None:
        az = ConnectionProfile(
            name="az",
            protocol="azure_blob",
            host="h",
            azure_container="c",
            azure_account_name="acct",
        )
        self.assertEqual(az.to_dict()["azure_account_name"], "acct")

        azf = ConnectionProfile(
            name="azf",
            protocol="azure_files",
            host="h",
            azure_share="sh",
            azure_account_name="acct",
        )
        self.assertEqual(azf.to_dict()["azure_account_name"], "acct")

        od = ConnectionProfile(
            name="od",
            protocol="onedrive",
            host="h",
            onedrive_client_id="cid",
            onedrive_tenant_id="tenant",
        )
        d = od.to_dict()
        self.assertEqual(d["onedrive_client_id"], "cid")
        self.assertEqual(d["onedrive_tenant_id"], "tenant")

        sp = ConnectionProfile(
            name="sp",
            protocol="sharepoint",
            host="h",
            sharepoint_site_url="https://acme/sp",
        )
        self.assertEqual(
            sp.to_dict()["sharepoint_site_url"],
            "https://acme/sp",
        )

        gd = ConnectionProfile(
            name="gd",
            protocol="gdrive",
            host="h",
            gdrive_client_id="cid",
        )
        self.assertEqual(gd.to_dict()["gdrive_client_id"], "cid")

        db = ConnectionProfile(
            name="db",
            protocol="dropbox",
            host="h",
            dropbox_app_key="ak",
        )
        self.assertEqual(db.to_dict()["dropbox_app_key"], "ak")

    def test_to_dict_iscsi_and_imap_branches(self) -> None:
        isc = ConnectionProfile(
            name="isc",
            protocol="iscsi",
            host="h",
            iscsi_target_iqn="iqn",
            iscsi_mount_point="/mnt/d",
        )
        d = isc.to_dict()
        self.assertEqual(d["iscsi_target_iqn"], "iqn")
        self.assertEqual(d["iscsi_mount_point"], "/mnt/d")

        im = ConnectionProfile(
            name="im",
            protocol="imap",
            host="h",
            imap_ssl=False,
        )
        self.assertEqual(im.to_dict()["imap_ssl"], False)

    def test_to_dict_proxy_and_key_file_branches(self) -> None:
        p = ConnectionProfile(
            name="px",
            host="h",
            key_file="/k",
            proxy_type="socks5",
            proxy_host="ph",
            proxy_port=1080,
            proxy_username="pu",
            proxy_command="ssh -W %h:%p bastion",
            address_family="ipv6",
        )
        d = p.to_dict()
        self.assertEqual(d["key_file"], "/k")
        self.assertEqual(d["proxy_type"], "socks5")
        self.assertEqual(d["proxy_username"], "pu")
        self.assertEqual(d["proxy_command"], "ssh -W %h:%p bastion")
        self.assertEqual(d["address_family"], "ipv6")

    def test_load_skips_corrupted_profiles_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pf = Path(tmp) / "profiles.json"
            pf.write_text("{not json")
            with mock.patch("core.profiles.PROFILES_FILE", pf):
                mgr = ProfileManager()
            self.assertEqual(mgr.list_names(), [])

    def test_save_handles_oserror_on_target_dir(self) -> None:
        # When mkdir can't create the config dir, save() logs and
        # continues without raising (user might be read-only FS).
        with tempfile.TemporaryDirectory() as tmp:
            pf = Path(tmp) / "cfg" / "profiles.json"
            with mock.patch("core.profiles.PROFILES_FILE", pf):
                mgr = ProfileManager()
                mgr.add(ConnectionProfile(name="a", host="h"))
                # Force save() to hit a simulated chmod/rename failure.
                with mock.patch("core.profiles.os.replace", side_effect=OSError("disk full")):
                    mgr.save()  # no raise


class ConnectionManagerRegressionTests(unittest.TestCase):
    def test_protocol_hooks_cover_valid_and_registered_backends(self) -> None:
        import inspect
        import re

        from core import backend_registry
        from core import connection_manager as cm
        from core.profiles import VALID_PROTOCOLS

        backend_registry.init_registry()
        src = inspect.getsource(ConnectionManager._create_session)
        dispatched = set(re.findall(r'proto == "([^"]+)"', src))
        for tuple_expr in re.findall(r"proto in \(([^\)]*)\)", src):
            dispatched.update(re.findall(r'"([^"]+)"', tuple_expr))

        classified = (
            set(cm._PROTOCOLS_HONOURING_PROFILE_PROXY)
            | set(cm._PROTOCOLS_PARTIAL_PROFILE_PROXY)
            | set(cm._PROTOCOLS_NOT_PROXIABLE)
        )
        registered = {b.protocol_id for b in backend_registry.all_backends()}

        self.assertEqual(set(), set(VALID_PROTOCOLS) - dispatched)
        self.assertEqual(set(), dispatched - set(VALID_PROTOCOLS))
        self.assertEqual(set(), set(VALID_PROTOCOLS) - classified)
        self.assertEqual(set(), registered - classified)

    def test_session_key_includes_proxy_and_address_family(self) -> None:
        manager = ConnectionManager()
        base = ConnectionProfile(name="a", host="example.com", username="user")
        via_proxy = ConnectionProfile(
            name="b",
            host="example.com",
            username="user",
            proxy_type="http",
            proxy_host="proxy.local",
            proxy_port=8080,
        )
        ipv6 = ConnectionProfile(
            name="c",
            host="example.com",
            username="user",
            address_family="ipv6",
        )

        self.assertNotEqual(manager._session_key(base), manager._session_key(via_proxy))
        self.assertNotEqual(manager._session_key(base), manager._session_key(ipv6))

    def test_session_key_varies_on_protocol_specific_fields(self) -> None:
        manager = ConnectionManager()
        cases = [
            (
                "ssh-auth",
                ConnectionProfile(
                    name="a",
                    protocol="sftp",
                    host="h",
                    username="u",
                    auth_type="password",
                ),
                ConnectionProfile(
                    name="b",
                    protocol="sftp",
                    host="h",
                    username="u",
                    auth_type="key",
                    key_file="/keys/id_ed25519",
                ),
            ),
            (
                "ssh-keepalive",
                ConnectionProfile(
                    name="a",
                    protocol="sftp",
                    host="h",
                    username="u",
                    ssh_keepalive_interval=0,
                ),
                ConnectionProfile(
                    name="b",
                    protocol="sftp",
                    host="h",
                    username="u",
                    ssh_keepalive_interval=30,
                ),
            ),
            (
                "ftp-mode",
                ConnectionProfile(
                    name="a",
                    protocol="ftp",
                    host="h",
                    username="u",
                    ftp_passive=True,
                ),
                ConnectionProfile(
                    name="b",
                    protocol="ftp",
                    host="h",
                    username="u",
                    ftp_passive=False,
                ),
            ),
            (
                "ftps-verify",
                ConnectionProfile(
                    name="a",
                    protocol="ftps",
                    host="h",
                    username="u",
                    ftps_verify_tls=True,
                ),
                ConnectionProfile(
                    name="b",
                    protocol="ftps",
                    host="h",
                    username="u",
                    ftps_verify_tls=False,
                ),
            ),
            (
                "smb-share",
                ConnectionProfile(
                    name="a",
                    protocol="smb",
                    host="h",
                    username="u",
                    smb_share="one",
                ),
                ConnectionProfile(
                    name="b",
                    protocol="smb",
                    host="h",
                    username="u",
                    smb_share="two",
                ),
            ),
            (
                "smb-client-name",
                ConnectionProfile(
                    name="a",
                    protocol="smb",
                    host="h",
                    username="u",
                    smb_share="one",
                    smb_client_name="WORKSTATION",
                ),
                ConnectionProfile(
                    name="b",
                    protocol="smb",
                    host="h",
                    username="u",
                    smb_share="one",
                    smb_client_name="LABBOX",
                ),
            ),
            (
                "s3-endpoint",
                ConnectionProfile(
                    name="a",
                    protocol="s3",
                    host="h",
                    username="u",
                    s3_bucket="one",
                    s3_region="us-east-1",
                    s3_endpoint="https://s3.example",
                ),
                ConnectionProfile(
                    name="b",
                    protocol="s3",
                    host="h",
                    username="u",
                    s3_bucket="one",
                    s3_region="eu-west-1",
                    s3_endpoint="https://minio.example",
                ),
            ),
            (
                "rsync-preserve",
                ConnectionProfile(
                    name="a",
                    protocol="rsync",
                    host="h",
                    username="u",
                    rsync_module="mod",
                    rsync_preserve_metadata=False,
                ),
                ConnectionProfile(
                    name="b",
                    protocol="rsync",
                    host="h",
                    username="u",
                    rsync_module="mod",
                    rsync_preserve_metadata=True,
                ),
            ),
            (
                "pop3-ssl",
                ConnectionProfile(
                    name="a",
                    protocol="pop3",
                    host="h",
                    username="u",
                    pop3_ssl=True,
                ),
                ConnectionProfile(
                    name="b",
                    protocol="pop3",
                    host="h",
                    username="u",
                    pop3_ssl=False,
                ),
            ),
            (
                "tftp-filelist",
                ConnectionProfile(
                    name="a",
                    protocol="tftp",
                    host="h",
                    tftp_filelist="a.bin",
                    tftp_filelist_enabled=True,
                    tftp_max_size_bytes=1024,
                ),
                ConnectionProfile(
                    name="b",
                    protocol="tftp",
                    host="h",
                    tftp_filelist="b.bin",
                    tftp_filelist_enabled=False,
                    tftp_max_size_bytes=2048,
                ),
            ),
            (
                "adb-mode",
                ConnectionProfile(
                    name="a",
                    protocol="adb",
                    host="10.0.0.2",
                    adb_mode="tcp",
                ),
                ConnectionProfile(
                    name="b",
                    protocol="adb",
                    host="10.0.0.2",
                    adb_mode="usb",
                    adb_usb_serial="ABC123",
                ),
            ),
            (
                "mtp-device",
                ConnectionProfile(
                    name="a",
                    protocol="mtp",
                    host="phone",
                    mtp_device_id="1",
                    mtp_mounter="jmtpfs",
                ),
                ConnectionProfile(
                    name="b",
                    protocol="mtp",
                    host="phone",
                    mtp_device_id="2",
                    mtp_mounter="simple-mtpfs",
                ),
            ),
            (
                "telnet-naws",
                ConnectionProfile(
                    name="a",
                    protocol="telnet",
                    host="h",
                    username="u",
                    telnet_naws_width=80,
                    telnet_naws_height=24,
                ),
                ConnectionProfile(
                    name="b",
                    protocol="telnet",
                    host="h",
                    username="u",
                    telnet_naws_width=132,
                    telnet_naws_height=43,
                ),
            ),
        ]
        for label, base, other in cases:
            with self.subTest(label=label):
                self.assertNotEqual(
                    manager._session_key(base),
                    manager._session_key(other),
                )

    def test_set_profile_resolver_stored(self) -> None:
        mgr = ConnectionManager()

        def resolver(n):
            return None

        mgr.set_profile_resolver(resolver)
        self.assertIs(mgr._profile_resolver, resolver)

    def test_warn_unsupported_proxy_emits_for_kernel_protocols(self) -> None:
        # Kernel-level mounts (NFS, iSCSI, MTP) cannot be tunneled
        # through a user-space proxy and must emit a warning if one
        # is configured.
        import logging as _log

        from core.connection_manager import _warn_unsupported_proxy

        prof = ConnectionProfile(
            name="c",
            protocol="nfs",
            host="h",
            proxy_type="socks5",
            proxy_host="p",
            proxy_port=1080,
        )
        with mock.patch.object(_log.getLogger("core.connection_manager"), "warning") as warn:
            _warn_unsupported_proxy(prof)
        warn.assert_called()

    def test_warn_unsupported_proxy_silent_for_sftp(self) -> None:
        # sftp natively honours the profile's proxy → no warning.
        import logging as _log

        from core.connection_manager import _warn_unsupported_proxy

        prof = ConnectionProfile(
            name="s",
            protocol="sftp",
            host="h",
            proxy_type="socks5",
            proxy_host="p",
            proxy_port=1080,
        )
        with mock.patch.object(_log.getLogger("core.connection_manager"), "warning") as warn:
            _warn_unsupported_proxy(prof)
        warn.assert_not_called()

    def test_warn_unsupported_proxy_silent_with_no_proxy(self) -> None:
        from core.connection_manager import _warn_unsupported_proxy

        prof = ConnectionProfile(name="n", protocol="s3", host="h", proxy_type="none")
        # Must not raise, must not log.
        _warn_unsupported_proxy(prof)

    def test_create_session_refuses_proxy_type_without_host(self) -> None:
        mgr = ConnectionManager()
        prof = ConnectionProfile(
            name="p",
            protocol="sftp",
            host="h",
            username="u",
            proxy_type="socks5",
            proxy_host="",
            proxy_port=1080,
        )
        with self.assertRaises(ValueError) as ctx:
            mgr._create_session(prof, "pw", "", None)
        self.assertIn("refusing direct traffic", str(ctx.exception))

    def test_create_session_refuses_proxy_type_without_port(self) -> None:
        mgr = ConnectionManager()
        prof = ConnectionProfile(
            name="p",
            protocol="webdav",
            host="h",
            username="u",
            proxy_type="socks5",
            proxy_host="proxy.local",
            proxy_port=0,
        )
        with self.assertRaises(ValueError) as ctx:
            mgr._create_session(prof, "pw", "", None)
        self.assertIn("Proxy port must be in range", str(ctx.exception))

    def test_warn_unsupported_proxy_for_backend_without_proxy(self) -> None:
        import logging as _log

        from core.connection_manager import _warn_unsupported_proxy

        # Kernel / local / explicit non-proxy backends must warn.
        prof = ConnectionProfile(
            name="n",
            protocol="nfs",
            host="h",
            proxy_type="socks5",
            proxy_host="p",
            proxy_port=1080,
        )
        with mock.patch.object(_log.getLogger("core.connection_manager"), "warning") as warn:
            _warn_unsupported_proxy(prof)
        warn.assert_called()

    def test_connect_reuses_existing_active_session(self) -> None:
        mgr = ConnectionManager()
        prof = ConnectionProfile(name="p", host="h", username="u", protocol="sftp")
        fake_session = mock.MagicMock()
        with (
            mock.patch.object(mgr, "_create_session", return_value=fake_session),
            mock.patch.object(mgr, "_is_connected", return_value=True),
        ):
            s1 = mgr.connect(prof)
            s2 = mgr.connect(prof)
        self.assertIs(s1, fake_session)
        self.assertIs(s2, fake_session)
        # refcount incremented to 2.
        self.assertEqual(
            mgr._ref_counts[mgr._session_key(prof)],
            2,
        )

    def test_connect_creates_new_session_when_stale(self) -> None:
        mgr = ConnectionManager()
        prof = ConnectionProfile(name="p", host="h", username="u", protocol="sftp")
        old_session = mock.MagicMock()
        new_session = mock.MagicMock()
        # Pre-populate with a stale session.
        key = mgr._session_key(prof)
        mgr._sessions[key] = old_session
        mgr._ref_counts[key] = 1
        with (
            mock.patch.object(mgr, "_create_session", return_value=new_session),
            mock.patch.object(mgr, "_is_connected", return_value=False),
        ):
            result = mgr.connect(prof)
        self.assertIs(result, new_session)
        self.assertEqual(mgr._ref_counts[key], 1)

    def _mock_backend_class(self, returned=None):
        """Return a (patch_ctx, fake_cls) pair — the patch swaps
        load_backend_class on core.connection_manager to return a
        MagicMock class that records its ctor args."""
        fake_cls = mock.MagicMock(return_value=returned or mock.MagicMock())
        return mock.patch(
            "core.connection_manager.load_backend_class",
            return_value=fake_cls,
        ), fake_cls

    def test_create_session_sftp_dispatches_to_ssh(self) -> None:
        mgr = ConnectionManager()
        prof = ConnectionProfile(name="p", protocol="sftp", host="h", username="u")
        fake_ssh = mock.MagicMock()
        with mock.patch("core.connection_manager.SSHSession", return_value=fake_ssh):
            session = mgr._create_session(prof, "pw", "", None)
        self.assertIs(session, fake_ssh)
        fake_ssh.connect.assert_called_once()

    def test_create_session_scp_dispatches_to_scp(self) -> None:
        mgr = ConnectionManager()
        prof = ConnectionProfile(name="p", protocol="scp", host="h", username="u")
        fake_scp = mock.MagicMock()
        with mock.patch("core.connection_manager.SCPSession", return_value=fake_scp):
            session = mgr._create_session(prof, "pw", "", None)
        self.assertIs(session, fake_scp)

    def test_create_session_ftp_loads_backend_class(self) -> None:
        mgr = ConnectionManager()
        prof = ConnectionProfile(name="p", protocol="ftp", host="h", username="u", port=21)
        ctx, fake_cls = self._mock_backend_class()
        with ctx:
            mgr._create_session(prof, "pw", "", None)
        fake_cls.assert_called_once()
        self.assertFalse(fake_cls.call_args.kwargs["tls"])

    def test_create_session_ftps_sets_tls_flag(self) -> None:
        mgr = ConnectionManager()
        prof = ConnectionProfile(name="p", protocol="ftps", host="h", username="u", port=990)
        ctx, fake_cls = self._mock_backend_class()
        with ctx:
            mgr._create_session(prof, "pw", "", None)
        self.assertTrue(fake_cls.call_args.kwargs["tls"])

    def test_create_session_smb_webdav_s3_rsync_nfs_dispatch(self) -> None:
        mgr = ConnectionManager()
        for proto in (
            "smb",
            "webdav",
            "s3",
            "rsync",
            "nfs",
            "azure_blob",
            "azure_files",
            "onedrive",
            "sharepoint",
            "gdrive",
            "dropbox",
            "iscsi",
            "imap",
            "pop3",
            "telnet",
            "dfsn",
            "nntp",
            "tftp",
            "cisco-telnet",
            "gopher",
            "pjl",
            "winrm",
            "adb",
            "svn",
        ):
            with self.subTest(proto=proto):
                prof = ConnectionProfile(name="p", protocol=proto, host="h", username="u")
                ctx, _ = self._mock_backend_class()
                with ctx:
                    mgr._create_session(prof, "pw", "", None)

    def test_profile_proxy_routed_branches_pass_proxy_kwargs(self) -> None:
        mgr = ConnectionManager()
        from core.connection_manager import _PROTOCOLS_HONOURING_PROFILE_PROXY

        routed = sorted(_PROTOCOLS_HONOURING_PROFILE_PROXY - {"sftp", "scp"})
        for proto in routed:
            with self.subTest(proto=proto):
                prof = ConnectionProfile(
                    name="p",
                    protocol=proto,
                    host="h",
                    username="u",
                    proxy_type="http",
                    proxy_host="proxy.local",
                    proxy_port=1080,
                    proxy_username="pxu",
                )
                ctx, fake_cls = self._mock_backend_class()
                with (
                    ctx,
                    mock.patch.object(
                        prof,
                        "get_proxy_password",
                        return_value="pxp",
                    ),
                ):
                    mgr._create_session(prof, "pw", "", None)
                kwargs = fake_cls.call_args.kwargs
                self.assertEqual(kwargs["proxy_type"], "http")
                self.assertEqual(kwargs["proxy_host"], "proxy.local")
                self.assertEqual(kwargs["proxy_port"], 1080)
                self.assertEqual(kwargs["proxy_username"], "pxu")
                self.assertEqual(kwargs["proxy_password"], "pxp")

    def test_create_session_unknown_protocol_raises(self) -> None:
        mgr = ConnectionManager()
        prof = ConnectionProfile(name="p", protocol="sftp", host="h")
        prof.protocol = "aliens-from-outer-space"
        with self.assertRaises(ValueError):
            mgr._create_session(prof, "pw", "", None)

    def test_release_decrements_and_disconnects(self) -> None:
        mgr = ConnectionManager()
        prof = ConnectionProfile(name="p", protocol="sftp", host="h", username="u")
        key = mgr._session_key(prof)
        fake_session = mock.MagicMock()
        mgr._sessions[key] = fake_session
        mgr._ref_counts[key] = 2
        mgr.release(prof)
        # Still open because refcount was 2.
        self.assertIn(key, mgr._sessions)
        mgr.release(prof)
        # Now dropped.
        self.assertNotIn(key, mgr._sessions)

    def test_release_ignored_for_unknown_profile(self) -> None:
        mgr = ConnectionManager()
        prof = ConnectionProfile(name="nope", protocol="sftp", host="h")
        # No raise, no effect.
        mgr.release(prof)


class FilePaneDragRegressionTests(unittest.TestCase):
    def test_file_table_model_marks_items_as_draggable_and_root_as_droppable(self) -> None:
        model = FileTableModel()
        model.set_items([FileItem(name="drag-me.txt", size=1)])

        flags = model.flags(model.index(0, 0))
        root_flags = model.flags(QModelIndex())

        self.assertTrue(flags & Qt.ItemFlag.ItemIsDragEnabled)
        self.assertTrue(root_flags & Qt.ItemFlag.ItemIsDropEnabled)

    def test_drag_payload_round_trips_paths_with_newlines(self) -> None:
        pane = FilePaneWidget(LocalFS())
        try:
            original_paths = ["/tmp/normal.txt", "/tmp/with\nnewline.txt"]
            mime = QMimeData()
            mime.setData(
                "application/x-axross-transfer",
                pane._encode_transfer_payload(original_paths),
            )

            payload = FilePaneWidget._decode_transfer_payload(mime)
            self.assertIsNotNone(payload)
            assert payload is not None
            self.assertEqual(payload["paths"], original_paths)
            self.assertEqual(payload["source_pane_id"], str(id(pane)))
        finally:
            pane.deleteLater()


class TextEditorRegressionTests(unittest.TestCase):
    def test_reload_does_not_discard_unsaved_changes_without_confirmation(self) -> None:
        fs = LocalFS()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "note.txt")
            Path(path).write_text("original", encoding="utf-8")

            dialog = TextEditorDialog(fs, path)
            dialog._editor.setPlainText("changed")

            with mock.patch.object(
                QMessageBox,
                "question",
                return_value=QMessageBox.StandardButton.No,
            ):
                dialog._reload_file()

            self.assertEqual(dialog._editor.toPlainText(), "changed")
            self.assertTrue(dialog._modified)
            dialog._modified = False
            dialog.close()

    def test_save_uses_temp_file_and_cleans_it_up(self) -> None:
        fs = LocalFS()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "note.txt")
            Path(path).write_text("original", encoding="utf-8")

            dialog = TextEditorDialog(fs, path)
            dialog._editor.setPlainText("updated")
            dialog._save_file()

            self.assertEqual(Path(path).read_text(encoding="utf-8"), "updated")
            leftovers = list(Path(tmpdir).glob(".note.txt.edit-*.tmp"))
            self.assertEqual(leftovers, [])
            dialog.close()

    def test_refuses_file_over_cap(self) -> None:
        # Files larger than MAX_FILE_SIZE get a dialog and reject().
        from ui.text_editor import MAX_FILE_SIZE

        fs = LocalFS()
        with tempfile.TemporaryDirectory() as tmpdir:
            big = Path(tmpdir) / "big.txt"
            big.write_bytes(b"x" * (MAX_FILE_SIZE + 10))
            with mock.patch.object(QMessageBox, "warning") as warn:
                dialog = TextEditorDialog(fs, str(big))
            warn.assert_called_once()
            dialog.close()

    def test_load_error_shows_critical_and_rejects(self) -> None:
        # Missing file → open_read raises → critical dialog + reject.
        fs = LocalFS()
        with tempfile.TemporaryDirectory() as tmpdir:
            missing = os.path.join(tmpdir, "ghost.txt")
            with mock.patch.object(QMessageBox, "critical") as crit:
                dialog = TextEditorDialog(fs, missing)
            crit.assert_called_once()
            dialog.close()

    def test_latin1_fallback_when_not_utf8(self) -> None:
        fs = LocalFS()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "latin.txt")
            Path(path).write_bytes(b"caf\xe9")  # "café" in latin-1
            dialog = TextEditorDialog(fs, path)
            self.assertEqual(dialog._encoding_label.text(), "Latin-1")
            dialog.close()

    def test_save_atomic_falls_back_to_delete_rename(self) -> None:
        # Some backends fail rename-over-existing with OSError; the
        # editor then falls back to remove + rename.
        fs = LocalFS()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "note.txt")
            Path(path).write_text("old", encoding="utf-8")
            dialog = TextEditorDialog(fs, path)
            dialog._editor.setPlainText("new-content")
            # First rename raises, then succeeds after remove.
            calls = {"n": 0}
            original_rename = fs.rename

            def flaky_rename(src, dst):
                calls["n"] += 1
                if calls["n"] == 1:
                    raise OSError("rename-over-existing not supported")
                return original_rename(src, dst)

            with mock.patch.object(fs, "rename", side_effect=flaky_rename):
                dialog._save_file()
            self.assertEqual(
                Path(path).read_text(encoding="utf-8"),
                "new-content",
            )
            dialog._modified = False
            dialog.close()


class ConnectionDialogRegressionTests(unittest.TestCase):
    def test_validation_rejects_invalid_host_characters(self) -> None:
        manager = ProfileManager()
        dialog = ConnectionDialog(manager)
        dialog._host.setText("bad host")
        dialog._username.setText("user")

        with mock.patch.object(QMessageBox, "warning") as warning:
            self.assertFalse(dialog._validate())
            warning.assert_called_once()
        dialog.close()

    def test_renaming_profile_preserves_stored_credentials(self) -> None:
        password_store = {"old": "secret"}
        proxy_store = {"old": "proxy-secret"}

        def _get_password(name: str) -> str | None:
            return password_store.get(name)

        def _store_password(name: str, value: str) -> bool:
            password_store[name] = value
            return True

        def _delete_password(name: str) -> bool:
            password_store.pop(name, None)
            return True

        def _get_proxy_password(name: str) -> str | None:
            return proxy_store.get(name)

        def _store_proxy_password(name: str, value: str) -> bool:
            proxy_store[name] = value
            return True

        def _delete_proxy_password(name: str) -> bool:
            proxy_store.pop(name, None)
            return True

        with tempfile.TemporaryDirectory() as tmpdir:
            with (
                mock.patch("core.profiles.CONFIG_DIR", Path(tmpdir)),
                mock.patch("core.profiles.PROFILES_FILE", Path(tmpdir) / "profiles.json"),
                mock.patch("core.profiles.get_password", side_effect=_get_password),
                mock.patch("core.profiles.store_password", side_effect=_store_password),
                mock.patch("core.profiles.delete_password", side_effect=_delete_password),
                mock.patch("core.profiles.get_proxy_password", side_effect=_get_proxy_password),
                mock.patch("core.profiles.store_proxy_password", side_effect=_store_proxy_password),
                mock.patch(
                    "core.profiles.delete_proxy_password", side_effect=_delete_proxy_password
                ),
                mock.patch.object(QMessageBox, "information"),
                mock.patch.object(QMessageBox, "warning"),
            ):
                manager = ProfileManager()
                old_profile = ConnectionProfile(
                    name="old",
                    host="example.com",
                    username="user",
                    store_password=True,
                    proxy_type="http",
                    proxy_host="proxy.local",
                    proxy_port=8080,
                    store_proxy_password=True,
                )
                manager.add(old_profile)

                dialog = ConnectionDialog(manager, profile=old_profile)
                dialog._profile_name.setText("new")
                dialog._save_profile()

                self.assertIsNone(manager.get("old"))
                self.assertIsNotNone(manager.get("new"))
                self.assertEqual(password_store.get("new"), "secret")
                self.assertEqual(proxy_store.get("new"), "proxy-secret")
                self.assertNotIn("old", password_store)
                self.assertNotIn("old", proxy_store)
                dialog.close()


if __name__ == "__main__":
    unittest.main()
