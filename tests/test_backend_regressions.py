from __future__ import annotations

import json
import importlib
import os
import sys
import tempfile
import unittest
from email.message import EmailMessage
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.profiles import ConnectionProfile, ProfileManager


def load_connection_manager_class():
    import types

    fake_ssh_client = types.ModuleType("core.ssh_client")
    fake_scp_client = types.ModuleType("core.scp_client")

    class _DummySSHSession:
        def __init__(self, *args, **kwargs):
            pass

    class _DummySCPSession:
        def __init__(self, *args, **kwargs):
            pass

    class _DummyUnknownHostKeyError(Exception):
        pass

    fake_ssh_client.SSHSession = _DummySSHSession
    fake_ssh_client.UnknownHostKeyError = _DummyUnknownHostKeyError
    fake_scp_client.SCPSession = _DummySCPSession

    with mock.patch.dict(
        sys.modules,
        {
            "core.ssh_client": fake_ssh_client,
            "core.scp_client": fake_scp_client,
        },
    ):
        sys.modules.pop("core.connection_manager", None)
        module = importlib.import_module("core.connection_manager")
        return module.ConnectionManager


class ProfileSecretRegressionTests(unittest.TestCase):
    def test_sensitive_fields_are_moved_out_of_profile_json(self) -> None:
        secret_store: dict[tuple[str, str], str] = {}

        def _store_secret(name: str, field: str, value: str) -> bool:
            secret_store[(name, field)] = value
            return True

        def _get_secret(name: str, field: str) -> str | None:
            return secret_store.get((name, field))

        with tempfile.TemporaryDirectory() as tmpdir:
            with (
                mock.patch("core.profiles.CONFIG_DIR", Path(tmpdir)),
                mock.patch("core.profiles.PROFILES_FILE", Path(tmpdir) / "profiles.json"),
                mock.patch("core.profiles.store_secret", side_effect=_store_secret),
                mock.patch("core.profiles.get_secret", side_effect=_get_secret),
                mock.patch("core.profiles.delete_secret", return_value=True),
                mock.patch("core.profiles.delete_password", return_value=True),
                mock.patch("core.profiles.delete_proxy_password", return_value=True),
            ):
                manager = ProfileManager()
                profile = ConnectionProfile(
                    name="demo",
                    host="example.com",
                    azure_connection_string="UseDevelopmentStorage=true",
                    azure_sas_token="sv=2024-01-01&sig=secret",
                    gdrive_client_secret="google-secret",
                    dropbox_app_secret="dropbox-secret",
                )
                manager.add(profile)

                data = json.loads((Path(tmpdir) / "profiles.json").read_text(encoding="utf-8"))
                stored = data["demo"]
                self.assertEqual(stored.get("azure_connection_string", ""), "")
                self.assertEqual(stored.get("azure_sas_token", ""), "")
                self.assertEqual(stored.get("gdrive_client_secret", ""), "")
                self.assertEqual(stored.get("dropbox_app_secret", ""), "")
                self.assertEqual(
                    secret_store[("demo", "azure_connection_string")],
                    "UseDevelopmentStorage=true",
                )
                self.assertEqual(
                    secret_store[("demo", "gdrive_client_secret")],
                    "google-secret",
                )

                reloaded = ProfileManager().get("demo")
                assert reloaded is not None
                self.assertEqual(reloaded.azure_connection_string, "UseDevelopmentStorage=true")
                self.assertEqual(reloaded.dropbox_app_secret, "dropbox-secret")

    def test_save_aborts_when_secret_storage_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with (
                mock.patch("core.profiles.CONFIG_DIR", Path(tmpdir)),
                mock.patch("core.profiles.PROFILES_FILE", Path(tmpdir) / "profiles.json"),
                mock.patch("core.profiles.store_secret", return_value=False),
                mock.patch("core.profiles.delete_secret", return_value=True),
                mock.patch("core.profiles.delete_password", return_value=True),
                mock.patch("core.profiles.delete_proxy_password", return_value=True),
            ):
                manager = ProfileManager()
                profile = ConnectionProfile(
                    name="demo",
                    host="example.com",
                    gdrive_client_secret="google-secret",
                )
                with self.assertRaises(RuntimeError):
                    manager.add(profile)
                self.assertFalse((Path(tmpdir) / "profiles.json").exists())


class ConnectionManagerRegressionTests(unittest.TestCase):
    def test_session_key_includes_backend_specific_connection_settings(self) -> None:
        manager = load_connection_manager_class()()

        onedrive_a = ConnectionProfile(
            name="onedrive-a",
            protocol="onedrive",
            onedrive_client_id="client-a",
            onedrive_tenant_id="tenant-a",
        )
        onedrive_b = ConnectionProfile(
            name="onedrive-b",
            protocol="onedrive",
            onedrive_client_id="client-b",
            onedrive_tenant_id="tenant-a",
        )
        rsync_daemon = ConnectionProfile(
            name="rsync-daemon",
            protocol="rsync",
            host="example.com",
            rsync_module="data",
            rsync_ssh=False,
        )
        rsync_ssh = ConnectionProfile(
            name="rsync-ssh",
            protocol="rsync",
            host="example.com",
            rsync_module="data",
            rsync_ssh=True,
            rsync_ssh_key="~/.ssh/id_ed25519",
        )
        iscsi_auto = ConnectionProfile(
            name="iscsi-a",
            protocol="iscsi",
            host="10.0.0.5",
            iscsi_target_iqn="iqn.test:target",
            iscsi_mount_point="/mnt/a",
        )
        iscsi_other_mount = ConnectionProfile(
            name="iscsi-b",
            protocol="iscsi",
            host="10.0.0.5",
            iscsi_target_iqn="iqn.test:target",
            iscsi_mount_point="/mnt/b",
        )
        via_jump_a = ConnectionProfile(
            name="sftp-a",
            protocol="sftp",
            host="example.com",
            username="alice",
            proxy_command="ssh -W %h:%p jump-a",
        )
        via_jump_b = ConnectionProfile(
            name="sftp-b",
            protocol="sftp",
            host="example.com",
            username="alice",
            proxy_command="ssh -W %h:%p jump-b",
        )

        self.assertNotEqual(manager._session_key(onedrive_a), manager._session_key(onedrive_b))
        self.assertNotEqual(manager._session_key(rsync_daemon), manager._session_key(rsync_ssh))
        self.assertNotEqual(manager._session_key(iscsi_auto), manager._session_key(iscsi_other_mount))
        self.assertNotEqual(manager._session_key(via_jump_a), manager._session_key(via_jump_b))


class BackendRegressionTests(unittest.TestCase):
    def test_rsync_ssh_mode_uses_remote_paths_and_keeps_host_key_validation(self) -> None:
        from core.rsync_client import RsyncSession

        session = object.__new__(RsyncSession)
        session._host = "example.com"
        session._port = 2222
        session._module = "remote/base"
        session._username = "alice"
        session._password = ""
        session._ssh_mode = True
        session._ssh_key = "/tmp/test key"
        session._rsync_bin = "rsync"

        self.assertEqual(
            session._build_url("/nested/file.txt"),
            "alice@example.com:/remote/base/nested/file.txt",
        )
        args = session._base_args()
        self.assertEqual(args[:2], ["rsync", "-e"])
        self.assertIn("BatchMode=yes", args[2])
        self.assertNotIn("StrictHostKeyChecking=no", args[2])

    def test_iscsi_init_connects_and_rejects_traversal(self) -> None:
        from core.iscsi_client import IscsiSession

        with mock.patch.object(IscsiSession, "connect") as connect:
            session = IscsiSession(target_ip="10.0.0.5", target_iqn="iqn.test:target")
            try:
                connect.assert_called_once()
            finally:
                session.disconnect()

        with tempfile.TemporaryDirectory() as tmpdir:
            session = object.__new__(IscsiSession)
            session._mount_point = tmpdir
            self.assertRaises(PermissionError, session._real, "../escape")

    def test_nfs_rejects_prefix_traversal(self) -> None:
        from core.nfs_client import NfsSession

        with tempfile.TemporaryDirectory() as tmpdir:
            session = object.__new__(NfsSession)
            session._mount_point = os.path.join(tmpdir, "mount")
            os.makedirs(session._mount_point, exist_ok=True)
            with self.assertRaises(PermissionError):
                session._full_path("../mount-evil/file.txt")


class ImapRegressionTests(unittest.TestCase):
    @staticmethod
    def _make_imap_session(*mailbox_entries: bytes):
        from core.imap_client import ImapSession

        class _FakeImap:
            def __init__(self, entries: tuple[bytes, ...]):
                self._entries = list(entries)

            def noop(self):
                return ("OK", [b"NOOP"])

            def list(self, *args, **kwargs):
                return ("OK", self._entries)

            def select(self, *args, **kwargs):
                return ("OK", [b"1"])

        session = object.__new__(ImapSession)
        session._host = "imap.example.test"
        session._port = 993
        session._username = "alice"
        session._password = "secret"
        session._use_ssl = True
        session._imap = _FakeImap(mailbox_entries)
        session._hierarchy_sep = "/"
        session._selected_mailbox = None
        session._mailbox_cache = None
        return session

    def test_nested_mailboxes_keep_full_names_and_are_parseable(self) -> None:
        session = self._make_imap_session(
            b'(\\HasNoChildren) "/" "INBOX"',
            b'(\\HasNoChildren) "/" "Projects/2025"',
        )

        items = session._list_mailboxes()
        self.assertEqual([item.name for item in items], ["INBOX", "Projects/2025"])
        self.assertEqual(
            session._parse_path("/Projects/2025/123_report.eml"),
            ("Projects/2025", "123"),
        )

    def test_nonexistent_mailboxes_and_virtual_write_targets_do_not_exist(self) -> None:
        session = self._make_imap_session(
            b'(\\HasNoChildren) "/" "INBOX"',
        )

        self.assertFalse(session.exists("/Missing"))
        self.assertFalse(session.exists("/INBOX/readme.txt"))
        with self.assertRaises(FileNotFoundError):
            session.list_dir("/INBOX/readme.txt")

    def test_attachment_without_filename_can_be_statted_and_read(self) -> None:
        session = self._make_imap_session(
            b'(\\HasNoChildren) "/" "INBOX"',
        )

        msg = EmailMessage()
        msg["Subject"] = "Attachment test"
        msg.set_content("body")
        msg.add_attachment(
            b"payload",
            maintype="application",
            subtype="pdf",
            disposition="attachment",
        )
        raw_message = msg.as_bytes()

        session._fetch_raw_message = lambda mailbox, uid: raw_message  # type: ignore[method-assign]

        items = session._list_attachments("INBOX", "1")
        self.assertEqual([item.name for item in items], ["attachment.pdf"])
        stat_item = session.stat("/INBOX/1/attachment.pdf")
        self.assertEqual(stat_item.size, len(b"payload"))
        with session.open_read("/INBOX/1/attachment.pdf") as handle:
            self.assertEqual(handle.read(), b"payload")


class BackendRegistryRegressionTests(unittest.TestCase):
    def test_nfs_backend_is_available_with_generic_mount_binary(self) -> None:
        from core import backend_registry

        available_commands = {
            "mount": "/bin/mount",
            "umount": "/bin/umount",
        }

        with mock.patch(
            "core.backend_registry.shutil.which",
            side_effect=lambda cmd: available_commands.get(cmd),
        ):
            backend_registry.init_registry()

        nfs = backend_registry.get("nfs")
        assert nfs is not None
        self.assertTrue(nfs.available)


class CloudPathRegressionTests(unittest.TestCase):
    def test_empty_or_relative_paths_normalize_to_rooted_paths(self) -> None:
        from core.gdrive_client import GDriveSession
        from core.onedrive_client import OneDriveSession

        gdrive = object.__new__(GDriveSession)
        onedrive = object.__new__(OneDriveSession)

        self.assertEqual(gdrive.normalize(""), "/")
        self.assertEqual(gdrive.normalize("docs/report.txt"), "/docs/report.txt")
        self.assertEqual(onedrive.normalize(""), "/")
        self.assertEqual(onedrive.normalize("docs/report.txt"), "/docs/report.txt")


class SshConfigRegressionTests(unittest.TestCase):
    def test_parse_ssh_config_keeps_proxy_command(self) -> None:
        from core.ssh_config import parse_ssh_config

        with tempfile.NamedTemporaryFile("w", suffix=".sshconfig", delete=False) as handle:
            handle.write(
                """
Host jump-demo
    HostName internal.example
    User deploy
    ProxyCommand ssh -W %h:%p bastion
    AddressFamily inet6
"""
            )
            config_path = Path(handle.name)

        try:
            hosts = parse_ssh_config(config_path)
        finally:
            config_path.unlink(missing_ok=True)

        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0].proxy_command, "ssh -W %h:%p bastion")
        self.assertEqual(hosts[0].address_family, "ipv6")

    def test_expand_proxy_command_supports_common_tokens(self) -> None:
        from core.ssh_config import expand_proxy_command

        expanded = expand_proxy_command(
            "ssh -l %r -W %h:%p jump %%done",
            host="srv.example",
            port=2222,
            username="alice",
        )
        self.assertEqual(expanded, "ssh -l alice -W srv.example:2222 jump %done")

    def test_expand_proxy_command_brackets_ipv6_in_dash_w(self) -> None:
        # OpenSSH requires [addr]:port notation for IPv6 in -W; expand
        # must wrap the colon-containing host in brackets.
        from core.ssh_config import expand_proxy_command
        out = expand_proxy_command(
            "ssh -W %h:%p bastion",
            host="2001:db8::1", port=22, username="u",
        )
        self.assertIn("[2001:db8::1]:22", out)

    def test_expand_proxy_command_ignores_trailing_percent(self) -> None:
        # Dangling %% at end leaves the literal % intact.
        from core.ssh_config import expand_proxy_command
        out = expand_proxy_command(
            "ssh %h %", host="h", port=22, username="u",
        )
        self.assertTrue(out.endswith(" %"))

    def test_expand_proxy_command_with_profile_resolver(self) -> None:
        # Bare alias at end of ssh command → resolver injects key+port.
        from core.ssh_config import expand_proxy_command
        from core.profiles import ConnectionProfile
        prof = ConnectionProfile(
            name="bastion", host="10.0.0.5", username="root",
            key_file="/k", port=2222,
        )
        def resolve(n):
            return prof if n == "bastion" else None
        out = expand_proxy_command(
            "ssh -W %h:%p bastion",
            host="t", port=22, username="u",
            resolve_profile=resolve,
        )
        self.assertIn("-i", out)
        self.assertIn("/k", out)
        self.assertIn("-p", out)
        self.assertIn("2222", out)

    def test_expand_proxy_command_resolver_leaves_flag_targets(self) -> None:
        # Target that starts with '-' (ie it's a flag, not an alias)
        # is left alone by the resolver.
        from core.ssh_config import expand_proxy_command
        out = expand_proxy_command(
            "ssh --help", host="t", port=22, username="u",
            resolve_profile=lambda n: None,
        )
        self.assertIn("--help", out)

    def test_expand_proxy_command_resolver_leaves_user_at_host(self) -> None:
        from core.ssh_config import expand_proxy_command
        out = expand_proxy_command(
            "ssh user@server", host="t", port=22, username="u",
            resolve_profile=lambda n: None,
        )
        self.assertIn("user@server", out)

    def test_expand_proxy_command_resolver_noop_when_profile_missing(self) -> None:
        from core.ssh_config import expand_proxy_command
        out = expand_proxy_command(
            "ssh unknown-alias", host="t", port=22, username="u",
            resolve_profile=lambda n: None,
        )
        self.assertIn("unknown-alias", out)

    def test_expand_proxy_command_non_ssh_command_is_passthrough(self) -> None:
        # First token isn't "ssh" → resolver returns original.
        from core.ssh_config import expand_proxy_command
        out = expand_proxy_command(
            "nc %h %p", host="h", port=22, username="u",
            resolve_profile=lambda n: None,
        )
        self.assertIn("nc h 22", out)

    def test_parse_ssh_config_missing_file_returns_empty(self) -> None:
        from core.ssh_config import parse_ssh_config
        self.assertEqual(parse_ssh_config(Path("/nope/does/not/exist")), [])

    def test_parse_ssh_config_swallows_read_oserror(self) -> None:
        # A file that raises on read (perm denied) → empty list, logged.
        from core.ssh_config import parse_ssh_config
        p = Path(tempfile.mkstemp(suffix=".sshconfig")[1])
        try:
            from unittest import mock as _mock
            with _mock.patch.object(
                Path, "read_text", side_effect=OSError("perm"),
            ):
                self.assertEqual(parse_ssh_config(p), [])
        finally:
            p.unlink(missing_ok=True)

    def test_parse_ssh_config_skips_wildcards_in_host(self) -> None:
        from core.ssh_config import parse_ssh_config
        with tempfile.NamedTemporaryFile("w", suffix=".sshconfig",
                                          delete=False) as h:
            h.write("Host *\n    User everyone\nHost real\n    User me\n")
            p = Path(h.name)
        try:
            hosts = parse_ssh_config(p)
            aliases = [x.alias for x in hosts]
            self.assertEqual(aliases, ["real"])
        finally:
            p.unlink(missing_ok=True)

    def test_parse_ssh_config_handles_addressfamily_inet(self) -> None:
        from core.ssh_config import parse_ssh_config
        with tempfile.NamedTemporaryFile("w", suffix=".sshconfig",
                                          delete=False) as h:
            h.write("Host v4only\n    AddressFamily inet\n")
            p = Path(h.name)
        try:
            hosts = parse_ssh_config(p)
            self.assertEqual(hosts[0].address_family, "ipv4")
        finally:
            p.unlink(missing_ok=True)

    def test_parse_ssh_config_ignores_bad_port(self) -> None:
        # Non-integer Port value is dropped (stays at default 22).
        from core.ssh_config import parse_ssh_config
        with tempfile.NamedTemporaryFile("w", suffix=".sshconfig",
                                          delete=False) as h:
            h.write("Host h\n    Port not-a-number\n")
            p = Path(h.name)
        try:
            hosts = parse_ssh_config(p)
            self.assertEqual(hosts[0].port, 22)
        finally:
            p.unlink(missing_ok=True)


class BundledScriptsTests(unittest.TestCase):
    """Smoke + end-to-end tests for resources/scripts/*.py — the
    20-something example scripts that ship with axross."""

    SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "resources" / "scripts"

    def _load_script(self, name: str) -> dict:
        """Compile + exec ``resources/scripts/<name>.py`` in a fresh
        namespace pre-populated with ``axross`` (the scripting module)
        and return the resulting namespace so tests can call the
        public helpers."""
        from core import scripting as _scripting
        path = self.SCRIPTS_DIR / f"{name}.py"
        src = path.read_text(encoding="utf-8")
        ns: dict = {
            "__name__": "__axross_script__",
            "__file__": str(path),
            "axross": _scripting,
        }
        exec(compile(src, str(path), "exec"), ns)
        return ns

    def test_every_script_imports_with_docstring(self) -> None:
        """Smoke test: each bundled script must compile, exec under a
        bare ``axross`` namespace, and expose at least one callable plus
        a module-level docstring."""
        scripts = sorted(p.stem for p in self.SCRIPTS_DIR.glob("*.py"))
        # Sanity: we shipped a healthy chunk. If this number drops
        # noticeably, someone deleted bundled scripts without telling
        # the docs.
        self.assertGreaterEqual(len(scripts), 20, scripts)
        for name in scripts:
            with self.subTest(script=name):
                ns = self._load_script(name)
                # Module-level docstring lives at __doc__ in the
                # namespace after exec().
                self.assertIn("__doc__", ns)
                self.assertTrue(ns["__doc__"], f"{name}: empty docstring")

    def test_du_against_localfs(self) -> None:
        ns = self._load_script("du")
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "small.txt").write_bytes(b"abc")
            sub = Path(tmp) / "deep"
            sub.mkdir()
            (sub / "big.bin").write_bytes(b"x" * 4096)
            from core import scripting as s
            sizes = ns["du"](s.localfs(), tmp)
            paths = {p: total for p, total in sizes}
            # Both directories appear; the deep dir owns the big file.
            self.assertEqual(paths[str(sub)], 4096)
            self.assertGreaterEqual(paths[tmp], 4096 + 3)

    def test_dedupe_finds_identical_files(self) -> None:
        ns = self._load_script("dedupe")
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "a.txt").write_bytes(b"hello")
            (Path(tmp) / "b.txt").write_bytes(b"hello")
            (Path(tmp) / "c.txt").write_bytes(b"different")
            from core import scripting as s
            dups = ns["find_duplicates"](s.localfs(), tmp)
            # Exactly one duplicate group, containing two paths.
            self.assertEqual(len(dups), 1)
            paths = next(iter(dups.values()))
            self.assertEqual(len(paths), 2)
            self.assertEqual({Path(p).name for p in paths}, {"a.txt", "b.txt"})

    def test_bulk_rename_dry_run_preserves_files(self) -> None:
        ns = self._load_script("bulk_rename")
        with tempfile.TemporaryDirectory() as tmp:
            files = ["raw_001.csv", "raw_002.csv", "stable.txt"]
            for f in files:
                (Path(tmp) / f).write_text("data")
            from core import scripting as s
            plan = ns["bulk_rename"](s.localfs(), tmp, r"^raw_", "trim_", dry_run=True)
            self.assertEqual(len(plan), 2)
            # Files must still be there with original names.
            self.assertTrue((Path(tmp) / "raw_001.csv").exists())

    def test_find_secrets_catches_aws_key(self) -> None:
        ns = self._load_script("find_secrets")
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "config").write_bytes(
                b"AKIAIOSFODNN7EXAMPLE\nrandom\n"
            )
            from core import scripting as s
            hits = ns["scan"](s.localfs(), tmp)
            self.assertTrue(any(h["rule"] == "aws_access_key" for h in hits))

    def test_fingerprint_diff_round_trip(self) -> None:
        ns = self._load_script("fingerprint_diff")
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "src"
            dst = Path(tmp) / "dst"
            src.mkdir()
            dst.mkdir()
            (src / "kept.txt").write_bytes(b"same")
            (dst / "kept.txt").write_bytes(b"same")
            (src / "only_src.txt").write_bytes(b"x")
            (dst / "only_dst.txt").write_bytes(b"x")
            (src / "changed.txt").write_bytes(b"v1")
            (dst / "changed.txt").write_bytes(b"v2")
            from core import scripting as s
            backend = s.localfs()
            diff = ns["compare"](backend, str(src), backend, str(dst))
            self.assertIn("only_dst.txt", diff["added"])
            self.assertIn("only_src.txt", diff["removed"])
            self.assertIn("changed.txt", diff["changed"])
            self.assertIn("kept.txt", diff["unchanged"])

    def test_sqlite_export_pack_round_trip(self) -> None:
        ns = self._load_script("sqlite_export")
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "src"
            src.mkdir()
            (src / "a.txt").write_bytes(b"alpha")
            (src / "deep").mkdir()
            (src / "deep" / "b.txt").write_bytes(b"beta")
            sqlite_path = str(Path(tmp) / "out.sqlite")
            from core import scripting as s
            report = ns["pack"](s.localfs(), str(src), sqlite_path)
            self.assertEqual(report["files"], 2)
            # Re-open the SQLite file and verify content.
            mounted = s.open_url(f"sqlite:///{sqlite_path}")
            try:
                self.assertEqual(s.read_bytes(mounted, "/a.txt"), b"alpha")
                self.assertEqual(s.read_bytes(mounted, "/deep/b.txt"), b"beta")
            finally:
                mounted.close()

    def test_redact_dry_run_lists_targets(self) -> None:
        ns = self._load_script("redact")
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "secret.env").write_bytes(b"SECRET=hunter2")
            (Path(tmp) / "readme.md").write_bytes(b"hi")
            from core import scripting as s
            affected = ns["redact"](
                s.localfs(), tmp, r"\.env$",
                passphrase="pw", commit=False,
            )
            self.assertEqual(len(affected), 1)
            self.assertTrue(affected[0].endswith("secret.env"))
            # commit=False ⇒ originals untouched.
            self.assertTrue((Path(tmp) / "secret.env").exists())

    def test_port_scan_finds_open_loopback_port(self) -> None:
        import socket
        ns = self._load_script("port_scan")
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        try:
            result = ns["scan"](
                ["127.0.0.1"], ports=[port, 1], timeout=0.3, workers=4,
            )
            self.assertIn(port, result["127.0.0.1"])
            self.assertNotIn(1, result["127.0.0.1"])
        finally:
            srv.close()

    def test_atomic_replace_round_trip(self) -> None:
        ns = self._load_script("atomic_replace")
        with tempfile.TemporaryDirectory() as tmp:
            from core import scripting as s
            backend = s.localfs()
            target = str(Path(tmp) / "config.txt")
            ns["rewrite"](backend, target, "first")
            self.assertEqual(s.read_text(backend, target), "first")
            ns["rewrite"](backend, target, "second")
            self.assertEqual(s.read_text(backend, target), "second")

    def test_encrypted_archive_pack_unpack(self) -> None:
        ns = self._load_script("encrypted_archive")
        with tempfile.TemporaryDirectory() as tmp:
            from core import scripting as s
            backend = s.localfs()
            src = Path(tmp) / "src"
            src.mkdir()
            (src / "a.txt").write_bytes(b"alpha")
            (src / "deep").mkdir()
            (src / "deep" / "b.txt").write_bytes(b"beta")
            sealed = str(Path(tmp) / "snap.tar.axenc")
            ns["pack"](backend, str(src), backend, sealed, "passphrase")
            self.assertTrue(Path(sealed).exists())
            out = Path(tmp) / "restored"
            n = ns["unpack"](backend, sealed, str(out), "passphrase")
            self.assertEqual(n, 2)
            self.assertEqual((out / "a.txt").read_bytes(), b"alpha")
            self.assertEqual((out / "deep" / "b.txt").read_bytes(), b"beta")

    def test_encrypted_archive_zip_slip_prefix_offbyone_refused(self) -> None:
        """A hostile tarball whose member sits in a SIBLING dir whose
        absolute path SHARES THE PREFIX of the destination
        (``/tmp/foo`` vs ``/tmp/foobar``) must NOT be extracted —
        otherwise the simple ``startswith`` check the previous
        revision used would silently leak into the sibling."""
        import io
        import tarfile
        ns = self._load_script("encrypted_archive")
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "foo"
            sibling = Path(tmp) / "foobar"
            base.mkdir()
            sibling.mkdir()
            # Build a tarball whose member's absolute path lands in
            # the sibling. We construct it by hand because pack() in
            # the script never produces such a member; this is what a
            # malicious archive would look like.
            buf = io.BytesIO()
            with tarfile.open(mode="w", fileobj=buf) as tar:
                payload = b"injected"
                info = tarfile.TarInfo(name="../foobar/escaped.txt")
                info.size = len(payload)
                tar.addfile(info, io.BytesIO(payload))
            from core.encrypted_overlay import encrypt_bytes
            sealed_path = str(Path(tmp) / "evil.tar.axenc")
            with open(sealed_path, "wb") as fh:
                fh.write(encrypt_bytes(buf.getvalue(), "pw"))
            from core import scripting as s
            backend = s.localfs()
            n = ns["unpack"](backend, sealed_path, str(base), "pw")
            self.assertEqual(n, 0, "zip-slip member should have been refused")
            # Sibling must still be empty.
            self.assertEqual(list(sibling.iterdir()), [])

    def test_encrypted_stream_round_trip(self) -> None:
        ns = self._load_script("encrypted_stream")
        with tempfile.TemporaryDirectory() as tmp:
            from core import scripting as s
            backend = s.localfs()
            src = str(Path(tmp) / "in.bin")
            sealed = str(Path(tmp) / "out.axenc")
            restored = str(Path(tmp) / "restored.bin")
            payload = b"x" * (300 * 1024)  # bigger than one frame
            Path(src).write_bytes(payload)
            ns["seal_stream"](
                backend, src, backend, sealed, "passphrase",
                frame_size=128 * 1024,
            )
            ns["unseal_stream"](
                backend, sealed, backend, restored, "passphrase",
            )
            self.assertEqual(Path(restored).read_bytes(), payload)

    def test_backend_capabilities_matrix(self) -> None:
        ns = self._load_script("backend_capabilities")
        text = ns["matrix"]()
        # Every protocol id we register must appear in the table.
        from core import backend_registry
        backend_registry.init_registry()
        for info in backend_registry.all_backends():
            self.assertIn(info.protocol_id, text)

    def test_mirror_skips_matching_files(self) -> None:
        """End-to-end mirror against two LocalFS dirs."""
        ns = self._load_script("mirror")
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "src"
            dst = Path(tmp) / "dst"
            src.mkdir()
            dst.mkdir()
            (src / "a.txt").write_bytes(b"hello")
            (src / "deep").mkdir()
            (src / "deep" / "b.txt").write_bytes(b"world")
            from core import scripting as s
            backend = s.localfs()
            r1 = ns["main"](backend, str(src), backend, str(dst))
            self.assertEqual(r1["copied"], 2)
            self.assertEqual(r1["skipped"], 0)
            # Re-mirror — both files match by hash, nothing copied.
            r2 = ns["main"](backend, str(src), backend, str(dst))
            self.assertEqual(r2["copied"], 0)
            self.assertEqual(r2["skipped"], 2)

    def test_ramfs_decrypt_round_trip(self) -> None:
        """End-to-end: encrypt a file on disk, decrypt via the script
        into RamFS, read the plaintext back from RAM."""
        ns = self._load_script("ramfs_decrypt")
        with tempfile.TemporaryDirectory() as tmp:
            from core import scripting as s
            backend = s.localfs()
            src = str(Path(tmp) / "secret.txt")
            Path(src).write_bytes(b"the eagle has landed")
            enc_path = s.encrypt(backend, src, "passphrase-abc")
            ram, mounted = ns["decrypt_to_ram"](backend, enc_path, "passphrase-abc")
            try:
                payload = s.read_bytes(ram, mounted)
                self.assertEqual(payload, b"the eagle has landed")
            finally:
                ram.close()

    def test_s3_inventory_walks_localfs(self) -> None:
        """The script is S3-themed but works against any FileBackend
        — exercise it on LocalFS so the test doesn't need MinIO up."""
        ns = self._load_script("s3_inventory")
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "a.log").write_bytes(b"x" * 10)
            (Path(tmp) / "b.log").write_bytes(b"x" * 5)
            (Path(tmp) / "deep").mkdir()
            (Path(tmp) / "deep" / "c.json").write_bytes(b"{}")
            from core import scripting as s
            report = ns["inventory"](s.localfs(), tmp, top_n=5)
            self.assertEqual(report["object_count"], 3)
            self.assertEqual(report["total_bytes"], 17)
            # Largest is a.log (10 bytes).
            self.assertTrue(report["top_largest"][0][0].endswith("a.log"))
            self.assertEqual(report["extension_histogram"]["log"], 2)
            self.assertEqual(report["extension_histogram"]["json"], 1)

    def test_bookmarks_export_round_trip(self) -> None:
        """Save → JSON → re-import. Uses an HOME-isolated bookmarks
        store so the user's real bookmarks aren't touched."""
        ns = self._load_script("bookmarks_export")
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {"HOME": tmp}):
                from core import scripting as s
                # Pre-seed two bookmarks.
                s.add_bookmark(name="logs", path="/var/log",
                               backend_name="Local")
                s.add_bookmark(name="etc", path="/etc",
                               backend_name="Local")
                json_path = str(Path(tmp) / "bms.json")
                count = ns["write_json"](json_path)
                self.assertEqual(count, 2)
                self.assertTrue(Path(json_path).exists())
                # Wipe + re-import.
                from core.bookmarks import BookmarkManager
                mgr = BookmarkManager()
                while mgr._bookmarks:  # noqa: SLF001
                    mgr._bookmarks.pop()  # noqa: SLF001
                mgr.save()
                imported = ns["import_json"](json_path)
                self.assertEqual(imported, 2)
                names = sorted(b.name for b in s.list_bookmarks())
                self.assertEqual(names, ["etc", "logs"])

    def test_git_changelog_walks_branch_history(self) -> None:
        """End-to-end against a fresh local bare repo: write three
        commits via Git-FS, then ask the script for the changelog."""
        try:
            from dulwich.repo import Repo
        except ImportError:
            self.skipTest("dulwich not installed")
        ns = self._load_script("git_changelog")
        with tempfile.TemporaryDirectory() as tmp:
            from core.git_fs_client import GitFsSession
            Repo.init_bare(str(Path(tmp) / "r.git"), mkdir=True)
            sess = GitFsSession(
                path=str(Path(tmp) / "r.git"),
                author_name="T", author_email="t@x",
            )
            for n in ("first", "second", "third"):
                with sess.open_write(f"/main/{n}.txt") as fh:
                    fh.write(n.encode())
            log = ns["changelog"](sess, "main", limit=10)
            self.assertEqual(len(log), 3)
            # Newest first — last write was "third.txt".
            self.assertIn("third.txt", log[0])

    def test_gopher_archive_against_inproc_server(self) -> None:
        """Spin up a tiny in-process Gopher server, archive its
        contents, verify files land on disk."""
        ns = self._load_script("gopher_archive")
        # Reuse the in-process Gopher server helper from
        # GopherBackendTests — same shape, just bypass the
        # @staticmethod descriptor by calling the wrapped function.
        menu_factory = lambda sel: {  # noqa: E731
            "":          (b"0readme.txt\t/readme.txt\texample\t70\r\n"
                          b"1docs\t/docs\texample\t70\r\n.\r\n"),
            "/readme.txt": b"top-level readme",
            "/docs":     b"0intro.txt\t/docs/intro.txt\texample\t70\r\n.\r\n",
            "/docs/intro.txt": b"intro content",
        }.get(sel, b"")
        host, port, stop = GopherBackendTests._start_server(menu_factory)
        try:
            with tempfile.TemporaryDirectory() as tmp:
                # Patch the SSRF-deny so the loopback target works.
                with mock.patch.dict(os.environ, {"AXROSS_ALLOW_PRIVATE_PROXY": "1"}):
                    report = ns["archive"](
                        f"gopher://{host}:{port}/",
                        str(Path(tmp) / "mirror"),
                    )
                self.assertEqual(report["fetched"], 2)
                self.assertTrue(
                    (Path(tmp) / "mirror" / "readme.txt").exists()
                )
        finally:
            stop()

    def test_hash_audit_detects_mismatch_and_missing(self) -> None:
        ns = self._load_script("hash_audit")
        from core import scripting as s
        backend = s.localfs()
        with tempfile.TemporaryDirectory() as tmp:
            # Create the backend tree.
            (Path(tmp) / "ok.txt").write_bytes(b"good")
            (Path(tmp) / "bad.txt").write_bytes(b"actual")
            # Build a manifest: one valid hash, one wrong, one missing.
            import hashlib
            ok_hash = hashlib.sha256(b"good").hexdigest()
            wrong_hash = "0" * 64
            manifest = (
                f"{ok_hash}\tok.txt\n"
                f"{wrong_hash}\tbad.txt\n"
                f"{wrong_hash}\tabsent.txt\n"
            )
            manifest_path = str(Path(tmp) / "manifest.sha256")
            Path(manifest_path).write_text(manifest)
            report = ns["audit"](manifest_path, backend, tmp)
            self.assertEqual(set(report["ok"]), {"ok.txt"})
            self.assertEqual([m["path"] for m in report["mismatch"]], ["bad.txt"])
            self.assertEqual(set(report["missing"]), {"absent.txt"})


class ScriptingReferenceQualityTests(unittest.TestCase):
    """Catch docstring rot before a function ships with one-line
    summaries that the doc-pane renders as ``(no docstring)``."""

    MIN_DOCSTRING_CHARS = 40  # "Read a whole file into memory." == 30

    def test_every_public_function_has_a_meaningful_docstring(self) -> None:
        from core import scripting as s
        too_short: list[tuple[str, int]] = []
        missing: list[str] = []
        for name in s.__all__:
            fn = getattr(s, name, None)
            if fn is None:
                missing.append(name)
                continue
            doc = (fn.__doc__ or "").strip()
            if not doc:
                missing.append(name)
                continue
            if len(doc) < self.MIN_DOCSTRING_CHARS:
                too_short.append((name, len(doc)))
        self.assertFalse(missing, f"missing docstrings: {missing}")
        self.assertFalse(
            too_short,
            f"docstrings shorter than {self.MIN_DOCSTRING_CHARS} chars: "
            f"{too_short}",
        )

    def test_docs_returns_complete_markdown(self) -> None:
        """``axross.docs()`` must produce the four-section reference
        with every function from __all__ accounted for."""
        from core import scripting as s
        md = s.docs()
        # Every public function name should appear at least once.
        for name in s.__all__:
            self.assertIn(f"axross.{name}", md, name)
        # Each top-level section header is present.
        for header in ("REPL slash-commands",
                       "Bundled example scripts",
                       "FileBackend` protocol"):
            self.assertIn(header, md, f"missing section: {header}")

    def test_docs_handles_unknown_topic_loudly(self) -> None:
        from core import scripting as s
        with self.assertRaises(KeyError):
            s.docs("does-not-exist")
        with self.assertRaises(KeyError):
            s.docs("_help_entries")  # private — refused

    def test_docs_for_single_function_round_trips(self) -> None:
        from core import scripting as s
        block = s.docs("checksum")
        self.assertIn("axross.checksum", block)
        self.assertIn("Return", block)


class ScriptingExpansionTests(unittest.TestCase):
    """The expanded scripting surface (round 4)."""

    def test_help_topics_cover_all_public_names(self) -> None:
        """Every name in __all__ should land in some _HELP_GROUPS
        bucket, otherwise help() is incomplete."""
        from core import scripting as s
        listed = set()
        for _, names in s._HELP_GROUPS:
            listed.update(names)
        # The "Other" bucket auto-collects leftovers; we still want
        # an explicit grouping for everything user-facing so help()
        # output reads sensibly.
        leftovers = [n for n in s.__all__ if n not in listed]
        self.assertEqual(
            leftovers, [],
            f"Functions in __all__ but not in _HELP_GROUPS: {leftovers}",
        )

    def test_hash_round_trip(self) -> None:
        from core import scripting as s
        b = s.localfs()
        with tempfile.NamedTemporaryFile(delete=False) as h:
            h.write(b"axross-hash")
            p = h.name
        try:
            sha = s.hash_file(b, p, "sha256")
            self.assertEqual(sha, s.hash_bytes(b"axross-hash", "sha256"))
        finally:
            os.unlink(p)

    def test_dns_resolve_localhost(self) -> None:
        from core import scripting as s
        ips = s.dns_resolve("localhost", family="any")
        # Either ::1 or 127.0.0.1 — depends on /etc/hosts but at least
        # ONE entry must come back on any sane machine.
        self.assertTrue(ips, "expected localhost to resolve to at least one IP")

    def test_port_open_loopback(self) -> None:
        import socket
        from core import scripting as s
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        try:
            self.assertTrue(s.port_open("127.0.0.1", port, timeout=1.0))
            self.assertFalse(s.port_open("127.0.0.1", 1, timeout=0.2))
        finally:
            srv.close()


class ScriptDirectoryTests(unittest.TestCase):
    """The save/load/run script-directory machinery."""

    def setUp(self) -> None:
        # Reroute HOME so we don't touch the user's real
        # ~/.config/axross/scripts during the test.
        self.tmp_home = tempfile.mkdtemp(prefix="axross-script-test-")
        self._patch_home = mock.patch.dict(os.environ, {"HOME": self.tmp_home})
        self._patch_home.start()

    def tearDown(self) -> None:
        self._patch_home.stop()
        import shutil
        shutil.rmtree(self.tmp_home, ignore_errors=True)

    def test_save_load_run_round_trip(self) -> None:
        from core import scripting as s
        path = s.save_script("hello", "result = 42\n")
        self.assertTrue(path.endswith("hello.py"))
        # Mode 0o600 — never world-readable.
        mode = os.stat(path).st_mode & 0o777
        self.assertEqual(mode, 0o600, f"got {oct(mode)}")
        self.assertEqual(s.load_script("hello"), "result = 42\n")
        self.assertIn("hello", s.list_scripts())
        ns = s.run_script("hello")
        self.assertEqual(ns["result"], 42)
        s.delete_script("hello")
        self.assertNotIn("hello", s.list_scripts())

    def test_invalid_script_name_refused(self) -> None:
        from core import scripting as s
        for bad in ("../etc/passwd", "with space", "evil/", "weird;rm"):
            with self.assertRaises(ValueError):
                s.save_script(bad, "x = 1")


class CiscoTelnetParsingTests(unittest.TestCase):
    """Pure-parser tests for the Cisco-Telnet helper — no live device."""

    def test_strip_trailing_prompt(self) -> None:
        from core.telnet_cisco import _strip_trailing_prompt
        text = (
            "Building configuration...\n"
            "version 15.1\n"
            "\n"
            "Router# "
        )
        out = _strip_trailing_prompt(text)
        self.assertIn("version 15.1", out)
        self.assertNotIn("Router#", out)

    def test_safe_show_subcmd_allow_list(self) -> None:
        from core.telnet_cisco import _safe_show_subcmd
        self.assertEqual(_safe_show_subcmd("ip-route.txt"), "ip route")
        self.assertEqual(_safe_show_subcmd("running-config.txt"), "running config")
        with self.assertRaises(OSError):
            _safe_show_subcmd("ip; show running-config")
        with self.assertRaises(OSError):
            _safe_show_subcmd("|cat /etc/passwd")


class LayoutPresetSpecTests(unittest.TestCase):
    """The preset DSL is small enough to verify by static inspection
    instead of building real Qt widgets."""

    def test_preset_order_covers_every_named_preset(self) -> None:
        from ui.layout_presets import PRESET_ORDER, PRESETS
        self.assertEqual(set(PRESET_ORDER), set(PRESETS))

    def test_known_presets_have_valid_node_kinds(self) -> None:
        """Every leaf is either ('file', None) or ('term', <profile>);
        every split node has two-or-more children. Catches typos in
        the DSL without needing Qt."""
        from ui.layout_presets import PRESETS

        def _walk(node):
            kind, payload = node
            if kind in ("hsplit", "vsplit"):
                self.assertIsInstance(payload, list)
                self.assertGreaterEqual(len(payload), 2)
                for child in payload:
                    _walk(child)
            elif kind == "file":
                self.assertIsNone(payload)
            elif kind == "term":
                self.assertIsInstance(payload, str)
            else:
                self.fail(f"unknown preset node kind: {kind!r}")

        for name, spec in PRESETS.items():
            with self.subTest(preset=name):
                _walk(spec)


class RshBackendTests(unittest.TestCase):
    """rsh / rcp backend unit tests. Subprocess-mocked so we don't
    need an actual rsh-client binary on the test host."""

    def _make_session(self):
        from core.rsh_client import RshSession
        sess = RshSession.__new__(RshSession)
        sess._host = "rshserver"
        sess._port = 514
        sess._username = "axuser"
        sess._timeout = 10.0
        sess._rsh = "/usr/bin/rsh"
        return sess

    def _patch_runner(self, recorded: list[str], stdout: bytes = b"axross-rsh-probe\n"):
        """Patch ``subprocess.run`` so we can capture the rsh
        invocations and feed canned stdout."""
        def fake_run(argv, *, input=None, capture_output, timeout, check):
            recorded.append(" ".join(argv))
            class _R:
                returncode = 0
                stderr = b""
            _R.stdout = stdout
            return _R
        return mock.patch("core.rsh_client.subprocess.run", side_effect=fake_run)

    def test_list_dir_parses_ls_output(self) -> None:
        sess = self._make_session()
        ls_output = (
            b"total 8\n"
            b"drwxr-xr-x  2 axuser axuser 4096 Jan 01 12:00 .\n"
            b"drwxr-xr-x  3 root   root   4096 Jan 01 12:00 ..\n"
            b"-rw-r--r--  1 axuser axuser   42 Jan 01 12:00 hello.txt\n"
            b"drwxr-xr-x  2 axuser axuser 4096 Jan 01 12:00 subdir\n"
        )
        recorded: list[str] = []
        with self._patch_runner(recorded, stdout=ls_output):
            items = sess.list_dir("/home/axuser")
        self.assertEqual(
            sorted((i.name, i.is_dir, i.size) for i in items),
            [("hello.txt", False, 42), ("subdir", True, 4096)],
        )
        # rsh argv ought to include host + the quoted path.
        self.assertTrue(any("/home/axuser" in cmd for cmd in recorded))

    def test_path_validation_refuses_crlf_smuggling(self) -> None:
        from core.rsh_client import _validate_path
        with self.assertRaises(OSError):
            _validate_path("/foo\nbar")
        with self.assertRaises(OSError):
            _validate_path("/foo\rbar")
        with self.assertRaises(OSError):
            _validate_path("/foo\x00bar")

    def test_open_read_uses_head_c_cap(self) -> None:
        sess = self._make_session()
        recorded: list[str] = []
        with self._patch_runner(recorded, stdout=b"file payload"):
            sess.open_read("/etc/motd")
        # The head -c <cap> guard must appear in the rsh command line.
        self.assertTrue(any("head -c" in cmd for cmd in recorded), recorded)

    def test_perms_to_octal(self) -> None:
        from core.rsh_client import _perms_to_octal
        self.assertEqual(_perms_to_octal("-rw-r--r--"), 0o644)
        self.assertEqual(_perms_to_octal("drwxr-xr-x"), 0o755)
        self.assertEqual(_perms_to_octal("-rwx------"), 0o700)


class GitFsBackendTests(unittest.TestCase):
    """Unit tests for the dulwich-backed Git FileBackend."""

    def setUp(self) -> None:
        try:
            import dulwich  # noqa: F401
            from dulwich.repo import Repo  # noqa: F401
        except ImportError:
            self.skipTest("dulwich not installed")
        self.tmp = Path(tempfile.mkdtemp(prefix="axross-gitfs-"))

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _new_session(self):
        from core.git_fs_client import GitFsSession
        from dulwich.repo import Repo
        repo_path = self.tmp / "repo.git"
        Repo.init_bare(str(repo_path), mkdir=True)
        return GitFsSession(
            path=str(repo_path),
            author_name="Tester",
            author_email="tester@example.com",
        )

    def test_first_write_creates_branch_and_commits(self) -> None:
        s = self._new_session()
        self.assertEqual(s.list_dir("/"), [])
        with s.open_write("/main/hello.txt") as fh:
            fh.write(b"hi")
        names = sorted(i.name for i in s.list_dir("/"))
        self.assertIn("main", names)
        self.assertEqual(
            sorted(i.name for i in s.list_dir("/main")),
            ["hello.txt"],
        )
        self.assertEqual(s.open_read("/main/hello.txt").read(), b"hi")

    def test_rename_copy_remove_round_trip(self) -> None:
        s = self._new_session()
        with s.open_write("/main/a.txt") as fh:
            fh.write(b"alpha")
        s.rename("/main/a.txt", "/main/b.txt")
        self.assertEqual(s.open_read("/main/b.txt").read(), b"alpha")
        s.copy("/main/b.txt", "/main/sub/c.txt")
        self.assertEqual(s.open_read("/main/sub/c.txt").read(), b"alpha")
        s.remove("/main/sub/c.txt")
        # Git doesn't track empty dirs — once the only file goes, the
        # parent disappears too. list_dir on a path that no longer
        # exists raises (matches every other backend's behaviour).
        with self.assertRaises(OSError):
            s.list_dir("/main/sub")

    def test_commit_refused_without_author_identity(self) -> None:
        from core.git_fs_client import GitFsSession
        from dulwich.repo import Repo
        repo_path = self.tmp / "noauthor.git"
        Repo.init_bare(str(repo_path), mkdir=True)
        # Construct without identity — also override git-config probe
        # so the empty result holds.
        s = GitFsSession(path=str(repo_path))
        s._author_name = ""
        s._author_email = ""
        with self.assertRaises(OSError):
            with s.open_write("/main/hello.txt") as fh:
                fh.write(b"x")

    def test_checksum_returns_git_blob_sha(self) -> None:
        s = self._new_session()
        with s.open_write("/main/x.txt") as fh:
            fh.write(b"axross")
        cs = s.checksum("/main/x.txt")
        self.assertTrue(cs.startswith("git:"), cs)
        self.assertEqual(len(cs), len("git:") + 40)

    def test_commit_refused_when_local_behind_origin(self) -> None:
        """Fast-forward guard: when origin/<branch> is ahead of the
        local tip, axross refuses to commit on top of stale state.

        Setup: commit A on main (locally), then synthesise an origin
        ref pointing at a commit B whose parent is A (origin is
        ahead). The next axross commit must raise GitForceRefused
        rather than silently rewriting history."""
        from datetime import datetime as _dt

        from dulwich.objects import Blob, Commit, Tree

        from core.git_fs_client import GitForceRefused
        s = self._new_session()
        # First commit lays down /main/start.txt → tip A.
        with s.open_write("/main/start.txt") as fh:
            fh.write(b"A")
        tip_a = s._branch_tips["main"]

        # Synthesise commit B (parent=A) directly via dulwich and put
        # it under refs/remotes/origin/main so the FF guard sees it
        # as "origin is ahead of local".
        repo = s._repo
        new_blob = Blob.from_string(b"B-from-origin")
        repo.object_store.add_object(new_blob)
        new_tree = Tree()
        new_tree.add(b"start.txt", 0o100644, new_blob.id)
        repo.object_store.add_object(new_tree)
        commit_b = Commit()
        commit_b.tree = new_tree.id
        commit_b.parents = [tip_a]
        commit_b.author = commit_b.committer = b"Origin <origin@example.com>"
        ts = int(_dt.now().timestamp())
        commit_b.author_time = commit_b.commit_time = ts
        commit_b.author_timezone = commit_b.commit_timezone = 0
        commit_b.encoding = b"UTF-8"
        commit_b.message = b"divergent commit on origin"
        repo.object_store.add_object(commit_b)
        repo.refs[b"refs/remotes/origin/main"] = commit_b.id
        # Refresh the cache so the next commit sees the new origin ref.
        s._refresh_branch_tips()
        # Re-pin local tip to A (refresh prefers refs/heads when present;
        # we want the test to keep local at A so the FF guard fires).
        s._branch_tips["main"] = tip_a

        with self.assertRaises(GitForceRefused):
            with s.open_write("/main/start.txt") as fh:
                fh.write(b"local change")


class PjlSafetyProbeTests(unittest.TestCase):
    """The PJL session MUST NOT send commands until a sane PJL reply
    confirms the device speaks the protocol."""

    @staticmethod
    def _start_server(payload: bytes):
        import socket
        import threading
        from core.pjl_client import UEL

        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(8)
        srv.settimeout(0.2)
        port = srv.getsockname()[1]
        stop = threading.Event()

        def loop():
            while not stop.is_set():
                try:
                    c, _ = srv.accept()
                except socket.timeout:
                    continue
                except OSError:
                    return
                try:
                    buf = b""
                    # Wait until both UEL frames arrived (start + end).
                    while buf.count(UEL) < 2:
                        try:
                            chunk = c.recv(4096)
                        except socket.timeout:
                            break
                        if not chunk:
                            break
                        buf += chunk
                    c.sendall(payload)
                finally:
                    c.close()

        threading.Thread(target=loop, daemon=True).start()

        def _stop():
            stop.set()
            srv.close()

        return "127.0.0.1", port, _stop

    def test_safety_probe_accepts_well_formed_pjl_reply(self) -> None:
        from core.pjl_client import PjlSession, UEL
        ok = (UEL + b"@PJL INFO ID\nMODEL=Test Printer\n"
              b"@PJL INFO STATUS\nCODE=10001\nDISPLAY=\"READY\"\nONLINE=TRUE\n" + UEL)
        host, port, stop = self._start_server(ok)
        try:
            sess = PjlSession(host=host, port=port)
            self.assertTrue(sess._safety_probed)
            self.assertIn("READY", sess._device_id)
        finally:
            stop()

    def test_safety_probe_refuses_silent_server(self) -> None:
        from core.pjl_client import PjlSession, PjlNotSupported
        host, port, stop = self._start_server(b"")
        try:
            with self.assertRaises(PjlNotSupported):
                PjlSession(host=host, port=port)
        finally:
            stop()

    def test_safety_probe_refuses_non_pjl_response(self) -> None:
        from core.pjl_client import PjlSession, PjlNotSupported
        host, port, stop = self._start_server(b"NOT PJL HERE\nplain text\n")
        try:
            with self.assertRaises(PjlNotSupported):
                PjlSession(host=host, port=port)
        finally:
            stop()


class SlpBackendSafetyTests(unittest.TestCase):
    """SLP backend must refuse multicast and SrvReg-style writes."""

    def test_multicast_targets_are_refused(self) -> None:
        from core.slp_lib import query_udp
        # 239.255.255.253 is the SLP DA discovery group; we hard-refuse.
        with self.assertRaises(OSError):
            query_udp("239.255.255.253", b"\x00")
        with self.assertRaises(OSError):
            query_udp("224.0.0.1", b"\x00")

    def test_writes_raise_with_cve_reference(self) -> None:
        from core.slp_client import SlpSession
        s = SlpSession.__new__(SlpSession)
        # Skip __init__ — we're testing the write surface, not connect.
        for op in (
            lambda: s.open_write("/x"),
            lambda: s.mkdir("/x"),
            lambda: s.remove("/x"),
            lambda: s.rename("/a", "/b"),
            lambda: s.chmod("/x", 0o755),
            lambda: s.copy("/a", "/b"),
        ):
            with self.assertRaises(OSError):
                op()

    def test_packet_builders_never_emit_srvreg(self) -> None:
        """Static-grep guarantee: no code path in slp_lib can emit a
        SrvReg (function-id 3) packet — even if a future caller asks."""
        import core.slp_lib as L
        src = Path(L.__file__).read_text()
        # The amplification CVE needs SrvReg (fn=0x03). Make sure we
        # neither define nor reference that constant in the lib.
        self.assertNotIn("SRV_REG", src.upper())
        self.assertNotIn("0x03", src)


class NntpLibTests(unittest.TestCase):
    """Wire-protocol coverage for the self-hosted NNTP lib (replaces
    stdlib nntplib, removed in Python 3.13)."""

    @staticmethod
    def _fake_server(scripted: dict[str, bytes]):
        """Start a fake NNTP server. ``scripted`` maps an upper-case
        command prefix → response bytes. Special keys: ``__greeting__``."""
        import socket
        import threading

        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(8)
        srv.settimeout(0.2)
        port = srv.getsockname()[1]
        stop = threading.Event()

        def loop():
            while not stop.is_set():
                try:
                    c, _ = srv.accept()
                except socket.timeout:
                    continue
                except OSError:
                    return
                try:
                    c.sendall(scripted.get("__greeting__", b"200 ok\r\n"))
                    f = c.makefile("rb", 0)
                    while True:
                        line = f.readline()
                        if not line:
                            break
                        cmd = line.decode("utf-8", "replace").strip().upper()
                        for prefix, body in scripted.items():
                            if prefix.startswith("__"):
                                continue
                            if cmd.startswith(prefix):
                                c.sendall(body)
                                break
                        else:
                            c.sendall(b"500 unknown\r\n")
                        if cmd == "QUIT":
                            break
                finally:
                    c.close()

        threading.Thread(target=loop, daemon=True).start()
        return "127.0.0.1", port, lambda: (stop.set(), srv.close())

    def test_greeting_capabilities_and_group_select(self) -> None:
        from core.nntp_lib import NntpClient

        host, port, stop = self._fake_server({
            "__greeting__": b"200 mock NNTP ready\r\n",
            "CAPABILITIES": b"101 caps\r\nVERSION 2\r\nREADER\r\n.\r\n",
            "MODE READER": b"200 ok\r\n",
            "LIST ACTIVE": b"215 active\r\nalt.test 50 1 y\r\nde.alt 100 1 m\r\n.\r\n",
            "GROUP": b"211 50 1 50 alt.test\r\n",
            "OVER": b"224 over\r\n"
                     b"1\tHello\tu@x\tMon, 01 Jan 2024 00:00:00 GMT\t<a@x>\t\t128\t10\r\n"
                     b".\r\n",
            "ARTICLE": b"220 1 art\r\nSubject: hi\r\n\r\nbody\r\n..stuff\r\n.\r\n",
            "QUIT": b"205 bye\r\n",
        })
        try:
            client = NntpClient(host=host, port=port, use_tls=False)
            self.assertIn("READER", client.capabilities())
            client.mode_reader()
            groups = list(client.list_groups())
            self.assertEqual(groups[0][0], "alt.test")
            count, low, high = client.select_group("alt.test")
            self.assertEqual((count, low, high), (50, 1, 50))
            recs = list(client.over(1, 1))
            self.assertEqual(recs[0]["subject"], "Hello")
            self.assertEqual(recs[0]["bytes"], 128)
            art = client.article(1)
            # Dot-unstuffing: "..stuff" must arrive as ".stuff"
            self.assertIn(b".stuff", art)
            self.assertNotIn(b"..stuff", art)
            client.quit()
        finally:
            stop()

    def test_authinfo_warns_on_plaintext(self) -> None:
        from core.nntp_lib import NntpClient

        host, port, stop = self._fake_server({
            "__greeting__": b"200 ready\r\n",
            "AUTHINFO USER": b"381 want pw\r\n",
            "AUTHINFO PASS": b"281 ok\r\n",
            "QUIT": b"205\r\n",
        })
        try:
            client = NntpClient(host=host, port=port, use_tls=False)
            with self.assertLogs("core.nntp_lib", level="WARNING") as logs:
                client.authinfo("alice", "secret")
            self.assertTrue(any("plaintext" in m.lower() for m in logs.output))
            client.quit()
        finally:
            stop()


class SqliteFsBackendTests(unittest.TestCase):
    """Round-trip the FileBackend surface against a real SQLite file."""

    def _new_backend(self):
        from core.sqlite_fs_client import SqliteFsSession
        with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as h:
            p = h.name
        os.unlink(p)
        return SqliteFsSession(url=p), p

    def test_full_lifecycle(self) -> None:
        b, p = self._new_backend()
        try:
            self.assertEqual(b.list_dir("/"), [])
            b.mkdir("/dir")
            with b.open_write("/dir/file.txt") as fh:
                fh.write(b"axross-fs")
            with b.open_write("/dir/file.txt", append=True) as fh:
                fh.write(b"-appended")
            self.assertEqual(
                b.open_read("/dir/file.txt").read(),
                b"axross-fs-appended",
            )
            b.rename("/dir/file.txt", "/dir/renamed.txt")
            kids = sorted(i.name for i in b.list_dir("/dir"))
            self.assertEqual(kids, ["renamed.txt"])
            b.copy("/dir/renamed.txt", "/dir/copy.txt")
            self.assertEqual(
                b.open_read("/dir/copy.txt").read(),
                b"axross-fs-appended",
            )
            b.chmod("/dir/copy.txt", 0o600)
            self.assertEqual(b.stat("/dir/copy.txt").permissions, 0o600)
            with self.assertRaises(OSError):
                # Refuse to remove a non-empty directory without recursive
                b.remove("/dir")
            b.remove("/dir", recursive=True)
            self.assertEqual(b.list_dir("/"), [])
        finally:
            b.close()
            try:
                os.unlink(p)
            except OSError:
                pass


class ScriptingApiTests(unittest.TestCase):
    """The curated axross.* surface used by the REPL + --script mode."""

    def test_help_lists_every_documented_function(self) -> None:
        """``axross.help()`` is the canonical cheat-sheet; if a public
        function gets added without a help entry, this catches it."""
        import io
        import contextlib
        from core import scripting

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            scripting.help()
        text = buf.getvalue()
        for fn in scripting.__all__:
            if fn == "help":
                continue
            self.assertIn(fn, text, f"axross.help() forgot {fn!r}")

    def test_localfs_round_trip_via_scripting(self) -> None:
        """Most user scripts will read/write a few files through the
        curated wrappers — sanity-check the round-trip on LocalFS."""
        from core import scripting
        b = scripting.localfs()
        with tempfile.NamedTemporaryFile(delete=False) as h:
            p = h.name
        try:
            scripting.write_text(b, p, "axross")
            self.assertEqual(scripting.read_text(b, p), "axross")
            cs = scripting.checksum(b, p, "sha256")
            self.assertTrue(cs.startswith("sha256:"))
        finally:
            os.unlink(p)

    def test_open_url_rejects_unknown_scheme(self) -> None:
        from core import scripting
        with self.assertRaises(ValueError):
            scripting.open_url("notarealproto://host/path")


class TftpFindFilesTests(unittest.TestCase):
    """Wordlist-driven probe of TFTP servers."""

    def _make_session(self):
        # Bypass __init__ — TFTP probe needs no socket here.
        from core.tftp_client import TftpSession
        s = TftpSession.__new__(TftpSession)
        s._host = "127.0.0.1"
        s._port = 69
        s._max_size_bytes = 16 * 1024 * 1024
        s._timeout = 0.5
        s._retries = 1
        s._filelist = []
        s._filelist_enabled = False
        s._find_cache = {}
        return s

    def test_find_files_records_hits_and_skips_misses(self) -> None:
        s = self._make_session()
        wordlist = ["config.text", "running-config", "missing.bin", "boot.ini"]

        def fake_probe(self, name: str) -> int:
            return {"config.text": 1024, "boot.ini": 4096}.get(name, 0)

        with mock.patch(
            "core.tftp_client.TftpSession._probe_size",
            new=fake_probe,
        ):
            hits = s.find_files(wordlist=wordlist)

        self.assertEqual(sorted(h.name for h in hits), ["boot.ini", "config.text"])
        self.assertEqual({h.name: h.size for h in hits}, {"boot.ini": 4096, "config.text": 1024})
        # Cache picks up only the hits.
        self.assertEqual(set(s._find_cache.keys()), {"boot.ini", "config.text"})

    def test_find_cache_is_bounded_by_limit(self) -> None:
        from core.tftp_client import TftpSession
        s = self._make_session()
        s.FIND_CACHE_LIMIT = 3  # type: ignore[attr-defined]
        for i, name in enumerate(["a", "b", "c", "d", "e"]):
            s._record_find_hit(name, i + 1)
        # Oldest dropped first; latest 3 retained.
        self.assertEqual(list(s._find_cache.keys()), ["c", "d", "e"])

    def test_load_wordlist_drops_comments_and_blanks(self) -> None:
        from core.tftp_client import TftpSession
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as h:
            h.write("# header\n\nconfig.txt\n# another\nfirmware.bin\n")
            p = Path(h.name)
        try:
            self.assertEqual(
                TftpSession.load_wordlist(str(p)),
                ["config.txt", "firmware.bin"],
            )
        finally:
            p.unlink(missing_ok=True)

    def test_default_wordlist_is_shipped(self) -> None:
        """The bundled list ships with the package."""
        from core.tftp_client import TftpSession
        path = TftpSession.default_wordlist_path()
        self.assertIsNotNone(path, "expected resources/wordlists/tftp_common.txt to ship")
        names = TftpSession.load_wordlist(path)  # type: ignore[arg-type]
        # Sanity: at least 50 entries — the bundled list aims for ~150+.
        self.assertGreater(len(names), 50)


class GopherBackendTests(unittest.TestCase):
    """Unit tests for the pure-stdlib Gopher (RFC 1436) backend."""

    @staticmethod
    def _start_server(menu_factory):
        """Start a tiny TCP server on 127.0.0.1 that answers
        ``selector → bytes`` from ``menu_factory``. Returns
        ``(host, port, stop)`` where ``stop()`` closes the listener.
        """
        import socket
        import threading

        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(8)
        srv.settimeout(0.2)
        port = srv.getsockname()[1]
        stop = threading.Event()

        def loop():
            while not stop.is_set():
                try:
                    c, _ = srv.accept()
                except socket.timeout:
                    continue
                except OSError:
                    return
                try:
                    sel = b""
                    while not sel.endswith(b"\r\n"):
                        chunk = c.recv(64)
                        if not chunk:
                            break
                        sel += chunk
                    body = menu_factory(sel.decode("utf-8", "replace").strip())
                    if body is not None:
                        c.sendall(body)
                finally:
                    c.close()

        threading.Thread(target=loop, daemon=True).start()

        def _stop():
            stop.set()
            srv.close()

        return "127.0.0.1", port, _stop

    def test_parse_menu_handles_info_dir_file_and_terminator(self) -> None:
        from core.gopher_client import _parse_menu, _entry_to_filename

        raw = (
            b"iWelcome\t\texample.org\t70\r\n"
            b"0README\t/readme.txt\texample.org\t70\r\n"
            b"1Tools\t/tools\texample.org\t70\r\n"
            b"9disk.iso\t/files/disk.iso\texample.org\t70\r\n"
            b".\r\n"
            b"this should be ignored\r\n"
        )
        entries = _parse_menu(raw)
        self.assertEqual(len(entries), 4)
        self.assertEqual(entries[0]["type"], "i")
        self.assertEqual(_entry_to_filename(entries[1]), "README.txt")
        self.assertEqual(_entry_to_filename(entries[2]), "Tools")
        # File with native extension keeps it (no .bin suffix added).
        self.assertEqual(_entry_to_filename(entries[3]), "disk.iso")

    def test_session_lists_root_navigates_via_display_name(self) -> None:
        from core.gopher_client import GopherSession

        def menus(sel):
            if sel == "":
                return (
                    b"0readme.txt\t/readme.txt\texample.org\t70\r\n"
                    b"1subdir\t/sub\texample.org\t70\r\n"
                    b".\r\n"
                )
            if sel == "/sub":
                return b"0nested.txt\t/sub/nested.txt\texample.org\t70\r\n.\r\n"
            if sel == "/readme.txt":
                return b"hello"
            if sel == "/sub/nested.txt":
                return b"nested"
            return b""

        host, port, stop = self._start_server(menus)
        try:
            sess = GopherSession(host=host, port=port)
            root = sess.list_dir("/")
            self.assertEqual(
                sorted([(i.name, i.is_dir) for i in root]),
                [("readme.txt", False), ("subdir", True)],
            )
            # Display-name path "/subdir" must transparently fetch the
            # real selector "/sub" via the parent listing's selector.
            sub = sess.list_dir("/subdir")
            self.assertEqual(
                [(i.name, i.is_dir) for i in sub],
                [("nested.txt", False)],
            )
            payload = sess.open_read("/subdir/nested.txt").read()
            self.assertEqual(payload, b"nested")
        finally:
            stop()

    def test_session_refuses_writes(self) -> None:
        from core.gopher_client import GopherSession

        host, port, stop = self._start_server(lambda sel: b".\r\n")
        try:
            sess = GopherSession(host=host, port=port)
            for op in (
                lambda: sess.open_write("/x"),
                lambda: sess.mkdir("/x"),
                lambda: sess.remove("/x"),
                lambda: sess.rename("/a", "/b"),
                lambda: sess.chmod("/x", 0o755),
                lambda: sess.copy("/a", "/b"),
            ):
                with self.assertRaises(OSError):
                    op()
        finally:
            stop()

    def test_send_selector_rejects_crlf_smuggling(self) -> None:
        """A path with embedded CR/LF must not be sent on the wire —
        otherwise an attacker-controlled bookmark could smuggle a
        second selector request into one socket."""
        from core.gopher_client import _send_selector, GopherProtocolError

        class _Fake:
            def sendall(self, _b):
                raise AssertionError("must not reach the wire")

        with self.assertRaises(GopherProtocolError):
            _send_selector(_Fake(), "/foo\r\n/bar")
        with self.assertRaises(GopherProtocolError):
            _send_selector(_Fake(), "/foo\tinjected")


if __name__ == "__main__":
    unittest.main()
