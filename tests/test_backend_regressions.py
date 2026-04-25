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


if __name__ == "__main__":
    unittest.main()
