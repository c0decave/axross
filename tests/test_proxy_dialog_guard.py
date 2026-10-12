"""The connection dialog must not offer a proxy the backend would refuse."""
from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import connection_manager as cm  # noqa: E402


class ProxyUnavailableReasonTest(unittest.TestCase):
    def test_refused_and_local_protocols_have_a_reason(self) -> None:
        for proto in ("nfs", "iscsi", "rsh", "wmi", "mtp", "ramfs", "sqlite"):
            self.assertTrue(cm.proxy_unavailable_reason(proto), proto)

    def test_proxy_capable_protocols_have_none(self) -> None:
        for proto in ("sftp", "ftp", "smb", "svn", "tftp", "postgres", "redis", "s3"):
            self.assertIsNone(cm.proxy_unavailable_reason(proto), proto)

    def test_unknown_protocol_has_none(self) -> None:
        self.assertIsNone(cm.proxy_unavailable_reason("no-such-protocol"))


class DialogProxyGroupTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])

    def _dialog(self):
        from ui.connection_dialog import ConnectionDialog

        manager = mock.MagicMock()
        manager.list_names.return_value = []
        return ConnectionDialog(manager)

    def _select(self, dialog, proto: str) -> None:
        dialog._protocol_combo.setCurrentIndex(dialog._protocol_ids.index(proto))

    def test_proxy_group_is_disabled_for_nfs_with_an_explanation(self) -> None:
        dialog = self._dialog()
        self._select(dialog, "nfs")
        self.assertFalse(dialog._proxy_group.isEnabled())
        self.assertFalse(dialog._proxy_group.isChecked())
        self.assertIn("proxy", dialog._proxy_group.toolTip().lower())

    def test_proxy_group_stays_usable_for_sftp(self) -> None:
        dialog = self._dialog()
        self._select(dialog, "nfs")
        self._select(dialog, "sftp")
        self.assertTrue(dialog._proxy_group.isEnabled())
        self.assertEqual(dialog._proxy_group.toolTip(), "")


if __name__ == "__main__":
    unittest.main()
