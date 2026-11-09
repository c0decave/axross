"""Trust Host Key? defaults to No.

Pressing Enter on the question about an unknown SSH host key trusted the
key: Yes was Qt's default. A key the user never compared must not be
trusted by a reflex; both places that ask now pass No as the default.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets")

from PyQt6.QtWidgets import QApplication, QMessageBox  # noqa: E402

APP = QApplication.instance() or QApplication([])


class _Err:
    host, key_type, fingerprint_sha256 = "example.org", "ssh-ed25519", "abc"


@pytest.mark.parametrize("module, cls", [("ui.connection_dialog", "ConnectionDialog"),
                                         ("ui.main_window", "MainWindow")])
def test_sad_enter_on_an_unknown_host_key_does_not_trust_it(module, cls):
    import importlib

    owner = getattr(importlib.import_module(module), cls)
    seen = {}

    def question(parent, title, text, buttons, default=QMessageBox.StandardButton.NoButton):
        seen["default"] = default
        return default  # what Enter answers

    with mock.patch.object(QMessageBox, "question", staticmethod(question)):
        trusted = owner._confirm_unknown_host(None, _Err())  # self is only the dialog parent
    assert seen["default"] == QMessageBox.StandardButton.No
    assert trusted is False
