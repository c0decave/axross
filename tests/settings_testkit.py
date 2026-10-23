"""Shared set-up for the Settings dialog tests: every settings store in a
temporary home, no modal message box, and windows that are closed again.

Used by tests/test_settings_dialog.py and tests/test_settings_matrix.py.
"""

from __future__ import annotations

from pathlib import Path
from unittest import mock

from PyQt6.QtCore import QEvent
from PyQt6.QtWidgets import QApplication, QMessageBox


class Stores:
    """Where each store of a test lives, and the windows it opened."""

    def __init__(self, home: Path) -> None:
        self.home = home
        self.config = home / ".config" / "axross"
        self.config.mkdir(parents=True)
        self.settings = self.config / "settings.json"
        self.session = self.config / "session.json"
        self.ramfs = self.config / "ramfs.json"
        self.proxy = self.config / "proxy.json"
        self.llm = self.config / "llm.json"
        self.agent = self.config / "agent" / "settings.json"
        self.extensions = self.config / "extensions.json"
        self.windows: list = []
        self.dialogs: list = []
        self.messages: list[tuple[str, str]] = []
        self.proxy_passwords: dict[str, str] = {}

    def make_window(self):
        from ui.main_window import MainWindow

        win = MainWindow()
        win._reconnect_timer.stop()
        self.windows.append(win)
        return win

    def close_windows(self) -> None:
        """Close every window (closing saves session.json, as on quit) and
        delete it now: a live window would be restyled by every later one."""
        from PyQt6 import sip

        for win in self.windows:
            if not sip.isdeleted(win):
                win.close()
                win.deleteLater()
        QApplication.instance().sendPostedEvents(None, QEvent.Type.DeferredDelete)
        self.windows = [w for w in self.windows if not sip.isdeleted(w)]

    def settings_dialog(self, win, page: str | None = None):
        from ui.settings_dialog import SettingsDialog

        dialog = SettingsDialog(win, window=win)
        if page is not None:
            dialog.show_page(page)
        self.dialogs.append(dialog)
        return dialog

    def files(self) -> dict[str, float]:
        """Every file below the config folder with its mtime."""
        return {
            str(p.relative_to(self.config)): p.stat().st_mtime_ns
            for p in self.config.rglob("*")
            if p.is_file()
        }


def isolate(tmp_path: Path, monkeypatch) -> Stores:
    """Redirect every settings store into *tmp_path* (module constants are
    computed at import time, so each is patched) and silence message boxes."""
    from core import i18n
    from core import llm_profiles as LP
    from core import open_limits as OL
    from core import proxy_settings as PS
    from core import ramfs_settings as RS
    from core import security_mode as SM
    from ui import column_prefs as CP
    from ui import icon_provider
    from ui import main_window as MW

    home = tmp_path / "home"
    home.mkdir()
    stores = Stores(home)
    monkeypatch.setenv("HOME", str(home))
    patcher = mock.patch("pathlib.Path.home", return_value=home)
    patcher.start()
    monkeypatch.setenv("AXROSS_OPERATION_JOURNAL", str(tmp_path / "ops.jsonl"))
    monkeypatch.delenv(SM.ENV, raising=False)
    for target, name, value in (
        (OL, "SETTINGS_PATH", stores.settings),
        (i18n, "SETTINGS_FILE", stores.session),
        (MW.MainWindow, "_SESSION_FILE", stores.session),
        (MW.MainWindow, "_RECENTS_FILE", stores.config / "recents.json"),
        (RS, "CONFIG_DIR", stores.config),
        (RS, "SETTINGS_FILE", stores.ramfs),
        (RS, "_CACHED", None),
        (PS, "SETTINGS_PATH", stores.proxy),
        (LP, "CONFIG_DIR", stores.config),
        (LP, "SETTINGS_FILE", stores.llm),
        (CP, "DEFAULT_PATH", stores.config / "column_prefs.json"),
        (SM, "_CURRENT", SM.NORMAL),
        (i18n, "_ACTIVE", i18n.Translator(i18n.DEFAULT_LANGUAGE)),
    ):
        monkeypatch.setattr(target, name, value)
    # The keyring of the proxy password: a dict.
    monkeypatch.setattr(PS, "get_password", lambda: stores.proxy_passwords.get("pw", ""))

    def set_password(value: str) -> bool:
        if value:
            stores.proxy_passwords["pw"] = value
        else:
            stores.proxy_passwords.pop("pw", None)
        return True

    monkeypatch.setattr(PS, "set_password", set_password)
    PS.set_session_password("")
    for name in ("information", "warning", "critical"):
        monkeypatch.setattr(
            QMessageBox, name,
            staticmethod(
                lambda *a, _n=name, **k: stores.messages.append((_n, str(a[2]) if a[2:] else ""))
            ),
        )
    monkeypatch.setattr(
        QMessageBox, "question",
        staticmethod(lambda *a, **k: QMessageBox.StandardButton.No),
    )
    icon_provider.set_monochrome(False)
    app = QApplication.instance() or QApplication([])
    font = app.font()
    stylesheet_before = app.styleSheet()

    def restore() -> None:
        from PyQt6 import sip

        for dialog in stores.dialogs:
            if not sip.isdeleted(dialog):
                dialog.reject()
        for win in stores.windows:
            if not sip.isdeleted(win):
                win.close()
                win.deleteLater()
        app.sendPostedEvents(None, QEvent.Type.DeferredDelete)
        icon_provider.set_monochrome(False)
        app.setFont(font)
        app.setStyleSheet(stylesheet_before)
        PS.set_session_password("")
        patcher.stop()

    stores.restore = restore
    return stores


def app() -> QApplication:
    return QApplication.instance() or QApplication([])


__all__ = ["Stores", "app", "isolate"]
