"""Tools > Network & Proxy: the default proxy every "Default" profile uses."""

from __future__ import annotations

import dataclasses
import logging
from pathlib import Path

from PyQt6.QtCore import QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from core import proxy_settings
from core.proxy import compose_proxy_type, parse_proxy_type

log = logging.getLogger(__name__)

# (label, transport) -- the transport half of the proxy kind string.
TRANSPORT_CHOICES: list[tuple[str, str]] = [
    ("SOCKS5", "socks5"),
    ("SOCKS4", "socks4"),
    ("HTTP CONNECT", "http"),
    ("HTTPS proxy (TLS to the proxy)", "https"),
]
# (label, auth scheme) -- only HTTP / HTTPS proxies authenticate this way.
AUTH_CHOICES: list[tuple[str, str]] = [
    ("Automatic (Basic when a username is set)", ""),
    ("Basic", "basic"),
    ("NTLM", "ntlm"),
    ("Negotiate (SPNEGO / Kerberos)", "negotiate"),
    ("Kerberos only", "kerberos"),
]


def transport_index(kind: str) -> int:
    """Index into :data:`TRANSPORT_CHOICES` for a proxy kind string."""
    try:
        transport, _auth = parse_proxy_type(kind)
    except ValueError:
        return 0
    for index, (_label, value) in enumerate(TRANSPORT_CHOICES):
        if value == transport:
            return index
    return 0


def auth_index(kind: str) -> int:
    """Index into :data:`AUTH_CHOICES` for a proxy kind string."""
    try:
        _transport, auth = parse_proxy_type(kind)
    except ValueError:
        return 0
    for index, (_label, value) in enumerate(AUTH_CHOICES):
        if value == auth:
            return index
    return 0


def kind_from_indexes(transport_idx: int, auth_idx: int) -> str:
    """Proxy kind string for the two combo boxes (auth only on HTTP kinds)."""
    transport = TRANSPORT_CHOICES[transport_idx][1]
    auth = AUTH_CHOICES[auth_idx][1] if transport in ("http", "https") else ""
    return compose_proxy_type(transport, auth)


class _ProbeThread(QThread):
    """Runs the probe off the UI thread (DNS / TLS / auth can take seconds)."""

    finished_with = pyqtSignal(bool, str, str, float)  # ok, stage, message, seconds

    def __init__(self, defaults, password: str, host: str, port: int, parent=None):
        super().__init__(parent)
        self._defaults = defaults
        self._password = password
        self._host = host
        self._port = port

    def run(self) -> None:
        try:
            res = proxy_settings.resolve(
                "default", None, self._host, self._port, defaults=self._defaults
            )
        except Exception as exc:  # noqa: BLE001 - PAC / resolution problems are the answer
            self.finished_with.emit(False, "config", str(exc), 0.0)
            return
        if res.config is None:
            self.finished_with.emit(True, "direct", res.description, 0.0)
            return
        cfg = res.config
        if self._password:
            cfg = dataclasses.replace(cfg, password=self._password)
        result = proxy_settings.probe(cfg, self._host, self._port)
        self.finished_with.emit(result.ok, result.stage, result.message, result.seconds)


class NetworkProxyDialog(QDialog):
    """Edit the default proxy, bypass list, PAC location and test them."""

    def __init__(
        self, profile_manager=None, parent: QWidget | None = None, path: Path | None = None
    ):
        super().__init__(parent)
        self.setWindowTitle("Network & Proxy")
        self.setMinimumWidth(520)
        self._profile_manager = profile_manager
        self._path = path
        self._probe: _ProbeThread | None = None

        layout = QVBoxLayout(self)
        intro = QLabel(
            "The default proxy is used by every connection profile set to "
            "“Default proxy”, by Quick Connect and by scripts that name no proxy."
        )
        intro.setWordWrap(True)
        layout.addWidget(intro)

        group = QGroupBox("Default proxy")
        form = QFormLayout(group)

        self._type = QComboBox()
        self._type.addItem("None (connect directly)", "none")
        for label, value in TRANSPORT_CHOICES:
            self._type.addItem(label, value)
        form.addRow("Type:", self._type)

        self._auth = QComboBox()
        for label, _value in AUTH_CHOICES:
            self._auth.addItem(label)
        form.addRow("Authentication:", self._auth)

        self._host = QLineEdit()
        self._host.setPlaceholderText("proxy hostname or IP")
        form.addRow("Host:", self._host)

        self._port = QSpinBox()
        self._port.setRange(1, 65535)
        self._port.setValue(1080)
        form.addRow("Port:", self._port)

        self._username = QLineEdit()
        self._username.setPlaceholderText("(optional)")
        form.addRow("Username:", self._username)

        self._password = QLineEdit()
        self._password.setEchoMode(QLineEdit.EchoMode.Password)
        self._password.setPlaceholderText("(unchanged)")
        form.addRow("Password:", self._password)

        self._store_pw = QCheckBox("Save password in keyring")
        form.addRow("", self._store_pw)

        ca_row = QHBoxLayout()
        self._ca_file = QLineEdit()
        self._ca_file.setPlaceholderText("CA bundle for an HTTPS proxy (empty = system store)")
        ca_row.addWidget(self._ca_file)
        browse = QPushButton("Browse…")
        browse.clicked.connect(self._browse_ca)
        ca_row.addWidget(browse)
        form.addRow("CA file:", ca_row)

        self._pac = QLineEdit()
        self._pac.setPlaceholderText("http(s) URL or file path of a PAC script (optional)")
        form.addRow("PAC script:", self._pac)
        layout.addWidget(group)

        bypass_group = QGroupBox("No proxy for")
        bypass_layout = QVBoxLayout(bypass_group)
        self._bypass = QPlainTextEdit()
        self._bypass.setPlaceholderText(
            "One entry per line: hostnames, .example.com, *.lan, 10.0.0.0/8, host:port"
        )
        self._bypass.setFixedHeight(90)
        bypass_layout.addWidget(self._bypass)
        layout.addWidget(bypass_group)

        test_group = QGroupBox("Test")
        test_layout = QHBoxLayout(test_group)
        self._test_host = QLineEdit()
        self._test_host.setPlaceholderText("target host, e.g. example.com")
        test_layout.addWidget(self._test_host, stretch=1)
        self._test_port = QSpinBox()
        self._test_port.setRange(1, 65535)
        self._test_port.setValue(443)
        test_layout.addWidget(self._test_port)
        self._test_btn = QPushButton("Test proxy")
        self._test_btn.clicked.connect(self._run_test)
        test_layout.addWidget(self._test_btn)
        layout.addWidget(test_group)
        self._test_result = QLabel("")
        self._test_result.setWordWrap(True)
        layout.addWidget(self._test_result)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )
        self._adopt_btn = buttons.addButton(
            "Use for all profiles…", QDialogButtonBox.ButtonRole.ActionRole
        )
        self._adopt_btn.setEnabled(profile_manager is not None)
        self._adopt_btn.clicked.connect(self._adopt_for_all)
        buttons.accepted.connect(self._save)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self._type.currentIndexChanged.connect(self._update_enabled)
        self._pac.textChanged.connect(self._update_enabled)
        self._load()
        self._update_enabled()

    # -- load / collect ------------------------------------------------
    def _load(self) -> None:
        d = proxy_settings.load(self._path)
        kind = d.proxy_type
        if kind == "none":
            self._type.setCurrentIndex(0)
        else:
            self._type.setCurrentIndex(1 + transport_index(kind))
            self._auth.setCurrentIndex(auth_index(kind))
        self._host.setText(d.host)
        if d.port:
            self._port.setValue(d.port)
        self._username.setText(d.username)
        self._store_pw.setChecked(d.store_password)
        self._ca_file.setText(d.ca_file)
        self._pac.setText(d.pac_url)
        self._bypass.setPlainText("\n".join(d.bypass))

    def collect(self) -> proxy_settings.ProxyDefaults:
        """The dialog state as :class:`ProxyDefaults` (not validated)."""
        if self._type.currentIndex() == 0:
            kind = "none"
        else:
            kind = kind_from_indexes(self._type.currentIndex() - 1, self._auth.currentIndex())
        bypass = [line.strip() for line in self._bypass.toPlainText().splitlines() if line.strip()]
        return proxy_settings.ProxyDefaults(
            proxy_type=kind,
            host=self._host.text().strip(),
            port=self._port.value() if kind != "none" or self._pac.text().strip() else 0,
            username=self._username.text().strip(),
            store_password=self._store_pw.isChecked(),
            bypass=bypass,
            ca_file=self._ca_file.text().strip(),
            pac_url=self._pac.text().strip(),
        )

    # -- enable / disable ---------------------------------------------
    def _update_enabled(self) -> None:
        index = self._type.currentIndex()
        proxied = index != 0
        http_kind = proxied and TRANSPORT_CHOICES[index - 1][1] in ("http", "https")
        https_kind = proxied and TRANSPORT_CHOICES[index - 1][1] == "https"
        has_pac = bool(self._pac.text().strip())
        self._auth.setEnabled(http_kind)
        self._host.setEnabled(proxied and not has_pac)
        self._port.setEnabled(proxied and not has_pac)
        for widget in (self._username, self._password, self._store_pw):
            widget.setEnabled(proxied)
        self._ca_file.setEnabled(https_kind or has_pac)

    def _browse_ca(self) -> None:
        name, _ = QFileDialog.getOpenFileName(self, "CA bundle", self._ca_file.text())
        if name:
            self._ca_file.setText(name)

    # -- actions --------------------------------------------------------
    def _typed_password(self) -> str:
        return self._password.text()

    def _run_test(self) -> None:
        host = self._test_host.text().strip()
        if not host:
            self._show_result(False, "Enter a target host to test, e.g. example.com.")
            return
        defaults = self.collect()
        try:
            proxy_settings.validate(defaults)
        except ValueError as exc:
            self._show_result(False, str(exc))
            return
        if self._probe is not None and self._probe.isRunning():
            return
        self._test_btn.setEnabled(False)
        self._show_result(None, "Testing…")
        # A typed password wins; otherwise resolve() reads the keyring entry.
        self._probe = _ProbeThread(
            defaults, self._typed_password(), host, self._test_port.value(), self
        )
        self._probe.finished_with.connect(self._on_probe_done)
        self._probe.start()

    def done(self, result: int) -> None:  # noqa: D102 - Qt override
        # A probe still running must neither report to the closed dialog
        # nor be destroyed with it (the window keeps this dialog until exit).
        from ui.thread_lifetime import detach_running_thread

        if self._probe is not None:
            detach_running_thread(self._probe, self._probe.finished_with)
            self._test_btn.setEnabled(True)
        super().done(result)

    def _on_probe_done(self, ok: bool, stage: str, message: str, seconds: float) -> None:
        self._test_btn.setEnabled(True)
        if stage == "direct":
            self._show_result(True, message)
        elif ok:
            self._show_result(True, f"{message} ({seconds:.2f} s)")
        else:
            self._show_result(False, f"Failed at stage “{stage}”: {message}")

    def _show_result(self, ok: bool | None, text: str) -> None:
        prefix = "" if ok is None else ("✔ " if ok else "✘ ")
        self._test_result.setText(prefix + text)

    def _save(self) -> None:
        defaults = self.collect()
        try:
            proxy_settings.save(defaults, self._path)
        except (ValueError, OSError) as exc:
            QMessageBox.warning(self, "Network & Proxy", str(exc))
            return
        typed = self._typed_password()
        # Without the keyring the typed password lives for this session, so
        # real connections use what "Test proxy" used.
        proxy_settings.set_session_password("" if defaults.store_password else typed)
        if defaults.store_password and typed:
            if not proxy_settings.set_password(typed):
                QMessageBox.warning(
                    self, "Keyring Error", "Could not save the proxy password to the keyring."
                )
                return
        elif not defaults.store_password:
            proxy_settings.set_password("")
        self.accept()

    def _adopt_for_all(self) -> None:
        if self._profile_manager is None:
            return
        profiles = self._profile_manager.all_profiles()
        reply = QMessageBox.question(
            self,
            "Use for all profiles",
            "Switch every profile whose protocol can use a proxy to the default proxy?\n"
            "Their own proxy settings are kept but no longer used. Profiles that "
            "reach their host through a ProxyCommand (jump host) keep it.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        changed = proxy_settings.adopt_default_proxy(profiles)
        if changed:
            self._profile_manager.save()
        QMessageBox.information(
            self, "Use for all profiles", f"{len(changed)} profile(s) now use the default proxy."
        )
