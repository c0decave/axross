"""Connection dialog for creating/editing connection profiles (multi-protocol)."""

from __future__ import annotations

import dataclasses
import logging
import os
from pathlib import Path

from PyQt6.QtCore import QRegularExpression, Qt, QThread, QTimer, pyqtSignal
from PyQt6.QtGui import QRegularExpressionValidator
from PyQt6.QtWidgets import (
    QButtonGroup,
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
    QMenu,
    QMessageBox,
    QPushButton,
    QRadioButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from core.backend_registry import all_backends, ensure_initialized, recheck_missing
from core.credentials import profile_name_problem
from core.desktop_open import open_in_browser
from core.i18n import tr
from core.profiles import SIMPLE_PASSWORD_PROTOCOLS, ConnectionProfile, ProfileManager
from core.ssh_client import SSHSession, UnknownHostKeyError
from ui.close_corner import add_close_corner
from ui.features_dialog import offer_features
from ui.network_proxy_dialog import (
    AUTH_CHOICES,
    TRANSPORT_CHOICES,
    auth_index,
    kind_from_indexes,
    transport_index,
)
from ui.scan_job import ScanJob
from ui.screen_fit import FitScrollArea, fit_size, fit_window, keep_on_screen
from ui.icon_provider import set_window_icon

log = logging.getLogger(__name__)

#: Protocols without a login name: the Username row is hidden for them and
#: validation never asks for one - one list, so a hidden field can never be
#: a required one (it was for RamFS, TFTP and MTP).
NO_USERNAME_PROTOCOLS = frozenset(
    {"nfs", "onedrive", "sharepoint", "gdrive", "dropbox", "gopher", "pjl", "ramfs", "tftp", "mtp"}
)


class _ConnectThread(QThread):
    """Background thread for test connection to avoid freezing the UI."""

    success = pyqtSignal(str)  # home directory
    error = pyqtSignal(str)  # error message
    #: The server's host key is not in known_hosts yet. A test has nobody
    #: to ask (it runs without the trust prompt), so this is no failure:
    #: the text sends the user to Connect, which shows the fingerprint.
    unknown_host_key = pyqtSignal(str)

    def __init__(self, profile: ConnectionProfile, password: str, key_passphrase: str, parent=None):
        super().__init__(parent)
        self._profile = profile
        self._password = password
        self._key_passphrase = key_passphrase

    def run(self) -> None:
        try:
            from core.connection_manager import ConnectionManager

            class _TestManager(ConnectionManager):
                # A test connection is no connection of the app: enrolled in
                # core.conn_health under the app's own key, its disconnect
                # removed the health record of a pane open on that profile.
                @staticmethod
                def _enroll_health(*_args, **_kwargs) -> None:
                    return None

                @staticmethod
                def _unenroll_health(*_args, **_kwargs) -> None:
                    return None

            mgr = _TestManager()
            try:
                session = mgr.connect(
                    self._profile,
                    password=self._password,
                    key_passphrase=self._key_passphrase,
                )
                home = session.home()
            finally:
                # Also when home() raises after the connect: the session,
                # its socket and its transport thread were left open.
                mgr.disconnect_all()
            self.success.emit(home)
        except UnknownHostKeyError as e:
            from core.user_errors import describe

            self.unknown_host_key.emit(describe(e))
        except Exception as e:
            from core.user_errors import describe

            self.error.emit(describe(e))


def _expand_home(path: str) -> str:
    """*path* with a leading ``~`` expanded; empty stays empty."""
    return os.path.expanduser(path) if path.startswith("~") else path


class ConnectionDialog(QDialog):
    """Dialog for creating/editing connection profiles and connecting."""

    def __init__(
        self,
        profile_manager: ProfileManager,
        parent: QWidget | None = None,
        profile: ConnectionProfile | None = None,
    ):
        super().__init__(parent)
        set_window_icon(self, "connection-manager")
        self._profile_manager = profile_manager
        self._result_profile: ConnectionProfile | None = None
        self._result_password: str = ""
        self._result_key_passphrase: str = ""
        self._loaded_profile_name: str | None = None
        # The profile the form was filled from: _build_profile starts from
        # it, so fields the form has no widget for survive a save.
        self._loaded_profile: ConnectionProfile | None = None

        # One name with the menu entry that opens it (File → Connection
        # Manager…; UX review round 6: the window said "Connect to Server").
        self.setWindowTitle(tr("Connection Manager"))
        self.setMinimumWidth(500)
        # Not init_registry() on every open (a dozen PATH searches): the
        # commands check themselves when PATH changes, and a package missing
        # so far is asked again (core.backend_registry.recheck_missing).
        ensure_initialized()
        recheck_missing()
        self._setup_ui()

        if profile:
            # A saved profile is selected in the list too, so Save and
            # Delete act on it (Quick Connect's "Edit Config…").
            if self._profile_combo.findText(profile.name) >= 0:
                self._profile_combo.setCurrentText(profile.name)
            if self._loaded_profile_name != profile.name:
                self._load_profile(profile)
        add_close_corner(self)
        # F1: the handbook's Connections (the window's own F1 does not reach a
        # modal dialog).
        from ui.handbook import install_help_key

        install_help_key(self, "connections")

    @property
    def result_profile(self) -> ConnectionProfile | None:
        return self._result_profile

    @property
    def result_password(self) -> str:
        return self._result_password

    @property
    def result_key_passphrase(self) -> str:
        return self._result_key_passphrase

    @property
    def result_new_pane(self) -> bool:
        """Open the connection in a new pane, not in the unused target
        pane: "Open in a new pane" ticked, or Shift held on OK."""
        return getattr(self, "_result_new_pane", False)

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)

        # Profile selector
        profile_layout = QHBoxLayout()
        profile_layout.addWidget(QLabel(tr("Profile:")))
        self._profile_combo = QComboBox()
        self._profile_combo.setEditable(False)
        self._profile_combo.addItem(tr("(New Connection)"))
        for name in self._profile_manager.list_names():
            self._profile_combo.addItem(name)
        self._profile_combo.currentTextChanged.connect(self._on_profile_selected)
        # Right click: delete the config shown (the Delete button's flow).
        self._profile_combo.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._profile_combo.customContextMenuRequested.connect(self._show_profile_menu)
        profile_layout.addWidget(self._profile_combo, stretch=1)

        self._btn_save_profile = QPushButton(tr("Save"))
        self._btn_save_profile.clicked.connect(self._save_profile)
        profile_layout.addWidget(self._btn_save_profile)

        self._btn_delete_profile = QPushButton(tr("Delete"))
        self._btn_delete_profile.clicked.connect(self._delete_profile)
        profile_layout.addWidget(self._btn_delete_profile)

        layout.addLayout(profile_layout)

        # The groups scroll when the screen is too short for them (947 px
        # with a custom proxy: OK and Cancel were off a 768 px screen).
        form_page = QWidget()
        form_layout = QVBoxLayout(form_page)
        form_layout.setContentsMargins(0, 0, 0, 0)
        self._form_scroll = FitScrollArea(form_page, reserve=110)
        layout.addWidget(self._form_scroll, stretch=1)
        outer, layout = layout, form_layout

        # Connection settings
        conn_group = QGroupBox(tr("Connection"))
        conn_form = QFormLayout(conn_group)

        self._profile_name = QLineEdit()
        self._profile_name.setPlaceholderText(tr("Profile name (for saving)"))
        conn_form.addRow(tr("Name:"), self._profile_name)

        # Protocol selector. The names first; whether each backend is
        # installed is asked off the GUI thread (_label_job): the first ask
        # imports its packages (~1 s for all). The hints follow then.
        self._protocol_combo = QComboBox()
        backends = all_backends()
        self._protocol_ids: list[str] = []
        for info in backends:
            self._protocol_combo.addItem(tr(info.display_name))
            self._protocol_ids.append(info.protocol_id)
        self._labels_ready = False
        self._label_job = ScanJob(self)
        self._label_job.finished.connect(
            lambda kind, value, _cancelled, b=backends: self._on_availability(b, kind, value))
        self._label_job.start(
            lambda _cancel, _progress, b=backends: [bool(info.available) for info in b])
        # Default to SFTP
        if "sftp" in self._protocol_ids:
            self._protocol_combo.setCurrentIndex(self._protocol_ids.index("sftp"))
        self._protocol_combo.currentIndexChanged.connect(self._on_protocol_changed)
        conn_form.addRow(tr("Protocol:"), self._protocol_combo)

        self._host = QLineEdit()
        self._host.setPlaceholderText(tr("hostname or IP"))
        conn_form.addRow(tr("Host:"), self._host)

        self._port = QSpinBox()
        self._port.setRange(1, 65535)
        self._port.setValue(22)
        conn_form.addRow(tr("Port:"), self._port)

        self._username = QLineEdit()
        conn_form.addRow(tr("Username:"), self._username)

        # Address family
        self._addr_family = QComboBox()
        self._addr_family.addItems([tr("Auto"), tr("IPv4 only"), tr("IPv6 only")])
        conn_form.addRow(tr("IP Version:"), self._addr_family)

        # SFTP: seconds of silence before a waiting request asks the
        # connection whether it is alive (core.ssh_client.SFTP_IO_TIMEOUT).
        from core.profiles import SFTP_TIMEOUT_MAX

        self._sftp_timeout = QSpinBox()
        self._sftp_timeout.setRange(0, SFTP_TIMEOUT_MAX)
        self._sftp_timeout.setSuffix(tr(" s"))
        self._sftp_timeout.setSpecialValueText(tr("Default (60 s)"))
        self._sftp_timeout.setToolTip(tr(
            "How long a request may wait for the server's answer before axross asks the "
            "SSH connection whether it is still alive. It fails only when the connection "
            "does not answer; a slow server that is alive (tape or HSM storage) is waited "
            "for. Larger for such servers, smaller to notice a lost network sooner."
        ))
        conn_form.addRow(tr("SFTP time-out:"), self._sftp_timeout)

        # --- Protocol-specific fields ---

        # FTP: passive mode
        self._ftp_passive = QCheckBox(tr("Passive mode (recommended)"))
        self._ftp_passive.setChecked(True)
        conn_form.addRow(tr("FTP Mode:"), self._ftp_passive)

        # SMB: share name
        self._smb_share = QLineEdit()
        self._smb_share.setPlaceholderText(tr("Share name (e.g. Documents)"))
        conn_form.addRow(tr("Share:"), self._smb_share)

        # WebDAV: full URL
        self._webdav_url = QLineEdit()
        self._webdav_url.setPlaceholderText("https://cloud.example.com/remote.php/dav")
        conn_form.addRow(tr("URL:"), self._webdav_url)

        # S3: bucket, region, endpoint
        self._s3_bucket = QLineEdit()
        self._s3_bucket.setPlaceholderText(tr("my-bucket or bucket.s3.region.amazonaws.com"))
        conn_form.addRow(tr("Bucket:"), self._s3_bucket)

        self._s3_region = QLineEdit()
        self._s3_region.setPlaceholderText("eu-central-1")
        conn_form.addRow(tr("Region:"), self._s3_region)

        self._s3_endpoint = QLineEdit()
        self._s3_endpoint.setPlaceholderText(tr("https://s3.example.com (for MinIO, R2, etc.)"))
        conn_form.addRow(tr("Endpoint:"), self._s3_endpoint)

        # --- Rsync fields ---
        self._rsync_module = QLineEdit()
        self._rsync_module.setPlaceholderText(tr("module name (for rsyncd)"))
        conn_form.addRow(tr("Module:"), self._rsync_module)

        self._rsync_ssh = QCheckBox(tr("Use SSH transport (instead of rsyncd)"))
        conn_form.addRow("", self._rsync_ssh)

        self._rsync_ssh_key = QLineEdit()
        self._rsync_ssh_key.setPlaceholderText(tr("Path to SSH key (optional)"))
        conn_form.addRow(tr("SSH Key:"), self._rsync_ssh_key)

        # --- NFS fields ---
        self._nfs_export = QLineEdit()
        self._nfs_export.setPlaceholderText("/srv/nfs/share")
        conn_form.addRow(tr("Export:"), self._nfs_export)

        self._nfs_version = QComboBox()
        self._nfs_version.addItems(["NFSv3", "NFSv4", "NFSv4.1"])
        conn_form.addRow(tr("Version:"), self._nfs_version)

        # What the client sends about itself (AUTH_SYS). Any of them set:
        # axross speaks NFSv3 itself instead of mounting through the kernel.
        sender_tip = tr(
            "What axross sends the NFS server about itself (AUTH_SYS) – the server "
            "believes it and decides access by it. Fill in any of these and axross "
            "speaks NFS itself – v3 or v4, as chosen above (no mount, no root); the fields left empty are this "
            "computer's name, your UID and GID and no extra groups. Empty: the system's "
            "NFS mount, which always sends this computer's name and your IDs."
        )
        self._nfs_machine_name = QLineEdit()
        self._nfs_machine_name.setPlaceholderText(tr("this computer's name"))
        self._nfs_machine_name.setToolTip(sender_tip)
        conn_form.addRow(tr("Machine Name:"), self._nfs_machine_name)
        id_validator = QRegularExpressionValidator(QRegularExpression(r"[0-9]{0,10}"))
        self._nfs_uid = QLineEdit()
        self._nfs_uid.setPlaceholderText(tr("your UID"))
        self._nfs_uid.setValidator(id_validator)
        self._nfs_uid.setToolTip(sender_tip)
        conn_form.addRow(tr("Send UID:"), self._nfs_uid)
        self._nfs_gid = QLineEdit()
        self._nfs_gid.setPlaceholderText(tr("your GID"))
        self._nfs_gid.setValidator(id_validator)
        self._nfs_gid.setToolTip(sender_tip)
        conn_form.addRow(tr("Send GID:"), self._nfs_gid)
        self._nfs_gids = QLineEdit()
        self._nfs_gids.setPlaceholderText(tr("extra GIDs, e.g. 27, 100 (at most 16)"))
        self._nfs_gids.setToolTip(sender_tip)
        conn_form.addRow(tr("Extra GIDs:"), self._nfs_gids)
        self._nfs_client_id = QLineEdit()
        self._nfs_client_id.setPlaceholderText(tr("NFSv4: axross:<machine name>"))
        self._nfs_client_id.setToolTip(
            tr("NFSv4 only: the client id string axross registers with the server (SETCLIENTID) – "
               "what the server knows this client as.") + " " + sender_tip
        )
        conn_form.addRow(tr("NFSv4 Client ID:"), self._nfs_client_id)
        self._nfs_privileged_port = QCheckBox(tr("Send from a privileged port (< 1024, needs root)"))
        self._nfs_privileged_port.setToolTip(
            tr("For exports with the 'secure' option, which accept only source ports below 1024. "
            "Only with axross's own client (a sender field filled in).")
        )
        conn_form.addRow("", self._nfs_privileged_port)

        # --- Azure fields ---
        self._azure_container = QLineEdit()
        self._azure_container.setPlaceholderText(tr("Container name"))
        conn_form.addRow(tr("Container:"), self._azure_container)

        self._azure_share = QLineEdit()
        self._azure_share.setPlaceholderText(tr("File share name"))
        conn_form.addRow(tr("Share:"), self._azure_share)

        self._azure_connection_string = QLineEdit()
        self._azure_connection_string.setPlaceholderText(
            "DefaultEndpointsProtocol=https;AccountName=..."
        )
        self._azure_connection_string.setEchoMode(QLineEdit.EchoMode.Password)
        conn_form.addRow(tr("Conn String:"), self._azure_connection_string)

        self._azure_account_name = QLineEdit()
        self._azure_account_name.setPlaceholderText(tr("Storage account name"))
        conn_form.addRow(tr("Account:"), self._azure_account_name)

        self._azure_sas_token = QLineEdit()
        self._azure_sas_token.setPlaceholderText("?sv=2021-06-08&ss=...")
        self._azure_sas_token.setEchoMode(QLineEdit.EchoMode.Password)
        conn_form.addRow(tr("SAS Token:"), self._azure_sas_token)

        # --- OneDrive / SharePoint fields ---
        self._onedrive_client_id = QLineEdit()
        self._onedrive_client_id.setPlaceholderText(tr("Azure App Registration Client ID"))
        conn_form.addRow(tr("Client ID:"), self._onedrive_client_id)

        self._onedrive_tenant_id = QLineEdit()
        self._onedrive_tenant_id.setPlaceholderText("common")
        self._onedrive_tenant_id.setText("common")
        conn_form.addRow(tr("Tenant ID:"), self._onedrive_tenant_id)

        self._sharepoint_site_url = QLineEdit()
        self._sharepoint_site_url.setPlaceholderText("https://company.sharepoint.com/sites/MySite")
        conn_form.addRow(tr("Site URL:"), self._sharepoint_site_url)

        # --- Google Drive fields ---
        self._gdrive_client_id = QLineEdit()
        self._gdrive_client_id.setPlaceholderText(tr("Google OAuth Client ID"))
        conn_form.addRow(tr("Client ID:"), self._gdrive_client_id)

        self._gdrive_client_secret = QLineEdit()
        self._gdrive_client_secret.setEchoMode(QLineEdit.EchoMode.Password)
        self._gdrive_client_secret.setPlaceholderText(tr("Google OAuth Client Secret"))
        conn_form.addRow(tr("Client Secret:"), self._gdrive_client_secret)

        self._gdrive_import = QPushButton(tr("Import Client JSON…"))
        self._gdrive_import.setToolTip(tr("The JSON file Google offers for download next to "
                                          "the client (type Desktop app)"))
        self._gdrive_import.clicked.connect(self._import_google_client)
        conn_form.addRow("", self._gdrive_import)

        # --- Dropbox fields ---
        self._dropbox_app_key = QLineEdit()
        self._dropbox_app_key.setPlaceholderText(tr("Dropbox App Key"))
        conn_form.addRow(tr("App Key:"), self._dropbox_app_key)

        self._dropbox_app_secret = QLineEdit()
        self._dropbox_app_secret.setEchoMode(QLineEdit.EchoMode.Password)
        self._dropbox_app_secret.setPlaceholderText(tr("Dropbox App Secret"))
        conn_form.addRow(tr("App Secret:"), self._dropbox_app_secret)

        # Where an OAuth service's values come from (core.oauth_help).
        self._oauth_help = QLabel()
        self._oauth_help.setWordWrap(True)
        self._oauth_help.setTextFormat(Qt.TextFormat.RichText)
        self._oauth_help.setOpenExternalLinks(False)
        self._oauth_help.linkActivated.connect(open_in_browser)
        conn_form.addRow(self._oauth_help)

        # --- iSCSI fields ---
        self._iscsi_target_iqn = QLineEdit()
        self._iscsi_target_iqn.setPlaceholderText("iqn.2024-01.com.example:storage.target1")
        conn_form.addRow(tr("Target IQN:"), self._iscsi_target_iqn)

        self._iscsi_mount_point = QLineEdit()
        self._iscsi_mount_point.setPlaceholderText(tr("/mnt/iscsi (auto if empty)"))
        conn_form.addRow(tr("Mount Point:"), self._iscsi_mount_point)

        # What the initiator sends about itself (freely chosen; empty =
        # the system's initiatorname.iscsi / any interface).
        self._iscsi_initiator_name = QLineEdit()
        self._iscsi_initiator_name.setPlaceholderText(tr("system default (/etc/iscsi/initiatorname.iscsi)"))
        self._iscsi_initiator_name.setToolTip(
            tr("The initiator name (IQN) this connection sends to the target – in the "
            "login and the discovery. Any name the target accepts, e.g. "
            "iqn.2026-11.org.example:client1. Empty: the system's.")
        )
        conn_form.addRow(tr("Initiator Name:"), self._iscsi_initiator_name)

        self._iscsi_initiator_interface = QLineEdit()
        self._iscsi_initiator_interface.setPlaceholderText(tr("any (e.g. eth0, wlan0)"))
        self._iscsi_initiator_interface.setToolTip(
            tr("The network interface the iSCSI connection leaves through. Empty: any.")
        )
        conn_form.addRow(tr("Send From Interface:"), self._iscsi_initiator_interface)

        # --- IMAP fields ---
        self._imap_ssl = QCheckBox(tr("Use SSL/TLS (IMAPS, port 993)"))
        self._imap_ssl.setChecked(True)
        conn_form.addRow("", self._imap_ssl)

        # --- NNTP fields ---
        self._nntp_ssl = QCheckBox(tr("Use SSL/TLS (NNTPS, port 563)"))
        self._nntp_ssl.setChecked(True)
        conn_form.addRow("", self._nntp_ssl)

        # Simple password field for non-SSH protocols
        self._simple_password = QLineEdit()
        self._simple_password.setEchoMode(QLineEdit.EchoMode.Password)
        self._simple_password.setPlaceholderText(tr("Enter password"))
        conn_form.addRow(tr("Password:"), self._simple_password)

        self._simple_store_pw = QCheckBox(tr("Save in keyring"))
        conn_form.addRow("", self._simple_store_pw)

        # The production countdown (core.safety_tarpit, docs/DAILY_DRIVER.md):
        # before, it could only be switched on in Python.
        self._production = QCheckBox(tr("Production (confirm destructive operations with a "
                                        "countdown)"))
        self._production.setToolTip(tr(
            "The first delete, move or overwrite on this connection in a pane waits a few "
            "seconds with a countdown that Cancel or Esc stops – for servers where a slip "
            "costs something."))
        conn_form.addRow("", self._production)

        layout.addWidget(conn_group)

        # Authentication
        auth_group = QGroupBox(tr("Authentication"))
        auth_layout = QVBoxLayout(auth_group)

        self._auth_password = QRadioButton(tr("Password"))
        self._auth_password.setChecked(True)
        self._auth_key = QRadioButton(tr("SSH Key File"))
        self._auth_agent = QRadioButton(tr("SSH Agent"))

        auth_btn_group = QButtonGroup(self)
        auth_btn_group.addButton(self._auth_password)
        auth_btn_group.addButton(self._auth_key)
        auth_btn_group.addButton(self._auth_agent)

        auth_layout.addWidget(self._auth_password)

        # Password field
        pw_layout = QHBoxLayout()
        self._password = QLineEdit()
        self._password.setEchoMode(QLineEdit.EchoMode.Password)
        self._password.setPlaceholderText(tr("Enter password"))
        pw_layout.addWidget(self._password)
        self._store_password = QCheckBox(tr("Save in keyring"))
        pw_layout.addWidget(self._store_password)
        auth_layout.addLayout(pw_layout)

        auth_layout.addWidget(self._auth_key)

        # Key file
        key_layout = QHBoxLayout()
        self._key_file = QLineEdit()
        self._key_file.setPlaceholderText(tr("Path to private key"))
        key_layout.addWidget(self._key_file)
        self._btn_browse_key = QPushButton(tr("Browse…"))
        self._btn_browse_key.clicked.connect(self._browse_key)
        key_layout.addWidget(self._btn_browse_key)
        auth_layout.addLayout(key_layout)

        # Key passphrase
        self._key_passphrase = QLineEdit()
        self._key_passphrase.setEchoMode(QLineEdit.EchoMode.Password)
        self._key_passphrase.setPlaceholderText(tr("Key passphrase (if any)"))
        auth_layout.addWidget(self._key_passphrase)

        auth_layout.addWidget(self._auth_agent)

        # Toggle field visibility based on auth type
        self._auth_password.toggled.connect(self._update_auth_fields)
        self._auth_key.toggled.connect(self._update_auth_fields)
        self._auth_agent.toggled.connect(self._update_auth_fields)

        layout.addWidget(auth_group)

        # Proxy settings (collapsible)
        self._proxy_group = QGroupBox(tr("Proxy Settings"))
        self._proxy_group.setCheckable(True)
        self._proxy_group.setChecked(False)
        proxy_form = QFormLayout(self._proxy_group)

        self._proxy_mode = QComboBox()
        # A combo box shows "&" as it is: "&&" showed up doubled.
        self._proxy_mode.addItem(tr("Default proxy (Tools → Network & Proxy)"), "default")
        self._proxy_mode.addItem(tr("Custom proxy for this profile"), "custom")
        proxy_form.addRow(tr("Use:"), self._proxy_mode)

        self._proxy_default_hint = QLabel()
        self._proxy_default_hint.setWordWrap(True)
        self._proxy_default_hint.setProperty("role", "muted")
        proxy_form.addRow("", self._proxy_default_hint)

        self._proxy_type = QComboBox()
        for label, _value in TRANSPORT_CHOICES:
            self._proxy_type.addItem(tr(label))
        proxy_form.addRow(tr("Type:"), self._proxy_type)

        self._proxy_auth = QComboBox()
        for label, _value in AUTH_CHOICES:
            self._proxy_auth.addItem(tr(label))
        proxy_form.addRow(tr("Authentication:"), self._proxy_auth)

        self._proxy_host = QLineEdit()
        self._proxy_host.setPlaceholderText(tr("proxy hostname or IP"))
        proxy_form.addRow(tr("Host:"), self._proxy_host)

        self._proxy_port = QSpinBox()
        self._proxy_port.setRange(1, 65535)
        self._proxy_port.setValue(1080)
        proxy_form.addRow(tr("Port:"), self._proxy_port)

        self._proxy_username = QLineEdit()
        self._proxy_username.setPlaceholderText(tr("(optional)"))
        proxy_form.addRow(tr("Username:"), self._proxy_username)

        self._proxy_password = QLineEdit()
        self._proxy_password.setEchoMode(QLineEdit.EchoMode.Password)
        self._proxy_password.setPlaceholderText(tr("(optional)"))
        proxy_form.addRow(tr("Password:"), self._proxy_password)

        self._store_proxy_pw = QCheckBox(tr("Save proxy password in keyring"))
        proxy_form.addRow("", self._store_proxy_pw)

        self._proxy_command = QLineEdit()
        self._proxy_command.setPlaceholderText(tr("ssh -W %h:%p jumphost  (overrides proxy above)"))
        proxy_form.addRow(tr("ProxyCommand:"), self._proxy_command)

        layout.addWidget(self._proxy_group)
        layout.addStretch(1)
        layout = outer
        self._proxy_mode.currentIndexChanged.connect(self._update_proxy_fields)
        self._proxy_type.currentIndexChanged.connect(self._update_proxy_fields)
        self._proxy_group.toggled.connect(self._update_proxy_fields)
        self._reset_proxy_fields()

        # Buttons
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        # The main button says what it does (it said "OK"; UX review round 8).
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText(tr("Connect"))
        buttons.accepted.connect(self._on_accept)
        buttons.rejected.connect(self.reject)

        self._btn_test = QPushButton(tr("Test Connection"))
        self._btn_test.clicked.connect(self._test_connection)
        buttons.addButton(self._btn_test, QDialogButtonBox.ButtonRole.ActionRole)

        self._btn_import_ssh = QPushButton(tr("Import SSH Config"))
        self._btn_import_ssh.setToolTip(tr("Import host from ~/.ssh/config"))
        self._btn_import_ssh.clicked.connect(self._import_from_ssh_config)
        buttons.addButton(self._btn_import_ssh, QDialogButtonBox.ButtonRole.ActionRole)

        self._btn_import_file = QPushButton(tr("Import Config File…"))
        self._btn_import_file.setToolTip(tr("Import host from a custom SSH config file"))
        self._btn_import_file.clicked.connect(self._import_from_ssh_config_file)
        buttons.addButton(self._btn_import_file, QDialogButtonBox.ButtonRole.ActionRole)

        self._btn_deploy_key = QPushButton(tr("Deploy SSH Key"))
        self._btn_deploy_key.setToolTip(
            tr("Copy your public key to the remote server (like ssh-copy-id)")
        )
        self._btn_deploy_key.clicked.connect(self._deploy_ssh_key)
        buttons.addButton(self._btn_deploy_key, QDialogButtonBox.ButtonRole.ActionRole)

        # Where the connection opens: by default in the target pane while
        # nobody has used it yet (ui.main_window._untouched_target_pane).
        self._new_pane_box = QCheckBox(tr("Open in a new pane"))
        self._new_pane_box.setToolTip(
            tr("Without this, the connection opens in the target pane while that is "
               "unused (a local pane still at your home folder). Holding Shift while "
               "you click Connect also opens a new pane.")
        )
        layout.addWidget(self._new_pane_box)
        layout.addWidget(buttons)

        self._update_auth_fields()
        self._on_protocol_changed()

    def _selected_protocol(self) -> str:
        """Return the currently selected protocol ID."""
        idx = self._protocol_combo.currentIndex()
        if 0 <= idx < len(self._protocol_ids):
            return self._protocol_ids[idx]
        return "sftp"

    def _on_protocol_changed(self) -> None:
        """Show/hide fields based on selected protocol."""
        proto = self._selected_protocol()
        is_ssh = proto in ("sftp", "scp")
        is_ftp = proto in ("ftp", "ftps")
        is_smb = proto in ("smb", "dfsn")
        is_webdav = proto == "webdav"
        is_s3 = proto == "s3"
        is_rsync = proto == "rsync"
        is_nfs = proto == "nfs"
        is_azure_blob = proto == "azure_blob"
        is_azure_files = proto == "azure_files"
        is_azure = is_azure_blob or is_azure_files
        is_onedrive = proto == "onedrive"
        is_sharepoint = proto == "sharepoint"
        is_gdrive = proto == "gdrive"
        is_dropbox = proto == "dropbox"
        is_iscsi = proto == "iscsi"
        is_imap = proto == "imap"

        # A proxy the backend cannot honour is refused at connect time;
        # make that visible here instead of letting it be configured.
        from core.connection_manager import proxy_unavailable_reason

        proxy_reason = proxy_unavailable_reason(proto)
        self._proxy_group.setEnabled(proxy_reason is None)
        # No proxy for this protocol: no box for one (UX review round 8).
        self._proxy_group.setVisible(proxy_reason is None)
        self._proxy_group.setToolTip(
            ""
            if proxy_reason is None
            else tr("A proxy cannot be used with this protocol. {reason}").format(reason=proxy_reason)
        )
        if proxy_reason is not None:
            self._proxy_group.setChecked(False)

        # SSH-only widgets
        for w in (self._auth_password, self._auth_key, self._auth_agent):
            w.parentWidget().setVisible(is_ssh) if w.parentWidget() else None
        auth_group = self._auth_password.parentWidget()
        while auth_group and not isinstance(auth_group, QGroupBox):
            auth_group = auth_group.parentWidget()
        if auth_group:
            auth_group.setVisible(is_ssh)

        # SSH-only buttons
        self._btn_import_ssh.setVisible(is_ssh)
        self._btn_import_file.setVisible(is_ssh)
        self._btn_deploy_key.setVisible(is_ssh)

        # Simple password field — show for protocols that need a password/secret
        needs_simple_pw = proto in SIMPLE_PASSWORD_PROTOCOLS
        self._set_form_row_visible(self._simple_password, needs_simple_pw)
        self._set_form_row_visible(self._simple_store_pw, needs_simple_pw)
        if is_s3:
            self._set_form_label(self._simple_password, "Secret Key:")
            self._simple_password.setPlaceholderText(tr("AWS secret access key"))
        elif is_azure:
            self._set_form_label(self._simple_password, "Account Key:")
            self._simple_password.setPlaceholderText(tr("Azure storage account key"))
        else:
            self._set_form_label(self._simple_password, "Password:")
            self._simple_password.setPlaceholderText(tr("Enter password"))

        # Protocol-specific field visibility
        self._set_form_row_visible(self._ftp_passive, is_ftp)
        self._set_form_row_visible(self._smb_share, is_smb)
        if is_smb:
            self._set_form_label(
                self._smb_share,
                "Namespace:" if proto == "dfsn" else "Share:",
            )
        self._set_form_row_visible(self._webdav_url, is_webdav)
        self._set_form_row_visible(self._s3_bucket, is_s3)
        self._set_form_row_visible(self._s3_region, is_s3)
        self._set_form_row_visible(self._s3_endpoint, is_s3)

        # Rsync
        self._set_form_row_visible(self._rsync_module, is_rsync)
        self._set_form_row_visible(self._rsync_ssh, is_rsync)
        self._set_form_row_visible(self._rsync_ssh_key, is_rsync)

        # NFS
        self._set_form_row_visible(self._nfs_export, is_nfs)
        self._set_form_row_visible(self._nfs_version, is_nfs)
        for w in (self._nfs_machine_name, self._nfs_uid, self._nfs_gid, self._nfs_gids,
                  self._nfs_client_id, self._nfs_privileged_port):
            self._set_form_row_visible(w, is_nfs)

        # Azure
        self._set_form_row_visible(self._azure_container, is_azure_blob)
        self._set_form_row_visible(self._azure_share, is_azure_files)
        self._set_form_row_visible(self._azure_connection_string, is_azure)
        self._set_form_row_visible(self._azure_account_name, is_azure)
        self._set_form_row_visible(self._azure_sas_token, is_azure)

        # OneDrive / SharePoint
        self._set_form_row_visible(self._onedrive_client_id, is_onedrive or is_sharepoint)
        self._set_form_row_visible(self._onedrive_tenant_id, is_onedrive or is_sharepoint)
        self._set_form_row_visible(self._sharepoint_site_url, is_sharepoint)

        # Google Drive
        self._set_form_row_visible(self._gdrive_client_id, is_gdrive)
        self._set_form_row_visible(self._gdrive_client_secret, is_gdrive)

        # Dropbox
        self._set_form_row_visible(self._dropbox_app_key, is_dropbox)
        self._set_form_row_visible(self._dropbox_app_secret, is_dropbox)

        # OAuth: where the values come from, and the Google client file
        self._set_form_row_visible(self._gdrive_import, is_gdrive)
        self._show_oauth_help(proto)

        # iSCSI
        self._set_form_row_visible(self._iscsi_target_iqn, is_iscsi)
        self._set_form_row_visible(self._iscsi_mount_point, is_iscsi)
        self._set_form_row_visible(self._iscsi_initiator_name, is_iscsi)
        self._set_form_row_visible(self._iscsi_initiator_interface, is_iscsi)

        # IMAP
        self._set_form_row_visible(self._imap_ssl, is_imap)
        self._set_form_row_visible(self._nntp_ssl, proto == "nntp")

        # Host/Port visibility
        # Azure: the endpoint comes from the account name or the connection
        # string (BlobEndpoint=...); the backend never reads a host.
        no_host_protos = (
            "webdav",
            "s3",
            "onedrive",
            "sharepoint",
            "gdrive",
            "dropbox",
            "azure_blob",
            "azure_files",
            # An in-process RAM workspace: nothing to connect to.
            "ramfs",
        )
        needs_host = proto not in no_host_protos
        self._set_form_row_visible(self._host, needs_host)
        self._set_form_row_visible(self._port, needs_host)

        # Username visibility — cloud OAuth and no-auth protocols don't need it
        needs_username = proto not in NO_USERNAME_PROTOCOLS
        self._set_form_row_visible(self._username, needs_username)

        # Username label
        if is_s3:
            self._set_form_label(self._username, "Access Key:")
            self._username.setPlaceholderText(tr("AWS access key ID"))
        elif is_azure:
            self._set_form_label(self._username, "Account:")
            self._username.setPlaceholderText(tr("Storage account name"))
        else:
            self._set_form_label(self._username, "Username:")
            self._username.setPlaceholderText("")

        # IP version — only relevant for host-based protocols
        self._set_form_row_visible(self._addr_family, needs_host)
        self._set_form_row_visible(self._sftp_timeout, proto == "sftp")

        # Update default port
        from core.backend_registry import get as get_backend

        info = get_backend(proto)
        if info:
            self._port.setValue(info.default_port)
        self._grow_to_content()

    def _grow_to_content(self) -> None:
        """Rows shown for a protocol or a custom proxy: a dialog on screen
        grows to show them, as far as the screen allows (then it scrolls)."""
        if self.isVisible():
            QTimer.singleShot(0, self._grow_now)

    def _grow_now(self) -> None:
        from PyQt6 import sip

        if sip.isdeleted(self) or not self.isVisible():
            return
        self._form_scroll.widget().adjustSize()
        self._form_scroll.updateGeometry()
        layout = self.layout()
        if layout is not None:
            layout.activate()
        want = self.sizeHint().height()
        if want > self.height():
            self.resize(self.width(), want)
            fit_window(self)
            keep_on_screen(self)

    def _show_oauth_help(self, proto: str) -> None:
        from html import escape

        from core.oauth_help import GUIDES

        guide = GUIDES.get(proto)
        self._oauth_help.setVisible(guide is not None)
        if guide is None:
            self._oauth_help.clear()
            return
        steps = "".join(f"<li>{escape(tr(step))}</li>" for step in guide.steps)
        self._oauth_help.setText(
            f"<p>{escape(tr('Where these values come from:'))} "
            f'<a href="{escape(guide.console_url)}">{escape(guide.console_name)}</a> '
            f"({escape(guide.console_url)})</p><ol>{steps}</ol>"
            f"<p>{escape(tr(guide.sign_in))}</p>")

    def _import_google_client(self) -> None:
        """Fill Client ID and Secret from Google's downloaded client file."""
        from core.oauth_help import MAX_CLIENT_FILE_BYTES, parse_google_client

        path, _filter = QFileDialog.getOpenFileName(
            self, tr("Import Google Client JSON"), "", tr("JSON files (*.json);;All files (*)"))
        if not path:
            return
        try:
            with open(path, encoding="utf-8") as handle:
                text = handle.read(MAX_CLIENT_FILE_BYTES + 1)
            client_id, secret = parse_google_client(text)
        except (OSError, UnicodeDecodeError, ValueError) as exc:
            QMessageBox.warning(self, tr("Import Google Client JSON"),
                                tr("The file cannot be used: {reason}").format(reason=exc))
            return
        self._gdrive_client_id.setText(client_id)
        self._gdrive_client_secret.setText(secret)

    def _set_form_row_visible(self, widget: QWidget, visible: bool) -> None:
        """Show/hide a QFormLayout row (widget + its label)."""
        widget.setVisible(visible)
        parent_layout = widget.parentWidget().layout() if widget.parentWidget() else None
        if isinstance(parent_layout, QFormLayout):
            label = parent_layout.labelForField(widget)
            if label:
                label.setVisible(visible)

    def _set_form_label(self, widget: QWidget, text: str) -> None:
        """Change the label text for a QFormLayout row."""
        parent_layout = widget.parentWidget().layout() if widget.parentWidget() else None
        if isinstance(parent_layout, QFormLayout):
            label = parent_layout.labelForField(widget)
            if label and isinstance(label, QLabel):
                label.setText(tr(text))

    def _update_auth_fields(self) -> None:
        is_pw = self._auth_password.isChecked()
        is_key = self._auth_key.isChecked()

        self._password.setEnabled(is_pw)
        self._store_password.setEnabled(is_pw)
        self._key_file.setEnabled(is_key)
        self._btn_browse_key.setEnabled(is_key)
        self._key_passphrase.setEnabled(is_key)

    def _browse_key(self) -> None:
        from pathlib import Path

        default_dir = str(Path.home() / ".ssh")
        path, _ = QFileDialog.getOpenFileName(
            self, tr("Select SSH Key"), default_dir, tr("All Files (*)"))
        if path:
            self._key_file.setText(path)

    def _on_profile_selected(self, name: str) -> None:
        if name == tr("(New Connection)"):
            self._clear_fields()
            return
        profile = self._profile_manager.get(name)
        if profile:
            self._load_profile(profile)

    def _load_profile(self, p: ConnectionProfile) -> None:
        self._loaded_profile_name = p.name
        self._loaded_profile = p
        # Every typed secret belongs to the profile it was typed for: the
        # FTP / SMB / WebDAV / IMAP password, S3 secret or Azure key field
        # survived a switch, and Connect sent A's password to B (and stored
        # it as B's with "Save in keyring" on).
        self._clear_typed_secrets()
        self._profile_name.setText(p.name)

        # Protocol
        if p.protocol in self._protocol_ids:
            self._protocol_combo.setCurrentIndex(self._protocol_ids.index(p.protocol))

        self._host.setText(p.host)
        self._port.setValue(p.port)
        self._username.setText(p.username)

        addr_map = {"auto": 0, "ipv4": 1, "ipv6": 2}
        self._addr_family.setCurrentIndex(addr_map.get(p.address_family, 0))
        self._sftp_timeout.setValue(p.sftp_timeout)

        if p.auth_type == "key":
            self._auth_key.setChecked(True)
        elif p.auth_type == "agent":
            self._auth_agent.setChecked(True)
        else:
            self._auth_password.setChecked(True)

        self._key_file.setText(p.key_file)
        self._store_password.setChecked(p.store_password)
        self._simple_store_pw.setChecked(p.store_password)

        # Protocol-specific fields
        self._ftp_passive.setChecked(p.ftp_passive)
        self._smb_share.setText(p.smb_share)
        self._webdav_url.setText(p.webdav_url)
        self._s3_bucket.setText(p.s3_bucket)
        self._s3_region.setText(p.s3_region)
        self._s3_endpoint.setText(p.s3_endpoint)
        # Rsync
        self._rsync_module.setText(p.rsync_module)
        self._rsync_ssh.setChecked(p.rsync_ssh)
        self._rsync_ssh_key.setText(p.rsync_ssh_key)
        # NFS
        self._nfs_export.setText(p.nfs_export)
        self._nfs_version.setCurrentIndex(0 if p.nfs_version != 4 else (2 if p.nfs_minor else 1))
        self._nfs_machine_name.setText(p.nfs_machine_name)
        self._nfs_uid.setText(str(p.nfs_uid) if p.nfs_uid >= 0 else "")
        self._nfs_gid.setText(str(p.nfs_gid) if p.nfs_gid >= 0 else "")
        self._nfs_gids.setText(p.nfs_gids)
        self._nfs_privileged_port.setChecked(p.nfs_privileged_port)
        self._nfs_client_id.setText(p.nfs_client_id)
        # Azure
        self._azure_container.setText(p.azure_container)
        self._azure_share.setText(p.azure_share)
        self._azure_connection_string.setText(p.azure_connection_string)
        self._azure_account_name.setText(p.azure_account_name)
        self._azure_sas_token.setText(p.azure_sas_token)
        # OneDrive / SharePoint
        self._onedrive_client_id.setText(p.onedrive_client_id)
        self._onedrive_tenant_id.setText(p.onedrive_tenant_id or "common")
        self._sharepoint_site_url.setText(p.sharepoint_site_url)
        # Google Drive
        self._gdrive_client_id.setText(p.gdrive_client_id)
        self._gdrive_client_secret.setText(p.gdrive_client_secret)
        # Dropbox
        self._dropbox_app_key.setText(p.dropbox_app_key)
        self._dropbox_app_secret.setText(p.dropbox_app_secret)
        # iSCSI
        self._iscsi_target_iqn.setText(p.iscsi_target_iqn)
        self._iscsi_mount_point.setText(p.iscsi_mount_point)
        self._iscsi_initiator_name.setText(p.iscsi_initiator_name)
        self._iscsi_initiator_interface.setText(p.iscsi_initiator_interface)
        # IMAP
        self._imap_ssl.setChecked(p.imap_ssl)
        self._nntp_ssl.setChecked(p.nntp_ssl)
        self._production.setChecked(bool(p.production))

        mode = getattr(p, "proxy_mode", "custom")
        self._reset_proxy_fields()
        if mode == "default":
            self._proxy_group.setChecked(True)
            self._proxy_mode.setCurrentIndex(0)
        elif mode == "custom" and (p.proxy_type != "none" or p.proxy_command):
            self._proxy_group.setChecked(True)
            self._proxy_mode.setCurrentIndex(1)
            self._proxy_type.setCurrentIndex(transport_index(p.proxy_type))
            self._proxy_auth.setCurrentIndex(auth_index(p.proxy_type))
            self._proxy_host.setText(p.proxy_host)
            self._proxy_port.setValue(p.proxy_port or 1080)
            self._proxy_username.setText(p.proxy_username)
            self._store_proxy_pw.setChecked(p.store_proxy_password)
            self._proxy_command.setText(p.proxy_command)
        else:
            self._proxy_group.setChecked(False)
        self._update_proxy_fields()

    def _reset_proxy_fields(self) -> None:
        """Back to a fresh profile: the default proxy when one is configured."""
        from core import proxy_settings

        self._proxy_type.setCurrentIndex(0)
        self._proxy_auth.setCurrentIndex(0)
        self._proxy_host.clear()
        self._proxy_port.setValue(1080)
        self._proxy_username.clear()
        self._proxy_password.clear()
        self._store_proxy_pw.setChecked(False)
        self._proxy_command.clear()
        defaults = proxy_settings.load()
        self._proxy_mode.setCurrentIndex(0)
        self._proxy_group.setChecked(defaults.configured and self._proxy_group.isEnabled())
        if defaults.pac_url:
            hint = f"PAC: {defaults.pac_url}"
        elif defaults.proxy_type != "none":
            hint = f"{defaults.proxy_type.upper()} {defaults.host}:{defaults.port}"
        else:
            hint = tr("No default proxy is configured yet (Tools → Network & Proxy).")
        self._proxy_default_hint.setText(hint)
        self._update_proxy_fields()

    def _update_proxy_fields(self) -> None:
        """Custom fields apply only to a custom proxy; auth only to HTTP(S).
        An unticked proxy group folds to its title, the default proxy shows
        its one-line summary only: the dialog fits a 768 px screen."""
        custom = self._proxy_mode.currentIndex() == 1
        transport = TRANSPORT_CHOICES[self._proxy_type.currentIndex()][1]
        used = self._proxy_group.isChecked()
        # Unticked, the group is its title alone, not an empty frame under
        # it (UX review round 8).
        self._proxy_group.setFlat(not used)
        self._set_form_row_visible(self._proxy_mode, used)
        self._set_form_row_visible(self._proxy_default_hint, used and not custom)
        for widget in (
            self._proxy_type,
            self._proxy_auth,
            self._proxy_host,
            self._proxy_port,
            self._proxy_username,
            self._proxy_password,
            self._store_proxy_pw,
            self._proxy_command,
        ):
            self._set_form_row_visible(widget, used and custom)
        self._grow_to_content()
        self._proxy_type.setEnabled(custom)
        self._proxy_auth.setEnabled(custom and transport in ("http", "https"))
        for widget in (
            self._proxy_host,
            self._proxy_port,
            self._proxy_username,
            self._proxy_password,
            self._store_proxy_pw,
            self._proxy_command,
        ):
            widget.setEnabled(custom)

    def _clear_typed_secrets(self) -> None:
        """Empty every field a secret is typed into (never loaded from a
        profile: the keyring holds those)."""
        for field in (
            self._password,
            self._simple_password,
            self._key_passphrase,
            self._proxy_password,
        ):
            field.clear()

    def _clear_fields(self) -> None:
        self._loaded_profile_name = None
        self._loaded_profile = None
        self._profile_name.clear()
        if "sftp" in self._protocol_ids:
            self._protocol_combo.setCurrentIndex(self._protocol_ids.index("sftp"))
        self._host.clear()
        self._port.setValue(22)
        self._username.clear()
        self._addr_family.setCurrentIndex(0)  # "auto": not the last profile's
        self._sftp_timeout.setValue(0)  # the default
        self._clear_typed_secrets()
        self._key_file.clear()
        self._store_password.setChecked(False)
        self._auth_password.setChecked(True)
        self._reset_proxy_fields()
        self._simple_store_pw.setChecked(False)
        # Protocol-specific
        self._ftp_passive.setChecked(True)
        self._smb_share.clear()
        self._webdav_url.clear()
        self._s3_bucket.clear()
        self._s3_region.clear()
        self._s3_endpoint.clear()
        self._rsync_module.clear()
        self._rsync_ssh.setChecked(False)
        self._rsync_ssh_key.clear()
        self._nfs_export.clear()
        self._nfs_version.setCurrentIndex(0)
        for w in (self._nfs_machine_name, self._nfs_uid, self._nfs_gid, self._nfs_gids, self._nfs_client_id):
            w.clear()
        self._nfs_privileged_port.setChecked(False)
        self._azure_container.clear()
        self._azure_share.clear()
        self._azure_connection_string.clear()
        self._azure_account_name.clear()
        self._azure_sas_token.clear()
        self._onedrive_client_id.clear()
        self._onedrive_tenant_id.setText("common")
        self._sharepoint_site_url.clear()
        self._gdrive_client_id.clear()
        self._gdrive_client_secret.clear()
        self._dropbox_app_key.clear()
        self._dropbox_app_secret.clear()
        self._iscsi_target_iqn.clear()
        self._iscsi_mount_point.clear()
        self._iscsi_initiator_name.clear()
        self._iscsi_initiator_interface.clear()
        self._imap_ssl.setChecked(True)
        self._nntp_ssl.setChecked(True)
        self._production.setChecked(False)

    def _build_profile(self) -> ConnectionProfile:
        """Build a ConnectionProfile from current field values."""
        if self._auth_key.isChecked():
            auth_type = "key"
        elif self._auth_agent.isChecked():
            auth_type = "agent"
        else:
            auth_type = "password"

        addr_map = {0: "auto", 1: "ipv4", 2: "ipv6"}
        address_family = addr_map.get(self._addr_family.currentIndex(), "auto")

        proxy_type = "none"
        proxy_command = ""
        proxy_mode = "none"
        if self._proxy_group.isChecked() and self._proxy_group.isEnabled():
            if self._proxy_mode.currentIndex() == 0:
                proxy_mode = "default"
            else:
                proxy_mode = "custom"
                proxy_type = kind_from_indexes(
                    self._proxy_type.currentIndex(), self._proxy_auth.currentIndex()
                )
                proxy_command = self._proxy_command.text().strip()
                if proxy_command and not self._proxy_host.text().strip():
                    # ProxyCommand alone: a proxy kind without a host would
                    # make the connection refuse to start.
                    proxy_type = "none"
        custom_proxy = proxy_mode == "custom"

        proto = self._selected_protocol()
        host = self._host.text().strip()
        username = self._username.text().strip()

        # Auto-generate name
        if proto == "s3":
            auto_name = f"s3://{self._s3_bucket.text().strip()}"
        elif proto == "webdav":
            auto_name = f"webdav://{self._webdav_url.text().strip()[:30]}"
        elif proto == "smb":
            auto_name = f"\\\\{host}\\{self._smb_share.text().strip()}"
        elif proto == "rsync":
            auto_name = f"rsync://{host}/{self._rsync_module.text().strip()}"
        elif proto == "nfs":
            auto_name = f"nfs://{host}{self._nfs_export.text().strip()}"
        elif proto in ("azure_blob", "azure_files"):
            container_or_share = (
                self._azure_container.text().strip() or self._azure_share.text().strip()
            )
            auto_name = f"azure://{self._azure_account_name.text().strip()}/{container_or_share}"
        elif proto == "onedrive":
            auto_name = "OneDrive"
        elif proto == "sharepoint":
            auto_name = f"SharePoint: {self._sharepoint_site_url.text().strip()[:30]}"
        elif proto == "gdrive":
            auto_name = "Google Drive"
        elif proto == "dropbox":
            auto_name = "Dropbox"
        elif proto == "iscsi":
            auto_name = f"iscsi://{host}/{self._iscsi_target_iqn.text().strip()[:30]}"
        elif proto == "imap":
            auto_name = f"imap://{username}@{host}"
        elif proto == "ramfs":
            auto_name = "RAM workspace"
        elif proto == "tftp":
            auto_name = f"tftp://{host}"
        else:
            auto_name = f"{username}@{host}"

        # Use appropriate store-password checkbox
        if proto in ("sftp", "scp"):
            store_pw = self._store_password.isChecked()
        else:
            store_pw = self._simple_store_pw.isChecked()

        fields = dict(
            name=self._profile_name.text().strip() or auto_name,
            protocol=proto,
            host=host,
            port=self._port.value(),
            username=username,
            auth_type=auth_type,
            # Stored as validated (_validate expands "~"): the SSH clients
            # open the path as given.
            key_file=_expand_home(self._key_file.text().strip()),
            store_password=store_pw,
            proxy_mode=proxy_mode,
            proxy_type=proxy_type,
            proxy_host=self._proxy_host.text().strip() if custom_proxy else "",
            proxy_port=self._proxy_port.value(),
            proxy_username=self._proxy_username.text().strip() if custom_proxy else "",
            store_proxy_password=self._store_proxy_pw.isChecked() and custom_proxy,
            proxy_command=proxy_command,
            address_family=address_family,
            sftp_timeout=self._sftp_timeout.value() if proto == "sftp" else 0,
            # Protocol-specific
            ftp_passive=self._ftp_passive.isChecked(),
            smb_share=self._smb_share.text().strip(),
            webdav_url=self._webdav_url.text().strip(),
            s3_bucket=self._s3_bucket.text().strip(),
            s3_region=self._s3_region.text().strip(),
            s3_endpoint=self._s3_endpoint.text().strip(),
            # Rsync
            rsync_module=self._rsync_module.text().strip(),
            rsync_ssh=self._rsync_ssh.isChecked(),
            rsync_ssh_key=self._rsync_ssh_key.text().strip(),
            # NFS
            nfs_export=self._nfs_export.text().strip(),
            nfs_version=3 if self._nfs_version.currentIndex() == 0 else 4,
            nfs_minor=1 if self._nfs_version.currentIndex() == 2 else 0,
            nfs_machine_name=self._nfs_machine_name.text().strip(),
            nfs_uid=int(self._nfs_uid.text()) if self._nfs_uid.text().strip() else -1,
            nfs_gid=int(self._nfs_gid.text()) if self._nfs_gid.text().strip() else -1,
            nfs_gids=self._nfs_gids.text().strip(),
            nfs_privileged_port=self._nfs_privileged_port.isChecked(),
            nfs_client_id=self._nfs_client_id.text().strip(),
            # Azure
            azure_container=self._azure_container.text().strip(),
            azure_connection_string=self._azure_connection_string.text().strip(),
            azure_account_name=self._azure_account_name.text().strip(),
            azure_sas_token=self._azure_sas_token.text().strip(),
            azure_share=self._azure_share.text().strip(),
            # OneDrive / SharePoint
            onedrive_client_id=self._onedrive_client_id.text().strip(),
            onedrive_tenant_id=self._onedrive_tenant_id.text().strip() or "common",
            sharepoint_site_url=self._sharepoint_site_url.text().strip(),
            # Google Drive
            gdrive_client_id=self._gdrive_client_id.text().strip(),
            gdrive_client_secret=self._gdrive_client_secret.text().strip(),
            # Dropbox
            dropbox_app_key=self._dropbox_app_key.text().strip(),
            dropbox_app_secret=self._dropbox_app_secret.text().strip(),
            # iSCSI
            iscsi_target_iqn=self._iscsi_target_iqn.text().strip(),
            iscsi_mount_point=self._iscsi_mount_point.text().strip(),
            iscsi_initiator_name=self._iscsi_initiator_name.text().strip(),
            iscsi_initiator_interface=self._iscsi_initiator_interface.text().strip(),
            # IMAP
            imap_ssl=self._imap_ssl.isChecked(),
            nntp_ssl=self._nntp_ssl.isChecked(),
            production=self._production.isChecked(),
        )
        if self._loaded_profile is None:
            return ConnectionProfile(**fields)
        # Editing: the form overrides what it shows; everything else the
        # profile carries (ftps_verify_tls, terminal_theme, ...)
        # is kept. A session-only proxy password override is not.
        return dataclasses.replace(
            self._loaded_profile, _proxy_password_override=None, **fields
        )

    @property
    def labels_ready(self) -> bool:
        """The protocol list names the backends that are not installed."""
        return self._labels_ready

    @staticmethod
    def _protocol_label(info, available: bool) -> str:
        label = tr(info.display_name)
        if not available:
            if info.required_extra:
                label += f"  (pip install axross[{info.required_extra}])"
            elif info.install_hint:
                label += "  (" + tr("needs {what}").format(what=tr(info.install_hint)) + ")"
        return label

    def _on_availability(self, backends, kind: str, value) -> None:
        self._labels_ready = True
        if kind != "done":
            log.warning("Could not check which backends are installed: %s", value)
            return
        for index, (info, available) in enumerate(zip(backends, value)):
            self._protocol_combo.setItemText(index, self._protocol_label(info, available))

    def _validate_backend_available(self) -> bool:
        """False (and Help > Features… offered) when the chosen backend's
        dependencies are missing. A backend without a pip extra names the
        system command it needs - never a made-up "axross[...]"."""
        from core import features as F
        from core.backend_registry import get as get_backend

        proto = self._selected_protocol()
        info = get_backend(proto)
        if info is None or info.available:
            return True
        feature = next((f for f in F.collect() if f.key == f"backend:{proto}"), None)
        how = F.how_to_get(feature) if feature is not None else (info.install_hint or "")
        offer_features(
            self, f"backend:{proto}",
            tr("{name} is not installed. To get it: {how}").format(name=info.display_name, how=how),
        )
        return False

    def _profile_from_form_nfs_sender(self) -> str | None:
        """What is wrong with the NFS sender fields, or None."""
        from core.nfs3_rpc import AuthSys, parse_gids

        try:
            uid = int(self._nfs_uid.text()) if self._nfs_uid.text().strip() else 0
            gid = int(self._nfs_gid.text()) if self._nfs_gid.text().strip() else 0
            AuthSys(machine_name=self._nfs_machine_name.text().strip(), uid=uid, gid=gid,
                    gids=parse_gids(self._nfs_gids.text()))
        except ValueError as exc:
            return str(exc)
        if any(c < " " for c in self._nfs_client_id.text()) or len(self._nfs_client_id.text().encode()) > 1024:
            return "The NFSv4 client id must be one line of at most 1024 bytes."
        return None

    def _validate(self) -> bool:
        if not self._validate_backend_available():
            return False
        proto = self._selected_protocol()

        profile_name = self._profile_name.text().strip()
        host = self._host.text().strip()
        username = self._username.text().strip()
        key_file = self._key_file.text().strip()
        proxy_host = self._proxy_host.text().strip()
        proxy_command = self._proxy_command.text().strip()

        for label, value, allow_space in (
            ("Profile name", profile_name, True),
            ("Host", host, False),
            ("Username", username, False),
            ("Proxy host", proxy_host, False),
            ("Proxy username", self._proxy_username.text().strip(), True),
            ("ProxyCommand", proxy_command, True),
        ):
            if value and not self._is_safe_text(value, allow_space=allow_space):
                QMessageBox.warning(self, tr("Validation"), tr("{label} contains invalid characters.").format(label=tr(label)))
                return False
        # A name whose keyring entries belong to another secret: the save
        # failed later inside the keyring code and was reported as a
        # "Keyring Error" - the name is the problem, so it is said here.
        problem = profile_name_problem(profile_name) if profile_name else None
        if problem:
            QMessageBox.warning(
                self, tr("Validation"),
                tr("The profile name {name} cannot be used: it {problem}. Choose another "
                   "name.").format(name=f"'{profile_name}'", problem=tr(problem)))
            self._profile_name.setFocus()
            return False

        # Protocol-specific validation
        if proto == "rsync":
            if not host:
                QMessageBox.warning(self, tr("Validation"), tr("Host is required."))
                return False
        elif proto == "nfs":
            if not host:
                QMessageBox.warning(self, tr("Validation"), tr("Host is required."))
                return False
            if not self._nfs_export.text().strip():
                QMessageBox.warning(self, tr("Validation"), tr("NFS export path is required."))
                return False
            sender = self._profile_from_form_nfs_sender()
            if sender is not None:
                QMessageBox.warning(self, tr("Validation"), sender)
                return False
        elif proto in ("azure_blob", "azure_files"):
            cs = self._azure_connection_string.text().strip()
            acct = self._azure_account_name.text().strip()
            if not cs and not acct:
                QMessageBox.warning(
                    self,
                    tr("Validation"),
                    tr("Either Connection String or Account Name is required."),
                )
                return False
            if proto == "azure_blob" and not self._azure_container.text().strip():
                QMessageBox.warning(self, tr("Validation"), tr("Container name is required."))
                return False
            if proto == "azure_files" and not self._azure_share.text().strip():
                QMessageBox.warning(self, tr("Validation"), tr("File share name is required."))
                return False
        elif proto in ("onedrive", "sharepoint"):
            if not self._onedrive_client_id.text().strip():
                QMessageBox.warning(
                    self, tr("Validation"), tr("Client ID is required. See OAUTH_SETUP.md.")
                )
                return False
            if proto == "sharepoint" and not self._sharepoint_site_url.text().strip():
                QMessageBox.warning(self, tr("Validation"), tr("SharePoint site URL is required."))
                return False
        elif proto == "gdrive":
            if not self._gdrive_client_id.text().strip():
                QMessageBox.warning(
                    self, tr("Validation"), tr("Google Client ID is required. See OAUTH_SETUP.md.")
                )
                return False
        elif proto == "dropbox":
            if not self._dropbox_app_key.text().strip():
                QMessageBox.warning(
                    self, tr("Validation"), tr("Dropbox App Key is required. See OAUTH_SETUP.md.")
                )
                return False
        elif proto == "iscsi":
            if not host:
                QMessageBox.warning(self, tr("Validation"), tr("Target IP is required."))
                return False
            if not self._iscsi_target_iqn.text().strip():
                QMessageBox.warning(self, tr("Validation"), tr("Target IQN is required."))
                return False
            from core.iscsi_client import validate_initiator_name, validate_interface

            try:
                validate_initiator_name(self._iscsi_initiator_name.text())
                validate_interface(self._iscsi_initiator_interface.text())
            except ValueError as exc:
                QMessageBox.warning(self, tr("Validation"), str(exc))
                return False
        elif proto == "webdav":
            url = self._webdav_url.text().strip()
            if not url:
                QMessageBox.warning(self, tr("Validation"), tr("WebDAV URL is required."))
                return False
        elif proto == "s3":
            bucket = self._s3_bucket.text().strip()
            if not bucket:
                QMessageBox.warning(self, tr("Validation"), tr("S3 bucket name or URL is required."))
                return False
            # Accept full URLs (https://bucket.s3.region.amazonaws.com) or plain names
            import re

            is_url = any(bucket.startswith(p) for p in ("https://", "http://", "s3://"))
            is_hostname = ".amazonaws.com" in bucket or ".s3." in bucket
            if not is_url and not is_hostname:
                if not re.fullmatch(r"^[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]$", bucket):
                    QMessageBox.warning(
                        self,
                        tr("Validation"),
                        tr("Invalid S3 bucket name. Use a valid bucket name (lowercase, "
                        "3-63 chars) or paste a full S3 URL like:\n"
                        "dev-s1.s3.ap-south-1.amazonaws.com"),
                    )
                    return False
            # Access key is optional — anonymous access for public buckets
        elif proto in ("smb", "dfsn"):
            if not host:
                QMessageBox.warning(self, tr("Validation"), tr("Host is required."))
                return False
            if not self._smb_share.text().strip():
                label = tr("DFS namespace") if proto == "dfsn" else tr("SMB share name")
                QMessageBox.warning(self, tr("Validation"), tr("{label} is required.").format(label=label))
                return False
        elif proto in ("gopher", "pjl", "nntp", "tftp"):
            # No username (TFTP has no login at all; its row is hidden).
            if not host:
                QMessageBox.warning(self, tr("Validation"), tr("Host is required."))
                return False
        elif proto in ("telnet", "cisco-telnet"):
            # The username is optional: telnet_client logs in on a bare
            # password prompt or a no-auth shell, and IOS line-password
            # mode has no username at all (core/telnet_cisco.py).
            if not host:
                QMessageBox.warning(self, tr("Validation"), tr("Host is required."))
                return False
        elif proto == "ramfs":
            pass  # an in-process RAM workspace: no host, no login
        else:
            # SFTP, FTP, FTPS need host + username; a protocol whose Username
            # row is hidden (MTP) must not ask for one.
            if not host:
                QMessageBox.warning(self, tr("Validation"), tr("Host is required."))
                return False
            if not username and proto not in NO_USERNAME_PROTOCOLS:
                QMessageBox.warning(self, tr("Validation"), tr("Username is required."))
                return False

        if (
            self._proxy_group.isChecked()
            and self._proxy_mode.currentIndex() == 1
            and not proxy_host
            and not proxy_command
        ):
            QMessageBox.warning(
                self,
                tr("Validation"),
                tr("Proxy host or ProxyCommand is required when proxy support is enabled."),
            )
            return False

        # SSH-specific validation
        if proto in ("sftp", "scp"):
            if self._auth_key.isChecked() and not key_file:
                QMessageBox.warning(self, tr("Validation"), tr("Key file is required for key auth."))
                return False
            if self._auth_key.isChecked():
                key_path = Path(key_file).expanduser()
                if not key_path.is_file():
                    QMessageBox.warning(
                        self, tr("Validation"), tr("Key file does not exist or is not a file.")
                    )
                    return False
        return True

    @staticmethod
    def _is_safe_text(value: str, *, allow_space: bool) -> bool:
        if any(ch in value for ch in ("\r", "\n", "\x00")):
            return False
        if not allow_space and any(ch.isspace() for ch in value):
            return False
        return True

    def _save_profile(self) -> None:
        if not self._validate():
            return
        profile = self._build_profile()
        if (
            profile.name != self._loaded_profile_name
            and self._profile_manager.get(profile.name) is not None
        ):
            # Another profile has this name (a rename onto it, or a new
            # connection whose automatic user@host name is taken): saving
            # replaces it, so ask - default No.
            reply = QMessageBox.question(
                self,
                tr("Replace Profile"),
                tr("A profile named '{name}' already exists.\n\n"
                   "Replace it with this one? Its settings are lost.").format(name=profile.name),
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if reply != QMessageBox.StandardButton.Yes:
                return
        fallback_password = None
        fallback_proxy_password = None
        old_profile_name = self._loaded_profile_name
        if self._loaded_profile_name and self._loaded_profile_name != profile.name:
            old_profile = self._profile_manager.get(self._loaded_profile_name)
            if old_profile:
                fallback_password = old_profile.get_password()
                fallback_proxy_password = old_profile.get_proxy_password()
        from core.user_errors import describe

        # Each step says what failed: a refused name, a keyring that kept
        # no secret, a file that was not written (full disk, an unreadable
        # profiles.json) - all of them were "Keyring Error", or "Saved".
        try:
            saved = self._profile_manager.add(profile, report_failure=False)
        except ValueError as e:  # a name the keyring entries cannot hold
            QMessageBox.warning(self, tr("Not saved"), describe(e))
            return
        except RuntimeError as e:  # the keyring refused a secret field
            log.error("Failed to store profile secrets in keyring: %s", e)
            QMessageBox.warning(
                self, tr("Not saved"),
                tr("The profile was not saved: the keyring did not store its secrets. "
                   "Start or unlock your keyring (SecretService, KWallet, KeePassXC) "
                   "and try again."))
            return
        except OSError as e:
            QMessageBox.warning(self, tr("Not saved"), describe(e))
            return
        keyring_problem = ""
        try:
            self._store_profile_credentials(
                profile,
                fallback_password=fallback_password,
                fallback_proxy_password=fallback_proxy_password,
            )
        except Exception as e:  # noqa: BLE001 - the profile itself is saved
            log.error("Failed to store credentials in keyring: %s", e)
            keyring_problem = describe(e)
        if saved and old_profile_name and old_profile_name != profile.name:
            saved = self._profile_manager.remove(old_profile_name, report_failure=False)
        self._loaded_profile_name = profile.name
        self._loaded_profile = self._profile_manager.get(profile.name) or profile

        # Update combo - with its signals blocked: selecting the saved name
        # loaded the profile again, which emptied the typed password (and
        # a rename left the old name in the list, to a profile now gone).
        combo = self._profile_combo
        combo.blockSignals(True)
        try:
            if old_profile_name and old_profile_name != profile.name:
                old_idx = combo.findText(old_profile_name)
                if old_idx > 0:
                    combo.removeItem(old_idx)
            if combo.findText(profile.name) < 0:
                combo.addItem(profile.name)
            combo.setCurrentText(profile.name)
        finally:
            combo.blockSignals(False)

        if not saved:
            log.error("Profile %s not saved: %s", profile.name, saved.reason)
            QMessageBox.warning(
                self, tr("Not saved"),
                tr("Profile '{name}' is not saved.\n\n{reason}\n\nIt stays available "
                   "until axross ends.").format(name=profile.name, reason=saved.reason))
            return
        if keyring_problem:
            QMessageBox.warning(
                self, tr("Saved without password"),
                tr("Profile '{name}' is saved, but the keyring did not store its "
                   "password.\n\n{reason}").format(name=profile.name, reason=keyring_problem))
            return
        log.info("Saved profile: %s", profile.name)
        QMessageBox.information(
            self, tr("Saved"), tr("Profile '{name}' saved.").format(name=profile.name))

    def _build_profile_menu(self) -> QMenu:
        menu = QMenu(self)
        delete = menu.addAction(tr("Delete Connection Config…"))
        delete.setEnabled(self._profile_combo.currentText() != tr("(New Connection)"))
        delete.triggered.connect(lambda _checked=False: self._delete_profile())
        return menu

    def _show_profile_menu(self, pos) -> None:
        menu = self._build_profile_menu()
        try:
            menu.exec(self._profile_combo.mapToGlobal(pos))
        finally:
            menu.deleteLater()

    def _delete_profile(self) -> None:
        name = self._profile_combo.currentText()
        if name == tr("(New Connection)"):
            return
        reply = QMessageBox.question(
            self,
            tr("Delete Profile"),
            tr("Delete this profile?\n\n{name}").format(name=name),  # never markup in line 1
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            try:
                self._profile_manager.remove(name)
                log.info("Deleted profile: %s", name)
            except Exception as e:
                log.error("Failed to delete profile %s: %s", name, e)
                QMessageBox.warning(self, tr("Error"), tr("Failed to delete profile:\n{error}").format(error=e))
                return
            # removeItem() selected the next profile, the form was then
            # emptied under its name - and the next Delete removed that
            # profile, unseen. "(New Connection)" is selected instead.
            combo = self._profile_combo
            combo.blockSignals(True)
            try:
                idx = combo.findText(name)
                if idx >= 0:
                    combo.removeItem(idx)
                combo.setCurrentIndex(0)
            finally:
                combo.blockSignals(False)
            self._clear_fields()

    def _test_connection(self) -> None:
        if not self._validate():
            return
        profile = self._build_profile()
        self._btn_test.setEnabled(False)
        self._btn_test.setText(tr("Connecting…"))

        self._connect_thread = _ConnectThread(
            profile, self._effective_password(), self._key_passphrase.text(), parent=self
        )
        self._connect_thread.success.connect(self._on_test_success)
        self._connect_thread.error.connect(self._on_test_error)
        self._connect_thread.unknown_host_key.connect(self._on_test_unknown_host_key)
        self._connect_thread.finished.connect(self._on_test_done)
        self._connect_thread.start()

    def _effective_password(self) -> str:
        """Return the password from the appropriate field based on protocol."""
        if self._selected_protocol() in ("sftp", "scp"):
            return self._password.text()
        return self._simple_password.text()

    def _on_accept(self) -> None:
        if not self._validate():
            return
        self._result_profile = self._build_profile()
        self._result_password = self._effective_password()
        self._result_key_passphrase = self._key_passphrase.text()
        from PyQt6.QtWidgets import QApplication

        shift = QApplication.keyboardModifiers() & Qt.KeyboardModifier.ShiftModifier
        self._result_new_pane = self._new_pane_box.isChecked() or bool(shift)

        # Save password if requested
        try:
            self._store_profile_credentials(self._result_profile)
        except Exception as e:
            log.error("Failed to store credentials in keyring: %s", e)

        self.accept()

    def showEvent(self, event) -> None:  # noqa: N802 - Qt
        super().showEvent(event)
        if not getattr(self, "_sized_once", False):
            # Qt opens a dialog at most 2/3 of the screen high: the form
            # scrolled while the screen had room for all of it.
            self._sized_once = True
            self.resize(fit_size(self.sizeHint().expandedTo(self.size()), self))
            # Grown after Qt placed it: back onto the screen (it stood off
            # the right and bottom edge of a 1024x600 screen).
            keep_on_screen(self)

    def done(self, result: int) -> None:  # noqa: D102 - Qt override
        self._label_job.abandon()  # an answer still coming relabels no closed dialog
        # A test still running must neither report to the closed dialog nor
        # be destroyed with it (the window keeps this dialog until exit).
        from ui.thread_lifetime import detach_running_thread

        thread = getattr(self, "_connect_thread", None)
        if thread is not None:
            detach_running_thread(thread, thread.success, thread.error,
                                  thread.unknown_host_key, thread.finished)
            self._btn_test.setEnabled(True)
            self._btn_test.setText(tr("Test Connection"))
        super().done(result)

    def _on_test_success(self, home: str) -> None:
        QMessageBox.information(self, tr("Success"), tr("Connection successful!\nHome folder: {home}").format(home=home))

    def _on_test_error(self, error: str) -> None:
        QMessageBox.critical(self, tr("Connection Failed"), error)

    def _on_test_unknown_host_key(self, text: str) -> None:
        """The server answered, but with a host key not in known_hosts: no
        failure of the connection - Connect shows the fingerprint to trust."""
        QMessageBox.information(self, tr("New host key"), text)

    def _on_test_done(self) -> None:
        self._btn_test.setEnabled(True)
        self._btn_test.setText(tr("Test Connection"))

    def _store_profile_credentials(
        self,
        profile: ConnectionProfile,
        fallback_password: str | None = None,
        fallback_proxy_password: str | None = None,
    ) -> None:
        # ``profile.set_password`` / ``set_proxy_password`` delegate to
        # ``core.credentials.store_password`` which itself reports back
        # via WARNING + return False when the OS keyring is unreachable
        # (no SecretService / KWallet daemon). The user-visible warning
        # path lives in the post-connect quick-connect prompt and the
        # File → "Re-detect System Keyring" menu — both rendered with
        # ``keyring_status_message()`` install hints. We don't duplicate
        # the warning here because this method runs unconditionally on
        # every Save, including profile renames where the password is
        # being re-stored under the new name and the user hasn't asked
        # for a UI prompt.
        password = self._effective_password() or (fallback_password or "")
        proxy_password = self._proxy_password.text() or (fallback_proxy_password or "")
        if profile.store_password and password:
            profile.set_password(password)
        if profile.store_proxy_password and proxy_password:
            profile.set_proxy_password(proxy_password)

    def _import_from_ssh_config(self) -> None:
        """Show SSH config hosts and fill fields from selected host."""
        from core.ssh_config import parse_ssh_config

        hosts = parse_ssh_config()
        if not hosts:
            QMessageBox.information(self, tr("SSH Config"), tr("No hosts found in ~/.ssh/config"))
            return

        names = [h.alias for h in hosts]
        from PyQt6.QtWidgets import QInputDialog

        choice, ok = QInputDialog.getItem(
            self, tr("Import SSH Config"), tr("Select host:"), names, editable=False
        )
        if not ok:
            return

        host = next((h for h in hosts if h.alias == choice), None)
        if host is None:
            log.warning("SSH import: host %r no longer in list", choice)
            return
        self._apply_ssh_host_config(host)
        log.info("Imported SSH config for host: %s", host.alias)

    def _import_from_ssh_config_file(self) -> None:
        """Let user pick a custom SSH config file and import hosts from it."""
        from pathlib import Path

        from core.ssh_config import parse_ssh_config

        default_dir = str(Path.home() / ".ssh")
        path, _ = QFileDialog.getOpenFileName(
            self, tr("Select SSH Config File"), default_dir, tr("All Files (*)")
        )
        if not path:
            return

        hosts = parse_ssh_config(Path(path))
        if not hosts:
            QMessageBox.information(self, tr("SSH Config"), tr("No hosts found in {source}").format(source=path))
            return

        names = [h.alias for h in hosts]
        from PyQt6.QtWidgets import QInputDialog

        choice, ok = QInputDialog.getItem(
            self, tr("Import SSH Config"), tr("Select host:"), names, editable=False
        )
        if not ok:
            return

        host = next((h for h in hosts if h.alias == choice), None)
        if host is None:
            log.warning("SSH import: host %r no longer in list", choice)
            return
        self._apply_ssh_host_config(host)
        log.info("Imported SSH config from file %s, host: %s", path, host.alias)

    def _apply_ssh_host_config(self, host) -> None:
        self._profile_name.setText(host.alias)
        self._host.setText(host.hostname or host.alias)
        if host.port:
            self._port.setValue(host.port)
        if host.user:
            self._username.setText(host.user)
        if host.identity_file:
            self._auth_key.setChecked(True)
            self._key_file.setText(host.identity_file)
        else:
            self._auth_password.setChecked(True)
            self._key_file.clear()
        self._proxy_command.setText(host.proxy_command or "")
        if host.proxy_command:
            self._proxy_group.setChecked(True)
        elif self._proxy_type.currentIndex() == 0 and not self._proxy_host.text().strip():
            self._proxy_group.setChecked(False)
        addr_map = {"auto": 0, "ipv4": 1, "ipv6": 2}
        self._addr_family.setCurrentIndex(addr_map.get(host.address_family, 0))

    def _deploy_ssh_key(self) -> None:
        """Deploy a public SSH key to the remote server (like ssh-copy-id)."""
        if not self._validate():
            return

        from pathlib import Path

        # Find public key to deploy
        ssh_dir = Path.home() / ".ssh"
        pub_keys = sorted(ssh_dir.glob("*.pub")) if ssh_dir.exists() else []

        if not pub_keys:
            QMessageBox.warning(
                self,
                tr("Deploy Key"),
                tr("No public keys found in ~/.ssh/.\nGenerate one first with: ssh-keygen -t ed25519"),
            )
            return

        key_names = [k.name for k in pub_keys]
        from PyQt6.QtWidgets import QInputDialog

        choice, ok = QInputDialog.getItem(
            self, tr("Deploy SSH Key"), tr("Select public key to deploy:"), key_names, editable=False
        )
        if not ok:
            return

        pub_key_path = ssh_dir / choice
        try:
            pub_key_content = pub_key_path.read_text().strip()
        except OSError as e:
            QMessageBox.critical(self, tr("Error"), tr("Could not read {path}:\n{error}").format(path=pub_key_path, error=e))
            return

        # Connect and deploy - on a worker (ui.off_gui): the connect, the
        # look at ~/.ssh and the write are round trips that froze every
        # window. The host-key question comes back to this thread
        # (core.connect_worker.HostKeyPrompt), as for every connect.
        from PyQt6.QtCore import Qt as _Qt

        from core.connect_worker import HostKeyPrompt
        from ui.off_gui import run_off_gui

        profile = self._build_profile()
        password = self._password.text()
        key_passphrase = self._key_passphrase.text()
        self._btn_deploy_key.setEnabled(False)
        self._btn_deploy_key.setText(tr("Deploying…"))
        bridge = HostKeyPrompt()
        bridge.set_prompt(self._confirm_unknown_host)
        bridge.request.connect(bridge.handle_request, _Qt.ConnectionType.QueuedConnection)

        from core.connection_manager import effective_profile

        def deploy() -> str:
            # The route a Connect takes (the default proxy, PAC, bypass
            # list), resolved here off the GUI thread (a PAC script is
            # fetched): SSHSession(profile) took a profile set to "default
            # proxy" for one without a proxy and went to the server directly.
            session = SSHSession(effective_profile(profile))
            try:
                session.connect(
                    password=password,
                    key_passphrase=key_passphrase,
                    on_unknown_host=bridge.ask,
                )
                ssh_dir = session.join(session.home(), ".ssh")
                authorized_keys = session.join(ssh_dir, "authorized_keys")
                pub_key_bytes = pub_key_content.encode("utf-8")

                if not session.exists(ssh_dir):
                    session.mkdir(ssh_dir)
                    log.info("Created remote .ssh directory: %s", ssh_dir)

                try:
                    session.chmod(ssh_dir, 0o700)
                except OSError as e:
                    log.warning("Could not chmod %s to 700: %s", ssh_dir, e)

                if session.exists(authorized_keys):
                    with session.open_read(authorized_keys) as f:
                        existing = f.read()
                else:
                    existing = b""

                if pub_key_bytes in existing.splitlines():
                    return "present"

                new_content = bytearray(existing)
                if new_content and not new_content.endswith(b"\n"):
                    new_content.extend(b"\n")
                new_content.extend(pub_key_bytes)
                new_content.extend(b"\n")

                from core.atomic_io import atomic_write

                atomic_write(session, authorized_keys, bytes(new_content))

                try:
                    session.chmod(authorized_keys, 0o600)
                except OSError as e:
                    log.warning("Could not chmod %s to 600: %s", authorized_keys, e)
                return "deployed"
            finally:
                try:
                    session.disconnect()
                except Exception:
                    log.debug("Failed to disconnect deploy-key session cleanly", exc_info=True)

        try:
            outcome = run_off_gui(deploy)
        except Exception as e:
            QMessageBox.critical(self, tr("Deploy Key Failed"), str(e))
            log.error("SSH key deployment failed: %s", e)
            return
        finally:
            self._btn_deploy_key.setEnabled(True)
            self._btn_deploy_key.setText(tr("Deploy SSH Key"))
        if outcome == "present":
            log.info("SSH key %s already present on %s", choice, profile.host)
            QMessageBox.information(
                self, tr("Deploy Key"), tr("Key {key} is already deployed on this server.").format(key=choice)
            )
            return
        QMessageBox.information(
            self,
            tr("Deploy Key"),
            tr("Successfully deployed {key} to {host}.\n\n"
               "You can now switch to SSH Key authentication.").format(key=choice, host=profile.host),
        )
        log.info("Deployed SSH key %s to %s", choice, profile.host)

    def _confirm_unknown_host(self, error: UnknownHostKeyError) -> bool:
        reply = QMessageBox.question(
            self,
            tr("Trust Host Key?"),
            tr("The host {host} is not present in known_hosts.\n\nKey type: {key_type}\n"
               "SHA256:{fingerprint}\n\nTrust this host key and continue?").format(
                host=error.host, key_type=error.key_type,
                fingerprint=error.fingerprint_sha256),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            # Enter must not trust a key nobody compared: No is the default.
            QMessageBox.StandardButton.No,
        )
        trusted = reply == QMessageBox.StandardButton.Yes
        # The error is raised next: core.user_errors words a No apart.
        error.declined = not trusted
        return trusted
