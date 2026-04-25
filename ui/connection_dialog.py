"""Connection dialog for creating/editing connection profiles (multi-protocol)."""
from __future__ import annotations

import logging
from pathlib import Path

from PyQt6.QtCore import QThread, Qt, pyqtSignal
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
    QMessageBox,
    QPushButton,
    QRadioButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from core.backend_registry import all_backends, init_registry
from core.profiles import ConnectionProfile, ProfileManager
from core.ssh_client import SSHSession, UnknownHostKeyError

log = logging.getLogger(__name__)


class _ConnectThread(QThread):
    """Background thread for test connection to avoid freezing the UI."""
    success = pyqtSignal(str)  # home directory
    error = pyqtSignal(str)  # error message

    def __init__(self, profile: ConnectionProfile, password: str, key_passphrase: str, parent=None):
        super().__init__(parent)
        self._profile = profile
        self._password = password
        self._key_passphrase = key_passphrase

    def run(self) -> None:
        try:
            from core.connection_manager import ConnectionManager
            mgr = ConnectionManager()
            session = mgr.connect(
                self._profile,
                password=self._password,
                key_passphrase=self._key_passphrase,
            )
            home = session.home()
            mgr.disconnect_all()
            self.success.emit(home)
        except Exception as e:
            self.error.emit(str(e))


class ConnectionDialog(QDialog):
    """Dialog for creating/editing connection profiles and connecting."""

    def __init__(
        self,
        profile_manager: ProfileManager,
        parent: QWidget | None = None,
        profile: ConnectionProfile | None = None,
    ):
        super().__init__(parent)
        self._profile_manager = profile_manager
        self._result_profile: ConnectionProfile | None = None
        self._result_password: str = ""
        self._result_key_passphrase: str = ""
        self._loaded_profile_name: str | None = None

        self.setWindowTitle("Connect to Server")
        self.setMinimumWidth(500)
        init_registry()
        self._setup_ui()

        if profile:
            self._load_profile(profile)

    @property
    def result_profile(self) -> ConnectionProfile | None:
        return self._result_profile

    @property
    def result_password(self) -> str:
        return self._result_password

    @property
    def result_key_passphrase(self) -> str:
        return self._result_key_passphrase

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)

        # Profile selector
        profile_layout = QHBoxLayout()
        profile_layout.addWidget(QLabel("Profile:"))
        self._profile_combo = QComboBox()
        self._profile_combo.setEditable(False)
        self._profile_combo.addItem("(New Connection)")
        for name in self._profile_manager.list_names():
            self._profile_combo.addItem(name)
        self._profile_combo.currentTextChanged.connect(self._on_profile_selected)
        profile_layout.addWidget(self._profile_combo, stretch=1)

        self._btn_save_profile = QPushButton("Save")
        self._btn_save_profile.clicked.connect(self._save_profile)
        profile_layout.addWidget(self._btn_save_profile)

        self._btn_delete_profile = QPushButton("Delete")
        self._btn_delete_profile.clicked.connect(self._delete_profile)
        profile_layout.addWidget(self._btn_delete_profile)

        layout.addLayout(profile_layout)

        # Connection settings
        conn_group = QGroupBox("Connection")
        conn_form = QFormLayout(conn_group)

        self._profile_name = QLineEdit()
        self._profile_name.setPlaceholderText("Profile name (for saving)")
        conn_form.addRow("Name:", self._profile_name)

        # Protocol selector
        self._protocol_combo = QComboBox()
        backends = all_backends()
        self._protocol_ids: list[str] = []
        for info in backends:
            label = info.display_name
            if not info.available:
                extra = info.required_extra or info.protocol_id
                label += f"  (pip install axross[{extra}])"
            self._protocol_combo.addItem(label)
            self._protocol_ids.append(info.protocol_id)
        # Default to SFTP
        if "sftp" in self._protocol_ids:
            self._protocol_combo.setCurrentIndex(self._protocol_ids.index("sftp"))
        self._protocol_combo.currentIndexChanged.connect(self._on_protocol_changed)
        conn_form.addRow("Protocol:", self._protocol_combo)

        self._host = QLineEdit()
        self._host.setPlaceholderText("hostname or IP")
        conn_form.addRow("Host:", self._host)

        self._port = QSpinBox()
        self._port.setRange(1, 65535)
        self._port.setValue(22)
        conn_form.addRow("Port:", self._port)

        self._username = QLineEdit()
        conn_form.addRow("Username:", self._username)

        # Address family
        self._addr_family = QComboBox()
        self._addr_family.addItems(["Auto", "IPv4 only", "IPv6 only"])
        conn_form.addRow("IP Version:", self._addr_family)

        # --- Protocol-specific fields ---

        # FTP: passive mode
        self._ftp_passive = QCheckBox("Passive mode (recommended)")
        self._ftp_passive.setChecked(True)
        conn_form.addRow("FTP Mode:", self._ftp_passive)

        # SMB: share name
        self._smb_share = QLineEdit()
        self._smb_share.setPlaceholderText("Share name (e.g. Documents)")
        conn_form.addRow("Share:", self._smb_share)

        # WebDAV: full URL
        self._webdav_url = QLineEdit()
        self._webdav_url.setPlaceholderText("https://cloud.example.com/remote.php/dav")
        conn_form.addRow("URL:", self._webdav_url)

        # S3: bucket, region, endpoint
        self._s3_bucket = QLineEdit()
        self._s3_bucket.setPlaceholderText("my-bucket or bucket.s3.region.amazonaws.com")
        conn_form.addRow("Bucket:", self._s3_bucket)

        self._s3_region = QLineEdit()
        self._s3_region.setPlaceholderText("eu-central-1")
        conn_form.addRow("Region:", self._s3_region)

        self._s3_endpoint = QLineEdit()
        self._s3_endpoint.setPlaceholderText("https://s3.example.com (for MinIO, R2, etc.)")
        conn_form.addRow("Endpoint:", self._s3_endpoint)

        # --- Rsync fields ---
        self._rsync_module = QLineEdit()
        self._rsync_module.setPlaceholderText("module name (for rsyncd)")
        conn_form.addRow("Module:", self._rsync_module)

        self._rsync_ssh = QCheckBox("Use SSH transport (instead of rsyncd)")
        conn_form.addRow("", self._rsync_ssh)

        self._rsync_ssh_key = QLineEdit()
        self._rsync_ssh_key.setPlaceholderText("Path to SSH key (optional)")
        conn_form.addRow("SSH Key:", self._rsync_ssh_key)

        # --- NFS fields ---
        self._nfs_export = QLineEdit()
        self._nfs_export.setPlaceholderText("/srv/nfs/share")
        conn_form.addRow("Export:", self._nfs_export)

        self._nfs_version = QComboBox()
        self._nfs_version.addItems(["NFSv3", "NFSv4"])
        conn_form.addRow("Version:", self._nfs_version)

        # --- Azure fields ---
        self._azure_container = QLineEdit()
        self._azure_container.setPlaceholderText("Container name")
        conn_form.addRow("Container:", self._azure_container)

        self._azure_share = QLineEdit()
        self._azure_share.setPlaceholderText("File share name")
        conn_form.addRow("Share:", self._azure_share)

        self._azure_connection_string = QLineEdit()
        self._azure_connection_string.setPlaceholderText("DefaultEndpointsProtocol=https;AccountName=...")
        self._azure_connection_string.setEchoMode(QLineEdit.EchoMode.Password)
        conn_form.addRow("Conn String:", self._azure_connection_string)

        self._azure_account_name = QLineEdit()
        self._azure_account_name.setPlaceholderText("Storage account name")
        conn_form.addRow("Account:", self._azure_account_name)

        self._azure_sas_token = QLineEdit()
        self._azure_sas_token.setPlaceholderText("?sv=2021-06-08&ss=...")
        self._azure_sas_token.setEchoMode(QLineEdit.EchoMode.Password)
        conn_form.addRow("SAS Token:", self._azure_sas_token)

        # --- OneDrive / SharePoint fields ---
        self._onedrive_client_id = QLineEdit()
        self._onedrive_client_id.setPlaceholderText("Azure App Registration Client ID")
        conn_form.addRow("Client ID:", self._onedrive_client_id)

        self._onedrive_tenant_id = QLineEdit()
        self._onedrive_tenant_id.setPlaceholderText("common")
        self._onedrive_tenant_id.setText("common")
        conn_form.addRow("Tenant ID:", self._onedrive_tenant_id)

        self._sharepoint_site_url = QLineEdit()
        self._sharepoint_site_url.setPlaceholderText("https://company.sharepoint.com/sites/MySite")
        conn_form.addRow("Site URL:", self._sharepoint_site_url)

        # --- Google Drive fields ---
        self._gdrive_client_id = QLineEdit()
        self._gdrive_client_id.setPlaceholderText("Google OAuth Client ID")
        conn_form.addRow("Client ID:", self._gdrive_client_id)

        self._gdrive_client_secret = QLineEdit()
        self._gdrive_client_secret.setEchoMode(QLineEdit.EchoMode.Password)
        self._gdrive_client_secret.setPlaceholderText("Google OAuth Client Secret")
        conn_form.addRow("Client Secret:", self._gdrive_client_secret)

        # --- Dropbox fields ---
        self._dropbox_app_key = QLineEdit()
        self._dropbox_app_key.setPlaceholderText("Dropbox App Key")
        conn_form.addRow("App Key:", self._dropbox_app_key)

        self._dropbox_app_secret = QLineEdit()
        self._dropbox_app_secret.setEchoMode(QLineEdit.EchoMode.Password)
        self._dropbox_app_secret.setPlaceholderText("Dropbox App Secret")
        conn_form.addRow("App Secret:", self._dropbox_app_secret)

        # --- iSCSI fields ---
        self._iscsi_target_iqn = QLineEdit()
        self._iscsi_target_iqn.setPlaceholderText("iqn.2024-01.com.example:storage.target1")
        conn_form.addRow("Target IQN:", self._iscsi_target_iqn)

        self._iscsi_mount_point = QLineEdit()
        self._iscsi_mount_point.setPlaceholderText("/mnt/iscsi (auto if empty)")
        conn_form.addRow("Mount Point:", self._iscsi_mount_point)

        # --- IMAP fields ---
        self._imap_ssl = QCheckBox("Use SSL/TLS (IMAPS, port 993)")
        self._imap_ssl.setChecked(True)
        conn_form.addRow("", self._imap_ssl)

        # Simple password field for non-SSH protocols
        self._simple_password = QLineEdit()
        self._simple_password.setEchoMode(QLineEdit.EchoMode.Password)
        self._simple_password.setPlaceholderText("Enter password")
        conn_form.addRow("Password:", self._simple_password)

        self._simple_store_pw = QCheckBox("Save in keyring")
        conn_form.addRow("", self._simple_store_pw)

        layout.addWidget(conn_group)

        # Authentication
        auth_group = QGroupBox("Authentication")
        auth_layout = QVBoxLayout(auth_group)

        self._auth_password = QRadioButton("Password")
        self._auth_password.setChecked(True)
        self._auth_key = QRadioButton("SSH Key File")
        self._auth_agent = QRadioButton("SSH Agent")

        auth_btn_group = QButtonGroup(self)
        auth_btn_group.addButton(self._auth_password)
        auth_btn_group.addButton(self._auth_key)
        auth_btn_group.addButton(self._auth_agent)

        auth_layout.addWidget(self._auth_password)

        # Password field
        pw_layout = QHBoxLayout()
        self._password = QLineEdit()
        self._password.setEchoMode(QLineEdit.EchoMode.Password)
        self._password.setPlaceholderText("Enter password")
        pw_layout.addWidget(self._password)
        self._store_password = QCheckBox("Save in keyring")
        pw_layout.addWidget(self._store_password)
        auth_layout.addLayout(pw_layout)

        auth_layout.addWidget(self._auth_key)

        # Key file
        key_layout = QHBoxLayout()
        self._key_file = QLineEdit()
        self._key_file.setPlaceholderText("Path to private key")
        key_layout.addWidget(self._key_file)
        self._btn_browse_key = QPushButton("Browse...")
        self._btn_browse_key.clicked.connect(self._browse_key)
        key_layout.addWidget(self._btn_browse_key)
        auth_layout.addLayout(key_layout)

        # Key passphrase
        self._key_passphrase = QLineEdit()
        self._key_passphrase.setEchoMode(QLineEdit.EchoMode.Password)
        self._key_passphrase.setPlaceholderText("Key passphrase (if any)")
        auth_layout.addWidget(self._key_passphrase)

        auth_layout.addWidget(self._auth_agent)

        # Toggle field visibility based on auth type
        self._auth_password.toggled.connect(self._update_auth_fields)
        self._auth_key.toggled.connect(self._update_auth_fields)
        self._auth_agent.toggled.connect(self._update_auth_fields)

        layout.addWidget(auth_group)

        # Proxy settings (collapsible)
        self._proxy_group = QGroupBox("Proxy Settings")
        self._proxy_group.setCheckable(True)
        self._proxy_group.setChecked(False)
        proxy_form = QFormLayout(self._proxy_group)

        self._proxy_type = QComboBox()
        self._proxy_type.addItems(["SOCKS5", "SOCKS4", "HTTP CONNECT"])
        proxy_form.addRow("Type:", self._proxy_type)

        self._proxy_host = QLineEdit()
        self._proxy_host.setPlaceholderText("proxy hostname or IP")
        proxy_form.addRow("Host:", self._proxy_host)

        self._proxy_port = QSpinBox()
        self._proxy_port.setRange(1, 65535)
        self._proxy_port.setValue(1080)
        proxy_form.addRow("Port:", self._proxy_port)

        self._proxy_username = QLineEdit()
        self._proxy_username.setPlaceholderText("(optional)")
        proxy_form.addRow("Username:", self._proxy_username)

        self._proxy_password = QLineEdit()
        self._proxy_password.setEchoMode(QLineEdit.EchoMode.Password)
        self._proxy_password.setPlaceholderText("(optional)")
        proxy_form.addRow("Password:", self._proxy_password)

        self._store_proxy_pw = QCheckBox("Save proxy password in keyring")
        proxy_form.addRow("", self._store_proxy_pw)

        self._proxy_command = QLineEdit()
        self._proxy_command.setPlaceholderText("ssh -W %h:%p jumphost  (overrides proxy above)")
        proxy_form.addRow("ProxyCommand:", self._proxy_command)

        layout.addWidget(self._proxy_group)

        # Buttons
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self._on_accept)
        buttons.rejected.connect(self.reject)

        self._btn_test = QPushButton("Test Connection")
        self._btn_test.clicked.connect(self._test_connection)
        buttons.addButton(self._btn_test, QDialogButtonBox.ButtonRole.ActionRole)

        self._btn_import_ssh = QPushButton("Import SSH Config")
        self._btn_import_ssh.setToolTip("Import host from ~/.ssh/config")
        self._btn_import_ssh.clicked.connect(self._import_from_ssh_config)
        buttons.addButton(self._btn_import_ssh, QDialogButtonBox.ButtonRole.ActionRole)

        self._btn_import_file = QPushButton("Import Config File...")
        self._btn_import_file.setToolTip("Import host from a custom SSH config file")
        self._btn_import_file.clicked.connect(self._import_from_ssh_config_file)
        buttons.addButton(self._btn_import_file, QDialogButtonBox.ButtonRole.ActionRole)

        self._btn_deploy_key = QPushButton("Deploy SSH Key")
        self._btn_deploy_key.setToolTip("Copy your public key to the remote server (like ssh-copy-id)")
        self._btn_deploy_key.clicked.connect(self._deploy_ssh_key)
        buttons.addButton(self._btn_deploy_key, QDialogButtonBox.ButtonRole.ActionRole)

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
        is_smb = proto == "smb"
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
        is_telnet = proto == "telnet"
        is_cloud_oauth = is_onedrive or is_sharepoint or is_gdrive or is_dropbox

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
        needs_simple_pw = proto in (
            "ftp", "ftps", "smb", "webdav", "s3",
            "rsync", "azure_blob", "azure_files", "iscsi", "imap", "telnet",
        )
        self._set_form_row_visible(self._simple_password, needs_simple_pw)
        self._set_form_row_visible(self._simple_store_pw, needs_simple_pw)
        if is_s3:
            self._set_form_label(self._simple_password, "Secret Key:")
            self._simple_password.setPlaceholderText("AWS secret access key")
        elif is_azure:
            self._set_form_label(self._simple_password, "Account Key:")
            self._simple_password.setPlaceholderText("Azure storage account key")
        else:
            self._set_form_label(self._simple_password, "Password:")
            self._simple_password.setPlaceholderText("Enter password")

        # Protocol-specific field visibility
        self._set_form_row_visible(self._ftp_passive, is_ftp)
        self._set_form_row_visible(self._smb_share, is_smb)
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

        # iSCSI
        self._set_form_row_visible(self._iscsi_target_iqn, is_iscsi)
        self._set_form_row_visible(self._iscsi_mount_point, is_iscsi)

        # IMAP
        self._set_form_row_visible(self._imap_ssl, is_imap)

        # Host/Port visibility
        no_host_protos = ("webdav", "s3", "onedrive", "sharepoint", "gdrive", "dropbox")
        needs_host = proto not in no_host_protos
        self._set_form_row_visible(self._host, needs_host)
        self._set_form_row_visible(self._port, needs_host)

        # Username visibility — cloud OAuth protocols don't need it
        needs_username = proto not in ("nfs", "onedrive", "sharepoint", "gdrive", "dropbox")
        self._set_form_row_visible(self._username, needs_username)

        # Username label
        if is_s3:
            self._set_form_label(self._username, "Access Key:")
            self._username.setPlaceholderText("AWS access key ID")
        elif is_azure:
            self._set_form_label(self._username, "Account:")
            self._username.setPlaceholderText("Storage account name")
        else:
            self._set_form_label(self._username, "Username:")
            self._username.setPlaceholderText("")

        # IP version — only relevant for host-based protocols
        self._set_form_row_visible(self._addr_family, needs_host)

        # Update default port
        from core.backend_registry import get as get_backend
        info = get_backend(proto)
        if info:
            self._port.setValue(info.default_port)

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
                label.setText(text)

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
            self, "Select SSH Key", default_dir, "All Files (*)"
        )
        if path:
            self._key_file.setText(path)

    def _on_profile_selected(self, name: str) -> None:
        if name == "(New Connection)":
            self._clear_fields()
            return
        profile = self._profile_manager.get(name)
        if profile:
            self._load_profile(profile)

    def _load_profile(self, p: ConnectionProfile) -> None:
        self._loaded_profile_name = p.name
        self._password.clear()
        self._proxy_password.clear()
        self._key_passphrase.clear()
        self._profile_name.setText(p.name)

        # Protocol
        if p.protocol in self._protocol_ids:
            self._protocol_combo.setCurrentIndex(self._protocol_ids.index(p.protocol))

        self._host.setText(p.host)
        self._port.setValue(p.port)
        self._username.setText(p.username)

        addr_map = {"auto": 0, "ipv4": 1, "ipv6": 2}
        self._addr_family.setCurrentIndex(addr_map.get(p.address_family, 0))

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
        self._nfs_version.setCurrentIndex(0 if p.nfs_version == 3 else 1)
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
        # IMAP
        self._imap_ssl.setChecked(p.imap_ssl)

        if p.proxy_type != "none" or p.proxy_command:
            self._proxy_group.setChecked(True)
            type_map = {"socks5": 0, "socks4": 1, "http": 2}
            self._proxy_type.setCurrentIndex(type_map.get(p.proxy_type, 0))
            self._proxy_host.setText(p.proxy_host)
            self._proxy_port.setValue(p.proxy_port)
            self._proxy_username.setText(p.proxy_username)
            self._store_proxy_pw.setChecked(p.store_proxy_password)
            self._proxy_command.setText(p.proxy_command)
        else:
            self._proxy_group.setChecked(False)
            self._proxy_host.clear()
            self._proxy_port.setValue(1080)
            self._proxy_username.clear()
            self._store_proxy_pw.setChecked(False)
            self._proxy_command.clear()

    def _clear_fields(self) -> None:
        self._loaded_profile_name = None
        self._profile_name.clear()
        if "sftp" in self._protocol_ids:
            self._protocol_combo.setCurrentIndex(self._protocol_ids.index("sftp"))
        self._host.clear()
        self._port.setValue(22)
        self._username.clear()
        self._password.clear()
        self._key_file.clear()
        self._key_passphrase.clear()
        self._store_password.setChecked(False)
        self._auth_password.setChecked(True)
        self._proxy_group.setChecked(False)
        self._proxy_host.clear()
        self._proxy_port.setValue(1080)
        self._proxy_username.clear()
        self._proxy_password.clear()
        self._store_proxy_pw.setChecked(False)
        self._proxy_command.clear()
        self._simple_password.clear()
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
        self._imap_ssl.setChecked(True)

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
        if self._proxy_group.isChecked():
            proxy_map = {0: "socks5", 1: "socks4", 2: "http"}
            proxy_type = proxy_map.get(self._proxy_type.currentIndex(), "socks5")
            proxy_command = self._proxy_command.text().strip()

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
                self._azure_container.text().strip()
                or self._azure_share.text().strip()
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
        else:
            auto_name = f"{username}@{host}"

        # Use appropriate store-password checkbox
        if proto in ("sftp", "scp"):
            store_pw = self._store_password.isChecked()
        else:
            store_pw = self._simple_store_pw.isChecked()

        return ConnectionProfile(
            name=self._profile_name.text().strip() or auto_name,
            protocol=proto,
            host=host,
            port=self._port.value(),
            username=username,
            auth_type=auth_type,
            key_file=self._key_file.text().strip(),
            store_password=store_pw,
            proxy_type=proxy_type,
            proxy_host=self._proxy_host.text().strip(),
            proxy_port=self._proxy_port.value(),
            proxy_username=self._proxy_username.text().strip(),
            store_proxy_password=self._store_proxy_pw.isChecked(),
            proxy_command=proxy_command,
            address_family=address_family,
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
            # IMAP
            imap_ssl=self._imap_ssl.isChecked(),
        )

    def _validate(self) -> bool:
        proto = self._selected_protocol()

        # Check backend availability
        from core.backend_registry import get as get_backend
        info = get_backend(proto)
        if info and not info.available:
            extra = info.required_extra or proto
            QMessageBox.warning(
                self, "Validation",
                f"{info.display_name} is not installed.\n"
                f"Install with: pip install axross[{extra}]"
            )
            return False

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
                QMessageBox.warning(self, "Validation", f"{label} contains invalid characters.")
                return False

        # Protocol-specific validation
        if proto == "rsync":
            if not host:
                QMessageBox.warning(self, "Validation", "Host is required.")
                return False
        elif proto == "nfs":
            if not host:
                QMessageBox.warning(self, "Validation", "Host is required.")
                return False
            if not self._nfs_export.text().strip():
                QMessageBox.warning(self, "Validation", "NFS export path is required.")
                return False
        elif proto in ("azure_blob", "azure_files"):
            cs = self._azure_connection_string.text().strip()
            acct = self._azure_account_name.text().strip()
            if not cs and not acct:
                QMessageBox.warning(
                    self, "Validation",
                    "Either Connection String or Account Name is required.",
                )
                return False
            if proto == "azure_blob" and not self._azure_container.text().strip():
                QMessageBox.warning(self, "Validation", "Container name is required.")
                return False
            if proto == "azure_files" and not self._azure_share.text().strip():
                QMessageBox.warning(self, "Validation", "File share name is required.")
                return False
        elif proto in ("onedrive", "sharepoint"):
            if not self._onedrive_client_id.text().strip():
                QMessageBox.warning(self, "Validation", "Client ID is required. See OAUTH_SETUP.md.")
                return False
            if proto == "sharepoint" and not self._sharepoint_site_url.text().strip():
                QMessageBox.warning(self, "Validation", "SharePoint site URL is required.")
                return False
        elif proto == "gdrive":
            if not self._gdrive_client_id.text().strip():
                QMessageBox.warning(self, "Validation", "Google Client ID is required. See OAUTH_SETUP.md.")
                return False
        elif proto == "dropbox":
            if not self._dropbox_app_key.text().strip():
                QMessageBox.warning(self, "Validation", "Dropbox App Key is required. See OAUTH_SETUP.md.")
                return False
        elif proto == "iscsi":
            if not host:
                QMessageBox.warning(self, "Validation", "Target IP is required.")
                return False
            if not self._iscsi_target_iqn.text().strip():
                QMessageBox.warning(self, "Validation", "Target IQN is required.")
                return False
        elif proto == "webdav":
            url = self._webdav_url.text().strip()
            if not url:
                QMessageBox.warning(self, "Validation", "WebDAV URL is required.")
                return False
        elif proto == "s3":
            bucket = self._s3_bucket.text().strip()
            if not bucket:
                QMessageBox.warning(self, "Validation", "S3 bucket name or URL is required.")
                return False
            # Accept full URLs (https://bucket.s3.region.amazonaws.com) or plain names
            import re
            is_url = any(bucket.startswith(p) for p in ("https://", "http://", "s3://"))
            is_hostname = ".amazonaws.com" in bucket or ".s3." in bucket
            if not is_url and not is_hostname:
                if not re.match(r'^[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]$', bucket):
                    QMessageBox.warning(
                        self, "Validation",
                        "Invalid S3 bucket name. Use a valid bucket name (lowercase, "
                        "3-63 chars) or paste a full S3 URL like:\n"
                        "dev-s1.s3.ap-south-1.amazonaws.com",
                    )
                    return False
            # Access key is optional — anonymous access for public buckets
        elif proto == "smb":
            if not host:
                QMessageBox.warning(self, "Validation", "Host is required.")
                return False
            if not self._smb_share.text().strip():
                QMessageBox.warning(self, "Validation", "SMB share name is required.")
                return False
        else:
            # SFTP, FTP, FTPS need host + username
            if not host:
                QMessageBox.warning(self, "Validation", "Host is required.")
                return False
            if not username:
                QMessageBox.warning(self, "Validation", "Username is required.")
                return False

        if self._proxy_group.isChecked() and not proxy_host and not proxy_command:
            QMessageBox.warning(
                self,
                "Validation",
                "Proxy host or ProxyCommand is required when proxy support is enabled.",
            )
            return False

        # SSH-specific validation
        if proto in ("sftp", "scp"):
            if self._auth_key.isChecked() and not key_file:
                QMessageBox.warning(self, "Validation", "Key file is required for key auth.")
                return False
            if self._auth_key.isChecked():
                key_path = Path(key_file).expanduser()
                if not key_path.is_file():
                    QMessageBox.warning(self, "Validation", "Key file does not exist or is not a file.")
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
        fallback_password = None
        fallback_proxy_password = None
        old_profile_name = self._loaded_profile_name
        if self._loaded_profile_name and self._loaded_profile_name != profile.name:
            old_profile = self._profile_manager.get(self._loaded_profile_name)
            if old_profile:
                fallback_password = old_profile.get_password()
                fallback_proxy_password = old_profile.get_proxy_password()
        try:
            self._profile_manager.add(profile)
            self._store_profile_credentials(
                profile,
                fallback_password=fallback_password,
                fallback_proxy_password=fallback_proxy_password,
            )
            if old_profile_name and old_profile_name != profile.name:
                self._profile_manager.remove(old_profile_name)
        except Exception as e:
            log.error("Failed to store credentials in keyring: %s", e)
            QMessageBox.warning(self, "Keyring Error", f"Could not save credentials:\n{e}")
            return
        self._loaded_profile_name = profile.name
        log.info("Saved profile: %s", profile.name)

        # Update combo
        idx = self._profile_combo.findText(profile.name)
        if idx < 0:
            self._profile_combo.addItem(profile.name)
        self._profile_combo.setCurrentText(profile.name)

        QMessageBox.information(self, "Saved", f"Profile '{profile.name}' saved.")

    def _delete_profile(self) -> None:
        name = self._profile_combo.currentText()
        if name == "(New Connection)":
            return
        reply = QMessageBox.question(
            self, "Delete Profile", f"Delete profile '{name}'?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            try:
                self._profile_manager.remove(name)
                log.info("Deleted profile: %s", name)
            except Exception as e:
                log.error("Failed to delete profile %s: %s", name, e)
                QMessageBox.warning(self, "Error", f"Failed to delete profile:\n{e}")
                return
            idx = self._profile_combo.findText(name)
            if idx >= 0:
                self._profile_combo.removeItem(idx)
            self._clear_fields()

    def _test_connection(self) -> None:
        if not self._validate():
            return
        profile = self._build_profile()
        self._btn_test.setEnabled(False)
        self._btn_test.setText("Connecting...")

        self._connect_thread = _ConnectThread(
            profile, self._effective_password(), self._key_passphrase.text(), parent=self
        )
        self._connect_thread.success.connect(self._on_test_success)
        self._connect_thread.error.connect(self._on_test_error)
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

        # Save password if requested
        try:
            self._store_profile_credentials(self._result_profile)
        except Exception as e:
            log.error("Failed to store credentials in keyring: %s", e)

        self.accept()

    def _on_test_success(self, home: str) -> None:
        QMessageBox.information(
            self, "Success", f"Connection successful!\nHome directory: {home}"
        )

    def _on_test_error(self, error: str) -> None:
        QMessageBox.critical(self, "Connection Failed", error)

    def _on_test_done(self) -> None:
        self._btn_test.setEnabled(True)
        self._btn_test.setText("Test Connection")

    def _store_profile_credentials(
        self,
        profile: ConnectionProfile,
        fallback_password: str | None = None,
        fallback_proxy_password: str | None = None,
    ) -> None:
        password = self._effective_password() or (fallback_password or "")
        if profile.store_password and password:
            profile.set_password(password)

        proxy_password = self._proxy_password.text() or (fallback_proxy_password or "")
        if profile.store_proxy_password and proxy_password:
            profile.set_proxy_password(proxy_password)

    def _import_from_ssh_config(self) -> None:
        """Show SSH config hosts and fill fields from selected host."""
        from core.ssh_config import parse_ssh_config

        hosts = parse_ssh_config()
        if not hosts:
            QMessageBox.information(self, "SSH Config", "No hosts found in ~/.ssh/config")
            return

        names = [h.alias for h in hosts]
        from PyQt6.QtWidgets import QInputDialog
        choice, ok = QInputDialog.getItem(
            self, "Import SSH Config", "Select host:", names, editable=False
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
            self, "Select SSH Config File", default_dir, "All Files (*)"
        )
        if not path:
            return

        hosts = parse_ssh_config(Path(path))
        if not hosts:
            QMessageBox.information(self, "SSH Config", f"No hosts found in {path}")
            return

        names = [h.alias for h in hosts]
        from PyQt6.QtWidgets import QInputDialog
        choice, ok = QInputDialog.getItem(
            self, "Import SSH Config", "Select host:", names, editable=False
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
                self, "Deploy Key",
                "No public keys found in ~/.ssh/.\n"
                "Generate one first with: ssh-keygen -t ed25519"
            )
            return

        key_names = [k.name for k in pub_keys]
        from PyQt6.QtWidgets import QInputDialog
        choice, ok = QInputDialog.getItem(
            self, "Deploy SSH Key", "Select public key to deploy:", key_names, editable=False
        )
        if not ok:
            return

        pub_key_path = ssh_dir / choice
        try:
            pub_key_content = pub_key_path.read_text().strip()
        except OSError as e:
            QMessageBox.critical(self, "Error", f"Could not read {pub_key_path}:\n{e}")
            return

        # Connect and deploy
        profile = self._build_profile()
        self._btn_deploy_key.setEnabled(False)
        self._btn_deploy_key.setText("Deploying...")
        session: SSHSession | None = None

        try:
            session = SSHSession(profile)
            session.connect(
                password=self._password.text(),
                key_passphrase=self._key_passphrase.text(),
                on_unknown_host=self._confirm_unknown_host,
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
                with session.open_write(authorized_keys):
                    pass
                existing = b""

            try:
                session.chmod(authorized_keys, 0o600)
            except OSError as e:
                log.warning("Could not chmod %s to 600: %s", authorized_keys, e)

            if pub_key_bytes in existing.splitlines():
                log.info("SSH key %s already present on %s", choice, profile.host)
                QMessageBox.information(
                    self, "Deploy Key",
                    f"Key {choice} is already deployed on this server."
                )
                return

            with session.open_write(authorized_keys, append=True) as f:
                if existing and not existing.endswith(b"\n"):
                    f.write(b"\n")
                f.write(pub_key_bytes)
                f.write(b"\n")
            session.disconnect()

            QMessageBox.information(
                self, "Deploy Key",
                f"Successfully deployed {choice} to {profile.host}.\n\n"
                "You can now switch to SSH Key authentication."
            )
            log.info("Deployed SSH key %s to %s", choice, profile.host)
        except Exception as e:
            QMessageBox.critical(self, "Deploy Key Failed", str(e))
            log.error("SSH key deployment failed: %s", e)
        finally:
            if session is not None:
                try:
                    session.disconnect()
                except Exception:
                    log.debug("Failed to disconnect deploy-key session cleanly", exc_info=True)
            self._btn_deploy_key.setEnabled(True)
            self._btn_deploy_key.setText("Deploy SSH Key")

    def _confirm_unknown_host(self, error: UnknownHostKeyError) -> bool:
        reply = QMessageBox.question(
            self,
            "Trust Host Key?",
            (
                f"The host {error.host} is not present in known_hosts.\n\n"
                f"Key type: {error.key_type}\n"
                f"SHA256:{error.fingerprint_sha256}\n\n"
                "Trust this host key and continue?"
            ),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        return reply == QMessageBox.StandardButton.Yes
