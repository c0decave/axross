"""LLM profiles: which server the Analysis dock's LLM mode talks to.

Profiles are saved without keys (``core.llm_profiles``); an API key typed
here goes to the system keyring and is never shown again - an empty field
keeps the stored key. A profile whose endpoint is not on this machine or a
private network shows a warning: analysing a file with it sends the file.

"Fetch models" asks the server for its model list on a background thread
(``core.agent.list_models``, no sift needed; no file is sent, nothing is
generated).
"""

from __future__ import annotations

import threading
from pathlib import Path

from PyQt6.QtCore import QObject, Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QDoubleSpinBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from core import llm_profiles as LP
from core.i18n import tr
from ui.close_corner import add_close_corner


class _ModelFetcher(QObject):
    done = pyqtSignal(int, object, str)  # token, models, error


class LLMSettingsDialog(QDialog):
    def __init__(self, parent=None, *, settings_path: Path | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(tr("LLM Profiles"))
        self.resize(720, 460)
        self._path = settings_path
        self._settings = LP.LLMSettings.load(settings_path)
        #: Keys and the active choice follow the profile, not its name: a
        #: rename moves the key, a deleted profile's key is deleted, and a new
        #: profile that reuses a deleted name starts without one.
        self._origin: dict[int, str] = {id(p): p.name for p in self._settings.profiles}
        #: Stored names of profiles deleted in this dialog. Their id() leaves
        #: _origin at once: a new profile may get the same address.
        self._deleted: list[str] = []
        active = self._settings.active_profile()
        self._active_id: int | None = id(active) if active is not None else None
        #: Keys typed in this dialog, by id() of their profile; saved on Save.
        self._new_keys: dict[int, str] = {}
        self._current: LP.LLMProfile | None = None
        self._loading = False
        self._fetcher = _ModelFetcher()
        self._fetcher.done.connect(self._on_models)
        self._fetch_token = 0

        self.profile_list = QListWidget()
        self.profile_list.currentRowChanged.connect(self._show_row)
        add_btn = QPushButton(tr("Add"))
        add_btn.clicked.connect(self.add_profile)
        del_btn = QPushButton(tr("Delete"))
        del_btn.clicked.connect(self.delete_profile)
        active_btn = QPushButton(tr("Use for analysis"))
        active_btn.clicked.connect(self.make_active)
        left = QVBoxLayout()
        left.addWidget(self.profile_list, 1)
        row = QHBoxLayout()
        row.addWidget(add_btn)
        row.addWidget(del_btn)
        left.addLayout(row)
        left.addWidget(active_btn)

        self.name_edit = QLineEdit()
        self.provider_combo = QComboBox()
        self.provider_combo.addItems(LP.PROVIDERS)
        self.endpoint_edit = QLineEdit()
        self.model_combo = QComboBox()
        self.model_combo.setEditable(True)
        fetch_btn = QPushButton(tr("Fetch models"))
        fetch_btn.clicked.connect(self.fetch_models)
        model_row = QHBoxLayout()
        model_row.addWidget(self.model_combo, 1)
        model_row.addWidget(fetch_btn)
        self.key_edit = QLineEdit()
        self.key_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.temperature_spin = QDoubleSpinBox()
        self.temperature_spin.setRange(0.0, 2.0)
        self.temperature_spin.setSingleStep(0.1)
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(1, 3600)
        self.timeout_spin.setSuffix(" s")
        self.max_tokens_spin = QSpinBox()
        self.max_tokens_spin.setRange(1, 1_000_000)
        self.load_check = QCheckBox(
            tr("May load a model that is not in memory (evicts the loaded one)")
        )
        self.remote_label = QLabel()
        self.remote_label.setTextFormat(Qt.TextFormat.PlainText)
        self.remote_label.setWordWrap(True)
        self.remote_label.setStyleSheet("color: #c0392b;")
        self.status_label = QLabel()
        self.status_label.setTextFormat(Qt.TextFormat.PlainText)  # server text is not markup
        self.status_label.setWordWrap(True)

        # What every profile needs; the tuning folds away under Advanced.
        form = QFormLayout()
        form.addRow(tr("Name"), self.name_edit)
        form.addRow(tr("Provider"), self.provider_combo)
        form.addRow(tr("Endpoint"), self.endpoint_edit)
        form.addRow(tr("Model"), model_row)
        form.addRow(tr("API key"), self.key_edit)
        self.advanced_button = QPushButton(tr("Advanced ▸"))
        self.advanced_button.setCheckable(True)
        self.advanced_button.setFlat(True)
        self.advanced_box = QWidget()
        advanced = QFormLayout(self.advanced_box)
        advanced.setContentsMargins(0, 0, 0, 0)
        advanced.addRow(tr("Temperature"), self.temperature_spin)
        advanced.addRow(tr("Timeout per call"), self.timeout_spin)
        advanced.addRow(tr("Max output tokens"), self.max_tokens_spin)
        advanced.addRow("", self.load_check)
        self.advanced_box.setVisible(False)
        self.advanced_button.toggled.connect(self._toggle_advanced)
        right = QVBoxLayout()
        right.addLayout(form)
        right.addWidget(self.advanced_button, 0, Qt.AlignmentFlag.AlignLeft)
        right.addWidget(self.advanced_box)
        right.addWidget(self.remote_label)
        right.addWidget(self.status_label)
        right.addStretch(1)
        self.form_widget = QWidget()
        self.form_widget.setLayout(right)

        top = QHBoxLayout()
        top.addLayout(left, 1)
        top.addWidget(self.form_widget, 2)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self._save_and_close)
        buttons.rejected.connect(self.reject)
        layout = QVBoxLayout(self)
        layout.addLayout(top, 1)
        layout.addWidget(buttons)

        self.endpoint_edit.textChanged.connect(self._update_remote)
        self.name_edit.textChanged.connect(self._store_form)
        self.endpoint_edit.textChanged.connect(self._store_form)
        self.key_edit.textChanged.connect(self._store_form)
        self.provider_combo.currentTextChanged.connect(self._on_provider)
        self.model_combo.editTextChanged.connect(self._store_form)
        for spin in (self.temperature_spin, self.timeout_spin, self.max_tokens_spin):
            spin.valueChanged.connect(self._store_form)
        self.load_check.toggled.connect(self._store_form)

        self._rebuild_list()
        if self._settings.profiles:
            self.profile_list.setCurrentRow(0)
        else:
            self._show_row(-1)
        add_close_corner(self)

    def _toggle_advanced(self, shown: bool) -> None:
        self.advanced_box.setVisible(shown)
        self.advanced_button.setText(tr("Advanced ▾") if shown else tr("Advanced ▸"))

    # -- list --------------------------------------------------------------
    def _label(self, p: LP.LLMProfile) -> str:
        return f"{p.name or tr('(unnamed)')}{'  ✓' if id(p) == self._active_id else ''}"

    def _rebuild_list(self) -> None:
        row = self.profile_list.currentRow()
        self.profile_list.blockSignals(True)
        self.profile_list.clear()
        for p in self._settings.profiles:
            self.profile_list.addItem(self._label(p))
        self.profile_list.blockSignals(False)
        if 0 <= row < self.profile_list.count():
            self.profile_list.setCurrentRow(row)

    def add_profile(self) -> None:
        self._settings.profiles.append(LP.LLMProfile(name=""))
        self._rebuild_list()
        self.profile_list.setCurrentRow(len(self._settings.profiles) - 1)
        self.name_edit.setFocus()

    def delete_profile(self) -> None:
        row = self.profile_list.currentRow()
        if not 0 <= row < len(self._settings.profiles):
            return
        removed = self._settings.profiles.pop(row)
        self._new_keys.pop(id(removed), None)
        origin = self._origin.pop(id(removed), None)
        if origin is not None:
            self._deleted.append(origin)
        if id(removed) == self._active_id:
            self._active_id = None
        self._current = None
        self._rebuild_list()
        self._show_row(min(row, len(self._settings.profiles) - 1))

    def make_active(self) -> None:
        if self._current is not None:
            self._active_id = id(self._current)
            self._rebuild_list()

    # -- form --------------------------------------------------------------
    def _show_row(self, row: int) -> None:
        self._fetch_token += 1  # a model list still on its way belongs to the row left
        self._loading = True
        try:
            if not 0 <= row < len(self._settings.profiles):
                self._current = None
                self.form_widget.setEnabled(False)
                return
            p = self._settings.profiles[row]
            self._current = p
            self.form_widget.setEnabled(True)
            self.name_edit.setText(p.name)
            self.provider_combo.setCurrentText(p.provider)
            self.endpoint_edit.setText(p.endpoint)
            self.endpoint_edit.setPlaceholderText(LP.DEFAULT_ENDPOINTS.get(p.provider, ""))
            self.model_combo.clear()
            self.model_combo.setEditText(p.model)
            self.key_edit.setText(self._new_keys.get(id(p), ""))
            stored = id(p) in self._origin and bool(LP.get_api_key(self._origin[id(p)]))
            self.key_edit.setPlaceholderText(
                tr("stored in the keyring - type to replace")
                if stored
                else tr("none (most local servers need none)")
            )
            self.temperature_spin.setValue(p.temperature)
            self.timeout_spin.setValue(int(p.timeout))
            self.max_tokens_spin.setValue(p.max_output_tokens)
            self.load_check.setChecked(p.allow_model_load)
            self.status_label.clear()
        finally:
            self._loading = False
        self._update_remote()

    def _on_provider(self, provider: str) -> None:
        self.endpoint_edit.setPlaceholderText(LP.DEFAULT_ENDPOINTS.get(provider, ""))
        self._store_form()
        self._update_remote()

    def _store_form(self, *_args) -> None:
        if self._loading or self._current is None:
            return
        p = self._current
        p.name = self.name_edit.text().strip()
        p.provider = self.provider_combo.currentText()
        p.endpoint = self.endpoint_edit.text().strip()
        p.model = self.model_combo.currentText().strip()
        p.temperature = round(self.temperature_spin.value(), 2)
        p.timeout = float(self.timeout_spin.value())
        p.max_output_tokens = self.max_tokens_spin.value()
        p.allow_model_load = self.load_check.isChecked()
        key = self.key_edit.text()
        if key:
            self._new_keys[id(p)] = key
        else:
            self._new_keys.pop(id(p), None)
        item = self.profile_list.item(self.profile_list.currentRow())
        if item is not None:
            item.setText(self._label(p))

    def _update_remote(self) -> None:
        # The dock's own decision: a proxy on the way counts, and a URL typed
        # half-way ("http://[") is no exception in a slot.
        probe = LP.LLMProfile(
            name="", provider=self.provider_combo.currentText(), endpoint=self.endpoint_edit.text()
        )
        remote = probe.is_remote()
        host = probe.host() or probe.resolved_endpoint()
        self.remote_label.setText(
            tr(
                "Remote endpoint: analysing a file with this profile sends its content to {host}."
            ).format(host=host)
        )
        self.remote_label.setVisible(remote and self._current is not None)

    # -- models ------------------------------------------------------------
    def fetch_models(self) -> None:
        if self._current is None:
            return
        self._store_form()
        profile = LP.LLMProfile(**{**self._current.__dict__})
        origin = self._origin.get(id(self._current))
        key = self._new_keys.get(id(self._current)) or (
            LP.get_api_key(origin) if origin is not None else ""
        )
        self._fetch_token += 1
        token = self._fetch_token
        self.status_label.setText(tr("Asking the server for its models…"))

        def work() -> None:
            from core.agent import AgentError, list_models

            try:
                self._fetcher.done.emit(token, list_models(profile, key), "")
            except AgentError as exc:
                self._fetcher.done.emit(
                    token, None, tr("Listing models failed: {error}").format(error=str(exc))
                )
            except Exception as exc:  # noqa: BLE001 - shown to the user
                self._fetcher.done.emit(
                    token,
                    None,
                    tr("Listing models failed: {error}").format(
                        error=f"{type(exc).__name__}: {exc}"
                    ),
                )

        threading.Thread(target=work, name="axross-llm-models", daemon=True).start()

    def _on_models(self, token: int, models, error: str) -> None:
        if token != self._fetch_token:
            return
        if error:
            self.status_label.setText(error)
            return
        current = self.model_combo.currentText()
        self.model_combo.clear()
        self.model_combo.addItems([str(m) for m in models or []])
        self.model_combo.setEditText(current or (self.model_combo.itemText(0) if models else ""))
        self.status_label.setText(tr("{n} model(s) on the server.").format(n=len(models or [])))

    # -- save --------------------------------------------------------------
    def save(self) -> bool:
        self._store_form()
        names = [p.name for p in self._settings.profiles]
        for p in self._settings.profiles:
            problems = p.problems()
            if problems:
                QMessageBox.warning(
                    self, tr("LLM Profiles"), f"{p.name or tr('(unnamed)')}: " + "; ".join(problems)
                )
                return False
            if names.count(p.name) > 1:
                QMessageBox.warning(
                    self,
                    tr("LLM Profiles"),
                    tr("Two profiles are named {name}.").format(name=p.name),
                )
                return False
        active = next((p for p in self._settings.profiles if id(p) == self._active_id), None)
        self._settings.active = active.name if active is not None else ""
        self._adopt_stored_consents()
        try:
            self._settings.save(self._path)
        except OSError as exc:
            # Nothing was written: leave the keys alone as well.
            QMessageBox.warning(
                self, tr("LLM Profiles"), tr("The profiles could not be saved:") + f"\n{exc}"
            )
            return False
        # Read every key that moves before any entry is touched: two profiles
        # may swap names.
        keys: dict[int, str] = {}
        for p in self._settings.profiles:
            origin = self._origin.get(id(p))
            typed = self._new_keys.get(id(p))
            if typed:
                keys[id(p)] = typed
            elif origin is not None and origin != p.name:
                keys[id(p)] = LP.get_api_key(origin)
        stale = set(self._deleted) | {
            self._origin[id(p)]
            for p in self._settings.profiles
            if id(p) in self._origin and self._origin[id(p)] != p.name
        }
        for name in stale:
            LP.delete_api_key(name)
        for p in self._settings.profiles:
            key = keys.get(id(p))
            if key and not LP.store_api_key(p.name, key):
                QMessageBox.warning(
                    self,
                    tr("LLM Profiles"),
                    tr("The API key of {name} could not be stored: no usable keyring.").format(
                        name=p.name
                    ),
                )
        self._origin = {id(p): p.name for p in self._settings.profiles}
        self._deleted.clear()
        self._new_keys.clear()
        return True

    def _adopt_stored_consents(self) -> None:
        """Take over consents the analysis dock saved while this dialog was open.

        The dialog read the file when it opened and never edits a consent
        itself, so writing its copy back as it is would drop a consent the
        dock remembered in the meantime. A stored consent is only taken
        when it still matches where the profile now sends content.
        """
        stored = LP.LLMSettings.load(self._path)
        for p in self._settings.profiles:
            origin = self._origin.get(id(p))
            other = stored.profile(origin) if origin is not None else None
            if other is None or not other.confirmed_origin:
                continue
            if other.confirmed_origin == p.consent_key():
                p.confirmed_origin = other.confirmed_origin

    def _save_and_close(self) -> None:
        if self.save():
            self.accept()
