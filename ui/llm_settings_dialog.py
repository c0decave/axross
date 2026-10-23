"""LLM profiles: which server the Analysis dock's LLM mode talks to.

:class:`LLMProfilesPage` is the page of Edit > Settings…;
:class:`LLMSettingsDialog` is the same form as a dialog of its own.

Profiles are saved without keys (``core.llm_profiles``); an API key typed
here goes to the system keyring and is never shown again - an empty field
keeps the stored key. A profile whose endpoint is not on this machine or a
private network shows a warning: analysing a file with it sends the file.

"Fetch models" asks the server for its model list on a background thread
(``core.agent.model_inventory``, no sift needed; no file is sent, nothing
is generated) and opens the model drop-down: each model with its size,
parameter count and quantisation where the server reports them ("size not
reported" where it does not) and a mark on the loaded one(s).

Speech recognition (the Agent dock's microphone) is part of a profile: a
local Whisper model (nothing leaves the machine) or an OpenAI-compatible
transcription server - the profile's own endpoint, or another one.
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
    QStyledItemDelegate,
    QVBoxLayout,
    QWidget,
)

from core import llm_profiles as LP
from core.i18n import tr
from ui.close_corner import add_close_corner


#: The item role of the model drop-down that holds an entry's label (size,
#: parameters, quantisation, loaded); the item text stays the model id, so
#: picking an entry puts the id into the field.
MODEL_LABEL_ROLE = Qt.ItemDataRole.UserRole + 1


def model_label(entry) -> str:
    """How a model (core.agent.ModelEntry) reads in the drop-down: its id,
    then what the server reported - never an invented size."""
    from ui.format_utils import human_bytes

    parts = [human_bytes(entry.size) if entry.size is not None else tr("size not reported")]
    parts += [p for p in (entry.parameters, entry.quantization) if p]
    if entry.context:
        parts.append(tr("context {n}").format(n=entry.context))
    if entry.loaded:
        parts.append(tr("● loaded"))
    return f"{entry.id}  —  " + " · ".join(parts)


class _ModelLabelDelegate(QStyledItemDelegate):
    """Paints an entry's label in the drop-down instead of the bare id."""

    def initStyleOption(self, option, index) -> None:  # noqa: N802 - Qt override
        super().initStyleOption(option, index)
        label = index.data(MODEL_LABEL_ROLE)
        if isinstance(label, str) and label:
            option.text = label


class _ModelFetcher(QObject):
    done = pyqtSignal(int, object, str)  # token, models, error


class _LLMProfilesForm:
    """The profile list and form; :class:`LLMProfilesPage` (Edit > Settings…)
    and :class:`LLMSettingsDialog` share it. The class it is mixed into is
    the widget."""

    def _build_form(self, settings_path: Path | None) -> QHBoxLayout:
        """Build the form; returns its layout for the widget to place."""
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
        self.model_combo.setItemDelegate(_ModelLabelDelegate(self.model_combo))
        self.fetch_button = QPushButton(tr("Fetch models"))
        self.fetch_button.setToolTip(
            tr("Ask the server for its models: size, parameters, quantisation and which one "
               "is loaded, as far as the server reports them"))
        self.fetch_button.clicked.connect(self.fetch_models)
        model_row = QHBoxLayout()
        model_row.addWidget(self.model_combo, 1)
        model_row.addWidget(self.fetch_button)
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
        self.stt_engine_combo = QComboBox()
        self.stt_engine_combo.addItem(tr("Local (faster-whisper, nothing leaves this machine)"),
                                      "local")
        self.stt_engine_combo.addItem(tr("Server (OpenAI-compatible /audio/transcriptions)"),
                                      "server")
        self.stt_endpoint_edit = QLineEdit()
        self.stt_endpoint_edit.setPlaceholderText(tr("the profile's endpoint"))
        self.stt_model_combo = QComboBox()
        self.stt_model_combo.setEditable(True)
        self.stt_remote_label = QLabel()
        self.stt_remote_label.setTextFormat(Qt.TextFormat.PlainText)
        self.stt_remote_label.setWordWrap(True)
        self.stt_remote_label.setStyleSheet("color: #c0392b;")

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
        speech = QLabel(tr("Speech recognition (Agent dock microphone)"))
        speech.setStyleSheet("font-weight: bold;")
        advanced.addRow(speech)
        advanced.addRow(tr("Recognised by"), self.stt_engine_combo)
        advanced.addRow(tr("Transcription endpoint"), self.stt_endpoint_edit)
        advanced.addRow(tr("Recognition model"), self.stt_model_combo)
        advanced.addRow("", self.stt_remote_label)
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

        self.endpoint_edit.textChanged.connect(self._update_remote)
        self.name_edit.textChanged.connect(self._store_form)
        self.endpoint_edit.textChanged.connect(self._store_form)
        self.key_edit.textChanged.connect(self._store_form)
        self.provider_combo.currentTextChanged.connect(self._on_provider)
        self.model_combo.editTextChanged.connect(self._store_form)
        for spin in (self.temperature_spin, self.timeout_spin, self.max_tokens_spin):
            spin.valueChanged.connect(self._store_form)
        self.load_check.toggled.connect(self._store_form)
        self.stt_engine_combo.currentIndexChanged.connect(self._on_stt_engine)
        self.stt_endpoint_edit.textChanged.connect(self._store_form)
        self.stt_model_combo.editTextChanged.connect(self._store_form)

        self._rebuild_list()
        if self._settings.profiles:
            self.profile_list.setCurrentRow(0)
        else:
            self._show_row(-1)
        return top

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
            self.stt_engine_combo.setCurrentIndex(max(0, self.stt_engine_combo.findData(
                p.stt_engine)))
            self.stt_endpoint_edit.setText(p.stt_endpoint)
            self._fill_stt_models(p.stt_model)
            self.status_label.clear()
        finally:
            self._loading = False
        self._update_remote()
        self._update_stt()

    def _fill_stt_models(self, current: str) -> None:
        from core.voice_models import WHISPER_MODELS

        self.stt_model_combo.blockSignals(True)
        self.stt_model_combo.clear()
        if self.stt_engine_combo.currentData() == "local":
            self.stt_model_combo.addItems(list(WHISPER_MODELS))
            self.stt_model_combo.lineEdit().setPlaceholderText(WHISPER_MODELS[0])
        else:
            self.stt_model_combo.lineEdit().setPlaceholderText("whisper-1")
        self.stt_model_combo.setEditText(current)
        self.stt_model_combo.blockSignals(False)

    def _on_stt_engine(self, *_args) -> None:
        if not self._loading:
            # A local model name means nothing to a server, and the other way round.
            self._fill_stt_models("")
        self._store_form()
        self._update_stt()

    def _update_stt(self) -> None:
        server = self.stt_engine_combo.currentData() == "server"
        self.stt_endpoint_edit.setEnabled(server)
        probe = self._current
        remote = False
        if probe is not None and server:
            target = LP.LLMProfile(name="", provider="openai",
                                   endpoint=probe.stt_resolved_endpoint())
            remote = target.is_remote()
            self.stt_remote_label.setText(tr(
                "Remote transcription server: what you say into the microphone is sent to "
                "{host}.").format(host=target.host() or target.resolved_endpoint()))
        self.stt_remote_label.setVisible(remote)

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
        p.stt_engine = self.stt_engine_combo.currentData() or "local"
        p.stt_endpoint = self.stt_endpoint_edit.text().strip()
        p.stt_model = self.stt_model_combo.currentText().strip()
        key = self.key_edit.text()
        if key:
            self._new_keys[id(p)] = key
        else:
            self._new_keys.pop(id(p), None)
        item = self.profile_list.item(self.profile_list.currentRow())
        if item is not None:
            item.setText(self._label(p))
        self._update_stt()

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
            from core.agent import AgentError, model_inventory

            try:
                self._fetcher.done.emit(token, model_inventory(profile, key), "")
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
        models = list(models or [])
        combo = self.model_combo
        current = combo.currentText()
        combo.blockSignals(True)
        try:
            combo.clear()
            for i, entry in enumerate(models):
                label = model_label(entry)
                combo.addItem(entry.id)
                combo.setItemData(i, label, MODEL_LABEL_ROLE)
                combo.setItemData(i, label, Qt.ItemDataRole.ToolTipRole)
            combo.setEditText(current or (combo.itemText(0) if models else ""))
        finally:
            combo.blockSignals(False)
        self._store_form()
        self.status_label.setText(self._models_status(models))
        if models and combo.isVisible():
            view = combo.view()
            view.setMinimumWidth(max(combo.width(), view.sizeHintForColumn(0) + 32))
            combo.showPopup()

    @staticmethod
    def _models_status(models) -> str:
        """The line under the form: how many, which are loaded - or that the
        server does not say - and whether it reports sizes."""
        lines = [tr("{n} model(s) on the server.").format(n=len(models))]
        if not models:
            return lines[0]
        if all(m.loaded is None for m in models):
            lines.append(tr("The server does not report which model is loaded."))
        else:
            loaded = [m.id for m in models if m.loaded]
            lines.append(tr("Loaded now: {names}.").format(
                names=", ".join(loaded) if loaded else tr("none")))
        if all(m.size is None for m in models):
            lines.append(tr("The server does not report sizes."))
        return " ".join(lines)

    # -- save --------------------------------------------------------------
    def problems(self) -> list[str]:
        """Why the profiles cannot be saved ([] when they can)."""
        self._store_form()
        names = [p.name for p in self._settings.profiles]
        out = []
        for p in self._settings.profiles:
            problems = p.problems()
            if problems:
                out.append(f"{p.name or tr('(unnamed)')}: " + "; ".join(problems))
            if names.count(p.name) > 1:
                out.append(tr("Two profiles are named {name}.").format(name=p.name))
        return list(dict.fromkeys(out))

    def profile_names(self) -> list[str]:
        """The names of the profiles as the form has them now."""
        return [p.name for p in self._settings.profiles if p.name]

    def save(self) -> bool:
        problems = self.problems()
        if problems:
            QMessageBox.warning(self, tr("LLM Profiles"), problems[0])
            return False
        active = next((p for p in self._settings.profiles if id(p) == self._active_id), None)
        if active is None and self._settings.profiles:
            # A set of profiles with none active gave "No LLM profile is
            # active" in the Agent and Analysis docks: the first one is it.
            active = self._settings.profiles[0]
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


class LLMProfilesPage(_LLMProfilesForm, QWidget):
    """Edit > Settings… > LLM Profiles (Tools > LLM Profiles… and the docks'
    settings buttons open it)."""

    def __init__(self, parent=None, *, settings_path: Path | None = None) -> None:
        QWidget.__init__(self, parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addLayout(self._build_form(settings_path), 1)
        # The form as stored values pass through it (a timeout of 30.5 s is
        # a 30 in the spin box): only what the user changes is a change.
        self._store_form()
        self._baseline = self._snapshot()

    def _snapshot(self):
        index = {id(p): i for i, p in enumerate(self._settings.profiles)}
        return (
            tuple(tuple(sorted(vars(p).items())) for p in self._settings.profiles),
            index.get(self._active_id),
            tuple(sorted((index.get(k, -1), v) for k, v in self._new_keys.items())),
            tuple(self._deleted),
        )

    def is_dirty(self) -> bool:
        self._store_form()
        return self._snapshot() != self._baseline

    def save(self) -> bool:
        if not super().save():
            return False
        self._baseline = self._snapshot()
        return True


class LLMSettingsDialog(_LLMProfilesForm, QDialog):
    """The LLM profiles as a dialog of their own (Save / Cancel)."""

    def __init__(self, parent=None, *, settings_path: Path | None = None) -> None:
        QDialog.__init__(self, parent)
        self.setWindowTitle(tr("LLM Profiles"))
        self.resize(720, 460)
        top = self._build_form(settings_path)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self._save_and_close)
        buttons.rejected.connect(self.reject)
        layout = QVBoxLayout(self)
        layout.addLayout(top, 1)
        layout.addWidget(buttons)
        add_close_corner(self)

    def _save_and_close(self) -> None:
        if self.save():
            self.accept()
