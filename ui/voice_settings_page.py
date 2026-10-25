"""The Voice settings page: talking with the Agent dock (core.voice_settings).

A page widget of its own - :meth:`VoicePage.load`, :meth:`is_dirty`,
:meth:`problems`, :meth:`apply`, :meth:`save` - registered as the Voice
page of Edit > Settings… (:func:`register_settings_page`, after Agent).
Constructing it writes nothing and starts nothing (it looks whether each
voice is downloaded). Which server recognises speech is part of each LLM
profile (LLM Profiles, Advanced).

**Voices** - a tab per language: the voice that speaks it, whether it is
downloaded (Download fetches it with its pinned SHA-256, core.voice_models,
off the GUI thread; a second click cancels), **Listen** (the sample
sentences in that voice with the page's values, saved or not - ui.voice.
VoicePreview; a second click stops) and how the voice speaks: speed, pitch,
expressiveness, rhythm, volume and the pause between sentences
(core.voice_settings.TUNING), each with a Reset. Every voice keeps values of
its own; switching the voice shows its values.
"""

from __future__ import annotations

import threading
from pathlib import Path

from PyQt6.QtCore import QObject, Qt, pyqtSignal
from PyQt6.QtGui import QKeySequence
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDoubleSpinBox,
    QFormLayout,
    QHBoxLayout,
    QKeySequenceEdit,
    QLabel,
    QPushButton,
    QSlider,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from core import voice_models as VM
from core import voice_settings as VS
from core.i18n import tr

LANGUAGE_LABELS = {"auto": "Follow the answer", "de": "German", "en": "English"}
VOICE_TAB_LABELS = {"de": "German", "en": "English"}
#: name -> (label, tooltip) of how a voice speaks.
TUNING_LABELS = {
    "speed": ("Speed", "How fast the voice speaks (Piper's length scale)."),
    "pitch": ("Pitch", "Higher or lower, in semitones. Piper has no pitch of its own: the "
                       "speech is made that much slower and then resampled that much higher, "
                       "so its length stays."),
    "expressiveness": ("Expressiveness", "How much the tone varies (Piper's noise scale): "
                                         "less is flatter, more is livelier."),
    "rhythm": ("Rhythm variation", "How much the length of the sounds varies (Piper's noise "
                                   "width scale): less is more even."),
    "volume": ("Volume", "A share of the output volume of Edit > Settings… > Audio."),
    "pause": ("Pause between sentences", "Silence between two sentences."),
}

MODE_LABELS = {
    "push_to_talk": "Push-to-talk - hold the microphone button or the hold key",
    "toggle": "Toggle - click to start, click again or pause to end",
    "conversation": "Conversation - listens again after each spoken answer",
}
AFTER_LABELS = {"insert": "Put it into the task field", "send": "Send it at once"}


def tuning_text(name: str, value: float) -> str:
    """*value* of the TUNING value *name* as the page shows it."""
    if name == "speed":
        return f"{value:.2f}×"
    if name == "pitch":
        return tr("{value} semitones").format(value=f"{value:+.1f}" if value else "0.0")
    if name == "pause":
        return f"{value:.2f} s"
    return f"{round(value * 100)} %"


def _steps(name: str, value: float) -> int:
    return int(round(value / VS.TUNING[name].step))


def _from_steps(name: str, steps: int) -> float:
    return round(steps * VS.TUNING[name].step, 6)


def _megabytes(model: VM.VoiceModel) -> int:
    return round(model.size / (1 << 20))


class _DownloadBridge(QObject):
    progress = pyqtSignal(str, object, object)  # model id, bytes done, total
    finished = pyqtSignal(str, str)  # model id, error ("" = done)


def _download(model, progress, cancel):
    """The download Help > Features… uses (pinned, SHA-256 checked)."""
    return VM.download(model, progress=progress, cancel=cancel)


def _preview():
    from ui.voice import VoicePreview

    return VoicePreview()


class VoicePage(QWidget):
    TITLE = "Voice"

    def __init__(self, parent=None, *, settings: VS.VoiceSettings | None = None,
                 path: Path | None = None, after_save=None, model_ready=None,
                 downloader=None, preview_factory=None) -> None:
        super().__init__(parent)
        #: The store (None: core.voice_settings.settings_file()).
        self._path = path
        #: ``after_save(settings)``: the saved values take effect (the dock).
        self._after_save = after_save
        #: ``model_ready(model)``: the voice is downloaded.
        self._model_ready = model_ready or VM.installed
        #: ``downloader(model, progress(done, total), cancel_event)``
        self._downloader = downloader or _download
        #: ``preview_factory()``: the VoicePreview behind Listen, made on the first click.
        self.preview_factory = preview_factory or _preview
        self._preview = None
        self._preview_lang = ""
        self._download_cancel: threading.Event | None = None
        self._download_lang = ""
        self._downloads = _DownloadBridge(self)  # gone with the page: late signals too
        self._downloads.progress.connect(self._on_download_progress)
        self._downloads.finished.connect(self._on_download_finished)
        #: voice id -> how it speaks, as the page shows it (saved or not).
        self._tuning: dict[str, dict[str, float]] = {}
        form = QFormLayout(self)
        self.output_check = QCheckBox(tr("Read the agent's answers aloud"))
        form.addRow("", self.output_check)
        self.language_combo = self._combo(VS.LANGUAGES, LANGUAGE_LABELS)
        form.addRow(tr("Spoken language"), self.language_combo)
        self.voice_tabs = QTabWidget()
        self.voice_combos: dict[str, QComboBox] = {}
        self.voice_states: dict[str, QLabel] = {}
        self.download_buttons: dict[str, QPushButton] = {}
        self.listen_buttons: dict[str, QPushButton] = {}
        self.voice_messages: dict[str, QLabel] = {}
        self.sliders: dict[str, dict[str, QSlider]] = {}
        self.slider_labels: dict[str, dict[str, QLabel]] = {}
        self.reset_buttons: dict[str, dict[str, QPushButton]] = {}
        self.reset_all_buttons: dict[str, QPushButton] = {}
        for lang in VS.VOICES:
            self.voice_tabs.addTab(self._voice_tab(lang), tr(VOICE_TAB_LABELS[lang]))
        form.addRow(tr("Voices"), self.voice_tabs)
        self.mode_combo = self._combo(VS.INPUT_MODES, MODE_LABELS)
        form.addRow(tr("Microphone"), self.mode_combo)
        self.hotkey_edit = QKeySequenceEdit()
        self.hotkey_edit.setMaximumSequenceLength(1)
        self.hotkey_edit.setToolTip(tr(
            "Held for push-to-talk, pressed for toggle and conversation. A key that types "
            "(a letter, a digit, Space) needs Ctrl, Alt, Shift or Meta."))
        form.addRow(tr("Hold key"), self.hotkey_edit)
        self.after_combo = self._combo(VS.AFTER_RECOGNITION, AFTER_LABELS)
        form.addRow(tr("Recognised text"), self.after_combo)
        self.silence_spin = QDoubleSpinBox()
        self.silence_spin.setRange(*VS.SILENCE_RANGE)
        self.silence_spin.setSingleStep(0.1)
        self.silence_spin.setDecimals(1)
        self.silence_spin.setSuffix(" s")
        form.addRow(tr("Pause that ends speaking"), self.silence_spin)
        note = QLabel(tr(
            "German speech says English terms in English. Voices are downloaded here or in "
            "Help > Features…, group Voice, which also has the speech recognition models. "
            "Which server recognises speech is set per LLM profile (LLM… > Advanced). The "
            "microphone is off in the paranoid security mode; confirmations are always "
            "clicked, never spoken."))
        note.setWordWrap(True)
        form.addRow("", note)
        self.load(settings or VS.VoiceSettings())

    # -- the voices ------------------------------------------------------------------------

    def _voice_tab(self, lang: str) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        top = QHBoxLayout()
        combo = QComboBox()
        for voice_id in VS.VOICES[lang]:
            combo.addItem(tr(VM.model(voice_id).title), voice_id)
        combo.currentIndexChanged.connect(lambda _i, lg=lang: self._voice_changed(lg))
        state = QLabel()
        state.setProperty("role", "muted")
        download = QPushButton(tr("Download"))
        download.setToolTip(tr("Download this voice (pinned SHA-256)"))
        download.clicked.connect(lambda _c=False, lg=lang: self._toggle_download(lg))
        listen = QPushButton(tr("Listen"))
        listen.setToolTip(tr("Speak a sample with the values below, saved or not; click "
                             "again to stop"))
        listen.clicked.connect(lambda _c=False, lg=lang: self._toggle_listen(lg))
        for widget in (combo, state, download, listen):
            top.addWidget(widget)
        top.addStretch(1)
        layout.addLayout(top)
        values = QFormLayout()
        self.sliders[lang], self.slider_labels[lang], self.reset_buttons[lang] = {}, {}, {}
        for name, limits in VS.TUNING.items():
            label, tip = TUNING_LABELS[name]
            slider = QSlider(Qt.Orientation.Horizontal)
            slider.setRange(_steps(name, limits.low), _steps(name, limits.high))
            slider.setSingleStep(1)
            slider.setPageStep(max(1, _steps(name, limits.high - limits.low) // 10))
            slider.setToolTip(tr(tip))
            slider.valueChanged.connect(lambda steps, lg=lang, n=name: self._slid(lg, n, steps))
            shown = QLabel()
            shown.setMinimumWidth(shown.fontMetrics().horizontalAdvance("+0.0 semitones__"))
            reset = QPushButton(tr("Reset"))
            reset.setToolTip(tr("Back to {value}").format(value=tuning_text(name,
                                                                             limits.default)))
            reset.clicked.connect(lambda _c=False, lg=lang, n=name: self._reset(lg, (n,)))
            row = QHBoxLayout()
            row.addWidget(slider, 1)
            row.addWidget(shown)
            row.addWidget(reset)
            values.addRow(tr(label), row)
            self.sliders[lang][name], self.slider_labels[lang][name] = slider, shown
            self.reset_buttons[lang][name] = reset
        layout.addLayout(values)
        bottom = QHBoxLayout()
        reset_all = QPushButton(tr("Reset All"))
        reset_all.setToolTip(tr("Every value of this voice back to its default"))
        reset_all.clicked.connect(lambda _c=False, lg=lang: self._reset(lg, tuple(VS.TUNING)))
        message = QLabel()
        message.setWordWrap(True)
        message.setTextFormat(Qt.TextFormat.PlainText)
        bottom.addWidget(reset_all)
        bottom.addWidget(message, 1)
        layout.addLayout(bottom)
        self.voice_combos[lang], self.voice_states[lang] = combo, state
        self.download_buttons[lang], self.listen_buttons[lang] = download, listen
        self.reset_all_buttons[lang], self.voice_messages[lang] = reset_all, message
        return tab

    def _voice(self, lang: str) -> str:
        return self.voice_combos[lang].currentData()

    def _voice_changed(self, lang: str) -> None:
        self._show_tuning(lang)
        self._show_state(lang)

    def _show_tuning(self, lang: str) -> None:
        """The sliders of *lang* show its voice's values (without writing them)."""
        tuning = self._tuning.setdefault(self._voice(lang), VS.default_tuning())
        for name, slider in self.sliders[lang].items():
            slider.blockSignals(True)
            slider.setValue(_steps(name, tuning[name]))
            slider.blockSignals(False)
            self.slider_labels[lang][name].setText(tuning_text(name, tuning[name]))

    def _slid(self, lang: str, name: str, steps: int) -> None:
        value = _from_steps(name, steps)
        self._tuning.setdefault(self._voice(lang), VS.default_tuning())[name] = value
        self.slider_labels[lang][name].setText(tuning_text(name, value))

    def _reset(self, lang: str, names) -> None:
        for name in names:
            self.sliders[lang][name].setValue(_steps(name, VS.TUNING[name].default))
            # A hand-edited value between two steps may not move the slider.
            self._slid(lang, name, _steps(name, VS.TUNING[name].default))

    def _show_state(self, lang: str) -> None:
        model = VM.model(self._voice(lang))
        downloading = self._download_lang == lang
        ready = not downloading and self._model_ready(model)
        if downloading:
            self.voice_states[lang].setText(tr("Downloading…"))
        elif ready:
            self.voice_states[lang].setText(tr("Downloaded"))
        else:
            self.voice_states[lang].setText(tr("Not downloaded ({size} MB)").format(
                size=_megabytes(model)))
        button = self.download_buttons[lang]
        button.setVisible(not ready)
        button.setText(tr("Cancel") if downloading else tr("Download"))
        button.setEnabled(downloading or self._download_cancel is None)

    # -- Download --------------------------------------------------------------------------

    def _toggle_download(self, lang: str) -> None:
        if self._download_cancel is not None:
            if self._download_lang == lang:
                self._download_cancel.set()  # the download stops and leaves nothing behind
            return
        model = VM.model(self._voice(lang))
        cancel = self._download_cancel = threading.Event()
        self._download_lang = lang
        bridge, downloader = self._downloads, self._downloader
        for each in self.voice_combos:
            self._show_state(each)
        self.voice_messages[lang].setText(tr("Downloading {name}…").format(name=model.title))

        def work() -> None:
            try:
                downloader(model, lambda done, total: bridge.progress.emit(model.id, done, total),
                           cancel)
                error = ""
            except VM.DownloadCancelled:
                error = tr("cancelled")
            except VM.DownloadError as exc:
                error = str(exc) or tr("failed")
            except Exception as exc:  # noqa: BLE001 - shown on the page
                error = f"{type(exc).__name__}: {exc}"
            try:
                bridge.finished.emit(model.id, error)
            except RuntimeError:  # the page is gone
                pass

        threading.Thread(target=work, name="axross-voice-download", daemon=True).start()

    def _on_download_progress(self, model_id: str, done, total) -> None:
        if not self._download_lang:
            return
        model = VM.model(model_id)
        percent = int(100 * done / total) if total else 0
        self.voice_messages[self._download_lang].setText(
            tr("Downloading {name}: {percent} %").format(name=model.title, percent=percent))

    def _on_download_finished(self, model_id: str, error: str) -> None:
        lang, self._download_lang, self._download_cancel = self._download_lang, "", None
        model = VM.model(model_id)
        if not error:
            from core import features as F

            F.refresh_availability()  # Help > Features… shows it downloaded
        for each in self.voice_combos:
            self._show_state(each)
        if lang:
            self.voice_messages[lang].setText(
                tr("Download of {name} failed: {error}").format(name=model.title, error=error)
                if error else tr("{name}: downloaded and verified").format(name=model.title))

    # -- Listen ----------------------------------------------------------------------------

    def _toggle_listen(self, lang: str) -> None:
        if self._preview is None:
            self._preview = self.preview_factory()
            self._preview.setParent(self)
            self._preview.busy_changed.connect(self._on_preview_busy)
            self._preview.message.connect(self._on_preview_message)
        voice = self._voice(lang)
        if self._preview_lang == lang and self._preview.playing_voice == voice:
            self._preview.stop()
            return
        self._preview_lang = lang
        self._preview.play(voice, dict(self._tuning.setdefault(voice, VS.default_tuning())))

    def _on_preview_busy(self, voice_id: str) -> None:
        if not voice_id:
            for button in self.listen_buttons.values():
                button.setText(tr("Listen"))
            return
        for lang, button in self.listen_buttons.items():
            button.setText(tr("Stop") if lang == self._preview_lang else tr("Listen"))

    def _on_preview_message(self, text: str) -> None:
        if self._preview_lang:
            self.voice_messages[self._preview_lang].setText(text)

    def shutdown(self) -> None:
        """The dialog closes: listening stops, a download is cancelled."""
        if self._preview is not None:
            self._preview.shutdown()
        if self._download_cancel is not None:
            self._download_cancel.set()

    # -- the page protocol -----------------------------------------------------------------

    def is_dirty(self) -> bool:
        return self.values() != self._baseline

    @staticmethod
    def _combo(values, labels) -> QComboBox:
        combo = QComboBox()
        for value in values:
            combo.addItem(tr(labels[value]), value)
        return combo

    def load(self, settings: VS.VoiceSettings) -> None:
        self.output_check.setChecked(settings.output_enabled)
        self._tuning = {voice_id: settings.tuning_for(voice_id)
                        for ids in VS.VOICES.values() for voice_id in ids}
        for combo, value in ((self.language_combo, settings.language),
                             (self.voice_combos["de"], settings.voice_de),
                             (self.voice_combos["en"], settings.voice_en),
                             (self.mode_combo, settings.input_mode),
                             (self.after_combo, settings.after_recognition)):
            combo.setCurrentIndex(max(0, combo.findData(value)))
        for lang in self.voice_combos:
            self._voice_changed(lang)
        self.hotkey_edit.setKeySequence(QKeySequence(settings.hotkey))
        self.silence_spin.setValue(settings.silence_seconds)
        self._baseline = self.values()

    def _hotkey(self) -> str:
        return self.hotkey_edit.keySequence().toString(QKeySequence.SequenceFormat.PortableText)

    def values(self) -> dict:
        return {
            "output_enabled": self.output_check.isChecked(),
            "language": self.language_combo.currentData(),
            "voice_de": self._voice("de"),
            "voice_en": self._voice("en"),
            "tuning": {v: dict(t) for v, t in self._tuning.items()
                       if t != VS.default_tuning()},
            "input_mode": self.mode_combo.currentData(),
            "hotkey": self._hotkey(),
            "after_recognition": self.after_combo.currentData(),
            "silence_seconds": round(self.silence_spin.value(), 1),
        }

    def problems(self) -> list[str]:
        out = []
        for name, value in self.values().items():
            if not VS.FIELDS[name](value):
                out.append(
                    tr("The hold key {key} is not usable: it needs Ctrl, Alt, Shift or Meta, or "
                       "a key that types nothing (F1-F35, Pause, …).").format(key=value or "-")
                    if name == "hotkey" else tr("Invalid voice setting: {name}").format(name=name))
        return out

    def apply(self, settings: VS.VoiceSettings) -> VS.VoiceSettings:
        """*settings* with the page's values (ValueError for an invalid one)."""
        for name, value in self.values().items():
            settings.set(name, value)
        return settings

    def save(self, path: Path | None = None) -> bool:
        """Store the page's values (OSError on a disk error) and let them
        take effect; False when a value is invalid."""
        if self.problems():
            return False
        path = path if path is not None else self._path
        settings = self.apply(VS.VoiceSettings.load(path))
        settings.save(path)
        self._baseline = self.values()
        if self._after_save is not None:
            self._after_save(settings)
        return True


KEYWORDS = ("voice", "speech", "microphone", "speaker", "hold key", "hotkey", "whisper", "piper",
            "conversation", "push-to-talk", "read aloud", "listen", "speed", "pitch",
            "expressiveness", "rhythm", "volume", "pause", "download")


def _settings_page(parent, window) -> VoicePage:
    dock = getattr(window, "_agent_dock", None)
    reload_voice = getattr(dock, "reload_voice", None)
    return VoicePage(parent, settings=VS.VoiceSettings.load(),
                     after_save=(lambda _s: reload_voice()) if callable(reload_voice) else None)


def register_settings_page() -> None:
    """The Voice page in Edit > Settings… (its slot is after Agent).
    Registering again replaces it - every Agent dock does it."""
    from ui.settings_dialog import register_page

    register_page("voice", tr(VoicePage.TITLE), _settings_page, keywords=KEYWORDS)
