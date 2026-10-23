"""The Voice settings page: talking with the Agent dock (core.voice_settings).

A page widget of its own - :meth:`VoicePage.load`, :meth:`is_dirty`,
:meth:`problems`, :meth:`apply`, :meth:`save` - registered as the Voice
page of Edit > Settings… (:func:`register_settings_page`, after Agent).
Constructing it reads and writes nothing. Which server recognises speech is
part of each LLM profile (LLM Profiles, Advanced).
"""

from __future__ import annotations

from pathlib import Path

from PyQt6.QtGui import QKeySequence
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDoubleSpinBox,
    QFormLayout,
    QKeySequenceEdit,
    QLabel,
    QWidget,
)

from core import voice_settings as VS
from core.i18n import tr

LANGUAGE_LABELS = {"auto": "Follow the answer", "de": "German", "en": "English"}
GENDER_LABELS = {"male": "Male", "female": "Female"}
MODE_LABELS = {
    "push_to_talk": "Push-to-talk - hold the microphone button or the hold key",
    "toggle": "Toggle - click to start, click again or pause to end",
    "conversation": "Conversation - listens again after each spoken answer",
}
AFTER_LABELS = {"insert": "Put it into the task field", "send": "Send it at once"}


class VoicePage(QWidget):
    TITLE = "Voice"

    def __init__(self, parent=None, *, settings: VS.VoiceSettings | None = None,
                 path: Path | None = None, after_save=None) -> None:
        super().__init__(parent)
        #: The store (None: core.voice_settings.settings_file()).
        self._path = path
        #: ``after_save(settings)``: the saved values take effect (the dock).
        self._after_save = after_save
        form = QFormLayout(self)
        self.output_check = QCheckBox(tr("Read the agent's answers aloud"))
        form.addRow("", self.output_check)
        self.language_combo = self._combo(VS.LANGUAGES, LANGUAGE_LABELS)
        form.addRow(tr("Spoken language"), self.language_combo)
        self.gender_combo = self._combo(VS.GENDERS, GENDER_LABELS)
        form.addRow(tr("Voice"), self.gender_combo)
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
            "German speech says English terms in English. Voices and the speech recognition "
            "model are downloaded in Help > Features…, group Voice. Which server recognises "
            "speech is set per LLM profile (LLM… > Advanced). The microphone is off in the "
            "paranoid security mode; confirmations are always clicked, never spoken."))
        note.setWordWrap(True)
        form.addRow("", note)
        self.load(settings or VS.VoiceSettings())

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
        for combo, value in ((self.language_combo, settings.language),
                             (self.gender_combo, settings.gender),
                             (self.mode_combo, settings.input_mode),
                             (self.after_combo, settings.after_recognition)):
            combo.setCurrentIndex(max(0, combo.findData(value)))
        self.hotkey_edit.setKeySequence(QKeySequence(settings.hotkey))
        self.silence_spin.setValue(settings.silence_seconds)
        self._baseline = self.values()

    def _hotkey(self) -> str:
        return self.hotkey_edit.keySequence().toString(QKeySequence.SequenceFormat.PortableText)

    def values(self) -> dict:
        return {
            "output_enabled": self.output_check.isChecked(),
            "language": self.language_combo.currentData(),
            "gender": self.gender_combo.currentData(),
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
            "conversation", "push-to-talk", "read aloud")


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
