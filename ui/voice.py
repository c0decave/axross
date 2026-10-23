"""Talking with the Agent dock: microphone, speaker and the voice worker.

:class:`VoiceController` (one per dock) records with QAudioSource, has the
speech recognised (core.voice_worker locally, or the profile's
transcription server through core.voice_stt), and speaks answers and short
phrases with Piper in core.voice_worker, played through QAudioSink. Stop
and any new input end speech at once: the synthesis child is killed and
the queue dropped.

Audio and transcripts stay in memory; nothing of what is said or heard is
logged. The microphone is off in the paranoid security mode. Tool
confirmations are never given by voice - recognised text only ever lands
in the task field or is sent as a task.
"""

from __future__ import annotations

import base64
import threading
from typing import Callable

from PyQt6.QtCore import QObject, QTimer, pyqtSignal

from core import voice_audio as VA
from core import voice_models as VM
from core import voice_settings as VS
from core import voice_text as VT
from core import voice_worker as VW
from core.i18n import tr

#: Longest recording; then it ends by itself.
MAX_RECORD_SECONDS = 60.0
#: Shorter than this is no input.
MIN_RECORD_SECONDS = 0.3
_SPEAK_TIMEOUT = 120.0
_TRANSCRIBE_TIMEOUT = 300.0
_LINE = "I'm sorry, Dave. I'm afraid I can't do that."
_LINE_VOICE = "piper-en-ryan"


# -- sound card -------------------------------------------------------------------------------


class QtRecorder(QObject):
    """The default microphone at 16 kHz mono int16 (converted when the
    device offers something else)."""

    data = pyqtSignal(bytes)

    def __init__(self) -> None:
        super().__init__()
        self._source = None
        self._io = None
        self._convert = None

    def start(self) -> None:
        from PyQt6.QtMultimedia import QAudioFormat, QAudioSource, QMediaDevices

        device = QMediaDevices.defaultAudioInput()
        if device.isNull():
            raise OSError(tr("No microphone found"))
        fmt = QAudioFormat()
        fmt.setSampleRate(VA.RATE)
        fmt.setChannelCount(1)
        fmt.setSampleFormat(QAudioFormat.SampleFormat.Int16)
        if not device.isFormatSupported(fmt):
            fmt = device.preferredFormat()
        names = {QAudioFormat.SampleFormat.Int16: "int16", QAudioFormat.SampleFormat.Int32: "int32",
                 QAudioFormat.SampleFormat.Float: "float", QAudioFormat.SampleFormat.UInt8: "uint8"}
        kind = names.get(fmt.sampleFormat())
        if kind is None:
            raise OSError(tr("The microphone's sample format is not supported"))
        rate, channels = fmt.sampleRate(), fmt.channelCount()
        self._convert = lambda raw: VA.to_mono16k(raw, rate, channels, kind)
        self._source = QAudioSource(device, fmt, self)
        self._io = self._source.start()
        if self._io is None:
            raise OSError(tr("The microphone could not be opened"))
        self._io.readyRead.connect(self._read)

    def _read(self) -> None:
        if self._io is not None:
            raw = bytes(self._io.readAll())
            if raw:
                self.data.emit(self._convert(raw))

    def stop(self) -> None:
        if self._source is not None:
            self._read()
            self._source.stop()
        self._source = self._io = None


def _qt_sink(rate: int):
    """(QAudioSink, its QIODevice, the rate it plays) for mono int16 at
    *rate*, or the device's own rate when it takes no other."""
    from PyQt6.QtMultimedia import QAudio, QAudioFormat, QAudioSink, QMediaDevices

    device = QMediaDevices.defaultAudioOutput()
    if device.isNull():
        raise OSError(tr("No audio output found"))
    fmt = QAudioFormat()
    fmt.setSampleRate(rate)
    fmt.setChannelCount(1)
    fmt.setSampleFormat(QAudioFormat.SampleFormat.Int16)
    if not device.isFormatSupported(fmt):
        fmt.setSampleRate(device.preferredFormat().sampleRate())
        if not device.isFormatSupported(fmt):
            raise OSError(tr("The audio output plays no 16-bit mono sound"))
    sink = QAudioSink(device, fmt)
    sink.setBufferSize(fmt.sampleRate() * 2 // 4)  # 250 ms
    io = sink.start()
    if io is None or sink.error() != QAudio.Error.NoError:
        sink.deleteLater()
        raise OSError(tr("The audio output could not be opened"))
    return sink, io, fmt.sampleRate()


class QtPlayer(QObject):
    """int16 mono chunks through QAudioSink in push mode; ``level`` while
    playing, ``drained`` when everything queued was played, ``failed`` (and
    drained) when there is no sound device - the voice never waits forever."""

    level = pyqtSignal(float)
    drained = pyqtSignal()
    failed = pyqtSignal(str)

    def __init__(self, sink_factory=None) -> None:
        super().__init__()
        self._sink_factory = sink_factory or _qt_sink
        self._sink = None
        self._io = None
        self._rate = 0  # the rate of the chunks the open sink plays
        self._device_rate = 0
        self._queue: list[tuple[bytes, int]] = []
        self._pending = b""
        self._timer = QTimer(self)
        self._timer.setInterval(30)
        self._timer.timeout.connect(self._push)

    def enqueue(self, pcm: bytes, rate: int) -> None:
        self._queue.append((pcm, rate))
        if not self._timer.isActive():
            self._timer.start()
        self._push()

    def busy(self) -> bool:
        return bool(self._queue or self._pending) or self._playing()

    def _playing(self) -> bool:
        if self._sink is None:
            return False
        from PyQt6.QtMultimedia import QAudio

        return self._sink.state() == QAudio.State.ActiveState and \
            self._sink.bytesFree() < self._sink.bufferSize()

    def _open(self, rate: int) -> bool:
        self._close()
        try:
            self._sink, self._io, self._device_rate = self._sink_factory(rate)
        except OSError as exc:
            self.stop()
            self.failed.emit(str(exc))
            self.drained.emit()
            return False
        self._rate = rate
        return True

    def _push(self) -> None:
        if not self._pending and self._queue:
            pcm, rate = self._queue[0]
            if rate != self._rate or self._sink is None:
                if self._playing():  # the last piece of the old rate ends first
                    return
                if not self._open(rate):
                    return
            self._queue.pop(0)
            self._pending = VA.resample(pcm, rate, self._device_rate)
        if self._pending and self._io is not None:
            free = self._sink.bytesFree()
            if free > 0:
                piece, self._pending = self._pending[:free], self._pending[free:]
                self._io.write(piece)
                self.level.emit(VA.level(piece))
        if not self._pending and not self._queue and not self._playing():
            self._timer.stop()
            self.level.emit(0.0)
            self.drained.emit()

    def _close(self) -> None:
        if self._sink is not None:
            self._sink.stop()
            self._sink.deleteLater()
        self._sink = self._io = None
        self._rate = self._device_rate = 0

    def stop(self) -> None:
        self._queue.clear()
        self._pending = b""
        self._timer.stop()
        self._close()
        self.level.emit(0.0)


# -- the controller ------------------------------------------------------------------------------


class _Bridge(QObject):
    audio = pyqtSignal(int, bytes, int)
    spoken = pyqtSignal(int, str)  # generation, error ("" = done)
    heard = pyqtSignal(int, str, str)  # generation, text, error


class VoiceController(QObject):
    """Speaks and listens for one Agent dock."""

    #: Recognised text for the task field (never the hidden phrase).
    transcribed = pyqtSignal(str)
    #: "idle", "listening", "transcribing", "speaking"
    state_changed = pyqtSignal(str)
    #: Something the user should read in the tab (a missing voice, an error).
    notice = pyqtSignal(str)
    #: 0..1 of the microphone while listening, of the speaker while speaking.
    level = pyqtSignal(float)
    #: Everything queued was spoken (conversation mode listens again).
    speaking_finished = pyqtSignal()
    line_started = pyqtSignal()
    line_finished = pyqtSignal()

    def __init__(
        self,
        parent=None,
        *,
        settings_loader: Callable[[], VS.VoiceSettings] | None = None,
        settings_saver: Callable[[VS.VoiceSettings], None] | None = None,
        tts_worker=None,
        stt_worker=None,
        recorder_factory=None,
        player=None,
        profile_provider: Callable[[], tuple] | None = None,
        confirm_remote: Callable[[object, str], bool] | None = None,
        packages: Callable[[], tuple[bool, bool]] | None = None,
        model_ready: Callable[[VM.VoiceModel], bool] | None = None,
        server_transcribe=None,
    ) -> None:
        super().__init__(parent)
        self._load_settings = settings_loader or VS.VoiceSettings.load
        self._save_settings = settings_saver or (lambda s: s.save())
        self.settings = self._load_settings()
        self._tts = tts_worker or VW.VoiceWorker()
        self._stt = stt_worker or VW.VoiceWorker()
        self._recorder_factory = recorder_factory or QtRecorder
        self._player = player if player is not None else QtPlayer()
        self._player.level.connect(self._on_player_level)
        self._player.drained.connect(self._on_drained)
        if hasattr(self._player, "failed"):
            self._player.failed.connect(
                lambda why: self._once("sound", tr("No sound: {error}").format(error=why)))
        #: () -> (LLMProfile | None, api key)
        self._profile = profile_provider or (lambda: (None, ""))
        self._confirm_remote = confirm_remote or (lambda profile, host: False)
        self._packages = packages or (lambda: (VW.piper_available(), VW.whisper_available()))
        self._model_ready = model_ready or VM.installed
        if server_transcribe is None:
            from core.voice_stt import transcribe_server as server_transcribe
        self._server_transcribe = server_transcribe
        self._lexicon = VT.load_lexicon()
        self._bridge = _Bridge()
        self._bridge.audio.connect(self._on_audio)
        self._bridge.spoken.connect(self._on_spoken)
        self._bridge.heard.connect(self._on_heard)
        self._state = "idle"
        self._generation = 0
        #: One step per recording that is dropped (Stop): its text is not used.
        self._listen_generation = 0
        self._queue: list[dict] = []
        self._synth_running = False
        self._cancel = threading.Event()
        self._recorder = None
        self._recording = bytearray()
        self._detector: VA.SilenceDetector | None = None
        self._auto_stop = False
        self._said_once: set[str] = set()
        self._greeted = False
        self._stt_consent: set[str] = set()
        self._line_active = False
        self._pulse = QTimer(self)
        self._pulse.setInterval(60)
        self._pulse.timeout.connect(self._fake_pulse)
        self._pulse_step = 0

    # -- state -----------------------------------------------------------------------------

    @property
    def state(self) -> str:
        return self._state

    def _set_state(self, state: str) -> None:
        if state != self._state:
            self._state = state
            self.state_changed.emit(state)

    def speaking(self) -> bool:
        return bool(self._queue) or self._synth_running or self._player.busy()

    def reload(self) -> None:
        self.settings = self._load_settings()

    def set_output_enabled(self, on: bool) -> None:
        self.settings.set("output_enabled", bool(on))
        try:
            self._save_settings(self.settings)
        except OSError as exc:
            self.notice.emit(tr("The voice settings could not be saved: {error}").format(error=exc))
        if on:
            self.greet()
        else:
            self.stop_speaking()

    def _once(self, key: str, text: str) -> None:
        if key not in self._said_once:
            self._said_once.add(key)
            self.notice.emit(text)

    # -- speaking ----------------------------------------------------------------------------

    def speak_answer(self, text: str) -> bool:
        """Read an agent answer aloud (voice output on): its speakable part,
        in the setting's language or the answer's own."""
        if not self.settings.output_enabled or not (text or "").strip():
            return False
        fallback = VS.phrase_language(self.settings.language)
        lang = VS.spoken_language(self.settings.language, text, fallback)
        return self._speak(VT.speakable_text(text, lang), lang)

    def say_phrase(self, text: str) -> bool:
        """A short phrase of axross itself, in the phrase language."""
        if not self.settings.output_enabled:
            return False
        return self._speak(text, VS.phrase_language(self.settings.language))

    def say_refusal(self, reason: str) -> bool:
        lang = VS.phrase_language(self.settings.language)
        return self.say_phrase(VT.refusal_phrase(reason, lang))

    def greet(self) -> bool:
        """Once a session, with voice output on: hello and a nice day."""
        if self._greeted or not self.settings.output_enabled:
            return False
        # Only a greeting that is spoken counts: one whose voice is missing
        # comes once the voice is there.
        self._greeted = self.say_phrase(
            VT.greeting_phrase(VS.phrase_language(self.settings.language)))
        return self._greeted

    def _voice_ready(self, model: VM.VoiceModel, *, quiet: bool = False) -> bool:
        piper, _whisper = self._packages()
        if not piper:
            if not quiet:
                self._once("piper", tr("Voice output needs the voice packages: pip install "
                                       "axross[voice] (Help > Features…)."))
            return False
        if not self._model_ready(model):
            if not quiet:
                self._once(model.id, tr("The voice {name} is not downloaded yet: Help > "
                                        "Features…, group Voice.").format(name=model.title))
            return False
        return True

    def _speak(self, text: str, lang: str, *, voice_id: str = "", quiet: bool = False,
               **tuning) -> bool:
        sentences = []
        for sentence in VT.split_sentences(text):
            if lang == "de":
                parts = VT.segment(sentence, self._lexicon)
            else:
                parts = [("en", VT.strip_term_braces(sentence).replace("{", "").replace("}", ""))]
            if parts:
                sentences.append(parts)
        if not sentences:
            return False
        model = VM.model(voice_id or VS.voice_for(lang, self.settings.gender))
        if model is None or not self._voice_ready(model, quiet=quiet):
            return False
        voice, config = VM.voice_paths(model)
        self._queue.append({"op": "speak", "voice": str(voice), "config": str(config),
                            "lang": lang, "sentences": sentences, **tuning})
        self._pump()
        return True

    def _pump(self) -> None:
        if self._synth_running or not self._queue:
            return
        request = self._queue.pop(0)
        rate_factor = request.pop("rate_factor", 1.0)
        self._synth_running = True
        self._set_state("speaking")
        generation = self._generation
        cancel = self._cancel

        def on_event(event: dict) -> None:
            try:
                pcm = base64.b64decode(str(event.get("pcm") or ""))
                rate = int(event.get("rate") or 22050)
            except (ValueError, TypeError):
                return
            if rate_factor != 1.0 and 8000 <= rate <= 96000:
                # Slower and lower, as if played at rate x factor - in
                # software, since not every sound device takes any rate.
                pcm = VA.resample(pcm, rate, int(rate / rate_factor))
            self._bridge.audio.emit(generation, pcm, rate)

        def work() -> None:
            error = ""
            try:
                reply = self._tts.call(request, timeout=_SPEAK_TIMEOUT, on_event=on_event,
                                       cancel=cancel)
                if not reply.get("ok"):
                    error = str(reply.get("error") or "speech failed")
            except VW.VoiceWorkerCancelled:
                error = ""
            except VW.VoiceWorkerError as exc:
                error = str(exc)
            self._bridge.spoken.emit(generation, error)

        threading.Thread(target=work, name="axross-voice-speak", daemon=True).start()

    def _on_audio(self, generation: int, pcm: bytes, rate: int) -> None:
        if generation == self._generation and pcm:
            self._player.enqueue(pcm, rate)

    def _on_spoken(self, generation: int, error: str) -> None:
        if generation != self._generation:
            return
        self._synth_running = False
        if error:
            self.notice.emit(tr("Speech output failed: {error}").format(error=error))
        if self._queue:
            self._pump()
        elif not self._player.busy():
            self._finish_speaking()

    def _on_drained(self) -> None:
        if not self._synth_running and not self._queue:
            self._finish_speaking()

    def _finish_speaking(self) -> None:
        if self._state == "speaking":
            self._set_state("idle")
        if self._line_active:
            self._end_line()
        self.speaking_finished.emit()

    def _on_player_level(self, value: float) -> None:
        if self._state == "speaking":
            self.level.emit(value)

    def stop_speaking(self) -> None:
        """Stop and any new input: the synthesis ends, nothing queued plays."""
        was = self.speaking()
        self._generation += 1
        self._queue.clear()
        self._cancel.set()
        self._cancel = threading.Event()
        if self._synth_running:
            self._tts.kill()
        self._synth_running = False
        self._player.stop()
        if self._line_active:
            self._end_line()
        if self._state == "speaking":
            self._set_state("idle")
        if was:
            self.level.emit(0.0)

    # -- one fixed line ------------------------------------------------------------------------

    def play_line(self) -> None:
        self.stop_speaking()
        self._line_active = True
        self.line_started.emit()
        model = VM.model(_LINE_VOICE)
        spoken = model is not None and self._voice_ready(model, quiet=True) and self._speak(
            _LINE, "en", voice_id=_LINE_VOICE, quiet=True, length_scale=1.15, rate_factor=0.9)
        if not spoken:
            self._pulse_step = 0
            self._pulse.start()

    def _fake_pulse(self) -> None:
        import math

        self._pulse_step += 1
        self.level.emit(0.35 + 0.3 * abs(math.sin(self._pulse_step / 3.0)))
        if self._pulse_step >= 55:
            self._end_line()

    def _end_line(self) -> None:
        self._pulse.stop()
        if self._line_active:
            self._line_active = False
            self.level.emit(0.0)
            self.line_finished.emit()

    def line_text(self) -> str:
        return _LINE

    # -- listening ------------------------------------------------------------------------------

    def listening(self) -> bool:
        return self._recorder is not None

    def start_listening(self, *, auto_stop: bool = False) -> bool:
        """Open the microphone. *auto_stop*: the input ends after speech and
        the configured silence (toggle, conversation)."""
        from core.security_mode import is_paranoid

        if is_paranoid():
            self.notice.emit(tr("The microphone is off in the paranoid security mode."))
            return False
        if self._recorder is not None:
            return True
        self.stop_speaking()
        recorder = self._recorder_factory()
        self._recording = bytearray()
        self._detector = VA.SilenceDetector(self.settings.silence_seconds)
        self._auto_stop = auto_stop
        recorder.data.connect(self._on_data)
        try:
            recorder.start()
        except OSError as exc:
            self.notice.emit(tr("The microphone could not be opened: {error}").format(error=exc))
            return False
        self._recorder = recorder
        self._set_state("listening")
        return True

    def _on_data(self, pcm: bytes) -> None:
        if self._recorder is None:
            return
        self._recording += pcm
        self.level.emit(VA.level(pcm))
        ended = self._detector.feed(pcm) if self._detector is not None else False
        if (self._auto_stop and ended) or len(self._recording) // 2 / VA.RATE >= MAX_RECORD_SECONDS:
            QTimer.singleShot(0, self.stop_listening)

    def cancel_listening(self) -> None:
        """Drop the recording, and the text of one still being recognised."""
        recorder, self._recorder = self._recorder, None
        if recorder is not None:
            recorder.stop()
        self._recording = bytearray()
        self._listen_generation += 1
        self.level.emit(0.0)
        if self._state in ("listening", "transcribing"):
            self._set_state("idle")

    def stop_listening(self) -> None:
        """End the recording and have it recognised."""
        recorder, self._recorder = self._recorder, None
        if recorder is None:
            return
        recorder.stop()
        pcm, self._recording = bytes(self._recording), bytearray()
        self.level.emit(0.0)
        heard = self._detector.heard_speech if self._detector is not None else True
        if VA.seconds(pcm) < MIN_RECORD_SECONDS or not heard:
            self._set_state("idle")
            self.notice.emit(tr("Nothing was heard."))
            return
        self._transcribe(pcm)

    def _transcribe(self, pcm: bytes) -> None:
        profile, key = self._profile()
        language = self.settings.language if self.settings.language in VT.LANGS else None
        if profile is None:
            self._set_state("idle")
            self.notice.emit(tr("No LLM profile is active."))
            return
        if profile.stt_engine == "server":
            target = profile.transcription_url()
            if profile.stt_needs_consent() and target not in self._stt_consent:
                host = profile.stt_host() or target
                if not self._confirm_remote(profile, host):
                    self._set_state("idle")
                    return
                self._stt_consent.add(target)

            def work() -> str:
                return self._server_transcribe(profile, key, pcm, language=language)
        else:
            _piper, whisper = self._packages()
            model = VM.whisper_model(profile.stt_model)
            if not whisper:
                self._set_state("idle")
                self.notice.emit(tr("Speech recognition needs the voice packages: pip install "
                                    "axross[voice] (Help > Features…)."))
                return
            if model is None or not self._model_ready(model):
                self._set_state("idle")
                self.notice.emit(tr("The speech recognition model {name} is not downloaded yet: "
                                    "Help > Features…, group Voice.").format(
                                        name=model.title if model else profile.stt_model))
                return
            request = {"op": "transcribe", "model": str(VM.model_dir(model)),
                       "pcm": base64.b64encode(pcm).decode(), "language": language}

            def work() -> str:
                reply = self._stt.call(request, timeout=_TRANSCRIBE_TIMEOUT)
                if not reply.get("ok"):
                    raise VW.VoiceWorkerError(str(reply.get("error") or "recognition failed"))
                return str(reply.get("text") or "")

        self._set_state("transcribing")
        generation = self._listen_generation

        def run() -> None:
            try:
                self._bridge.heard.emit(generation, work(), "")
            except Exception as exc:  # noqa: BLE001 - shown to the user, never logged
                self._bridge.heard.emit(generation, "", str(exc))

        threading.Thread(target=run, name="axross-voice-listen", daemon=True).start()

    def _on_heard(self, generation: int, text: str, error: str) -> None:
        if generation != self._listen_generation:
            return  # dropped (Stop) while it was being recognised
        if self._state == "transcribing":
            self._set_state("idle")
        if error:
            self.notice.emit(tr("Speech recognition failed: {error}").format(error=error))
            return
        text = text.strip()
        if not text:
            self.notice.emit(tr("Nothing was recognised."))
            return
        if VT.is_pod_bay_request(text):
            self.play_line()
            return
        self.greet()  # the first voice input of a session
        self.transcribed.emit(text)

    def shutdown(self) -> None:
        self.cancel_listening()
        self.stop_speaking()
        self._tts.close()
        self._stt.close()
