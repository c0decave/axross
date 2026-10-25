"""Qt Multimedia without probing the GPU drivers.

Qt's FFmpeg backend tries every hardware decoder and encoder (CUDA, VA-API,
...) when its integration is created - the first QAudioDecoder, QMediaPlayer
or QMediaDevices. That runs the host's GPU driver code in the calling
thread, usually the GUI thread. Measured on a laptop with the NVIDIA driver:
QAudioDecoder() -> av_hwdevice_ctx_create -> cuInit -> wait4, and it never
returned - axross-full showed no window, because the Media Player builds its
engine while the main window starts.

axross decodes audio and shows media previews; neither needs a hardware
decoder. So unless the user set them, both lists of device types are empty:
Qt then tries no hardware device at all. Both are needed - with only one of
them set, cuInit still ran (measured with a hanging driver stand-in,
tests/hanging_gpu_driver.py).

What axross set here is not handed to host programs (core.subprocess_env.
clean_child_env drops it); axross's own workers keep it.

``AXROSS_MULTIMEDIA_GPU_PROBE=1`` leaves both unset: Qt then tries the
hardware devices as it does by default. For a user who wants hardware
decoding without naming the device types, and for the tests that show the
second layer holds without this one (core.multimedia_probe: Qt Multimedia
is tried in a child first, and a hang there turns into a message).
"""

from __future__ import annotations

import os

#: Qt's lists of FFmpeg hardware device types (decoding, encoding).
HW_DEVICE_VARS = ("QT_FFMPEG_DECODING_HW_DEVICE_TYPES", "QT_FFMPEG_ENCODING_HW_DEVICE_TYPES")

#: Set to 1 (true, yes, on): Qt's own probing of every hardware device.
GPU_PROBE_ENV = "AXROSS_MULTIMEDIA_GPU_PROBE"
_TRUTHY = {"1", "true", "yes", "on"}

#: The variables this process set itself (not the user): host programs
#: started from axross must not inherit them.
_SET_BY_AXROSS: set[str] = set()


def apply_no_gpu_probe(environ: dict | None = None) -> list[str]:
    """Set every unset variable of :data:`HW_DEVICE_VARS` to "" (no device)
    in *environ* (default ``os.environ``); return the names it set. A
    value the user gave - also an empty one - is kept. Nothing is set
    when :data:`GPU_PROBE_ENV` is on."""
    environ = os.environ if environ is None else environ
    if environ.get(GPU_PROBE_ENV, "").strip().lower() in _TRUTHY:
        return []
    applied = []
    for name in HW_DEVICE_VARS:
        if name not in environ:
            environ[name] = ""
            _SET_BY_AXROSS.add(name)
            applied.append(name)
    return applied


#: Qt's choice of audio backend on Linux. Measured (Qt 6.10 and 6.11):
#: unset - PipeWire when its daemon runs, else PulseAudio; "pipewire";
#: "pulseaudio"; any other value - PulseAudio.
AUDIO_BACKEND_VAR = "QT_AUDIO_BACKEND"
AUDIO_BACKENDS = ("pulseaudio", "pipewire")


def apply_audio_backend(backend: str, environ: dict | None = None) -> str | None:
    """Make Qt use *backend* ("auto", "pulseaudio" or "pipewire") in
    *environ* (default ``os.environ``); return the value set, None when
    nothing was. "auto" leaves Qt's own choice. A value the user set keeps
    winning; one axross set before (the saved choice, replaced by the
    probe's fallback) may be replaced. Before the first multimedia object
    only: Qt reads it once per process."""
    environ = os.environ if environ is None else environ
    if backend != "auto" and backend not in AUDIO_BACKENDS:
        raise ValueError(f"unknown audio backend {backend!r}")
    if AUDIO_BACKEND_VAR in environ and AUDIO_BACKEND_VAR not in _SET_BY_AXROSS:
        return None
    if backend == "auto":
        return None
    environ[AUDIO_BACKEND_VAR] = backend
    _SET_BY_AXROSS.add(AUDIO_BACKEND_VAR)
    return backend


def users_audio_backend(environ: dict | None = None) -> str | None:
    """The QT_AUDIO_BACKEND the user set themselves, None without one."""
    environ = os.environ if environ is None else environ
    if AUDIO_BACKEND_VAR in environ and AUDIO_BACKEND_VAR not in _SET_BY_AXROSS:
        return environ[AUDIO_BACKEND_VAR]
    return None


def set_by_axross() -> frozenset[str]:
    """The names this module set in this process (not the user)."""
    return frozenset(_SET_BY_AXROSS)


def _ignore(*_args) -> None:
    pass


def prime_notify_lookups(obj) -> None:
    """Let Qt's own threads call *obj*'s connectNotify / disconnectNotify
    without the GIL; call it on the GUI thread right after making a Qt
    Multimedia object (QMediaPlayer, QAudioOutput, QAudioSink, ...).

    A PyQt-made object is a sip subclass: each of those calls first asks
    Python whether the method is reimplemented, and asking takes the GIL -
    until the answer was "no" once, which sip then keeps for that object.
    Qt FFmpeg's renderer threads destroy objects connected to it, and
    QObject::~QObject() calls the sender's disconnectNotify() while it holds
    its own signal-slot lock. Measured (core dump of a hung run): the
    renderer waited for the GIL inside QAudioOutput.disconnectNotify(), the
    main thread held the GIL in QMediaPlayer.stop() and waited for that
    lock - for ever. One connect and disconnect here gives sip its answer
    while this thread holds the GIL anyway."""
    if obj is None:
        return
    try:
        from PyQt6 import sip

        if sip.isdeleted(obj):
            return
        obj.destroyed.connect(_ignore)
        obj.destroyed.disconnect(_ignore)
    except (RuntimeError, TypeError, ImportError):  # deleted meanwhile; not a QObject
        pass


__all__ = ["AUDIO_BACKENDS", "AUDIO_BACKEND_VAR", "GPU_PROBE_ENV", "HW_DEVICE_VARS",
           "apply_audio_backend", "apply_no_gpu_probe", "prime_notify_lookups", "set_by_axross",
           "users_audio_backend"]
