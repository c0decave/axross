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


def set_by_axross() -> frozenset[str]:
    """The names :func:`apply_no_gpu_probe` set in this process."""
    return frozenset(_SET_BY_AXROSS)


__all__ = ["GPU_PROBE_ENV", "HW_DEVICE_VARS", "apply_no_gpu_probe", "set_by_axross"]
