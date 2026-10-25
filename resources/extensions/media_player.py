"""A media player panel: playlist (drag & drop, M3U, shuffle and repeat;
folds away), seeking, volume with mute, tags and cover, a 10-band
equalizer (folds away) and animated visualizations a click switches
between - in colour schemes, with options, fullscreen or in a window of
their own."""

from __future__ import annotations

import logging
import math
import os
import posixpath
import random
import shutil
import time
from typing import NamedTuple

from PyQt6 import sip
from PyQt6.QtCore import (
    QByteArray,
    QEvent,
    QLineF,
    QObject,
    QPointF,
    QRectF,
    QSize,
    Qt,
    QTimer,
    QUrl,
    pyqtSignal,
)
from PyQt6.QtGui import (
    QActionGroup,
    QColor,
    QFont,
    QIcon,
    QImage,
    QLinearGradient,
    QPainter,
    QPalette,
    QPen,
    QPixmap,
    QPolygonF,
    QRadialGradient,
)
from PyQt6.QtSvg import QSvgRenderer
from PyQt6.QtWidgets import (
    QAbstractButton,
    QAbstractItemView,
    QAbstractSlider,
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMenu,
    QPushButton,
    QSlider,
    QSpinBox,
    QStyle,
    QStyleOptionSlider,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from core import audio_route
from core.i18n import tr
from core.multimedia_env import prime_notify_lookups
from ui.themes import contrast_ratio, is_hex_colour

log = logging.getLogger(__name__)

try:  # the equalizer and the visualizations need numpy; playback does not
    import numpy as np
except ImportError:  # pragma: no cover - depends on the install
    np = None

EXTENSION = {
    "name": "Media Player",
    "version": "1.3",
    "description": "A panel that plays MP3, WAV, Ogg Vorbis, FLAC, Opus, AAC and more: playlist "
    "with drag & drop, M3U load/save and the last list restored, seeking, shuffle and repeat, "
    "volume with mute, keyboard control, tags and cover, a 10-band equalizer with presets that "
    "folds away, and animated visualizations - spectrum, mirrored, radial, line and polar "
    "spectrum, waterfall, oscilloscope, stereo scope, VU meter, starfield - a click switches "
    "between, in colour schemes (or your own colours) with bar count, smoothing, peak fall and "
    "frame rate, fullscreen like a screensaver or detached into a window of any size; the "
    "playlist folds away (equalizer and visualizations need numpy).",
    "author": "axross",
}

#: Each one played by the engine (Qt's FFmpeg) from source and in the frozen
#: axross-full (tests/test_media_player_drop_reports.py names the measurement).
#: Video containers (.mp4, .mkv) stay out: a folder of films is no playlist.
AUDIO_SUFFIXES = (".mp3", ".wav", ".ogg", ".oga", ".opus", ".flac", ".m4a", ".aac", ".wma", ".aiff",
                  ".aif", ".mka", ".m4b", ".wv", ".spx", ".tta", ".ac3", ".mp2", ".caf", ".au",
                  ".amr", ".webm")
#: Centre frequencies of the ten bands (Hz).
BANDS = (31, 62, 125, 250, 500, 1000, 2000, 4000, 8000, 16000)
MAX_GAIN_DB = 12.0
PRESETS = {
    "Flat": [0.0] * 10,
    "Bass boost": [8.0, 7.0, 5.0, 3.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0],
    "Treble boost": [0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 3.0, 5.0, 7.0, 8.0],
    "Vocal": [-3.0, -2.0, -1.0, 1.0, 4.0, 5.0, 4.0, 2.0, 0.0, -1.0],
    "Loudness": [6.0, 5.0, 2.0, 0.0, -1.0, -1.0, 0.0, 2.0, 4.0, 5.0],
    "Rock": [5.0, 4.0, 2.0, -1.0, -2.0, -1.0, 2.0, 4.0, 5.0, 5.0],
}
RATE = 44100
#: Seconds of audio decoded ahead of the sound card at most. The decoder
#: waits until its buffer is read, so not reading bounds the memory: read
#: at once, a one-hour track ended up in memory as float samples (~1 GB).
MAX_AHEAD_SECONDS = 2.0
FRAME = 2048
HOP = FRAME // 2
#: Bytes per sample of the sample formats a sound card may take.
SAMPLE_BYTES = {"Float": 4, "Int16": 2, "Int32": 4, "UInt8": 1}
#: Seconds of playback the monitor judges the sound card's speed over, and
#: how far from real time counts as wrong (0.2: below 0.8x or above 1.2x).
MONITOR_WINDOW_SECONDS = 3.0
MONITOR_TOLERANCE = 0.2
#: Bytes copied from a remote backend at most (the file is played locally).
MAX_REMOTE_BYTES = 512 * 1024 * 1024
#: The arrow keys seek by this much, with Shift by the big step (ms).
SEEK_STEP_MS = 5_000
SEEK_BIG_STEP_MS = 30_000
#: ⏮ starts the track again once it played this long, else goes back.
RESTART_AFTER_MS = 3_000
#: + and - change the volume by this many slider steps (of 100).
VOLUME_STEP = 5
REPEAT_MODES = ("off", "all", "one")

#: The control buttons' icons, drawn here (24x24, Feather-style strokes):
#: a label like 🔀 needs an emoji font, which a plain Linux install lacks -
#: the button showed an empty box.
CONTROL_ICONS = {
    "previous": '<polygon points="19 20 9 12 19 4 19 20"/><line x1="5" y1="19" x2="5" y2="5"/>',
    "play": '<polygon points="6 4 20 12 6 20 6 4"/>',
    "pause": '<rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/>',
    "stop": '<rect x="5" y="5" width="14" height="14" rx="1"/>',
    "next": '<polygon points="5 4 15 12 5 20 5 4"/><line x1="19" y1="5" x2="19" y2="19"/>',
    "shuffle": '<polyline points="16 3 21 3 21 8"/><line x1="4" y1="20" x2="21" y2="3"/>'
               '<polyline points="21 16 21 21 16 21"/><line x1="15" y1="15" x2="21" y2="21"/>'
               '<line x1="4" y1="4" x2="9" y2="9"/>',
    "repeat": '<polyline points="17 1 21 5 17 9"/><path d="M3 11V9a4 4 0 0 1 4-4h14"/>'
              '<polyline points="7 23 3 19 7 15"/><path d="M21 13v2a4 4 0 0 1-4 4H3"/>',
    "repeat-one": '<polyline points="17 1 21 5 17 9"/><path d="M3 11V9a4 4 0 0 1 4-4h14"/>'
                  '<polyline points="7 23 3 19 7 15"/><path d="M21 13v2a4 4 0 0 1-4 4H3"/>'
                  '<path d="M11 10.5l1.5-1v5"/>',
    "volume": '<polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5"/>'
              '<path d="M19.07 4.93a10 10 0 0 1 0 14.14M15.54 8.46a5 5 0 0 1 0 7.07"/>',
    "volume-x": '<polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5"/>'
                '<line x1="23" y1="9" x2="17" y2="15"/><line x1="17" y1="9" x2="23" y2="15"/>',
}
CONTROL_ICON_SIZE = 18


def control_svg(name: str, colour: str) -> str:
    """The SVG of control icon *name*, stroked in *colour* (``#rrggbb``)."""
    body = CONTROL_ICONS[name]
    return ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" '
            f'stroke="{colour}" stroke-width="2" stroke-linecap="round" '
            f'stroke-linejoin="round">{body}</svg>')


_control_icon_cache: dict[tuple[str, str, int], QIcon] = {}


def control_icon(name: str, colour: str, size: int = 32) -> QIcon:
    """Control icon *name* in *colour*, rendered once per (name, colour, size)."""
    key = (name, colour, size)
    cached = _control_icon_cache.get(key)
    if cached is None:
        renderer = QSvgRenderer(QByteArray(control_svg(name, colour).encode("utf-8")))
        pixmap = QPixmap(size, size)
        pixmap.fill(Qt.GlobalColor.transparent)
        painter = QPainter(pixmap)
        try:
            renderer.render(painter)
        finally:
            painter.end()
        cached = _control_icon_cache[key] = QIcon(pixmap)
    return cached


def is_audio(name: str) -> bool:
    return name.lower().endswith(AUDIO_SUFFIXES) and "." in name.strip(".")


def format_time(ms) -> str:
    """``m:ss``, or ``h:mm:ss`` from an hour on; nonsense is ``0:00``."""
    try:
        seconds = max(0, int(ms)) // 1000
    except (TypeError, ValueError):
        seconds = 0
    hours, rest = divmod(seconds, 3600)
    minutes, seconds = divmod(rest, 60)
    if hours:
        return f"{hours}:{minutes:02d}:{seconds:02d}"
    return f"{minutes}:{seconds:02d}"


def perceptual_to_linear(value: float) -> float:
    """The amplitude for a volume slider position (0..1): cubic, as
    PulseAudio maps its volumes - equal slider steps sound like about equal
    steps in loudness, where a linear mapping crowds all audible change
    into the bottom fifth of the slider."""
    value = min(1.0, max(0.0, float(value)))
    return value ** 3


def linear_to_perceptual(gain: float) -> float:
    gain = min(1.0, max(0.0, float(gain)))
    return gain ** (1.0 / 3.0)


# -- files, playlists and the saved state ------------------------------------------------

#: A dropped folder adds at most this many tracks, this many levels deep.
MAX_DROP_FILES = 2000
MAX_DROP_DEPTH = 6
#: Bytes copied from a remote backend for one drop at most, all files.
MAX_REMOTE_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
#: An M3U playlist is read only up to this size, this many entries and
#: this long a line; a longer line is no path anyone wrote.
MAX_PLAYLIST_BYTES = 1024 * 1024
MAX_PLAYLIST_ENTRIES = 10_000
MAX_PLAYLIST_LINE = 4096
PLAYLIST_SUFFIXES = (".m3u", ".m3u8")
#: The saved state (last playlist, position, volume) is read up to this size.
MAX_STATE_BYTES = 4 * 1024 * 1024
STATE_VERSION = 1

#: Temporary folders holding copies of remote tracks (up to
#: MAX_REMOTE_BYTES each): the playlist plays from them until the
#: extension unloads, then they go.
_TEMP_FOLDERS: list[str] = []


class PlaylistError(ValueError):
    """A playlist file that is refused as a whole."""


class PlaylistEntry:
    """One track of a playlist: its local path, the #EXTINF title ("" for
    none) and length in seconds (0 when unknown)."""

    __slots__ = ("path", "title", "duration")

    def __init__(self, path: str, title: str = "", duration: int = 0) -> None:
        self.path = path
        self.title = title
        self.duration = duration

    def __eq__(self, other) -> bool:
        return isinstance(other, PlaylistEntry) and (self.path, self.title, self.duration) == (
            other.path, other.title, other.duration)

    def __repr__(self) -> str:
        return f"PlaylistEntry({self.path!r}, {self.title!r}, {self.duration!r})"


def _is_temp_copy(path: str) -> bool:
    """Whether *path* is a temporary copy of a remote track. Names only (the
    copies' paths are built from the folders' own): no filesystem call, so
    a save of a long list never waits on a slow mount."""
    path = os.path.abspath(path)
    return any(path.startswith(folder + os.sep) for folder in _TEMP_FOLDERS)


def _is_track(path: str) -> bool:
    """An audio file by name that is a regular file: not a FIFO (the
    decoder would block on it), device or folder named like a track."""
    return is_audio(os.path.basename(path)) and os.path.isfile(path)


def _clean_text(text: str, limit: int = 300) -> str:
    return "".join(c for c in text if c.isprintable())[:limit].strip()


def collect_local(paths, max_files: int | None = None, max_depth: int | None = None):
    """The tracks among local *paths* as ``[(path, title)]``: audio files,
    the audio files in folders (sorted, at most *max_files* and *max_depth*
    levels; a link to a folder is followed, each folder walked once, so a
    loop ends) and the entries of M3U playlists. Also the number of entries
    that gave no track - dropped ones that are none, folders that cannot be
    read or lie deeper than the bound, and, only when nothing was found, the
    other files the folders held (a cover beside the tracks is no news) -
    and whether the bound cut the list."""
    max_files = MAX_DROP_FILES if max_files is None else max_files
    max_depth = MAX_DROP_DEPTH if max_depth is None else max_depth
    found: list[tuple[str, str]] = []
    skipped = 0
    others = 0  # files in the folders that are no track
    truncated = False
    walked: set[str] = set()

    def walk(folder: str, depth: int) -> None:
        nonlocal truncated, skipped, others
        real = os.path.realpath(folder)
        if real in walked:
            return
        if depth > max_depth:
            skipped += 1
            return
        walked.add(real)
        try:
            with os.scandir(folder) as it:
                entries = sorted(it, key=lambda e: e.name.casefold())
        except OSError:
            skipped += 1
            return
        for entry in entries:
            if len(found) >= max_files:
                truncated = True
                return
            try:
                if entry.is_dir():  # a link to a folder too: *walked* stops a loop
                    walk(entry.path, depth + 1)
                elif is_audio(entry.name) and entry.is_file():
                    found.append((entry.path, ""))
                else:
                    others += 1
            except OSError:
                skipped += 1

    for path in paths:
        if len(found) >= max_files:
            truncated = True
            break
        path = str(path)
        if os.path.isdir(path):
            walk(path, 1)
        elif path.lower().endswith(PLAYLIST_SUFFIXES):
            try:
                entries, gone = read_playlist(path)
            except PlaylistError:
                skipped += 1
                continue
            skipped += gone
            room = max_files - len(found)
            truncated = truncated or len(entries) > room
            found.extend((e.path, e.title) for e in entries[:room])
        elif _is_track(path):
            found.append((path, ""))
        else:
            skipped += 1
    return found, skipped + (0 if found else others), truncated


def fetch_remote(backend, paths, temp_root: str | None = None):
    """Copy the tracks among *paths* of a remote *backend* (folders listed
    as :func:`collect_local` walks them) into a new temporary folder:
    ``([(local copy, name)], skipped, truncated, folder)``. Every file is
    bounded by MAX_REMOTE_BYTES and the drop by MAX_REMOTE_TOTAL_BYTES; a
    file over its bound fails the drop, the folder then goes. Runs on a
    worker thread: backend calls only, no Qt."""
    import tempfile

    remote: list[tuple[str, str]] = []
    skipped = 0
    others = 0  # files in the folders that are no track
    truncated = False

    def walk(folder: str, depth: int) -> None:
        # Counted as in collect_local; a remote link to a folder is not
        # followed (no realpath to stop a loop with) and counts as skipped.
        nonlocal truncated, skipped, others
        if depth > MAX_DROP_DEPTH:
            skipped += 1
            return
        try:
            items = sorted(backend.list_dir(folder), key=lambda i: i.name.casefold())
        except OSError:
            skipped += 1
            return
        for item in items:
            if len(remote) >= MAX_DROP_FILES:
                truncated = True
                return
            child = backend.join(folder, item.name)
            if item.is_dir:
                if getattr(item, "is_link", False):
                    skipped += 1
                else:
                    walk(child, depth + 1)
            elif is_audio(item.name):
                remote.append((child, item.name))
            else:
                others += 1

    for path in paths:
        if len(remote) >= MAX_DROP_FILES:
            truncated = True
            break
        name = posixpath.basename(str(path).replace("\\", "/").rstrip("/"))
        try:
            is_dir = backend.stat(path).is_dir
        except OSError:
            skipped += 1
            continue
        if is_dir:
            walk(path, 1)
        elif is_audio(name):
            remote.append((path, name))
        else:
            skipped += 1
    if not remote:
        return [], skipped + others, truncated, ""
    folder = os.path.abspath(tempfile.mkdtemp(prefix="axross-media-", dir=temp_root))
    # Registered at once: an unload while this copies still removes it.
    _TEMP_FOLDERS.append(folder)
    out: list[tuple[str, str]] = []
    total = 0
    try:
        for index, (path, name) in enumerate(remote):
            os.mkdir(os.path.join(folder, str(index)))  # equal names do not clash
            target = os.path.join(folder, str(index), name)
            copied = 0
            with backend.open_read(path) as src, open(target, "wb") as dst:
                while True:
                    chunk = src.read(1 << 20)
                    if not chunk:
                        break
                    copied += len(chunk)
                    total += len(chunk)
                    if copied > MAX_REMOTE_BYTES:
                        raise OSError(f"{name} is larger than {MAX_REMOTE_BYTES >> 20} MB")
                    if total > MAX_REMOTE_TOTAL_BYTES:
                        raise OSError(f"the tracks are larger than "
                                      f"{MAX_REMOTE_TOTAL_BYTES >> 20} MB together")
                    dst.write(chunk)
            out.append((target, name))
    except BaseException:
        _forget_temp(folder)
        raise
    if not out:
        _forget_temp(folder)
    return out, skipped, truncated, folder


def _forget_temp(folder: str) -> None:
    shutil.rmtree(folder, ignore_errors=True)
    try:
        _TEMP_FOLDERS.remove(folder)
    except ValueError:
        pass


def _entry_path(line: str, base_dir: str) -> str | None:
    """The local path an M3U line names, or None (a URL, nonsense)."""
    if line.lower().startswith("file:"):
        local = QUrl(line).toLocalFile()
        return os.path.normpath(local) if local else None
    if "://" in line:
        return None  # streams are not played from a playlist
    path = line if os.path.isabs(line) else os.path.join(base_dir, line)
    path = os.path.normpath(path)
    if os.sep == "/" and "\\" in line and not os.path.exists(path):
        # A playlist written on Windows: Music\a.mp3
        alt = line.replace("\\", "/")
        path = os.path.normpath(alt if os.path.isabs(alt) else os.path.join(base_dir, alt))
    return path


def parse_m3u(data: bytes, base_dir: str):
    """The tracks of an M3U/M3U8 playlist as ``([PlaylistEntry], skipped)``.

    UTF-8 (a BOM is fine; a legacy .m3u that is no UTF-8 is read as
    Latin-1); relative paths are resolved against *base_dir*; ``#EXTINF``
    gives title and length. An entry is skipped when it is a URL, longer
    than MAX_PLAYLIST_LINE, has control characters, is no audio file by
    name or no regular file (missing, a FIFO, a device) - absolute paths
    and ``..`` are allowed as in every player, but only for such files.
    After MAX_PLAYLIST_ENTRIES the rest counts as skipped. NUL bytes refuse
    the whole file: it is no text playlist."""
    if b"\x00" in data:
        raise PlaylistError("not a text playlist (NUL bytes)")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = data.decode("latin-1")
    entries: list[PlaylistEntry] = []
    skipped = 0
    title, duration = "", 0
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#"):
            if line.upper().startswith("#EXTINF:"):
                head, _sep, rest = line[8:].partition(",")
                try:
                    duration = max(0, int(float(head.split()[0]))) if head.split() else 0
                except ValueError:
                    duration = 0
                title = _clean_text(rest)
            continue
        if len(entries) >= MAX_PLAYLIST_ENTRIES:
            skipped += 1
            continue
        path = None
        if len(line) <= MAX_PLAYLIST_LINE and line.isprintable():
            path = _entry_path(line, base_dir)
        if path is not None and _is_track(path):
            entries.append(PlaylistEntry(path, title, duration))
        else:
            skipped += 1
        title, duration = "", 0
    return entries, skipped


def read_playlist(path: str):
    """:func:`parse_m3u` of the file at *path*; PlaylistError when it is no
    regular file, unreadable or larger than MAX_PLAYLIST_BYTES."""
    import stat as stat_module

    try:
        st = os.stat(path)
    except OSError as exc:
        raise PlaylistError(f"cannot read the playlist: {exc.strerror or exc}") from exc
    if not stat_module.S_ISREG(st.st_mode):
        raise PlaylistError("the playlist is no regular file")
    if st.st_size > MAX_PLAYLIST_BYTES:
        raise PlaylistError(f"the playlist is larger than {MAX_PLAYLIST_BYTES >> 10} KiB")
    try:
        with open(path, "rb") as fh:
            data = fh.read(MAX_PLAYLIST_BYTES + 1)
    except OSError as exc:
        raise PlaylistError(f"cannot read the playlist: {exc.strerror or exc}") from exc
    if len(data) > MAX_PLAYLIST_BYTES:
        raise PlaylistError(f"the playlist is larger than {MAX_PLAYLIST_BYTES >> 10} KiB")
    return parse_m3u(data, os.path.dirname(os.path.abspath(path)))


def write_playlist(path: str, entries) -> tuple[int, int]:
    """Write *entries* as an extended M3U in UTF-8 (atomically): paths under
    the playlist's folder relative, others absolute. Temporary copies of
    remote tracks and paths a line cannot hold are left out. Returns
    (written, left out)."""
    import tempfile

    folder = os.path.dirname(os.path.abspath(path))
    lines = ["#EXTM3U"]
    written = skipped = 0
    for entry in entries:
        track = os.path.abspath(entry.path)
        if _is_temp_copy(track) or not track.isprintable():
            skipped += 1
            continue
        rel = os.path.relpath(track, folder)
        inside = not (rel == os.pardir or rel.startswith(os.pardir + os.sep) or os.path.isabs(rel))
        title = _clean_text(entry.title or "")
        if title or entry.duration:
            lines.append(f"#EXTINF:{int(entry.duration) if entry.duration else -1},{title}")
        lines.append(rel.replace(os.sep, "/") if inside else track)
        written += 1
    fd, tmp = tempfile.mkstemp(prefix=".playlist-", suffix=".tmp", dir=folder)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write("\n".join(lines) + "\n")
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return written, skipped


def state_file():
    """The extension's own settings: the last playlist, position, volume."""
    from pathlib import Path

    return Path.home() / ".config" / "axross" / "media_player.json"


def read_state(path) -> tuple[dict, bool]:
    """The saved state and whether the file could be used (a missing file
    can; a broken, huge or non-object one cannot - it is kept aside before
    the next save replaces it)."""
    import json
    import stat as stat_module

    try:
        if not stat_module.S_ISREG(os.stat(path).st_mode):
            return {}, False  # never open a FIFO: it would block
        with open(path, "rb") as fh:
            data = fh.read(MAX_STATE_BYTES + 1)
    except FileNotFoundError:
        return {}, True
    except OSError:
        return {}, False
    if len(data) > MAX_STATE_BYTES:
        return {}, False
    try:
        state = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return {}, False
    return (state, True) if isinstance(state, dict) else ({}, False)


def write_state(path, state: dict, *, keep_old: bool = False) -> None:
    """Save *state* privately (0600, atomic); *keep_old* first keeps a copy
    of an unreadable file next to it."""
    import json

    from core.secure_storage import keep_unreadable_copy, write_secret_file

    if keep_old and not keep_unreadable_copy(path):
        raise OSError(f"{path} is unreadable and could not be kept aside")
    write_secret_file(str(path), json.dumps(state, ensure_ascii=False, indent=1) + "\n")


# -- DSP (numpy) ---------------------------------------------------------------------


def _gain_curve(gains_db, rate: int, n_fft: int):
    """Linear gain per rfft bin: the band gains interpolated over the log of
    the frequency, flat beyond the outer bands."""
    freqs = np.fft.rfftfreq(n_fft, 1.0 / rate)
    logf = np.log10(np.maximum(freqs, BANDS[0]))
    db = np.interp(logf, np.log10(BANDS), gains_db)
    return (10.0 ** (db / 20.0)).astype(np.float32)


class Equalizer:
    """Ten bands by short-time FFT with 50 % overlap-add: sqrt-Hann before
    and after, so unity gains give back the input exactly, delayed by
    :attr:`latency` samples, whatever the block sizes."""

    def __init__(self, rate: int = RATE, channels: int = 2) -> None:
        self.rate = rate
        self.channels = channels
        n = np.arange(FRAME)
        hann = 0.5 - 0.5 * np.cos(2 * np.pi * n / FRAME)  # periodic: sums to 1 at 50 %
        self._window = np.sqrt(hann).astype(np.float32)[:, None]
        self.latency = HOP
        self.gains_db = [0.0] * 10
        self._curve = _gain_curve(self.gains_db, rate, FRAME)[:, None]
        self.reset()

    def reset(self) -> None:
        self._in = np.zeros((HOP, self.channels), np.float32)  # the pre-pad: latency
        self._acc = np.zeros((FRAME, self.channels), np.float32)

    def set_gains(self, gains_db) -> None:
        if len(gains_db) != len(BANDS):
            raise ValueError(f"{len(BANDS)} band gains, not {len(gains_db)}")
        self.gains_db = [float(max(-MAX_GAIN_DB, min(MAX_GAIN_DB, g))) for g in gains_db]
        self._curve = _gain_curve(self.gains_db, self.rate, FRAME)[:, None]

    @property
    def flat(self) -> bool:
        return all(g == 0.0 for g in self.gains_db)

    def process(self, block):
        """Filtered samples for *block* (frames x channels); as many as are
        complete, so the output lags by :attr:`latency` overall."""
        block = np.asarray(block, np.float32).reshape(-1, self.channels)
        self._in = np.concatenate([self._in, block])
        out = []
        while len(self._in) >= FRAME:
            frame = self._in[:FRAME] * self._window
            spectrum = np.fft.rfft(frame, axis=0) * self._curve
            self._acc += np.fft.irfft(spectrum, n=FRAME, axis=0).astype(np.float32) * self._window
            out.append(self._acc[:HOP].copy())
            self._acc = np.concatenate([self._acc[HOP:], np.zeros((HOP, self.channels), np.float32)])
            self._in = self._in[HOP:]
        return np.concatenate(out) if out else np.zeros((0, self.channels), np.float32)

    def flush(self):
        """The rest, as if silence followed."""
        tail = self.process(np.zeros((FRAME, self.channels), np.float32))
        self.reset()
        return tail


def bar_centres(rate: int, n_fft: int, n_bars: int):
    top = min(16000.0, rate / 2)
    edges = np.geomspace(40.0, top, n_bars + 1)
    return np.sqrt(edges[:-1] * edges[1:])


def spectrum_bars(samples, rate: int, n_bars: int = 32):
    """0..1 per bar (log-spaced, 40 Hz to 16 kHz) for the last samples:
    the loudest bin of each bar on a -70..0 dBFS scale. A bar narrower
    than the bin spacing (21.5 Hz at 2048 frames: the low bars) holds no
    bin; it takes the spectrum interpolated at its centre - it stayed at
    0 for ever before (bars 1 and 3 of 32, a quarter of 128)."""
    data = np.asarray(samples, np.float32)
    mono = data.mean(axis=1) if data.ndim == 2 else data
    n = len(mono)
    if n == 0:
        return np.zeros(n_bars, np.float32)
    window = 0.5 - 0.5 * np.cos(2 * np.pi * np.arange(n) / n)
    mags = np.abs(np.fft.rfft(mono * window))
    freqs = np.fft.rfftfreq(n, 1.0 / rate)
    edges = np.geomspace(40.0, min(16000.0, rate / 2), n_bars + 1)
    starts = np.searchsorted(freqs, edges[:-1], side="left")  # the bins in [edge, next edge)
    stops = np.searchsorted(freqs, edges[1:], side="left")
    has = stops > starts
    peak = np.interp(np.sqrt(edges[:-1] * edges[1:]), freqs, mags)
    if has.any():
        # The bars are contiguous: the bins of one end where the next one's
        # begin, so a reduceat over the starts (and the last stop) is each
        # bar's maximum. The appended 0 keeps a stop at the end in range.
        bounds = np.append(starts[has], stops[has][-1])
        peak[has] = np.maximum.reduceat(np.append(mags, 0.0), bounds)[:-1]
    ref = n / 4.0  # a full-scale sine under the Hann window
    with np.errstate(divide="ignore"):
        db = np.where(peak > 0, 20 * np.log10(np.maximum(peak, 1e-300) / ref), -200.0)
    return np.clip((db + 70.0) / 70.0, 0.0, 1.0).astype(np.float32)


def waveform(samples, n_points: int):
    """*n_points* evenly spaced values of the mono mix, clipped to -1..1:
    the oscilloscope's trace (all zero for no samples)."""
    if n_points < 2:
        raise ValueError(f"a waveform needs at least 2 points, not {n_points}")
    data = np.asarray(samples, np.float32)
    mono = data.mean(axis=1) if data.ndim == 2 else data
    if len(mono) == 0:
        return np.zeros(n_points, np.float32)
    index = np.linspace(0, len(mono) - 1, n_points).astype(np.intp)
    return np.clip(mono[index], -1.0, 1.0)


#: The VU meter shows -VU_RANGE_DB..0 dBFS.
VU_RANGE_DB = 60.0


def _vu_scale(value: float) -> float:
    if value <= 0.0:
        return 0.0
    db = 20.0 * float(np.log10(value))
    return min(1.0, max(0.0, (db + VU_RANGE_DB) / VU_RANGE_DB))


def vu_levels(samples) -> tuple[float, float, float, float]:
    """RMS left, RMS right, peak left, peak right of the last samples, each
    0..1 on a -60..0 dBFS scale (mono: both channels the same)."""
    data = np.asarray(samples, np.float32)
    if data.ndim == 1:
        data = data[:, None]
    if data.ndim != 2 or len(data) == 0 or data.shape[1] == 0:
        return (0.0, 0.0, 0.0, 0.0)
    left = data[:, 0]
    right = data[:, 1] if data.shape[1] > 1 else left
    rms = [float(np.sqrt(np.mean(np.square(channel)))) for channel in (left, right)]
    peak = [float(np.max(np.abs(channel))) for channel in (left, right)]
    rms_l, rms_r, peak_l, peak_r = (_vu_scale(v) for v in (*rms, *peak))
    return (rms_l, rms_r, peak_l, peak_r)


# -- playback --------------------------------------------------------------------------


class MemorySink:
    """An audio sink that keeps what it is given (tests, no sound card)."""

    def __init__(self) -> None:
        self.data = bytearray()
        self.running = False

    def start(self) -> None:
        self.running = True

    def bytes_free(self) -> int:
        return 1 << 30

    def write(self, data: bytes) -> int:
        self.data += data
        return len(data)

    def suspend(self) -> None:
        self.running = False

    def resume(self) -> None:
        self.running = True

    def stop(self) -> None:
        self.running = False

    def set_volume(self, volume: float) -> None:
        pass

    def samples(self, channels: int = 2):
        return np.frombuffer(bytes(self.data), np.float32).reshape(-1, channels)


# -- the sound card's format ------------------------------------------------------------
#
# Measured against real PipeWire sinks: a QAudioSink opened in a format the
# device reports unsupported (float stereo on every mono sink - Bluetooth in
# its headset profile is one) stays in StoppedState under Qt's PipeWire
# backend: nothing plays, the position stands. The same sinks played float
# mono, or their preferred format, at 1.00x. So the engine asks the device.


def choose_sink_format(supported, preferred) -> tuple[int, int, str]:
    """(rate, channels, sample format) to open the sound card with:
    float stereo at :data:`RATE`, else float mono at RATE (the engine mixes
    down), else float at the device's rate, else its *preferred* format
    (rate, channels, sample format). *supported(rate, channels, format)*
    answers for the device."""
    rate, channels, _fmt = preferred
    for candidate in ((RATE, 2, "Float"), (RATE, 1, "Float"), (rate, 2, "Float"),
                      (rate, 1, "Float")):
        if supported(*candidate):
            return candidate
    return preferred


def qt_format(rate: int, channels: int, sample_format: str):
    from PyQt6.QtMultimedia import QAudioFormat

    fmt = QAudioFormat()
    fmt.setSampleRate(int(rate))
    fmt.setChannelCount(int(channels))
    fmt.setSampleFormat(getattr(QAudioFormat.SampleFormat, sample_format))
    return fmt


def format_tuple(fmt) -> tuple[int, int, str]:
    return fmt.sampleRate(), fmt.channelCount(), fmt.sampleFormat().name


def device_sink_format(device):
    """The QAudioFormat :func:`choose_sink_format` picks for *device*."""
    preferred = format_tuple(device.preferredFormat())
    if preferred[2] not in SAMPLE_BYTES or preferred[0] <= 0 or preferred[1] <= 0:
        preferred = (RATE, 2, "Int16")
    chosen = choose_sink_format(
        lambda r, c, f: device.isFormatSupported(qt_format(r, c, f)), preferred)
    return qt_format(*chosen)


def routed_sink_format(_desired=None):
    """The sink format for the output device chosen in Settings > Audio
    (the system's default when none is)."""
    from PyQt6.QtMultimedia import QMediaDevices

    device = audio_route.output_device() or QMediaDevices.defaultAudioOutput()
    return device_sink_format(device)


def convert_frames(frames, channels: int, sample_format: str) -> bytes:
    """Float stereo *frames* (n x 2) as the sound card takes them: mono is
    the mean of both channels, more than two channels get the pair and
    silence; Int16/Int32/UInt8 are scaled and clipped."""
    if sample_format not in SAMPLE_BYTES:
        raise ValueError(f"unknown sample format {sample_format!r}")
    frames = np.asarray(frames, np.float32).reshape(-1, 2)
    if channels == 1:
        data = frames.mean(axis=1, keepdims=True)
    elif channels == 2:
        data = frames
    else:
        data = np.zeros((len(frames), channels), np.float32)
        data[:, :2] = frames
    if sample_format == "Float":
        return np.ascontiguousarray(data, np.float32).tobytes()
    clipped = np.clip(data.astype(np.float64), -1.0, 1.0)
    if sample_format == "Int16":
        return (clipped * 32767).astype(np.int16).tobytes()
    if sample_format == "Int32":
        return (clipped * 2147483647).astype(np.int32).tobytes()
    return (128 + clipped * 127).astype(np.uint8).tobytes()


class PlaybackMonitor:
    """Judges the sound card's speed: frames it took over the last
    :data:`MONITOR_WINDOW_SECONDS`, against real time. Reports once per
    track (:meth:`reset`); a pause or seek starts the window anew
    (:meth:`pause`)."""

    def __init__(self, rate: int) -> None:
        self.rate = rate
        self.reset()

    def reset(self) -> None:
        from collections import deque

        self._samples = deque()
        self._reported = False

    def pause(self) -> None:
        self._samples.clear()

    def update(self, now: float, frames: int, backend: str = "") -> str | None:
        """Feed the frames taken so far at *now*; a sentence for the user
        when the speed is wrong, once."""
        if self._reported:
            return None
        self._samples.append((now, frames))
        while len(self._samples) > 1 and now - self._samples[1][0] >= MONITOR_WINDOW_SECONDS:
            self._samples.popleft()
        first_time, first_frames = self._samples[0]
        span = now - first_time
        if span < MONITOR_WINDOW_SECONDS:
            return None
        speed = (frames - first_frames) / span / self.rate
        via = f" through {backend}" if backend else ""
        hint = tr("Choose PulseAudio (or another output) in Edit > Settings… > Audio.")
        if speed < 0.05:
            text = tr("The sound card takes no audio{via} - playback stands. {hint}").format(
                via=via, hint=hint)
        elif abs(speed - 1.0) > MONITOR_TOLERANCE:
            text = tr("The sound card plays at x{speed:.2f} speed{via} (measured over {seconds:g} s)"
                      " instead of x1.00. {hint}").format(speed=speed, via=via, hint=hint,
                                                          seconds=MONITOR_WINDOW_SECONDS)
        else:
            return None
        self._reported = True
        return text


class QtSink:
    """The sound card: QAudioSink in push mode, on the output device chosen
    in Edit > Settings… > Audio (core.audio_route; the system's default
    when none is or it is not connected), in the format *fmt* - one the
    device takes (:func:`routed_sink_format`)."""

    def __init__(self, fmt) -> None:
        from PyQt6.QtMultimedia import QAudioSink, QMediaDevices

        device = audio_route.output_device() or QMediaDevices.defaultAudioOutput()
        self._sink = QAudioSink(device, fmt)
        prime_notify_lookups(self._sink)
        rate, channels, sample_format = format_tuple(fmt)
        self._sink.setBufferSize(rate * channels * SAMPLE_BYTES.get(sample_format, 4) // 4)  # 250 ms
        self._io = None

    def start(self) -> None:
        self._io = self._sink.start()

    def bytes_free(self) -> int:
        return self._sink.bytesFree() if self._io is not None else 0

    def write(self, data: bytes) -> int:
        return int(self._io.write(data)) if self._io is not None else 0

    def suspend(self) -> None:
        self._sink.suspend()

    def resume(self) -> None:
        self._sink.resume()

    def stop(self) -> None:
        self._sink.stop()
        self._io = None

    def set_volume(self, volume: float) -> None:
        self._sink.setVolume(volume)


def _audio_format(rate: int = RATE):
    """What the decoder delivers and the equalizer works on: float stereo."""
    return qt_format(rate, 2, "Float")


class EqEngine(QObject):
    """Qt's FFmpeg decoder -> the equalizer -> an audio sink, pushed by a
    timer; keeps the last samples played for the spectrum.

    Seeking: QAudioDecoder has no seek, so :meth:`seek` takes the target
    from the audio already decoded ahead when it lies there (the equalizer
    runs on unbroken), lets the decoder run on and drops what it decodes
    up to the target when it lies ahead, and starts the decoder again from
    the top otherwise. Dropped audio skips the equalizer, which starts from
    silence at the target - as a fresh start there would. The decoder runs
    600-2500x real time (MP3/Ogg/FLAC/WAV measured), so a seek 10 minutes
    into an MP3 takes about a second, into a WAV a quarter of one.
    """

    finished_playing = pyqtSignal()
    changed = pyqtSignal()
    #: The track cannot be played; the reason.
    failed = pyqtSignal(str)
    #: The sound card plays too slow, too fast or not at all; the sentence
    #: (core: PlaybackMonitor).
    playback_problem = pyqtSignal(str)

    def __init__(self, sink_factory=None, negotiate=None) -> None:
        super().__init__()
        from PyQt6.QtMultimedia import QAudioDecoder

        self.sink_factory = sink_factory or QtSink
        #: desired QAudioFormat -> the one to open the sink with. The real
        #: sound card is asked (routed_sink_format); a test sink takes all.
        if negotiate is None:
            negotiate = routed_sink_format if self.sink_factory is QtSink else (lambda fmt: fmt)
        self.negotiate = negotiate
        #: The rate the decoder delivers and the equalizer runs at (the
        #: sound card's), the sink's (rate, channels, sample format), its
        #: bytes per frame, and converted bytes the sink did not take yet.
        self.rate = RATE
        self._out_format = (RATE, 2, "Float")
        self._out_bpf = 8
        self._sink_format = None
        self._carry = b""
        self.monitor = PlaybackMonitor(RATE)
        self.equalizer = Equalizer(RATE, 2)
        self.eq_enabled = True
        self._user_gains = [0.0] * len(BANDS)
        self.state = "stopped"
        self.error = ""
        self.finished = False
        self.loaded = False
        self.path = ""
        self.volume = 1.0
        self._decoder = QAudioDecoder(self)
        prime_notify_lookups(self._decoder)
        self._decoder.setAudioFormat(_audio_format(self.rate))
        self._decoder.bufferReady.connect(self._decoded)
        self._decoder.finished.connect(self._decoder_done)
        self._decoder.error.connect(self._decoder_error)
        self._decoder.durationChanged.connect(self._duration_known)
        #: Decoded float stereo frames not through the equalizer yet (up to
        #: MAX_AHEAD_SECONDS), and equalized ones the sink has not taken. The
        #: equalizer runs when the sink takes audio, not when it is decoded:
        #: run at decode time, a slider moved during playback was heard
        #: 2.35 s later (measured) - after the queue ahead had played.
        self._pending = bytearray()
        self._ready = bytearray()
        #: Frames fed to the equalizer since the chain (re)started, frames it
        #: gave back (after its latency was dropped), whether its tail went out.
        self._fed = 0
        self._produced = 0
        self._flushed = False
        self._decoding_done = False
        self._finish_waiting = False
        #: True while this engine stops the decoder itself: QAudioDecoder
        #: emits finished() from stop(), which is no end of the track.
        self._stopping_decoder = False
        self._decoder_starts = 0
        self._skip = 0
        self._sink = None
        #: Track frame the frames written to the sink count from (a seek
        #: target); frames written since; frames read from the decoder
        #: since its start; the frame decoding drops up to (None: none).
        self._base_frames = 0
        self._written_frames = 0
        self._raw_frames = 0
        self._drop_to: int | None = None
        #: Where play() starts from a stop (a seek before playing).
        self._start_frames = 0
        self._duration = 0
        self._decoded_frames = 0
        self._recent = np.zeros((FRAME, 2), np.float32)
        self._timer = QTimer(self)
        self._timer.setInterval(10)
        self._timer.timeout.connect(self._pump)

    @property
    def gains_db(self) -> list[float]:
        """The user's band gains (kept while the equalizer is off)."""
        return list(self._user_gains)

    def set_gains(self, gains) -> None:
        self.equalizer.set_gains(gains)  # validates and clamps
        self._user_gains = list(self.equalizer.gains_db)
        if not self.eq_enabled:
            self.equalizer.set_gains([0.0] * len(BANDS))

    def set_eq_enabled(self, on: bool) -> None:
        """Off is flat: the equalizer stays in the chain (taking it out
        mid-track would jump by its latency)."""
        self.eq_enabled = bool(on)
        self.equalizer.set_gains(self._user_gains if on else [0.0] * len(BANDS))

    def load(self, path: str) -> None:
        self.stop()
        self.path = path
        self.error = ""
        self.finished = False
        self.loaded = True
        self._duration = 0
        self.monitor.reset()
        self._decoder.setSource(QUrl.fromLocalFile(path))
        self.changed.emit()

    def play(self) -> None:
        if not self.loaded:
            return
        if self.state == "paused":
            self.state = "playing"
            if self._sink is not None:
                self._sink.resume()
            self._timer.start()
            self.changed.emit()
            return
        if self.state == "playing":
            return
        if not os.path.isfile(self.path):
            self._fail(f"{self.path}: no such file")
            return
        self.finished = False
        start_ms = self._start_frames * 1000 // self.rate
        self._prepare_format()
        self._base_frames = start_ms * self.rate // 1000 if self._start_frames else 0
        self._start_frames = 0
        self._written_frames = 0
        self.monitor.pause()
        self._sink = self._new_sink()
        self.state = "playing"
        # An unreadable file fails inside start() already (_fail stops all).
        self._start_decoder(self._base_frames)
        if self.state != "playing":
            return
        self._timer.start()
        self.changed.emit()

    def pause(self) -> None:
        if self.state == "playing":
            self.state = "paused"
            self._timer.stop()
            self.monitor.pause()
            if self._sink is not None:
                self._sink.suspend()
            self.changed.emit()

    def stop(self) -> None:
        self._timer.stop()
        self._stop_decoder()
        if self._sink is not None:
            self._sink.stop()
            self._sink = None
        self._pending.clear()
        self._ready.clear()
        self._carry = b""
        self._written_frames = 0
        self._base_frames = 0
        self._start_frames = 0
        self.state = "stopped"
        self.changed.emit()

    def seek(self, ms) -> None:
        """Play on from *ms* (clamped to the start); past the end the
        track ends as if played. Paused stays paused, stopped starts there
        on the next play()."""
        if not self.loaded or self.error:
            return
        target = max(0, int(ms)) * self.rate // 1000
        if self.state == "stopped":
            self._start_frames = target
            self.changed.emit()
            return
        if self._duration > 0 and target >= self._duration * self.rate // 1000:
            self._end_track()
            return
        current = self._base_frames + self._written_frames
        pending_start = self._base_frames + self._fed  # track frame of the queue's first
        ahead = len(self._pending) // 8
        if current <= target < pending_start + ahead:
            # Decoded already: drop up to the target (a target inside the
            # few milliseconds in the equalizer starts at the queue).
            del self._pending[: max(0, target - pending_start) * 8]
            target = max(target, pending_start)
            self._reset_equalizer()
        elif not self._decoding_done and target >= self._raw_frames:
            self._restart_chain(target)
        elif self._decoding_done and target >= current + ahead:
            self._end_track()
            return
        else:
            self._start_decoder(target)
        self._base_frames = target
        self._written_frames = 0
        self._carry = b""
        self.monitor.pause()
        # What the sound card holds is from before the seek.
        if self._sink is not None:
            self._sink.stop()
        self._sink = self._new_sink()
        if self.state == "paused":
            self._sink.suspend()
        self.changed.emit()

    def set_volume(self, volume: float) -> None:
        self.volume = max(0.0, min(1.0, volume))
        if self._sink is not None:
            self._sink.set_volume(self.volume)

    def reroute(self) -> None:
        """The output device was changed (Edit > Settings… > Audio): a
        playing or paused track goes on through a new sink, which the sink
        factory opens on the device now chosen. What the old sink still
        held (at most its 250 ms buffer) is not played."""
        if self._sink is None or self.state not in ("playing", "paused"):
            return
        position = self.position_ms()
        old_rate = self.rate
        self._sink.stop()
        self._sink = None
        self._carry = b""
        self._prepare_format()
        self.monitor.pause()
        if self.rate != old_rate:
            # Another rate: the decoder starts again at the position.
            target = position * self.rate // 1000
            self._start_decoder(target)
            self._base_frames = target
            self._written_frames = 0
        self._sink = self._new_sink()
        if self.state == "paused":
            self._sink.suspend()

    def position_ms(self) -> int:
        if self.state == "stopped":
            return int(self._start_frames * 1000 // self.rate)
        return int((self._base_frames + self._written_frames) * 1000 // self.rate)

    def duration_ms(self) -> int:
        """The track's length once the decoder knows it, else 0."""
        return int(self._duration)

    def current_bars(self, n_bars: int = 32):
        return spectrum_bars(self._recent, self.rate, n_bars)

    def current_samples(self):
        """The last FRAME frames written to the sound card (frames x 2,
        float32), for the oscilloscope and the VU meter. Replaced, never
        changed in place."""
        return self._recent

    # -- the chain -------------------------------------------------------------------------

    def _prepare_format(self) -> None:
        """Ask the sound card for its format; a new rate goes to the decoder
        (which resamples) and the equalizer. Before the decoder starts."""
        fmt = self.negotiate(_audio_format(RATE))
        rate, channels, sample_format = format_tuple(fmt)
        if sample_format not in SAMPLE_BYTES:
            fmt = qt_format(rate, channels, "Float")
            sample_format = "Float"
        self._sink_format = fmt
        self._out_format = (rate, channels, sample_format)
        self._out_bpf = channels * SAMPLE_BYTES[sample_format]
        if rate != self.rate:
            self._stop_decoder()
            self.rate = rate
            self._decoder.setAudioFormat(_audio_format(rate))
            self.equalizer = Equalizer(rate, 2)
            self.equalizer.set_gains(self._user_gains if self.eq_enabled else [0.0] * len(BANDS))
            self.monitor = PlaybackMonitor(rate)
            self._recent = np.zeros((FRAME, 2), np.float32)

    def _new_sink(self):
        if self._sink_format is None:
            self._prepare_format()
        sink = self.sink_factory(self._sink_format)
        sink.set_volume(self.volume)
        sink.start()
        return sink

    def _duration_known(self, ms) -> None:
        if int(ms) > 0:  # stop() reports -1
            self._duration = int(ms)

    def _stop_decoder(self) -> None:
        self._stopping_decoder = True
        try:
            self._decoder.stop()
            # A buffer not read yet stays available after stop() and would
            # be the first one read after the next start() - audio from the
            # old position counted as the new run's first frames.
            for _ in range(64):
                if not self._decoder.bufferAvailable():
                    break
                self._decoder.read()
        finally:
            self._stopping_decoder = False

    def _reset_equalizer(self) -> None:
        """A fresh equalizer for audio that does not follow on what went
        through it: what it holds is dropped."""
        self.equalizer.reset()
        self._ready.clear()
        self._fed = self._produced = 0
        self._flushed = False
        # The equalizer's output lags by its latency: that many leading
        # samples are dropped, and its flush supplies them at the end.
        self._skip = self.equalizer.latency

    def _restart_chain(self, drop_to: int) -> None:
        """A fresh equalizer and queue for audio from frame *drop_to* on;
        the decoder (running) drops what it decodes before it."""
        self._reset_equalizer()
        self._pending.clear()
        self._decoded_frames = 0
        self._drop_to = drop_to if drop_to > self._raw_frames else None
        self._decoding_done = False

    def _start_decoder(self, drop_to: int) -> None:
        """Decode from the top, dropping the frames before *drop_to*."""
        self._stop_decoder()
        self._raw_frames = 0
        self._finish_waiting = False
        self._restart_chain(drop_to)
        self._decoder_starts += 1
        self._decoder.start()

    def _end_track(self) -> None:
        """The end of the track, reached by a seek past it."""
        self._timer.stop()
        self._stop_decoder()
        if self._sink is not None:
            self._sink.stop()
            self._sink = None
        self._pending.clear()
        self._ready.clear()
        self._carry = b""
        self._decoding_done = True
        self._written_frames = self._base_frames = self._start_frames = 0
        self.state = "stopped"
        self.finished = True
        self.changed.emit()
        self.finished_playing.emit()

    def _room(self) -> bool:
        """Whether one more decoded buffer may be taken now."""
        return len(self._pending) + len(self._ready) < MAX_AHEAD_SECONDS * self.rate * 8

    def _write_to(self, sink) -> None:
        """Hand the sink what it takes now, in its format: converted bytes
        it did not take last time first, then whole frames of the queue."""
        if self._carry:
            taken = sink.write(self._carry)
            self._carry = self._carry[taken:]
            if self._carry:
                return
        free = sink.bytes_free()
        frames_free = free // self._out_bpf
        if not frames_free:
            return
        self._equalize(frames_free)
        count = min(frames_free, len(self._ready) // 8)
        if not count:
            return
        frames = np.frombuffer(bytes(self._ready[:count * 8]), np.float32).reshape(-1, 2)
        del self._ready[:count * 8]
        _rate, channels, sample_format = self._out_format
        data = (frames.tobytes() if (channels, sample_format) == (2, "Float")
                else convert_frames(frames, channels, sample_format))
        taken = sink.write(data)
        if taken < len(data):
            self._carry = data[taken:]
        # The frames count as played once handed over (the rest follows).
        self._written_frames += count
        self._recent = np.concatenate([self._recent, frames])[-FRAME:]

    def _decoded(self) -> None:
        # A full queue leaves the buffer with the decoder, which then waits;
        # _pump takes it once the sound card has played some.
        if not self._room():
            return
        buffer = self._decoder.read()
        if not buffer.isValid() or buffer.byteCount() == 0:
            return
        size = buffer.byteCount() // 8 * 8
        start = self._raw_frames
        self._raw_frames += size // 8
        offset = 0
        if self._drop_to is not None:
            if self._raw_frames <= self._drop_to:
                return  # before the seek target: not even converted
            offset = self._drop_to - start
            self._drop_to = None
        raw = buffer.constData().asstring(size)
        self._decoded_frames += size // 8 - offset
        self._pending += raw[offset * 8:]

    def _equalize(self, wanted: int) -> None:
        """Run frames of the queue through the equalizer until *wanted*
        equalized frames wait for the sink (or the queue is empty; then,
        once decoding is done, the equalizer's tail)."""
        while len(self._ready) // 8 < wanted and self._pending:
            count = min(len(self._pending) // 8, max(HOP, wanted - len(self._ready) // 8))
            block = np.frombuffer(bytes(self._pending[:count * 8]), np.float32).reshape(-1, 2)
            del self._pending[:count * 8]
            self._fed += count
            self._take(self.equalizer.process(block))
        if self._decoding_done and not self._pending and not self._flushed:
            self._flushed = True
            tail = self.equalizer.flush()
            if self._skip:
                tail = tail[self._skip:]
                self._skip = 0
            self._take(tail[: max(0, self._fed - self._produced)])

    def _take(self, frames) -> None:
        """Equalized *frames* for the sink, after the latency is dropped."""
        if self._skip and len(frames):
            dropped = min(self._skip, len(frames))
            frames = frames[dropped:]
            self._skip -= dropped
        if len(frames):
            self._produced += len(frames)
            self._ready += np.ascontiguousarray(frames, np.float32).tobytes()

    def _decoder_done(self) -> None:
        if self._stopping_decoder:
            return  # stop() emits finished(): not the end of the track
        if self._decoder.bufferAvailable():
            self._finish_waiting = True  # the last buffer is not taken yet
            return
        self._finish_waiting = False
        self._drop_to = None  # a seek past the real end: nothing follows
        self._decoding_done = True  # the equalizer's tail follows the queue
        if self._raw_frames == 0 and not self.error:
            self._fail(f"{os.path.basename(self.path)}: no audio could be decoded")

    def _decoder_error(self, _error) -> None:
        self._fail(self._decoder.errorString() or "the file could not be decoded")

    def _fail(self, text: str) -> None:
        self.error = text
        self.stop()
        self.changed.emit()
        self.failed.emit(text)

    def _pump(self) -> None:
        sink = self._sink
        if sink is None:
            return
        while self._room() and self._decoder.bufferAvailable():
            before = self._raw_frames
            self._decoded()
            if self._raw_frames == before:
                break  # an empty buffer: never spin on it
        if self._finish_waiting and not self._decoder.bufferAvailable():
            self._decoder_done()
        self._write_to(sink)
        if self._decoding_done and not self._pending and not self._flushed:
            self._equalize(0)  # the equalizer's tail, also when the sink is full
        if self._pending or self._ready or self._carry or not self._decoding_done:
            problem = self.monitor.update(time.monotonic(), self._written_frames,
                                          _backend_name())
            if problem:
                log.warning("Media Player: %s", problem)
                self.playback_problem.emit(problem)
        else:
            self.monitor.pause()  # the end drains the sound card: not a speed
        if (self._decoding_done and self._flushed and not self._pending and not self._ready
                and not self._carry):
            self._timer.stop()
            self.state = "stopped"
            self.finished = True
            self.changed.emit()
            self.finished_playing.emit()


class SimpleEngine(QObject):
    """Playback without numpy: QMediaPlayer, no equalizer, no spectrum."""

    finished_playing = pyqtSignal()
    changed = pyqtSignal()
    #: The track cannot be played; the reason.
    failed = pyqtSignal(str)

    def __init__(self) -> None:
        super().__init__()
        from PyQt6.QtMultimedia import QAudioOutput, QMediaPlayer

        self._player = QMediaPlayer(self)
        self._output = QAudioOutput(self)
        prime_notify_lookups(self._player)
        prime_notify_lookups(self._output)
        device = audio_route.output_device()
        if device is not None:
            self._output.setDevice(device)
        self._player.setAudioOutput(self._output)
        self._player.mediaStatusChanged.connect(self._status)
        self._player.errorOccurred.connect(lambda _e, text: self._fail(text))
        self.state, self.error, self.finished, self.loaded, self.path = "stopped", "", False, False, ""
        self.gains_db = [0.0] * 10
        #: Where play() starts from a stop: QMediaPlayer ignores a
        #: position set before it plays.
        self._start_ms = 0

    def _status(self, status) -> None:
        from PyQt6.QtMultimedia import QMediaPlayer

        if status == QMediaPlayer.MediaStatus.EndOfMedia and self.state != "stopped":
            self._ended()

    def _ended(self) -> None:
        self.state, self.finished, self._start_ms = "stopped", True, 0
        self.changed.emit()
        self.finished_playing.emit()

    def _fail(self, text: str) -> None:
        self.error = text or "the file could not be played"
        self.state = "stopped"
        self.changed.emit()
        self.failed.emit(self.error)

    def load(self, path: str) -> None:
        self._player.stop()
        self.path, self.error, self.finished, self.loaded = path, "", False, True
        self.state, self._start_ms = "stopped", 0
        self._player.setSource(QUrl.fromLocalFile(path))

    def play(self) -> None:
        if not self.loaded or self.state == "playing":
            return
        start, self._start_ms = (self._start_ms if self.state == "stopped" else 0), 0
        self.finished = False
        self._player.play()
        if start:
            self._player.setPosition(start)
        self.state = "playing"
        self.changed.emit()

    def pause(self) -> None:
        if self.state != "playing":
            return
        self._player.pause()
        self.state = "paused"
        self.changed.emit()

    def stop(self) -> None:
        self._player.stop()
        self.state, self._start_ms = "stopped", 0
        self.changed.emit()

    def seek(self, ms) -> None:
        """As :meth:`EqEngine.seek`."""
        if not self.loaded or self.error:
            return
        ms = max(0, int(ms))
        if self.state == "stopped":
            self._start_ms = ms
            self.changed.emit()
            return
        duration = self.duration_ms()
        if duration > 0 and ms >= duration:
            self._player.stop()
            self._ended()
            return
        self._player.setPosition(ms)
        self.changed.emit()

    def duration_ms(self) -> int:
        return max(0, int(self._player.duration()))

    def set_volume(self, volume: float) -> None:
        self._output.setVolume(volume)

    def reroute(self) -> None:
        """The output device was changed: QAudioOutput moves at once."""
        from PyQt6.QtMultimedia import QMediaDevices

        self._output.setDevice(audio_route.output_device()
                               or QMediaDevices.defaultAudioOutput())

    def set_gains(self, gains) -> None:
        pass

    def position_ms(self) -> int:
        if self.state == "stopped":
            return self._start_ms
        return int(self._player.position())

    def current_bars(self, n_bars: int = 32):
        return None

    def current_samples(self):
        return None


# -- the panel -----------------------------------------------------------------------


def _backend_name() -> str:
    """The audio backend this run plays through, for messages."""
    try:
        from core import multimedia_probe

        backend = multimedia_probe.active_backend()
    except Exception:  # noqa: BLE001 - a message must not fail
        return ""
    return {"pipewire": "PipeWire", "pulseaudio": "PulseAudio"}.get(backend or "", "")


def default_engine():
    """The engine a panel builds itself: the equalizer one with numpy."""
    return EqEngine() if np is not None else SimpleEngine()


class PendingEngine(QObject):
    """Stands in for the engine until Qt Multimedia answered
    (:meth:`PlayerPanel._start_engine`): it plays nothing, creates no
    multimedia object and keeps what the panel asked for - the track, its
    position, play, volume, gains - for the real engine. A panel whose
    audio does not start keeps it, so the saved state stays intact."""

    finished_playing = pyqtSignal()
    changed = pyqtSignal()
    failed = pyqtSignal(str)

    def __init__(self) -> None:
        super().__init__()
        self.state = "stopped"
        self.error = ""
        self.path = ""
        self.loaded = False
        self.position = 0
        self.wants_play = False
        self.gains: list[float] | None = None

    def load(self, path: str) -> None:
        self.path, self.loaded, self.position, self.wants_play = path, True, 0, False

    def play(self) -> None:
        self.wants_play = self.loaded

    def pause(self) -> None:
        self.wants_play = False

    def stop(self) -> None:
        self.wants_play = False

    def seek(self, ms) -> None:
        self.position = max(0, int(ms))

    def set_volume(self, volume: float) -> None:
        pass  # the panel's slider holds it; attaching applies it

    def set_gains(self, gains) -> None:
        self.gains = [float(g) for g in gains]

    def set_eq_enabled(self, on: bool) -> None:
        pass  # the panel's check box holds it; attaching applies it

    def position_ms(self) -> int:
        return self.position

    def duration_ms(self) -> int:
        return 0

    def current_bars(self, n_bars: int = 32):
        return None

    def current_samples(self):
        return None


#: The visualizations, in the order a click on them goes through them.
VISUALIZER_NAMES = {
    "spectrum": "Spectrum",
    "mirror": "Mirrored spectrum",
    "radial": "Radial spectrum",
    "scope": "Oscilloscope",
    "vu": "VU meter",
    "line": "Line spectrum",
    "waterfall": "Waterfall",
    "polar": "Polar spectrum",
    "lissajous": "Stereo scope",
    "starfield": "Starfield",
}
#: The faces drawn from the raw samples; the others from the spectrum bars.
_SAMPLE_MODES = ("scope", "vu", "lissajous")


class ColourScheme(NamedTuple):
    """A visualizer's colours (``#rrggbb``): the background, the bars from
    quiet over middle to loud, and the peak caps."""

    background: str
    low: str
    mid: str
    high: str
    peak: str


#: The named colour schemes; "classic" is the look the visualizer always had.
COLOUR_SCHEMES = {
    "classic": ColourScheme("#101418", "#2ecc71", "#f1c40f", "#e74c3c", "#ecf0f1"),
    "fire": ColourScheme("#140805", "#8b1a00", "#ff6a00", "#ffd84d", "#fff6e0"),
    "ice": ColourScheme("#06111c", "#1b4f8a", "#3fa9f5", "#bdeaff", "#ffffff"),
    "neon": ColourScheme("#0b0016", "#00e5ff", "#ff2bd6", "#faff00", "#ffffff"),
    "mono": ColourScheme("#0c0c0c", "#555555", "#a0a0a0", "#e8e8e8", "#ffffff"),
}
#: Every scheme the menu offers: the named ones, the app theme's, the user's.
SCHEME_NAMES = {
    "classic": "Classic",
    "fire": "Fire",
    "ice": "Ice",
    "neon": "Neon",
    "mono": "Mono",
    "theme": "Follow the theme",
    "custom": "Custom",
}
DEFAULT_SCHEME = "classic"
#: The colours a user picks for "custom" (the middle bar colour lies between
#: low and high), and what they start as.
CUSTOM_COLOURS = {"background": "#000000", "low": "#1e90ff", "high": "#ff1493",
                  "peak": "#ffffff"}
CUSTOM_LABELS = {"background": "Background", "low": "Quiet bars", "high": "Loud bars",
                 "peak": "Peaks"}
#: The least contrast a peak cap keeps on the background: WCAG 2.x success
#: criterion 1.4.11 (non-text contrast) asks 3:1 of graphics that carry
#: information. Black or white always reach it: one of them has at least
#: sqrt(21) = 4.58:1 on any colour.
MIN_PEAK_CONTRAST = 3.0

#: The options: (lowest, highest, default).
#: * bars - 8 is the fewest a radial or polar face still reads as round;
#:   above 128 more than a quarter of the bars would only interpolate
#:   between the same FFT bins (2048 frames: 21.5 Hz apart).
#: * peak_fall - % of the height a peak cap falls a second; 45 is the
#:   0.015 a frame at 30 frames a second the caps always fell.
#: * smoothing - % of a bar's height kept when the sound gets quieter, a
#:   frame at the default 30 fps (85: the old 0.85; at other rates the same
#:   decay a second); at 95 a bar still falls to a tenth in 1.5 s.
#: * fps - frames a second at most: below 10 it stutters, 60 is the usual
#:   display refresh.
#: Peak fall and smoothing are per second, so the frame rate cap does not
#: change how the bars move.
VISUAL_OPTIONS = {
    "bars": (8, 128, 32),
    "peak_fall": (5, 300, 45),
    "smoothing": (0, 95, 85),
    "fps": (10, 60, 30),
}
VISUAL_OPTION_LABELS = {
    "bars": ("Bars", ""),
    "peak_fall": ("Peak fall speed", " %/s"),
    "smoothing": ("Smoothing", " %"),
    "fps": ("Frame rate cap", " fps"),
}
#: A face may take half a frame at the highest frame rate cap - painting
#: runs on the GUI thread, the other half is the rest of the window's.
#: tests/test_media_player_visual_modes.py measures every face against it
#: fullscreen (1920x1080) with the most bars and white noise (the worst case).
PAINT_BUDGET_MS = 1000 / VISUAL_OPTIONS["fps"][1] / 2


def clamp_option(name: str, value) -> int:
    """*value* for option *name* within its range; anything but an int
    gives the default (an unknown name raises KeyError)."""
    low, high, default = VISUAL_OPTIONS[name]
    if not isinstance(value, int) or isinstance(value, bool):
        return default
    return max(low, min(high, value))


def _mix(a: str, b: str, t: float) -> str:
    """``#rrggbb`` a share *t* of the way from *a* to *b*."""
    ca, cb = QColor(a), QColor(b)
    return QColor(round(ca.red() + (cb.red() - ca.red()) * t),
                  round(ca.green() + (cb.green() - ca.green()) * t),
                  round(ca.blue() + (cb.blue() - ca.blue()) * t)).name()


def readable_on(colour: str, background: str, minimum: float = MIN_PEAK_CONTRAST) -> str:
    """*colour* when it has *minimum* contrast on *background*; else the
    nearest step of it towards white or black that has (its hue kept as
    far as it can be)."""
    if contrast_ratio(colour, background) >= minimum:
        return colour
    for step in range(1, 11):
        for target in ("#ffffff", "#000000"):
            candidate = _mix(colour, target, step / 10)
            if contrast_ratio(candidate, background) >= minimum:
                return candidate
    return "#ffffff"  # pragma: no cover - white or black always reach 4.58:1


def peak_contrast(scheme: ColourScheme) -> float:
    return contrast_ratio(scheme.peak, scheme.background)


def custom_scheme(colours) -> ColourScheme:
    """The scheme from the user's colours (a dict of CUSTOM_COLOURS keys);
    a missing or broken colour is the default one, the peak is made
    readable on the background."""
    chosen = dict(CUSTOM_COLOURS)
    if isinstance(colours, dict):
        for key in CUSTOM_COLOURS:
            value = colours.get(key)
            if is_hex_colour(value):
                chosen[key] = value.lower()
    background = chosen["background"]
    return ColourScheme(background, chosen["low"], _mix(chosen["low"], chosen["high"], 0.5),
                        chosen["high"], readable_on(chosen["peak"], background))


def theme_scheme(palette) -> ColourScheme:
    """The scheme of the app theme: its base colour behind, its highlight
    colour for the bars, its text colour (made readable) for the peaks."""
    role = QPalette.ColorRole
    background = palette.color(role.Base).name()
    text = palette.color(role.Text).name()
    highlight = palette.color(role.Highlight).name()
    return ColourScheme(background, _mix(highlight, background, 0.45), highlight,
                        _mix(highlight, text, 0.5), readable_on(text, background))


def stereo_points(samples, n_points: int):
    """The stereo scope's (goniometer's) points: x = (R - L) / sqrt(2),
    y = (L + R) / sqrt(2), clipped to -1..1 - mono is a vertical line, the
    left channel alone the diagonal to the top left, the right alone the one
    to the top right. *n_points* evenly spaced over the samples."""
    data = np.asarray(samples, np.float32)
    if data.ndim == 2 and data.shape[1] >= 2:
        left, right = data[:, 0], data[:, 1]
    else:
        left = right = data.reshape(-1) if data.ndim < 2 else data[:, 0]
    if len(left) == 0:
        return np.zeros(n_points, np.float32), np.zeros(n_points, np.float32)
    index = np.linspace(0, len(left) - 1, n_points).astype(np.intp)
    left, right = left[index], right[index]
    root = math.sqrt(0.5)
    return (np.clip((right - left) * root, -1.0, 1.0), np.clip((left + right) * root, -1.0, 1.0))


def _segments(points) -> list:
    """*points* as separate line segments. An antialiased pen wider than a
    pixel strokes a polyline as one outline path, and a trace that crosses
    itself (noise in the oscilloscope, any stereo scope) made that cost
    79 ms for 256 points at 1280x720 - as segments 1 ms, the same look."""
    return [QLineF(points[i], points[i + 1]) for i in range(len(points) - 1)]


class Visualizer(QWidget):
    """The sound as a picture, at up to the fps cap while playing. A left
    click goes to the next face (:data:`VISUALIZER_NAMES`), a double click
    (or F11) asks for fullscreen and Esc out of it, the right button opens
    the menu: every face, every colour scheme, bar count and frame rate,
    and what the host adds (:attr:`menu_hook`). Each face asks the engine
    only for what it shows: the spectra, the waterfall and the starfield
    for an FFT (:meth:`current_bars`), the scopes and the VU meter for the
    raw samples (:meth:`current_samples`). An engine without numpy answers
    None: the face stays empty."""

    #: The default bar count (VISUAL_OPTIONS["bars"]).
    BARS = 32
    MODES = tuple(VISUALIZER_NAMES)
    #: Points of the oscilloscope's trace at most.
    SCOPE_POINTS = 256
    #: Points of the stereo scope, and the steps its older part fades in.
    LISSAJOUS_POINTS = 512
    LISSAJOUS_FADE = 4
    #: Rows of the waterfall's history (over 4 s at 30 fps).
    WATERFALL_ROWS = 128
    #: Stars of the starfield; what they travel a second (of their depth)
    #: in silence and on top with full bass; the bass is below BASS_HZ.
    STAR_COUNT = 300
    STAR_DRIFT = 0.15
    STAR_BOOST = 1.2
    STAR_NEAR = 0.04
    BASS_HZ = 250.0
    #: How long the face's name shows after a switch.
    LABEL_SECONDS = 1.5
    #: In fullscreen the mouse pointer hides after this long without a move.
    CURSOR_HIDE_MS = 2500
    #: The face now shown (one of MODES).
    mode_changed = pyqtSignal(str)
    #: The colour scheme, its custom colours, an option or hide_cursor changed.
    settings_changed = pyqtSignal()
    #: Fullscreen wanted (True) or not (False): double click, F11, Esc.
    fullscreen_requested = pyqtSignal(bool)

    def __init__(self, engine) -> None:
        super().__init__()
        self.engine = engine
        self.mode = self.MODES[0]
        self.options = {name: spec[2] for name, spec in VISUAL_OPTIONS.items()}
        #: Hide the mouse pointer in fullscreen after CURSOR_HIDE_MS.
        self.hide_cursor = True
        #: Set by the host while the visualizer is shown fullscreen.
        self.fullscreen = False
        #: menu_hook(menu) adds the host's entries to the right-click menu.
        self.menu_hook = None
        #: The right-click menu last shown (a popup: never a blocking exec).
        self.menu: QMenu | None = None
        self.scheme = DEFAULT_SCHEME
        self.custom_colours = dict(CUSTOM_COLOURS)
        self.colours = COLOUR_SCHEMES[DEFAULT_SCHEME]
        self._palette_cache: dict[str, QColor] = {}
        self._lut = None
        self.trace = None
        self.lissajous = None
        self.vu = [0.0, 0.0]
        self.vu_peaks = [0.0, 0.0]
        self.stars = None
        self._rng = np.random.default_rng() if np is not None else None
        self._label_until = 0.0
        self._clicks_from = self.mode
        self._last_press = -(10 ** 9)
        self._autohide = False
        self._resize_bars(self.options["bars"])
        self._apply_scheme()
        self.setMinimumHeight(90)
        self.setFocusPolicy(Qt.FocusPolicy.ClickFocus)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.timer = QTimer(self)
        self.timer.setInterval(round(1000 / self.options["fps"]))
        self.timer.timeout.connect(self.tick)
        self._label_timer = QTimer(self)  # repaints once the name is due to go
        self._label_timer.setSingleShot(True)
        self._label_timer.timeout.connect(self.update)
        self._cursor_timer = QTimer(self)
        self._cursor_timer.setSingleShot(True)
        self._cursor_timer.timeout.connect(self._hide_pointer)
        self._update_tooltip()

    # -- the face ---------------------------------------------------------------------

    def set_mode(self, mode: str, *, announce: bool = True) -> None:
        """Show face *mode*; *announce* shows its name for a moment."""
        if mode not in self.MODES:
            raise ValueError(f"unknown visualization {mode!r}")
        if mode == self.mode:
            return
        self.mode = mode
        if announce:
            self._label_until = time.monotonic() + self.LABEL_SECONDS
            self._label_timer.start(int(self.LABEL_SECONDS * 1000) + 50)
        self._update_tooltip()
        self.tick()  # the new face shows the sound at once, paused too
        self.update()
        self.mode_changed.emit(mode)

    def next_mode(self) -> None:
        self.set_mode(self.MODES[(self.MODES.index(self.mode) + 1) % len(self.MODES)])

    def _update_tooltip(self) -> None:
        self.setToolTip(tr("{name} - click for the next visualization, double-click for "
                           "fullscreen, right-click for more").format(
            name=tr(VISUALIZER_NAMES[self.mode])))

    # -- colours and options ------------------------------------------------------------

    def set_scheme(self, name: str) -> None:
        """Use colour scheme *name* (one of SCHEME_NAMES)."""
        if name not in SCHEME_NAMES:
            raise ValueError(f"unknown colour scheme {name!r}")
        if name == self.scheme:
            return
        self.scheme = name
        self._apply_scheme()
        self.settings_changed.emit()

    def set_custom_colours(self, colours) -> None:
        """Take the valid ``#rrggbb`` entries of *colours* for the custom
        scheme; the rest stays."""
        if not isinstance(colours, dict):
            return
        changed = False
        for key in CUSTOM_COLOURS:
            value = colours.get(key)
            if is_hex_colour(value) and value.lower() != self.custom_colours[key]:
                self.custom_colours[key] = value.lower()
                changed = True
        if changed:
            if self.scheme == "custom":
                self._apply_scheme()
            self.settings_changed.emit()

    def set_option(self, name: str, value) -> None:
        """Set option *name* (VISUAL_OPTIONS), clamped to its range."""
        value = clamp_option(name, value)
        if self.options[name] == value:
            return
        self.options[name] = value
        if name == "bars":
            self._resize_bars(value)
        elif name == "fps":
            self.timer.setInterval(round(1000 / value))
        self.settings_changed.emit()
        self.update()

    def set_hide_cursor(self, on: bool) -> None:
        on = bool(on)
        if on == self.hide_cursor:
            return
        self.hide_cursor = on
        self.set_cursor_autohide(self.fullscreen)
        self.settings_changed.emit()

    def _resize_bars(self, n: int) -> None:
        self.levels = [0.0] * n
        self.peaks = [0.0] * n
        self._unit = [(math.cos(2 * math.pi * i / n - math.pi / 2),
                       math.sin(2 * math.pi * i / n - math.pi / 2)) for i in range(n)]
        # The polar face: the bars down the right half, then mirrored up the left.
        half = [math.pi * (i + 0.5) / n for i in range(n)]
        angles = [*half, *(2 * math.pi - a for a in reversed(half))]
        self._polar_unit = [(math.sin(a), -math.cos(a)) for a in angles]
        self.waterfall = np.zeros((self.WATERFALL_ROWS, n), np.uint8) if np is not None else None
        self._bass = None

    def _apply_scheme(self) -> None:
        if self.scheme == "custom":
            colours = custom_scheme(self.custom_colours)
        elif self.scheme == "theme":
            colours = theme_scheme(self.palette())
        else:
            colours = COLOUR_SCHEMES[self.scheme]
        self.colours = colours
        background = colours.background
        self._palette_cache = {
            "background": QColor(background), "low": QColor(colours.low),
            "mid": QColor(colours.mid), "high": QColor(colours.high),
            "peak": QColor(colours.peak),
            "grid": QColor(_mix(background, colours.peak, 0.22)),
            "track": QColor(_mix(background, colours.peak, 0.08)),
            "text": QColor(_mix(background, colours.peak, 0.6)),
            # the oscilloscope's trace: the first bar colour that stands out
            "trace": QColor(next((c for c in (colours.low, colours.mid, colours.high)
                                  if contrast_ratio(c, background) >= MIN_PEAK_CONTRAST),
                                 colours.peak)),
        }
        self._lut = None
        self.update()

    def _colour(self, key: str) -> QColor:
        return self._palette_cache[key]

    def _level_colour(self, level: float) -> QColor:
        """Quiet over middle to loud, like the bars' gradient."""
        level = min(1.0, max(0.0, level))
        if level < 0.6:
            a, b, t = self.colours.low, self.colours.mid, level / 0.6
        else:
            a, b, t = self.colours.mid, self.colours.high, (level - 0.6) / 0.4
        return QColor(_mix(a, b, t))

    def changeEvent(self, event) -> None:  # noqa: N802 - Qt
        super().changeEvent(event)
        if event.type() == QEvent.Type.PaletteChange and getattr(self, "scheme", "") == "theme":
            self._apply_scheme()

    # -- the mouse, the keys and the menu -------------------------------------------------

    def mousePressEvent(self, event) -> None:  # noqa: N802 - Qt
        if event.button() == Qt.MouseButton.LeftButton:
            stamp = event.timestamp()
            if stamp - self._last_press > QApplication.doubleClickInterval():
                self._clicks_from = self.mode  # a new run of clicks starts here
            self._last_press = stamp
            self.next_mode()
            event.accept()
            return
        super().mousePressEvent(event)

    def mouseDoubleClickEvent(self, event) -> None:  # noqa: N802 - Qt
        """Fullscreen on or off. The press that opened the double click
        (press, release, double click) went to the next face: that is taken
        back, the face is the one before the run of clicks."""
        if event.button() != Qt.MouseButton.LeftButton:
            super().mouseDoubleClickEvent(event)
            return
        recent = 0 <= event.timestamp() - self._last_press <= QApplication.doubleClickInterval()
        if recent and self._clicks_from in self.MODES and self._clicks_from != self.mode:
            self.set_mode(self._clicks_from, announce=False)
        self.fullscreen_requested.emit(not self.fullscreen)
        event.accept()

    def _fullscreen_key(self, event) -> bool | None:
        """The fullscreen state F11 / Esc asks for, or None for other keys."""
        if event.modifiers() & ~Qt.KeyboardModifier.KeypadModifier:
            return None
        if event.key() == Qt.Key.Key_F11:
            return not self.fullscreen
        if event.key() == Qt.Key.Key_Escape and self.fullscreen:
            return False
        return None

    def event(self, event) -> bool:
        if event.type() == QEvent.Type.ShortcutOverride and self._fullscreen_key(event) is not None:
            event.accept()  # F11 / Esc are the visualizer's, not a window shortcut
            return True
        return super().event(event)

    def keyPressEvent(self, event) -> None:  # noqa: N802 - Qt
        wanted = self._fullscreen_key(event)
        if wanted is None:
            super().keyPressEvent(event)
            return
        event.accept()
        self.fullscreen_requested.emit(wanted)

    def set_cursor_autohide(self, on: bool) -> None:
        """Hide the pointer after CURSOR_HIDE_MS without a move (when
        :attr:`hide_cursor`); off shows it again."""
        self._autohide = bool(on) and self.hide_cursor
        self.setMouseTracking(self._autohide)
        if self._autohide:
            self._cursor_timer.start(self.CURSOR_HIDE_MS)
        else:
            self._cursor_timer.stop()
            self.setCursor(Qt.CursorShape.PointingHandCursor)

    def _hide_pointer(self) -> None:
        if self._autohide:
            self.setCursor(Qt.CursorShape.BlankCursor)

    def mouseMoveEvent(self, event) -> None:  # noqa: N802 - Qt
        if self._autohide:
            self.setCursor(Qt.CursorShape.PointingHandCursor)
            self._cursor_timer.start(self.CURSOR_HIDE_MS)
        super().mouseMoveEvent(event)

    def contextMenuEvent(self, event) -> None:  # noqa: N802 - Qt
        self.menu = self.build_menu()
        self.menu.popup(event.globalPos())
        event.accept()

    def build_menu(self) -> QMenu:
        """The right-click menu: the faces, the colour schemes, bars and
        frame rate, then what :attr:`menu_hook` adds. Every entry carries
        its ``(kind, value)`` as data."""
        menu = QMenu(self)

        def choices(title: str, kind: str, items, current, apply) -> None:
            sub = menu.addMenu(title)
            group = QActionGroup(sub)
            for value, label in items:
                action = sub.addAction(label)
                action.setCheckable(True)
                action.setChecked(value == current)
                action.setData((kind, value))
                group.addAction(action)
                action.triggered.connect(lambda _checked=False, v=value: apply(v))

        choices(tr("Visualization"), "mode",
                [(m, tr(VISUALIZER_NAMES[m])) for m in self.MODES], self.mode,
                lambda m: self.set_mode(m))
        choices(tr("Colours"), "scheme",
                [(s, tr(label)) for s, label in SCHEME_NAMES.items()], self.scheme,
                self.set_scheme)
        low, high, _default = VISUAL_OPTIONS["bars"]
        bar_counts = sorted({low, 16, 32, 64, high, self.options["bars"]})
        choices(tr("Bars"), "bars", [(n, str(n)) for n in bar_counts if low <= n <= high],
                self.options["bars"], lambda n: self.set_option("bars", n))
        low, high, _default = VISUAL_OPTIONS["fps"]
        rates = sorted({low, 15, 30, high, self.options["fps"]})
        choices(tr("Frame rate cap"), "fps",
                [(n, tr("{n} fps").format(n=n)) for n in rates if low <= n <= high],
                self.options["fps"], lambda n: self.set_option("fps", n))
        if callable(self.menu_hook):
            self.menu_hook(menu)
        return menu

    def hideEvent(self, event) -> None:  # noqa: N802 - Qt
        menu = getattr(self, "menu", None)
        if menu is not None and not sip.isdeleted(menu) and menu.isVisible():
            menu.close()  # an open popup takes every click until it closes
        super().hideEvent(event)

    # -- the data ---------------------------------------------------------------------

    def _samples(self):
        getter = getattr(self.engine, "current_samples", None)
        if np is None or not callable(getter):
            return None
        return getter()

    def reset_stars(self, seed=None) -> None:
        """New stars (*seed*: the same field every time, for tests)."""
        if np is None:
            return
        self._rng = np.random.default_rng(seed)
        n = self.STAR_COUNT
        self.stars = np.column_stack([self._rng.uniform(-1, 1, n), self._rng.uniform(-1, 1, n),
                                      self._rng.uniform(self.STAR_NEAR, 1, n)])

    def _bass_level(self, values) -> float:
        if self._bass is None:
            centres = bar_centres(RATE, FRAME, len(values))
            self._bass = max(1, int(np.count_nonzero(centres < self.BASS_HZ)))
        return float(np.mean(values[:self._bass]))

    def _move_stars(self, values) -> None:
        if self.stars is None:
            self.reset_stars()
        speed = self.STAR_DRIFT + self.STAR_BOOST * self._bass_level(values)
        stars = self.stars
        stars[:, 2] -= speed / self.options["fps"]
        gone = ((stars[:, 2] <= self.STAR_NEAR) | (np.abs(stars[:, 0]) > stars[:, 2] * 1.2)
                | (np.abs(stars[:, 1]) > stars[:, 2] * 1.2))
        count = int(np.count_nonzero(gone))
        if count:
            stars[gone, 0] = self._rng.uniform(-1, 1, count)
            stars[gone, 1] = self._rng.uniform(-1, 1, count)
            stars[gone, 2] = 1.0

    def tick(self) -> None:
        if self.mode in _SAMPLE_MODES:
            samples = self._samples()
            if samples is None:
                return
            if self.mode == "scope":
                self.trace = waveform(samples, max(2, min(self.SCOPE_POINTS, self.width())))
            elif self.mode == "lissajous":
                self.lissajous = stereo_points(samples, self.LISSAJOUS_POINTS)
            else:
                levels = vu_levels(samples)
                for i in (0, 1):
                    value = levels[i]
                    self.vu[i] = value if value > self.vu[i] else self.vu[i] * 0.85 + value * 0.15
                    self.vu_peaks[i] = max(levels[2 + i], self.vu_peaks[i] - 0.01)
            self.update()
            return
        n = self.options["bars"]
        bars = self.engine.current_bars(n)
        if bars is None or np is None:
            return
        values = np.zeros(n, np.float32)
        count = min(n, len(bars))
        values[:count] = np.asarray(bars, np.float32)[:count]
        fps = self.options["fps"]
        keep = (self.options["smoothing"] / 100.0) ** (VISUAL_OPTIONS["fps"][2] / fps)
        fall = self.options["peak_fall"] / 100.0 / fps
        levels, peaks = list(self.levels), list(self.peaks)
        for i in range(n):
            value = float(values[i])
            levels[i] = value if value > levels[i] else levels[i] * keep + value * (1.0 - keep)
            peaks[i] = max(levels[i], peaks[i] - fall)
        self.levels, self.peaks = levels, peaks
        if self.mode == "waterfall":
            self.waterfall[:-1] = self.waterfall[1:]
            self.waterfall[-1] = np.round(np.clip(values, 0.0, 1.0) * 255).astype(np.uint8)
        elif self.mode == "starfield":
            self._move_stars(values)
        self.update()

    # -- painting ---------------------------------------------------------------------

    def paintEvent(self, _event) -> None:  # noqa: N802 - Qt
        painter = QPainter(self)
        try:
            painter.fillRect(self.rect(), self._colour("background"))
            if self.width() < 8 or self.height() < 8:
                return
            getattr(self, f"_paint_{self.mode}")(painter)
            if time.monotonic() < self._label_until:
                self._paint_label(painter)
        finally:
            painter.end()

    def _gradient(self, y_quiet: float, y_loud: float) -> QLinearGradient:
        gradient = QLinearGradient(0, y_quiet, 0, y_loud)
        gradient.setColorAt(0.0, self._colour("low"))
        gradient.setColorAt(0.6, self._colour("mid"))
        gradient.setColorAt(1.0, self._colour("high"))
        return gradient

    def _paint_spectrum(self, painter: QPainter) -> None:
        width = self.width() / len(self.levels)
        height = self.height() - 4
        gradient = self._gradient(self.height(), 0)
        cap = self._colour("peak")
        for i, (level, peak) in enumerate(zip(self.levels, self.peaks)):
            x = i * width + 1
            bar = max(2.0, level * height)
            painter.fillRect(QRectF(x, self.height() - bar, max(1.0, width - 2), bar), gradient)
            painter.fillRect(QRectF(x, self.height() - peak * height - 3, max(1.0, width - 2), 2),
                             cap)

    def _paint_mirror(self, painter: QPainter) -> None:
        width = self.width() / len(self.levels)
        mid = self.height() / 2
        reach = mid - 3
        up, down = self._gradient(mid, 0), self._gradient(mid, self.height())
        cap = self._colour("peak")
        bar_width = max(1.0, width - 2)
        for i, (level, peak) in enumerate(zip(self.levels, self.peaks)):
            x = i * width + 1
            bar = max(1.0, level * reach)
            painter.fillRect(QRectF(x, mid - bar, bar_width, bar), up)
            painter.fillRect(QRectF(x, mid, bar_width, bar), down)
            painter.fillRect(QRectF(x, mid - peak * reach - 2, bar_width, 1.5), cap)
            painter.fillRect(QRectF(x, mid + peak * reach + 0.5, bar_width, 1.5), cap)

    def _paint_radial(self, painter: QPainter) -> None:
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        cx, cy = self.width() / 2, self.height() / 2
        radius = min(cx, cy)
        inner = radius * 0.22
        reach = max(1.0, radius - inner - 2)
        pen = QPen()
        pen.setWidthF(max(1.5, 2 * math.pi * inner / len(self.levels) * 0.6))
        pen.setCapStyle(Qt.PenCapStyle.FlatCap)
        cap = self._colour("peak")
        for (ux, uy), level, peak in zip(self._unit, self.levels, self.peaks):
            pen.setColor(self._level_colour(level))
            painter.setPen(pen)
            outer = inner + max(1.0, level * reach)
            painter.drawLine(QPointF(cx + ux * inner, cy + uy * inner),
                             QPointF(cx + ux * outer, cy + uy * outer))
            tip = inner + peak * reach + 2
            painter.fillRect(QRectF(cx + ux * tip - 1, cy + uy * tip - 1, 2, 2), cap)
        painter.setPen(QPen(self._colour("grid"), 1))
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawEllipse(QPointF(cx, cy), inner - 2, inner - 2)

    def _paint_scope(self, painter: QPainter) -> None:
        mid = self.height() / 2
        painter.setPen(QPen(self._colour("grid"), 1))
        painter.drawLine(QPointF(0, mid), QPointF(self.width(), mid))
        trace = self.trace
        if trace is None or len(trace) < 2:
            return
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        pen = QPen(self._colour("trace"))
        pen.setWidthF(1.5)
        painter.setPen(pen)
        step = (self.width() - 1) / (len(trace) - 1)
        reach = mid - 2
        painter.drawLines(_segments([QPointF(i * step, mid - float(v) * reach)
                                     for i, v in enumerate(trace)]))

    def _paint_vu(self, painter: QPainter) -> None:
        margin = 6
        label_width = 14
        track_left = margin + label_width
        track_width = max(1.0, self.width() - track_left - margin)
        row = (self.height() - 3 * margin) / 2
        gradient = QLinearGradient(track_left, 0, track_left + track_width, 0)
        gradient.setColorAt(0.0, self._colour("low"))
        gradient.setColorAt(0.75, self._colour("mid"))  # -15 dBFS
        gradient.setColorAt(0.9, self._colour("high"))  # -6 dBFS
        cap = self._colour("peak")
        painter.setPen(cap)
        for i, name in enumerate(("L", "R")):
            top = margin + i * (row + margin)
            painter.drawText(QRectF(margin, top, label_width, row),
                             Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft, name)
            painter.fillRect(QRectF(track_left, top, track_width, row), self._colour("track"))
            painter.fillRect(QRectF(track_left, top, track_width * self.vu[i], row), gradient)
            peak_x = track_left + track_width * self.vu_peaks[i]
            painter.fillRect(QRectF(peak_x - 1, top, 2, row), cap)
        tick = self._colour("grid")
        for db in range(10, int(VU_RANGE_DB), 10):  # a tick every 10 dB
            x = track_left + track_width * (1 - db / VU_RANGE_DB)
            painter.fillRect(QRectF(x, self.height() - margin + 1, 1, margin - 2), tick)

    #: The line spectrum's grid: frequency and label, on its log axis.
    LINE_GRID = ((100, "100"), (1000, "1k"), (10000, "10k"))

    def _paint_line(self, painter: QPainter) -> None:
        """The bars as a filled curve over a log frequency axis (40 Hz to
        16 kHz, like the bars), a grid at 100 Hz, 1 kHz and 10 kHz, the
        peaks as a line on top."""
        w, h = self.width(), self.height()
        n = len(self.levels)
        top = min(16000.0, RATE / 2)
        painter.setPen(QPen(self._colour("grid"), 1))
        grid = [(math.log(freq / 40.0) / math.log(top / 40.0) * w, label)
                for freq, label in self.LINE_GRID]
        for x, _label in grid:
            painter.drawLine(QPointF(x, 0), QPointF(x, h))
        reach = h - 4
        xs = [(i + 0.5) / n * w for i in range(n)]
        curve = [QPointF(x, h - level * reach) for x, level in zip(xs, self.levels)]
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(self._gradient(h, 0))
        painter.drawPolygon(QPolygonF([QPointF(0, h), QPointF(0, curve[0].y()), *curve,
                                       QPointF(w, curve[-1].y()), QPointF(w, h)]))
        pen = QPen(self._colour("peak"))
        pen.setWidthF(1.5)
        painter.setPen(pen)
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawLines(_segments([QPointF(x, h - peak * reach - 2)
                                     for x, peak in zip(xs, self.peaks)]))
        painter.setPen(self._colour("text"))
        for x, label in grid:  # over the curve: the axis stays readable
            painter.drawText(QPointF(x + 3, painter.fontMetrics().ascent() + 2), label)

    def _waterfall_image(self) -> QImage:
        """The history as an image of bars x rows (newest at the bottom), a
        colour per level from the background over the bar colours."""
        if self._lut is None:
            stops = [(0.0, self.colours.background), (0.15, self.colours.low),
                     (0.6, self.colours.mid), (1.0, self.colours.high)]
            at = np.linspace(0.0, 1.0, 256)
            channels = []
            for shift in (16, 8, 0):
                values = [(int(colour[1:], 16) >> shift) & 0xFF for _pos, colour in stops]
                channels.append(np.interp(at, [pos for pos, _c in stops], values))
            red, green, blue = (np.round(c).astype(np.uint32) for c in channels)
            self._lut = (0xFF000000 | (red << 16) | (green << 8) | blue).astype(np.uint32)
        pixels = np.ascontiguousarray(self._lut[self.waterfall])
        rows, cols = pixels.shape
        image = QImage(pixels.data, cols, rows, cols * 4, QImage.Format.Format_RGB32)
        return image.copy()  # owns its pixels: the array goes when this returns

    def _paint_waterfall(self, painter: QPainter) -> None:
        if self.waterfall is None:
            return
        painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform, False)
        painter.drawImage(QRectF(0, 0, self.width(), self.height()), self._waterfall_image())

    def _paint_polar(self, painter: QPainter) -> None:
        """The bars as one closed shape around the middle - low to high
        from the top down the right, mirrored on the left - filled from the
        quiet colour inside to the loud one outside; the peaks outlined."""
        cx, cy = self.width() / 2, self.height() / 2
        radius = min(cx, cy)
        inner = radius * 0.18
        reach = max(1.0, radius - inner - 3)
        gradient = QRadialGradient(QPointF(cx, cy), radius)
        gradient.setColorAt(inner / radius, self._colour("low"))
        gradient.setColorAt(0.6, self._colour("mid"))
        gradient.setColorAt(1.0, self._colour("high"))
        levels = [*self.levels, *reversed(self.levels)]
        tops = [*self.peaks, *reversed(self.peaks)]
        shape = QPolygonF([QPointF(cx + ux * (inner + level * reach),
                                   cy + uy * (inner + level * reach))
                           for (ux, uy), level in zip(self._polar_unit, levels)])
        peaks = [QPointF(cx + ux * (inner + peak * reach + 2), cy + uy * (inner + peak * reach + 2))
                 for (ux, uy), peak in zip(self._polar_unit, tops)]
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(gradient)
        painter.drawPolygon(shape)
        pen = QPen(self._colour("peak"))
        pen.setWidthF(1.2)
        painter.setPen(pen)
        painter.drawLines(_segments([*peaks, peaks[0]]))

    def _paint_lissajous(self, painter: QPainter) -> None:
        """Left against right, turned 45 degrees: mono stands upright, a wide
        stereo image spreads sideways, out of phase lies flat."""
        cx, cy = self.width() / 2, self.height() / 2
        reach = min(cx, cy) - 3
        painter.setPen(QPen(self._colour("grid"), 1))
        painter.drawLine(QPointF(cx - reach, cy), QPointF(cx + reach, cy))
        painter.drawLine(QPointF(cx, cy - reach), QPointF(cx, cy + reach))
        diagonal = reach * math.sqrt(0.5)
        for sign in (-1, 1):  # the L and R axes
            painter.drawLine(QPointF(cx - sign * diagonal, cy - diagonal),
                             QPointF(cx + sign * diagonal, cy + diagonal))
        painter.setPen(self._colour("text"))
        metrics = painter.fontMetrics()
        ascent = metrics.ascent()
        # L and R beside their axes' upper ends, M right of the upright axis.
        painter.drawText(QPointF(cx - diagonal - metrics.horizontalAdvance("L") - 3,
                                 cy - diagonal + ascent), "L")
        painter.drawText(QPointF(cx + diagonal + 3, cy - diagonal + ascent), "R")
        painter.drawText(QPointF(cx + 4, cy - reach + ascent), "M")
        points = self.lissajous
        if points is None:
            return
        xs, ys = points
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        segments = _segments([QPointF(cx + float(x) * reach, cy - float(y) * reach)
                              for x, y in zip(xs, ys)])
        # Like a phosphor screen: the older part of the trace fades into the
        # background, the newest is in the loud colour.
        parts = self.LISSAJOUS_FADE
        size = math.ceil(len(segments) / parts)
        for part in range(parts):
            pen = QPen(QColor(_mix(self.colours.background, self.colours.high,
                                   (part + 1) / parts)))
            pen.setWidthF(1.2)
            painter.setPen(pen)
            painter.drawLines(segments[part * size:(part + 1) * size])

    def _paint_starfield(self, painter: QPainter) -> None:
        """Stars flying at the viewer, faster with the bass: near ones big
        and in the peak colour, far ones small and in the quiet colour."""
        if self.stars is None:
            self.reset_stars()
        if self.stars is None:
            return  # no numpy
        cx, cy = self.width() / 2, self.height() / 2
        stars = self.stars
        depth = stars[:, 2]
        sx = cx + stars[:, 0] / depth * cx
        sy = cy + stars[:, 1] / depth * cy
        for low, high, key, size in ((0.75, 1.01, "low", 1.0), (0.5, 0.75, "mid", 1.6),
                                     (0.25, 0.5, "high", 2.2), (0.0, 0.25, "peak", 3.0)):
            chosen = (depth >= low) & (depth < high)
            if not chosen.any():
                continue
            pen = QPen(self._colour(key))
            pen.setWidthF(size)
            pen.setCapStyle(Qt.PenCapStyle.RoundCap)
            painter.setPen(pen)
            painter.drawPoints(QPolygonF([QPointF(float(x), float(y))
                                          for x, y in zip(sx[chosen], sy[chosen])]))

    def _paint_label(self, painter: QPainter) -> None:
        text = tr(VISUALIZER_NAMES[self.mode])
        metrics = painter.fontMetrics()
        box = QRectF(4, 4, metrics.horizontalAdvance(text) + 12, metrics.height() + 6)
        painter.fillRect(box, QColor(0, 0, 0, 170))
        painter.setPen(QColor("#ecf0f1"))
        painter.drawText(box, Qt.AlignmentFlag.AlignCenter, text)


class VisualizerWindow(QWidget):
    """The visualizer on its own: a resizable window (Detach) or the whole
    screen (Fullscreen). Closing it gives the visualizer back to the panel
    (:attr:`closed`)."""

    closed = pyqtSignal()

    def __init__(self, parent: QWidget) -> None:
        super().__init__(parent, Qt.WindowType.Window)
        self.setWindowTitle(tr("Media Player - Visualization"))
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.resize(640, 360)
        #: True while the panel itself closes it (attaching).
        self.closing_quietly = False

    def closeEvent(self, event) -> None:  # noqa: N802 - Qt
        super().closeEvent(event)
        if event.isAccepted() and not self.closing_quietly:
            self.closed.emit()


class VisualizerSettingsDialog(QDialog):
    """The visualizer's settings: face, colour scheme and custom colours,
    the options (VISUAL_OPTIONS ranges) and the pointer in fullscreen.
    Changes apply at once; the panel saves them."""

    def __init__(self, visualizer: Visualizer, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(tr("Media Player Visualizer"))
        self.visualizer = visualizer
        layout = QVBoxLayout(self)
        form = QFormLayout()
        self.mode_box = QComboBox()
        for mode in Visualizer.MODES:
            self.mode_box.addItem(tr(VISUALIZER_NAMES[mode]), mode)
        self.mode_box.currentIndexChanged.connect(
            lambda _i: self._apply(lambda: visualizer.set_mode(self.mode_box.currentData())))
        form.addRow(tr("Visualization"), self.mode_box)
        self.scheme_box = QComboBox()
        for name, label in SCHEME_NAMES.items():
            self.scheme_box.addItem(tr(label), name)
        self.scheme_box.currentIndexChanged.connect(
            lambda _i: self._apply(lambda: visualizer.set_scheme(self.scheme_box.currentData())))
        form.addRow(tr("Colours"), self.scheme_box)
        colours = QHBoxLayout()
        self.colour_buttons: dict[str, QPushButton] = {}
        for key, label in CUSTOM_LABELS.items():
            button = QPushButton(tr(label))
            button.setToolTip(tr("Pick the colour (Custom scheme)"))
            button.clicked.connect(lambda _checked=False, k=key: self._choose(k))
            self.colour_buttons[key] = button
            colours.addWidget(button)
        form.addRow(tr("Custom colours"), colours)
        self.contrast_note = QLabel(tr("The peak colour was adjusted: it would not stand out "
                                       "on the background."))
        self.contrast_note.setWordWrap(True)
        form.addRow("", self.contrast_note)
        self.spins: dict[str, QSpinBox] = {}
        for name, (low, high, _default) in VISUAL_OPTIONS.items():
            label, suffix = VISUAL_OPTION_LABELS[name]
            spin = QSpinBox()
            spin.setObjectName(name)
            spin.setRange(low, high)
            spin.setSuffix(suffix)
            spin.valueChanged.connect(
                lambda value, n=name: self._apply(lambda: visualizer.set_option(n, value)))
            self.spins[name] = spin
            form.addRow(tr(label), spin)
        self.cursor_check = QCheckBox(tr("Hide the mouse pointer in fullscreen"))
        self.cursor_check.toggled.connect(
            lambda on: self._apply(lambda: visualizer.set_hide_cursor(on)))
        form.addRow("", self.cursor_check)
        layout.addLayout(form)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        from ui.close_corner import add_close_corner

        self.close_corner = add_close_corner(self)
        self._syncing = False
        visualizer.mode_changed.connect(self.sync)
        visualizer.settings_changed.connect(self.sync)
        self.sync()

    def _apply(self, change) -> None:
        if not self._syncing:
            change()

    def sync(self, *_args) -> None:
        """Show what the visualizer has now."""
        vis = self.visualizer
        self._syncing = True
        try:
            self.mode_box.setCurrentIndex(self.mode_box.findData(vis.mode))
            self.scheme_box.setCurrentIndex(self.scheme_box.findData(vis.scheme))
            for name, spin in self.spins.items():
                spin.setValue(vis.options[name])
            self.cursor_check.setChecked(vis.hide_cursor)
            custom = vis.scheme == "custom"
            for key, button in self.colour_buttons.items():
                button.setEnabled(custom)
                button.setIcon(self._swatch(vis.custom_colours[key]))
            self.contrast_note.setVisible(custom and vis.colours.peak != vis.custom_colours["peak"])
        finally:
            self._syncing = False

    @staticmethod
    def _swatch(colour: str) -> QIcon:
        pixmap = QPixmap(14, 14)
        pixmap.fill(QColor(colour))
        return QIcon(pixmap)

    def _choose(self, key: str) -> None:
        from PyQt6.QtWidgets import QColorDialog

        chosen = QColorDialog.getColor(QColor(self.visualizer.custom_colours[key]), self,
                                       tr(CUSTOM_LABELS[key]))
        if chosen.isValid():
            self.pick_colour(key, chosen)

    def pick_colour(self, key: str, colour: QColor) -> None:
        """Custom colour *key* is now *colour* (the colour dialog's answer)."""
        self.visualizer.set_custom_colours({key: colour.name()})
        self.sync()


class SeekSlider(QSlider):
    """The position slider: a click on the groove jumps there at once
    (QSlider's own click only steps a page); dragging the handle works as
    usual and seeks on release."""

    jumped = pyqtSignal(int)

    def __init__(self) -> None:
        super().__init__(Qt.Orientation.Horizontal)

    def mousePressEvent(self, event) -> None:  # noqa: N802 - Qt
        if event.button() != Qt.MouseButton.LeftButton or self.maximum() <= self.minimum():
            super().mousePressEvent(event)
            return
        opt = QStyleOptionSlider()
        self.initStyleOption(opt)
        style = self.style()
        handle = style.subControlRect(QStyle.ComplexControl.CC_Slider, opt,
                                      QStyle.SubControl.SC_SliderHandle, self)
        pos = event.position().toPoint()
        if handle.contains(pos):
            super().mousePressEvent(event)  # a drag starts
            return
        groove = style.subControlRect(QStyle.ComplexControl.CC_Slider, opt,
                                      QStyle.SubControl.SC_SliderGroove, self)
        span = max(1, groove.width() - handle.width())
        x = pos.x() - groove.x() - handle.width() // 2
        value = QStyle.sliderValueFromPosition(self.minimum(), self.maximum(),
                                               max(0, min(span, x)), span, opt.upsideDown)
        self.setValue(value)
        self.jumped.emit(value)
        event.accept()


class PlaylistWidget(QListWidget):
    """The playlist: rows reorder by dragging (InternalMove); files dropped
    from a file pane or the desktop go to :attr:`dropped`."""

    #: The QMimeData of a drop from outside.
    dropped = pyqtSignal(object)

    def __init__(self) -> None:
        super().__init__()
        self.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.setDragDropMode(QAbstractItemView.DragDropMode.InternalMove)
        self.setDefaultDropAction(Qt.DropAction.MoveAction)
        self.setAcceptDrops(True)

    @staticmethod
    def accepts(mime) -> bool:
        """A pane drag or local file URLs (no filesystem access here)."""
        if mime is None:
            return False
        if mime.hasFormat(TRANSFER_MIME_TYPE):
            return True
        return mime.hasUrls() and any(u.isLocalFile() for u in mime.urls())

    def _internal(self, event) -> bool:
        return event.source() is self

    def dragEnterEvent(self, event) -> None:  # noqa: N802 - Qt
        if self._internal(event):
            super().dragEnterEvent(event)
        elif self.accepts(event.mimeData()):
            event.setDropAction(Qt.DropAction.CopyAction)
            event.accept()
        else:
            event.ignore()

    def dragMoveEvent(self, event) -> None:  # noqa: N802 - Qt
        if self._internal(event):
            super().dragMoveEvent(event)
        elif self.accepts(event.mimeData()):
            event.setDropAction(Qt.DropAction.CopyAction)
            event.accept()
        else:
            event.ignore()

    def dropEvent(self, event) -> None:  # noqa: N802 - Qt
        if self._internal(event):
            super().dropEvent(event)  # the items move; their objects stay
            return
        mime = event.mimeData()
        if not self.accepts(mime):
            event.ignore()
            return
        event.setDropAction(Qt.DropAction.CopyAction)
        event.accept()
        self.dropped.emit(mime)


#: The pane drag payload's MIME type (ui.file_pane.TRANSFER_MIME_TYPE).
TRANSFER_MIME_TYPE = "application/x-axross-transfer"
_PATH_ROLE = Qt.ItemDataRole.UserRole
#: A track's length in seconds when known (0: unknown).
_DURATION_ROLE = Qt.ItemDataRole.UserRole + 1
#: The state is saved this long after the last change, and every this many
#: seconds while playing (the position).
_SAVE_DELAY_MS = 1000
_SAVE_EVERY_SECONDS = 30.0


def _local_drop_context(mime):
    """Without the extension API (a panel on its own): local files only -
    file:// URLs, or a pane drag from the local disk."""
    from types import SimpleNamespace

    try:
        from ui.file_pane import decode_transfer_payload
    except ImportError:  # pragma: no cover - outside axross
        decode_transfer_payload = None
    payload = decode_transfer_payload(mime) if decode_transfer_payload else None
    if payload is not None:
        if payload.get("filesystem") == "Local" and payload["paths"]:
            return SimpleNamespace(is_local=True, paths=tuple(payload["paths"]), backend=None)
        return None
    if mime.hasUrls():
        paths = tuple(u.toLocalFile() for u in mime.urls() if u.isLocalFile())
        if paths:
            return SimpleNamespace(is_local=True, paths=paths, backend=None)
    return None


class PlayerPanel(QWidget):
    """The player. Given an *engine* (the tests) it uses it at once.
    Without one it comes up with the controls off and builds its engine
    only after core.multimedia_probe found that Qt Multimedia answers
    (*audio_probe*, run through *run_in_background*): Qt starts its backend
    in the thread of the first multimedia object, here the GUI thread, and
    a GPU driver or an audio server that hangs there froze the whole window
    (axross-full showed no window: QAudioDecoder() -> cuInit, for ever).
    When the probe fails the panel says why and stays off."""

    #: The title of the track now playing ("" when none).
    track_changed = pyqtSignal(str)
    #: The audio did not start; the text the panel shows.
    engine_failed = pyqtSignal(str)

    def __init__(self, engine=None, state_path=None, run_in_background=None, *,
                 engine_factory=None, audio_probe=None, open_audio_settings=None) -> None:
        super().__init__()
        #: open_audio_settings() opens Edit > Settings… > Audio (the host
        #: window's); None: no "Audio Settings…" button.
        self.open_audio_settings = open_audio_settings
        #: engine_factory() -> engine, called on the GUI thread once the probe passed.
        self._engine_factory = engine_factory or default_engine
        #: audio_probe() -> core.multimedia_probe.ProbeResult; blocks, so it
        #: runs through run_in_background.
        self._audio_probe = audio_probe
        self.engine_ready = engine is not None
        #: The text shown when the audio did not start ("" otherwise).
        self.audio_error = ""
        self._shut_down = False
        self.engine = engine if engine is not None else PendingEngine()
        if self.engine_ready:
            self._connect_engine(self.engine)
        self.repeat = "off"
        self.shuffle = False
        self.muted = False
        self._current: QListWidgetItem | None = None
        #: The row the playing track had when it was removed: next goes on
        #: from there.
        self._resume_row: int | None = None
        self._history: list[QListWidgetItem] = []
        self._round: set[int] = set()
        self._rng = random.Random()
        self._fail_streak = 0
        self._track_ms = 0
        self._title = ""
        #: run_in_background(work, on_done, on_error) - the extension API's;
        #: None runs the work at once.
        self.run_in_background = run_in_background
        #: drop_context(mime) -> what a drop is about (the extension API's);
        #: None: local files only.
        self.drop_resolver = None
        self._state_path = state_path
        self._state_unreadable = False
        self._restoring = False
        self._last_save = time.monotonic()
        root = QVBoxLayout(self)
        top = QHBoxLayout()
        self.cover = QLabel()
        self.cover.setFixedSize(72, 72)
        self.cover.setStyleSheet("background: #20262c;")
        self.now_playing = QLabel(tr("Nothing playing"))
        self.now_playing.setWordWrap(True)
        top.addWidget(self.cover)
        top.addWidget(self.now_playing, 1)
        root.addLayout(top)
        #: "Starting audio…" until the engine is there, or why it is not.
        self.audio_status = QLabel(tr("Starting audio…"))
        self.audio_status.setWordWrap(True)
        self.audio_status.setVisible(not self.engine_ready)
        root.addWidget(self.audio_status)
        # Shown while audio is off: check again, or choose another backend
        # or device first.
        self.retry_button = QPushButton(tr("Try Again"))
        self.retry_button.setToolTip(tr("Check the audio again and start the player when it "
                                        "answers"))
        self.retry_button.clicked.connect(self.retry_audio)
        self.audio_settings_button = QPushButton(tr("Audio Settings…"))
        self.audio_settings_button.setToolTip(tr("Edit > Settings… > Audio: backend, devices, "
                                                 "volume and a test"))
        self.audio_settings_button.clicked.connect(self._open_audio_settings)
        audio_row = QHBoxLayout()
        audio_row.setContentsMargins(0, 0, 0, 0)
        audio_row.addWidget(self.retry_button)
        audio_row.addWidget(self.audio_settings_button)
        audio_row.addStretch(1)
        root.addLayout(audio_row)
        self._show_audio_buttons(False)
        position = QHBoxLayout()
        self.seek_slider = SeekSlider()
        self.seek_slider.setRange(0, 0)
        self.seek_slider.setSingleStep(SEEK_STEP_MS)
        self.seek_slider.setPageStep(SEEK_BIG_STEP_MS)
        self.seek_slider.setToolTip(tr("Position: click or drag to seek (←/→ ±5 s, "
                                       "Shift ±30 s)"))
        self.seek_slider.jumped.connect(self.seek_to)
        self.seek_slider.sliderReleased.connect(
            lambda: self.seek_to(self.seek_slider.sliderPosition()))
        self.seek_slider.sliderMoved.connect(lambda _v: self._refresh_time())
        self.seek_slider.actionTriggered.connect(self._slider_action)
        self.time_label = QLabel("0:00 / 0:00")
        position.addWidget(self.seek_slider, 1)
        position.addWidget(self.time_label)
        root.addLayout(position)
        controls = QHBoxLayout()
        self.prev_button = QPushButton()
        self.play_button = QPushButton()
        self.stop_button = QPushButton()
        self.next_button = QPushButton()
        self.shuffle_button = QPushButton()
        self.repeat_button = QPushButton()
        self.prev_button.setToolTip(tr("Previous (Ctrl+←); after 3 s: start of the track"))
        self.play_button.setToolTip(tr("Play / pause (Space)"))
        self.stop_button.setToolTip(tr("Stop"))
        self.next_button.setToolTip(tr("Next (Ctrl+→)"))
        self.shuffle_button.setCheckable(True)
        self.shuffle_button.setToolTip(tr("Shuffle"))
        self.repeat_button.setCheckable(True)
        self.prev_button.clicked.connect(self.previous_track)
        self.play_button.clicked.connect(self.toggle_play)
        self.stop_button.clicked.connect(lambda: self.engine.stop())
        self.next_button.clicked.connect(self.next_track)
        self.shuffle_button.toggled.connect(self.set_shuffle)
        self.repeat_button.clicked.connect(self._cycle_repeat)
        self.mute_button = QPushButton()
        self.mute_button.setCheckable(True)
        self.mute_button.setToolTip(tr("Mute (M)"))
        self.mute_button.toggled.connect(self.set_muted)
        self.volume = QSlider(Qt.Orientation.Horizontal)
        self.volume.setRange(0, 100)
        self.volume.setValue(80)
        self.volume.setToolTip(tr("Volume (+/-, mouse wheel)"))
        self.volume.valueChanged.connect(lambda _v: self._apply_volume())
        for widget in (self.prev_button, self.play_button, self.stop_button, self.next_button,
                       self.shuffle_button, self.repeat_button):
            controls.addWidget(widget)
        controls.addStretch(1)
        controls.addWidget(self.mute_button)
        controls.addWidget(self.volume)
        root.addLayout(controls)
        self.visualizer = Visualizer(self.engine)
        self.visualizer.menu_hook = self._visualizer_menu
        self.visualizer.fullscreen_requested.connect(self.set_fullscreen)
        #: The visualizer's place in the panel; while it is in its own
        #: window (Detach, Fullscreen) a note with Attach stands there.
        self.visual_box = QWidget()
        visual_layout = QVBoxLayout(self.visual_box)
        visual_layout.setContentsMargins(0, 0, 0, 0)
        visual_layout.addWidget(self.visualizer, 1)
        self.visual_placeholder = QWidget()
        placeholder = QHBoxLayout(self.visual_placeholder)
        placeholder.setContentsMargins(0, 0, 0, 0)
        placeholder.addWidget(QLabel(tr("The visualization is in its own window.")), 1)
        attach = QPushButton(tr("Attach"))
        attach.setToolTip(tr("Put the visualization back into the panel"))
        attach.clicked.connect(self.attach_visualizer)
        placeholder.addWidget(attach)
        self.visual_placeholder.setVisible(False)
        visual_layout.addWidget(self.visual_placeholder)
        root.addWidget(self.visual_box)
        #: The visualizer's own window while detached or fullscreen (None: in the panel).
        self.visual_window: VisualizerWindow | None = None
        self._fullscreen = False
        #: Fullscreen came from the panel (leaving it attaches) or from the window.
        self._fullscreen_from_panel = False
        #: The visualizer settings dialog while it is open.
        self.visual_settings: VisualizerSettingsDialog | None = None
        # The equalizer: a header row (fold, on/off, preset) that stays, and
        # the band sliders below it that fold away - the playlist gets the room.
        self._eq_open = True
        self.eq_toggle = QToolButton()
        self.eq_toggle.setCheckable(True)
        self.eq_toggle.setChecked(True)
        self.eq_toggle.setAutoRaise(True)
        self.eq_toggle.setArrowType(Qt.ArrowType.DownArrow)  # drawn by the style: no font needed
        self.eq_toggle.setToolTip(tr("Show / hide the equalizer bands"))
        self.eq_toggle.setAccessibleName(tr("Show / hide the equalizer bands"))
        self.eq_toggle.toggled.connect(self.set_equalizer_open)
        self.eq_check = QCheckBox(tr("Equalizer"))
        self.eq_check.setChecked(True)
        self.preset = QComboBox()
        self.preset.addItems(list(PRESETS))
        self.preset.currentTextChanged.connect(self.apply_preset)
        header = QHBoxLayout()
        header.setContentsMargins(0, 0, 0, 0)
        header.addWidget(self.eq_toggle)
        header.addWidget(self.eq_check)
        header.addWidget(self.preset, 1)
        eq = QGridLayout()
        eq.setContentsMargins(0, 0, 0, 0)
        self.sliders: list[QSlider] = []
        for i, freq in enumerate(BANDS):
            slider = QSlider(Qt.Orientation.Vertical)
            slider.setRange(-int(MAX_GAIN_DB), int(MAX_GAIN_DB))
            slider.setMinimumHeight(80)
            slider.valueChanged.connect(lambda _v: self._sliders_moved())
            self.sliders.append(slider)
            eq.addWidget(slider, 0, i, Qt.AlignmentFlag.AlignHCenter)
            label = QLabel(f"{freq // 1000}k" if freq >= 1000 else str(freq))
            eq.addWidget(label, 1, i, Qt.AlignmentFlag.AlignHCenter)
        self.eq_body = QWidget()
        self.eq_body.setLayout(eq)
        self.eq_box = QWidget()
        box = QVBoxLayout(self.eq_box)
        box.setContentsMargins(0, 0, 0, 0)
        box.addLayout(header)
        box.addWidget(self.eq_body)
        if not isinstance(self.engine, EqEngine) and np is None:
            for widget in (self.eq_check, self.preset, self.eq_body):
                widget.setEnabled(False)
            self.eq_box.setToolTip(tr("The equalizer and the visualizations need numpy "
                                      "(pip install numpy)."))
        self.eq_check.toggled.connect(self._eq_toggled)
        root.addWidget(self.eq_box)
        # The playlist folds away (the visualizer gets the room); the toggle stays.
        self._playlist_open = True
        self.playlist_toggle = QToolButton()
        self.playlist_toggle.setCheckable(True)
        self.playlist_toggle.setChecked(True)
        self.playlist_toggle.setAutoRaise(True)
        self.playlist_toggle.setArrowType(Qt.ArrowType.DownArrow)
        self.playlist_toggle.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.playlist_toggle.setText(tr("Playlist"))
        self.playlist_toggle.setToolTip(tr("Show / hide the playlist"))
        self.playlist_toggle.setAccessibleName(tr("Show / hide the playlist"))
        self.playlist_toggle.toggled.connect(self.set_playlist_open)
        root.addWidget(self.playlist_toggle)
        self.playlist = PlaylistWidget()
        self.playlist.setToolTip(tr("Drop files or folders here; drag rows to reorder. "
                                    "Enter plays, Delete removes."))
        self.playlist.itemDoubleClicked.connect(lambda _item: self.play_selected())
        self.playlist.dropped.connect(self._on_drop)
        root.addWidget(self.playlist, 1)
        self.playlist_buttons = QWidget()
        row = QHBoxLayout(self.playlist_buttons)
        row.setContentsMargins(0, 0, 0, 0)
        add = QPushButton(tr("Add…"))
        add.clicked.connect(self._add_dialog)
        remove = QPushButton(tr("Remove"))
        remove.clicked.connect(self._remove_selected)
        clear = QPushButton(tr("Clear"))
        clear.clicked.connect(self.clear_playlist)
        load = QPushButton(tr("Load…"))
        load.setToolTip(tr("Load an M3U playlist (replaces the list)"))
        load.clicked.connect(self._load_dialog)
        save = QPushButton(tr("Save…"))
        save.setToolTip(tr("Save the list as an M3U playlist"))
        save.clicked.connect(self._save_dialog)
        for button in (add, remove, clear):
            row.addWidget(button)
        row.addStretch(1)
        row.addWidget(load)
        row.addWidget(save)
        root.addWidget(self.playlist_buttons)
        self.note = QLabel("")
        self.note.setWordWrap(True)
        root.addWidget(self.note)
        self._update_repeat_button()
        #: The output device the engine plays on (core.audio_route), to see a change.
        self._output_device = audio_route.settings().output_device
        audio_route.notifier().changed.connect(self._audio_settings_saved)
        self._apply_volume()
        self._update_control_icons()
        self.setFocusPolicy(Qt.FocusPolicy.ClickFocus)
        for widget in [self, *self.findChildren(QWidget)]:
            widget.installEventFilter(self)
        self._save_timer = QTimer(self)
        self._save_timer.setSingleShot(True)
        self._save_timer.setInterval(_SAVE_DELAY_MS)
        self._save_timer.timeout.connect(self.save_state)
        model = self.playlist.model()
        for signal in (model.rowsInserted, model.rowsRemoved, model.rowsMoved):
            signal.connect(self._schedule_save)
        self.volume.valueChanged.connect(self._schedule_save)
        self.visualizer.mode_changed.connect(self._schedule_save)
        self.visualizer.settings_changed.connect(self._schedule_save)
        # Files dropped anywhere on the panel (the visualizer, the controls,
        # a folded playlist) go to the playlist too.
        self.setAcceptDrops(True)
        self._clock = QTimer(self)
        self._clock.setInterval(250)
        self._clock.timeout.connect(self._refresh_time)
        self._clock.start()
        self._set_transport_enabled(self.engine_ready)
        if self._state_path:
            self.restore_state()
        if not self.engine_ready:
            self._start_engine()

    # -- the engine ------------------------------------------------------------------------

    def _connect_engine(self, engine) -> None:
        engine.finished_playing.connect(self._next_after_end)
        engine.changed.connect(self._refresh)
        failed = getattr(engine, "failed", None)
        if failed is not None:
            failed.connect(self._track_failed)
        problem = getattr(engine, "playback_problem", None)
        if problem is not None:
            problem.connect(self._playback_problem)

    def _playback_problem(self, text: str) -> None:
        """The sound card plays too slow, too fast or not at all: said in
        the panel and as a notice, with what to do."""
        self.note.setText(text)
        self.engine_failed.emit(text)

    def _set_transport_enabled(self, on: bool) -> None:
        for button in (self.prev_button, self.play_button, self.stop_button, self.next_button):
            button.setEnabled(on)

    def _start_engine(self) -> None:
        """Probe Qt Multimedia off the GUI thread; the engine follows."""
        probe = self._audio_probe
        if probe is None:
            from core import multimedia_probe

            probe = multimedia_probe.probe
        self._background(probe, self._probe_done, self._probe_failed)

    def _gone(self) -> bool:
        return self._shut_down or sip.isdeleted(self)

    def _probe_done(self, result) -> None:
        if self._gone():
            return  # the panel closed meanwhile: no engine any more
        if not result.ok:
            self._audio_failed(result.reason)
            return
        try:
            engine = self._engine_factory()
        except Exception as exc:  # noqa: BLE001 - shown, the rest of axross goes on
            log.warning("Media Player: the engine could not be built", exc_info=True)
            self._audio_failed(str(exc) or type(exc).__name__)
            return
        self._attach_engine(engine)

    def _probe_failed(self, exc) -> None:
        if not self._gone():
            self._audio_failed(str(exc) or type(exc).__name__)

    def _audio_failed(self, reason: str) -> None:
        text = tr("Audio does not start on this system: {reason}. The Media Player is off; "
                  "everything else works.").format(reason=reason)
        self.audio_error = text
        self.audio_status.setText(text)
        self.audio_status.setVisible(True)
        self._show_audio_buttons(True)
        self._set_transport_enabled(False)
        log.warning("Media Player: %s", text)
        self.engine_failed.emit(text)

    def _show_audio_buttons(self, on: bool) -> None:
        self.retry_button.setVisible(on)
        self.audio_settings_button.setVisible(on and self.open_audio_settings is not None)

    def retry_audio(self) -> None:
        """Try Again: check Qt Multimedia once more (this run's answer is
        forgotten, core.multimedia_probe.reset) and build the engine when it
        answers now - after a changed backend or device, a started audio
        server, a plugged-in card."""
        if self._gone() or self.engine_ready:
            return
        self._show_audio_buttons(False)
        self.audio_error = ""
        self.audio_status.setText(tr("Starting audio…"))
        self.audio_status.setVisible(True)
        if self._audio_probe is None:
            from core import multimedia_probe

            multimedia_probe.reset()
        self._start_engine()

    def _open_audio_settings(self) -> None:
        if self.open_audio_settings is not None:
            self.open_audio_settings()

    def _attach_engine(self, engine) -> None:
        """Use *engine* from now on and hand it what was asked for while
        the panel waited: the track (at its position, playing if asked),
        the volume, the gains and the equalizer switch."""
        pending = self.engine if isinstance(self.engine, PendingEngine) else None
        self.engine = engine
        self._connect_engine(engine)
        self.visualizer.engine = engine
        self.engine_ready = True
        self.audio_error = ""
        self.audio_status.setVisible(False)
        self._show_audio_buttons(False)
        self._set_transport_enabled(True)
        self._apply_volume()
        if pending is None:
            return
        if pending.gains is not None:
            engine.set_gains(pending.gains)
        if isinstance(engine, EqEngine):
            engine.set_eq_enabled(self.eq_check.isChecked())
        if pending.loaded:
            engine.load(pending.path)
            if pending.position > 0:
                engine.seek(pending.position)
            if self._current is not None and self._row_of(self._current) >= 0 \
                    and self._current.data(_PATH_ROLE) == pending.path:
                self._read_tags(pending.path)
            if pending.wants_play:
                engine.play()
                self.visualizer.timer.start()
        self._refresh()
        self._refresh_time()

    # -- playlist --------------------------------------------------------------------------

    def add_files(self, paths) -> int:
        """Add local files, folders (bounded) and M3U playlists at once;
        how many tracks were added."""
        found, _skipped, _truncated = collect_local(paths)
        for path, title in found:
            self._append(path, title)
        return len(found)

    def _append(self, path: str, title: str = "", duration: int = 0) -> QListWidgetItem:
        item = QListWidgetItem(title or os.path.basename(path))
        item.setData(_PATH_ROLE, path)
        item.setData(_DURATION_ROLE, int(duration or 0))
        item.setToolTip(path)
        self.playlist.addItem(item)
        return item

    def add_collected(self, found, skipped: int = 0, truncated: bool = False):
        """Append what collect_local / fetch_remote found and say so in the
        note; the first added item (None when nothing was)."""
        first = None
        for path, title in found:
            item = self._append(path, title)
            first = first or item
        parts = []
        if found:
            parts.append(tr("Added {count} track(s).").format(count=len(found)))
        if skipped:
            parts.append(tr("Skipped {count} entry(s): not audio, not readable, or in a "
                            "folder nested too deep.")
                         .format(count=skipped))
        if truncated:
            parts.append(tr("Only the first {count} tracks were taken.")
                         .format(count=MAX_DROP_FILES))
        self.note.setText(" ".join(parts) or tr("Nothing to add."))
        return first

    def _background(self, work, done, failed) -> None:
        if self.run_in_background is not None:
            self.run_in_background(work, done, failed)
            return
        try:
            result = work()
        except Exception as exc:  # noqa: BLE001 - shown like the host shows it
            failed(exc)
            return
        done(result)

    def _on_drop(self, mime) -> None:
        """Files dropped from a pane or the desktop: local ones collected,
        remote ones copied to a bounded temporary folder - both off the GUI
        thread."""
        resolve = self.drop_resolver or _local_drop_context
        ctx = resolve(mime)
        if ctx is None:
            self.note.setText(tr("Cannot add these: their connection is gone or they are no "
                                 "files."))
            return
        paths = list(ctx.paths)

        def failed(exc) -> None:
            self.note.setText(tr("Cannot add: {error}").format(error=exc))

        if getattr(ctx, "is_local", True):
            self._background(lambda: collect_local(paths),
                             lambda r: self.add_collected(*r), failed)
            return
        backend = ctx.backend
        self._background(lambda: fetch_remote(backend, paths),
                         lambda r: self.add_collected(r[0], r[1], r[2]), failed)

    def _add_dialog(self) -> None:
        from PyQt6.QtWidgets import QFileDialog

        pattern = " ".join(f"*{s}" for s in AUDIO_SUFFIXES + PLAYLIST_SUFFIXES)
        paths, _f = QFileDialog.getOpenFileNames(self, tr("Add tracks"), "",
                                                 f"{tr('Audio')} ({pattern})")
        if paths:
            self._background(lambda: collect_local(paths), lambda r: self.add_collected(*r),
                             lambda exc: self.note.setText(str(exc)))

    def _load_dialog(self) -> None:
        from PyQt6.QtWidgets import QFileDialog

        path, _f = QFileDialog.getOpenFileName(self, tr("Load playlist"), "",
                                               f"{tr('Playlists')} (*.m3u *.m3u8)")
        if path:
            self.load_playlist(path)

    def _save_dialog(self) -> None:
        from PyQt6.QtWidgets import QFileDialog

        path, _f = QFileDialog.getSaveFileName(self, tr("Save playlist"), "playlist.m3u8",
                                               f"{tr('Playlists')} (*.m3u8 *.m3u)")
        if path:
            if not path.lower().endswith(PLAYLIST_SUFFIXES):
                path += ".m3u8"
            self.save_playlist(path)

    def _entries(self) -> list[PlaylistEntry]:
        out = []
        for item in self._items():
            path = item.data(_PATH_ROLE)
            title = item.text() if item.text() != os.path.basename(path) else ""
            out.append(PlaylistEntry(path, title, int(item.data(_DURATION_ROLE) or 0)))
        return out

    def save_playlist(self, path: str) -> None:
        try:
            written, left_out = write_playlist(path, self._entries())
        except OSError as exc:
            self.note.setText(tr("Cannot save the playlist: {error}").format(error=exc))
            return
        text = tr("Saved {count} track(s) to {name}.").format(count=written,
                                                              name=os.path.basename(path))
        if left_out:
            text += " " + tr("{count} remote track(s) left out: they are temporary copies.") \
                .format(count=left_out)
        self.note.setText(text)

    def load_playlist(self, path: str) -> None:
        """Replace the list by the playlist at *path* (nothing changes when
        it is refused)."""
        try:
            entries, skipped = read_playlist(path)
        except PlaylistError as exc:
            self.note.setText(tr("Cannot load {name}: {error}").format(
                name=os.path.basename(path), error=exc))
            return
        self._remove_all_rows()
        for entry in entries:
            self._append(entry.path, entry.title, entry.duration)
        text = tr("Loaded {count} track(s) from {name}.").format(count=len(entries),
                                                                 name=os.path.basename(path))
        if skipped:
            text += " " + tr("Skipped {count} entry(s): missing, not audio or not a local "
                             "file.").format(count=skipped)
        self.note.setText(text)

    def _row_of(self, item) -> int:
        if item is None:
            return -1
        try:
            return self.playlist.row(item)
        except RuntimeError:  # the item is gone
            return -1

    def current_row(self) -> int:
        """The playing track's row; -1 when none (or it was removed)."""
        return self._row_of(self._current)

    def _remove_selected(self) -> None:
        rows = sorted({self.playlist.row(i) for i in self.playlist.selectedItems()})
        if not rows:
            return
        playing = self.current_row()
        if playing in rows:
            # It plays on; next continues with what followed it.
            self._resume_row = playing - sum(1 for r in rows if r < playing)
            self._current = None
        for row in reversed(rows):
            item = self.playlist.takeItem(row)
            if item in self._history:
                self._history = [h for h in self._history if h is not item]
            self._round.discard(id(item))

    def clear_playlist(self) -> None:
        self._remove_all_rows()

    def _remove_all_rows(self) -> None:
        self._current = None
        self._resume_row = None
        self._history.clear()
        self._round.clear()
        while self.playlist.count():
            self.playlist.takeItem(self.playlist.count() - 1)

    def play_selected(self) -> None:
        item = self.playlist.currentItem()
        if item is None and self.playlist.count():
            self.playlist.setCurrentRow(0)
            item = self.playlist.currentItem()
        if item is None:
            return
        self._fail_streak = 0
        self.play_item(item)

    def play_item(self, item: QListWidgetItem, *, record: bool = True) -> None:
        self._set_current(item)
        path = item.data(_PATH_ROLE)
        if record:
            self._history.append(item)
            del self._history[:-1000]  # bounded
            self._round.add(id(item))
        self.note.setText("")
        self.engine.load(path)
        self._track_ms = 0
        self._read_tags(path)
        self.engine.play()
        self.visualizer.timer.start()

    def _set_current(self, item) -> None:
        old = self._current
        if old is not None and self._row_of(old) >= 0:
            self._mark(old, False)
        self._current = item
        self._resume_row = None
        if item is not None:
            self._mark(item, True)
            self.playlist.setCurrentItem(item)
            self.playlist.scrollToItem(item)
            self._set_title(item.text())
        self._schedule_save()

    def _mark(self, item, playing: bool) -> None:
        font = QFont(item.font())
        font.setBold(playing)
        item.setFont(font)
        item.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_MediaPlay)
                     if playing else QIcon())

    def _set_title(self, title: str) -> None:
        self._title = title
        self.now_playing.setToolTip(title)
        self.track_changed.emit(title)

    def toggle_play(self) -> None:
        if self.engine.state == "playing":
            self.engine.pause()
        elif self.engine.state == "paused":
            self.engine.play()
        elif self._current is not None and self._row_of(self._current) >= 0 \
                and self.engine.loaded and self.engine.path == self._current.data(_PATH_ROLE):
            self._fail_streak = 0
            self.engine.play()  # a stopped track (maybe at a restored position)
            self.visualizer.timer.start()
        else:
            self.play_selected()

    # -- next / previous -------------------------------------------------------------------

    def _items(self) -> list[QListWidgetItem]:
        return [self.playlist.item(i) for i in range(self.playlist.count())]

    def _next_item(self) -> QListWidgetItem | None:
        count = self.playlist.count()
        if not count:
            return None
        if self.shuffle:
            items = self._items()
            fresh = [i for i in items if id(i) not in self._round and i is not self._current]
            if not fresh:
                if self.repeat != "all":
                    return None
                self._round.clear()  # a new round
                fresh = [i for i in items if i is not self._current] or items
            return self._rng.choice(fresh)
        row = self.current_row()
        if row < 0 and self._resume_row is not None:
            nxt = self._resume_row
        else:
            nxt = row + 1
        if nxt >= count:
            return self.playlist.item(0) if self.repeat == "all" else None
        return self.playlist.item(max(0, nxt))

    def _previous_item(self) -> tuple[QListWidgetItem | None, bool]:
        """The track ⏮ goes to and whether that is a step back in the
        shuffle history (played again without being recorded)."""
        count = self.playlist.count()
        if not count:
            return None, False
        if self.shuffle:
            while len(self._history) >= 2:
                candidate = self._history[-2]
                if self._row_of(candidate) >= 0:
                    self._history.pop()
                    return candidate, True
                del self._history[-2]
        row = self.current_row()
        if row < 0:
            row = self._resume_row if self._resume_row is not None else 0
        if row - 1 >= 0:
            return self.playlist.item(min(row - 1, count - 1)), False
        if self.repeat == "all":
            return self.playlist.item(count - 1), False
        return self.playlist.item(0), False

    def next_track(self) -> None:
        """⏭: the next track (repeat one does not hold it)."""
        item = self._next_item()
        if item is not None:
            self._fail_streak = 0
            self.play_item(item)

    def previous_track(self) -> None:
        """⏮: the start of this track once it played a little, else the
        previous one."""
        if self._row_of(self._current) >= 0 and self.engine.position_ms() > RESTART_AFTER_MS:
            self.engine.seek(0)
            return
        item, back = self._previous_item()
        if item is not None:
            self._fail_streak = 0
            self.play_item(item, record=not back)

    def _next_after_end(self) -> None:
        self._fail_streak = 0
        if self.repeat == "one" and self._row_of(self._current) >= 0:
            self.play_item(self._current, record=False)
            return
        item = self._next_item()
        if item is not None:
            self.play_item(item)
        else:
            self.visualizer.timer.stop()

    def _track_failed(self, reason: str) -> None:
        """An unplayable track: marked, noted and skipped - unless no track
        of the list played, which ends it instead of looping."""
        item = self._current
        name = item.text() if self._row_of(item) >= 0 else os.path.basename(self.engine.path)
        if self._row_of(item) >= 0:
            item.setToolTip(f"{item.data(_PATH_ROLE)}\n{tr('Cannot play')}: {reason}")
            item.setForeground(QColor("#c0392b"))
        self._fail_streak += 1
        if self._fail_streak >= max(1, self.playlist.count()):
            self.note.setText(tr("Cannot play {name}: {reason}. No track in the list could be "
                                 "played.").format(name=name, reason=reason))
            self.visualizer.timer.stop()
            return
        self.note.setText(tr("Cannot play {name}: {reason} - skipped.").format(name=name,
                                                                               reason=reason))
        # Not from inside the engine's signal: a list of broken files would
        # recurse one level per file.
        QTimer.singleShot(0, self._skip_failed)

    def _skip_failed(self) -> None:
        if self.engine.state != "stopped" or not self.engine.error:
            return  # the user started something else meanwhile
        item = self._next_item()
        note = self.note.text()
        if item is not None:
            self.play_item(item)
            self.note.setText(note)

    # -- shuffle and repeat ------------------------------------------------------------------

    def set_shuffle(self, on: bool) -> None:
        self.shuffle = bool(on)
        if self.shuffle_button.isChecked() != self.shuffle:
            self.shuffle_button.setChecked(self.shuffle)
        current = self._current if self._row_of(self._current) >= 0 else None
        self._round = {id(current)} if current is not None else set()
        self._history = [current] if current is not None else []
        self._schedule_save()

    def set_repeat(self, mode: str) -> None:
        if mode not in REPEAT_MODES:
            raise ValueError(f"repeat is one of {REPEAT_MODES}, not {mode!r}")
        self.repeat = mode
        self._update_repeat_button()
        self._schedule_save()

    def _cycle_repeat(self) -> None:
        index = REPEAT_MODES.index(self.repeat)
        self.set_repeat(REPEAT_MODES[(index + 1) % len(REPEAT_MODES)])

    def _update_repeat_button(self) -> None:
        self._set_control(self.repeat_button, "repeat-one" if self.repeat == "one" else "repeat")
        self.repeat_button.setChecked(self.repeat != "off")
        label = {"off": tr("off"), "all": tr("all"), "one": tr("one")}[self.repeat]
        self.repeat_button.setToolTip(tr("Repeat: {mode} (click: off → all → one)")
                                      .format(mode=label))

    # -- seeking ---------------------------------------------------------------------------

    def seek_to(self, ms: int) -> None:
        if self.engine.loaded:
            self.engine.seek(max(0, int(ms)))
            self._refresh_time()

    def seek_relative(self, delta_ms: int) -> None:
        if self.engine.loaded:
            self.seek_to(max(0, self.engine.position_ms() + int(delta_ms)))

    def _slider_action(self, action: int) -> None:
        # Keyboard steps on the slider (Page Up/Down, Home, End); a drag
        # seeks on release, a click through `jumped`.
        moves = (QAbstractSlider.SliderAction.SliderNoAction.value,
                 QAbstractSlider.SliderAction.SliderMove.value)
        if action not in moves and not self.seek_slider.isSliderDown():
            QTimer.singleShot(0, lambda: self.seek_to(self.seek_slider.sliderPosition()))

    def _duration(self) -> int:
        duration = 0
        getter = getattr(self.engine, "duration_ms", None)
        if getter is not None:
            duration = int(getter() or 0)
        return duration or int(self._track_ms or 0)

    # -- volume ------------------------------------------------------------------------------

    def set_muted(self, on: bool) -> None:
        self.muted = bool(on)
        if self.mute_button.isChecked() != self.muted:
            self.mute_button.setChecked(self.muted)
        self._set_control(self.mute_button, "volume-x" if self.muted else "volume")
        self._apply_volume()
        self._schedule_save()

    def _apply_volume(self) -> None:
        """The slider's level (perceptual), scaled by the output volume of
        Edit > Settings… > Audio."""
        level = 0.0 if self.muted else perceptual_to_linear(self.volume.value() / 100)
        self.engine.set_volume(level * audio_route.output_gain())

    def _audio_settings_saved(self, saved) -> None:
        """Edit > Settings… > Audio saved: the volume at once, a new output
        device for the running engine where it can move (else its next
        playback takes it)."""
        if self._gone():
            return
        self._apply_volume()
        if saved.output_device != self._output_device:
            self._output_device = saved.output_device
            reroute = getattr(self.engine, "reroute", None)
            if callable(reroute):
                try:
                    reroute()
                except Exception:  # noqa: BLE001 - the player goes on on the old device
                    log.warning("Media Player: the output device could not be changed",
                                exc_info=True)

    def step_volume(self, steps: int) -> None:
        self.volume.setValue(self.volume.value() + steps * VOLUME_STEP)

    # -- keyboard (while the panel has the focus) --------------------------------------------

    _ARROWS = (Qt.Key.Key_Left, Qt.Key.Key_Right, Qt.Key.Key_Up, Qt.Key.Key_Down,
               Qt.Key.Key_PageUp, Qt.Key.Key_PageDown, Qt.Key.Key_Home, Qt.Key.Key_End)

    def _key_action(self, widget, event):
        """What a key pressed in *widget* (this panel or a child) does, or
        None to leave it to the widget. Caught as ShortcutOverride too, so
        the panel's keys win over the main window's shortcuts while it has
        the focus - and only then."""
        key = event.key()  # an int; Qt.Key is an IntEnum
        mods = event.modifiers() & (Qt.KeyboardModifier.ShiftModifier
                                    | Qt.KeyboardModifier.ControlModifier
                                    | Qt.KeyboardModifier.AltModifier
                                    | Qt.KeyboardModifier.MetaModifier)
        none = mods == Qt.KeyboardModifier.NoModifier
        shift = mods == Qt.KeyboardModifier.ShiftModifier
        ctrl = mods == Qt.KeyboardModifier.ControlModifier
        if isinstance(widget, QComboBox):
            return None
        if isinstance(widget, QSlider) and widget is not self.seek_slider \
                and key in self._ARROWS and not ctrl:
            return None
        if isinstance(widget, QAbstractButton) and key in (
                Qt.Key.Key_Space, Qt.Key.Key_Return, Qt.Key.Key_Enter):
            return None
        if key == Qt.Key.Key_Space and none:
            return self.toggle_play
        if key in (Qt.Key.Key_Return, Qt.Key.Key_Enter) and none:
            return self.play_selected
        if key == Qt.Key.Key_Delete and none:
            return self._remove_selected
        if key in (Qt.Key.Key_Left, Qt.Key.Key_Right):
            sign = 1 if key == Qt.Key.Key_Right else -1
            if none:
                return lambda: self.seek_relative(sign * SEEK_STEP_MS)
            if shift:
                return lambda: self.seek_relative(sign * SEEK_BIG_STEP_MS)
            if ctrl:
                return self.next_track if sign > 0 else self.previous_track
            return None
        if key == Qt.Key.Key_M and none:
            return lambda: self.set_muted(not self.muted)
        if key == Qt.Key.Key_Plus and (none or shift):
            return lambda: self.step_volume(1)
        if key == Qt.Key.Key_Minus and none:
            return lambda: self.step_volume(-1)
        return None

    def _owns(self, widget) -> bool:
        """*widget* is this panel, inside it, or inside the visualizer's
        own window (isAncestorOf stops at a window's edge)."""
        if widget is self or self.isAncestorOf(widget):
            return True
        window = getattr(self, "visual_window", None)
        return window is not None and not sip.isdeleted(window) and (
            widget is window or window.isAncestorOf(widget))

    def eventFilter(self, obj, event) -> bool:  # noqa: N802 - Qt
        kind = event.type()
        if kind not in (QEvent.Type.ShortcutOverride, QEvent.Type.KeyPress):
            return False
        if not isinstance(obj, QWidget) or not self._owns(obj):
            return False
        action = self._key_action(obj, event)
        if action is None:
            return False
        event.accept()
        if kind == QEvent.Type.KeyPress:
            action()
        return True

    # -- equalizer ---------------------------------------------------------------------

    def apply_preset(self, name: str) -> None:
        gains = PRESETS.get(name)
        if gains is None:
            return
        self._setting = True
        for slider, gain in zip(self.sliders, gains):
            slider.setValue(round(gain))
        self._setting = False
        self.engine.set_gains(list(gains))

    def _sliders_moved(self) -> None:
        if getattr(self, "_setting", False):
            return
        self.engine.set_gains([float(s.value()) for s in self.sliders])

    def set_equalizer_open(self, open_: bool) -> None:
        """Show the band sliders or fold them away; the header row (the
        fold button, on/off, the preset) stays, and so do the gains."""
        open_ = bool(open_)
        self._eq_open = open_
        self.eq_body.setVisible(open_)
        if self.eq_toggle.isChecked() != open_:
            self.eq_toggle.blockSignals(True)
            self.eq_toggle.setChecked(open_)
            self.eq_toggle.blockSignals(False)
        self.eq_toggle.setArrowType(Qt.ArrowType.DownArrow if open_ else Qt.ArrowType.RightArrow)
        self._schedule_save()

    def _eq_toggled(self, on: bool) -> None:
        if isinstance(self.engine, EqEngine):
            self.engine.set_eq_enabled(on)
        for slider in self.sliders:
            slider.setEnabled(on)

    # -- the playlist folds --------------------------------------------------------------

    def set_playlist_open(self, open_: bool) -> None:
        """Show the playlist and its buttons or fold them away: the panel is
        then the controls and the visualizer, which gets the room. Keys and
        drops onto the panel keep working."""
        open_ = bool(open_)
        focus = self.focusWidget()
        self._playlist_open = open_
        self.playlist.setVisible(open_)
        self.playlist_buttons.setVisible(open_)
        if self.playlist_toggle.isChecked() != open_:
            self.playlist_toggle.blockSignals(True)
            self.playlist_toggle.setChecked(open_)
            self.playlist_toggle.blockSignals(False)
        self.playlist_toggle.setArrowType(Qt.ArrowType.DownArrow if open_
                                          else Qt.ArrowType.RightArrow)
        layout = self.layout()
        layout.setStretchFactor(self.visual_box, 0 if open_ else 1)
        if not open_ and focus is not None and (
                focus is self.playlist or self.playlist.isAncestorOf(focus)
                or self.playlist_buttons.isAncestorOf(focus)):
            self.setFocus()  # the keys stay with the player
        self._schedule_save()

    # -- drops onto the panel --------------------------------------------------------------

    def dragEnterEvent(self, event) -> None:  # noqa: N802 - Qt
        if PlaylistWidget.accepts(event.mimeData()):
            event.setDropAction(Qt.DropAction.CopyAction)
            event.accept()
        else:
            event.ignore()

    def dragMoveEvent(self, event) -> None:  # noqa: N802 - Qt
        self.dragEnterEvent(event)

    def dropEvent(self, event) -> None:  # noqa: N802 - Qt
        mime = event.mimeData()
        if not PlaylistWidget.accepts(mime):
            event.ignore()
            return
        event.setDropAction(Qt.DropAction.CopyAction)
        event.accept()
        self._on_drop(mime)

    # -- the visualizer: its menu, its window, fullscreen ------------------------------------

    @property
    def is_fullscreen(self) -> bool:
        return self.visual_window is not None and self._fullscreen

    @property
    def is_detached(self) -> bool:
        return self.visual_window is not None

    def _visualizer_menu(self, menu) -> None:
        """The panel's entries in the visualizer's right-click menu."""
        menu.addSeparator()
        fullscreen = menu.addAction(tr("Fullscreen") + "\tF11")
        fullscreen.setCheckable(True)
        fullscreen.setChecked(self.is_fullscreen)
        fullscreen.setData(("window", "fullscreen"))
        fullscreen.setEnabled(self.is_fullscreen or (self.isVisible() and not self._shut_down))
        fullscreen.triggered.connect(lambda checked: self.set_fullscreen(checked))
        if self.is_detached and not self.is_fullscreen:
            attach = menu.addAction(tr("Attach to the Panel"))
            attach.setData(("window", "attach"))
            attach.triggered.connect(lambda _checked=False: self.attach_visualizer())
        elif not self.is_detached:
            detach = menu.addAction(tr("Detach into a Window"))
            detach.setData(("window", "detach"))
            detach.triggered.connect(lambda _checked=False: self.detach_visualizer())
        playlist = menu.addAction(tr("Show Playlist"))
        playlist.setCheckable(True)
        playlist.setChecked(self._playlist_open)
        playlist.setData(("playlist", "open"))
        playlist.triggered.connect(lambda checked: self.set_playlist_open(checked))
        menu.addSeparator()
        settings = menu.addAction(tr("Visualizer Settings…"))
        settings.setData(("settings", "open"))
        settings.triggered.connect(lambda _checked=False: self.open_visual_settings())

    def open_visual_settings(self) -> None:
        """The visualizer settings dialog (one; raised when it is open)."""
        if self._gone():
            return
        dialog = self.visual_settings
        if dialog is None or sip.isdeleted(dialog):
            dialog = VisualizerSettingsDialog(self.visualizer, self)
            dialog.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
            dialog.finished.connect(lambda _result: setattr(self, "visual_settings", None))
            self.visual_settings = dialog
        dialog.show()
        dialog.raise_()
        dialog.activateWindow()

    def _take_visualizer_out(self) -> VisualizerWindow:
        window = VisualizerWindow(self)
        window.closed.connect(self.attach_visualizer)
        window.installEventFilter(self)  # the player's keys work there too
        self.visual_box.layout().removeWidget(self.visualizer)
        window.layout().addWidget(self.visualizer)
        self.visualizer.show()
        self.visual_placeholder.setVisible(True)
        self.visual_window = window
        return window

    def detach_visualizer(self) -> None:
        """The visualizer into a resizable window of its own: the same
        widget moves (nothing renders twice) and keeps playing."""
        if self._gone():
            return
        window = self.visual_window
        if window is None:
            window = self._take_visualizer_out()
            window.resize(max(480, self.visualizer.width()), max(270, self.visualizer.height()))
        elif self._fullscreen:
            self._fullscreen = self._fullscreen_from_panel = False
            self.visualizer.fullscreen = False
            self.visualizer.set_cursor_autohide(False)
            window.showNormal()
        window.show()
        window.raise_()
        window.activateWindow()

    def attach_visualizer(self) -> None:
        """The visualizer back into the panel; its window goes."""
        window = self.visual_window
        if window is None:
            return
        self.visual_window = None
        self._fullscreen = self._fullscreen_from_panel = False
        vis = self.visualizer
        vis.fullscreen = False
        vis.set_cursor_autohide(False)
        if not sip.isdeleted(window):
            window.layout().removeWidget(vis)
        self.visual_box.layout().insertWidget(0, vis, 1)
        vis.show()
        self.visual_placeholder.setVisible(False)
        if not sip.isdeleted(window):
            window.removeEventFilter(self)
            window.closing_quietly = True
            window.close()
            window.deleteLater()

    def set_fullscreen(self, on: bool) -> bool:
        """The visualizer alone on the panel's screen (*on*) or back where
        it was - the panel, or its own window. Refused (False) while the
        panel is hidden or switched off: nothing may take the screen then."""
        if not on:
            if self._fullscreen:
                vis = self.visualizer
                vis.fullscreen = False
                vis.set_cursor_autohide(False)
                self._fullscreen = False
                if self._fullscreen_from_panel or self.visual_window is None:
                    self.attach_visualizer()
                else:
                    self.visual_window.showNormal()
                    vis.setFocus()
            return True
        if self._gone() or not self.isVisible():
            return False
        if self._fullscreen:
            return True
        from_panel = self.visual_window is None
        window = self.visual_window or self._take_visualizer_out()
        screen = self.screen()
        if screen is not None:
            window.move(screen.geometry().topLeft())  # fullscreen on the panel's screen
        self._fullscreen = True
        self._fullscreen_from_panel = from_panel
        vis = self.visualizer
        vis.fullscreen = True
        window.showFullScreen()
        window.raise_()
        window.activateWindow()
        vis.setFocus()
        vis.set_cursor_autohide(True)
        return True

    def toggle_fullscreen(self) -> bool:
        return self.set_fullscreen(not self.is_fullscreen)

    def hideEvent(self, event) -> None:  # noqa: N802 - Qt
        super().hideEvent(event)
        if self._fullscreen:
            # Closed (not just moved to another workspace, which shows it
            # again at once): the screen is given back.
            QTimer.singleShot(0, self._hidden_while_fullscreen)

    def _hidden_while_fullscreen(self) -> None:
        if not sip.isdeleted(self) and self._fullscreen and not self.isVisible():
            self.set_fullscreen(False)

    # -- now playing -----------------------------------------------------------------------

    def _read_tags(self, path: str) -> None:
        """Title, artist, album, length and cover from Qt's metadata reader
        (a QMediaPlayer: not before the engine is there - _attach_engine
        reads them then)."""
        self.now_playing.setText(os.path.basename(path))
        self.cover.clear()
        if not self.engine_ready:
            return
        try:
            from PyQt6.QtMultimedia import QMediaMetaData, QMediaPlayer
        except ImportError:  # pragma: no cover
            return
        reader = QMediaPlayer(self)
        prime_notify_lookups(reader)

        def loaded(status, r=reader) -> None:
            if status not in (QMediaPlayer.MediaStatus.LoadedMedia,
                              QMediaPlayer.MediaStatus.InvalidMedia):
                return
            r.mediaStatusChanged.disconnect()
            if self.engine.path != path:
                r.deleteLater()
                return  # the track changed meanwhile
            meta = r.metaData()
            title = meta.stringValue(QMediaMetaData.Key.Title) or os.path.basename(path)
            artist = meta.stringValue(QMediaMetaData.Key.ContributingArtist) or meta.stringValue(
                QMediaMetaData.Key.AlbumArtist)
            album = meta.stringValue(QMediaMetaData.Key.AlbumTitle)
            self._track_ms = max(0, int(r.duration()))
            if self._track_ms and self._row_of(self._current) >= 0 \
                    and self._current.data(_PATH_ROLE) == path:
                self._current.setData(_DURATION_ROLE, self._track_ms // 1000)
            text = " — ".join(t for t in (title, artist, album) if t)
            if not self.engine.error:
                self.now_playing.setText(text)
            if self._current is not None and self._row_of(self._current) >= 0 \
                    and self._current.data(_PATH_ROLE) == path:
                self._set_title(text)
            for key in (QMediaMetaData.Key.CoverArtImage, QMediaMetaData.Key.ThumbnailImage):
                image = meta.value(key)
                if image is not None and hasattr(image, "isNull") and not image.isNull():
                    self.cover.setPixmap(QPixmap.fromImage(image).scaled(
                        72, 72, Qt.AspectRatioMode.KeepAspectRatio,
                        Qt.TransformationMode.SmoothTransformation))
                    break
            r.deleteLater()

        reader.mediaStatusChanged.connect(loaded)
        reader.setSource(QUrl.fromLocalFile(path))

    def _refresh(self) -> None:
        self._set_control(self.play_button, "pause" if self.engine.state == "playing" else "play")
        if self.engine.state != getattr(self, "_shown_state", None):
            self._shown_state = self.engine.state
            if self.engine.state != "playing":
                self._schedule_save()  # paused or stopped: keep the position
        if self.engine.error:
            self.now_playing.setText(tr("Cannot play: {reason}").format(reason=self.engine.error))

    def _refresh_time(self) -> None:
        duration = self._duration()
        slider = self.seek_slider
        slider.setEnabled(bool(self.engine.loaded) and duration > 0)
        if slider.maximum() != duration:
            slider.blockSignals(True)
            slider.setRange(0, duration)
            slider.blockSignals(False)
        if slider.isSliderDown():
            shown = slider.sliderPosition()  # where the drag would go
        else:
            shown = self.engine.position_ms() if self.engine.loaded else 0
            slider.blockSignals(True)
            slider.setValue(min(shown, duration))
            slider.blockSignals(False)
            if shown > 0 and self.engine.state == "playing":
                self._fail_streak = 0
        self.time_label.setText(f"{format_time(shown)} / {format_time(duration)}")
        if self._state_path and self.engine.state == "playing" \
                and time.monotonic() - self._last_save > _SAVE_EVERY_SECONDS:
            self.save_state()

    # -- the saved state ------------------------------------------------------------------

    def _schedule_save(self, *_args) -> None:
        if self._state_path and not self._restoring:
            self._save_timer.start()

    def _state(self) -> dict:
        tracks: list[dict] = []
        current = -1
        for item in self._items():
            path = item.data(_PATH_ROLE)
            if _is_temp_copy(path) or len(tracks) >= MAX_PLAYLIST_ENTRIES:
                continue  # a remote track's copy goes with the extension
            if item is self._current:
                current = len(tracks)
            title = item.text() if item.text() != os.path.basename(path) else ""
            tracks.append({"path": path, "title": title,
                           "duration": int(item.data(_DURATION_ROLE) or 0)})
        position = 0
        if current >= 0 and self.engine.loaded \
                and self.engine.path == self._current.data(_PATH_ROLE):
            position = int(self.engine.position_ms())
        return {"version": STATE_VERSION, "volume": self.volume.value(), "muted": self.muted,
                "shuffle": self.shuffle, "repeat": self.repeat, "tracks": tracks,
                "current": current, "position_ms": position,
                "visualizer": self.visualizer.mode, "equalizer_open": self._eq_open,
                "visual_scheme": self.visualizer.scheme,
                "visual_custom": dict(self.visualizer.custom_colours),
                "visual_options": {**self.visualizer.options,
                                   "hide_cursor": self.visualizer.hide_cursor},
                "playlist_open": self._playlist_open}

    def save_state(self) -> None:
        """Write the playlist, the current track and position, volume, mute,
        shuffle, repeat, the visualization with its colours and options, and
        whether the equalizer and the playlist are open to the private
        state file."""
        self._save_timer.stop()
        if not self._state_path or self._restoring:
            return  # restoring: the file still holds more than the list
        self._last_save = time.monotonic()
        try:
            write_state(self._state_path, self._state(), keep_old=self._state_unreadable)
            self._state_unreadable = False
        except OSError as exc:
            self.note.setText(tr("Cannot save the player state: {error}").format(error=exc))

    def restore_state(self) -> None:
        """The last playlist, track (loaded at its position, not playing),
        volume, mute, shuffle, repeat, visualization and the equalizer open
        or folded; tracks that are gone are left out,
        nonsense values are ignored. Whether the tracks still exist is
        checked off the GUI thread (a stale network mount must not hang the
        start); until then nothing is saved over the file."""
        state, usable = read_state(self._state_path)
        self._state_unreadable = not usable
        if not state:
            return
        self._restoring = True
        volume = state.get("volume")
        if isinstance(volume, int) and not isinstance(volume, bool):
            self.volume.setValue(max(0, min(100, volume)))
        self.set_muted(state.get("muted") is True)
        self.set_shuffle(state.get("shuffle") is True)
        repeat = state.get("repeat")
        self.set_repeat(repeat if repeat in REPEAT_MODES else "off")
        visual = state.get("visualizer")
        if isinstance(visual, str) and visual in Visualizer.MODES:
            self.visualizer.set_mode(visual, announce=False)
        self.set_equalizer_open(state.get("equalizer_open") is not False)
        self._restore_visual_settings(state)
        self.set_playlist_open(state.get("playlist_open") is not False)
        tracks = state.get("tracks")
        wanted = []
        for index, track in enumerate(tracks[:MAX_PLAYLIST_ENTRIES]
                                      if isinstance(tracks, list) else []):
            path = track.get("path") if isinstance(track, dict) else None
            if not isinstance(path, str) or not path.isprintable():
                continue
            title = track.get("title")
            duration = track.get("duration")
            wanted.append((index, path, _clean_text(title) if isinstance(title, str) else "",
                           duration if isinstance(duration, int) and duration > 0 else 0))
        current = state.get("current")
        position = state.get("position_ms")

        def work():
            return [entry for entry in wanted if _is_track(entry[1])]

        def done(found) -> None:
            try:
                items = {index: self._append(path, title, duration)
                         for index, path, title, duration in found}
                item = items.get(current) if isinstance(current, int) else None
                if item is not None and self._current is None:
                    self._set_current(item)
                    self._history = [item]
                    self._round = {id(item)}
                    path = item.data(_PATH_ROLE)
                    self.engine.load(path)
                    if isinstance(position, int) and position > 0:
                        self.engine.seek(position)
                    self._read_tags(path)
            finally:
                self._restoring = False

        def failed(_exc) -> None:
            self._restoring = False

        self._background(work, done, failed)

    def _restore_visual_settings(self, state: dict) -> None:
        """The colour scheme, custom colours and options; a broken value
        leaves its default, a number out of range is clamped."""
        vis = self.visualizer
        vis.set_custom_colours(state.get("visual_custom"))
        scheme = state.get("visual_scheme")
        if isinstance(scheme, str) and scheme in SCHEME_NAMES:
            vis.set_scheme(scheme)
        options = state.get("visual_options")
        if isinstance(options, dict):
            for name in VISUAL_OPTIONS:
                if name in options:
                    vis.set_option(name, options[name])
            if isinstance(options.get("hide_cursor"), bool):
                vis.set_hide_cursor(options["hide_cursor"])

    def shutdown(self) -> None:
        """The extension unloads (or the window closes): save, then stop."""
        self._shut_down = True  # a probe answering later builds no engine
        self.attach_visualizer()  # its window and the screen go with the extension
        self._close_visual_settings()
        self.save_state()
        self._state_path = None  # nothing after this writes
        self._clock.stop()
        self.engine.stop()
        self.visualizer.timer.stop()

    # -- control icons ----------------------------------------------------------------------

    def _control_colour(self) -> str:
        return self.palette().color(QPalette.ColorRole.ButtonText).name()

    def _set_control(self, button, name: str) -> None:
        """Show control icon *name* on *button* in the theme's button text
        colour; nothing is redrawn when icon and colour are unchanged."""
        colour = self._control_colour()
        if button.property("control") == name and button.property("control-colour") == colour:
            return
        button.setIcon(control_icon(name, colour))
        button.setIconSize(QSize(CONTROL_ICON_SIZE, CONTROL_ICON_SIZE))
        button.setProperty("control", name)
        button.setProperty("control-colour", colour)

    def _update_control_icons(self) -> None:
        self._set_control(self.prev_button, "previous")
        self._set_control(self.play_button,
                          "pause" if getattr(self.engine, "state", "") == "playing" else "play")
        self._set_control(self.stop_button, "stop")
        self._set_control(self.next_button, "next")
        self._set_control(self.shuffle_button, "shuffle")
        self._set_control(self.repeat_button,
                          "repeat-one" if self.repeat == "one" else "repeat")
        self._set_control(self.mute_button, "volume-x" if self.muted else "volume")

    def changeEvent(self, event) -> None:  # noqa: N802 - Qt
        super().changeEvent(event)
        if event.type() in (QEvent.Type.PaletteChange, QEvent.Type.StyleChange) \
                and hasattr(self, "mute_button"):
            self._update_control_icons()

    def _close_visual_settings(self) -> None:
        dialog = self.visual_settings
        self.visual_settings = None
        if dialog is not None and not sip.isdeleted(dialog):
            dialog.close()

    def closeEvent(self, event) -> None:  # noqa: N802 - Qt
        self.attach_visualizer()
        self._close_visual_settings()
        if self._state_path:
            self.save_state()
        self.engine.stop()
        self.visualizer.timer.stop()
        super().closeEvent(event)


#: The panels activate() made, for deactivate().
_PANELS: list = []


def deactivate(api):
    while _PANELS:
        panel = _PANELS.pop()
        try:
            panel.shutdown()  # saves the playlist and position
        except RuntimeError:  # pragma: no cover - the widget is gone already
            pass
    while _TEMP_FOLDERS:
        shutil.rmtree(_TEMP_FOLDERS.pop(), ignore_errors=True)


def activate(api):
    window = getattr(api, "window", None)
    open_settings = getattr(window, "open_settings", None)
    panel = PlayerPanel(state_path=str(state_file()),
                        run_in_background=lambda work, done, error: api.run_in_background(
                            work, on_done=done, on_error=error),
                        open_audio_settings=(lambda: open_settings("audio"))
                        if callable(open_settings) else None)
    panel.drop_resolver = getattr(api, "drop_context", None)
    panel.engine_failed.connect(api.notify)
    if panel.audio_error:  # a host that answered at once
        api.notify(panel.audio_error)
    _PANELS.append(panel)
    dock = api.add_dock(tr("Media Player"), panel)
    bar = dock.titleBarWidget() if dock is not None else None

    def show_track(title: str) -> None:
        if bar is None:
            return
        if hasattr(bar, "set_title"):
            bar.set_title(f"{tr('Media Player')} — {title}" if title else tr("Media Player"))
        bar.setToolTip(title)

    panel.track_changed.connect(show_track)
    add_menu_action = getattr(api, "add_menu_action", None)
    if callable(add_menu_action):
        add_menu_action("Media Player Visualizer…", panel.open_visual_settings)

    def play(ctx) -> None:
        """Add the selection and play the first of it: local files at once,
        remote ones copied to a bounded temporary folder off the GUI
        thread first."""
        paths = list(ctx.paths)
        if ctx.is_local:
            first = panel.add_collected(*collect_local(paths))
            if first is not None:
                panel.play_item(first)
            return

        def done(result) -> None:
            first = panel.add_collected(result[0], result[1], result[2])
            if first is not None:
                panel.play_item(first)

        api.run_in_background(lambda: fetch_remote(ctx.backend, paths), on_done=done,
                              on_error=lambda exc: api.notify(f"Cannot play: {exc}"))

    api.add_context_action("Play in Media Player", play, applies_to="files", extensions=AUDIO_SUFFIXES)
