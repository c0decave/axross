"""A media player panel: playlist (drag & drop, M3U, shuffle and repeat),
seeking, volume with mute, tags and cover, a 10-band equalizer (folds
away) and animated visualizations a click switches between."""

from __future__ import annotations

import logging
import math
import os
import posixpath
import random
import shutil
import time

from PyQt6.QtCore import (
    QByteArray,
    QEvent,
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
    QColor,
    QFont,
    QIcon,
    QLinearGradient,
    QPainter,
    QPalette,
    QPen,
    QPixmap,
    QPolygonF,
)
from PyQt6.QtSvg import QSvgRenderer
from PyQt6.QtWidgets import (
    QAbstractButton,
    QAbstractItemView,
    QAbstractSlider,
    QCheckBox,
    QComboBox,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QSlider,
    QStyle,
    QStyleOptionSlider,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from core.i18n import tr

log = logging.getLogger(__name__)

try:  # the equalizer and the visualizations need numpy; playback does not
    import numpy as np
except ImportError:  # pragma: no cover - depends on the install
    np = None

EXTENSION = {
    "name": "Media Player",
    "version": "1.2",
    "description": "A panel that plays MP3, WAV, Ogg Vorbis, FLAC, Opus, AAC and more: playlist "
    "with drag & drop, M3U load/save and the last list restored, seeking, shuffle and repeat, "
    "volume with mute, keyboard control, tags and cover, a 10-band equalizer with presets that "
    "folds away, and animated visualizations - spectrum, mirrored and radial spectrum, "
    "oscilloscope, VU meter - a click switches between (equalizer and visualizations need "
    "numpy).",
    "author": "axross",
}

AUDIO_SUFFIXES = (".mp3", ".wav", ".ogg", ".oga", ".opus", ".flac", ".m4a", ".aac", ".wma", ".aiff",
                  ".aif", ".mka")
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
    levels; links to folders are not followed) and the entries of M3U
    playlists. Also the number of dropped entries that are no track and
    whether the bound cut the list."""
    max_files = MAX_DROP_FILES if max_files is None else max_files
    max_depth = MAX_DROP_DEPTH if max_depth is None else max_depth
    found: list[tuple[str, str]] = []
    skipped = 0
    truncated = False

    def walk(folder: str, depth: int) -> None:
        nonlocal truncated
        if depth > max_depth:
            return
        try:
            with os.scandir(folder) as it:
                entries = sorted(it, key=lambda e: e.name.casefold())
        except OSError:
            return
        for entry in entries:
            if len(found) >= max_files:
                truncated = True
                return
            try:
                if entry.is_dir(follow_symlinks=False):
                    walk(entry.path, depth + 1)
                elif is_audio(entry.name) and entry.is_file():
                    found.append((entry.path, ""))
            except OSError:
                continue

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
    return found, skipped, truncated


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
    truncated = False

    def walk(folder: str, depth: int) -> None:
        nonlocal truncated
        if depth > MAX_DROP_DEPTH:
            return
        try:
            items = sorted(backend.list_dir(folder), key=lambda i: i.name.casefold())
        except OSError:
            return
        for item in items:
            if len(remote) >= MAX_DROP_FILES:
                truncated = True
                return
            child = backend.join(folder, item.name)
            if item.is_dir:
                if not getattr(item, "is_link", False):
                    walk(child, depth + 1)
            elif is_audio(item.name):
                remote.append((child, item.name))

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
        return [], skipped, truncated, ""
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
    the loudest bin of each bar on a -70..0 dBFS scale."""
    data = np.asarray(samples, np.float32)
    mono = data.mean(axis=1) if data.ndim == 2 else data
    n = len(mono)
    if n == 0:
        return np.zeros(n_bars, np.float32)
    window = 0.5 - 0.5 * np.cos(2 * np.pi * np.arange(n) / n)
    mags = np.abs(np.fft.rfft(mono * window))
    freqs = np.fft.rfftfreq(n, 1.0 / rate)
    edges = np.geomspace(40.0, min(16000.0, rate / 2), n_bars + 1)
    bars = np.zeros(n_bars, np.float32)
    ref = n / 4.0  # a full-scale sine under the Hann window
    for i in range(n_bars):
        sel = mags[(freqs >= edges[i]) & (freqs < edges[i + 1])]
        if len(sel):
            peak = float(sel.max()) / ref
            db = 20 * np.log10(peak) if peak > 0 else -200.0
            bars[i] = min(1.0, max(0.0, (db + 70.0) / 70.0))
    return bars


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


class QtSink:
    """The sound card: QAudioSink in push mode."""

    def __init__(self, fmt) -> None:
        from PyQt6.QtMultimedia import QAudioSink, QMediaDevices

        self._sink = QAudioSink(QMediaDevices.defaultAudioOutput(), fmt)
        self._sink.setBufferSize(RATE * 2 * 4 // 4)  # 250 ms
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


def _audio_format():
    from PyQt6.QtMultimedia import QAudioFormat

    fmt = QAudioFormat()
    fmt.setSampleRate(RATE)
    fmt.setChannelCount(2)
    fmt.setSampleFormat(QAudioFormat.SampleFormat.Float)
    return fmt


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

    def __init__(self, sink_factory=None) -> None:
        super().__init__()
        from PyQt6.QtMultimedia import QAudioDecoder

        self.sink_factory = sink_factory or QtSink
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
        self._decoder.setAudioFormat(_audio_format())
        self._decoder.bufferReady.connect(self._decoded)
        self._decoder.finished.connect(self._decoder_done)
        self._decoder.error.connect(self._decoder_error)
        self._decoder.durationChanged.connect(self._duration_known)
        self._pending = bytearray()
        self._decoding_done = False
        self._finish_waiting = False
        #: True while this engine stops the decoder itself: QAudioDecoder
        #: emits finished() from stop(), which is no end of the track.
        self._stopping_decoder = False
        self._decoder_starts = 0
        self._skip = 0
        self._queued_frames = 0
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
        self._base_frames = self._start_frames
        self._start_frames = 0
        self._written_frames = 0
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
        target = max(0, int(ms)) * RATE // 1000
        if self.state == "stopped":
            self._start_frames = target
            self.changed.emit()
            return
        if self._duration > 0 and target >= self._duration * RATE // 1000:
            self._end_track()
            return
        current = self._base_frames + self._written_frames
        ahead = len(self._pending) // 8
        if current <= target < current + ahead:
            # Decoded already: the equalizer's state runs on unbroken.
            del self._pending[: (target - current) * 8]
        elif not self._decoding_done and target >= self._raw_frames:
            self._restart_chain(target)
        elif self._decoding_done and target >= current + ahead:
            self._end_track()
            return
        else:
            self._start_decoder(target)
        self._base_frames = target
        self._written_frames = 0
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

    def position_ms(self) -> int:
        if self.state == "stopped":
            return int(self._start_frames * 1000 // RATE)
        return int((self._base_frames + self._written_frames) * 1000 // RATE)

    def duration_ms(self) -> int:
        """The track's length once the decoder knows it, else 0."""
        return int(self._duration)

    def current_bars(self, n_bars: int = 32):
        return spectrum_bars(self._recent, RATE, n_bars)

    def current_samples(self):
        """The last FRAME frames written to the sound card (frames x 2,
        float32), for the oscilloscope and the VU meter. Replaced, never
        changed in place."""
        return self._recent

    # -- the chain -------------------------------------------------------------------------

    def _new_sink(self):
        sink = self.sink_factory(_audio_format())
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

    def _restart_chain(self, drop_to: int) -> None:
        """A fresh equalizer and queue for audio from frame *drop_to* on;
        the decoder (running) drops what it decodes before it."""
        self.equalizer.reset()
        self._pending.clear()
        self._decoded_frames = self._queued_frames = 0
        # The equalizer's output lags by its latency: that many leading
        # samples are dropped, and the flush supplies them at the end.
        self._skip = self.equalizer.latency
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
        self._decoding_done = True
        self._written_frames = self._base_frames = self._start_frames = 0
        self.state = "stopped"
        self.finished = True
        self.changed.emit()
        self.finished_playing.emit()

    def _room(self) -> bool:
        """Whether one more decoded buffer may be taken now."""
        return len(self._pending) < MAX_AHEAD_SECONDS * RATE * 8

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
        block = np.frombuffer(raw, np.float32).reshape(-1, 2)[offset:]
        self._decoded_frames += len(block)
        self._queue(self.equalizer.process(block))

    def _queue(self, frames) -> None:
        if self._skip and len(frames):
            dropped = min(self._skip, len(frames))
            frames = frames[dropped:]
            self._skip -= dropped
        if len(frames):
            self._queued_frames += len(frames)
            self._pending += np.ascontiguousarray(frames, np.float32).tobytes()

    def _decoder_done(self) -> None:
        if self._stopping_decoder:
            return  # stop() emits finished(): not the end of the track
        if self._decoder.bufferAvailable():
            self._finish_waiting = True  # the last buffer is not taken yet
            return
        self._finish_waiting = False
        self._drop_to = None  # a seek past the real end: nothing follows
        need = self._decoded_frames - self._queued_frames
        tail = self.equalizer.flush()
        self._queue(tail[: max(0, need + self._skip)])
        self._decoding_done = True
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
        free = sink.bytes_free()
        if free and self._pending:
            size = min(free, len(self._pending)) // 8 * 8
            if size:
                chunk = bytes(self._pending[:size])
                written = sink.write(chunk)
                del self._pending[:written]
                frames = np.frombuffer(chunk[:written], np.float32).reshape(-1, 2)
                self._written_frames += len(frames)
                if len(frames):
                    self._recent = np.concatenate([self._recent, frames])[-FRAME:]
        if self._decoding_done and not self._pending:
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
}
_VISUAL_BACKGROUND = "#101418"
_SAMPLE_MODES = ("scope", "vu")


def _level_colour(level: float) -> QColor:
    """Green (quiet) over yellow to red (loud), like the bars' gradient."""
    level = min(1.0, max(0.0, level))
    return QColor.fromHsvF((1.0 - level) * 120.0 / 360.0, 0.8, 0.95)


class Visualizer(QWidget):
    """The sound as a picture, at 30 frames a second while playing. A left
    click goes to the next face (:data:`VISUALIZER_NAMES`): spectrum bars
    (fast rise, slow fall, a falling peak cap per bar, green-yellow-red),
    the same mirrored around a middle line, a radial spectrum, an
    oscilloscope of the last samples and a stereo VU meter with peak hold.
    Each face asks the engine only for what it shows: the spectra for an
    FFT (:meth:`current_bars`), the others for the raw samples
    (:meth:`current_samples`). An engine without numpy answers None: the
    face stays empty."""

    BARS = 32
    MODES = tuple(VISUALIZER_NAMES)
    #: Points of the oscilloscope's trace at most.
    SCOPE_POINTS = 256
    #: How long the face's name shows after a switch.
    LABEL_SECONDS = 1.5
    #: The face now shown (one of MODES).
    mode_changed = pyqtSignal(str)

    def __init__(self, engine) -> None:
        super().__init__()
        self.engine = engine
        self.mode = self.MODES[0]
        self.levels = [0.0] * self.BARS
        self.peaks = [0.0] * self.BARS
        self.trace = None
        self.vu = [0.0, 0.0]
        self.vu_peaks = [0.0, 0.0]
        self._label_until = 0.0
        self._unit = [(math.cos(2 * math.pi * i / self.BARS - math.pi / 2),
                       math.sin(2 * math.pi * i / self.BARS - math.pi / 2))
                      for i in range(self.BARS)]
        self.setMinimumHeight(90)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.timer = QTimer(self)
        self.timer.setInterval(33)
        self.timer.timeout.connect(self.tick)
        self._label_timer = QTimer(self)  # repaints once the name is due to go
        self._label_timer.setSingleShot(True)
        self._label_timer.timeout.connect(self.update)
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
        self.setToolTip(tr("{name} - click for the next visualization").format(
            name=tr(VISUALIZER_NAMES[self.mode])))

    def mousePressEvent(self, event) -> None:  # noqa: N802 - Qt
        if event.button() == Qt.MouseButton.LeftButton:
            self.next_mode()
            event.accept()
            return
        super().mousePressEvent(event)

    # -- the data ---------------------------------------------------------------------

    def _samples(self):
        getter = getattr(self.engine, "current_samples", None)
        if np is None or not callable(getter):
            return None
        return getter()

    def tick(self) -> None:
        if self.mode in _SAMPLE_MODES:
            samples = self._samples()
            if samples is None:
                return
            if self.mode == "scope":
                self.trace = waveform(samples, max(2, min(self.SCOPE_POINTS, self.width())))
            else:
                levels = vu_levels(samples)
                for i in (0, 1):
                    value = levels[i]
                    self.vu[i] = value if value > self.vu[i] else self.vu[i] * 0.85 + value * 0.15
                    self.vu_peaks[i] = max(levels[2 + i], self.vu_peaks[i] - 0.01)
            self.update()
            return
        bars = self.engine.current_bars(self.BARS)
        if bars is None:
            return
        for i, value in enumerate(bars):
            value = float(value)
            self.levels[i] = value if value > self.levels[i] else self.levels[i] * 0.85 + value * 0.15
            self.peaks[i] = max(self.levels[i], self.peaks[i] - 0.015)
        self.update()

    # -- painting ---------------------------------------------------------------------

    def paintEvent(self, _event) -> None:  # noqa: N802 - Qt
        painter = QPainter(self)
        try:
            painter.fillRect(self.rect(), QColor(_VISUAL_BACKGROUND))
            if self.width() < 8 or self.height() < 8:
                return
            getattr(self, f"_paint_{self.mode}")(painter)
            if time.monotonic() < self._label_until:
                self._paint_label(painter)
        finally:
            painter.end()

    @staticmethod
    def _gradient(y_quiet: float, y_loud: float) -> QLinearGradient:
        gradient = QLinearGradient(0, y_quiet, 0, y_loud)
        gradient.setColorAt(0.0, QColor("#2ecc71"))
        gradient.setColorAt(0.6, QColor("#f1c40f"))
        gradient.setColorAt(1.0, QColor("#e74c3c"))
        return gradient

    def _paint_spectrum(self, painter: QPainter) -> None:
        width = self.width() / self.BARS
        height = self.height() - 4
        gradient = self._gradient(self.height(), 0)
        for i, (level, peak) in enumerate(zip(self.levels, self.peaks)):
            x = i * width + 1
            bar = max(2.0, level * height)
            painter.fillRect(QRectF(x, self.height() - bar, width - 2, bar), gradient)
            painter.fillRect(QRectF(x, self.height() - peak * height - 3, width - 2, 2), QColor("#ecf0f1"))

    def _paint_mirror(self, painter: QPainter) -> None:
        width = self.width() / self.BARS
        mid = self.height() / 2
        reach = mid - 3
        up, down = self._gradient(mid, 0), self._gradient(mid, self.height())
        cap = QColor("#ecf0f1")
        for i, (level, peak) in enumerate(zip(self.levels, self.peaks)):
            x = i * width + 1
            bar = max(1.0, level * reach)
            painter.fillRect(QRectF(x, mid - bar, width - 2, bar), up)
            painter.fillRect(QRectF(x, mid, width - 2, bar), down)
            painter.fillRect(QRectF(x, mid - peak * reach - 2, width - 2, 1.5), cap)
            painter.fillRect(QRectF(x, mid + peak * reach + 0.5, width - 2, 1.5), cap)

    def _paint_radial(self, painter: QPainter) -> None:
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        cx, cy = self.width() / 2, self.height() / 2
        radius = min(cx, cy)
        inner = radius * 0.22
        reach = max(1.0, radius - inner - 2)
        pen = QPen()
        pen.setWidthF(max(1.5, 2 * math.pi * inner / self.BARS * 0.6))
        pen.setCapStyle(Qt.PenCapStyle.FlatCap)
        for (ux, uy), level, peak in zip(self._unit, self.levels, self.peaks):
            pen.setColor(_level_colour(level))
            painter.setPen(pen)
            outer = inner + max(1.0, level * reach)
            painter.drawLine(QPointF(cx + ux * inner, cy + uy * inner),
                             QPointF(cx + ux * outer, cy + uy * outer))
            tip = inner + peak * reach + 2
            painter.fillRect(QRectF(cx + ux * tip - 1, cy + uy * tip - 1, 2, 2), QColor("#ecf0f1"))
        painter.setPen(QPen(QColor("#3d4650"), 1))
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawEllipse(QPointF(cx, cy), inner - 2, inner - 2)

    def _paint_scope(self, painter: QPainter) -> None:
        mid = self.height() / 2
        painter.setPen(QPen(QColor("#2a323a"), 1))
        painter.drawLine(QPointF(0, mid), QPointF(self.width(), mid))
        trace = self.trace
        if trace is None or len(trace) < 2:
            return
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        pen = QPen(QColor("#2ecc71"))
        pen.setWidthF(1.5)
        painter.setPen(pen)
        step = (self.width() - 1) / (len(trace) - 1)
        reach = mid - 2
        painter.drawPolyline(QPolygonF([QPointF(i * step, mid - float(v) * reach)
                                        for i, v in enumerate(trace)]))

    def _paint_vu(self, painter: QPainter) -> None:
        margin = 6
        label_width = 14
        track_left = margin + label_width
        track_width = max(1.0, self.width() - track_left - margin)
        row = (self.height() - 3 * margin) / 2
        gradient = QLinearGradient(track_left, 0, track_left + track_width, 0)
        gradient.setColorAt(0.0, QColor("#2ecc71"))
        gradient.setColorAt(0.75, QColor("#f1c40f"))  # -15 dBFS
        gradient.setColorAt(0.9, QColor("#e74c3c"))  # -6 dBFS
        painter.setPen(QColor("#9aa5b1"))
        for i, name in enumerate(("L", "R")):
            top = margin + i * (row + margin)
            painter.drawText(QRectF(margin, top, label_width, row),
                             Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft, name)
            painter.fillRect(QRectF(track_left, top, track_width, row), QColor("#20262c"))
            painter.fillRect(QRectF(track_left, top, track_width * self.vu[i], row), gradient)
            peak_x = track_left + track_width * self.vu_peaks[i]
            painter.fillRect(QRectF(peak_x - 1, top, 2, row), QColor("#ecf0f1"))
        tick = QColor("#3d4650")
        for db in range(10, int(VU_RANGE_DB), 10):  # a tick every 10 dB
            x = track_left + track_width * (1 - db / VU_RANGE_DB)
            painter.fillRect(QRectF(x, self.height() - margin + 1, 1, margin - 2), tick)

    def _paint_label(self, painter: QPainter) -> None:
        text = tr(VISUALIZER_NAMES[self.mode])
        metrics = painter.fontMetrics()
        box = QRectF(4, 4, metrics.horizontalAdvance(text) + 12, metrics.height() + 6)
        painter.fillRect(box, QColor(0, 0, 0, 170))
        painter.setPen(QColor("#ecf0f1"))
        painter.drawText(box, Qt.AlignmentFlag.AlignCenter, text)


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
                 engine_factory=None, audio_probe=None) -> None:
        super().__init__()
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
        root.addWidget(self.visualizer)
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
        self.playlist = PlaylistWidget()
        self.playlist.setToolTip(tr("Drop files or folders here; drag rows to reorder. "
                                    "Enter plays, Delete removes."))
        self.playlist.itemDoubleClicked.connect(lambda _item: self.play_selected())
        self.playlist.dropped.connect(self._on_drop)
        root.addWidget(self.playlist, 1)
        row = QHBoxLayout()
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
        root.addLayout(row)
        self.note = QLabel("")
        self.note.setWordWrap(True)
        root.addWidget(self.note)
        self._update_repeat_button()
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
        from PyQt6 import sip

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
        self._set_transport_enabled(False)
        log.warning("Media Player: %s", text)
        self.engine_failed.emit(text)

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
            parts.append(tr("Skipped {count} entry(s) that are not audio or not readable.")
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
        level = 0.0 if self.muted else perceptual_to_linear(self.volume.value() / 100)
        self.engine.set_volume(level)

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

    def eventFilter(self, obj, event) -> bool:  # noqa: N802 - Qt
        kind = event.type()
        if kind not in (QEvent.Type.ShortcutOverride, QEvent.Type.KeyPress):
            return False
        if not isinstance(obj, QWidget) or not (obj is self or self.isAncestorOf(obj)):
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
                "visualizer": self.visualizer.mode, "equalizer_open": self._eq_open}

    def save_state(self) -> None:
        """Write the playlist, the current track and position, volume, mute,
        shuffle, repeat, the visualization and whether the equalizer is
        open to the private state file."""
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

    def shutdown(self) -> None:
        """The extension unloads (or the window closes): save, then stop."""
        self._shut_down = True  # a probe answering later builds no engine
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

    def closeEvent(self, event) -> None:  # noqa: N802 - Qt
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
    panel = PlayerPanel(state_path=str(state_file()),
                        run_in_background=lambda work, done, error: api.run_in_background(
                            work, on_done=done, on_error=error))
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
