"""Draw an SVG in a killable child process.

The gate in front of QtSvg (core.previews.svg_refusal) counts the elements
an SVG's references draw, not what each one costs: one path of 10,000
segments drawn 1000 times is 1000 elements, and its 61 KB kept a thumbnail
worker 13 s; filled, 23 KB ran past two minutes. QSvgRenderer.render()
cannot be interrupted, so the drawing runs in a child interpreter that the
parent kills after :data:`RENDER_SECONDS` (and that ends by itself at its
CPU limit, and with its parent: PR_SET_PDEATHSIG on Linux, a kill-on-close
job object on Windows).

The child is ``python -I -c`` :data:`_CHILD_SOURCE` (a frozen build answers
``--svg-worker``, main.py). It reads the SVG from stdin and writes the
picture as PNG to stdout; its exit status says what went wrong
(:data:`INVALID`, :data:`NO_MEMORY`). It sees this process's environment
(core.subprocess_env.worker_env), so it draws with the same Qt platform.
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys

from core.subprocess_env import worker_env

log = logging.getLogger(__name__)

#: Seconds one SVG may take to be drawn (the child's start included).
RENDER_SECONDS = 10.0
#: Address space of the child (bytes): Qt, the parsed SVG and the picture.
ADDRESS_SPACE_LIMIT = 4 * 1024**3
#: Exit statuses of the child.
INVALID, NO_MEMORY = 3, 4

_CHILD_SOURCE = r'''
import os, sys
_parent, _cpu, _space, _edge, _options = (int(a) for a in sys.argv[-5:])
if sys.platform.startswith("linux"):
    # End with the parent (PR_SET_PDEATHSIG = 1, SIGKILL = 9).
    import ctypes
    try:
        ctypes.CDLL(None, use_errno=True).prctl(1, 9, 0, 0, 0)
    except (OSError, AttributeError):
        pass
    if os.getppid() != _parent:
        sys.exit(1)
try:
    import resource
    for _name, _value in (("RLIMIT_CORE", 0), ("RLIMIT_CPU", _cpu), ("RLIMIT_AS", _space)):
        try:
            resource.setrlimit(getattr(resource, _name), (_value, _value))
        except (ValueError, OSError):
            pass
except ImportError:
    pass
data = sys.stdin.buffer.read()
from PyQt6.QtCore import QBuffer, QByteArray, QIODevice, QLibraryInfo, QRectF, Qt
from PyQt6.QtGui import QGuiApplication, QImage, QPainter
from PyQt6.QtSvg import QSvgRenderer
if b"text" in data.lower():
    # Text needs Qt's font database, which needs an application: on the
    # offscreen platform where Qt has it (no window, no display).
    try:
        _platforms = os.path.join(QLibraryInfo.path(QLibraryInfo.LibraryPath.PluginsPath), "platforms")
        if any("qoffscreen" in _name for _name in os.listdir(_platforms)):
            os.environ["QT_QPA_PLATFORM"] = "offscreen"
    except OSError:
        pass
    app = QGuiApplication(["axross-svg-worker"])
renderer = QSvgRenderer()
if _options >= 0:
    from PyQt6.QtSvg import QtSvg
    renderer.setOptions(QtSvg.Option(_options))
if not renderer.load(QByteArray(data)) or not renderer.isValid():
    sys.exit(3)
size = renderer.defaultSize()
w, h = (size.width(), size.height()) if not size.isEmpty() else (_edge, _edge)
scale = _edge / max(w, h)
out_w, out_h = max(1, round(w * scale)), max(1, round(h * scale))
image = QImage(out_w, out_h, QImage.Format.Format_ARGB32_Premultiplied)
if image.isNull():
    sys.exit(4)
image.fill(Qt.GlobalColor.transparent)
painter = QPainter(image)
renderer.render(painter, QRectF(0, 0, out_w, out_h))
painter.end()
out = QByteArray()
buffer = QBuffer(out)
buffer.open(QIODevice.OpenModeFlag.WriteOnly)
if not image.save(buffer, "PNG", 50):
    sys.exit(4)
sys.stdout.buffer.write(bytes(out))
sys.stdout.flush()
os._exit(0)
'''


class SvgTooSlow(Exception):
    """Drawing the SVG took longer than :data:`RENDER_SECONDS` (the child was killed)."""


class SvgFailed(Exception):
    """The child could not draw the SVG; ``str()`` says why."""


def cpu_seconds_for(seconds: float) -> int:
    """The child's CPU limit: the wall-clock bound with room to spare (the
    parent's timer normally ends it first)."""
    return int(seconds) * 2 + 5


def worker_argv(edge: int, options: int = -1, seconds: float = RENDER_SECONDS) -> list[str]:
    """The command that starts the drawing child. A frozen build has no
    ``python -c``: the binary itself answers ``--svg-worker`` (main.py).
    The last five arguments: this process's pid, the CPU seconds, the
    address-space limit, the picture's longer side, the QSvgRenderer
    options (-1: none)."""
    tail = [str(os.getpid()), str(cpu_seconds_for(seconds)), str(ADDRESS_SPACE_LIMIT),
            str(int(edge)), str(int(options))]
    if getattr(sys, "frozen", False):
        return [sys.executable, "--svg-worker", *tail]
    return [sys.executable, "-I", "-c", _CHILD_SOURCE, *tail]


def _child_main() -> int:
    """The frozen build's ``--svg-worker`` entry point."""
    exec(compile(_CHILD_SOURCE, "<svg-worker>", "exec"), {"__name__": "__svg_worker__"})
    return 0


def render_png(data: bytes, edge: int, options: int = -1, seconds: float | None = None) -> bytes:
    """*data* (an SVG that passed core.previews.svg_refusal) drawn with its
    longer side *edge* px, as PNG bytes. Raises :class:`SvgTooSlow` past
    *seconds* (:data:`RENDER_SECONDS`), :class:`SvgFailed` when it cannot
    be drawn."""
    seconds = RENDER_SECONDS if seconds is None else seconds
    kwargs = {}
    if os.name == "nt":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        proc = subprocess.Popen(worker_argv(edge, options, seconds), stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                env=worker_env(), **kwargs)
    except OSError as exc:
        raise SvgFailed(f"the SVG drawing process could not start: {exc}") from exc
    try:
        from core.regex_worker import _kill_with_parent_windows

        _kill_with_parent_windows(proc)
    except ImportError:  # an exported tool comes without the regex worker
        pass
    try:
        out, _ = proc.communicate(data, timeout=seconds)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        raise SvgTooSlow(f"drawing the SVG took longer than {seconds:g} s") from None
    except BaseException:
        proc.kill()
        proc.communicate()
        raise
    if proc.returncode == INVALID:
        raise SvgFailed("not a valid SVG")
    if proc.returncode == NO_MEMORY:
        raise SvgFailed("not enough memory to draw the SVG")
    if proc.returncode != 0 or not out:
        raise SvgFailed(f"the SVG drawing process failed (exit status {proc.returncode})")
    return out


__all__ = ["RENDER_SECONDS", "SvgFailed", "SvgTooSlow", "render_png", "worker_argv"]
