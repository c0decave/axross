"""Pictures are decoded in a killable child process (core.image_worker).

Qt's image plugins and Pillow parse a picture in native code inside axross:
a crafted file that kept libjpeg, libpng or libtiff busy pinned the image
viewer's, the media viewer's or the thumbnails' thread for good, and one
that crashed a decoder took the whole program down. Now a pooled child
decodes, the parent kills it past its bound, and the caller gets a
PreviewError that says why. A hostile picture is played by a child whose
QImageReader hangs, crashes or allocates without end - the decoders' own
failures cannot be summoned on demand.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtGui import QColor, QImage, QImageReader  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import image_worker as IW  # noqa: E402
from core import previews as P  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

APP = QApplication.instance() or QApplication([])

# A child whose QImageReader misbehaves when it reads.
_HOSTILE = r'''
import os, signal, time
import PyQt6.QtGui as _gui
_MODE = {mode!r}
class _Reader(_gui.QImageReader):
    def read(self, *args):
        if _MODE == "hang":
            time.sleep(1000)
        if _MODE == "spin":
            while True:
                pass
        if _MODE == "crash":
            os.kill(os.getpid(), signal.SIGSEGV)
        if _MODE == "hog":
            hog = bytearray(1536 * 1024 * 1024)
            hog[::4096] = b"x" * len(hog[::4096])
        return super().read(*args)
_gui.QImageReader = _Reader
'''


@pytest.fixture(autouse=True)
def _fresh_pool():
    IW.close_pool()
    yield
    IW.close_pool()


@pytest.fixture
def hostile(monkeypatch, tmp_path):
    """Make every decoding child misbehave as *mode* says."""

    def use(mode: str) -> None:
        script = tmp_path / f"hostile_{mode}.py"
        script.write_text(_HOSTILE.format(mode=mode) + IW._CHILD_SOURCE)
        real = IW.worker_argv

        def argv(*args, **kwargs):
            return [sys.executable, "-I", str(script), *real(*args, **kwargs)[-4:]]

        monkeypatch.setattr(IW, "worker_argv", argv)
        IW.close_pool()

    return use


def _png(path: Path, w: int = 64, h: int = 40, color: str = "#3366cc") -> Path:
    img = QImage(w, h, QImage.Format.Format_RGB32)
    img.fill(QColor(color))
    assert img.save(str(path), "PNG")
    return path


def _jpeg(path: Path, w: int = 120, h: int = 80) -> Path:
    img = QImage(w, h, QImage.Format.Format_RGB32)
    img.fill(QColor("#cc8844"))
    assert img.save(str(path), "JPEG", 90)
    return path


# -- happy -------------------------------------------------------------------------


def test_happy_the_viewer_decode_runs_in_another_process(monkeypatch, tmp_path):
    """QImageReader.read in axross itself is never reached."""
    pic = _png(tmp_path / "a.png", 64, 40, "#3366cc")

    def never(*_a):
        raise AssertionError("decoded inside axross")

    monkeypatch.setattr(QImageReader, "read", never)
    img = P.decode_image(LocalFS(), str(pic))
    assert (img.width(), img.height()) == (64, 40)
    assert QColor(img.pixel(10, 10)).name() == "#3366cc"
    assert IW.idle_pids() and os.getpid() not in IW.idle_pids()


def test_happy_a_thumbnail_runs_in_another_process(monkeypatch, tmp_path):
    pic = _jpeg(tmp_path / "a.jpg", 400, 200)

    def never(*_a):
        raise AssertionError("decoded inside axross")

    monkeypatch.setattr(QImageReader, "read", never)
    result = P.thumbnail(LocalFS(), str(pic), edge=100, use_cache=False)
    thumb = QImage.fromData(result.data, "PNG")
    assert (thumb.width(), thumb.height()) == (100, 50) == (result.width, result.height)


def test_happy_the_child_is_reused_for_the_next_picture(tmp_path):
    first = _png(tmp_path / "a.png")
    second = _png(tmp_path / "b.png", 30, 30, "#00ff00")
    P.decode_image(LocalFS(), str(first))
    pids = IW.idle_pids()
    started = time.monotonic()
    img = P.decode_image(LocalFS(), str(second))
    assert QColor(img.pixel(1, 1)).name() == "#00ff00"
    assert IW.idle_pids() == pids
    assert time.monotonic() - started < 5


def test_happy_pixels_alpha_and_grey_come_back_as_decoded(tmp_path):
    alpha = QImage(20, 10, QImage.Format.Format_ARGB32)
    alpha.fill(QColor(255, 0, 0, 128))
    alpha.save(str(tmp_path / "alpha.png"), "PNG")
    grey = QImage(16, 16, QImage.Format.Format_Grayscale8)
    grey.fill(77)
    grey.save(str(tmp_path / "grey.png"), "PNG")
    got = P.decode_image(LocalFS(), str(tmp_path / "alpha.png"))
    assert got.hasAlphaChannel() and QColor.fromRgba(got.pixel(3, 3)).alpha() in (127, 128)
    got = P.decode_image(LocalFS(), str(tmp_path / "grey.png"))
    assert got.format() == QImage.Format.Format_Grayscale8 and QColor(got.pixel(2, 2)).red() == 77


# -- sad -------------------------------------------------------------------------


def test_sad_a_picture_that_hangs_the_decoder_is_given_up_with_a_reason(hostile, monkeypatch,
                                                                         tmp_path):
    monkeypatch.setattr(IW, "DECODE_SECONDS", 2.0)
    hostile("hang")
    pic = _png(tmp_path / "a.png")
    started = time.monotonic()
    with pytest.raises(P.PreviewTooLarge) as caught:
        P.decode_image(LocalFS(), str(pic))
    assert time.monotonic() - started < 8
    assert "longer than 2 s" in str(caught.value)
    assert IW.idle_pids() == []


def test_sad_a_picture_that_spins_in_native_code_is_given_up(hostile, monkeypatch, tmp_path):
    """A decoder busy on the CPU (holding its own GIL) is killed all the same."""
    monkeypatch.setattr(IW, "DECODE_SECONDS", 2.0)
    hostile("spin")
    pic = _jpeg(tmp_path / "a.jpg")
    with pytest.raises(P.PreviewTooLarge):
        P.thumbnail(LocalFS(), str(pic), use_cache=False)


def test_sad_a_picture_that_crashes_the_decoder_leaves_axross_running(hostile, tmp_path):
    hostile("crash")
    pic = _png(tmp_path / "a.png")
    with pytest.raises(P.PreviewDecodeFailed) as caught:
        P.decode_image(LocalFS(), str(pic))
    assert "signal 11" in str(caught.value)


def test_sad_a_decoder_that_allocates_without_end_hits_the_memory_cap(hostile, monkeypatch,
                                                                     tmp_path):
    if not sys.platform.startswith("linux"):
        pytest.skip("RLIMIT_DATA is the bound on Linux")
    monkeypatch.setattr(IW, "DATA_LIMIT", 1024 * 1024 * 1024)
    hostile("hog")
    pic = _png(tmp_path / "a.png")
    with pytest.raises((P.PreviewTooLarge, P.PreviewDecodeFailed)) as caught:
        P.decode_image(LocalFS(), str(pic))
    assert "memory" in str(caught.value) or "ended" in str(caught.value)


def test_sad_after_a_hostile_picture_the_next_one_decodes(hostile, monkeypatch, tmp_path):
    monkeypatch.setattr(IW, "DECODE_SECONDS", 2.0)
    real = IW.worker_argv
    hostile("hang")
    with pytest.raises(P.PreviewTooLarge):
        P.decode_image(LocalFS(), str(_png(tmp_path / "bad.png")))
    monkeypatch.setattr(IW, "worker_argv", real)
    img = P.decode_image(LocalFS(), str(_png(tmp_path / "good.png", 8, 8, "#ff00ff")))
    assert QColor(img.pixel(1, 1)).name() == "#ff00ff"


def test_sad_the_refusals_of_the_child_keep_their_kind(tmp_path):
    """A bomb, a PDF under a picture's name and an SVG under one are
    refused as before - the child says which refusal it was."""
    bomb = tmp_path / "bomb.png"
    import struct
    import zlib

    def chunk(kind: bytes, data: bytes) -> bytes:
        return (struct.pack(">I", len(data)) + kind + data
                + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF))

    bomb.write_bytes(b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 60000, 60000,
                                                                       8, 2, 0, 0, 0))
                     + chunk(b"IDAT", zlib.compress(b"\x00" * 100)) + chunk(b"IEND", b""))
    with pytest.raises(P.PreviewTooLarge):
        P.decode_image(LocalFS(), str(bomb))
    svg = tmp_path / "x.png"
    svg.write_text('<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10"/>')
    with pytest.raises(P.PreviewNotAvailable):
        P.thumbnail(LocalFS(), str(svg), use_cache=False)


# -- edge ------------------------------------------------------------------------


def test_edge_the_child_is_started_isolated_and_bounded(monkeypatch):
    argv = IW.worker_argv()
    assert argv[0] == sys.executable and argv[1:3] == ["-I", "-c"]
    assert argv[-3:] == [str(os.getpid()), str(IW.cpu_seconds_for(IW.DECODE_SECONDS)),
                         str(IW.DATA_LIMIT)]
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    assert IW.worker_argv() == [sys.executable, "--image-worker", *argv[-4:]]
    main_source = (Path(__file__).resolve().parent.parent / "main.py").read_text()
    assert '["--image-worker"]' in main_source
    assert "core.image_worker import _child_main" in main_source


def test_edge_a_stray_child_does_not_decode(tmp_path):
    """A child whose parent is not the program that started it ends."""
    if not sys.platform.startswith("linux"):
        pytest.skip("the parent check is Linux's")
    import subprocess

    command = IW.worker_argv()
    stranger = command[:-3] + ["1"] + command[-2:]
    result = subprocess.run(stranger, input=b"", capture_output=True, timeout=60)
    assert result.returncode == 1 and not result.stdout


def test_edge_the_pool_ends_idle_children(monkeypatch, tmp_path):
    P.decode_image(LocalFS(), str(_png(tmp_path / "a.png")))
    (pid,) = IW.idle_pids()
    monkeypatch.setattr(IW, "POOL_IDLE_SECONDS", 0.0)
    P.decode_image(LocalFS(), str(_png(tmp_path / "b.png")))
    assert IW.idle_pids() != [pid]


def test_edge_an_answer_for_a_picture_past_the_caps_is_refused_unallocated():
    """A child that answers a picture larger than the caps allow (only a
    child gone wrong does) gets no allocation of that size here."""

    class _Huge:
        def __len__(self):
            return 30000 * 4 * 30000

        def read_into(self, view, offset=0):
            raise AssertionError("read")

        def tail(self, offset):
            return b""

    head = {"w": 30000, "h": 30000, "stride": 120000, "format": QImage.Format.Format_RGB32.value,
            "icc": 0}
    with pytest.raises(P.PreviewDecodeFailed):
        P._unpack_qimage(head, _Huge(), "/x.png")
