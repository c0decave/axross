"""A pooled drawing or decoding child outlives the thread that started it.

The children of core.pdf_worker and core.image_worker ask Linux for
PR_SET_PDEATHSIG, so they end with axross. Linux sends that signal when the
*thread* that started the child ends, not the process: a child started by a
short-lived worker (ui.off_gui's thread for each picture the image viewer
opens, a thumbnail runner that was shut down) was killed with it, and the
next picture or PDF page through the pool failed with "ended (signal 9)".
"""

from __future__ import annotations

import os
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtGui import QColor, QImage  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import image_worker as IW  # noqa: E402
from core import media_load as ML  # noqa: E402
from core import pdf_worker as PW  # noqa: E402
from core import previews as P  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from tests.media_testkit import requires_qtpdf, write_pdf  # noqa: E402

APP = QApplication.instance() or QApplication([])

pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"),
                                reason="PR_SET_PDEATHSIG is Linux's")


def _in_a_thread(fn):
    out: dict = {}

    def run():
        try:
            out["value"] = fn()
        except BaseException as exc:  # noqa: BLE001 - raised below
            out["error"] = exc

    worker = threading.Thread(target=run)
    worker.start()
    worker.join(120)
    if "error" in out:
        raise out["error"]
    return out["value"]


@pytest.fixture(autouse=True)
def _fresh_pools():
    IW.close_pool()
    PW.close_pool()
    yield
    IW.close_pool()
    PW.close_pool()


def test_sad_a_picture_after_the_thread_of_the_first_has_ended(tmp_path):
    paths = []
    for i, color in enumerate(("#102030", "#405060")):
        img = QImage(32, 32, QImage.Format.Format_RGB32)
        img.fill(QColor(color))
        img.save(str(tmp_path / f"{i}.png"))
        paths.append(str(tmp_path / f"{i}.png"))
    _in_a_thread(lambda: P.decode_image(LocalFS(), paths[0]))
    got = _in_a_thread(lambda: P.decode_image(LocalFS(), paths[1]))
    assert QColor(got.pixel(1, 1)).name() == "#405060"


@requires_qtpdf
def test_sad_a_pdf_page_after_the_thread_of_the_first_has_ended(tmp_path):
    pdf = write_pdf(tmp_path / "d.pdf", pages=2)
    _in_a_thread(lambda: ML.render_pdf_page(str(pdf), 0, 100))
    image = _in_a_thread(lambda: ML.render_pdf_page(str(pdf), 1, 100))
    assert not image.isNull()
