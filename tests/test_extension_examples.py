"""The bundled example extensions: their logic, and that each one loads and
registers what it promises."""

from __future__ import annotations

import hashlib
import importlib.util
import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtGui import QColor, QImage  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import extensions as EX  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

APP = QApplication.instance() or QApplication([])
FS = LocalFS()


def load(name: str):
    path = EX.bundled_dir() / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"example_{name}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def pump(seconds: float = 0.05) -> None:
    end = time.time() + seconds
    while time.time() < end:
        APP.processEvents()
        time.sleep(0.01)


@pytest.fixture(autouse=True)
def own_home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))


# --- checksum manifest -------------------------------------------------------


def test_happy_manifest_matches_sha256sum_and_verifies(tmp_path) -> None:
    CM = load("checksum_manifest")
    (tmp_path / "b.txt").write_bytes(b"bee")
    (tmp_path / "a.bin").write_bytes(b"\x00" * 3_000_000)
    text = CM.manifest_text(FS, str(tmp_path), ["b.txt", "a.bin"])
    expected = (
        f"{hashlib.sha256(b'\x00' * 3_000_000).hexdigest()}  a.bin\n"
        f"{hashlib.sha256(b'bee').hexdigest()}  b.txt\n"
    )
    assert text == expected
    assert CM.verify(FS, str(tmp_path), text) == {
        "ok": ["a.bin", "b.txt"],
        "failed": [],
        "missing": [],
    }


def test_sad_verify_names_changed_and_missing_files(tmp_path) -> None:
    CM = load("checksum_manifest")
    (tmp_path / "a.txt").write_text("one")
    (tmp_path / "b.txt").write_text("two")
    text = CM.manifest_text(FS, str(tmp_path), ["a.txt", "b.txt"])
    (tmp_path / "a.txt").write_text("changed")
    (tmp_path / "b.txt").unlink()
    result = CM.verify(FS, str(tmp_path), text)
    assert result == {"ok": [], "failed": ["a.txt"], "missing": ["b.txt"]}


def test_edge_manifest_lines_that_leave_the_folder_are_ignored() -> None:
    CM = load("checksum_manifest")
    good = "a" * 64
    text = "\n".join(
        [
            f"{good}  ok.txt",
            f"{good}  ../../etc/passwd",
            f"{good}  /etc/shadow",
            f"{good} *binary.bin",
            "zz" * 32 + "  nothex.txt",
            "garbage",
            f"{good}  " + "x" * 5000,
        ]
    )
    assert CM.parse_manifest(text) == [(good, "ok.txt"), (good, "binary.bin")]


# --- entropy heatmap ---------------------------------------------------------


def test_happy_entropy_tells_random_from_text(tmp_path) -> None:
    EH = load("entropy_heatmap")
    assert EH.entropy(b"") == 0.0
    assert EH.entropy(b"aaaa") == 0.0
    assert EH.entropy(bytes(range(256))) == pytest.approx(8.0)
    (tmp_path / "rand.bin").write_bytes(os.urandom(64 * 1024))
    values, more = EH.block_entropies(FS, str(tmp_path / "rand.bin"))
    assert len(values) == 16 and not more
    assert min(values) > 7.5
    assert EH.verdict(values) == "looks compressed or encrypted throughout"


def test_edge_entropy_stops_at_the_limit_and_says_so(tmp_path) -> None:
    EH = load("entropy_heatmap")
    (tmp_path / "big.txt").write_bytes(b"hello world " * 2000)
    values, more = EH.block_entropies(FS, str(tmp_path / "big.txt"), block=1024, limit=4096)
    assert len(values) == 4 and more
    assert EH.verdict(values) == "low entropy: text, tables or padding"
    assert EH.verdict([]) == "empty file"
    image = EH.heat_image([0.0, 8.0], width=10, height=4)
    assert image.pixelColor(0, 0).blue() > image.pixelColor(0, 0).red()
    assert image.pixelColor(9, 0).red() > image.pixelColor(9, 0).blue()


# --- treemap -----------------------------------------------------------------


def test_happy_squarify_fills_the_box_exactly() -> None:
    FT = load("folder_treemap")
    sizes = [500, 300, 120, 50, 20, 10]
    rects = FT.squarify(sizes, 0, 0, 400, 300)
    assert len(rects) == len(sizes)
    assert sum(w * h for _x, _y, w, h in rects) == pytest.approx(400 * 300)
    for (x, y, w, h), size in zip(rects, sizes):
        assert x >= -1e-6 and y >= -1e-6 and x + w <= 400 + 1e-6 and y + h <= 300 + 1e-6
        assert w * h == pytest.approx(size / sum(sizes) * 400 * 300)
    assert FT.squarify([], 0, 0, 100, 100) == []
    assert FT.squarify([0, 0], 0, 0, 100, 100) == []


def test_happy_folder_sizes_sum_subfolders(tmp_path) -> None:
    FT = load("folder_treemap")
    (tmp_path / "sub" / "deep").mkdir(parents=True)
    (tmp_path / "sub" / "x").write_bytes(b"1" * 100)
    (tmp_path / "sub" / "deep" / "y").write_bytes(b"1" * 50)
    (tmp_path / "top.bin").write_bytes(b"1" * 7)
    entries, complete = FT.folder_sizes(FS, str(tmp_path))
    assert sorted(entries) == [("sub", 150, True), ("top.bin", 7, False)]
    assert complete


def test_edge_folder_sizes_stop_at_the_budget(tmp_path) -> None:
    FT = load("folder_treemap")
    sub = tmp_path / "many"
    sub.mkdir()
    for i in range(30):
        (sub / f"f{i}").write_bytes(b"x")
    entries, complete = FT.folder_sizes(FS, str(tmp_path), max_entries=10)
    assert not complete
    assert entries[0][0] == "many" and entries[0][1] <= 10
    assert FT.human(512) == "512 B" and FT.human(1536) == "1.5 KiB"


# --- image batch ---------------------------------------------------------------


def _png(path: Path, w: int, h: int) -> Path:
    image = QImage(w, h, QImage.Format.Format_RGB32)
    image.fill(QColor("green"))
    image.save(str(path), "PNG")
    return path


def test_happy_batch_scales_down_and_converts_into_resized(tmp_path) -> None:
    IB = load("image_batch")
    _png(tmp_path / "big.png", 800, 400)
    _png(tmp_path / "small.png", 100, 50)
    written, skipped = IB.run_batch(FS, str(tmp_path), ["big.png", "small.png"], 200, "JPEG")
    assert written == ["big.jpg", "small.jpg"] and skipped == []
    big = QImage(str(tmp_path / "resized" / "big.jpg"))
    small = QImage(str(tmp_path / "resized" / "small.jpg"))
    assert (big.width(), big.height()) == (200, 100)
    assert (small.width(), small.height()) == (100, 50)  # never scaled up
    assert (tmp_path / "big.png").exists()  # the original stays


def test_sad_batch_skips_what_is_not_an_image_and_never_overwrites(tmp_path) -> None:
    IB = load("image_batch")
    _png(tmp_path / "a.png", 50, 50)
    (tmp_path / "fake.png").write_bytes(b"not an image")
    (tmp_path / "resized").mkdir()
    (tmp_path / "resized" / "a.png").write_bytes(b"keep me")
    written, skipped = IB.run_batch(FS, str(tmp_path), ["a.png", "fake.png"], 0, "PNG")
    assert written == ["a (2).png"]
    assert len(skipped) == 1 and skipped[0].startswith("fake.png")
    assert (tmp_path / "resized" / "a.png").read_bytes() == b"keep me"
    with pytest.raises(ValueError):
        IB.convert(b"", 10, "TIFF")


# --- markdown preview ------------------------------------------------------------


def test_edge_markdown_is_read_bounded(tmp_path) -> None:
    MP = load("markdown_preview")
    (tmp_path / "a.md").write_bytes(b"# Title\n" + b"x" * 100 + b"\xff")
    text, cut = MP.read_markdown(FS, str(tmp_path / "a.md"), limit=50)
    assert cut and len(text) == 50 and text.startswith("# Title")
    text, cut = MP.read_markdown(FS, str(tmp_path / "a.md"))
    assert not cut and text.endswith("�")


# --- all of them in a window ------------------------------------------------------


def test_happy_every_bundled_example_loads_and_registers(tmp_path) -> None:
    from ui.main_window import MainWindow

    bundled = [e for e in EX.discover() if e.source == "bundled"]
    assert {e.module_name for e in bundled} >= {
        "checksum_manifest",
        "entropy_heatmap",
        "folder_treemap",
        "image_batch",
        "markdown_preview",
    }
    for info in bundled:
        EX.set_enabled(info.ext_id, True)
    win = MainWindow()
    try:
        win._reconnect_timer.stop()
        host = win.extension_host
        pump(0.3)
        for info in bundled:
            assert host.module(info.ext_id) is not None, (info.ext_id, host.error(info.ext_id))
            assert host.error(info.ext_id) == ""
        assert [d.windowTitle() for d in host.docks("bundled:folder_treemap")] == ["Folder Treemap"]
        folder = tmp_path / "pics"
        folder.mkdir()
        _png(folder / "p.png", 20, 20)
        (folder / "SHA256SUMS").write_text("")
        pane = win._active_pane
        pane.navigate(str(folder))
        pane._table.selectAll()
        labels = [a.text() for a in pane._build_context_menu().actions()]
        assert "Resize / Convert Images…" not in labels  # SHA256SUMS is no image
        assert "Create SHA256SUMS" in labels
    finally:
        win.close()
        win.deleteLater()
        pump()
