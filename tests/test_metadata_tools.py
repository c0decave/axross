"""The metadata tools on top of the formats: backends, write modes, the
directory walk, export, settings and capabilities (core.metadata_tools).

Write modes (operator decision): in place - atomic replace, the original
kept in the trash, one journal entry so Ctrl+Z restores it - or a cleaned
copy next to the original that never overwrites anything. Remote files go
through a bounded local copy and the backend's atomic write path.
"""

from __future__ import annotations

import csv
import io
import json
import os
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import metadata_formats as MF  # noqa: E402
from core import metadata_tools as MT  # noqa: E402
from core import open_limits as OL  # noqa: E402
from core import trash as T  # noqa: E402
from core import undo as U  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from core.operation_journal import read_recent  # noqa: E402
from core.ram_fs import RamFsSession  # noqa: E402
from tests import metadata_testkit as K  # noqa: E402


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(OL, "SETTINGS_PATH", tmp_path / "settings.json")
    monkeypatch.setenv("AXROSS_OPERATION_JOURNAL", str(tmp_path / "ops.jsonl"))
    # LocalFS keeps an in-place original in <home>/.axross-trash.
    (tmp_path / "home").mkdir()
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    from core import security_mode

    previous = security_mode.current_policy().name
    security_mode.set_policy("normal")
    yield
    security_mode.set_policy(previous)


def _metadata_events():
    return [e for e in read_recent() if e.get("operation") == "metadata_remove"]


def _undo_last(backend):
    plan = U.pick_undoable(U.undoable(read_recent()), {backend.name})
    assert plan is not None and plan.operation == "metadata_remove"
    U.apply_undo(plan, backend)
    U.record_undone(plan)
    return plan


def _ram_with(path: str, data: bytes) -> RamFsSession:
    ram = RamFsSession()
    parent = path.rsplit("/", 1)[0]
    if parent and parent != "/":
        ram.mkdir(parent)
    with ram.open_write(path) as fh:
        fh.write(data)
    return ram


def _ram_read(ram, path: str) -> bytes:
    with ram.open_read(path) as fh:
        return fh.read()


# ---------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------


def test_happy_read_a_local_image(tmp_path):
    f = K.write(tmp_path / "photo.jpg", K.jpeg_bytes())
    report = MT.read_metadata(LocalFS(), str(f))
    assert report.kind == MF.IMAGE and report.error == ""
    assert report.removable > 0
    assert report.size == f.stat().st_size
    assert any("SECRETSERIAL" in fld.value for fld in report.fields)


def test_happy_read_a_remote_office_file_through_a_bounded_copy(tmp_path):
    ram = _ram_with("/docs/report.docx", K.docx_bytes())
    report = MT.read_metadata(ram, "/docs/report.docx")
    assert report.kind == MF.OFFICE and report.error == ""
    assert any(f.value == "SECRETCREATOR" for f in report.fields)


def test_sad_read_unsupported_missing_and_corrupt(tmp_path):
    fs = LocalFS()
    txt = K.write(tmp_path / "notes.txt", b"hello")
    assert "not a supported" in MT.read_metadata(fs, str(txt)).error
    assert MT.read_metadata(fs, str(tmp_path / "missing.jpg")).error
    bad = K.write(tmp_path / "bad.jpg", b"\xff\xd8\xff\xe1\xff\xffgarbage")
    report = MT.read_metadata(fs, str(bad))
    assert report.error and report.kind == MF.IMAGE


def test_sad_remote_file_over_the_open_limit_is_not_copied(tmp_path, monkeypatch):
    monkeypatch.setattr(OL, "max_open_bytes", lambda: 1000)
    ram = _ram_with("/big.png", K.png_bytes() + b"\x00" * 5000)
    report = MT.read_metadata(ram, "/big.png")
    assert "too large" in report.error


def test_edge_read_does_not_follow_a_directory_or_fifo(tmp_path):
    fs = LocalFS()
    (tmp_path / "dir.jpg").mkdir()
    assert MT.read_metadata(fs, str(tmp_path / "dir.jpg")).error
    fifo = tmp_path / "pipe.jpg"
    os.mkfifo(fifo)
    assert "regular file" in MT.read_metadata(fs, str(fifo)).error


def test_edge_report_dict_round_trip(tmp_path):
    f = K.write(tmp_path / "a.png", K.png_bytes())
    d = MT.read_metadata(LocalFS(), str(f)).to_dict()
    assert d["kind"] == "image" and d["fields"] and {"group", "name", "value", "removable"} <= set(
        d["fields"][0]
    )
    json.dumps(d)


# ---------------------------------------------------------------------------
# Removing - in place
# ---------------------------------------------------------------------------


def test_edge_an_in_place_removal_trashes_into_the_test_home_only(tmp_path):
    """The kept original goes to <home>/.axross-trash; without its own HOME a
    test run filled the runner's real trash, and a later test that expects
    an empty recovery scan saw these entries."""
    fs = LocalFS()
    f = K.write(tmp_path / "photo.jpg", K.jpeg_bytes())
    result = MT.remove_metadata(fs, str(f), mode=MT.MODE_IN_PLACE)
    assert result.status == "cleaned", result.error
    assert Path(fs.home()).is_relative_to(tmp_path)
    assert (Path(fs.home()) / T.TRASH_DIRNAME / result.trash_id).exists()


def test_happy_in_place_keeps_the_original_and_ctrl_z_restores_it(tmp_path):
    fs = LocalFS()
    original = K.jpeg_bytes()
    f = K.write(tmp_path / "photo.jpg", original)
    result = MT.remove_metadata(fs, str(f), mode=MT.MODE_IN_PLACE)
    assert result.status == "cleaned", result.error
    assert result.output == str(f) and result.removed > 0
    cleaned = f.read_bytes()
    assert K.MARK not in cleaned and MF.pixels_equal(original, cleaned)
    kept = [e for e in T.list_trash(fs) if e.trash_id == result.trash_id]
    assert kept and kept[0].original_path == str(f)
    events = _metadata_events()
    assert [e["phase"] for e in events] == ["start", "finish"]
    _undo_last(fs)
    assert f.read_bytes() == original
    assert U.pick_undoable(U.undoable(read_recent()), {fs.name}) is None


def test_happy_in_place_on_a_remote_backend_and_undo(tmp_path):
    original = K.png_bytes()
    ram = _ram_with("/pics/a.png", original)
    result = MT.remove_metadata(ram, "/pics/a.png", mode=MT.MODE_IN_PLACE)
    assert result.status == "cleaned", result.error
    assert K.MARK not in _ram_read(ram, "/pics/a.png")
    assert ram.exists("/.axross-trash/" + result.trash_id)
    _undo_last(ram)
    assert _ram_read(ram, "/pics/a.png") == original


def test_happy_in_place_office_keeps_other_entries(tmp_path):
    fs = LocalFS()
    f = K.write(tmp_path / "report.docx", K.docx_bytes())
    assert K.MARK in K.plain(f)
    assert MT.remove_metadata(fs, str(f)).status == "cleaned"
    assert K.MARK not in K.plain(f)
    import zipfile

    with zipfile.ZipFile(f) as zf:
        assert zf.read("word/document.xml") == K.DOCUMENT_XML


def test_sad_remote_without_a_usable_trash_falls_back_to_a_copy(tmp_path):
    ram = _ram_with("/a.jpg", K.jpeg_bytes())
    real_mkdir = ram.mkdir

    def no_trash(path, *a, **kw):
        if path.endswith(".axross-trash"):
            raise PermissionError("read-only area")
        return real_mkdir(path, *a, **kw)

    ram.mkdir = no_trash
    result = MT.remove_metadata(ram, "/a.jpg", mode=MT.MODE_IN_PLACE)
    assert result.status == "cleaned" and result.mode == MT.MODE_COPY
    assert "trash" in result.note
    assert result.output == "/a.clean.jpg"
    assert K.MARK in _ram_read(ram, "/a.jpg")
    assert K.MARK not in _ram_read(ram, "/a.clean.jpg")


def test_sad_corrupt_file_is_left_alone(tmp_path):
    data = bytearray(K.jpeg_bytes())
    pos = data.index(b"\xff\xe1")
    data[pos + 2 : pos + 4] = b"\xff\xff"
    f = K.write(tmp_path / "bad.jpg", bytes(data))
    result = MT.remove_metadata(LocalFS(), str(f))
    assert result.status == "error" and result.error
    assert f.read_bytes() == bytes(data)
    assert _metadata_events() == []


def test_sad_a_symlink_is_not_replaced(tmp_path):
    target = K.write(tmp_path / "real.jpg", K.jpeg_bytes())
    link = tmp_path / "link.jpg"
    link.symlink_to(target)
    result = MT.remove_metadata(LocalFS(), str(link))
    assert result.status == "error" and "symbolic link" in result.error
    assert link.is_symlink()


def test_sad_a_file_changed_while_being_cleaned_is_not_overwritten(tmp_path, monkeypatch):
    f = K.write(tmp_path / "photo.jpg", K.jpeg_bytes())
    real = MF.image_clean

    def clean_and_meanwhile_edit(data):
        out = real(data)
        with open(f, "ab") as fh:
            fh.write(b"appended by someone else")
        return out

    monkeypatch.setattr(MF, "image_clean", clean_and_meanwhile_edit)
    result = MT.remove_metadata(LocalFS(), str(f))
    assert result.status == "error" and "changed" in result.error
    assert f.read_bytes().endswith(b"appended by someone else")


def test_sad_pdf_removal_without_pypdf_is_unsupported(tmp_path, monkeypatch):
    monkeypatch.setattr(MF, "have_pypdf", lambda: False)
    f = K.write(tmp_path / "doc.pdf", K.pdf_bytes())
    result = MT.remove_metadata(LocalFS(), str(f))
    assert result.status == "unsupported" and "pypdf" in result.error
    assert f.read_bytes() == K.pdf_bytes()


def test_edge_nothing_to_remove_is_unchanged_and_not_journaled(tmp_path):
    f = K.write(tmp_path / "bare.jpg", K.jpeg_bytes(everything=False))
    before = f.read_bytes()
    result = MT.remove_metadata(LocalFS(), str(f))
    assert result.status == "unchanged"
    assert f.read_bytes() == before
    assert _metadata_events() == []


def test_edge_in_place_keeps_the_file_mode(tmp_path):
    f = K.write(tmp_path / "photo.jpg", K.jpeg_bytes())
    os.chmod(f, 0o640)
    MT.remove_metadata(LocalFS(), str(f))
    assert f.stat().st_mode & 0o777 == 0o640


# ---------------------------------------------------------------------------
# Removing - cleaned copy
# ---------------------------------------------------------------------------


def test_happy_copy_mode_writes_name_clean_ext_and_never_overwrites(tmp_path):
    fs = LocalFS()
    original = K.jpeg_bytes()
    f = K.write(tmp_path / "photo.jpg", original)
    existing = K.write(tmp_path / "photo.clean.jpg", b"do not touch")
    r1 = MT.remove_metadata(fs, str(f), mode=MT.MODE_COPY)
    r2 = MT.remove_metadata(fs, str(f), mode=MT.MODE_COPY)
    assert r1.output == str(tmp_path / "photo.clean (1).jpg")
    assert r2.output == str(tmp_path / "photo.clean (2).jpg")
    assert f.read_bytes() == original
    assert existing.read_bytes() == b"do not touch"
    assert K.MARK not in Path(r1.output).read_bytes()
    _undo_last(fs)
    assert not Path(r2.output).exists() and Path(r1.output).exists()


def test_edge_clean_copy_names():
    assert MT.clean_copy_name("photo.jpg") == "photo.clean.jpg"
    assert MT.clean_copy_name("photo.jpg", 3) == "photo.clean (3).jpg"
    assert MT.clean_copy_name("archive.tar.gz") == "archive.tar.clean.gz"
    assert MT.clean_copy_name("README") == "README.clean"


def test_sad_unknown_mode_is_rejected(tmp_path):
    f = K.write(tmp_path / "photo.jpg", K.jpeg_bytes())
    with pytest.raises(ValueError):
        MT.remove_metadata(LocalFS(), str(f), mode="shred")


# ---------------------------------------------------------------------------
# Directories
# ---------------------------------------------------------------------------


def _tree(root: Path) -> Path:
    K.write(root / "a.jpg", K.jpeg_bytes())
    K.write(root / "b.png", K.png_bytes())
    K.write(root / "notes.txt", b"not metadata")
    K.write(root / "sub" / "c.docx", K.docx_bytes())
    K.write(root / "sub" / "deeper" / "d.webp", K.webp_bytes())
    (root / "sub" / "loop").symlink_to(root, target_is_directory=True)
    return root


def test_happy_scan_a_folder_recursively_with_progress(tmp_path):
    root = _tree(tmp_path / "tree")
    seen = []
    batch = MT.scan_metadata(LocalFS(), str(root), recursive=True,
                             progress=lambda d, t, p: seen.append((d, t, p)))
    names = sorted(r.name for r in batch.reports)
    assert names == ["a.jpg", "b.png", "c.docx", "d.webp"]
    assert all(r.error == "" and r.removable for r in batch.reports)
    assert seen and not batch.cancelled
    assert batch.scan.links_skipped == 1
    flat = MT.scan_metadata(LocalFS(), str(root))
    assert sorted(r.name for r in flat.reports) == ["a.jpg", "b.png"]


def test_happy_remove_a_whole_folder_is_one_undo(tmp_path):
    fs = LocalFS()
    root = _tree(tmp_path / "tree")
    before = {p: p.read_bytes() for p in root.rglob("*") if p.is_file() and not p.is_symlink()}
    batch = MT.remove_folder(fs, str(root), recursive=True)
    assert sorted(Path(r.path).name for r in batch.results if r.status == "cleaned") == [
        "a.jpg", "b.png", "c.docx", "d.webp"]
    assert batch.operation_id
    finishes = [e for e in _metadata_events() if e["phase"] == "finish"]
    assert len(finishes) == 1 and len(finishes[0]["details"]["items"]) == 4
    for p in before:
        assert K.MARK not in K.plain(p) or p.name == "notes.txt", p
    _undo_last(fs)
    for p, data in before.items():
        assert p.read_bytes() == data, p


def test_sad_cancel_stops_a_folder_walk_and_a_removal(tmp_path):
    root = _tree(tmp_path / "tree")
    cancel = threading.Event()
    cancel.set()
    scan = MT.scan_metadata(LocalFS(), str(root), recursive=True, cancel=cancel)
    assert scan.cancelled and scan.reports == []
    calls = []

    def stop_after_first(done, total, path):
        calls.append(path)
        cancel_after.set()

    cancel_after = threading.Event()
    batch = MT.remove_many(LocalFS(), [str(root / "a.jpg"), str(root / "b.png")],
                           cancel=cancel_after, progress=stop_after_first)
    assert batch.cancelled
    assert [r.status for r in batch.results] == ["cleaned"]
    assert K.MARK in (root / "b.png").read_bytes()


def test_edge_remove_many_with_nothing_to_do_writes_no_journal(tmp_path):
    f = K.write(tmp_path / "bare.jpg", K.jpeg_bytes(everything=False))
    batch = MT.remove_many(LocalFS(), [str(f), str(tmp_path / "x.txt")])
    assert [r.status for r in batch.results] == ["unchanged", "unsupported"]
    assert batch.operation_id == "" and _metadata_events() == []


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------


def test_happy_export_json_and_csv(tmp_path):
    root = _tree(tmp_path / "tree")
    reports = MT.scan_metadata(LocalFS(), str(root)).reports
    doc = json.loads(MT.export_reports(reports, "json"))
    assert [f["name"] for f in doc["files"]] == ["a.jpg", "b.png"]
    assert any(fld["value"] == "SECRETSERIAL" for fld in doc["files"][0]["fields"])
    rows = list(csv.reader(io.StringIO(MT.export_reports(reports, "csv"))))
    assert rows[0] == ["path", "kind", "group", "field", "value", "removable", "error"]
    assert any(r[4] == "SECRETSERIAL" for r in rows[1:])


def test_sad_export_unknown_format():
    with pytest.raises(ValueError):
        MT.export_reports([], "xml")


def test_edge_csv_export_neutralises_spreadsheet_formulas():
    report = MT.MetadataReport(
        path="/x.jpg", name="x.jpg", kind="image",
        fields=[MF.Field("EXIF", "Artist", '=HYPERLINK("http://evil","click")')],
    )
    rows = list(csv.reader(io.StringIO(MT.export_reports([report], "csv"))))
    assert rows[1][4].startswith("'=")
    empty = MT.MetadataReport(path="/y.jpg", name="y.jpg", kind="image", fields=[], error="bad")
    rows = list(csv.reader(io.StringIO(MT.export_reports([empty], "csv"))))
    assert rows[1][6] == "bad"


# ---------------------------------------------------------------------------
# Settings + capabilities
# ---------------------------------------------------------------------------


def test_happy_settings_default_and_persist(tmp_path):
    assert MT.write_mode() == MT.MODE_IN_PLACE
    assert MT.confirm_before_remove() is False
    MT.set_write_mode(MT.MODE_COPY)
    MT.set_confirm_before_remove(True)
    assert MT.write_mode() == MT.MODE_COPY and MT.confirm_before_remove() is True
    data = json.loads((tmp_path / "settings.json").read_text())
    assert data["metadata_write_mode"] == "copy" and data["metadata_confirm_remove"] is True
    OL.set_max_open_mb(64)  # the shared store keeps both
    assert MT.write_mode() == MT.MODE_COPY


def test_sad_bad_settings_values(tmp_path):
    with pytest.raises(ValueError):
        MT.set_write_mode("shred")
    with pytest.raises(TypeError):
        MT.set_confirm_before_remove("yes")
    (tmp_path / "settings.json").write_text('{"metadata_write_mode": 5, '
                                            '"metadata_confirm_remove": "x"}')
    assert MT.write_mode() == MT.MODE_IN_PLACE and MT.confirm_before_remove() is False
    (tmp_path / "settings.json").write_text("not json")
    assert MT.write_mode() == MT.MODE_IN_PLACE


def test_happy_capabilities(monkeypatch):
    caps = MT.capabilities()
    assert caps[MF.IMAGE].read and caps[MF.IMAGE].remove
    assert caps[MF.OFFICE].read and caps[MF.OFFICE].remove
    monkeypatch.setattr(MF, "have_pypdf", lambda: False)
    caps = MT.capabilities()
    assert caps[MF.PDF].read and not caps[MF.PDF].remove and "pypdf" in caps[MF.PDF].reason


def test_sad_capabilities_without_ffmpeg_and_in_paranoid_mode(monkeypatch):
    from core import security_mode

    monkeypatch.setattr(MF, "ffprobe_path", lambda: None)
    monkeypatch.setattr(MF, "ffmpeg_path", lambda: None)
    caps = MT.capabilities()
    assert not caps[MF.VIDEO].read and "ffprobe" in caps[MF.VIDEO].reason
    monkeypatch.undo()
    security_mode.set_policy("paranoid")
    caps = MT.capabilities()
    assert not caps[MF.AUDIO].read and "paranoid" in caps[MF.AUDIO].reason
    assert caps[MF.IMAGE].read and caps[MF.IMAGE].remove


# ---------------------------------------------------------------------------
# Audio / video through the tools
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not K.have_ffmpeg(), reason="ffmpeg / ffprobe not installed")
def test_happy_video_in_place_with_a_dash_name_and_undo(tmp_path):
    fs = LocalFS()
    f = K.ffmpeg_make(tmp_path / "-clip.mp4", "mp4")
    original = f.read_bytes()
    result = MT.remove_metadata(fs, str(f))
    assert result.status == "cleaned", result.error
    assert K.MARK not in f.read_bytes()
    _undo_last(fs)
    assert f.read_bytes() == original
