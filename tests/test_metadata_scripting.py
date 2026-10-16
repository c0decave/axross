"""The metadata verbs of the scripting API: axross.metadata,
axross.remove_metadata and axross.export_metadata."""

from __future__ import annotations

import csv
import io
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import axross  # noqa: E402
from core import open_limits as OL  # noqa: E402
from tests import metadata_testkit as K  # noqa: E402


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(OL, "SETTINGS_PATH", tmp_path / "settings.json")
    monkeypatch.setenv("AXROSS_OPERATION_JOURNAL", str(tmp_path / "ops.jsonl"))


def _tree(root: Path) -> Path:
    K.write(root / "a.jpg", K.jpeg_bytes())
    K.write(root / "sub" / "b.docx", K.docx_bytes())
    return root


def test_happy_metadata_report(tmp_path):
    f = K.write(tmp_path / "a.jpg", K.jpeg_bytes())
    report = axross.metadata(axross.localfs(), str(f))
    assert report.kind == "image" and report.removable > 0


def test_sad_metadata_of_a_folder_points_to_export(tmp_path):
    with pytest.raises(IsADirectoryError, match="export_metadata"):
        axross.metadata(axross.localfs(), str(tmp_path))


def test_happy_remove_metadata_file_and_folder(tmp_path):
    root = _tree(tmp_path / "t")
    b = axross.localfs()
    one = axross.remove_metadata(b, str(root / "a.jpg"), mode="copy")
    assert [r.status for r in one] == ["cleaned"]
    assert (root / "a.clean.jpg").exists()
    flat = axross.remove_metadata(b, str(root))
    assert {Path(r.path).name: r.status for r in flat} == {
        "a.clean.jpg": "unchanged", "a.jpg": "cleaned"}
    deep = axross.remove_metadata(b, str(root), recursive=True)
    assert "b.docx" in {Path(r.path).name for r in deep if r.status == "cleaned"}
    assert K.MARK not in K.plain(root / "sub" / "b.docx")


def test_sad_remove_metadata_bad_mode_and_missing_path(tmp_path):
    b = axross.localfs()
    f = K.write(tmp_path / "a.jpg", K.jpeg_bytes())
    with pytest.raises(ValueError):
        axross.remove_metadata(b, str(f), mode="wipe")
    with pytest.raises(FileNotFoundError):
        axross.remove_metadata(b, str(tmp_path / "missing.jpg"))


def test_happy_export_metadata_json_csv_and_out_file(tmp_path):
    root = _tree(tmp_path / "t")
    b = axross.localfs()
    doc = json.loads(axross.export_metadata(b, str(root), recursive=True))
    assert sorted(f["name"] for f in doc["files"]) == ["a.jpg", "b.docx"]
    out = tmp_path / "meta.csv"
    text = axross.export_metadata(b, str(root / "a.jpg"), fmt="csv", out=str(out))
    assert out.read_text(encoding="utf-8") == text
    rows = list(csv.reader(io.StringIO(text)))
    assert rows[0][0] == "path" and len(rows) > 2


def test_edge_export_metadata_refuses_to_overwrite_and_unknown_format(tmp_path):
    f = K.write(tmp_path / "a.jpg", K.jpeg_bytes())
    out = K.write(tmp_path / "exists.json", b"keep")
    with pytest.raises(FileExistsError):
        axross.export_metadata(axross.localfs(), str(f), out=str(out))
    assert out.read_bytes() == b"keep"
    with pytest.raises(ValueError):
        axross.export_metadata(axross.localfs(), str(f), fmt="xml")


def test_edge_remote_through_ramfs(tmp_path):
    ram = axross.ramfs()
    axross.write_bytes(ram, "/p.png", K.png_bytes())
    report = axross.metadata(ram, "/p.png")
    assert report.removable
    results = axross.remove_metadata(ram, "/p.png")
    assert results[0].status == "cleaned"
    assert K.MARK not in axross.read_bytes(ram, "/p.png")


def test_edge_names_are_public_and_grouped():
    from core import scripting as s

    for name in ("metadata", "remove_metadata", "export_metadata"):
        assert name in s.__all__
        assert any(name in names for _g, names in s._HELP_GROUPS)
        assert f"axross.{name}" in s.docs(name)
    reference = Path(__file__).resolve().parent.parent / "docs" / "SCRIPTING_REFERENCE.md"
    assert "axross.remove_metadata" in reference.read_text(encoding="utf-8")
