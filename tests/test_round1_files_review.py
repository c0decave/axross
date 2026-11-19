"""Review round 1 (files, transfers, archives, metadata, trash, compare, pack,
checksum, duplicates): what a hostile or broken input did. Each test names
what was measured before its fix."""

from __future__ import annotations

import io
import os
import sys
import tarfile
import time
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import archive as AR  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402


def _tar(names: list[str]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name in names:
            info = tarfile.TarInfo(name)
            info.size = 1
            tf.addfile(info, io.BytesIO(b"x"))
    return buf.getvalue()


def _zip(names: list[str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name in names:
            zf.writestr(name, b"x")
    return buf.getvalue()


SPOOFING = [
    "invoice\u202egpj.exe",      # right-to-left override: shows as "invoiceexe.jpg"
    "report\u2066.pdf\u2069.sh",  # isolate controls
    "evil\x1b[31mred.txt",        # a terminal escape
    "bell\x07.txt",
]


@pytest.mark.parametrize("name", SPOOFING)
@pytest.mark.parametrize("kind", ["tar", "zip"])
def test_sad_an_archive_member_with_a_spoofing_name_is_refused(tmp_path, kind, name):
    """Measured before: extracting made "invoice<RLO>gpj.exe" on disk - shown
    as "invoiceexe.jpg" by every other program - and names with terminal
    escapes; a transfer from a server skips such names (core.remote_name).
    Now the archive is refused as unsafe, nothing is left behind."""
    archive = tmp_path / f"a.{kind}"
    archive.write_bytes(_tar([name]) if kind == "tar" else _zip([name]))
    out = tmp_path / "out"
    with pytest.raises(AR.UnsafeArchive, match="control"):
        AR.extract(str(archive), str(out))
    assert not out.exists()
    with pytest.raises(AR.UnsafeArchive):
        AR.extract_members(str(archive), str(tmp_path / "out2"), [name])


def test_happy_ordinary_and_right_to_left_names_still_extract(tmp_path):
    names = ["notes.txt", "קובץ.txt", "ملف.txt", "日本語.txt", "tab\there.txt"]
    archive = tmp_path / "a.zip"
    archive.write_bytes(_zip(names))
    out = tmp_path / "out"
    AR.extract(str(archive), str(out))
    assert sorted(os.listdir(out)) == sorted(names)


# -- a pack that never finished leaves nothing that stays forever ---------------------

def test_sad_a_killed_pack_leaves_a_temp_file_the_folder_sweep_removes(tmp_path, monkeypatch):
    """Measured before: a pack killed half way (power cut, kill -9) left
    ".axross-pack-xxxx.tmp" - a full-size half archive - in the folder for
    good: nothing ever swept that name. Its temporary file now has the
    name of axross's other atomic writes (core.atomic_recovery), which the
    pane sweeps once it is an hour old."""
    from core import atomic_recovery
    from core import packer as PK

    (tmp_path / "a.txt").write_text("a" * 1000)
    seen: list[str] = []
    real_write_zip = PK._write_zip

    def killed(backend, entries, out, *args, **kwargs):
        real_write_zip(backend, entries, out, *args, **kwargs)
        seen.append(out.name)  # the open temp file the writer is handed
        raise KeyboardInterrupt  # stands for the process being killed

    monkeypatch.setattr(PK, "_write_zip", killed)
    monkeypatch.setattr(PK.os, "unlink", lambda *_a, **_k: None)  # a dead process cleans nothing
    with pytest.raises(KeyboardInterrupt):
        PK.pack(LocalFS(), str(tmp_path), ["a.txt"], "a", PK.PackOptions(fmt="zip"))
    left = [n for n in os.listdir(tmp_path) if n != "a.txt"]
    assert left and [os.path.basename(p) for p in seen] == left
    assert atomic_recovery.is_orphan_name(left[0]), left
    removed = atomic_recovery.sweep_orphans(LocalFS(), str(tmp_path),
                                            now_epoch=time.time() + 7200)
    assert removed == 1
    assert os.listdir(tmp_path) == ["a.txt"]


# -- an encrypted 7z says so, not a dump of its header --------------------------------

@pytest.mark.parametrize("names_encrypted", [False, True])
def test_sad_an_encrypted_7z_is_named_as_such(tmp_path, names_encrypted):
    """Measured before: axross packs 7z with a password, but opening such an
    archive in axross failed with "PasswordRequired ([{'method':
    b'\\x06\\xf1\\x07\\x01', 'numinstreams': 1, ...". It now says the archive
    is encrypted and that axross cannot open it, nothing left behind."""
    pytest.importorskip("py7zr")
    from core import packer as PK

    (tmp_path / "a.txt").write_text("secret")
    result = PK.pack(LocalFS(), str(tmp_path), ["a.txt"], "x", PK.PackOptions(
        fmt="7z", password="pw", encrypt_names=names_encrypted))
    out = tmp_path / "out"
    with pytest.raises(AR.ArchivePasswordRequired, match="encrypted with a password"):
        AR.extract(result.path, str(out))
    assert not out.exists()
    if names_encrypted:
        with pytest.raises(AR.ArchivePasswordRequired):
            AR.list_archive(result.path)
    else:
        assert [m.name for m in AR.list_archive(result.path)] == ["a.txt"]


def test_edge_a_pdf_listing_too_many_objects_is_not_read_as_empty(tmp_path, monkeypatch):
    """A PDF can list millions of objects; they are not looked at one by
    one (time), and the file is then not reported as having nothing."""
    pytest.importorskip("pypdf")
    from core import metadata_formats as MF

    path = tmp_path / "many.pdf"
    path.write_bytes(
        b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n"
        b"xref\n0 3\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n"
        b"trailer\n<< /Size 3 /Root 1 0 R >>\nstartxref\n107\n%%EOF\n")
    monkeypatch.setattr(MF, "MAX_PDF_WALK_OBJECTS", 1)
    fields, error, _ = MF.pdf_fields(str(path))
    assert not error, error
    assert any(f.name == "objects not checked" and f.removable for f in fields), fields
