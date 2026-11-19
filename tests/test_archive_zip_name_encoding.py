"""ZIP names written without the UTF-8 flag read in the encoding they
were written in (the UTF-8 flag, then UTF-8 itself, then chardet over all
names, then cp437), as unzip and 7-Zip read them - on extract, in the
preview listing, and through the Unicode Path extra field."""
from __future__ import annotations

import os
import struct
import sys
import zipfile
import zlib

import pytest

from core import archive as AR


def _zip_with_raw_names(path, raw_names: list[bytes], extra: dict | None = None) -> None:
    """A ZIP whose member names are *raw_names* byte for byte, the UTF-8
    flag not set (zipfile itself sets it on every non-ASCII name)."""
    placeholders = [chr(ord("A") + i).encode() * len(r) for i, r in enumerate(raw_names)]
    with zipfile.ZipFile(path, "w") as zf:
        for i, ph in enumerate(placeholders):
            info = zipfile.ZipInfo(ph.decode())
            if extra and i in extra:
                info.extra = extra[i]
            zf.writestr(info, f"content {i}")
    data = open(path, "rb").read()
    for ph, raw in zip(placeholders, raw_names):
        assert len(ph) == len(raw) and data.count(ph) == 2
        data = data.replace(ph, raw)
    open(path, "wb").write(data)


def _extract_names(tmp_path, archive) -> set[str]:
    out = tmp_path / "out"
    AR.extract(str(archive), str(out))
    return {os.path.relpath(os.path.join(d, f), out) for d, _, fs in os.walk(out) for f in fs}


def test_utf8_names_without_the_flag(tmp_path):
    archive = tmp_path / "mac.zip"
    _zip_with_raw_names(archive, ["Grüße.txt".encode(), "Ordner/Café.txt".encode()])
    assert _extract_names(tmp_path, archive) == {"Grüße.txt", os.path.join("Ordner", "Café.txt")}
    assert {e.name for e in AR.list_archive(str(archive))} == {"Grüße.txt", "Ordner/Café.txt"}


@pytest.mark.parametrize("enc, names", [
    ("cp866", ["Отчёт за квартал.txt", "Приложение.doc"]),
    ("shift_jis", ["日本語のファイル.txt", "説明書.pdf"]),
])
def test_legacy_code_page_names_detected(tmp_path, enc, names):
    pytest.importorskip("chardet")
    archive = tmp_path / "legacy.zip"
    _zip_with_raw_names(archive, [n.encode(enc) for n in names])
    assert _extract_names(tmp_path, archive) == set(names)
    assert {e.name for e in AR.list_archive(str(archive))} == set(names)


def test_cp437_stays_without_a_detector(tmp_path, monkeypatch):
    archive = tmp_path / "dos.zip"
    _zip_with_raw_names(archive, ["Résumé.txt".encode("cp437")])
    monkeypatch.setitem(sys.modules, "chardet", None)
    assert _extract_names(tmp_path, archive) == {"Résumé.txt"}


def test_unicode_path_extra_field(tmp_path):
    raw = "Bericht ue.txt".encode("cp437")
    real = "Bericht ü.txt"
    body = b"\x01" + struct.pack("<I", zlib.crc32(raw)) + real.encode()
    field = struct.pack("<HH", 0x7075, len(body)) + body
    archive = tmp_path / "winzip.zip"
    _zip_with_raw_names(archive, [raw], extra={0: field})
    assert _extract_names(tmp_path, archive) == {real}


def test_unicode_path_with_a_wrong_crc_is_ignored(tmp_path):
    raw = b"plain.txt"
    body = b"\x01" + struct.pack("<I", 0) + "other.txt".encode()
    field = struct.pack("<HH", 0x7075, len(body)) + body
    archive = tmp_path / "stale.zip"
    _zip_with_raw_names(archive, [raw], extra={0: field})
    assert _extract_names(tmp_path, archive) == {"plain.txt"}


def test_unicode_path_cannot_escape(tmp_path):
    raw = b"inside.txt"
    body = b"\x01" + struct.pack("<I", zlib.crc32(raw)) + b"../outside.txt"
    field = struct.pack("<HH", 0x7075, len(body)) + body
    archive = tmp_path / "evil.zip"
    _zip_with_raw_names(archive, [raw], extra={0: field})
    out = tmp_path / "out"
    with pytest.raises(AR.UnsafeArchive):
        AR.extract(str(archive), str(out))
    assert not (tmp_path / "outside.txt").exists()
