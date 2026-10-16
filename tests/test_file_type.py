"""Identify File Type: the real type of a file from its content.

``core.file_type`` sniffs a bounded prefix (magic bytes) instead of
trusting the name, says what the extension claims and whether the two
disagree, and reports size, text encoding and line endings. It reads
through the backend's ``open_read`` on a helper thread with a deadline, so
a dead remote produces a "timed out" row instead of a hang.
"""

from __future__ import annotations

import io
import os
import shutil
import subprocess
import sys
import threading
import time
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import file_type as FT  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from core.ram_fs import RamFsSession  # noqa: E402

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\rIHDR" + b"\x00" * 64
JPEG = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00" + b"\x00" * 64
ELF = b"\x7fELF\x02\x01\x01" + b"\x00" * 120
GZIP = b"\x1f\x8b\x08\x00" + b"\x00" * 40


def _zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types/>")
        zf.writestr("word/document.xml", "<w:document/>")
    return buf.getvalue()


class _HangingBackend:
    """open_read blocks until released: a remote that stopped answering."""

    def __init__(self) -> None:
        self.release = threading.Event()
        self.opened = threading.Event()

    def stat(self, path):
        from models.file_item import FileItem

        return FileItem(name=os.path.basename(path), size=10)

    def open_read(self, path):
        self.opened.set()
        self.release.wait(30)
        raise OSError("connection reset")


class _FailingBackend:
    def stat(self, path):
        from models.file_item import FileItem

        return FileItem(name=os.path.basename(path), size=10)

    def open_read(self, path):
        raise PermissionError(13, "Permission denied", path)


class _CountingRam(RamFsSession):
    """RamFS that records how many bytes a caller pulled out of a file."""

    def __init__(self) -> None:
        super().__init__()
        self.bytes_read = 0

    def open_read(self, path, mode="rb"):
        inner = super().open_read(path, mode)
        owner = self

        class _Handle:
            def read(self, n=-1):
                data = inner.read(n)
                owner.bytes_read += len(data)
                return data

            def close(self):
                inner.close()

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                self.close()

        return _Handle()


# --------------------------------------------------------------------------
# happy path
# --------------------------------------------------------------------------


def test_happy_png_named_png_is_a_match():
    info = FT.identify_bytes(PNG, "photo.png")
    assert info.mime == "image/png"
    assert "PNG" in info.description
    assert info.extension == ".png"
    assert info.extension_mime == "image/png"
    assert info.verdict == FT.MATCH
    assert not info.mismatch
    assert info.encoding == "" and info.line_endings == ""


def test_happy_local_file_identified_by_content(tmp_path):
    p = tmp_path / "photo.png"
    p.write_bytes(PNG)
    info = FT.identify(LocalFS(), str(p), use_file_command=False)
    assert info.kind == FT.KIND_FILE
    assert info.mime == "image/png"
    assert info.size == len(PNG)
    assert info.bytes_read == len(PNG)
    assert info.error == ""


def test_happy_utf8_text_with_crlf(tmp_path):
    p = tmp_path / "notes.txt"
    p.write_bytes("Grüße\r\nzweite Zeile\r\n".encode())
    info = FT.identify(LocalFS(), str(p), use_file_command=False)
    assert info.mime == "text/plain"
    assert info.verdict == FT.MATCH
    assert info.encoding == "UTF-8"
    assert info.line_endings == "CRLF"


def test_happy_ascii_text_with_lf():
    info = FT.identify_bytes(b"one\ntwo\n", "a.txt")
    assert info.encoding == "ASCII"
    assert info.line_endings == "LF"


def test_happy_remote_backend_reads_only_a_bounded_prefix():
    ram = _CountingRam()
    with ram.open_write("/big.bin") as fh:
        fh.write(PNG + b"\x00" * (1024 * 1024))
    info = FT.identify(ram, "/big.bin", max_bytes=4096)
    assert info.mime == "image/png"
    assert info.size == len(PNG) + 1024 * 1024
    assert ram.bytes_read <= 4096
    assert info.bytes_read == 4096


def test_happy_docx_with_zip_content_is_not_a_mismatch():
    info = FT.identify_bytes(_zip_bytes(), "report.docx")
    assert info.verdict == FT.MATCH, info


def test_happy_tar_gz_with_gzip_content_is_not_a_mismatch():
    info = FT.identify_bytes(GZIP, "backup.tar.gz")
    assert info.mime in ("application/gzip", "application/x-gzip")
    assert info.verdict == FT.MATCH, info


def test_happy_summary_names_the_mismatch():
    info = FT.identify_bytes(PNG, "notes.txt", path="/x/notes.txt")
    text = info.summary()
    assert "notes.txt" in text and "image/png" in text and "MISMATCH" in text


# --------------------------------------------------------------------------
# sad path
# --------------------------------------------------------------------------


def test_sad_extension_mismatch_png_named_txt():
    info = FT.identify_bytes(PNG, "notes.txt")
    assert info.mime == "image/png"
    assert info.extension_mime == "text/plain"
    assert info.verdict == FT.MISMATCH
    assert info.mismatch


def test_sad_jpeg_named_png_is_a_mismatch():
    info = FT.identify_bytes(JPEG, "fake.png")
    assert info.mime == "image/jpeg"
    assert info.verdict == FT.MISMATCH


def test_sad_binary_garbage_named_txt_is_a_mismatch():
    info = FT.identify_bytes(bytes(range(256)) * 4, "readme.txt")
    assert info.mime == "application/octet-stream"
    assert info.verdict == FT.MISMATCH


def test_sad_missing_file_gives_an_error_row(tmp_path):
    info = FT.identify(LocalFS(), str(tmp_path / "gone.bin"), use_file_command=False)
    assert info.kind == FT.KIND_ERROR
    assert info.error
    assert info.mime == ""


def test_sad_backend_read_raises_gives_an_error_row():
    info = FT.identify(_FailingBackend(), "/secret.bin")
    assert info.kind == FT.KIND_ERROR
    assert "Permission denied" in info.error


def test_sad_backend_read_hangs_times_out_without_blocking():
    backend = _HangingBackend()
    try:
        started = time.monotonic()
        info = FT.identify(backend, "/stuck.bin", timeout=0.3)
        elapsed = time.monotonic() - started
    finally:
        backend.release.set()
    assert info.kind == FT.KIND_TIMEOUT
    assert "0.3" in info.error
    assert elapsed < 3.0


def test_sad_cancel_interrupts_a_hanging_read():
    backend = _HangingBackend()
    cancel = threading.Event()
    threading.Timer(0.2, cancel.set).start()
    try:
        started = time.monotonic()
        info = FT.identify(backend, "/stuck.bin", timeout=30, cancel=cancel)
        elapsed = time.monotonic() - started
    finally:
        backend.release.set()
    assert info.kind == FT.KIND_CANCELLED
    assert elapsed < 3.0


def test_sad_cancel_accepts_a_callable():
    info = FT.identify(RamFsSession(), "/whatever", cancel=lambda: True)
    assert info.kind == FT.KIND_CANCELLED


@pytest.mark.parametrize("kwargs", [{"max_bytes": 0}, {"max_bytes": -1}, {"timeout": 0}])
def test_sad_invalid_limits_are_refused(kwargs):
    with pytest.raises(ValueError):
        FT.identify(RamFsSession(), "/x", **kwargs)


def test_sad_read_prefix_raises_timeout_error():
    backend = _HangingBackend()
    try:
        with pytest.raises(TimeoutError):
            FT.read_prefix(backend, "/stuck", timeout=0.2)
    finally:
        backend.release.set()


# --------------------------------------------------------------------------
# edge cases
# --------------------------------------------------------------------------


def test_edge_empty_file(tmp_path):
    p = tmp_path / "empty.txt"
    p.write_bytes(b"")
    info = FT.identify(LocalFS(), str(p), use_file_command=False)
    assert info.kind == FT.KIND_FILE
    assert info.size == 0
    assert info.mime == "application/x-zerosize"
    assert "empty" in info.description.lower()
    assert info.verdict == FT.UNKNOWN


def test_edge_directory_gives_a_clear_row(tmp_path):
    info = FT.identify(LocalFS(), str(tmp_path))
    assert info.kind == FT.KIND_DIRECTORY
    assert info.mime == "inode/directory"
    assert info.error == ""


def test_edge_remote_directory_gives_a_clear_row():
    ram = RamFsSession()
    ram.mkdir("/sub")
    info = FT.identify(ram, "/sub")
    assert info.kind == FT.KIND_DIRECTORY


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs FIFOs")
def test_edge_fifo_is_not_read(tmp_path):
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    started = time.monotonic()
    info = FT.identify(LocalFS(), str(fifo), timeout=5)
    assert time.monotonic() - started < 2.0
    assert info.kind == FT.KIND_SPECIAL
    assert "FIFO" in info.description


def test_edge_no_extension_claims_nothing():
    info = FT.identify_bytes(ELF, "program")
    assert info.mime == "application/x-executable"
    assert info.extension == ""
    assert info.extension_mime == ""
    assert info.verdict == FT.UNKNOWN


def test_edge_dotfile_has_no_extension():
    info = FT.identify_bytes(b"alias ll='ls -l'\n", ".bashrc")
    assert info.extension == ""
    assert info.verdict == FT.UNKNOWN


def test_edge_text_family_is_not_a_mismatch():
    # JSON detected as text/plain, a shell script in a .txt: text is text.
    assert FT.identify_bytes(b'{"a": 1}\n', "data.json").verdict == FT.MATCH
    assert FT.identify_bytes(b"#!/bin/sh\necho hi\n", "run.txt").verdict == FT.MATCH


def test_edge_utf16_with_bom():
    info = FT.identify_bytes(b"\xff\xfe" + "hi\r\nyou\r\n".encode("utf-16-le"), "a.txt")
    assert info.encoding == "UTF-16 LE (BOM)"
    assert info.line_endings == "CRLF"


def test_edge_utf8_bom():
    info = FT.identify_bytes(b"\xef\xbb\xbfhello\n", "a.txt")
    assert info.encoding == "UTF-8 (BOM)"


def test_edge_latin1_text_is_not_utf8():
    info = FT.identify_bytes("café crème\nnaïve\n".encode("latin-1") * 20, "a.txt")
    assert info.encoding not in ("", "UTF-8", "ASCII")
    assert info.line_endings == "LF"


def test_edge_prefix_cut_inside_a_multibyte_character_is_still_utf8():
    data = ("ä" * 3000).encode()  # 6000 bytes
    info = FT.identify_bytes(data[:4095], "a.txt", size=len(data))
    assert info.encoding == "UTF-8"


def test_edge_mixed_line_endings():
    info = FT.identify_bytes(b"a\nb\r\nc\rd\n", "a.txt")
    assert info.line_endings.startswith("mixed")
    assert "LF 2" in info.line_endings and "CRLF 1" in info.line_endings


def test_edge_text_without_line_breaks():
    assert FT.identify_bytes(b"one line", "a.txt").line_endings == "none"


def test_edge_without_qt_the_fallback_engines_still_identify(monkeypatch):
    monkeypatch.setattr(FT, "_mime_db", lambda: None)
    info = FT.identify_bytes(PNG, "notes.txt")
    assert info.mime == "image/png"
    assert info.verdict == FT.MISMATCH
    assert info.engine != "Qt"


def test_edge_signature_table_alone_identifies_png(monkeypatch):
    monkeypatch.setattr(FT, "_mime_db", lambda: None)
    monkeypatch.setattr(FT, "_puremagic_mime", lambda data: "")
    info = FT.identify_bytes(PNG, "x.png")
    assert info.mime == "image/png"
    assert info.engine == "signature table"
    assert info.verdict == FT.MATCH
    text = FT.identify_bytes(b"hello\n", "x.txt")
    assert text.mime == "text/plain" and text.verdict == FT.MATCH


def test_edge_file_pane_binary_magic_keeps_every_old_signature():
    from ui.file_pane import FilePaneWidget

    old = {
        (0, b"\x89PNG"), (0, b"\xff\xd8\xff"), (0, b"GIF8"), (0, b"PK\x03\x04"),
        (0, b"\x1f\x8b"), (0, b"BZ"), (0, b"\xfd7zXZ"), (0, b"\x7fELF"), (0, b"MZ"),
        (0, b"\xca\xfe\xba\xbe"), (0, b"%PDF"), (0, b"SQLite"), (0, b"\x00asm"),
        (0, b"RIFF"), (0, b"\xff\xfb"), (0, b"ID3"), (0, b"fLaC"), (0, b"OggS"),
        (0, b"\x1a\x45\xdf\xa3"),
    }
    assert old <= set(FilePaneWidget._BINARY_MAGIC)


# --------------------------------------------------------------------------
# file(1): an optional extra, never a dependency
# --------------------------------------------------------------------------


def test_file_command_uses_an_argument_list_with_double_dash(tmp_path, monkeypatch):
    p = tmp_path / "-rf odd 'name'.png"
    p.write_bytes(PNG)
    calls = []

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0, stdout=b"PNG image data, 1 x 1\n", stderr=b"")

    monkeypatch.setattr(FT.shutil, "which", lambda name: "/usr/bin/file")
    monkeypatch.setattr(FT.subprocess, "run", fake_run)
    info = FT.identify(LocalFS(), str(p))
    assert info.file_command == "PNG image data, 1 x 1"
    argv, kwargs = calls[0]
    assert argv[0] == "/usr/bin/file"
    assert argv[-2:] == ["--", str(p)]
    assert not kwargs.get("shell")
    assert kwargs.get("timeout")


def test_file_command_missing_does_not_change_the_result(tmp_path, monkeypatch):
    p = tmp_path / "a.png"
    p.write_bytes(PNG)
    monkeypatch.setattr(FT.shutil, "which", lambda name: None)
    info = FT.identify(LocalFS(), str(p))
    assert info.file_command == ""
    assert info.mime == "image/png" and info.verdict == FT.MATCH


def test_file_command_timeout_does_not_change_the_result(tmp_path, monkeypatch):
    p = tmp_path / "a.png"
    p.write_bytes(PNG)

    def slow_run(argv, **kwargs):
        raise subprocess.TimeoutExpired(argv, kwargs.get("timeout"))

    monkeypatch.setattr(FT.shutil, "which", lambda name: "/usr/bin/file")
    monkeypatch.setattr(FT.subprocess, "run", slow_run)
    info = FT.identify(LocalFS(), str(p))
    assert info.file_command == ""
    assert info.mime == "image/png"


def test_file_command_is_never_used_for_remote_backends(monkeypatch):
    monkeypatch.setattr(FT.shutil, "which", lambda name: "/usr/bin/file")

    def boom(*a, **k):
        raise AssertionError("file(1) must not run for a remote backend")

    monkeypatch.setattr(FT.subprocess, "run", boom)
    ram = RamFsSession()
    with ram.open_write("/a.png") as fh:
        fh.write(PNG)
    assert FT.identify(ram, "/a.png").mime == "image/png"


@pytest.mark.skipif(shutil.which("file") is None, reason="no file(1) installed")
def test_file_command_real_binary_adds_a_description(tmp_path):
    p = tmp_path / "a.png"
    p.write_bytes(PNG)
    info = FT.identify(LocalFS(), str(p))
    assert "PNG" in info.file_command


# --------------------------------------------------------------------------
# scripting API
# --------------------------------------------------------------------------


def test_scripting_file_type_on_a_local_path_string(tmp_path):
    import axross

    p = tmp_path / "a.txt"
    p.write_bytes(PNG)
    info = axross.file_type(str(p))
    assert info.mime == "image/png" and info.mismatch


def test_scripting_file_type_on_a_backend():
    import axross

    ram = axross.ramfs()
    axross.write_bytes(ram, "/doc.txt", b"plain words\n")
    info = axross.file_type(ram, "/doc.txt")
    assert info.verdict == FT.MATCH
    assert info.encoding == "ASCII"


def test_scripting_file_type_requires_a_path_with_a_backend():
    import axross

    with pytest.raises(TypeError):
        axross.file_type(axross.ramfs())


def test_scripting_file_type_is_public_grouped_and_documented():
    from core import scripting as s

    assert "file_type" in s.__all__
    assert any("file_type" in names for _g, names in s._HELP_GROUPS)
    assert "axross.file_type" in s.docs("file_type")
    reference = Path(__file__).resolve().parent.parent / "docs" / "SCRIPTING_REFERENCE.md"
    assert "axross.file_type(" in reference.read_text(encoding="utf-8")


def test_edge_module_never_builds_a_shell_command():
    source = Path(FT.__file__).read_text(encoding="utf-8")
    assert "shell=True" not in source
    assert "os.system" not in source
