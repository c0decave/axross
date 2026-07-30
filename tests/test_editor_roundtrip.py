#!/usr/bin/env python3
"""Which files the text editor can actually open and save again.

Reported from real use: opening a file and trying to write it back
failed with

    Error -3 while decompressing data: incorrect header check

on ``.xinitrc`` — a plain text file. That is a zlib error, which means
something on the path decided the bytes were compressed. Nothing in a
save should be decompressing anything, so this matrix walks the whole
round trip (detect → read → edit → atomic_write → read back) over the
kinds of file a user actually opens, and asserts the bytes survive.

Dotfiles get their own cases on purpose. ``.xinitrc``, ``.bashrc`` and
friends have no extension at all, so every extension-based shortcut in
the detector misses them and they fall through to whatever the fallback
does — which is exactly where a wrong guess would land.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from core.atomic_io import atomic_write  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

APP = QApplication.instance() or QApplication([])

XINITRC = (
    "#!/bin/sh\n"
    "userresources=$HOME/.Xresources\n"
    "xrdb -merge $userresources\n"
    "exec i3\n"
)

CASES = {
    "xinitrc": (".xinitrc", XINITRC),
    "bashrc": (".bashrc", "export PATH=$PATH:/usr/local/bin\nalias ll='ls -la'\n"),
    "plain_txt": ("notes.txt", "just some text\n"),
    "no_extension": ("Makefile", "all:\n\tgcc -o x x.c\n"),
    "empty": (".empty", ""),
    "utf8": ("umlaut.txt", "Grüße aus München — äöüß\n"),
    "long_lines": ("long.txt", "x" * 10000 + "\n"),
    "crlf": ("dos.txt", "line one\r\nline two\r\n"),
    "no_trailing_newline": ("bare.txt", "no newline at the end"),
    "conf": ("app.conf", "[main]\nkey = value\n"),
    "yaml": ("config.yaml", "a: 1\nb:\n  - x\n"),
    "json": ("data.json", '{"a": 1}\n'),
}


@pytest.mark.parametrize("case", sorted(CASES))
def test_happy_text_files_survive_a_save(tmp_path, case):
    """Read it, change it, write it back, read it again."""
    name, body = CASES[case]
    path = tmp_path / name
    path.write_text(body, encoding="utf-8")

    backend = LocalFS()
    full = str(path)

    with backend.open_read(full) as fh:
        original = fh.read()
    assert original == body.encode("utf-8")

    edited = original + b"# edited\n"
    atomic_write(backend, full, edited)

    with backend.open_read(full) as fh:
        assert fh.read() == edited


@pytest.mark.parametrize("case", sorted(CASES))
def test_happy_editor_classifies_text_files_as_text(tmp_path, case):
    """A text file must not be routed to the hex editor."""
    from core.local_fs import LocalFS
    from ui.file_pane import FilePaneWidget

    name, body = CASES[case]
    path = tmp_path / name
    path.write_text(body, encoding="utf-8")

    pane = FilePaneWidget(LocalFS())
    try:
        assert pane._is_binary_file(str(path), name) is False, name
    finally:
        pane.deleteLater()
        APP.processEvents()


def test_sad_a_gzip_file_is_classified_binary_not_text(tmp_path):
    """The counterpart: real compressed data must NOT be handed to the
    text editor, or saving it back would corrupt it."""
    import gzip

    from ui.file_pane import FilePaneWidget

    path = tmp_path / "archive.gz"
    path.write_bytes(gzip.compress(b"hello"))

    pane = FilePaneWidget(LocalFS())
    try:
        assert pane._is_binary_file(str(path), "archive.gz") is True
    finally:
        pane.deleteLater()
        APP.processEvents()


def test_edge_a_text_file_named_like_an_archive_is_still_read_verbatim(tmp_path):
    """Nothing in the save path may act on the NAME. A file called
    x.gz that holds text must round-trip byte for byte rather than
    being run through a decompressor."""
    path = tmp_path / "misleading.gz"
    path.write_bytes(b"this is not actually gzipped\n")

    backend = LocalFS()
    with backend.open_read(str(path)) as fh:
        data = fh.read()
    assert data == b"this is not actually gzipped\n"

    atomic_write(backend, str(path), data + b"more\n")
    with backend.open_read(str(path)) as fh:
        assert fh.read() == b"this is not actually gzipped\nmore\n"


def test_edge_atomic_write_preserves_an_existing_files_mode(tmp_path):
    """.xinitrc is executable. A save that drops the x bit leaves the
    user with a session that will not start."""
    path = tmp_path / ".xinitrc"
    path.write_text(XINITRC, encoding="utf-8")
    path.chmod(0o755)
    before = path.stat().st_mode & 0o777

    atomic_write(LocalFS(), str(path), XINITRC.encode() + b"# more\n")
    assert path.stat().st_mode & 0o777 == before, (
        "atomic_write replaced the file and lost its permission bits"
    )
