"""File operations review (2026-11-19): the dialogs around the files -
Trash, Permissions, Checksum, Folder size. Each test names what was
measured before its fix."""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication, QMessageBox  # noqa: E402

from core import trash as T  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

APP = QApplication.instance() or QApplication([])


def _wait(predicate, timeout: float = 10.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        APP.processEvents()
        if predicate():
            return True
        time.sleep(0.01)
    APP.processEvents()
    return False


@pytest.fixture
def fs(tmp_path):
    backend = LocalFS()
    (tmp_path / "home").mkdir()
    backend.home = lambda: str(tmp_path / "home")
    return backend


# -- Empty Trash: Cancel stops it ----------------------------------------------

def test_sad_cancel_during_empty_trash_keeps_the_entries_not_yet_removed(fs, tmp_path):
    """Measured before: the Trash window's status strip offered Cancel
    while Empty Trash ran, but the job ignored it - "Cancelling…", then
    every entry was deleted for good ("Removed 30 entries."). Now Cancel
    stops between entries and the rest stay in the trash."""
    from ui.trash_browser import TrashBrowserDialog

    for i in range(30):
        folder = tmp_path / f"d{i}"
        folder.mkdir()
        (folder / "f").write_text("x")
        T.trash(fs, str(folder))
    dialog = TrashBrowserDialog(fs)
    assert _wait(lambda: not dialog.busy)
    real = fs.remove

    def slow_remove(path, recursive=False):
        time.sleep(0.03)
        return real(path, recursive=recursive)

    fs.remove = slow_remove
    with mock.patch("ui.trash_browser.QMessageBox.question",
                    return_value=QMessageBox.StandardButton.Yes), \
            mock.patch("ui.trash_browser.QMessageBox.information") as info, \
            mock.patch("ui.trash_browser.QMessageBox.warning") as warn:
        dialog._do_empty()
        _wait(lambda: False, 0.15)
        dialog._job.cancel()
        assert _wait(lambda: not dialog.busy)
    left = len(T.list_trash(fs))
    assert 0 < left < 30
    warn.assert_not_called()
    assert info.called and "stopped" in info.call_args[0][2].lower()
    dialog.deleteLater()


def test_happy_empty_trash_without_cancel_removes_everything(fs, tmp_path):
    for i in range(3):
        (tmp_path / f"f{i}").write_text("x")
        T.trash(fs, str(tmp_path / f"f{i}"))
    assert T.empty_trash(fs, should_continue=lambda: True) == 3
    assert T.list_trash(fs) == []


def test_edge_a_stop_before_the_first_entry_removes_nothing(fs, tmp_path):
    (tmp_path / "f").write_text("x")
    T.trash(fs, str(tmp_path / "f"))
    assert T.empty_trash(fs, should_continue=lambda: False) == 0
    assert len(T.list_trash(fs)) == 1


# -- Permissions: one entry at a time -----------------------------------------

def _pane_on(folder: Path):
    from ui.file_pane import FilePaneWidget

    pane = FilePaneWidget(LocalFS())
    pane.resize(700, 400)
    pane.show()
    pane.navigate(str(folder))
    assert _wait(lambda: not pane.is_loading and pane.current_path == str(folder))
    return pane


def _select(pane, *names: str) -> None:
    from PyQt6.QtCore import QItemSelectionModel

    model, selection = pane._proxy, pane._table.selectionModel()
    selection.clearSelection()
    for row in range(model.rowCount()):
        if model.data(model.index(row, 0)) in names:
            selection.select(model.index(row, 0),
                             QItemSelectionModel.SelectionFlag.Select
                             | QItemSelectionModel.SelectionFlag.Rows)


def _menu_texts(menu) -> list[str]:
    found = []
    for action in menu.actions():
        found.append(action.text().replace("&", ""))
        if action.menu() is not None:
            found += _menu_texts(action.menu())
    return found


def test_sad_permissions_of_several_entries_is_not_offered_for_the_first_only(tmp_path):
    """Measured before: with a, b and c selected, More ▸ Permissions… opened
    "Permissions: a" and OK changed a alone - b and c kept their mode while
    the user had chosen all three. The editor shows and sets one entry's
    mode, so it is offered for one entry only."""
    for name in ("a", "b", "c"):
        (tmp_path / name).write_text(name)
        os.chmod(tmp_path / name, 0o644)
    pane = _pane_on(tmp_path)
    try:
        _select(pane, "a", "b", "c")
        assert len(pane.selected_items()) == 3
        assert "Permissions…" not in _menu_texts(pane._build_context_menu())
        with mock.patch("ui.permissions_dialog.PermissionsDialog") as dialog:
            pane._show_permissions()
        dialog.assert_not_called()
        _select(pane, "b")
        assert "Permissions…" in _menu_texts(pane._build_context_menu())
    finally:
        pane.close()
        pane.deleteLater()


# -- Show Checksum: Cancel on a local file, a server without commands ----------

def _checksum(pane, item, answer=QMessageBox.StandardButton.Yes):
    from tests.off_gui_wait import _drain_checksum

    shown, warnings, questions = [], [], []

    def ask(*args, **_kw):
        questions.append(args)
        return answer

    with mock.patch("ui.viewer_window.show_independent", shown.append), \
            mock.patch("ui.file_pane.QMessageBox.question", side_effect=ask), \
            mock.patch("ui.file_pane.QMessageBox.warning",
                       side_effect=lambda *a, **_k: warnings.append(a)):
        pane._show_checksum(item)
        assert _drain_checksum(pane)
    return shown, warnings, questions


def test_sad_cancel_stops_a_local_checksum_and_a_fifo_never_blocks_it(tmp_path):
    """Measured before: Show Checksum on a local file ran LocalFS.checksum,
    which read the whole file whatever Cancel said ("Cancelling…" for as
    long as the read took, no progress), and on a named pipe it blocked in
    open() for good. A local file is now hashed by the stream reader, which
    stops at Cancel and shows how far it is; a pipe is refused at once."""
    import hashlib

    from tests.off_gui_wait import _drain_checksum

    data = os.urandom(3 * 1024 * 1024 + 7)
    (tmp_path / "f.bin").write_bytes(data)
    fs = LocalFS()
    pane = _pane_on(tmp_path)
    try:
        shown, warnings, questions = _checksum(pane, fs.stat(str(tmp_path / "f.bin")))
        assert not warnings and not questions
        assert shown[0]._value == hashlib.sha256(data).hexdigest()

        reads: list = []
        real_open_read = LocalFS.open_read

        class _Slow:
            def __init__(self, inner):
                self.inner = inner

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                self.inner.close()

            def read(self, n=-1):
                time.sleep(0.02)
                reads.append(n)
                return self.inner.read(n)

        (tmp_path / "big").write_bytes(b"\0" * (40 * 1024 * 1024))
        with mock.patch.object(LocalFS, "open_read",
                               lambda self, p: _Slow(real_open_read(self, p))), \
                mock.patch("ui.file_pane.QMessageBox.question") as question, \
                mock.patch("ui.viewer_window.show_independent") as show:
            pane._show_checksum(fs.stat(str(tmp_path / "big")))
            _wait(lambda: len(reads) >= 2)
            pane._cancel_checksum()
            at_cancel = len(reads)
            assert _drain_checksum(pane)
        show.assert_not_called()
        question.assert_not_called()
        assert len(reads) <= at_cancel + 1

        os.mkfifo(tmp_path / "pipe")
        _shown, warnings, _questions = _checksum(pane, fs.stat(str(tmp_path / "pipe")))
        assert warnings and "not a regular file" in str(warnings[0])
    finally:
        pane.close()
        pane.deleteLater()


def test_sad_an_sftp_server_without_commands_still_gets_a_checksum(tmp_path):
    """Measured before: on an SFTP server that refuses to run commands
    (sha256sum), Show Checksum ended with "Failed to compute checksum:
    checksum failed: Channel closed." and never offered to read the file.
    Now a failed native checksum offers the SHA-256 of the file's bytes,
    as a backend without one does."""
    import hashlib

    data = os.urandom(1024 * 1024 + 1)
    (tmp_path / "f.bin").write_bytes(data)

    class _Refusing(LocalFS):
        def checksum(self, path, algorithm="sha256"):
            raise OSError("checksum failed: Channel closed.")

    from ui.file_pane import FilePaneWidget

    backend = _Refusing()
    pane = FilePaneWidget(backend)
    pane.navigate(str(tmp_path))
    try:
        assert _wait(lambda: not pane.is_loading)
        shown, warnings, questions = _checksum(pane, backend.stat(str(tmp_path / "f.bin")))
        assert not warnings, warnings
        assert len(questions) == 1 and "Channel closed" in questions[0][2]
        assert shown and shown[0]._value == hashlib.sha256(data).hexdigest()
        shown, warnings, questions = _checksum(
            pane, backend.stat(str(tmp_path / "f.bin")), QMessageBox.StandardButton.No)
        assert not shown and not warnings and len(questions) == 1
    finally:
        pane.close()
        pane.deleteLater()


# -- Folder size: entries that cannot be stat'ed --------------------------------

def _unsearchable(tmp_path: Path) -> Path:
    """d/nox: a folder the user may list but not enter (r--): the names
    are there, their sizes are not."""
    folder = tmp_path / "d"
    (folder / "nox").mkdir(parents=True)
    (folder / "nox" / "big").write_bytes(b"z" * 100_000)
    os.chmod(folder / "nox", 0o644)
    return folder


def test_sad_a_folder_without_search_permission_is_not_sized_as_exactly_zero(tmp_path):
    """Measured before: Calculate Size of a folder holding an r-- folder
    (listable, not enterable) said "0 bytes, 1 file", complete, no note -
    the entry whose stat failed was summed as 0 bytes. Now such an entry
    makes the size a lower bound and the note says how many could not be
    read; Properties and the selection summary say so too."""
    from core.fs_summary import summarize_selection
    from core.tree_size import tree_size
    from ui.dir_size_dialog import rows_from_results

    folder = _unsearchable(tmp_path)
    try:
        result = tree_size(LocalFS(), str(folder))
        row = rows_from_results([("d", result)])[0]
        assert row.incomplete
        assert "could not be read" in row.notes
        summary = summarize_selection(LocalFS(), str(folder), LocalFS().list_dir(str(folder)))
        assert summary.unreadable_count >= 1
    finally:
        os.chmod(folder / "nox", 0o755)


def test_sad_properties_of_such_a_folder_show_at_least(tmp_path):
    from ui.properties_dialog import PropertiesDialog

    folder = tmp_path / "d"
    folder.mkdir()
    (folder / "big").write_bytes(b"z" * 100_000)
    os.chmod(folder, 0o644)
    try:
        fs = LocalFS()
        dialog = PropertiesDialog(fs, str(folder), fs.stat(str(folder)))
        dialog.wait_for_size()
        size = dialog.general_fields()["Size"]
        assert "at least" in size, size
        dialog.deleteLater()
    finally:
        os.chmod(folder, 0o755)


# -- Pack: the gzip header names the file, not the temporary file ----------------

@pytest.mark.parametrize("fmt", ["gz", "tar.gz"])
def test_sad_a_gzip_archive_does_not_carry_the_temporary_name(tmp_path, fmt):
    """Measured before: gzip.GzipFile took the name of the file it wrote
    into - the hidden temporary ``.axross-pack-….tmp`` - and stored it in
    the header: ``gunzip -N notes.txt.gz`` made ``.axross-pack-uqpkie7e.tmp``
    instead of ``notes.txt``, and 7-Zip showed that name. Now a single
    file's header names that file and a tar.gz names none."""
    import gzip

    from core import packer as PK

    (tmp_path / "notes.txt").write_text("hello")
    result = PK.pack(LocalFS(), str(tmp_path), ["notes.txt"], "notes.txt",
                     PK.PackOptions(fmt=fmt))
    head = Path(result.path).read_bytes()[:64]
    assert b".axross-pack-" not in head
    if fmt == "gz":
        assert b"notes.txt\x00" in head
        assert gzip.decompress(Path(result.path).read_bytes()) == b"hello"


def test_sad_calculate_size_names_the_folder_it_could_not_read(tmp_path):
    """Measured before: the handbook says a folder that cannot be read "is
    named in the result", but the note only said "1 folder could not be
    read". Now the note names it (the first few of many)."""
    from core.tree_size import tree_size
    from ui.dir_size_dialog import rows_from_results

    folder = tmp_path / "d"
    (folder / "locked").mkdir(parents=True)
    (folder / "ok.txt").write_text("ok")
    os.chmod(folder / "locked", 0)
    try:
        row = rows_from_results([("d", tree_size(LocalFS(), str(folder)))])[0]
    finally:
        os.chmod(folder / "locked", 0o755)
    assert row.incomplete
    assert str(folder / "locked") in row.notes


# -- Texts that stayed English in the German window ------------------------------

def test_sad_a_failed_rename_and_the_quit_question_are_in_the_interface_language(tmp_path):
    """Measured before: "Could not rename a to b: …" (F2) and the quit
    question "N transfer(s) are running or waiting…" were English in the
    German window: plain f-strings, not looked up."""
    from core import i18n

    (tmp_path / "a.txt").write_text("a")
    (tmp_path / "taken").mkdir()
    pane = _pane_on(tmp_path)
    i18n.install("de")
    try:
        _select(pane, "a.txt")
        from PyQt6.QtWidgets import QInputDialog

        with mock.patch.object(QInputDialog, "getText", return_value=("x" * 300, True)), \
                mock.patch("ui.file_pane.QMessageBox.warning") as warn:
            pane._rename_selected()
            assert _wait(lambda: warn.called)
        text = warn.call_args[0][2]
        assert "ließ sich nicht" in text and "a.txt" in text
        assert (tmp_path / "a.txt").exists()
        assert i18n.tr("Transfers running") == "Übertragungen laufen"
        assert "Trotzdem beenden" in i18n.tr_n(
            2, "{n} transfer is running or waiting. Quitting cancels it; a partly copied "
               "file is left behind.\n\nQuit anyway?",
            "{n} transfers are running or waiting. Quitting cancels them; partly copied "
            "files are left behind.\n\nQuit anyway?")
    finally:
        i18n.install("en")
        pane.close()
        pane.deleteLater()


# -- Compare Panes: a tree deeper than the walk goes is not "the same" ------------

def test_sad_a_difference_below_the_depth_limit_is_not_reported_as_matching(tmp_path):
    """Measured before: the compare walk stopped at its depth limit (64)
    without a word: a file only on one side 66 folders down was never
    listed and Sync said "Nothing to do - the two sides already match".
    Now the folder at the limit is recorded as not compared, so what lies
    below it shows as unknown, never as equal."""
    from core import tree_compare as TC

    left, right = tmp_path / "L", tmp_path / "R"
    rel = "/".join(f"d{i}" for i in range(66))
    (left / rel).mkdir(parents=True)
    (right / rel).mkdir(parents=True)
    (left / rel / "only_left.txt").write_text("data")
    entries = TC.compare_trees(LocalFS(), str(left), LocalFS(), str(right))
    assert any(e.status == TC.Status.UNKNOWN for e in entries)


# -- Pack: a socket or a pipe in a folder is left out, not fatal --------------------

def test_sad_a_folder_holding_a_socket_or_a_pipe_still_packs(tmp_path):
    """Measured before: packing a folder that holds a socket (``~/.gnupg``
    has ``S.gpg-agent``) or a named pipe failed the whole archive ("cannot
    read gnupg/S.gpg-agent: [Errno 6]"), while a link in it was left out
    and named. Now such entries are left out and named the same way, and
    the pane says how many."""
    import socket
    import zipfile

    from core import packer as PK

    folder = tmp_path / "gnupg"
    folder.mkdir()
    (folder / "pubring.kbx").write_bytes(b"keys")
    os.mkfifo(folder / "fifo")
    sock = socket.socket(socket.AF_UNIX)
    sock.bind(str(folder / "S.agent"))
    try:
        result = PK.pack(LocalFS(), str(tmp_path), ["gnupg"], "gnupg",
                         PK.PackOptions(fmt="zip"))
    finally:
        sock.close()
    with zipfile.ZipFile(result.path) as zf:
        names = sorted(zf.namelist())
    assert "gnupg/pubring.kbx" in names
    assert not any(n.endswith(("fifo", "S.agent")) for n in names)
    assert sorted(result.special) == ["gnupg/S.agent", "gnupg/fifo"]


def test_sad_7z_refuses_a_name_it_cannot_store_and_says_which(tmp_path):
    """Measured before: a file name that is not UTF-8 failed a 7z pack with
    "packing failed: 'utf-16-le' codec can't encode character '\\udcff' …
    surrogates not allowed" - no file named, no way on. 7z stores names as
    UTF-16, so such a name cannot go in: the refusal now names the file and
    says that tar keeps it."""
    pytest.importorskip("py7zr")
    from core import packer as PK

    folder = tmp_path / "d"
    folder.mkdir()
    with open(os.fsencode(str(folder)) + b"/bad\xff.txt", "wb") as fh:
        fh.write(b"x")
    with pytest.raises(PK.PackError) as caught:
        PK.pack(LocalFS(), str(tmp_path), ["d"], "d", PK.PackOptions(fmt="7z"))
    text = str(caught.value)
    assert "bad" in text and "7z" in text and "tar" in text
    assert not [n for n in os.listdir(tmp_path) if n.startswith(".axross-pack")]


# -- The entry a rename or New Folder / New File made is the selected one ----------

def test_sad_after_rename_and_new_folder_the_new_entry_is_selected(tmp_path):
    """Measured before: after F2 the renamed entry was not selected any
    more (the selection was kept by the old name, which is gone), so the
    next key started at the top; New Folder and New File left the new
    entry unselected too. Now the pane selects the entry under its new
    name once the folder is shown again."""
    from PyQt6.QtWidgets import QInputDialog

    for name in ("a.txt", "b.txt", "c.txt"):
        (tmp_path / name).write_text(name)
    pane = _pane_on(tmp_path)

    def selected() -> list[str]:
        return [os.path.basename(p) for p in pane.selected_items()]

    try:
        _select(pane, "b.txt")
        with mock.patch.object(QInputDialog, "getText", return_value=("renamed.txt", True)):
            pane._rename_selected()
        assert _wait(lambda: selected() == ["renamed.txt"]), selected()
        assert (tmp_path / "renamed.txt").read_text() == "b.txt"
        with mock.patch.object(QInputDialog, "getText", return_value=("new folder", True)):
            pane._create_folder()
        assert _wait(lambda: selected() == ["new folder"]), selected()
        with mock.patch.object(QInputDialog, "getText", return_value=("new.txt", True)):
            pane._create_empty_file()
        assert _wait(lambda: selected() == ["new.txt"]), selected()
    finally:
        pane.close()
        pane.deleteLater()


def test_sad_tar_keeps_a_date_before_1980(tmp_path):
    """Measured before: every packed entry's time was raised to 1980 (ZIP's
    earliest date) for tar too, which stores any date: a 1971 file came
    back dated 1 Jan 1980. Only ZIP clamps now."""
    import tarfile
    import zipfile

    from core import packer as PK

    old = 86400 * 365  # 1971
    (tmp_path / "old.txt").write_text("x")
    os.utime(tmp_path / "old.txt", (old, old))
    result = PK.pack(LocalFS(), str(tmp_path), ["old.txt"], "t", PK.PackOptions(fmt="tar.gz"))
    with tarfile.open(result.path) as tf:
        assert tf.getmember("old.txt").mtime == old
    result = PK.pack(LocalFS(), str(tmp_path), ["old.txt"], "z", PK.PackOptions(fmt="zip"))
    with zipfile.ZipFile(result.path) as zf:
        assert zf.getinfo("old.txt").date_time[0] == 1980


def test_sad_7z_keeps_the_times_and_modes_of_remote_files_and_of_folders(tmp_path, monkeypatch):
    """Measured before: a 7z of a remote folder stored each file with the
    time and mode of axross's staging copy (the pack time, 0644), and every
    folder - local ones too - with those of the staging folder. ZIP and tar
    kept them. Now 7z does too."""
    pytest.importorskip("py7zr")
    from core import archive as AR
    from core import packer as PK

    class _Remote(LocalFS):
        pass

    monkeypatch.setattr(PK, "_is_local", lambda backend: not isinstance(backend, _Remote))
    src = tmp_path / "s"
    (src / "sub").mkdir(parents=True)
    (src / "sub" / "f.txt").write_text("x")
    os.chmod(src / "sub" / "f.txt", 0o600)
    os.utime(src / "sub" / "f.txt", (1_500_000_000, 1_500_000_000))
    os.utime(src / "sub", (1_400_000_000, 1_400_000_000))
    for backend, name in ((_Remote(), "remote"), (LocalFS(), "local")):
        result = PK.pack(backend, str(src), ["sub"], name, PK.PackOptions(fmt="7z"))
        out = tmp_path / f"out-{name}"
        AR.extract(result.path, str(out))
        st = os.stat(out / "sub" / "f.txt")
        assert abs(st.st_mtime - 1_500_000_000) < 3, (name, st.st_mtime)
        assert (st.st_mode & 0o777) == 0o600, (name, oct(st.st_mode))
        with __import__("py7zr").SevenZipFile(result.path) as zf:
            folder = next(i for i in zf.list() if i.filename == "sub")
        assert abs(folder.creationtime.timestamp() - 1_400_000_000) < 3, (name, folder.creationtime)


def test_sad_new_file_never_empties_a_file_that_appears_meanwhile(tmp_path):
    """Measured before: New File checked that the name was free and then
    opened it for writing ("wb"): a file saved under that name in between
    (another program, the other pane) was emptied. On a local folder the
    file is now created exclusively - one that is there is refused."""
    from PyQt6.QtWidgets import QInputDialog

    pane = _pane_on(tmp_path)
    target = tmp_path / "notes.txt"
    real_exists = LocalFS.exists

    def exists_then_appears(self, path):
        answer = real_exists(self, path)
        if path == str(target) and not answer:
            target.write_text("saved meanwhile")
        return answer

    try:
        with mock.patch.object(QInputDialog, "getText", return_value=("notes.txt", True)), \
                mock.patch.object(LocalFS, "exists", exists_then_appears), \
                mock.patch("ui.file_pane.QMessageBox.warning") as warn:
            pane._create_empty_file()
            assert _wait(lambda: warn.called)
        assert target.read_text() == "saved meanwhile"
        assert "exists" in warn.call_args[0][2]
    finally:
        pane.close()
        pane.deleteLater()
